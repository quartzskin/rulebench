import base64
import json
import posixpath
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import engine, fixtures_gen, harness
from .engine import Fixtures, PathError

STATIC = Path(__file__).parent / "static"
MAX_BODY = 12 * 1024 * 1024
HEX_VIEW = 4096


class App:
    def __init__(self, fixtures, store, rules_path=None):
        self.fixtures = Fixtures(fixtures)
        self.store = store
        self.rules_path = Path(rules_path) if rules_path else None

    def initial_source(self):
        if self.rules_path and self.rules_path.is_file():
            return self.rules_path.read_text(encoding="utf-8")
        return ""


def _annotations_payload(store):
    return [{"rule": r, "fixture": f, **a} for (r, f), a in store.all().items()]


def _handle(app, method, route, body):
    fx = app.fixtures
    if method == "GET" and route == "/api/state":
        return {
            "fixture_dir": fx.root.name,
            "rules_path": str(app.rules_path) if app.rules_path else None,
            "source": app.initial_source(),
            "files": fx.list(),
            "annotations": _annotations_payload(app.store),
        }
    if method == "POST" and route == "/api/validate":
        return engine.validate(body.get("source", ""))
    if method == "POST" and route == "/api/scan":
        try:
            rules, warnings = engine.compile_rules(body.get("source", ""))
        except engine.RuleError as e:
            return {"ok": False, "errors": e.errors}
        results = fx.scan(rules)
        names = {r.identifier for r in rules}
        rows = harness.evaluate(results, names, app.store.all())
        return {
            "ok": True,
            "warnings": warnings,
            "rules": sorted(names),
            "results": results,
            "checks": rows,
            "summary": harness.summarize(rows),
            "annotations": _annotations_payload(app.store),
        }
    if method == "POST" and route == "/api/view":
        data = fx.read(body.get("path"), HEX_VIEW)
        rows = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            rows.append({"offset": i, "hex": chunk.hex(" "), "text": text})
        return {"path": body["path"], "size": fx.resolve(body["path"]).stat().st_size, "rows": rows}
    if method == "POST" and route == "/api/fixture/add":
        fx.write(body.get("path"), base64.b64decode(body.get("data", ""), validate=True))
        return {"files": fx.list()}
    if method == "POST" and route == "/api/fixture/delete":
        fx.delete(body.get("path"))
        return {"files": fx.list()}
    if method == "POST" and route == "/api/fixture/generate":
        fixtures_gen.generate(fx.root)
        return {"files": fx.list()}
    if method == "POST" and route == "/api/expect":
        expect = body.get("expect")
        if expect not in (True, False, None):
            raise ValueError("expect must be true, false or null")
        app.store.set_expect(_name(body, "rule"), _fixture(body), expect)
        return {"annotations": _annotations_payload(app.store)}
    if method == "POST" and route == "/api/note":
        note = body.get("note", "")
        if not isinstance(note, str) or len(note) > 4000:
            raise ValueError("bad note")
        app.store.set_note(_name(body, "rule"), _fixture(body), note)
        return {"annotations": _annotations_payload(app.store)}
    if method == "POST" and route == "/api/save":
        if not app.rules_path:
            raise ValueError("server was started without --rules")
        app.rules_path.write_text(body.get("source", ""), encoding="utf-8")
        return {"saved": str(app.rules_path)}
    return None


def _name(body, key):
    v = body.get(key)
    if not isinstance(v, str) or not v or len(v) > 256:
        raise ValueError("bad " + key)
    return v


def _fixture(body):
    v = body.get("fixture", "")
    if v == "":
        return v
    return posixpath.normpath(str(_name(body, "fixture")))


def make_handler(app, allowed_hosts):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, status, payload, ctype="application/json"):
            raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)

        def _dispatch(self, method):
            if self.headers.get("Host", "") not in allowed_hosts:
                return self._send(403, {"error": "bad host"})
            route = self.path.split("?", 1)[0]
            if method == "GET" and route in ("/", "/index.html"):
                page = (STATIC / "index.html").read_bytes()
                return self._send(200, page, "text/html; charset=utf-8")
            body = {}
            if method == "POST":
                if not self.headers.get("Content-Type", "").startswith("application/json"):
                    return self._send(415, {"error": "json only"})
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = -1
                if not 0 <= length <= MAX_BODY:
                    return self._send(413, {"error": "body too large"})
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                    if not isinstance(body, dict):
                        raise ValueError
                except ValueError:
                    return self._send(400, {"error": "invalid json"})
            try:
                result = _handle(app, method, route, body)
            except PathError as e:
                return self._send(400, {"error": str(e)})
            except FileNotFoundError:
                return self._send(404, {"error": "no such fixture"})
            except ValueError as e:
                return self._send(400, {"error": str(e) or "bad request"})
            except OSError as e:
                return self._send(500, {"error": e.strerror or "io error"})
            if result is None:
                return self._send(404, {"error": "not found"})
            self._send(200, result)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

    return Handler


def make_server(app, port=8470):
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, hosts))
    if port == 0:
        port = srv.server_address[1]
        hosts.update({f"127.0.0.1:{port}", f"localhost:{port}"})
    return srv
