import base64
import json
import threading
import urllib.error
import urllib.request

import pytest

from rulebench import engine, fixtures_gen, harness
from rulebench.cli import main
from rulebench.engine import Fixtures, PathError
from rulebench.server import App, make_server
from rulebench.store import Store

RULE = 'rule m { strings: $a = "RULEBENCH-TEST-MARKER" condition: $a }'


@pytest.fixture
def fx(tmp_path):
    root = tmp_path / "fx"
    fixtures_gen.generate(root)
    return root


@pytest.fixture
def live(tmp_path, fx):
    app = App(fx, Store(tmp_path / "t.db"), tmp_path / "rules.yar")
    srv = make_server(app, 0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}", app
    srv.shutdown()
    srv.server_close()


def call(base, route, body=None, headers=None, host=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    if host:
        h["Host"] = host
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + route, data=data, headers=h)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_validate_ok():
    v = engine.validate(RULE)
    assert v["ok"] and v["rules"] == ["m"]


def test_validate_error_location():
    src = 'rule a {\n  strings:\n    $a = "x"\n  condition:\n    $b\n}'
    v = engine.validate(src)
    assert not v["ok"]
    e = v["errors"][0]
    assert (e["line"], e["code"]) == (5, "E025")
    assert src[e["start"] : e["end"]] == "$b"


def test_error_offsets_with_non_ascii():
    src = 'rule a { strings: $a = "\u00e9\u00e9" condition: $zz }'
    e = engine.validate(src)["errors"][0]
    assert src[e["start"] : e["end"]] == "$zz"


def test_syntax_error_reported():
    v = engine.validate("rule {")
    assert not v["ok"] and v["errors"][0]["line"] == 1


def test_scan_offsets_and_preview(fx):
    rules, _ = engine.compile_rules(RULE)
    res = {r["path"]: r for r in Fixtures(fx).scan(rules)}
    hit = res["binary/marker_in_noise.bin"]["matches"][0]["patterns"][0]["hits"][0]
    assert hit["offset"] == 700 and hit["length"] == 21
    assert hit["text"].startswith("RULEBENCH-TEST-MARKER")
    assert res["plain/clean.txt"]["matches"] == []


def test_harness_pass_fail_missing(fx):
    rules, _ = engine.compile_rules(RULE)
    results = Fixtures(fx).scan(rules)
    ann = {
        ("m", "plain/marker.txt"): {"expect": True, "note": ""},
        ("m", "plain/clean.txt"): {"expect": True, "note": ""},
        ("m", "gone.txt"): {"expect": False, "note": ""},
        ("m", "plain/label_only.txt"): {"expect": None, "note": "n"},
        ("other", "plain/marker.txt"): {"expect": True, "note": ""},
    }
    rows = {r["fixture"]: r["status"] for r in harness.evaluate(results, {"m"}, ann)}
    assert rows == {"plain/marker.txt": "pass", "plain/clean.txt": "fail", "gone.txt": "missing"}


def test_store_roundtrip(tmp_path):
    s = Store(tmp_path / "a.db")
    s.set_expect("r", "f", True)
    s.set_note("r", "f", " fp: docs ")
    assert s.all()[("r", "f")] == {"expect": True, "note": "fp: docs"}
    s.set_expect("r", "f", None)
    s.set_note("r", "f", "")
    assert s.all() == {}
    s.import_expect({"r": {"f": False}})
    assert s.export_expect() == {"r": {"f": False}}


@pytest.mark.parametrize(
    "rel",
    [
        "../x",
        "..\\x",
        "plain/../../x",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "C:/Windows/win.ini",
        "plain/marker.txt:stream",
        "",
        ".",
        "plain/..",
        "con",
        "plain/NUL.txt",
        "aux.tar.gz",
        "com1",
        "plain\\lpt9.log",
        "a\0b",
        None,
    ],
)
def test_fixtures_reject_escapes(fx, rel):
    with pytest.raises(PathError):
        Fixtures(fx).resolve(rel)


def test_sibling_prefix_dir_rejected(tmp_path):
    root = tmp_path / "fx"
    (tmp_path / "fx-secret").mkdir()
    (tmp_path / "fx-secret" / "k.txt").write_text("secret")
    root.mkdir()
    with pytest.raises(PathError):
        Fixtures(root).resolve("../fx-secret/k.txt")


def test_symlink_escape_not_listed_or_read(tmp_path):
    root = tmp_path / "fx"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    try:
        (root / "link.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks not permitted")
    f = Fixtures(root)
    assert f.list() == []
    with pytest.raises(PathError):
        f.read("link.txt")


def test_server_traversal_and_host(live):
    base, _ = live
    for route in ("/api/view", "/api/fixture/delete"):
        status, _ = call(base, route, {"path": "../../etc/passwd"})
        assert status == 400
    status, _ = call(base, "/api/fixture/add", {"path": "../evil.txt", "data": ""})
    assert status == 400
    status, _ = call(base, "/api/state", host="evil.example:80")
    assert status == 403


def test_server_requires_json(live):
    base, _ = live
    req = urllib.request.Request(
        base + "/api/validate", data=b"{}", headers={"Content-Type": "text/plain"}
    )
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 415


def test_server_binds_loopback(live):
    base, _ = live
    assert base.startswith("http://127.0.0.1:")


def test_server_flow(live, fx):
    base, app = live
    status, state = call(base, "/api/state")
    assert status == 200 and "plain/marker.txt" in state["files"]
    assert state["fixture_dir"] == "fx"
    status, _ = call(
        base, "/api/expect", {"rule": "m", "fixture": "plain/marker.txt", "expect": True}
    )
    assert status == 200
    call(base, "/api/expect", {"rule": "m", "fixture": "plain/clean.txt", "expect": True})
    call(base, "/api/note", {"rule": "m", "fixture": "plain/clean.txt", "note": "never matches"})
    status, r = call(base, "/api/scan", {"source": RULE})
    assert r["summary"] == {"pass": 1, "fail": 1, "missing": 0}
    assert {a["note"] for a in r["annotations"]} == {"", "never matches"}
    status, r = call(base, "/api/scan", {"source": "rule {"})
    assert r["ok"] is False


def test_server_add_view_delete(live, fx):
    base, _ = live
    data = base64.b64encode(b"hello\x00world").decode()
    status, r = call(base, "/api/fixture/add", {"path": "new/h.bin", "data": data})
    assert "new/h.bin" in r["files"]
    status, v = call(base, "/api/view", {"path": "new/h.bin"})
    assert v["size"] == 11 and v["rows"][0]["text"] == "hello.world"
    status, r = call(base, "/api/fixture/delete", {"path": "new/h.bin"})
    assert "new/h.bin" not in r["files"]
    status, _ = call(base, "/api/view", {"path": "new/h.bin"})
    assert status == 404


def test_fixtures_never_executed(tmp_path):
    root = tmp_path / "fx"
    root.mkdir()
    marker = tmp_path / "ran"
    (root / "x.py").write_text(f"open({str(marker)!r}, 'w')")
    (root / "x.bat").write_text(f"echo hi > {marker}")
    rules, _ = engine.compile_rules("rule r { condition: true }")
    Fixtures(root).scan(rules)
    assert not marker.exists()


def test_cli_check(tmp_path, fx, capsys):
    rules = tmp_path / "r.yar"
    rules.write_text(RULE.replace("m {", "m_rule {"))
    exp = tmp_path / "e.json"
    exp.write_text(json.dumps({"m_rule": {"plain/marker.txt": True, "plain/clean.txt": False}}))
    db = str(tmp_path / "c.db")
    assert main(["--db", db, "check", str(rules), str(fx), "--expect", str(exp)]) == 0
    exp.write_text(json.dumps({"m_rule": {"plain/clean.txt": True}}))
    assert main(["--db", db, "check", str(rules), str(fx), "--expect", str(exp)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_cli_compile_error(tmp_path, fx, capsys):
    rules = tmp_path / "bad.yar"
    rules.write_text("rule {")
    assert main(["--db", str(tmp_path / "d.db"), "check", str(rules), str(fx)]) == 2
    assert "bad.yar:1:" in capsys.readouterr().err


def test_examples_pass(tmp_path, fx):
    args = ["--db", str(tmp_path / "x.db"), "check", "examples/markers.yar", str(fx)]
    assert main([*args, "--expect", "examples/expect.json"]) == 0
