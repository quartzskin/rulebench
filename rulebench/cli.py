import argparse
import json
import sys
from pathlib import Path

from . import engine, fixtures_gen, harness
from .server import App, make_server
from .store import Store


def _print_errors(errors, path):
    for e in errors:
        print(f"{path}:{e['line']}:{e['column']}: {e['title']}", file=sys.stderr)
        print(e["text"], file=sys.stderr)


def cmd_check(args):
    source = Path(args.rules).read_text(encoding="utf-8")
    try:
        rules, warnings = engine.compile_rules(source)
    except engine.RuleError as e:
        _print_errors(e.errors, args.rules)
        return 2
    store = Store(args.db)
    if args.expect:
        store.import_expect(json.loads(Path(args.expect).read_text(encoding="utf-8")))
    results = engine.Fixtures(args.fixtures).scan(rules)
    names = {r.identifier for r in rules}
    rows = harness.evaluate(results, names, store.all())
    for w in warnings:
        print(f"warning: line {w['line']}: {w['title']}", file=sys.stderr)
    for r in rows:
        want = "match" if r["expect"] else "no match"
        print(f"{r['status'].upper():7} {r['rule']} on {r['fixture']} (expected {want})")
    counts = harness.summarize(rows)
    print(f"{counts['pass']} passed, {counts['fail']} failed, {counts['missing']} missing")
    for r in results:
        if r["error"]:
            print(f"note: {r['path']}: {r['error']}", file=sys.stderr)
    return 1 if counts["fail"] or counts["missing"] else 0


def cmd_gen(args):
    for rel in fixtures_gen.generate(args.dir):
        print(rel)
    return 0


def cmd_export(args):
    print(json.dumps(Store(args.db).export_expect(), indent=2, sort_keys=True))
    return 0


def cmd_serve(args):
    fixtures = Path(args.fixtures)
    if not fixtures.is_dir():
        print(f"not a directory: {fixtures}", file=sys.stderr)
        return 2
    app = App(fixtures, Store(args.db), args.rules)
    srv = make_server(app, args.port)
    print(f"http://127.0.0.1:{srv.server_address[1]}/  (fixtures: {app.fixtures.root})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="rulebench")
    p.add_argument("--db", default="rulebench.db", help="SQLite file for notes and expectations")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the local web UI")
    s.add_argument("fixtures")
    s.add_argument("--rules", help="rule file to load and save")
    s.add_argument("--port", type=int, default=8470)
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("check", help="scan fixtures and report pass/fail per expectation")
    s.add_argument("rules")
    s.add_argument("fixtures")
    s.add_argument("--expect", help="JSON file of expectations, merged into the db")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("gen", help="write the synthetic fixtures")
    s.add_argument("dir")
    s.set_defaults(fn=cmd_gen)

    s = sub.add_parser("export", help="print stored expectations as JSON")
    s.set_defaults(fn=cmd_export)

    args = p.parse_args(argv)
    return args.fn(args)
