import os
from pathlib import Path

import yara_x

MAX_SCAN_SIZE = 32 * 1024 * 1024
MAX_HITS = 50
PREVIEW = 48


class RuleError(Exception):
    def __init__(self, errors):
        super().__init__(errors[0]["title"] if errors else "compile error")
        self.errors = errors


class PathError(ValueError):
    pass


def _char_span(source, span):
    raw = source.encode()
    start = len(raw[: span["start"]].decode(errors="ignore"))
    end = len(raw[: span["end"]].decode(errors="ignore"))
    return start, end


def _describe(source, items):
    out = []
    for item in items:
        label = item["labels"][0] if item["labels"] else None
        start = end = None
        if label:
            start, end = _char_span(source, label["span"])
        out.append(
            {
                "code": item["code"],
                "title": item["title"],
                "line": item["line"],
                "column": item["column"],
                "label": label["text"] if label else "",
                "start": start,
                "end": end,
                "text": item["text"],
            }
        )
    return out


def compile_rules(source):
    comp = yara_x.Compiler()
    try:
        comp.add_source(source)
    except yara_x.CompileError:
        raise RuleError(_describe(source, comp.errors())) from None
    warnings = _describe(source, comp.warnings())
    return comp.build(), warnings


def validate(source):
    try:
        rules, warnings = compile_rules(source)
    except RuleError as e:
        return {"ok": False, "errors": e.errors, "warnings": [], "rules": []}
    return {
        "ok": True,
        "errors": [],
        "warnings": warnings,
        "rules": [r.identifier for r in rules],
    }


def _preview(data):
    shown = data[:PREVIEW]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in shown)
    return {"text": text, "hex": shown.hex(" ")}


def scan_bytes(scanner, data):
    out = []
    for rule in scanner.scan(data).matching_rules:
        patterns = []
        for pat in rule.patterns:
            hits = [
                {
                    "offset": m.offset,
                    "length": m.length,
                    **_preview(data[m.offset : m.offset + m.length]),
                }
                for m in pat.matches
            ]
            if hits:
                patterns.append({"id": pat.identifier, "count": len(hits), "hits": hits[:MAX_HITS]})
        out.append({"rule": rule.identifier, "tags": list(rule.tags), "patterns": patterns})
    return out


RESERVED = {"con", "prn", "aux", "nul", *(f"{n}{i}" for n in ("com", "lpt") for i in range(1, 10))}


class Fixtures:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def resolve(self, rel):
        if not isinstance(rel, str) or not rel or "\0" in rel or ":" in rel:
            raise PathError("bad path")
        rel = rel.replace("\\", "/")
        for part in rel.split("/"):
            if part.split(".")[0].rstrip(" ").lower() in RESERVED:
                raise PathError("reserved device name")
        path = (self.root / rel).resolve()
        if path == self.root or not path.is_relative_to(self.root):
            raise PathError("path escapes fixture directory")
        return path

    def list(self):
        found = []
        for base, dirs, names in os.walk(self.root, followlinks=False):
            dirs.sort()
            for name in sorted(names):
                full = Path(base) / name
                if full.is_symlink() or not full.is_file():
                    continue
                if not full.resolve().is_relative_to(self.root):
                    continue
                found.append(full.relative_to(self.root).as_posix())
        return found

    def read(self, rel, limit=None):
        path = self.resolve(rel)
        if not path.is_file():
            raise FileNotFoundError(rel)
        with open(path, "rb") as f:
            return f.read(limit)

    def write(self, rel, data):
        path = self.resolve(rel)
        if path.exists() and not path.is_file():
            raise PathError("not a file")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def delete(self, rel):
        path = self.resolve(rel)
        if not path.is_file():
            raise FileNotFoundError(rel)
        path.unlink()

    def scan(self, rules):
        scanner = yara_x.Scanner(rules)
        results = []
        for rel in self.list():
            path = self.root / rel
            size = path.stat().st_size
            entry = {"path": rel, "size": size, "matches": [], "error": None}
            if size > MAX_SCAN_SIZE:
                entry["error"] = f"skipped: larger than {MAX_SCAN_SIZE >> 20} MiB"
            else:
                try:
                    entry["matches"] = scan_bytes(scanner, path.read_bytes())
                except (OSError, yara_x.ScanError) as e:
                    entry["error"] = str(e)
            results.append(entry)
        return results
