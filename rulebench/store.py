import sqlite3

SCHEMA = """
create table if not exists annotation (
    rule text not null,
    fixture text not null,
    expect integer,
    note text not null default '',
    primary key (rule, fixture)
)
"""


class Store:
    def __init__(self, path):
        self.path = str(path)
        with self._conn() as c:
            c.execute(SCHEMA)

    def _conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _update(self, rule, fixture, **fields):
        with self._conn() as c:
            c.execute(
                "insert or ignore into annotation (rule, fixture) values (?, ?)", (rule, fixture)
            )
            for col, value in fields.items():
                c.execute(
                    f"update annotation set {col} = ? where rule = ? and fixture = ?",
                    (value, rule, fixture),
                )
            c.execute("delete from annotation where expect is null and note = ''")

    def set_expect(self, rule, fixture, expect):
        value = None if expect is None else int(bool(expect))
        self._update(rule, fixture, expect=value)

    def set_note(self, rule, fixture, note):
        self._update(rule, fixture, note=note.strip())

    def all(self):
        with self._conn() as c:
            rows = c.execute("select * from annotation order by rule, fixture").fetchall()
        return {
            (r["rule"], r["fixture"]): {
                "expect": None if r["expect"] is None else bool(r["expect"]),
                "note": r["note"],
            }
            for r in rows
        }

    def import_expect(self, data):
        for rule, fixtures in data.items():
            for fixture, expect in fixtures.items():
                self.set_expect(rule, fixture, expect)

    def export_expect(self):
        out = {}
        for (rule, fixture), a in self.all().items():
            if a["expect"] is not None:
                out.setdefault(rule, {})[fixture] = a["expect"]
        return out
