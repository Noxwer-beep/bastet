"""Case notes: the half of the job that survives after the alert is closed.

Every incident gets an id, a timeline, and a markdown export that can go into the
documentation vault or straight into the ticket. SQLite, one file, no server.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from .config import db_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'medium',
    status      TEXT NOT NULL DEFAULT 'open',
    created     TEXT NOT NULL,
    updated     TEXT NOT NULL,
    summary     TEXT DEFAULT '',
    ttps        TEXT DEFAULT '',
    resolution  TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    ts      TEXT NOT NULL,
    kind    TEXT NOT NULL DEFAULT 'note',
    text    TEXT NOT NULL,
    source  TEXT DEFAULT 'analyst',
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id, ts);
"""

EVENT_KINDS = ("note", "ioc", "log", "action", "finding", "decision", "comms")


@dataclass
class Case:
    id: str
    title: str
    severity: str = "medium"
    status: str = "open"
    created: str = ""
    updated: str = ""
    summary: str = ""
    ttps: str = ""
    resolution: str = ""
    events: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "status": self.status, "created": self.created, "updated": self.updated,
            "summary": self.summary, "ttps": self.ttps, "resolution": self.resolution,
            "events": self.events,
        }


@contextmanager
def connect():
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


def _now() -> str:
    return dt.datetime.now().replace(microsecond=0).isoformat(sep=" ")


def new_id(conn: sqlite3.Connection, when: dt.datetime | None = None) -> str:
    when = when or dt.datetime.now()
    prefix = f"IR-{when.year}-"
    row = conn.execute(
        "SELECT id FROM cases WHERE id LIKE ? ORDER BY id DESC LIMIT 1", (prefix + "%",)
    ).fetchone()
    if row:
        last = int(row["id"].split("-")[-1])
        return f"{prefix}{last + 1:04d}"
    return f"{prefix}0001"


def new_case(title: str, severity: str = "medium", summary: str = "", ttps: str = "") -> Case:
    init_db()
    now = _now()
    with connect() as conn:
        case_id = new_id(conn)
        conn.execute(
            "INSERT INTO cases (id, title, severity, status, created, updated, summary, ttps) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (case_id, title, severity, "open", now, now, summary, ttps),
        )
    return Case(case_id, title, severity, "open", now, now, summary, ttps)


def add_event(case_id: str, text: str, kind: str = "note", source: str = "analyst") -> None:
    init_db()
    now = _now()
    with connect() as conn:
        exists = conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone()
        if not exists:
            raise KeyError(case_id)
        conn.execute(
            "INSERT INTO events (case_id, ts, kind, text, source) VALUES (?,?,?,?,?)",
            (case_id, now, kind, text, source),
        )
        conn.execute("UPDATE cases SET updated=? WHERE id=?", (now, case_id))


def list_cases(status: str = "", limit: int = 50) -> list[dict[str, Any]]:
    init_db()
    sql = "SELECT * FROM cases"
    params: tuple = ()
    if status:
        sql += " WHERE status=?"
        params = (status,)
    sql += " ORDER BY created DESC LIMIT ?"
    with connect() as conn:
        rows = conn.execute(sql, params + (limit,)).fetchall()
    return [dict(row) for row in rows]


def get_case(case_id: str) -> Case | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            return None
        events = conn.execute(
            "SELECT ts, kind, text, source FROM events WHERE case_id=? ORDER BY ts, id",
            (case_id,),
        ).fetchall()
    case = Case(**{k: row[k] for k in row.keys()})
    case.events = [dict(e) for e in events]
    return case


def set_status(case_id: str, status: str, resolution: str = "") -> None:
    init_db()
    with connect() as conn:
        conn.execute(
            "UPDATE cases SET status=?, resolution=?, updated=? WHERE id=?",
            (status, resolution, _now(), case_id),
        )


def open_count() -> int:
    init_db()
    with connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) c FROM cases WHERE status != 'closed'"
        ).fetchone()
    return row["c"] if row else 0


def export_markdown(case_id: str) -> str:
    case = get_case(case_id)
    if case is None:
        raise KeyError(case_id)
    lines = [
        f"# {case.id} — {case.title}",
        "",
        f"- **Severity**: {case.severity}",
        f"- **Status**: {case.status}",
        f"- **Opened**: {case.created}",
        f"- **Updated**: {case.updated}",
    ]
    if case.ttps:
        lines.append(f"- **ATT&CK**: {case.ttps}")
    lines.append("")
    if case.summary:
        lines += ["## Summary", "", case.summary, ""]
    lines += ["## Timeline", ""]
    if not case.events:
        lines.append("_No events recorded._")
    for event in case.events:
        text = event["text"].replace("\n", " ")
        lines.append(f"- `{event['ts']}` **{event['kind']}** — {text} _({event['source']})_")
    lines.append("")
    if case.resolution:
        lines += ["## Resolution", "", case.resolution, ""]
    lines += ["---", "", "_Written with Bastet._", ""]
    return "\n".join(lines)
