"""Lightweight SQLite persistence for scan history."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_DB_PATH: Optional[Path] = None
_CONNECTION: Optional[sqlite3.Connection] = None

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    scan_type     TEXT NOT NULL,
    ports         TEXT,
    extra_args    TEXT,
    use_privileged INTEGER DEFAULT 0,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT DEFAULT 'running',
    result_json   TEXT
);
"""


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialise the database, creating the file and table if needed."""
    global _DB_PATH, _CONNECTION
    if db_path is None:
        db_dir = Path.home() / ".nmap_insight"
        db_dir.mkdir(parents=True, exist_ok=True)
        db_path = db_dir / "history.db"
    _DB_PATH = db_path
    _CONNECTION = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    _CONNECTION.row_factory = sqlite3.Row
    _CONNECTION.execute(_SCHEMA)
    _CONNECTION.commit()


def _conn() -> sqlite3.Connection:
    if _CONNECTION is None:
        raise RuntimeError("Database not initialised – call init_db() first")
    return _CONNECTION


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_id() -> str:
    return f"scan_{uuid.uuid4().hex[:12]}"


def save_scan(
    scan_id: str,
    target: str,
    scan_type: str,
    ports: Optional[str],
    extra_args: list[str],
    use_privileged: bool,
) -> None:
    _conn().execute(
        "INSERT INTO scans (id, target, scan_type, ports, extra_args, use_privileged, started_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (scan_id, target, scan_type, ports, json.dumps(extra_args), int(use_privileged), _now()),
    )
    _conn().commit()


def complete_scan(scan_id: str, result: dict[str, Any]) -> None:
    _conn().execute(
        "UPDATE scans SET status = 'completed', finished_at = ?, result_json = ? WHERE id = ?",
        (_now(), json.dumps(result), scan_id),
    )
    _conn().commit()


def fail_scan(scan_id: str, error: str) -> None:
    _conn().execute(
        "UPDATE scans SET status = 'failed', finished_at = ?, result_json = ? WHERE id = ?",
        (_now(), json.dumps({"error": error}), scan_id),
    )
    _conn().commit()


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    rows = _conn().execute(
        "SELECT id, target, scan_type, ports, use_privileged, started_at, finished_at, status"
        " FROM scans ORDER BY started_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: str) -> Optional[dict[str, Any]]:
    row = _conn().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    if result.get("result_json"):
        result["result_json"] = json.loads(result["result_json"])
    if result.get("extra_args"):
        result["extra_args"] = json.loads(result["extra_args"])
    return result


def delete_scan(scan_id: str) -> bool:
    cur = _conn().execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    _conn().commit()
    return cur.rowcount > 0
