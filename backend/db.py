from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "klypen.db"
DB_PATH = Path(os.getenv("KLYPEN_DB_PATH", str(_DEFAULT_DB))).expanduser()
_lock = threading.RLock()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc, tb):
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _lock, connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            origin TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            stage TEXT NOT NULL DEFAULT 'queued',
            progress INTEGER NOT NULL DEFAULT 0,
            pages_scanned INTEGER NOT NULL DEFAULT 0,
            requests_made INTEGER NOT NULL DEFAULT 0,
            summary_json TEXT NOT NULL DEFAULT '{}',
            errors_json TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            url TEXT NOT NULL,
            finding_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        """)
        # Do not claim interrupted work completed after a process restart.
        c.execute("UPDATE scans SET status='failed', stage='interrupted', completed_at=?, errors_json=? WHERE status IN ('queued','running')",
                  (now(), json.dumps(["Application restarted while this scan was active; rerun it to obtain complete results."])))


def row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None: return None
    out = dict(row)
    for key in ("summary_json", "errors_json"):
        if key in out:
            out[key[:-5] if key.endswith("_json") else key] = json.loads(out.pop(key) or ("{}" if key == "summary_json" else "[]"))
    return out


def create_scan(scan_id: str, target_url: str, origin: str) -> dict:
    with _lock, connect() as c:
        c.execute("INSERT INTO scans(id,target_url,origin,status,created_at,stage) VALUES(?,?,?,?,?,?)",
                  (scan_id, target_url, origin, "queued", now(), "queued"))
    return get_scan(scan_id)


def update_scan(scan_id: str, **fields) -> None:
    allowed = {"status", "started_at", "completed_at", "stage", "progress", "pages_scanned", "requests_made", "summary_json", "errors_json"}
    values = []
    parts = []
    for k, v in fields.items():
        if k not in allowed: continue
        if k in {"summary_json", "errors_json"}: v = json.dumps(v, ensure_ascii=False)
        parts.append(f"{k}=?"); values.append(v)
    if not parts: return
    values.append(scan_id)
    with _lock, connect() as c:
        c.execute(f"UPDATE scans SET {', '.join(parts)} WHERE id=?", values)


def add_findings(scan_id: str, findings: list[dict]) -> None:
    with _lock, connect() as c:
        c.executemany("INSERT INTO findings(scan_id,title,category,severity,confidence,url,finding_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
            [(scan_id, f["title"], f["category"], f["severity"], f["confidence"], f["url"], json.dumps(f, ensure_ascii=False), now()) for f in findings])


def get_scan(scan_id: str) -> dict | None:
    with _lock, connect() as c:
        row = row_dict(c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())
        if row:
            row["findings"] = [json.loads(r[0]) for r in c.execute("SELECT finding_json FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()]
        return row


def list_scans(limit: int = 50) -> list[dict]:
    with _lock, connect() as c:
        rows = c.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 100)),)).fetchall()
        result = []
        for item in rows:
            d = row_dict(item)
            d["finding_count"] = c.execute("SELECT COUNT(*) FROM findings WHERE scan_id=?", (d["id"],)).fetchone()[0]
            result.append(d)
        return result


def delete_oldest_scans(max_rows: int = 200) -> None:
    with _lock, connect() as c:
        c.execute("DELETE FROM scans WHERE id IN (SELECT id FROM scans ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ?)", (max_rows,))


def list_findings(limit: int = 500) -> list[dict]:
    with _lock, connect() as c:
        rows = c.execute("SELECT finding_json, scan_id, created_at FROM findings ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        out = []
        for row in rows:
            item = json.loads(row[0])
            item["scan_id"] = row[1]
            item["created_at"] = row[2]
            out.append(item)
        return out
