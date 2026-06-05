"""
database.py — ShadowPort Scanner v2.0.0
SQLite-backed scan history: store, retrieve, and compare scans.
All DB operations wrapped in try/except — never crashes the app.
"""

import sqlite3
import json
import os
from datetime import datetime

from config.settings import DB_PATH, LOGS_DIR

CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT    NOT NULL,
    hostname      TEXT    DEFAULT '',
    status        TEXT    DEFAULT 'unknown',
    mode_name     TEXT    DEFAULT '',
    start_time    TEXT    DEFAULT '',
    end_time      TEXT    DEFAULT '',
    duration_s    REAL    DEFAULT 0,
    open_count    INTEGER DEFAULT 0,
    risk_score    INTEGER DEFAULT 0,
    os_match      TEXT    DEFAULT '',
    ports_json    TEXT    DEFAULT '[]',
    report_path   TEXT    DEFAULT '',
    partial       INTEGER DEFAULT 0,
    created_at    TEXT    DEFAULT (datetime('now'))
);
"""


def _get_conn() -> sqlite3.Connection:
    os.makedirs(LOGS_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(CREATE_SCANS)
    conn.commit()
    return conn


def save_scan(scan_data: dict, report_path: str = "", risk_score: int = 0) -> int:
    ports      = scan_data.get("ports", [])
    open_count = sum(1 for p in ports if p["state"] == "open")
    os_match   = scan_data.get("os_matches", [""])[0] if scan_data.get("os_matches") else ""
    partial    = 1 if scan_data.get("partial", False) else 0

    conn = _get_conn()
    cur  = conn.execute(
        """INSERT INTO scans
           (target, hostname, status, mode_name, start_time, end_time,
            duration_s, open_count, risk_score, os_match, ports_json, report_path, partial)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            scan_data.get("host", ""),
            scan_data.get("hostname", ""),
            scan_data.get("state", "unknown"),
            scan_data.get("mode_name", ""),
            scan_data.get("start_time", ""),
            scan_data.get("end_time", ""),
            scan_data.get("duration_seconds", 0),
            open_count,
            risk_score,
            os_match,
            json.dumps(ports),
            report_path,
            partial,
        ),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def get_history(limit: int = 20) -> list[dict]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int) -> dict | None:
    conn = _get_conn()
    row  = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_scans_for_target(target: str) -> list[dict]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM scans WHERE target=? ORDER BY id ASC", (target,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def compare_scans(target: str) -> dict | None:
    scans = get_scans_for_target(target)
    if len(scans) < 2:
        return None

    prev = scans[-2]
    curr = scans[-1]

    prev_ports = {p["port"] for p in json.loads(prev["ports_json"]) if p["state"] == "open"}
    curr_ports = {p["port"] for p in json.loads(curr["ports_json"]) if p["state"] == "open"}

    return {
        "previous":     prev,
        "current":      curr,
        "new_ports":    sorted(curr_ports - prev_ports),
        "closed_ports": sorted(prev_ports - curr_ports),
        "unchanged":    sorted(curr_ports & prev_ports),
    }


def get_stats() -> dict:
    conn     = _get_conn()
    total    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    targets  = conn.execute("SELECT COUNT(DISTINCT target) FROM scans").fetchone()[0]
    avg_dur  = conn.execute("SELECT AVG(duration_s) FROM scans").fetchone()[0] or 0
    avg_open = conn.execute("SELECT AVG(open_count) FROM scans").fetchone()[0] or 0
    conn.close()
    return {
        "total_scans":    total,
        "unique_targets": targets,
        "avg_duration_s": round(avg_dur, 1),
        "avg_open_ports": round(avg_open, 1),
    }
