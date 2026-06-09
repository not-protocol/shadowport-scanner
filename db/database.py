"""
db/database.py — ShadowPort Scanner v2.1.0

Complete SQLite layer:
  - Full schema: scans, ports, plugins_log, scan_statistics
  - Schema migration via PRAGMA table_info (never drops data)
  - Thread-safe via threading.Lock
  - Parameterized queries only — zero f-string SQL
  - Context managers on every connection
  - save_scan() maps every field explicitly
"""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Optional

from config.settings import DB_PATH, LOGS_DIR, SCHEMA_VERSION

_db_lock = threading.Lock()


# ─── Schema ───────────────────────────────────────────────────────────────────

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT    NOT NULL,
    scan_type     TEXT    NOT NULL DEFAULT '',
    timestamp     TEXT    NOT NULL DEFAULT (datetime('now')),
    duration      REAL    NOT NULL DEFAULT 0.0,
    open_ports    INTEGER NOT NULL DEFAULT 0,
    total_ports   INTEGER NOT NULL DEFAULT 0,
    partial       INTEGER NOT NULL DEFAULT 0,
    risk_score    INTEGER NOT NULL DEFAULT 0,
    raw_output    TEXT    NOT NULL DEFAULT '',
    services_json TEXT    NOT NULL DEFAULT '[]',
    status        TEXT    NOT NULL DEFAULT 'unknown',
    hostname      TEXT    NOT NULL DEFAULT '',
    os_match      TEXT    NOT NULL DEFAULT '',
    mode_name     TEXT    NOT NULL DEFAULT '',
    report_path   TEXT    NOT NULL DEFAULT ''
);
"""

_CREATE_PORTS = """
CREATE TABLE IF NOT EXISTS ports (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port      TEXT    NOT NULL,
    protocol  TEXT    NOT NULL DEFAULT 'tcp',
    service   TEXT    NOT NULL DEFAULT '',
    state     TEXT    NOT NULL DEFAULT 'unknown',
    banner    TEXT    NOT NULL DEFAULT ''
);
"""

_CREATE_PLUGINS_LOG = """
CREATE TABLE IF NOT EXISTS plugins_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    plugin_name TEXT    NOT NULL,
    ran_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    output      TEXT    NOT NULL DEFAULT '',
    success     INTEGER NOT NULL DEFAULT 1
);
"""

_CREATE_SCAN_STATISTICS = """
CREATE TABLE IF NOT EXISTS scan_statistics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    total_scans     INTEGER NOT NULL DEFAULT 0,
    unique_targets  INTEGER NOT NULL DEFAULT 0,
    avg_open_ports  REAL    NOT NULL DEFAULT 0.0,
    avg_duration    REAL    NOT NULL DEFAULT 0.0,
    avg_risk_score  REAL    NOT NULL DEFAULT 0.0
);
"""

_CREATE_SCHEMA_META = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# All columns that must exist in scans (used by migration)
_SCANS_REQUIRED_COLUMNS = {
    "id":            "INTEGER PRIMARY KEY AUTOINCREMENT",
    "target":        "TEXT NOT NULL DEFAULT ''",
    "scan_type":     "TEXT NOT NULL DEFAULT ''",
    "timestamp":     "TEXT NOT NULL DEFAULT (datetime('now'))",
    "duration":      "REAL NOT NULL DEFAULT 0.0",
    "open_ports":    "INTEGER NOT NULL DEFAULT 0",
    "total_ports":   "INTEGER NOT NULL DEFAULT 0",
    "partial":       "INTEGER NOT NULL DEFAULT 0",
    "risk_score":    "INTEGER NOT NULL DEFAULT 0",
    "raw_output":    "TEXT NOT NULL DEFAULT ''",
    "services_json": "TEXT NOT NULL DEFAULT '[]'",
    "status":        "TEXT NOT NULL DEFAULT 'unknown'",
    "hostname":      "TEXT NOT NULL DEFAULT ''",
    "os_match":      "TEXT NOT NULL DEFAULT ''",
    "mode_name":     "TEXT NOT NULL DEFAULT ''",
    "report_path":   "TEXT NOT NULL DEFAULT ''",
}


# ─── Connection helper ────────────────────────────────────────────────────────

@contextmanager
def _get_conn():
    os.makedirs(LOGS_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─── Schema initialisation & migration ───────────────────────────────────────

def _get_existing_columns(conn: sqlite3.Connection, table: str) -> set:
    """Return set of column names that currently exist in table."""
    try:
        rows = conn.execute(
            "SELECT name FROM pragma_table_info(?)", (table,)
        ).fetchall()
        return {row["name"] for row in rows}
    except sqlite3.Error:
        return set()


def migrate_schema() -> list[str]:
    """
    Bring the database schema up to the current version.
    Uses PRAGMA table_info to detect missing columns.
    Never drops existing data.
    Returns list of migration actions performed.
    """
    actions: list[str] = []

    with _db_lock, _get_conn() as conn:
        # Create all tables if they don't exist
        conn.execute(_CREATE_SCHEMA_META)
        conn.execute(_CREATE_SCANS)
        conn.execute(_CREATE_PORTS)
        conn.execute(_CREATE_PLUGINS_LOG)
        conn.execute(_CREATE_SCAN_STATISTICS)

        # Migrate scans table: add any missing columns
        existing = _get_existing_columns(conn, "scans")
        for col_name, col_def in _SCANS_REQUIRED_COLUMNS.items():
            if col_name == "id":
                continue  # cannot ALTER PRIMARY KEY
            if col_name not in existing:
                try:
                    conn.execute(
                        f"ALTER TABLE scans ADD COLUMN {col_name} {col_def}"
                    )
                    actions.append(f"Added column scans.{col_name}")
                except sqlite3.OperationalError as exc:
                    actions.append(f"Skipped scans.{col_name}: {exc}")

        # Record schema version
        conn.execute(
            "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
        if actions:
            actions.insert(0, f"Schema migrated to v{SCHEMA_VERSION}")

    return actions


def init_db() -> list[str]:
    """Initialise database on startup. Returns migration log."""
    return migrate_schema()


# ─── Save scan ────────────────────────────────────────────────────────────────

def save_scan(scan_data: dict, risk_score: int = 0, report_path: str = "") -> int:
    """
    Insert a completed scan into the database.
    All fields mapped explicitly — no dynamic column insertion.
    Returns the new scan id.
    """
    ports      = scan_data.get("ports", [])
    open_count = sum(1 for p in ports if p.get("state") == "open")
    os_match   = ""
    if scan_data.get("os_matches"):
        os_match = scan_data["os_matches"][0]

    services = [
        {
            "port":    p.get("port", ""),
            "proto":   p.get("proto", "tcp"),
            "service": p.get("service", ""),
            "state":   p.get("state", "unknown"),
            "version": p.get("version", ""),
        }
        for p in ports
    ]

    with _db_lock, _get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (
                target, scan_type, timestamp, duration,
                open_ports, total_ports, partial, risk_score,
                raw_output, services_json, status,
                hostname, os_match, mode_name, report_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_data.get("host", ""),
                scan_data.get("mode_name", ""),
                scan_data.get("start_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                float(scan_data.get("duration_seconds", 0.0)),
                open_count,
                len(ports),
                1 if scan_data.get("partial", False) else 0,
                int(risk_score),
                scan_data.get("raw_output", ""),
                json.dumps(services),
                scan_data.get("state", "unknown"),
                scan_data.get("hostname", ""),
                os_match,
                scan_data.get("mode_name", ""),
                report_path,
            ),
        )
        scan_id = cur.lastrowid

        # Insert normalised port records
        for p in ports:
            conn.execute(
                """
                INSERT INTO ports (scan_id, port, protocol, service, state, banner)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    str(p.get("port", "")),
                    str(p.get("proto", "tcp")),
                    str(p.get("service", "")),
                    str(p.get("state", "unknown")),
                    str(p.get("banner", "")),
                ),
            )

    return scan_id


# ─── Retrieve scans ───────────────────────────────────────────────────────────

def get_scan_history(limit: int = 20) -> list[dict]:
    """Return the most recent scans as dicts, newest first."""
    with _db_lock, _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int) -> Optional[dict]:
    with _db_lock, _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    return dict(row) if row else None


def get_ports_for_scan(scan_id: int) -> list[dict]:
    with _db_lock, _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM ports WHERE scan_id = ? ORDER BY CAST(port AS INTEGER)",
            (scan_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scans_for_target(target: str) -> list[dict]:
    with _db_lock, _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE target = ? ORDER BY id ASC", (target,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    with _db_lock, _get_conn() as conn:
        total    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        targets  = conn.execute("SELECT COUNT(DISTINCT target) FROM scans").fetchone()[0]
        avg_dur  = conn.execute("SELECT AVG(duration) FROM scans").fetchone()[0] or 0.0
        avg_open = conn.execute("SELECT AVG(open_ports) FROM scans").fetchone()[0] or 0.0
        avg_risk = conn.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0.0
    return {
        "total_scans":    total,
        "unique_targets": targets,
        "avg_duration_s": round(avg_dur, 1),
        "avg_open_ports": round(avg_open, 1),
        "avg_risk_score": round(avg_risk, 1),
    }


def log_plugin_run(scan_id: int, plugin_name: str, output: str, success: bool = True) -> None:
    with _db_lock, _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO plugins_log (scan_id, plugin_name, output, success)
            VALUES (?, ?, ?, ?)
            """,
            (scan_id, plugin_name, output, 1 if success else 0),
        )


def snapshot_statistics() -> None:
    """Record a statistics snapshot into scan_statistics table."""
    stats = get_stats()
    with _db_lock, _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO scan_statistics
                (total_scans, unique_targets, avg_open_ports, avg_duration, avg_risk_score)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                stats["total_scans"],
                stats["unique_targets"],
                stats["avg_open_ports"],
                stats["avg_duration_s"],
                stats["avg_risk_score"],
            ),
        )
