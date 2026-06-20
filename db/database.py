"""
db/database.py — ShadowPort Scanner v2.3.0

Full SQLite layer:
  - scans, ports, plugins_log, reports_log, errors_log, scan_statistics
  - Schema migration via PRAGMA table_info
  - Thread-safe via threading.Lock
  - Parameterized queries only — zero f-string SQL
  - Context managers on every connection
"""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Optional

from config.settings import DB_PATH, LOG_DIR, SCHEMA_VERSION

_db_lock = threading.Lock()

# ── Schema ────────────────────────────────────────────────────────────────────

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT    NOT NULL DEFAULT '',
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
    port      TEXT    NOT NULL DEFAULT '',
    protocol  TEXT    NOT NULL DEFAULT 'tcp',
    service   TEXT    NOT NULL DEFAULT '',
    state     TEXT    NOT NULL DEFAULT 'unknown',
    banner    TEXT    NOT NULL DEFAULT ''
);
"""

_CREATE_PLUGINS_LOG = """
CREATE TABLE IF NOT EXISTS plugins_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    target      TEXT    NOT NULL DEFAULT '',
    plugin_name TEXT    NOT NULL DEFAULT '',
    ran_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    output      TEXT    NOT NULL DEFAULT '',
    duration    REAL    NOT NULL DEFAULT 0.0,
    success     INTEGER NOT NULL DEFAULT 1,
    error_msg   TEXT    NOT NULL DEFAULT ''
);
"""

_CREATE_REPORTS_LOG = """
CREATE TABLE IF NOT EXISTS reports_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    target      TEXT    NOT NULL DEFAULT '',
    format      TEXT    NOT NULL DEFAULT '',
    filepath    TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    success     INTEGER NOT NULL DEFAULT 1
);
"""

_CREATE_ERRORS_LOG = """
CREATE TABLE IF NOT EXISTS errors_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred   TEXT    NOT NULL DEFAULT (datetime('now')),
    module     TEXT    NOT NULL DEFAULT '',
    target     TEXT    NOT NULL DEFAULT '',
    message    TEXT    NOT NULL DEFAULT '',
    traceback  TEXT    NOT NULL DEFAULT ''
);
"""

_CREATE_SCAN_STATISTICS = """
CREATE TABLE IF NOT EXISTS scan_statistics (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    total_scans    INTEGER NOT NULL DEFAULT 0,
    unique_targets INTEGER NOT NULL DEFAULT 0,
    avg_open_ports REAL    NOT NULL DEFAULT 0.0,
    avg_duration   REAL    NOT NULL DEFAULT 0.0,
    avg_risk_score REAL    NOT NULL DEFAULT 0.0
);
"""

_CREATE_SCHEMA_META = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_SCANS_REQUIRED = {
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

# ── Connection ────────────────────────────────────────────────────────────────

@contextmanager
def _conn():
    os.makedirs(LOG_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

# ── Migration ─────────────────────────────────────────────────────────────────

def migrate_schema() -> list[str]:
    actions: list[str] = []
    with _db_lock, _conn() as con:
        con.execute(_CREATE_SCHEMA_META)
        for ddl in [_CREATE_SCANS, _CREATE_PORTS, _CREATE_PLUGINS_LOG,
                    _CREATE_REPORTS_LOG, _CREATE_ERRORS_LOG, _CREATE_SCAN_STATISTICS]:
            con.execute(ddl)

        existing = {
            r["name"]
            for r in con.execute("SELECT name FROM pragma_table_info('scans')").fetchall()
        }
        for col, defn in _SCANS_REQUIRED.items():
            if col not in existing:
                try:
                    con.execute(f"ALTER TABLE scans ADD COLUMN {col} {defn}")
                    actions.append(f"Added scans.{col}")
                except sqlite3.OperationalError as e:
                    actions.append(f"Skipped scans.{col}: {e}")

        con.execute(
            "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
    return actions


def init_db() -> list[str]:
    return migrate_schema()

# ── Save scan ─────────────────────────────────────────────────────────────────

def save_scan(scan_data: dict, risk_score: int = 0, report_path: str = "") -> int:
    ports      = scan_data.get("ports", [])
    open_count = sum(1 for p in ports if p.get("state") == "open")
    os_match   = (scan_data.get("os_matches") or [""])[0]
    services   = [
        {"port": p.get("port",""), "proto": p.get("proto","tcp"),
         "service": p.get("service",""), "state": p.get("state",""), "version": p.get("version","")}
        for p in ports
    ]
    with _db_lock, _conn() as con:
        cur = con.execute(
            """INSERT INTO scans
               (target,scan_type,timestamp,duration,open_ports,total_ports,
                partial,risk_score,raw_output,services_json,status,hostname,
                os_match,mode_name,report_path)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_data.get("host",""), scan_data.get("mode_name",""),
             scan_data.get("start_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
             float(scan_data.get("duration_seconds", 0.0)), open_count, len(ports),
             1 if scan_data.get("partial") else 0, int(risk_score),
             scan_data.get("raw_output",""), json.dumps(services),
             scan_data.get("state","unknown"), scan_data.get("hostname",""),
             os_match, scan_data.get("mode_name",""), report_path),
        )
        sid = cur.lastrowid
        for p in ports:
            con.execute(
                "INSERT INTO ports (scan_id,port,protocol,service,state,banner) VALUES(?,?,?,?,?,?)",
                (sid, str(p.get("port","")), str(p.get("proto","tcp")),
                 str(p.get("service","")), str(p.get("state","unknown")), str(p.get("banner",""))),
            )
    return sid

# ── Plugin log ────────────────────────────────────────────────────────────────

def log_plugin(scan_id: Optional[int], target: str, plugin_name: str,
               output: str, duration: float = 0.0,
               success: bool = True, error_msg: str = "") -> int:
    with _db_lock, _conn() as con:
        cur = con.execute(
            """INSERT INTO plugins_log
               (scan_id,target,plugin_name,output,duration,success,error_msg)
               VALUES(?,?,?,?,?,?,?)""",
            (scan_id, target, plugin_name, output,
             duration, 1 if success else 0, error_msg),
        )
        return cur.lastrowid

# ── Report log ────────────────────────────────────────────────────────────────

def log_report(scan_id: Optional[int], target: str,
               fmt: str, filepath: str, success: bool = True) -> None:
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT INTO reports_log (scan_id,target,format,filepath,success) VALUES(?,?,?,?,?)",
            (scan_id, target, fmt, filepath, 1 if success else 0),
        )

# ── Error log ─────────────────────────────────────────────────────────────────

def log_db_error(module: str, target: str, message: str, tb: str = "") -> None:
    try:
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT INTO errors_log (module,target,message,traceback) VALUES(?,?,?,?)",
                (module, target, message, tb),
            )
    except Exception:
        pass

# ── Queries ───────────────────────────────────────────────────────────────────

def get_scan_history(limit: int = 50) -> list[dict]:
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]

def get_scan_by_id(sid: int) -> Optional[dict]:
    with _db_lock, _conn() as con:
        row = con.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return dict(row) if row else None

def get_ports_for_scan(sid: int) -> list[dict]:
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM ports WHERE scan_id=? ORDER BY CAST(port AS INTEGER)", (sid,)
        ).fetchall()
    return [dict(r) for r in rows]

def get_plugin_history(limit: int = 50) -> list[dict]:
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM plugins_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]

def get_report_history(limit: int = 50) -> list[dict]:
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM reports_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]

def get_error_history(limit: int = 50) -> list[dict]:
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM errors_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]

def get_scans_for_target(target: str) -> list[dict]:
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM scans WHERE target=? ORDER BY id ASC", (target,)
        ).fetchall()
    return [dict(r) for r in rows]

def get_stats() -> dict:
    with _db_lock, _conn() as con:
        total    = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        targets  = con.execute("SELECT COUNT(DISTINCT target) FROM scans").fetchone()[0]
        plugins  = con.execute("SELECT COUNT(*) FROM plugins_log").fetchone()[0]
        reports  = con.execute("SELECT COUNT(*) FROM reports_log").fetchone()[0]
        errors   = con.execute("SELECT COUNT(*) FROM errors_log").fetchone()[0]
        avg_dur  = con.execute("SELECT AVG(duration) FROM scans").fetchone()[0] or 0.0
        avg_open = con.execute("SELECT AVG(open_ports) FROM scans").fetchone()[0] or 0.0
        avg_risk = con.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0.0
        last_row = con.execute(
            "SELECT target, timestamp FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    last_scan = f"{last_row['target']} @ {last_row['timestamp']}" if last_row else "—"
    return {
        "total_scans":    total,
        "unique_targets": targets,
        "total_plugins":  plugins,
        "total_reports":  reports,
        "total_errors":   errors,
        "avg_duration_s": round(avg_dur, 1),
        "avg_open_ports": round(avg_open, 1),
        "avg_risk_score": round(avg_risk, 1),
        "last_scan":      last_scan,
    }
