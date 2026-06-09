"""
tests/test_database.py — ShadowPort Scanner v2.1.0
Full database layer test suite.
Uses a temporary DB — never touches production data.
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import db.database as database
from db.database import (
    init_db, save_scan, get_scan_history, get_scan_by_id,
    get_ports_for_scan, get_stats, migrate_schema, log_plugin_run,
)


SAMPLE_SCAN = {
    "host":             "192.168.1.1",
    "hostname":         "router.local",
    "state":            "up",
    "mode_name":        "Quick Scan",
    "start_time":       "2026-06-05 10:00:00",
    "end_time":         "2026-06-05 10:00:15",
    "duration_seconds": 15.0,
    "os_matches":       ["Linux 4.x (95% accuracy)"],
    "partial":          False,
    "raw_output":       "",
    "ports": [
        {"port": "22",  "proto": "tcp", "state": "open",   "service": "ssh",  "version": "OpenSSH 8.9", "banner": ""},
        {"port": "80",  "proto": "tcp", "state": "open",   "service": "http", "version": "Apache 2.4",  "banner": ""},
        {"port": "443", "proto": "tcp", "state": "closed", "service": "https","version": "",             "banner": ""},
    ],
    "risk": {"score": 14, "label": "LOW EXPOSURE", "breakdown": []},
}


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    tmp_db   = str(tmp_path / "test.db")
    tmp_logs = str(tmp_path)
    monkeypatch.setattr(database, "DB_PATH",  tmp_db)
    monkeypatch.setattr(database, "LOGS_DIR", tmp_logs)
    import config.settings as s
    monkeypatch.setattr(s, "DB_PATH",  tmp_db)
    monkeypatch.setattr(s, "LOGS_DIR", tmp_logs)
    init_db()


# ─── migrate_schema ───────────────────────────────────────────────────────────

def test_migrate_schema_idempotent():
    """Running migration twice must not raise or duplicate columns."""
    actions1 = migrate_schema()
    actions2 = migrate_schema()
    assert isinstance(actions1, list)
    assert isinstance(actions2, list)

def test_migrate_adds_missing_columns(tmp_path, monkeypatch):
    """Migration adds partial column to an old-schema database."""
    import sqlite3
    db_path = str(tmp_path / "old.db")
    monkeypatch.setattr(database, "DB_PATH",  db_path)
    monkeypatch.setattr(database, "LOGS_DIR", str(tmp_path))

    # Create a minimal old-style table without 'partial' column
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            scan_type TEXT
        )
    """)
    conn.commit()
    conn.close()

    actions = migrate_schema()
    added = [a for a in actions if "partial" in a]
    assert added, "Expected migration to add 'partial' column"


# ─── save_scan ────────────────────────────────────────────────────────────────

def test_save_scan_returns_int():
    row_id = save_scan(SAMPLE_SCAN, risk_score=14)
    assert isinstance(row_id, int) and row_id >= 1

def test_save_scan_open_count():
    row_id = save_scan(SAMPLE_SCAN, risk_score=14)
    row    = get_scan_by_id(row_id)
    assert row["open_ports"] == 2

def test_save_scan_total_count():
    row_id = save_scan(SAMPLE_SCAN, risk_score=14)
    row    = get_scan_by_id(row_id)
    assert row["total_ports"] == 3

def test_save_scan_partial_false():
    row_id = save_scan(SAMPLE_SCAN, risk_score=14)
    row    = get_scan_by_id(row_id)
    assert row["partial"] == 0

def test_save_scan_partial_true():
    scan = {**SAMPLE_SCAN, "partial": True}
    row_id = save_scan(scan, risk_score=14)
    row    = get_scan_by_id(row_id)
    assert row["partial"] == 1

def test_save_scan_risk_score():
    row_id = save_scan(SAMPLE_SCAN, risk_score=42)
    row    = get_scan_by_id(row_id)
    assert row["risk_score"] == 42

def test_save_scan_creates_port_records():
    row_id = save_scan(SAMPLE_SCAN, risk_score=14)
    ports  = get_ports_for_scan(row_id)
    assert len(ports) == 3

def test_save_scan_port_fields():
    row_id = save_scan(SAMPLE_SCAN, risk_score=14)
    ports  = {p["port"]: p for p in get_ports_for_scan(row_id)}
    assert ports["22"]["service"] == "ssh"
    assert ports["22"]["state"]   == "open"
    assert ports["80"]["service"] == "http"

def test_save_scan_services_json():
    row_id = save_scan(SAMPLE_SCAN, risk_score=14)
    row    = get_scan_by_id(row_id)
    services = json.loads(row["services_json"])
    assert isinstance(services, list)
    assert len(services) == 3

def test_save_scan_no_sql_injection():
    """Target with SQL-like content must be stored safely via parameterized query."""
    evil = "'; DROP TABLE scans; --"
    scan = {**SAMPLE_SCAN, "host": evil}
    row_id = save_scan(scan, risk_score=0)
    row    = get_scan_by_id(row_id)
    assert row is not None
    assert row["target"] == evil


# ─── get_scan_history ─────────────────────────────────────────────────────────

def test_get_scan_history_empty():
    assert get_scan_history() == []

def test_get_scan_history_returns_rows():
    save_scan(SAMPLE_SCAN, risk_score=14)
    save_scan(SAMPLE_SCAN, risk_score=14)
    rows = get_scan_history()
    assert len(rows) == 2

def test_get_scan_history_newest_first():
    id1 = save_scan(SAMPLE_SCAN, risk_score=14)
    id2 = save_scan(SAMPLE_SCAN, risk_score=14)
    rows = get_scan_history()
    assert rows[0]["id"] == id2

def test_get_scan_history_limit():
    for _ in range(5):
        save_scan(SAMPLE_SCAN, risk_score=14)
    assert len(get_scan_history(limit=3)) == 3


# ─── get_stats ────────────────────────────────────────────────────────────────

def test_get_stats_empty():
    stats = get_stats()
    assert stats["total_scans"] == 0
    assert stats["unique_targets"] == 0

def test_get_stats_counts():
    save_scan(SAMPLE_SCAN, risk_score=14)
    save_scan({**SAMPLE_SCAN, "host": "10.0.0.1"}, risk_score=5)
    stats = get_stats()
    assert stats["total_scans"] == 2
    assert stats["unique_targets"] == 2


# ─── log_plugin_run ───────────────────────────────────────────────────────────

def test_log_plugin_run():
    row_id = save_scan(SAMPLE_SCAN, risk_score=0)
    log_plugin_run(row_id, "dns_lookup", "Forward: 192.168.1.1", success=True)
    # No exception = pass
