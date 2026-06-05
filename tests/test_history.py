"""
tests/test_history.py — ShadowPort Scanner v2.0.0
Unit tests for SQLite scan history functions.
Uses a temporary database so it never touches production data.
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import database


# ─── Fixtures ─────────────────────────────────────────────────────────────────

SAMPLE_SCAN = {
    "host":             "192.168.1.1",
    "hostname":         "router.local",
    "state":            "up",
    "mode_name":        "Quick Scan",
    "start_time":       "2026-06-04 22:00:00",
    "end_time":         "2026-06-04 22:00:15",
    "duration_seconds": 15.0,
    "os_matches":       ["Linux 4.x (95% accuracy)"],
    "partial":          False,
    "ports": [
        {"port": "22", "proto": "tcp", "state": "open",   "service": "ssh",  "version": ""},
        {"port": "80", "proto": "tcp", "state": "closed", "service": "http", "version": ""},
    ],
    "risk": {"score": 6, "label": "LOW EXPOSURE", "breakdown": ["22/tcp (ssh) +6"]},
}


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Redirect all DB operations to a temporary file."""
    tmp_db   = str(tmp_path / "test.db")
    tmp_logs = str(tmp_path)
    monkeypatch.setattr(database, "DB_PATH",  tmp_db)
    monkeypatch.setattr(database, "LOGS_DIR", tmp_logs)
    # Also patch the settings import inside database
    import config.settings as settings
    monkeypatch.setattr(settings, "DB_PATH",  tmp_db)
    monkeypatch.setattr(settings, "LOGS_DIR", tmp_logs)


# ─── save_scan ────────────────────────────────────────────────────────────────

def test_save_scan_returns_id():
    row_id = database.save_scan(SAMPLE_SCAN, risk_score=6)
    assert isinstance(row_id, int)
    assert row_id >= 1

def test_save_scan_increments_id():
    id1 = database.save_scan(SAMPLE_SCAN, risk_score=6)
    id2 = database.save_scan(SAMPLE_SCAN, risk_score=6)
    assert id2 == id1 + 1

def test_save_scan_open_count():
    row_id = database.save_scan(SAMPLE_SCAN, risk_score=6)
    row    = database.get_scan_by_id(row_id)
    assert row["open_count"] == 1  # only port 22 is open

def test_save_scan_partial_flag():
    scan = {**SAMPLE_SCAN, "partial": True}
    row_id = database.save_scan(scan, risk_score=6)
    row    = database.get_scan_by_id(row_id)
    assert row["partial"] == 1


# ─── get_history ──────────────────────────────────────────────────────────────

def test_get_history_empty():
    rows = database.get_history()
    assert rows == []

def test_get_history_returns_rows():
    database.save_scan(SAMPLE_SCAN, risk_score=6)
    database.save_scan(SAMPLE_SCAN, risk_score=6)
    rows = database.get_history()
    assert len(rows) == 2

def test_get_history_newest_first():
    id1 = database.save_scan(SAMPLE_SCAN, risk_score=6)
    id2 = database.save_scan(SAMPLE_SCAN, risk_score=6)
    rows = database.get_history()
    assert rows[0]["id"] == id2  # newest first

def test_get_history_limit():
    for _ in range(5):
        database.save_scan(SAMPLE_SCAN, risk_score=6)
    rows = database.get_history(limit=3)
    assert len(rows) == 3


# ─── get_scan_by_id ───────────────────────────────────────────────────────────

def test_get_scan_by_id_found():
    row_id = database.save_scan(SAMPLE_SCAN, risk_score=6)
    row    = database.get_scan_by_id(row_id)
    assert row is not None
    assert row["target"] == "192.168.1.1"

def test_get_scan_by_id_not_found():
    row = database.get_scan_by_id(99999)
    assert row is None


# ─── compare_scans ────────────────────────────────────────────────────────────

def test_compare_needs_two_scans():
    database.save_scan(SAMPLE_SCAN, risk_score=6)
    result = database.compare_scans("192.168.1.1")
    assert result is None  # only one scan

def test_compare_two_scans():
    database.save_scan(SAMPLE_SCAN, risk_score=6)
    scan2 = {**SAMPLE_SCAN, "ports": [
        {"port": "22",   "proto": "tcp", "state": "open", "service": "ssh",   "version": ""},
        {"port": "3306", "proto": "tcp", "state": "open", "service": "mysql", "version": ""},
    ]}
    database.save_scan(scan2, risk_score=20)
    result = database.compare_scans("192.168.1.1")
    assert result is not None
    assert "3306" in result["new_ports"]

def test_compare_closed_ports():
    scan1 = {**SAMPLE_SCAN, "ports": [
        {"port": "22", "proto": "tcp", "state": "open", "service": "ssh", "version": ""},
        {"port": "80", "proto": "tcp", "state": "open", "service": "http", "version": ""},
    ]}
    scan2 = {**SAMPLE_SCAN, "ports": [
        {"port": "22", "proto": "tcp", "state": "open", "service": "ssh", "version": ""},
    ]}
    database.save_scan(scan1, risk_score=14)
    database.save_scan(scan2, risk_score=6)
    result = database.compare_scans("192.168.1.1")
    assert "80" in result["closed_ports"]


# ─── get_stats ────────────────────────────────────────────────────────────────

def test_get_stats_empty():
    stats = database.get_stats()
    assert stats["total_scans"] == 0
    assert stats["unique_targets"] == 0

def test_get_stats_counts():
    database.save_scan(SAMPLE_SCAN, risk_score=6)
    database.save_scan({**SAMPLE_SCAN, "host": "10.0.0.1"}, risk_score=6)
    stats = database.get_stats()
    assert stats["total_scans"] == 2
    assert stats["unique_targets"] == 2
