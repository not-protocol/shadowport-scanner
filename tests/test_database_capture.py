"""tests/test_database_capture.py — ShadowPort Scanner v2.4.0

Covers the v2.4 `captures` table additions to db/database.py, using the
exact same temp_db fixture pattern as tests/test_database.py.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import db.database as database
from db.database import init_db, log_capture, get_capture_history, get_stats


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    logs    = str(tmp_path)
    monkeypatch.setattr(database, "DB_PATH", db_path)
    monkeypatch.setattr(database, "LOG_DIR", logs)
    import config.settings as s
    monkeypatch.setattr(s, "DB_PATH", db_path)
    monkeypatch.setattr(s, "LOG_DIR", logs)
    init_db()


def test_log_capture_returns_id():
    cap_id = log_capture("eth0", "tcp port 443", "", 30.5, 120, "/tmp/cap.pcapng", "stopped")
    assert isinstance(cap_id, int) and cap_id >= 1

def test_get_capture_history_returns_logged_row():
    log_capture("eth0", "tcp port 443", "", 30.5, 120, "/tmp/cap.pcapng", "stopped")
    history = get_capture_history()
    assert len(history) == 1
    assert history[0]["interface"] == "eth0"
    assert history[0]["packet_count"] == 120
    assert history[0]["status"] == "stopped"

def test_capture_history_newest_first():
    log_capture("eth0", "", "", 1.0, 1, "/tmp/a.pcapng", "stopped")
    log_capture("wlan0", "", "", 2.0, 2, "/tmp/b.pcapng", "stopped")
    history = get_capture_history()
    assert history[0]["interface"] == "wlan0"
    assert history[1]["interface"] == "eth0"

def test_capture_history_limit():
    for i in range(5):
        log_capture("eth0", "", "", 1.0, i, f"/tmp/{i}.pcapng", "stopped")
    assert len(get_capture_history(limit=3)) == 3

def test_filepath_accepts_pathlib_path():
    from pathlib import Path
    p = Path("/tmp/from_path.pcapng")
    cap_id = log_capture("eth0", "", "", 1.0, 1, p, "stopped")
    history = get_capture_history()
    matching = [r for r in history if r["id"] == cap_id]
    assert matching
    assert matching[0]["file_path"] == str(p)

def test_capture_sql_injection_safe():
    evil = "'; DROP TABLE captures; --"
    log_capture("eth0", evil, "", 1.0, 0, "/tmp/x.pcapng", "stopped")
    history = get_capture_history()
    assert history[0]["bpf_filter"] == evil
    assert get_capture_history() != []  # table still exists

def test_stats_includes_total_captures():
    log_capture("eth0", "", "", 1.0, 1, "/tmp/a.pcapng", "stopped")
    log_capture("wlan0", "", "", 1.0, 1, "/tmp/b.pcapng", "stopped")
    stats = get_stats()
    assert stats["total_captures"] == 2

def test_schema_version_is_5():
    import config.settings as s
    assert s.SCHEMA_VERSION == 5

def test_migration_adds_captures_to_old_db(tmp_path, monkeypatch):
    """A real v2.3 DB (no captures table) must gain it via migrate_schema()."""
    import sqlite3
    p = str(tmp_path / "old_v23.db")
    monkeypatch.setattr(database, "DB_PATH", p)
    monkeypatch.setattr(database, "LOG_DIR", str(tmp_path))

    con = sqlite3.connect(p)
    con.execute(database._CREATE_SCANS)
    con.execute(database._CREATE_PORTS)
    con.execute(database._CREATE_PLUGINS_LOG)
    con.execute(database._CREATE_REPORTS_LOG)
    con.execute(database._CREATE_ERRORS_LOG)
    con.execute(database._CREATE_SCAN_STATISTICS)
    con.commit()
    tables_before = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    assert "captures" not in tables_before

    database.migrate_schema()

    con = sqlite3.connect(p)
    tables_after = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    indexes_after = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    con.close()
    assert "captures" in tables_after
    assert "idx_captures_timestamp" in indexes_after
