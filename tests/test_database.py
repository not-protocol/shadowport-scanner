"""tests/test_database.py — ShadowPort Scanner v2.3.0"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import db.database as database
from db.database import (
    init_db, save_scan, get_scan_by_id, get_ports_for_scan,
    get_scan_history, get_stats, log_plugin, log_report,
    get_plugin_history, get_report_history, log_db_error,
    get_error_history, migrate_schema,
)


SAMPLE = {
    "host": "192.168.1.1", "hostname": "router.local", "state": "up",
    "mode_name": "Quick Scan", "start_time": "2026-06-05 10:00:00",
    "end_time": "2026-06-05 10:00:15", "duration_seconds": 15.0,
    "os_matches": ["Linux 4.x (95% accuracy)"], "partial": False, "raw_output": "",
    "ports": [
        {"port":"22","proto":"tcp","state":"open","service":"ssh","version":"OpenSSH","banner":""},
        {"port":"80","proto":"tcp","state":"open","service":"http","version":"Apache","banner":""},
        {"port":"443","proto":"tcp","state":"closed","service":"https","version":"","banner":""},
    ],
    "risk": {"score": 14, "label": "LOW EXPOSURE", "breakdown": []},
}


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    logs    = str(tmp_path)
    monkeypatch.setattr(database, "DB_PATH",  db_path)
    monkeypatch.setattr(database, "LOG_DIR",  logs)
    import config.settings as s
    monkeypatch.setattr(s, "DB_PATH", db_path)
    monkeypatch.setattr(s, "LOG_DIR", logs)
    init_db()


# ── migration ─────────────────────────────────────────────────────────────────

def test_migrate_idempotent():
    a1 = migrate_schema()
    a2 = migrate_schema()
    assert isinstance(a1, list) and isinstance(a2, list)

def test_migrate_adds_missing_columns(tmp_path, monkeypatch):
    import sqlite3
    p = str(tmp_path / "old.db")
    monkeypatch.setattr(database, "DB_PATH", p)
    monkeypatch.setattr(database, "LOG_DIR", str(tmp_path))
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT)")
    con.commit(); con.close()
    actions = migrate_schema()
    assert any("partial" in a for a in actions)


# ── save_scan ─────────────────────────────────────────────────────────────────

def test_save_scan_id():
    sid = save_scan(SAMPLE, risk_score=14)
    assert isinstance(sid, int) and sid >= 1

def test_open_count():
    sid = save_scan(SAMPLE, risk_score=14)
    row = get_scan_by_id(sid)
    assert row["open_ports"] == 2

def test_total_count():
    sid = save_scan(SAMPLE, risk_score=14)
    assert get_scan_by_id(sid)["total_ports"] == 3

def test_partial_flag():
    sid = save_scan({**SAMPLE, "partial": True}, risk_score=0)
    assert get_scan_by_id(sid)["partial"] == 1

def test_ports_table_populated():
    sid = save_scan(SAMPLE, risk_score=14)
    ports = get_ports_for_scan(sid)
    assert len(ports) == 3
    assert {p["port"] for p in ports} == {"22","80","443"}

def test_services_json_valid():
    sid = save_scan(SAMPLE, risk_score=14)
    services = json.loads(get_scan_by_id(sid)["services_json"])
    assert len(services) == 3

def test_sql_injection_safe():
    evil = "'; DROP TABLE scans; --"
    sid = save_scan({**SAMPLE, "host": evil}, risk_score=0)
    row = get_scan_by_id(sid)
    assert row["target"] == evil
    # table still exists
    assert get_scan_history() != []


# ── history ───────────────────────────────────────────────────────────────────

def test_history_empty():
    assert get_scan_history() == []

def test_history_newest_first():
    id1 = save_scan(SAMPLE, risk_score=0)
    id2 = save_scan(SAMPLE, risk_score=0)
    rows = get_scan_history()
    assert rows[0]["id"] == id2

def test_history_limit():
    for _ in range(5):
        save_scan(SAMPLE, risk_score=0)
    assert len(get_scan_history(limit=3)) == 3


# ── plugins_log ───────────────────────────────────────────────────────────────

def test_log_plugin():
    sid = save_scan(SAMPLE, risk_score=0)
    pid = log_plugin(sid, "192.168.1.1", "dns_lookup", "output text", 1.2, True, "")
    assert isinstance(pid, int)
    rows = get_plugin_history()
    assert rows[0]["plugin_name"] == "dns_lookup"
    assert rows[0]["success"] == 1

def test_log_plugin_failure():
    log_plugin(None, "10.0.0.1", "broken_plugin", "", 0.1, False, "boom")
    rows = get_plugin_history()
    assert rows[0]["success"] == 0
    assert rows[0]["error_msg"] == "boom"


# ── reports_log ───────────────────────────────────────────────────────────────

def test_log_report():
    sid = save_scan(SAMPLE, risk_score=0)
    log_report(sid, "192.168.1.1", "html", "/path/to/report.html", True)
    rows = get_report_history()
    assert rows[0]["format"] == "html"
    assert rows[0]["success"] == 1


# ── errors_log ────────────────────────────────────────────────────────────────

def test_log_error():
    log_db_error("scanner", "10.0.0.5", "DNS failed", "traceback text")
    rows = get_error_history()
    assert rows[0]["module"] == "scanner"
    assert rows[0]["message"] == "DNS failed"


# ── stats ─────────────────────────────────────────────────────────────────────

def test_stats_empty():
    s = get_stats()
    assert s["total_scans"] == 0
    assert s["last_scan"] == "—"

def test_stats_counts():
    save_scan(SAMPLE, risk_score=14)
    save_scan({**SAMPLE, "host": "10.0.0.1"}, risk_score=5)
    s = get_stats()
    assert s["total_scans"] == 2
    assert s["unique_targets"] == 2
    assert "10.0.0.1" in s["last_scan"] or "192.168.1.1" in s["last_scan"]
