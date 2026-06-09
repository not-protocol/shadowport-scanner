"""
tests/test_change_detector.py — ShadowPort Scanner v2.1.0
Change detection tests using temporary SQLite database.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import db.database as database
from db.database import init_db, save_scan
from core.change_detector import compare_scans, format_change_report


def _make_scan(ports_open: list[str], host: str = "10.0.0.1") -> dict:
    ports = [
        {"port": p, "proto": "tcp", "state": "open", "service": "ssh", "version": "", "banner": ""}
        for p in ports_open
    ]
    return {
        "host": host, "hostname": "", "state": "up",
        "mode_name": "Quick Scan", "start_time": "2026-06-05 10:00:00",
        "end_time": "2026-06-05 10:00:10", "duration_seconds": 10.0,
        "os_matches": [], "partial": False, "raw_output": "",
        "ports": ports,
        "risk": {"score": 0, "label": "MINIMAL", "breakdown": []},
    }


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    logs    = str(tmp_path)
    monkeypatch.setattr(database, "DB_PATH",  db_path)
    monkeypatch.setattr(database, "LOGS_DIR", logs)
    import config.settings as s
    monkeypatch.setattr(s, "DB_PATH",  db_path)
    monkeypatch.setattr(s, "LOGS_DIR", logs)
    init_db()


def test_no_changes():
    id1 = save_scan(_make_scan(["22", "80"]))
    id2 = save_scan(_make_scan(["22", "80"]))
    r   = compare_scans(id1, id2)
    assert not r.new_ports
    assert not r.closed_ports
    assert not r.has_changes

def test_new_port_detected():
    id1 = save_scan(_make_scan(["22"]))
    id2 = save_scan(_make_scan(["22", "80"]))
    r   = compare_scans(id1, id2)
    assert len(r.new_ports) == 1
    assert r.new_ports[0].port == "80"
    assert r.has_changes

def test_closed_port_detected():
    id1 = save_scan(_make_scan(["22", "80"]))
    id2 = save_scan(_make_scan(["22"]))
    r   = compare_scans(id1, id2)
    assert len(r.closed_ports) == 1
    assert r.closed_ports[0].port == "80"

def test_unchanged_ports():
    id1 = save_scan(_make_scan(["22", "80"]))
    id2 = save_scan(_make_scan(["22", "80", "443"]))
    r   = compare_scans(id1, id2)
    unchanged_ports = [p.port for p in r.unchanged_ports]
    assert "22" in unchanged_ports
    assert "80" in unchanged_ports

def test_missing_scan_returns_error():
    r = compare_scans(9999, 9998)
    assert r.error is not None

def test_format_report_no_changes():
    id1 = save_scan(_make_scan(["22"]))
    id2 = save_scan(_make_scan(["22"]))
    r   = compare_scans(id1, id2)
    out = format_change_report(r)
    assert "No changes" in out

def test_format_report_shows_new_port():
    id1 = save_scan(_make_scan(["22"]))
    id2 = save_scan(_make_scan(["22", "3306"]))
    r   = compare_scans(id1, id2)
    out = format_change_report(r)
    assert "3306" in out

def test_format_report_error():
    r = compare_scans(9999, 9998)
    out = format_change_report(r)
    assert "Error" in out or "not found" in out.lower()
