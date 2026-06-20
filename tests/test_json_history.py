"""tests/test_json_history.py — ShadowPort Scanner v2.3.0"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import core.json_history as jh
from core.json_history import record_scan, record_plugin, record_report, get_history


SCAN = {
    "host": "192.168.1.1", "mode_name": "Quick Scan", "state": "up",
    "partial": False,
    "ports": [
        {"port":"22","proto":"tcp","state":"open","service":"ssh"},
        {"port":"80","proto":"tcp","state":"closed","service":"http"},
    ],
}


@pytest.fixture(autouse=True)
def temp_json(tmp_path, monkeypatch):
    path = str(tmp_path / "history.json")
    monkeypatch.setattr(jh, "JSON_HIST", path)
    monkeypatch.setattr(jh, "LOG_DIR",   str(tmp_path))
    import config.settings as s
    monkeypatch.setattr(s, "JSON_HIST", path)
    monkeypatch.setattr(s, "LOG_DIR",   str(tmp_path))


def test_empty_history():
    assert get_history() == []

def test_record_scan_creates_entry():
    record_scan(SCAN, risk_score=14)
    hist = get_history()
    assert len(hist) == 1
    assert hist[0]["type"] == "scan"
    assert hist[0]["target"] == "192.168.1.1"
    assert hist[0]["open_ports"] == 1
    assert hist[0]["risk_score"] == 14

def test_record_plugin_creates_entry():
    record_plugin("192.168.1.1", "dns_lookup", "Forward: 1.2.3.4", True)
    hist = get_history()
    assert hist[0]["type"] == "plugin"
    assert hist[0]["plugin"] == "dns_lookup"
    assert hist[0]["success"] is True

def test_record_report_creates_entry():
    record_report("192.168.1.1", "html", "/reports/scan.html")
    hist = get_history()
    assert hist[0]["type"] == "report"
    assert hist[0]["format"] == "html"

def test_history_newest_first():
    record_scan(SCAN, 0)
    record_plugin("x", "y", "z", True)
    hist = get_history()
    assert hist[0]["type"] == "plugin"
    assert hist[1]["type"] == "scan"

def test_history_limit():
    for i in range(10):
        record_plugin("x", f"plugin{i}", "out", True)
    hist = get_history(limit=5)
    assert len(hist) == 5

def test_file_is_valid_json(tmp_path):
    record_scan(SCAN, 0)
    with open(jh.JSON_HIST, encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list)
    assert len(data) == 1

def test_plugin_preview_truncated():
    record_plugin("x", "y", "z" * 500, True)
    hist = get_history()
    assert len(hist[0]["preview"]) <= 120
