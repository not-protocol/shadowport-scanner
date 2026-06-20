"""tests/test_reports.py — ShadowPort Scanner v2.3.0"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import reports as reports_mod
import db.database as database
import core.json_history as jh
from reports import save_report


SAMPLE = {
    "host": "192.168.1.1", "hostname": "router.local", "state": "up",
    "mode_name": "Quick Scan", "start_time": "2026-06-05 10:00:00",
    "end_time": "2026-06-05 10:00:15", "duration_seconds": 15.0,
    "os_matches": ["Linux 4.x (95% accuracy)"], "partial": False,
    "ports": [
        {"port":"22","proto":"tcp","state":"open","service":"ssh","version":"OpenSSH 8.9",
         "intel":{"use":"Secure shell","risk":"Use key auth"}},
        {"port":"443","proto":"tcp","state":"closed","service":"https","version":""},
    ],
    "risk": {"score": 6, "label": "LOW EXPOSURE", "breakdown": ["22/tcp (ssh) +6"]},
}

EMPTY = {**SAMPLE, "ports": [], "risk": {"score":0,"label":"MINIMAL","breakdown":[]}}
PARTIAL = {**SAMPLE, "partial": True}


@pytest.fixture(autouse=True)
def temp_paths(tmp_path, monkeypatch):
    reports_dir = str(tmp_path / "reports")
    logs_dir    = str(tmp_path / "Log")
    db_path     = str(tmp_path / "Log" / "test.db")
    json_path   = str(tmp_path / "Log" / "history.json")

    for mod, mapping in [
        (reports_mod, {"REPORTS_DIR": reports_dir, "LOG_DIR": logs_dir}),
        (database,    {"DB_PATH": db_path, "LOG_DIR": logs_dir}),
        (jh,          {"JSON_HIST": json_path, "LOG_DIR": logs_dir}),
    ]:
        for k, v in mapping.items():
            monkeypatch.setattr(mod, k, v)

    import config.settings as s
    monkeypatch.setattr(s, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(s, "LOG_DIR", logs_dir)
    monkeypatch.setattr(s, "DB_PATH", db_path)
    monkeypatch.setattr(s, "JSON_HIST", json_path)

    database.init_db()


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


# ── TXT ───────────────────────────────────────────────────────────────────────

def test_txt_created():
    p = save_report(SAMPLE, "txt")
    assert p and os.path.exists(p)

def test_txt_contains_host():
    p = save_report(SAMPLE, "txt")
    assert "192.168.1.1" in _read(p)

def test_txt_empty_ports():
    p = save_report(EMPTY, "txt")
    assert "No open ports" in _read(p)

def test_txt_partial_flag():
    p = save_report(PARTIAL, "txt")
    assert "Partial" in _read(p) or "partial" in _read(p)


# ── JSON ──────────────────────────────────────────────────────────────────────

def test_json_valid():
    p = save_report(SAMPLE, "json")
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    assert data["scan"]["host"] == "192.168.1.1"
    assert "meta" in data

def test_json_partial_meta():
    p = save_report(PARTIAL, "json")
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    assert data["meta"]["partial"] is True


# ── XML ───────────────────────────────────────────────────────────────────────

def test_xml_structure():
    p = save_report(SAMPLE, "xml")
    content = _read(p)
    assert "<?xml" in content
    assert "<shadowport_scan" in content
    assert "</shadowport_scan>" in content

def test_xml_host_present():
    p = save_report(SAMPLE, "xml")
    assert "192.168.1.1" in _read(p)


# ── HTML ──────────────────────────────────────────────────────────────────────

def test_html_valid():
    p = save_report(SAMPLE, "html")
    content = _read(p)
    assert "<!DOCTYPE html>" in content
    assert "</html>" in content

def test_html_risk_bar():
    p = save_report(SAMPLE, "html")
    assert "risk-bar" in _read(p)

def test_html_partial_banner():
    p = save_report(PARTIAL, "html")
    assert "Partial" in _read(p)

def test_html_no_ports_message():
    p = save_report(EMPTY, "html")
    assert "No open ports" in _read(p)


# ── unknown format ───────────────────────────────────────────────────────────

def test_unknown_format_returns_none():
    assert save_report(SAMPLE, "pdf") is None


# ── DB + JSON logging integration ────────────────────────────────────────────

def test_report_logged_to_db():
    sid = database.save_scan(SAMPLE, risk_score=6)
    save_report(SAMPLE, "html", scan_id=sid)
    rows = database.get_report_history()
    assert rows[0]["format"] == "html"
    assert rows[0]["success"] == 1

def test_report_logged_to_json():
    save_report(SAMPLE, "txt")
    hist = jh.get_history()
    assert hist[0]["type"] == "report"
    assert hist[0]["format"] == "txt"
