"""
tests/test_reports.py — ShadowPort Scanner v2.0.0
Unit tests for all 4 report export formats.
"""

import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from reports import save_report
from config.settings import REPORTS_DIR

# ─── Fixture: minimal scan data ───────────────────────────────────────────────

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
        {
            "port": "22", "proto": "tcp", "state": "open",
            "service": "ssh", "version": "OpenSSH 8.9",
            "intel": {"use": "Secure remote shell", "risk": "Ensure key-based auth."},
        },
        {
            "port": "80", "proto": "tcp", "state": "open",
            "service": "http", "version": "Apache 2.4",
            "intel": {"use": "Web server", "risk": "Check for outdated versions."},
        },
        {
            "port": "443", "proto": "tcp", "state": "open",
            "service": "https", "version": "",
            "intel": {"use": "Encrypted web server", "risk": "Inspect TLS version."},
        },
    ],
    "risk": {
        "score":     17,
        "label":     "LOW EXPOSURE",
        "breakdown": ["22/tcp (ssh) +6", "80/tcp (http) +8", "443/tcp (https) +3"],
    },
}

EMPTY_SCAN = {
    "host":             "10.0.0.1",
    "hostname":         "",
    "state":            "down",
    "mode_name":        "Quick Scan",
    "start_time":       "2026-06-04 22:00:00",
    "end_time":         "2026-06-04 22:00:05",
    "duration_seconds": 5.0,
    "os_matches":       [],
    "partial":          False,
    "ports":            [],
    "risk":             {"score": 0, "label": "MINIMAL", "breakdown": []},
}

PARTIAL_SCAN = {**SAMPLE_SCAN, "partial": True}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


# ─── TXT ─────────────────────────────────────────────────────────────────────

def test_txt_creates_file():
    path = save_report(SAMPLE_SCAN, "txt")
    assert path is not None
    assert os.path.exists(path)

def test_txt_contains_host():
    path = save_report(SAMPLE_SCAN, "txt")
    content = _read(path)
    assert "192.168.1.1" in content

def test_txt_contains_ports():
    path = save_report(SAMPLE_SCAN, "txt")
    content = _read(path)
    assert "22/tcp" in content
    assert "ssh" in content

def test_txt_empty_scan():
    path = save_report(EMPTY_SCAN, "txt")
    content = _read(path)
    assert "No open ports" in content

def test_txt_partial_flagged():
    path = save_report(PARTIAL_SCAN, "txt")
    content = _read(path)
    assert "Partial" in content or "partial" in content


# ─── JSON ─────────────────────────────────────────────────────────────────────

def test_json_creates_file():
    path = save_report(SAMPLE_SCAN, "json")
    assert path is not None
    assert path.endswith(".json")

def test_json_is_valid():
    path = save_report(SAMPLE_SCAN, "json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert "scan" in data
    assert "meta" in data

def test_json_host_preserved():
    path = save_report(SAMPLE_SCAN, "json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert data["scan"]["host"] == "192.168.1.1"

def test_json_partial_flag():
    path = save_report(PARTIAL_SCAN, "json")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert data["meta"]["partial"] is True


# ─── XML ─────────────────────────────────────────────────────────────────────

def test_xml_creates_file():
    path = save_report(SAMPLE_SCAN, "xml")
    assert path is not None
    assert path.endswith(".xml")

def test_xml_is_valid_structure():
    path = save_report(SAMPLE_SCAN, "xml")
    content = _read(path)
    assert "<?xml" in content
    assert "<shadowport_scan" in content
    assert "</shadowport_scan>" in content

def test_xml_contains_host():
    path = save_report(SAMPLE_SCAN, "xml")
    content = _read(path)
    assert "192.168.1.1" in content

def test_xml_empty_ports():
    path = save_report(EMPTY_SCAN, "xml")
    content = _read(path)
    assert "<ports>" in content


# ─── HTML ─────────────────────────────────────────────────────────────────────

def test_html_creates_file():
    path = save_report(SAMPLE_SCAN, "html")
    assert path is not None
    assert path.endswith(".html")

def test_html_is_valid():
    path = save_report(SAMPLE_SCAN, "html")
    content = _read(path)
    assert "<!DOCTYPE html>" in content
    assert "</html>" in content

def test_html_contains_host():
    path = save_report(SAMPLE_SCAN, "html")
    content = _read(path)
    assert "192.168.1.1" in content

def test_html_risk_bar():
    path = save_report(SAMPLE_SCAN, "html")
    content = _read(path)
    assert "risk-bar" in content

def test_html_partial_banner():
    path = save_report(PARTIAL_SCAN, "html")
    content = _read(path)
    assert "Partial" in content

def test_html_no_ports_message():
    path = save_report(EMPTY_SCAN, "html")
    content = _read(path)
    assert "No open ports" in content


# ─── Invalid format ───────────────────────────────────────────────────────────

def test_unknown_format_returns_none():
    path = save_report(SAMPLE_SCAN, "pdf")
    assert path is None
