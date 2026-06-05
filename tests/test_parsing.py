"""
tests/test_parsing.py — ShadowPort Scanner v2.0.0
Unit tests for port enrichment and risk scoring.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from scanner import enrich_port, calculate_risk


# ─── enrich_port ─────────────────────────────────────────────────────────────

def test_enrich_known_service():
    port = {"port": "22", "proto": "tcp", "state": "open", "service": "ssh", "version": ""}
    result = enrich_port(port)
    assert "intel" in result
    assert result["intel"]["use"] != ""
    assert result["intel"]["risk"] != ""

def test_enrich_unknown_service():
    port = {"port": "9999", "proto": "tcp", "state": "open", "service": "unknownthing", "version": ""}
    result = enrich_port(port)
    assert "intel" in result
    # Falls back to "unknown" intel
    assert result["intel"] is not None

def test_enrich_preserves_original_fields():
    port = {"port": "80", "proto": "tcp", "state": "open", "service": "http", "version": "Apache 2.4"}
    result = enrich_port(port)
    assert result["port"] == "80"
    assert result["version"] == "Apache 2.4"

def test_enrich_http():
    port = {"port": "80", "proto": "tcp", "state": "open", "service": "http", "version": ""}
    result = enrich_port(port)
    assert "web" in result["intel"]["use"].lower() or "http" in result["intel"]["use"].lower()


# ─── calculate_risk ───────────────────────────────────────────────────────────

def _make_port(service, state="open"):
    return {"port": "1", "proto": "tcp", "state": state, "service": service, "version": ""}

def test_risk_no_open_ports():
    risk = calculate_risk([])
    assert risk["score"] == 0
    assert risk["label"] == "MINIMAL"
    assert risk["breakdown"] == []

def test_risk_closed_ports_not_counted():
    ports = [_make_port("telnet", state="closed")]
    risk  = calculate_risk(ports)
    assert risk["score"] == 0

def test_risk_telnet_high():
    ports = [_make_port("telnet")]
    risk  = calculate_risk(ports)
    assert risk["score"] >= 20

def test_risk_https_low():
    ports = [_make_port("https")]
    risk  = calculate_risk(ports)
    assert risk["score"] <= 10

def test_risk_capped_at_100():
    ports = [_make_port(svc) for svc in
             ["telnet", "rdp", "ftp", "smb", "vnc", "redis", "mongodb", "mysql", "mssql"]]
    risk = calculate_risk(ports)
    assert risk["score"] <= 100

def test_risk_label_high():
    ports = [_make_port(s) for s in ["telnet", "rdp", "ftp", "smb"]]
    risk  = calculate_risk(ports)
    assert risk["label"] in ("HIGH EXPOSURE", "MEDIUM EXPOSURE")

def test_risk_breakdown_entries():
    ports = [_make_port("ssh"), _make_port("http")]
    risk  = calculate_risk(ports)
    assert len(risk["breakdown"]) == 2

def test_risk_unknown_service_default_weight():
    ports = [_make_port("mycustomservice")]
    risk  = calculate_risk(ports)
    assert risk["score"] == 4  # default weight
