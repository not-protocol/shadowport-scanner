"""
tests/test_service_kb.py — ShadowPort Scanner v2.1.0
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from core.service_kb import get_service_info, get_all_known_ports, format_service_info


def test_known_port_ssh():
    info = get_service_info(22)
    assert info.name == "SSH"
    assert info.default_port == 22
    assert info.risk_level == "medium"

def test_known_port_telnet_critical():
    info = get_service_info(23)
    assert info.risk_level == "critical"

def test_known_port_redis_critical():
    info = get_service_info(6379)
    assert info.risk_level == "critical"

def test_unknown_port_returns_fallback():
    info = get_service_info(54321)
    assert info.name == "Unknown"

def test_all_known_ports_non_empty():
    ports = get_all_known_ports()
    assert len(ports) > 0
    assert 22 in ports
    assert 443 in ports

def test_format_output_is_string():
    out = format_service_info(80)
    assert isinstance(out, str)
    assert "HTTP" in out

def test_string_port_coerced():
    info = get_service_info(int("443"))
    assert info.name == "HTTPS"
