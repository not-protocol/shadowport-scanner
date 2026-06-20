"""tests/test_validation.py — ShadowPort Scanner v2.3.0"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from core.scanner_engine import validate_target


@pytest.mark.parametrize("target", [
    "192.168.1.1", "10.0.0.1", "0.0.0.0", "255.255.255.255",
    "192.168.1.0/24", "0.0.0.0/0", "192.168.1.1/32",
    "scanme.nmap.org", "google.com", "sub.domain.co.uk",
])
def test_valid(target):
    ok, reason = validate_target(target)
    assert ok, f"{target!r} should be valid: {reason}"


@pytest.mark.parametrize("target", [
    "", " ", "1", "abc", "hello world",
    "999.999.999.999", "192.168", "192.168.1",
    "256.0.0.1", "@@@@", "192.168.1.0/33", "999.0.0.0/24",
])
def test_invalid(target):
    ok, reason = validate_target(target)
    assert not ok
    assert reason


@pytest.mark.parametrize("target", [
    "; rm -rf /", "192.168.1.1; ls", "| cat /etc/passwd",
    "`whoami`", "$(id)", "192.168.1.1 && reboot",
    "1.1.1.1\nrm -rf /", "target\r\n",
])
def test_shell_injection_rejected(target):
    ok, _ = validate_target(target)
    assert not ok


@pytest.mark.parametrize("target", [
    "héllo.com", "目标.com", "тест.рф",
])
def test_unicode_rejected(target):
    ok, _ = validate_target(target)
    assert not ok
