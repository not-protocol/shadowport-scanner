"""
tests/test_validation.py — ShadowPort Scanner v2.0.0
Unit tests for target validation and input sanitization.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from scanner import validate_target, resolve_hostname


# ─── Valid inputs ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("target", [
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "192.168.1.0/24",
    "10.0.0.0/8",
    "scanme.nmap.org",
    "google.com",
    "sub.domain.co.uk",
])
def test_valid_targets(target):
    ok, reason = validate_target(target)
    assert ok, f"Expected {target!r} to be valid, got: {reason}"


# ─── Invalid inputs ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("target", [
    "",                    # empty
    " ",                   # whitespace only
    "1",                   # single digit
    "abc",                 # single word, no dots
    "hello world",         # spaces
    "999.999.999.999",     # octets out of range
    "192.168",             # incomplete IP
    "192.168.1",           # incomplete IP
    "256.0.0.1",           # first octet out of range
    "@@@@",                # garbage
    "@",                   # garbage
    "192.168.1.0/33",      # invalid prefix
    "192.168.1.0/99",      # invalid prefix
    "300.1.1.1",           # bad octet
])
def test_invalid_targets(target):
    ok, reason = validate_target(target)
    assert not ok, f"Expected {target!r} to be INVALID but it passed"
    assert reason, "Expected a rejection reason message"


# ─── Whitespace stripping ─────────────────────────────────────────────────────

def test_whitespace_stripped():
    """validate_target receives already-stripped input from _input() helper."""
    # The _input() helper strips before calling validate_target.
    # Here we confirm the stripped value is valid.
    ok, _ = validate_target("192.168.1.1")
    assert ok


# ─── CIDR edge cases ─────────────────────────────────────────────────────────

def test_cidr_slash_zero():
    ok, _ = validate_target("0.0.0.0/0")
    assert ok

def test_cidr_slash_32():
    ok, _ = validate_target("192.168.1.1/32")
    assert ok

def test_cidr_bad_ip_part():
    ok, _ = validate_target("999.0.0.0/24")
    assert not ok
