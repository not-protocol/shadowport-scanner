"""tests/test_capture_view_filters.py — ShadowPort Scanner v2.4.0

Covers CaptureView's structured filter row (protocol/port/IP -> BPF string),
field validation, and protocol-based packet-row coloring — the
Wireshark-style filter UI added on top of the original free-text BPF box.

CaptureView itself subclasses textual.containers.Vertical, so a full
import requires `textual` to be installed. The logic under test here
(build_bpf_filter, validate_ip_field, validate_port_field,
_color_for_protocol) only touches `self.query_one(...)` and plain Python —
no textual-specific behavior — so these tests exercise it through a
lightweight fake `self` that implements just `query_one`, keeping the
suite runnable even without `textual` present (e.g. in CI stages that
only check business logic, or this project's own authoring sandbox).
"""

import sys, os, ast, textwrap
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

MAIN_PY = os.path.join(os.path.dirname(os.path.dirname(__file__)), "main.py")


def _extract_capture_view_methods(*names):
    """Pull the literal source of named CaptureView methods out of main.py.

    Returns a dict {name: source_text}. Used to exec the exact bytecode
    that ships in main.py against a fake harness, rather than maintaining
    a hand-copied duplicate that could silently drift from the real code.
    """
    with open(MAIN_PY, encoding="utf-8") as f:
        source = f.read()
    lines = source.splitlines(keepends=True)
    tree = ast.parse(source)
    capture_view = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name == "CaptureView"
    )
    found = {}
    for node in capture_view.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            found[node.name] = "".join(lines[node.lineno - 1:node.end_lineno])
    missing = set(names) - found.keys()
    assert not missing, f"Could not find method(s) in CaptureView: {missing}"
    return found


class _FakeWidget:
    def __init__(self, value):
        self.value = value


class _FakeNoMatches(Exception):
    pass


def _make_harness():
    """Build a Harness class with the real extracted methods attached."""
    extracted = _extract_capture_view_methods(
        "build_bpf_filter", "validate_ip_field", "validate_port_field",
        "_color_for_protocol",
    )

    class Harness:
        _PROTOCOL_BPF = {
            "any": (None, None), "tcp": ("tcp", None), "udp": ("udp", None),
            "dns": ("udp", 53), "http": ("tcp", 80), "https": ("tcp", 443),
            "icmp": ("icmp", None),
        }
        _SHELL_CHARS = set(";|&`$()<>\n\r")
        PROTOCOL_COLORS = {
            "TCP": "#4fc3f7", "UDP": "#81c784", "DNS": "#ffd54f",
            "HTTP": "#aed581", "TLS": "#ce93d8", "ICMP": "#ff8a65",
            "ARP": "#90a4ae",
        }
        DEFAULT_ROW_COLOR = "#c9d1e0"

        def __init__(self, protocol=None, port="", ip=""):
            self._protocol, self._port, self._ip = protocol, port, ip

        def query_one(self, selector, widget_type=None):
            if selector == "#capture-protocol-select":
                return _FakeWidget(self._protocol)
            if selector == "#capture-port-input":
                return _FakeWidget(self._port)
            if selector == "#capture-ip-input":
                return _FakeWidget(self._ip)
            raise _FakeNoMatches()

    namespace = {"NoMatches": _FakeNoMatches, "Select": object, "Input": object}
    for name, src in extracted.items():
        exec(textwrap.dedent(src), namespace)
        setattr(Harness, name, namespace[name])

    return Harness


@pytest.fixture(scope="module")
def Harness():
    return _make_harness()


# ── build_bpf_filter ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("protocol,port,ip,expected", [
    ("any",   "",     "",            ""),
    ("tcp",   "",     "",            "tcp"),
    ("tcp",   "443",  "",            "tcp port 443"),
    ("udp",   "53",   "",            "udp port 53"),
    ("dns",   "",     "",            "udp port 53"),
    ("dns",   "5353", "",            "udp port 5353"),
    ("http",  "",     "",            "tcp port 80"),
    ("https", "",     "192.168.1.1", "tcp port 443 and host 192.168.1.1"),
    ("icmp",  "",     "10.0.0.1",    "icmp and host 10.0.0.1"),
    ("any",   "",     "10.0.0.1",    "host 10.0.0.1"),
    ("any",   "8080", "",            "port 8080"),
])
def test_build_bpf_filter(Harness, protocol, port, ip, expected):
    h = Harness(protocol, port, ip)
    assert h.build_bpf_filter() == expected


# ── validate_ip_field ────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected_ok", [
    ("", True),
    ("192.168.1.1", True),
    ("scanme.nmap.org", True),
    ("; rm -rf /", False),
    ("$(whoami)", False),
    ("`id`", False),
    ("8.8.8.8; ls", False),
    ("héllo.com", False),  # non-ASCII rejected, mirroring validate_target's discipline
])
def test_validate_ip_field(Harness, value, expected_ok):
    ok, _ = Harness().validate_ip_field(value)
    assert ok is expected_ok


# ── validate_port_field ──────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected_ok", [
    ("", True),
    ("1", True),
    ("443", True),
    ("65535", True),
    ("0", False),
    ("65536", False),
    ("abc", False),
    ("80; ls", False),
])
def test_validate_port_field(Harness, value, expected_ok):
    ok, _ = Harness().validate_port_field(value)
    assert ok is expected_ok


# ── _color_for_protocol ──────────────────────────────────────────────────────

@pytest.mark.parametrize("proto,expected_color", [
    ("TCP", "#4fc3f7"),
    ("udp", "#81c784"),   # case-insensitive
    ("DNS", "#ffd54f"),
    ("Icmp", "#ff8a65"),
    ("QUIC", "#c9d1e0"),  # unknown protocol falls back to default text color
])
def test_color_for_protocol(Harness, proto, expected_color):
    assert Harness()._color_for_protocol(proto) == expected_color
