"""
config.py — ShadowPort Scanner v1.2
Central configuration and constants.
"""

import os

# ─── Version ────────────────────────────────────────────────────────────────
VERSION = "1.2.0"
TOOL_NAME = "ShadowPort Scanner"

# ─── Directories ─────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR    = os.path.join(BASE_DIR, "logs")

# ─── Scan mode definitions ───────────────────────────────────────────────────
# Each mode has: name, args, description, estimated_seconds (rough guide)
SCAN_MODES = {
    "1": {
        "name":        "Quick Scan",
        "args":        "",
        "description": "Top 1000 common ports",
        "eta":         15,
        "root":        False,
    },
    "2": {
        "name":        "Full TCP Scan",
        "args":        "-p-",
        "description": "All 65535 TCP ports",
        "eta":         120,
        "root":        False,
    },
    "3": {
        "name":        "Service Detection",
        "args":        "-sV",
        "description": "Services + version banners",
        "eta":         30,
        "root":        False,
    },
    "4": {
        "name":        "OS Detection",
        "args":        "-O",
        "description": "OS fingerprinting (needs root)",
        "eta":         25,
        "root":        True,
    },
    "5": {
        "name":        "Aggressive Scan",
        "args":        "-A",
        "description": "OS + versions + scripts + traceroute",
        "eta":         60,
        "root":        True,
    },
    "6": {
        "name":        "Host Discovery",
        "args":        "-sn",
        "description": "Ping sweep — check if host is alive",
        "eta":         5,
        "root":        False,
    },
    "7": {
        "name":        "Stealth SYN Scan",
        "args":        "-sS",
        "description": "Fast SYN scan (needs root)",
        "eta":         20,
        "root":        True,
    },
    "8": {
        "name":        "Vuln Scripts",
        "args":        "--script vuln",
        "description": "Run NSE vulnerability scripts",
        "eta":         90,
        "root":        False,
    },
}

EXIT_OPTION = "9"
