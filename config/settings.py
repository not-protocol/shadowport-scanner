"""
config/settings.py — ShadowPort Scanner v2.0.0
Central configuration: version, paths, scan modes, profiles, service intel, risk weights.
"""

import os

# ─── Version ──────────────────────────────────────────────────────────────────
VERSION   = "2.0.0"
TOOL_NAME = "ShadowPort Scanner"
RELEASE   = "Stability before features."

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR    = os.path.join(BASE_DIR, "logs")
PLUGINS_DIR = os.path.join(BASE_DIR, "plugins")
DB_PATH     = os.path.join(LOGS_DIR, "shadowport.db")
ERROR_LOG   = os.path.join(LOGS_DIR, "error.log")

# ─── Scan modes ───────────────────────────────────────────────────────────────
SCAN_MODES = {
    "1": {
        "name":        "Quick Scan",
        "args":        "",
        "description": "Top 1000 common ports",
        "eta":         15,
        "timeout":     60,
        "root":        False,
    },
    "2": {
        "name":        "Full TCP Scan",
        "args":        "-p-",
        "description": "All 65535 TCP ports",
        "eta":         120,
        "timeout":     600,
        "root":        False,
    },
    "3": {
        "name":        "Service Detection",
        "args":        "-sV",
        "description": "Services + version banners",
        "eta":         30,
        "timeout":     180,
        "root":        False,
    },
    "4": {
        "name":        "OS Detection",
        "args":        "-O",
        "description": "OS fingerprinting",
        "eta":         25,
        "timeout":     120,
        "root":        True,
    },
    "5": {
        "name":        "Aggressive Scan",
        "args":        "-A",
        "description": "OS + versions + scripts",
        "eta":         60,
        "timeout":     300,
        "root":        True,
    },
    "6": {
        "name":        "Host Discovery",
        "args":        "-sn",
        "description": "Ping sweep — is host alive?",
        "eta":         5,
        "timeout":     30,
        "root":        False,
    },
    "7": {
        "name":        "Stealth SYN Scan",
        "args":        "-sS",
        "description": "Silent SYN scan",
        "eta":         20,
        "timeout":     120,
        "root":        True,
    },
    "8": {
        "name":        "Vuln Scripts",
        "args":        "--script vuln",
        "description": "NSE vulnerability scripts",
        "eta":         90,
        "timeout":     300,
        "root":        False,
    },
}

EXIT_OPTION = "9"

# ─── Scan profiles ────────────────────────────────────────────────────────────
PROFILES = {
    "fast":    {"name": "Fast Profile",    "mode": "1", "description": "Quick top-port scan, minimal noise"},
    "deep":    {"name": "Deep Profile",    "mode": "2", "description": "Full TCP + service detection"},
    "lab":     {"name": "Lab Profile",     "mode": "5", "description": "Aggressive — best for VM labs"},
    "stealth": {"name": "Stealth Profile", "mode": "7", "description": "SYN scan, lower footprint (root)"},
}

# ─── Service intelligence ─────────────────────────────────────────────────────
SERVICE_INTEL = {
    "ssh":     {"use": "Secure remote shell / administration",      "risk": "Weak credentials allow unauthorized access. Ensure key-based auth."},
    "http":    {"use": "Web server / application delivery",         "risk": "May expose sensitive data or vulnerable web apps. Check for outdated versions."},
    "https":   {"use": "Encrypted web server",                      "risk": "Inspect TLS version and certificate validity."},
    "ftp":     {"use": "File transfer (plaintext)",                 "risk": "Credentials and data sent unencrypted. Prefer SFTP."},
    "smtp":    {"use": "Email sending",                             "risk": "Open relay may be abused for spam. Verify auth requirements."},
    "dns":     {"use": "Domain name resolution",                    "risk": "Open resolvers can be abused for amplification attacks."},
    "mysql":   {"use": "MySQL database server",                     "risk": "Database exposure on network. Should not be publicly accessible."},
    "mssql":   {"use": "Microsoft SQL Server",                      "risk": "Database exposure. Restrict access to trusted IPs only."},
    "rdp":     {"use": "Remote Desktop (Windows)",                  "risk": "High-value target. Brute-force and BlueKeep-type vulnerabilities common."},
    "smb":     {"use": "Windows file/printer sharing",              "risk": "EternalBlue and similar exploits target SMB. Patch regularly."},
    "telnet":  {"use": "Remote shell (plaintext, legacy)",          "risk": "All traffic unencrypted. Replace with SSH immediately."},
    "pop3":    {"use": "Email retrieval",                           "risk": "Plaintext credentials if not using TLS variant."},
    "imap":    {"use": "Email access protocol",                     "risk": "Ensure TLS. Exposed IMAP allows mailbox enumeration."},
    "snmp":    {"use": "Network device management",                 "risk": "Default community strings (public/private) expose device config."},
    "ldap":    {"use": "Directory / Active Directory access",       "risk": "Unauthenticated LDAP queries may expose user information."},
    "nfs":     {"use": "Unix network file sharing",                 "risk": "Misconfigured exports allow unauthorized file access."},
    "vnc":     {"use": "Remote desktop (cross-platform)",           "risk": "Often has weak/no auth. Avoid exposing to internet."},
    "mongodb": {"use": "NoSQL database",                            "risk": "Historically exposed without auth. Verify authentication is enabled."},
    "redis":   {"use": "In-memory cache / data store",              "risk": "Often no auth by default. Remote code execution risk if exposed."},
    "unknown": {"use": "Service not identified",                    "risk": "Investigate manually to determine purpose and exposure."},
}

# ─── Risk scoring weights ─────────────────────────────────────────────────────
RISK_WEIGHTS = {
    "telnet": 20, "ftp": 15, "rdp": 18, "smb": 16, "vnc": 15,
    "redis":  18, "mongodb": 16, "snmp": 12,
    "http": 8, "ssh": 6, "smtp": 7, "mysql": 14, "mssql": 14,
    "ldap": 10, "nfs": 12, "pop3": 6, "imap": 6,
    "https": 3, "dns": 5,
}
RISK_BASE = 0
RISK_MAX  = 100
