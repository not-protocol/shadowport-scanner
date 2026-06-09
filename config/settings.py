"""
config/settings.py — ShadowPort Scanner v2.1.0
Central configuration: version, paths, scan modes, profiles, service intel.
"""

import os

VERSION   = "2.1.0"
TOOL_NAME = "ShadowPort Scanner"
RELEASE   = "From stability to intelligence."

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR    = os.path.join(BASE_DIR, "Log")
DB_PATH     = os.path.join(LOGS_DIR, "shadowport.db")
ERROR_LOG   = os.path.join(LOGS_DIR, "error.log")
EXCEL_PATH  = os.path.join(LOGS_DIR, "scannerhistory.xlsx")

SCAN_MODES = {
    "1": {"name": "Quick Scan",        "args": "",              "description": "Top 1000 ports",            "eta": 15,  "timeout": 60,  "root": False},
    "2": {"name": "Full TCP Scan",     "args": "-p-",           "description": "All 65535 TCP ports",       "eta": 120, "timeout": 600, "root": False},
    "3": {"name": "Service Detection", "args": "-sV",           "description": "Services + banners",        "eta": 30,  "timeout": 180, "root": False},
    "4": {"name": "OS Detection",      "args": "-O",            "description": "OS fingerprinting",         "eta": 25,  "timeout": 120, "root": True},
    "5": {"name": "Aggressive Scan",   "args": "-A",            "description": "OS + versions + scripts",   "eta": 60,  "timeout": 300, "root": True},
    "6": {"name": "Host Discovery",    "args": "-sn",           "description": "Ping sweep",                "eta": 5,   "timeout": 30,  "root": False},
    "7": {"name": "Stealth SYN",       "args": "-sS",           "description": "Silent SYN scan",           "eta": 20,  "timeout": 120, "root": True},
    "8": {"name": "Vuln Scripts",      "args": "--script vuln", "description": "NSE vulnerability scripts", "eta": 90,  "timeout": 300, "root": False},
}

EXIT_OPTION = "9"

PROFILES = {
    "fast":    {"name": "Fast Profile",    "mode": "1", "description": "Quick top-port scan"},
    "deep":    {"name": "Deep Profile",    "mode": "2", "description": "Full TCP scan"},
    "lab":     {"name": "Lab Profile",     "mode": "5", "description": "Aggressive — VM labs"},
    "stealth": {"name": "Stealth Profile", "mode": "7", "description": "SYN scan (root)"},
    "web":     {"name": "Web Profile",     "mode": "3", "description": "Web server analysis"},
}

SERVICE_INTEL = {
    "ssh":     {"use": "Secure remote shell",          "risk": "Ensure key-based auth. Disable root login."},
    "http":    {"use": "Web server",                   "risk": "Check for outdated versions and exposed apps."},
    "https":   {"use": "Encrypted web server",         "risk": "Inspect TLS version and certificate validity."},
    "ftp":     {"use": "File transfer (plaintext)",    "risk": "Credentials sent unencrypted. Prefer SFTP."},
    "smtp":    {"use": "Email sending",                "risk": "Open relay may be abused for spam."},
    "dns":     {"use": "Domain name resolution",       "risk": "Open resolvers can be abused for amplification."},
    "mysql":   {"use": "MySQL database",               "risk": "Should not be publicly accessible."},
    "mssql":   {"use": "Microsoft SQL Server",         "risk": "Restrict to trusted IPs only."},
    "rdp":     {"use": "Remote Desktop (Windows)",     "risk": "High-value target. Patch regularly."},
    "smb":     {"use": "Windows file sharing",         "risk": "Patch against EternalBlue and variants."},
    "telnet":  {"use": "Remote shell (plaintext)",     "risk": "All traffic unencrypted. Replace with SSH."},
    "pop3":    {"use": "Email retrieval",              "risk": "Plaintext credentials without TLS."},
    "imap":    {"use": "Email access",                 "risk": "Ensure TLS. Exposed IMAP allows enumeration."},
    "snmp":    {"use": "Network device management",    "risk": "Default community strings expose device config."},
    "ldap":    {"use": "Directory / AD access",        "risk": "Unauthenticated queries may expose user info."},
    "nfs":     {"use": "Unix network file sharing",    "risk": "Misconfigured exports allow unauthorized access."},
    "vnc":     {"use": "Remote desktop",               "risk": "Often weak/no auth. Avoid internet exposure."},
    "mongodb": {"use": "NoSQL database",               "risk": "Verify authentication is enabled."},
    "redis":   {"use": "In-memory cache",              "risk": "No auth by default. RCE risk if exposed."},
    "unknown": {"use": "Service not identified",       "risk": "Investigate manually."},
}

RISK_WEIGHTS = {
    "telnet": 20, "ftp": 15, "rdp": 18, "smb": 16, "vnc": 15,
    "redis": 18,  "mongodb": 16, "snmp": 12, "http": 8, "ssh": 6,
    "smtp": 7,    "mysql": 14, "mssql": 14, "ldap": 10, "nfs": 12,
    "pop3": 6,    "imap": 6, "https": 3, "dns": 5,
}
RISK_BASE = 0
RISK_MAX  = 100

SCHEMA_VERSION = 3
