# ShadowPort Scanner v2.1.0

> "From stability to intelligence."

A modular Python-based network port scanner built on Nmap, designed for
ethical hackers, cybersecurity students, and home lab enthusiasts.

> ⚠️ **ETHICAL USE ONLY** — Use exclusively on systems you own or have
> written authorization to test. Unauthorized scanning is illegal.

---

## What's New in v2.1.0

| Feature | v2.0 | v2.1 |
|---|---|---|
| Database schema | fixed | **full schema + migration via PRAGMA** |
| Excel logging | broken | **dual-write: SQLite + Excel on every scan** |
| SQL injection protection | basic | **parameterized queries only, zero f-string SQL** |
| Thread safety | partial | **threading.Lock on DB, Excel, and UI events** |
| Service Knowledge Base | — | ✅ **17 ports with purpose, uses, risk level** |
| Scan Profiles | basic | ✅ **5 dataclass profiles: Fast, Deep, Web, Stealth, Vuln** |
| Change Detection | basic | ✅ **SQLite ports table diff: new/closed/unchanged** |
| Live Telemetry Monitor | — | ✅ **Textual widgets: ScanStatusPanel + LiveEventsLog** |
| Service Intel Plugin | — | ✅ **new plugin: service_intel** |
| Log consistency audit | — | ✅ **startup health check: SQLite vs Excel count** |
| Production checklist | — | ✅ **PRODUCTION_CHECKLIST.md with 12 sections** |
| Test suite | 4 files | **6 files, 80+ test cases** |

---

## Folder Structure

```
shadowport-v2.1.0/
├── main.py                    # Entry point
├── scanner.py                 # Nmap engine, validation, timeout, DNS pre-check
├── output.py                  # Terminal UI, progress bar, results table
├── reports.py                 # TXT / JSON / XML / HTML export
├── logger.py                  # Silent error logging → Log/error.log
│
├── config/
│   ├── __init__.py
│   └── settings.py            # All constants, modes, profiles, service intel
│
├── db/
│   ├── __init__.py
│   └── database.py            # SQLite: full schema, migration, thread-safe
│
├── core/
│   ├── __init__.py
│   ├── excel_logger.py        # openpyxl dual-write logger, file lock, retry
│   ├── service_kb.py          # Service Knowledge Base (17 ports)
│   ├── scan_profiles.py       # 5 scan profile dataclasses
│   └── change_detector.py     # Scan diff engine using ports table
│
├── ui/
│   ├── __init__.py
│   └── live_monitor.py        # Textual: ScanStatusPanel + LiveEventsLog
│
├── plugins/
│   ├── __init__.py            # Auto-discovery loader
│   ├── base.py                # BasePlugin abstract class
│   ├── dns_lookup.py          # DNS forward + reverse lookup
│   ├── banner_grabber.py      # TCP banner grabbing (5s timeout)
│   └── service_intel.py       # Service KB for every open port
│
├── tests/
│   ├── __init__.py
│   ├── test_validation.py     # 30+ input validation cases + injection attempts
│   ├── test_database.py       # save_scan, history, migration, SQL injection safety
│   ├── test_excel_logger.py   # new file, append, auto-increment, missing dir
│   ├── test_change_detector.py# new/closed/unchanged port detection
│   └── test_service_kb.py     # known ports, fallback, formatting
│
├── Log/                       # Auto-created
│   ├── shadowport.db          # SQLite scan history
│   ├── scannerhistory.xlsx    # Excel scan log (dual-write)
│   └── error.log              # Silent error log
│
├── reports/                   # Auto-created — exported scan reports
├── PRODUCTION_CHECKLIST.md
├── requirements.txt
└── README.md
```

---

## Setup

### 1. Install Nmap

```bash
# Fedora / RHEL
sudo dnf install nmap

# Debian / Ubuntu / Kali
sudo apt install nmap
```

### 2. Install Python dependencies

```bash
sudo pip install -r requirements.txt --break-system-packages
```

### 3. Fix permissions if needed

```bash
sudo chown -R $USER:$USER Log/ reports/
```

---

## Usage

```bash
python main.py         # standard modes
sudo python main.py    # full access: OS detect, SYN, Aggressive
```

---

## Scan Modes

| # | Mode | Root? | Timeout |
|---|---|---|---|
| 1 | Quick Scan | No | 60s |
| 2 | Full TCP Scan | No | 600s |
| 3 | Service Detection | No | 180s |
| 4 | OS Detection | **Yes** | 120s |
| 5 | Aggressive Scan | **Yes** | 300s |
| 6 | Host Discovery | No | 30s |
| 7 | Stealth SYN Scan | **Yes** | 120s |
| 8 | Vuln Scripts | No | 300s |

---

## Scan Profiles

Press `p` at the mode prompt:

| # | Profile | Description |
|---|---|---|
| 1 | Fast Lab Scan | Top 1000 ports, quick triage |
| 2 | Deep Enumeration | All 65535 TCP + service versions |
| 3 | Web Server Analysis | Ports 80/443/8080/8443 + HTTP headers |
| 4 | Stealth SYN Scan | Half-open SYN, slow timing (root) |
| 5 | Vulnerability Audit | NSE vuln scripts + service detection |

---

## Plugins

Press `x` after a scan to run a plugin:

| Plugin | Description |
|---|---|
| `dns_lookup` | Forward and reverse DNS resolution |
| `banner_grabber` | TCP banner grabbing (5s max per host) |
| `service_intel` | Service Knowledge Base for every open port |

### Writing a plugin

```python
# plugins/my_plugin.py
from plugins.base import BasePlugin

class MyPlugin(BasePlugin):
    name        = "my_plugin"
    description = "Does something useful"
    version     = "1.0"

    def run(self, target: str, scan_data: dict) -> dict:
        return {"output": f"Hello from {target}!"}
```

Drop it in `plugins/` — it loads automatically on next run.

---

## Change Detection

Press `d` at the mode prompt to diff the last two scans for the current target:

```
  Change Detection: 192.168.1.1
  Comparing scan #3 → #4
  ✚ New open ports:
      → 3306/tcp (mysql)
  ═ Unchanged: 22/tcp, 80/tcp
```

---

## Excel Log

Every scan writes immediately to `Log/scannerhistory.xlsx`:

| Scan # | Date | Time | Target | Scan Type | Open Ports | Total Ports | Risk Score | Duration (s) | Status |
|---|---|---|---|---|---|---|---|---|---|

---

## Running Tests

```bash
pytest tests/ -v --tb=short
```

---

## Security Notes

- All user inputs validated before reaching Nmap
- Shell metacharacters rejected
- Subprocess never called with `shell=True`
- `sudo` never auto-invoked programmatically
- Root check enforced before SYN and OS detection scans

---

## Legal Disclaimer

This tool is for educational and authorized security testing only.
Unauthorized scanning may violate local, state, or federal law.
The authors assume no liability for misuse.
