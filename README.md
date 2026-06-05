# ShadowPort Scanner v2.0.0

> "Stability before features."

A modular Python-based network port scanner built on Nmap — designed for ethical hackers, cybersecurity students, and home lab enthusiasts.

> ⚠️ **ETHICAL USE ONLY** — Use exclusively on systems you own or have written authorization to test.

---

## What's New in v2.0.0

| Feature | v1.3 | v2.0 |
|---|---|---|
| Target validation | basic regex | **strict — rejects all garbage input** |
| Scan timeout | none | **per-mode hard timeout** |
| CTRL+C handling | crash | **graceful — returns to menu** |
| Nmap error display | traceback | **clean human-readable messages** |
| Empty scan results | broken output | **helpful message with suggestions** |
| DNS pre-check | none | **resolves hostname before scan** |
| Progress bar | could hang | **always terminates cleanly** |
| Report errors | crash | **caught — shown clearly** |
| Error logging | none | **logs/error.log auto-created** |
| Partial scan recovery | none | **partial results saved and shown** |
| Input sanitization | none | **whitespace stripped automatically** |
| Test suite | none | **pytest — validation, reports, DB, parsing** |

---

## Folder Structure

```
shadowport-v2.0/
├── main.py              # Entry point
├── scanner.py           # Nmap engine + validation + timeout + DNS pre-check
├── output.py            # Terminal UI + progress bar
├── reports.py           # TXT / JSON / XML / HTML export
├── database.py          # SQLite scan history
├── profiles.py          # Scan profile presets
├── logger.py            # Silent error logging to logs/error.log
├── config/
│   ├── __init__.py
│   └── settings.py      # All constants, modes, profiles, service intel
├── plugins/
│   ├── __init__.py      # Plugin auto-loader
│   ├── base.py
│   ├── dns_lookup.py
│   └── banner_grabber.py
├── tests/
│   ├── test_validation.py
│   ├── test_reports.py
│   ├── test_parsing.py
│   └── test_history.py
├── logs/
│   ├── shadowport.db    # Scan history
│   └── error.log        # Auto-created error log
├── reports/
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
sudo pip install python-nmap colorama pytest --break-system-packages
```

### 3. Fix folder permissions (if needed)

```bash
sudo chown -R $USER:$USER reports/ logs/
```

---

## Usage

```bash
python main.py       # standard modes
sudo python main.py  # full access (OS detect, SYN, Aggressive)
```

---

## Running Tests

```bash
pytest tests/ -v --tb=short
```

---

## Scan Modes

| # | Mode | Root? | Timeout |
|---|---|---|---|
| 1 | Quick Scan | No | 60s |
| 2 | Full TCP Scan | No | 600s |
| 3 | Service Detection | No | 180s |
| 4 | OS Detection | Yes | 120s |
| 5 | Aggressive Scan | Yes | 300s |
| 6 | Host Discovery | No | 30s |
| 7 | Stealth SYN Scan | Yes | 120s |
| 8 | Vuln Scripts | No | 300s |

---

## v2.0.0 Acceptance Criteria

| Criteria | Status |
|---|---|
| Invalid targets rejected before scan | ✅ |
| No scan freezes or hangs | ✅ |
| CTRL+C handled gracefully everywhere | ✅ |
| All 4 report formats generate correctly | ✅ |
| Progress bar always terminates cleanly | ✅ |
| All Nmap errors caught and displayed clearly | ✅ |
| logs/error.log created automatically | ✅ |
| No uncaught exceptions under any input | ✅ |
| Automated test suite included | ✅ |

---

## Legal Disclaimer

This tool is for educational and authorized security testing only.
Unauthorized scanning may violate local, state, or federal law.
The authors assume no liability for misuse.
