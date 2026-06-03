# ShadowPort Scanner v1.2

A Python-based command-line network port scanner built on Nmap — designed for ethical hackers, cybersecurity students, and Linux power users.

> ⚠️ **ETHICAL USE ONLY** — Use exclusively on systems you own or have written authorization to test.

---

## What's New in v1.2

| Feature | v1.0 | v1.2 |
|---|---|---|
| Scan modes | 5 | **8** |
| Progress bar with ETA | ✗ | ✅ |
| Scan timestamps & duration | ✗ | ✅ |
| Host discovery (ping sweep) | ✗ | ✅ |
| Root privilege detection | ✗ | ✅ |
| HTML report export | ✗ | ✅ |
| Scan history log (CSV) | ✗ | ✅ |
| Scan summary (open/closed/filtered) | ✗ | ✅ |
| Config module | ✗ | ✅ |

---

## Folder Structure

```
shadowport-v1.2/
├── main.py          # Entry point — menu & workflow
├── scanner.py       # Nmap execution, parsing, host discovery
├── output.py        # Terminal UI, progress bar, results table
├── report.py        # Save TXT / JSON / XML / HTML + history log
├── config.py        # Scan modes, paths, constants
├── requirements.txt
├── README.md
├── reports/         # Auto-created — scan reports saved here
└── logs/
    └── scan_history.csv   # Auto-created — all past scans logged
```

---

## Requirements

- Python 3.10+
- Nmap installed on your system

### Install Nmap

```bash
# Fedora / RHEL
sudo dnf install nmap

# Debian / Ubuntu / Kali
sudo apt install nmap
```

### Install Python dependencies

```bash
# IMPORTANT: install under sudo so it works with 'sudo python main.py'
sudo pip install python-nmap colorama --break-system-packages
```

---

## Usage

```bash
# Standard modes (1, 2, 3, 6, 8)
python main.py

# Full access — unlocks OS detection, Stealth SYN, Aggressive (modes 4, 5, 7)
sudo python main.py
```

---

## Scan Modes

| # | Mode | Nmap Equivalent | Root? | ETA |
|---|---|---|---|---|
| 1 | Quick Scan | `nmap <target>` | No | ~15s |
| 2 | Full TCP Scan | `nmap -p-` | No | ~2min |
| 3 | Service Detection | `nmap -sV` | No | ~30s |
| 4 | OS Detection | `nmap -O` | **Yes** | ~25s |
| 5 | Aggressive Scan | `nmap -A` | **Yes** | ~60s |
| 6 | Host Discovery | `nmap -sn` | No | ~5s |
| 7 | Stealth SYN Scan | `nmap -sS` | **Yes** | ~20s |
| 8 | Vuln Scripts | `nmap --script vuln` | No | ~90s |

---

## Report Formats

After every scan you can save:

| Format | Description |
|---|---|
| TXT | Human-readable plain text table |
| JSON | Machine-readable with metadata wrapper |
| XML | Structured markup |
| HTML | Styled browser report with dark theme ⭐ |

Reports are saved to `reports/` with timestamped filenames:
```
reports/scan_192-168-56-101_2026-05-25_14-30-00.html
```

---

## Scan History

Every scan is automatically logged to `logs/scan_history.csv`.

View recent history from the menu by typing `h` at the mode prompt.

---

## Beginner Example

```bash
sudo python main.py

# Enter: 192.168.56.101
# Mode: 1 (Quick Scan)
# → See open ports
# → Save as HTML
# → Open report in browser
```

## Intermediate Example

```bash
sudo python main.py

# Enter: 192.168.1.1
# Mode: 5 (Aggressive)
# → OS, versions, scripts, traceroute
# → Save as JSON for further processing
```

---

## Roadmap

### v1.2 ✅ (Current)
- Progress bar + ETA
- 8 scan modes
- Host discovery
- HTML reports
- Scan history log
- Root privilege detection

### v2.0 (Planned)
- Multi-target / CIDR scanning
- Async parallel scans
- UDP scanning
- Rich/Textual terminal UI
- Plugin architecture
- AI-assisted port analysis

---

## Legal Disclaimer

This tool is for educational and authorized security testing only.
Unauthorized scanning may violate local, state, or federal law.
The authors assume no liability for misuse.
