# ShadowPort Scanner v2.3.0

> "Not a script. A platform."

A full Textual TUI cybersecurity reconnaissance application built on Nmap.
Persistent dashboard, live telemetry, plugin system, unified history, and
multi-target database — all in your terminal.

> ⚠️ **ETHICAL USE ONLY** — Use exclusively on systems you own or have
> written authorization to test. Unauthorized scanning is illegal.

---

## What's New in v2.3.0

| Area | v2.1 | v2.3 |
|---|---|---|
| Interface | Menu-driven CLI | **Persistent Textual dashboard** |
| Navigation | Sequential prompts | **Sidebar: Dashboard, Plugins, Reports, History, Database, System, Settings, Help** |
| Scan visibility | Results after completion | **Live telemetry feed during scan** |
| Progress | Could stall at 97% | **Event-driven: Initializing → Scanning → Processing → 100%** |
| Plugin results | Not saved | **Saved to SQLite + Excel + JSON automatically** |
| Logging | Scans only | **Unified: scans, plugins, reports, errors — all 4 logged everywhere** |
| Storage | SQLite only | **SQLite + Excel (multi-sheet) + JSON history, all dual/triple-write** |
| Database | scans + ports | **+ plugins_log, reports_log, errors_log, scan_statistics** |
| Themes | None | **5 built-in themes, switchable live** |
| Shortcuts | None | **F1–F5, ESC, Ctrl+C** |
| Error tracking | error.log only | **error.log + errors_log table, visible in History/Database views** |

---

## Folder Structure

```
shadowport-v2.3.0/
├── main.py                    # Full Textual TUI application
├── reports.py                 # TXT / JSON / XML / HTML export + logging
│
├── config/
│   ├── __init__.py
│   └── settings.py            # Modes, themes, service intel, paths
│
├── core/
│   ├── __init__.py
│   ├── scanner_engine.py       # Validation + Nmap engine + live events
│   ├── logger.py               # Unified error logging (file + DB)
│   ├── excel_logger.py         # Dual-sheet Excel logger (Scans + Plugins)
│   └── json_history.py         # Append-only JSON activity history
│
├── db/
│   ├── __init__.py
│   └── database.py             # scans, ports, plugins_log, reports_log,
│                                #   errors_log, scan_statistics + migration
│
├── ui/
│   ├── __init__.py
│   └── themes.py                # 5 theme colour palettes
│
├── plugins/
│   ├── __init__.py              # Auto-discovery loader
│   ├── base.py
│   ├── dns_lookup.py
│   ├── banner_grabber.py        # 5s/host timeout
│   └── service_intel.py
│
├── tests/
│   ├── __init__.py
│   ├── test_validation.py
│   ├── test_database.py
│   ├── test_excel_logger.py
│   ├── test_json_history.py
│   └── test_reports.py
│
├── Log/                          # Auto-created
│   ├── shadowport.db
│   ├── scannerhistory.xlsx       # Sheets: Scans, Plugins
│   ├── history.json
│   └── error.log
│
├── reports/                       # Auto-created
└── requirements.txt
```

---

## Setup

```bash
# 1. Install Nmap
sudo dnf install nmap          # Fedora/RHEL
sudo apt install nmap          # Debian/Ubuntu

# 2. Install Python deps
sudo pip install -r requirements.txt --break-system-packages

# 3. Fix permissions if needed
sudo chown -R $USER:$USER Log/ reports/
```

---

## Usage

```bash
python main.py         # standard modes
sudo python main.py    # unlocks SYN / OS detection / Aggressive
```

You land directly on the **Dashboard**:

1. Enter a target (IP, hostname, or CIDR)
2. Select a scan mode
3. Press **▶ Scan**
4. Watch live telemetry stream in real time
5. Results populate the table automatically
6. Everything is saved to SQLite, Excel, and JSON — no manual save needed

---

## Sidebar Pages

| Page | Description |
|---|---|
| **Dashboard** | Target input, live status bar, progress bar, telemetry log, results table |
| **Plugins** | Select and run a plugin against the last scan; output streams live |
| **Reports** | Browse generated report files (TXT/JSON/XML/HTML) with size and timestamp |
| **History** | Tabbed view: Scans, Plugins, Reports, Errors — all unified |
| **Database** | Raw SQLite table viewer with refresh button |
| **System** | Nmap version, root status, plugin count, DB stats, last scan |
| **Settings** | Switch between 5 themes live |
| **Help** | Keyboard shortcuts and scan mode reference |

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| F1 | Help |
| F2 | New Scan (Dashboard) |
| F3 | Reports |
| F4 | Plugins |
| F5 | Refresh current view |
| ESC | Back to Dashboard |
| Ctrl+C | Exit safely |

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

## Themes

Switch live from **Settings**:

| Theme | Style |
|---|---|
| 🟢 Cyber Green | Default — terminal hacker aesthetic |
| 🔵 Blue Team | Cool blues for defensive ops |
| 🟣 Purple Neon | High-contrast neon |
| ⚫ Dark Mode | Neutral dark |
| ⚪ Light Mode | Light background for bright environments |

---

## Plugins

| Plugin | Description |
|---|---|
| `dns_lookup` | Forward + reverse DNS resolution |
| `banner_grabber` | TCP banner grab, 5s timeout, 10-port cap |
| `service_intel` | Security notes for every open port |

Every plugin run is logged to:
- **SQLite** `plugins_log` table
- **Excel** `Plugins` sheet
- **JSON** `Log/history.json`

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

Drop it in `plugins/` — loads automatically on next launch.

---

## Unified Logging

Every scan, plugin run, report export, and error is written to **three**
places simultaneously:

1. **SQLite** (`Log/shadowport.db`) — `scans`, `ports`, `plugins_log`, `reports_log`, `errors_log`
2. **Excel** (`Log/scannerhistory.xlsx`) — `Scans` and `Plugins` sheets
3. **JSON** (`Log/history.json`) — append-only activity log

View it all from the **History** and **Database** pages.

---

## Running Tests

```bash
pytest tests/ -v --tb=short
```

Covers: input validation (including shell injection + unicode rejection),
SQL injection safety, schema migration, Excel dual-sheet logging, JSON
history, and all four report formats with DB/JSON logging integration.

---

## Security Notes

- Shell metacharacters and unicode rejected before reaching Nmap
- `subprocess` never called with `shell=True`
- `sudo` never auto-invoked
- Root checked before SYN/OS scans — clear error if missing
- All SQL parameterized — zero f-string queries

---

## Legal Disclaimer

This tool is for educational and authorized security testing only.
Unauthorized scanning may violate local, state, or federal law.
The authors assume no liability for misuse.
