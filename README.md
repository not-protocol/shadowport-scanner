# ShadowPort Scanner v2.4.0

> "Not a script. A platform."

A full Textual TUI cybersecurity reconnaissance application built on Nmap,
now with live packet capture via TShark. Persistent dashboard, live
telemetry, plugin system, unified history, multi-target database, and
packet-level visibility — all in your terminal.

> ⚠️ **ETHICAL USE ONLY** — Use exclusively on systems and networks you own
> or have written authorization to test or capture traffic on. Unauthorized
> scanning or packet capture is illegal.

---

## What's New in v2.4.0

| Area | v2.3 | v2.4 |
|---|---|---|
| Traffic visibility | Scan results only | **Live packet capture via TShark, with BPF filter + duration** |
| Sidebar | Dashboard, Plugins, Reports, … | **+ "Capture" page, between Plugins and Reports** |
| Themes | Switchable live, but reset on restart | **Persisted to `~/.shadowport/config.json` — survives restarts** |
| Capture permissions | N/A | **Non-root via `setcap cap_net_raw,cap_net_admin+eip` on `dumpcap`** |
| Database | scans, ports, plugins_log, reports_log, errors_log, scan_statistics | **+ `captures` table, schema version 5** |
| Config | None | **`ConfigManager` — atomic JSON config (theme + capture defaults)** |
| Disk safety | N/A | **Capture ring buffer (50MB × 5 files)** |

---

## Folder Structure

```
shadowport-v2.4.0/
├── main.py                        # Full Textual TUI application
├── reports.py                     # TXT / JSON / XML / HTML export + logging
│
├── config/
│   ├── __init__.py
│   ├── settings.py                # Modes, themes, service intel, paths, v2.4 capture defaults
│   └── config_manager.py          # NEW v2.4 — persistent JSON config (theme, capture defaults)
│
├── core/
│   ├── __init__.py
│   ├── scanner_engine.py          # Validation + Nmap engine + live events
│   ├── capture_engine.py          # NEW v2.4 — TShark wrapper, background thread, ring buffer
│   ├── logger.py                  # Unified error logging (file + DB)
│   ├── excel_logger.py            # Dual-sheet Excel logger (Scans + Plugins)
│   └── json_history.py            # Append-only JSON activity history
│
├── db/
│   ├── __init__.py
│   └── database.py                # scans, ports, plugins_log, reports_log,
│                                   #   errors_log, scan_statistics, captures (v2.4) + migration
│
├── ui/
│   ├── __init__.py
│   ├── themes.py                  # 5 theme colour palettes (CSS variable sets)
│   └── theme_manager.py           # NEW v2.4 — persists the active theme via ConfigManager
│
├── plugins/
│   ├── __init__.py                # Auto-discovery loader
│   ├── base.py
│   ├── dns_lookup.py
│   ├── banner_grabber.py          # 5s/host timeout
│   └── service_intel.py
│
├── tools/
│   └── reserved_attr_guard.py     # Static guard against shadowing Textual's internal attrs
│
├── tests/
│   ├── __init__.py
│   ├── test_validation.py
│   ├── test_database.py
│   ├── test_excel_logger.py
│   ├── test_json_history.py
│   ├── test_reports.py
│   ├── test_app_shutdown.py
│   ├── test_reserved_attr_guard.py
│   ├── test_capture_engine.py     # NEW v2.4
│   ├── test_config_manager.py     # NEW v2.4
│   ├── test_theme_manager.py      # NEW v2.4
│   └── test_database_capture.py   # NEW v2.4
│
├── Log/                            # Auto-created
│   ├── shadowport.db
│   ├── scannerhistory.xlsx         # Sheets: Scans, Plugins
│   ├── history.json
│   ├── error.log
│   └── captures/                   # NEW v2.4 — .pcapng files, ring-buffered, 0o700
│
├── reports/                         # Auto-created
└── requirements.txt
```

---
<p align="center">
  <img src="https://github.com/not-protocol/shadowport-scanner/blob/main/assets/Screenshot_20260626_011228.png" width="32%">
  <img src="https://github.com/not-protocol/shadowport-scanner/blob/main/assets/Screenshot_20260626_011257.png" width="32%">
  <img src="https://github.com/not-protocol/shadowport-scanner/blob/main/assets/Screenshot_20260626_011320.png" width="32%">
</p>

---

## Setup

```bash
# 1. Install Nmap
sudo dnf install nmap          # Fedora/RHEL
sudo apt install nmap          # Debian/Ubuntu

# 2. Install TShark (for packet capture — see "Packet Capture" below)
sudo apt install tshark        # Debian/Ubuntu
sudo dnf install wireshark-cli # Fedora/RHEL

# 3. Install Python deps
sudo pip install -r requirements.txt --break-system-packages

# 4. Fix permissions if needed
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

For live packet capture, use the **Capture** sidebar page — see
[Packet Capture](#packet-capture) below.

---

## Sidebar Pages

| Page | Description |
|---|---|
| **Dashboard** | Target input, live status bar, progress bar, telemetry log, results table |
| **Plugins** | Select and run a plugin against the last scan; output streams live |
| **Capture** | *(New in v2.4)* Configure and run a live TShark packet capture; view captured packets |
| **Reports** | Browse generated report files (TXT/JSON/XML/HTML) with size and timestamp |
| **History** | Tabbed view: Scans, Plugins, Reports, Errors — all unified |
| **Database** | Raw SQLite table viewer with refresh button |
| **System** | Nmap version, root status, plugin count, DB stats, last scan |
| **Settings** | Switch between 5 themes live — choice now persists across restarts |
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

## Packet Capture

*(New in v2.4)*

ShadowPort can capture live traffic via **TShark** (Wireshark's CLI), in
addition to its existing Nmap-based scanning.

### Install TShark

```bash
sudo apt install tshark        # Debian/Ubuntu
sudo dnf install wireshark-cli # Fedora/RHEL
sudo pacman -S wireshark-cli   # Arch
```

### Non-root capture setup (recommended)

Capturing raw packets normally requires root. Instead of running ShadowPort
as root just for this feature, grant the capture binary the two specific
capabilities it needs:

```bash
sudo groupadd wireshark
sudo usermod -aG wireshark $USER
sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)
```

Log out and back in for the group change to take effect. After this,
ShadowPort can capture packets without running as root or using `sudo`.

### Usage

The Capture page has a Wireshark-style layout: a structured filter row,
a colored packet-list grid, a detail pane for the selected packet, and a
live telemetry log.

1. From the sidebar, select **Capture** (between Plugins and Reports).
2. **Filter row** — instead of typing raw BPF syntax, pick from dedicated
   fields and the app builds the filter for you:
   - **Interface** — `eth0`, `wlan0`, `lo`, etc. (auto-populated from
     `tshark -D`)
   - **Protocol** — Any / TCP / UDP / DNS / HTTP / HTTPS / ICMP
   - **Port** — optional, numeric (e.g. `443`)
   - **IP / host** — optional, restricts capture to one address
   - A live preview line under the row shows the exact BPF filter that
     will be used (e.g. `tcp port 443 and host 10.0.0.5`)
3. Set a **Duration** in seconds, or leave it `0` to capture until you
   press Stop.
4. Press **Start**. Live packet count and elapsed time update in the
   status bar; telemetry streams into the log panel below.
5. Press **Stop** to end the capture. The result is saved to the database,
   and the packet list grid populates automatically — each row is
   color-coded by protocol (TCP, UDP, DNS, HTTP, ICMP, etc.), matching
   Wireshark's own coloring convention.
6. **Click any row** to see its full detail (time, source, destination,
   protocol, length, info) in the detail pane below the grid.
7. Captures are written under `Log/captures/`, rotated via a ring buffer
   (50MB per file, 5 files max) so an unbounded capture can't fill your disk.

Your last-used protocol, port, IP, and duration are remembered across
restarts (stored in `~/.shadowport/config.json`, same as the active theme).

If you need a capture filter this structured UI doesn't cover, open the
saved `.pcapng` file directly in the real Wireshark GUI (see below) for
the full filter language and deep packet inspection.

### Opening a capture in real Wireshark

ShadowPort's own packet grid is a quick summary view, not a full protocol
dissector. For byte-level inspection, open the saved file in Wireshark:

```bash
wireshark Log/captures/capture_eth0_20260626_120000.pcapng
```

(Requires the separate `wireshark` GUI package — `tshark` alone only
provides the CLI engine.)

### Security notes specific to capture

- All `tshark`/`dumpcap` invocations use list-form `subprocess` calls —
  never `shell=True`, never a shell string.
- Interface names are validated against `^[a-zA-Z0-9_:.-]{1,15}$` before
  reaching any subprocess call.
- BPF filters are passed as a single argv element, never interpolated into
  a shell command.
- `Log/captures/` is created with `mode=0o700`.
- `captures` table inserts use parameterized `?` queries, same as every
  other table in `db/database.py`.

### Troubleshooting: "Permission denied"

- Confirm `tshark` is installed: `which tshark`
- Confirm the capability was applied: `getcap $(which dumpcap)` should show
  `cap_net_raw,cap_net_admin=eip`
- Confirm your user is in the `wireshark` group: `groups $USER`
- If you changed group membership in this session, log out and back in (or
  run `newgrp wireshark`) — group changes don't apply retroactively to an
  already-open shell.
- As a last resort, `sudo python main.py` will also work, since root
  bypasses the capability check entirely.

---

## Themes

Switch live from **Settings** — your choice now persists across restarts,
stored in `~/.shadowport/config.json` (written atomically):

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

Every scan, plugin run, capture, report export, and error is written to
**three** places simultaneously (capture is SQLite-only, since per-packet
capture metadata doesn't fit the Excel/JSON shape used for scans):

1. **SQLite** (`Log/shadowport.db`) — `scans`, `ports`, `plugins_log`,
   `reports_log`, `errors_log`, `captures` *(new in v2.4)*
2. **Excel** (`Log/scannerhistory.xlsx`) — `Scans` and `Plugins` sheets
3. **JSON** (`Log/history.json`) — append-only activity log

View scan/plugin/report/error history from the **History** and **Database**
pages; capture history is visible in the **Database** page's `captures`
table view and via `db.database.get_capture_history()`.

---

## Running Tests

```bash
pytest tests/ -v --tb=short
```

Covers: input validation (including shell injection + unicode rejection),
SQL injection safety, schema migration, Excel dual-sheet logging, JSON
history, all four report formats with DB/JSON logging integration, the
Textual `App._registry` shadowing regression guard, and *(new in v2.4)*
packet-capture engine behavior, config persistence, theme persistence, and
the `captures` table (including its own SQL-injection and migration checks).

> **Note:** `test_app_shutdown.py` requires `textual`, `pytest-asyncio`, and
> a real Nmap/TShark-capable environment to run meaningfully — it was not
> executed in a network-isolated authoring environment. Everything else
> runs with just `pytest` + `pytest-mock` + the packages in
> `requirements.txt`.

---

## Security Notes

- Shell metacharacters and unicode rejected before reaching Nmap
- `subprocess` never called with `shell=True` — for Nmap **or** TShark
- `sudo` never auto-invoked
- Root checked before SYN/OS scans — clear error if missing
- All SQL parameterized — zero f-string queries
- Packet capture uses capability-based non-root access (`setcap`), not `sudo`
- A static guard (`tools/reserved_attr_guard.py`) checks that no `App`/`Screen`
  subclass shadows Textual's reserved internal attribute names

---

## Legal Disclaimer

This tool is for educational and authorized security testing only.
Unauthorized scanning or packet capture may violate local, state, or
federal law. The authors assume no liability for misuse.
