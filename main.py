#!/usr/bin/env python3
"""
main.py — ShadowPort Scanner v2.3.0
Full Textual TUI: persistent dashboard, live telemetry, sidebar navigation,
plugin window, history explorer, database viewer, report center, system monitor.

Usage:
    python main.py
    sudo python main.py   ← unlocks SYN / OS detection scans

Ethics: Use ONLY on systems you own or are authorized to test.
"""

import os
import sys
import time
import threading
from datetime import datetime
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label,
    Log, Markdown, ProgressBar, Select, Static, TabbedContent, TabPane,
)

from config.settings import VERSION, TOOL_NAME, SCAN_MODES, LOG_DIR, REPORTS_DIR
from core.scanner_engine import validate_target, is_root, is_nmap_installed, run_scan
from core.logger import log_error
from core.excel_logger import log_scan_to_excel, log_plugin_to_excel
from core.json_history import record_scan, record_plugin, record_report, get_history
from core.capture_engine import CaptureEngine
from config.config_manager import ConfigManager
from ui.theme_manager import ThemeManager
from db.database import (
    init_db, save_scan, log_plugin, log_report,
    get_scan_history, get_plugin_history, get_report_history,
    get_error_history, get_stats,
    log_capture, get_capture_history,
)
import plugins as plugin_loader

# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────

APP_CSS = """
/* ── Base ── */
Screen {
    background: #0a0e1a;
    color: #c9d1e0;
    layers: base notifications;
}

/* ── Layout ── */
#app-layout {
    layout: horizontal;
    height: 1fr;
}

#sidebar {
    width: 20;
    background: #0d1929;
    border-right: solid #1e3a5f;
    padding: 1 0;
}

#main-area {
    width: 1fr;
}

/* ── Sidebar nav buttons ── */
.nav-btn {
    width: 100%;
    background: transparent;
    color: #607090;
    border: none;
    text-align: left;
    padding: 0 2;
    height: 3;
}
.nav-btn:hover { background: #111827; color: #00cfff; }
.nav-btn.active { background: #111827; color: #00ff88; border-left: solid #00ff88; }

/* ── Cards / panels ── */
.panel {
    background: #111827;
    border: solid #1e3a5f;
    border-title-color: #00cfff;
    border-title-align: left;
    padding: 1 2;
    margin: 1;
}

/* ── Scan input area ── */
#scan-input-row {
    layout: horizontal;
    height: 5;
    margin: 1;
}
#target-input {
    width: 1fr;
    background: #0d1929;
    border: solid #1e3a5f;
    color: #c9d1e0;
}
#mode-select {
    width: 30;
    background: #0d1929;
    border: solid #1e3a5f;
    color: #c9d1e0;
}
#scan-btn {
    width: 16;
    background: #1e3a5f;
    color: #00ff88;
    border: solid #00ff88;
}
#scan-btn:hover { background: #00ff88; color: #0a0e1a; }
#stop-btn {
    width: 14;
    background: #1e3a5f;
    color: #ff4455;
    border: solid #ff4455;
    display: none;
}

/* ── Status bar ── */
#status-bar {
    layout: horizontal;
    height: 3;
    background: #0d1929;
    border: solid #1e3a5f;
    margin: 0 1;
    padding: 0 2;
}
.status-cell {
    width: 1fr;
    content-align: center middle;
    color: #607090;
}
.status-val { color: #00ff88; }

/* ── Progress ── */
#progress-row {
    height: 3;
    margin: 0 1;
}
ProgressBar {
    color: #00ff88;
    background: #1e3a5f;
}

/* ── Telemetry log ── */
#telemetry-log {
    height: 14;
    background: #0a0e1a;
    border: solid #1e3a5f;
    border-title-color: #00cfff;
    margin: 0 1;
}

/* ── Results table panel ── */
#results-panel {
    height: 1fr;
    margin: 0 1 1 1;
}

/* ── Notification toast ── */
.toast {
    layer: notifications;
    dock: bottom;
    width: 50;
    align: right bottom;
    background: #111827;
    border: solid #00ff88;
    color: #00ff88;
    padding: 1 2;
    margin: 1;
    display: none;
}
.toast.error  { border: solid #ff4455; color: #ff4455; }
.toast.warn   { border: solid #ffcc00; color: #ffcc00; }

/* ── History / DB tables ── */
DataTable {
    height: 1fr;
    background: #0a0e1a;
}
DataTable > .datatable--header { background: #0d1929; color: #00cfff; }
DataTable > .datatable--cursor { background: #1e3a5f; }

/* ── Plugin panel ── */
#plugin-select { width: 1fr; background: #0d1929; border: solid #1e3a5f; }
#run-plugin-btn {
    width: 18;
    background: #1e3a5f;
    color: #00cfff;
    border: solid #00cfff;
}
#run-plugin-btn:hover { background: #00cfff; color: #0a0e1a; }
#plugin-output {
    height: 1fr;
    background: #0a0e1a;
    border: solid #1e3a5f;
    border-title-color: #00cfff;
    margin-top: 1;
}

/* ── Settings ── */
.theme-btn {
    width: 20;
    margin: 0 1;
    background: #0d1929;
    border: solid #1e3a5f;
    color: #c9d1e0;
}
.theme-btn:hover { background: #1e3a5f; color: #00ff88; }

/* ── System monitor ── */
.sys-row {
    layout: horizontal;
    height: 3;
    border-bottom: solid #1e3a5f;
    padding: 0 1;
}
.sys-label { width: 24; color: #607090; content-align: left middle; }
.sys-value { width: 1fr; color: #00ff88; content-align: left middle; }

/* ── Header ── */
Header { background: #0d1929; color: #00cfff; }
Footer { background: #0d1929; color: #607090; }
"""

# ─────────────────────────────────────────────────────────────────────────────
# Notification widget
# ─────────────────────────────────────────────────────────────────────────────

class Toast(Static):
    def show(self, message: str, kind: str = "success") -> None:
        self.remove_class("error", "warn")
        if kind == "error":
            self.add_class("error")
        elif kind == "warn":
            self.add_class("warn")
        self.update(message)
        self.styles.display = "block"
        self.set_timer(3.0, self._hide)

    def _hide(self) -> None:
        self.styles.display = "none"

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard screen
# ─────────────────────────────────────────────────────────────────────────────

class DashboardView(Vertical):
    """Live scan dashboard with target input, telemetry, results."""

    def compose(self) -> ComposeResult:
        # ── Scan input row ─────────────────────────────────────────────────
        with Horizontal(id="scan-input-row"):
            yield Input(placeholder="Target: IP, hostname, or CIDR …", id="target-input")
            yield Select(
                [(cfg["name"], key) for key, cfg in SCAN_MODES.items()],
                value="1",
                id="mode-select",
            )
            yield Button("▶  Scan",  id="scan-btn",  variant="success")
            yield Button("■  Stop",  id="stop-btn",  variant="error")

        # ── Status bar ─────────────────────────────────────────────────────
        with Horizontal(id="status-bar"):
            yield Static("Target",    classes="status-cell")
            yield Static("—",         classes="status-cell status-val", id="sb-target")
            yield Static("Mode",      classes="status-cell")
            yield Static("—",         classes="status-cell status-val", id="sb-mode")
            yield Static("Status",    classes="status-cell")
            yield Static("Idle",      classes="status-cell status-val", id="sb-status")
            yield Static("Elapsed",   classes="status-cell")
            yield Static("00:00",     classes="status-cell status-val", id="sb-elapsed")

        # ── Progress ───────────────────────────────────────────────────────
        with Horizontal(id="progress-row"):
            yield ProgressBar(total=100, show_eta=False, id="scan-progress")

        # ── Live telemetry ─────────────────────────────────────────────────
        yield Log(id="telemetry-log", auto_scroll=True)

        # ── Results table ──────────────────────────────────────────────────
        with Container(id="results-panel", classes="panel"):
            yield DataTable(id="results-table", zebra_stripes=True)

    def on_mount(self) -> None:
        tbl = self.query_one("#results-table", DataTable)
        tbl.add_columns("Port", "Protocol", "State", "Service", "Version", "Risk")

    def reset_results(self) -> None:
        tbl = self.query_one("#results-table", DataTable)
        tbl.clear()

    def add_port_row(self, port: str, proto: str, state: str,
                     service: str, version: str, risk: str) -> None:
        tbl = self.query_one("#results-table", DataTable)
        tbl.add_row(port, proto, state, service, version[:30], risk)

# ─────────────────────────────────────────────────────────────────────────────
# History view
# ─────────────────────────────────────────────────────────────────────────────

class HistoryView(Vertical):
    def compose(self) -> ComposeResult:
        with TabbedContent():
            with TabPane("Scans"):
                yield DataTable(id="hist-scans", zebra_stripes=True)
            with TabPane("Plugins"):
                yield DataTable(id="hist-plugins", zebra_stripes=True)
            with TabPane("Reports"):
                yield DataTable(id="hist-reports", zebra_stripes=True)
            with TabPane("Errors"):
                yield DataTable(id="hist-errors", zebra_stripes=True)

    def on_mount(self) -> None:
        scans = self.query_one("#hist-scans", DataTable)
        scans.add_columns("ID","Target","Mode","Open","Risk","Status","Timestamp")

        plugins = self.query_one("#hist-plugins", DataTable)
        plugins.add_columns("ID","Target","Plugin","Status","Duration","Time")

        reports = self.query_one("#hist-reports", DataTable)
        reports.add_columns("ID","Target","Format","File","Time")

        errors = self.query_one("#hist-errors", DataTable)
        errors.add_columns("ID","Module","Target","Message","Time")

    def refresh_data(self) -> None:
        self._load_scans()
        self._load_plugins()
        self._load_reports()
        self._load_errors()

    def _load_scans(self) -> None:
        tbl = self.query_one("#hist-scans", DataTable)
        tbl.clear()
        for r in get_scan_history(50):
            tbl.add_row(
                str(r["id"]), r["target"], r["scan_type"],
                str(r["open_ports"]), str(r["risk_score"]),
                r["status"], r["timestamp"],
            )

    def _load_plugins(self) -> None:
        tbl = self.query_one("#hist-plugins", DataTable)
        tbl.clear()
        for r in get_plugin_history(50):
            tbl.add_row(
                str(r["id"]), r["target"], r["plugin_name"],
                "✓" if r["success"] else "✗",
                f"{r['duration']:.1f}s", r["ran_at"],
            )

    def _load_reports(self) -> None:
        tbl = self.query_one("#hist-reports", DataTable)
        tbl.clear()
        for r in get_report_history(50):
            fname = os.path.basename(r["filepath"])
            tbl.add_row(str(r["id"]), r["target"], r["format"], fname, r["created_at"])

    def _load_errors(self) -> None:
        tbl = self.query_one("#hist-errors", DataTable)
        tbl.clear()
        for r in get_error_history(50):
            msg = r["message"][:60]
            tbl.add_row(str(r["id"]), r["module"], r["target"], msg, r["occurred"])

# ─────────────────────────────────────────────────────────────────────────────
# Plugin view
# ─────────────────────────────────────────────────────────────────────────────

class PluginView(Vertical):
    def __init__(self, registry: dict, **kwargs):
        super().__init__(**kwargs)
        self._registry = registry

    @staticmethod
    def _options_for(registry: dict) -> list[tuple[str, str]]:
        opts = [(p.description, name) for name, p in registry.items()]
        return opts if opts else [("No plugins loaded", "none")]

    def compose(self) -> ComposeResult:
        with Horizontal(id="plugin-input-row"):
            yield Select(self._options_for(self._registry), id="plugin-select")
            yield Button("▶  Run Plugin", id="run-plugin-btn")
        yield Log(id="plugin-output", auto_scroll=True)

    def set_registry(self, registry: dict) -> None:
        self._registry = registry
        try:
            select = self.query_one("#plugin-select", Select)
            select.set_options(self._options_for(registry))
        except NoMatches:
            pass  # view not mounted yet — compose() will pick up self._registry directly

    def write_output(self, text: str) -> None:
        try:
            log = self.query_one("#plugin-output", Log)
            log.write_line(text)
        except NoMatches:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# Packet capture (v2.4)
# ─────────────────────────────────────────────────────────────────────────────

class CaptureView(Vertical):
    """Packet capture setup, live telemetry, and results table.

    Mirrors DashboardView's status-bar/telemetry-log/results-table shape
    and PluginView's "configure -> run -> stream output" flow, so it slots
    into the existing page-switching model (display: block/none on a
    sibling widget) instead of introducing a separate screen stack.
    """

    def compose(self) -> ComposeResult:
        with Horizontal(id="capture-input-row"):
            yield Select(
                [("eth0", "eth0"), ("lo", "lo"), ("wlan0", "wlan0")],
                value="eth0",
                id="capture-interface-select",
            )
            yield Input(placeholder="BPF filter, e.g. tcp port 443", id="capture-filter-input")
            yield Input(placeholder="Duration (s), 0 = until Stop", id="capture-duration-input", value="60")
            yield Button("▶  Start", id="capture-start-btn", variant="success")
            yield Button("■  Stop",  id="capture-stop-btn",  variant="error")

        with Horizontal(id="capture-status-bar"):
            yield Static("Interface", classes="status-cell")
            yield Static("—",         classes="status-cell status-val", id="cap-interface")
            yield Static("Packets",   classes="status-cell")
            yield Static("0",         classes="status-cell status-val", id="cap-packets")
            yield Static("Status",    classes="status-cell")
            yield Static("Idle",      classes="status-cell status-val", id="cap-status")
            yield Static("Elapsed",   classes="status-cell")
            yield Static("00:00",     classes="status-cell status-val", id="cap-elapsed")

        yield Log(id="capture-telemetry-log", auto_scroll=True)

        with Container(id="capture-results-panel", classes="panel"):
            yield DataTable(id="capture-packet-table", zebra_stripes=True)

    def on_mount(self) -> None:
        tbl = self.query_one("#capture-packet-table", DataTable)
        tbl.add_columns("No.", "Time", "Source", "Dest", "Protocol", "Length", "Info")

    def populate_interfaces(self, interfaces: list[tuple[str, str]]) -> None:
        if not interfaces:
            return
        select = self.query_one("#capture-interface-select", Select)
        select.set_options(interfaces)

    def write_output(self, text: str) -> None:
        try:
            log = self.query_one("#capture-telemetry-log", Log)
            log.write_line(text)
        except NoMatches:
            pass

    def set_status(self, interface: str, packets: str, status: str, elapsed: str) -> None:
        try:
            self.query_one("#cap-interface", Static).update(interface)
            self.query_one("#cap-packets",   Static).update(packets)
            self.query_one("#cap-status",    Static).update(status)
            self.query_one("#cap-elapsed",   Static).update(elapsed)
        except NoMatches:
            pass

    def reset_packet_table(self) -> None:
        try:
            self.query_one("#capture-packet-table", DataTable).clear()
        except NoMatches:
            pass

    def add_packet_row(self, no: str, time_s: str, src: str, dst: str,
                       proto: str, length: str, info: str) -> None:
        try:
            tbl = self.query_one("#capture-packet-table", DataTable)
            tbl.add_row(no, time_s, src, dst, proto, length, info[:60])
        except NoMatches:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# Database viewer
# ─────────────────────────────────────────────────────────────────────────────

class DatabaseView(Vertical):
    def compose(self) -> ComposeResult:
        with TabbedContent():
            with TabPane("Scans"):
                yield DataTable(id="db-scans", zebra_stripes=True)
            with TabPane("Plugins"):
                yield DataTable(id="db-plugins", zebra_stripes=True)
            with TabPane("Reports"):
                yield DataTable(id="db-reports", zebra_stripes=True)
            with TabPane("Errors"):
                yield DataTable(id="db-errors", zebra_stripes=True)
        yield Button("⟳  Refresh", id="db-refresh-btn")

    def on_mount(self) -> None:
        s = self.query_one("#db-scans", DataTable)
        s.add_columns("ID","Target","Scan Type","Open","Risk","Status","Timestamp")
        p = self.query_one("#db-plugins", DataTable)
        p.add_columns("ID","Target","Plugin","Success","Duration","Time")
        r = self.query_one("#db-reports", DataTable)
        r.add_columns("ID","Target","Format","File","Time")
        e = self.query_one("#db-errors", DataTable)
        e.add_columns("ID","Module","Target","Message","Time")
        self.load_all()

    def load_all(self) -> None:
        self._load("#db-scans",   get_scan_history(100),   self._scan_row)
        self._load("#db-plugins", get_plugin_history(100), self._plugin_row)
        self._load("#db-reports", get_report_history(100), self._report_row)
        self._load("#db-errors",  get_error_history(100),  self._error_row)

    def _load(self, sel: str, rows: list, mapper) -> None:
        tbl = self.query_one(sel, DataTable)
        tbl.clear()
        for r in rows:
            tbl.add_row(*mapper(r))

    @staticmethod
    def _scan_row(r):   return str(r["id"]), r["target"], r["scan_type"], str(r["open_ports"]), str(r["risk_score"]), r["status"], r["timestamp"]
    @staticmethod
    def _plugin_row(r): return str(r["id"]), r["target"], r["plugin_name"], "✓" if r["success"] else "✗", f"{r['duration']:.1f}s", r["ran_at"]
    @staticmethod
    def _report_row(r): return str(r["id"]), r["target"], r["format"], os.path.basename(r["filepath"]), r["created_at"]
    @staticmethod
    def _error_row(r):  return str(r["id"]), r["module"], r["target"], r["message"][:60], r["occurred"]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "db-refresh-btn":
            self.load_all()

# ─────────────────────────────────────────────────────────────────────────────
# Reports view
# ─────────────────────────────────────────────────────────────────────────────

class ReportsView(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Report Center", classes="panel")
        yield DataTable(id="reports-list", zebra_stripes=True)
        with Horizontal():
            yield Button("⟳ Refresh", id="reports-refresh")

    def on_mount(self) -> None:
        tbl = self.query_one("#reports-list", DataTable)
        tbl.add_columns("File", "Size", "Modified")
        self.load_reports()

    def load_reports(self) -> None:
        tbl = self.query_one("#reports-list", DataTable)
        tbl.clear()
        try:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            for fname in sorted(os.listdir(REPORTS_DIR), reverse=True):
                fpath = os.path.join(REPORTS_DIR, fname)
                size  = f"{os.path.getsize(fpath) // 1024} KB"
                mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M")
                tbl.add_row(fname, size, mtime)
        except Exception as e:
            log_error("reports_view", "", str(e), e)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "reports-refresh":
            self.load_reports()

# ─────────────────────────────────────────────────────────────────────────────
# System monitor
# ─────────────────────────────────────────────────────────────────────────────

class SystemView(Vertical):
    def compose(self) -> ComposeResult:
        import shutil, platform
        root     = "Yes ✓" if is_root() else "No ✗"
        nmap_ok  = "Installed ✓" if is_nmap_installed() else "Not found ✗"
        nmap_ver = "—"
        try:
            import subprocess
            r = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=3)
            nmap_ver = r.stdout.splitlines()[0] if r.stdout else "—"
        except Exception:
            pass

        try:
            stats = get_stats()
        except Exception as e:
            log_error("main", "", "SystemView get_stats failed", e)
            stats = {
                "total_scans": "—", "unique_targets": "—", "total_plugins": "—",
                "total_reports": "—", "total_errors": "—", "avg_risk_score": "—",
                "last_scan": "—",
            }

        rows = [
            ("Version",         f"ShadowPort Scanner v{VERSION}"),
            ("Nmap",            nmap_ok),
            ("Nmap Version",    nmap_ver),
            ("Root Privileges", root),
            ("Platform",        platform.platform()),
            ("Python",          sys.version.split()[0]),
            ("Total Scans",     str(stats["total_scans"])),
            ("Unique Targets",  str(stats["unique_targets"])),
            ("Total Plugins",   str(stats["total_plugins"])),
            ("Total Reports",   str(stats["total_reports"])),
            ("Total Errors",    str(stats["total_errors"])),
            ("Avg Risk Score",  str(stats["avg_risk_score"])),
            ("Last Scan",       stats["last_scan"]),
            ("DB Path",         str(os.path.abspath(os.path.join(LOG_DIR, "shadowport.db")))),
            ("Log Dir",         str(os.path.abspath(LOG_DIR))),
        ]
        for label, value in rows:
            with Horizontal(classes="sys-row"):
                yield Static(label, classes="sys-label")
                yield Static(value, classes="sys-value")

# ─────────────────────────────────────────────────────────────────────────────
# Settings view
# ─────────────────────────────────────────────────────────────────────────────

class SettingsView(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Themes", classes="panel")
        with Horizontal():
            yield Button("🟢 Cyber Green",  id="theme-cyber_green",  classes="theme-btn")
            yield Button("🔵 Blue Team",    id="theme-blue_team",    classes="theme-btn")
            yield Button("🟣 Purple Neon",  id="theme-purple_neon",  classes="theme-btn")
            yield Button("⚫ Dark Mode",    id="theme-dark",         classes="theme-btn")
            yield Button("⚪ Light Mode",   id="theme-light",        classes="theme-btn")

# ─────────────────────────────────────────────────────────────────────────────
# Help view
# ─────────────────────────────────────────────────────────────────────────────

HELP_MD = f"""
# ShadowPort Scanner v{VERSION} — Help

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| F1  | Help   |
| F2  | New Scan (focus Dashboard) |
| F3  | Reports |
| F4  | Plugins |
| F5  | Refresh current view |
| ESC | Back / Cancel |
| Ctrl+C | Exit safely |

## Scan Modes

| # | Mode | Root? | Timeout |
|---|------|-------|---------|
| 1 | Quick Scan | No | 60s |
| 2 | Full TCP | No | 600s |
| 3 | Service Detection | No | 180s |
| 4 | OS Detection | Yes | 120s |
| 5 | Aggressive | Yes | 300s |
| 6 | Host Discovery | No | 30s |
| 7 | Stealth SYN | Yes | 120s |
| 8 | Vuln Scripts | No | 300s |

## Usage

Enter a target IP, hostname, or CIDR range, select a mode, press **Scan**.

Live events appear in the telemetry panel in real time.

Results are saved automatically to **SQLite**, **Excel**, and **JSON**.

## Ethical Use

Use only on systems you own or are explicitly authorized to test.
"""

class HelpView(ScrollableContainer):
    def compose(self) -> ComposeResult:
        yield Markdown(HELP_MD)

# ─────────────────────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────────────────────

class ShadowPortApp(App):
    TITLE   = f"ShadowPort Scanner v{VERSION}"
    CSS     = APP_CSS

    BINDINGS = [
        Binding("f1",     "show_help",      "Help",      show=True),
        Binding("f2",     "show_dashboard", "New Scan",  show=True),
        Binding("f3",     "show_reports",   "Reports",   show=True),
        Binding("f4",     "show_plugins",   "Plugins",   show=True),
        Binding("f5",     "refresh_view",   "Refresh",   show=True),
        Binding("escape", "go_back",        "Back",      show=True),
        Binding("ctrl+c", "quit_safe",      "Exit",      show=True),
    ]

    _current_page: reactive[str] = reactive("dashboard")
    _scanning:     bool          = False
    _scan_thread:  Optional[threading.Thread] = None
    _scan_data:    Optional[dict] = None
    _last_target:  str           = ""
    _last_mode:    str           = "1"
    _start_ts:     float         = 0.0
    _elapsed_thread: Optional[threading.Thread] = None
    _plugin_registry: dict       = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="app-layout"):
            # ── Sidebar ───────────────────────────────────────────────────
            with Vertical(id="sidebar"):
                yield Static(f"[bold #00cfff]☠ ShadowPort[/]\n[dim]v{VERSION}[/]\n")
                yield Button("◉  Dashboard",  id="nav-dashboard",  classes="nav-btn active")
                yield Button("⊙  Plugins",    id="nav-plugins",    classes="nav-btn")
                yield Button("⊙  Capture",    id="nav-capture",    classes="nav-btn")
                yield Button("⊙  Reports",    id="nav-reports",    classes="nav-btn")
                yield Button("⊙  History",    id="nav-history",    classes="nav-btn")
                yield Button("⊙  Database",   id="nav-database",   classes="nav-btn")
                yield Button("⊙  System",     id="nav-system",     classes="nav-btn")
                yield Button("⊙  Settings",   id="nav-settings",   classes="nav-btn")
                yield Button("⊙  Help",       id="nav-help",       classes="nav-btn")

            # ── Main area ─────────────────────────────────────────────────
            with Container(id="main-area"):
                yield DashboardView(id="page-dashboard")
                yield PluginView(self._plugin_registry, id="page-plugins")
                yield CaptureView(id="page-capture")
                yield ReportsView(id="page-reports")
                yield HistoryView(id="page-history")
                yield DatabaseView(id="page-database")
                yield SystemView(id="page-system")
                yield SettingsView(id="page-settings")
                yield HelpView(id="page-help")

        yield Toast(id="toast", classes="toast")
        yield Footer()

    def on_mount(self) -> None:
        # v2.4 — persistent config + theme restoration. Done first so the
        # saved theme is visible from the very first frame, before the
        # hardcoded CSS defaults would otherwise be what's on screen.
        self.config_manager = ConfigManager()
        self.theme_manager = ThemeManager(self, self.config_manager)
        self.theme_manager.apply_saved_theme()
        self._capture_engine: Optional[CaptureEngine] = None
        self._capture_start_ts: float = 0.0

        # Init DB
        try:
            init_db()
        except Exception as e:
            log_error("main", "", "DB init failed", e)

        # Load plugins
        try:
            self._plugin_registry = plugin_loader.load_plugins()
            pv = self.query_one("#page-plugins", PluginView)
            pv.set_registry(self._plugin_registry)
            if not self._plugin_registry:
                log_error("main", "", "Plugin auto-discovery found 0 plugins — "
                          "check plugins/__init__.py and Log/error.log for per-file import errors")
        except Exception as e:
            log_error("main", "", "Plugin load failed", e)

        # Show only dashboard
        self._show_page("dashboard")

        # Startup notification
        stats = get_stats()
        self._toast(
            f"Welcome! {stats['total_scans']} scans | "
            f"{stats['unique_targets']} targets | "
            f"DB ready"
        )

    # ── Page navigation ───────────────────────────────────────────────────────

    _PAGES = ["dashboard","plugins","capture","reports","history","database","system","settings","help"]

    def _show_page(self, name: str) -> None:
        for page in self._PAGES:
            try:
                w = self.query_one(f"#page-{page}")
                w.styles.display = "block" if page == name else "none"
            except NoMatches:
                pass

        for btn in self.query(".nav-btn"):
            btn.remove_class("active")
        try:
            self.query_one(f"#nav-{name}").add_class("active")
        except NoMatches:
            pass

        self._current_page = name

        # Refresh data on page switch
        if name == "history":
            try:
                self.query_one("#page-history", HistoryView).refresh_data()
            except NoMatches:
                pass
        elif name == "database":
            try:
                self.query_one("#page-database", DatabaseView).load_all()
            except NoMatches:
                pass
        elif name == "reports":
            try:
                self.query_one("#page-reports", ReportsView).load_reports()
            except NoMatches:
                pass
        elif name == "capture":
            self._load_capture_interfaces()

    def on_button_pressed(self, event: Button.Pressed) -> None:  # noqa: C901
        bid = event.button.id or ""

        # Navigation
        nav_map = {
            "nav-dashboard": "dashboard", "nav-plugins":  "plugins",
            "nav-capture":   "capture",
            "nav-reports":   "reports",   "nav-history":  "history",
            "nav-database":  "database",  "nav-system":   "system",
            "nav-settings":  "settings",  "nav-help":     "help",
        }
        if bid in nav_map:
            self._show_page(nav_map[bid])
            return

        # Theme buttons
        if bid.startswith("theme-"):
            theme_key = bid[len("theme-"):]
            self.theme_manager.switch(theme_key)
            return

        # Scan
        if bid == "scan-btn":
            self._start_scan()
            return

        if bid == "stop-btn":
            self._scanning = False
            self._set_status("Cancelled")
            self._toast("Scan cancelled.", "warn")
            self._toggle_scan_buttons(scanning=False)
            return

        # Plugin run
        if bid == "run-plugin-btn":
            self._run_plugin()
            return

        # Packet capture (v2.4)
        if bid == "capture-start-btn":
            self._start_capture()
            return

        if bid == "capture-stop-btn":
            self._stop_capture()
            return

    # ── Scan workflow ─────────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        if self._scanning:
            return

        target_input = self.query_one("#target-input", Input)
        mode_select  = self.query_one("#mode-select",  Select)
        target = target_input.value.strip()
        mode   = str(mode_select.value) if mode_select.value else "1"

        ok, reason = validate_target(target)
        if not ok:
            self._toast(f"Invalid target: {reason}", "error")
            self._log_event("ERROR", f"Invalid target: {reason}")
            return

        self._last_target = target
        self._last_mode   = mode
        self._scanning    = True
        self._start_ts    = time.time()
        self._scan_data   = None

        mode_name = SCAN_MODES.get(mode, {}).get("name", mode)
        self._set_status_bar(target, mode_name, "Scanning…", "00:00")
        self._set_progress(0)
        self._toggle_scan_buttons(scanning=True)

        # Reset results table
        try:
            self.query_one("#page-dashboard", DashboardView).reset_results()
        except NoMatches:
            pass

        self._log_event("INFO", f"Starting {mode_name} on {target}")
        self._show_page("dashboard")

        # Elapsed timer thread
        self._elapsed_thread = threading.Thread(target=self._tick_elapsed, daemon=True)
        self._elapsed_thread.start()

        # Scan thread
        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(target, mode),
            daemon=True,
        )
        self._scan_thread.start()

    def _scan_worker(self, target: str, mode: str) -> None:
        result = run_scan(target, mode, on_event=self._on_scan_event)
        self.app.call_from_thread(self._on_scan_done, result)

    def _on_scan_event(self, level: str, message: str) -> None:
        self.app.call_from_thread(self._handle_event, level, message)

    def _handle_event(self, level: str, message: str) -> None:
        if level == "PROGRESS":
            try:
                self._set_progress(int(message))
            except ValueError:
                pass
            return
        self._log_event(level, message)

    def _on_scan_done(self, result: Optional[dict]) -> None:
        self._scanning = False
        self._toggle_scan_buttons(scanning=False)
        self._set_progress(100)

        if not result:
            self._set_status("Failed")
            self._toast("Scan failed. See telemetry for details.", "error")
            return

        self._scan_data = result
        risk = result.get("risk", {})
        rs   = risk.get("score", 0)

        # Populate results table
        try:
            dv = self.query_one("#page-dashboard", DashboardView)
            for p in result.get("ports", []):
                if p.get("state") == "open":
                    intel = p.get("intel") or {}
                    dv.add_port_row(
                        p.get("port",""), p.get("proto",""),
                        p.get("state",""), p.get("service",""),
                        p.get("version",""),
                        intel.get("risk","")[:40],
                    )
        except NoMatches:
            pass

        open_c  = sum(1 for p in result.get("ports",[]) if p.get("state")=="open")
        partial = " [PARTIAL]" if result.get("partial") else ""
        self._set_status(f"Done — {open_c} open{partial}")
        self._log_event("INFO", f"Risk: {rs}/100 [{risk.get('label','—')}]")

        # Dual-write: SQLite
        try:
            sid = save_scan(result, risk_score=rs)
        except Exception as e:
            sid = None
            log_error("main", result.get("host",""), "DB save failed", e)

        # Dual-write: Excel
        try:
            ok, msg = log_scan_to_excel(result, risk_score=rs)
            if not ok:
                self._log_event("WARNING", f"Excel: {msg}")
        except Exception as e:
            log_error("main", result.get("host",""), "Excel save failed", e)

        # JSON history
        try:
            record_scan(result, rs)
        except Exception as e:
            log_error("main", result.get("host",""), "JSON history failed", e)

        self._toast(f"✓ Scan complete — {open_c} open port(s) | Risk {rs}/100")

    def _tick_elapsed(self) -> None:
        while self._scanning:
            elapsed = int(time.time() - self._start_ts)
            mm, ss  = elapsed // 60, elapsed % 60
            self.app.call_from_thread(
                self._update_elapsed, f"{mm:02d}:{ss:02d}"
            )
            time.sleep(1.0)

    def _update_elapsed(self, val: str) -> None:
        try:
            self.query_one("#sb-elapsed").update(val)
        except NoMatches:
            pass

    # ── Plugin workflow ───────────────────────────────────────────────────────

    def _run_plugin(self) -> None:
        if not self._scan_data and not self._last_target:
            self._toast("Run a scan first.", "warn")
            return

        try:
            sel = self.query_one("#plugin-select", Select)
            plugin_name = str(sel.value)
        except NoMatches:
            return

        if plugin_name == "none" or plugin_name not in self._plugin_registry:
            self._toast("No plugin selected.", "warn")
            return

        plugin = self._plugin_registry[plugin_name]
        target = self._last_target or (self._scan_data or {}).get("host","")
        scan_d = self._scan_data or {"host": target, "ports": []}

        try:
            pv = self.query_one("#page-plugins", PluginView)
            pv.write_output(f"[{datetime.now().strftime('%H:%M:%S')}] Running {plugin_name} on {target}…")
        except NoMatches:
            pass

        def _worker():
            start = time.time()
            try:
                result  = plugin.run(target, scan_d)
                output  = result.get("output","(no output)")
                success = True
                error   = ""
            except Exception as e:
                output  = f"Plugin error: {e}"
                success = False
                error   = str(e)
                log_error("plugin", target, error, e)

            duration = time.time() - start
            self.app.call_from_thread(
                self._on_plugin_done, plugin_name, target, output, duration, success, error
            )

        threading.Thread(target=_worker, daemon=True).start()

    def _on_plugin_done(self, name: str, target: str, output: str,
                        duration: float, success: bool, error: str) -> None:
        try:
            pv = self.query_one("#page-plugins", PluginView)
            pv.write_output(output)
            pv.write_output(f"{'✓ Done' if success else '✗ Failed'} in {duration:.1f}s")
        except NoMatches:
            pass

        # Save plugin result: SQLite
        try:
            sid = self._get_last_scan_id()
            log_plugin(sid, target, name, output, duration, success, error)
        except Exception as e:
            log_error("plugin_save", target, str(e), e)

        # Save plugin result: Excel
        try:
            log_plugin_to_excel(target, name, output, duration, success)
        except Exception as e:
            log_error("plugin_excel", target, str(e), e)

        # JSON history
        try:
            record_plugin(target, name, output, success)
        except Exception as e:
            log_error("plugin_json", target, str(e), e)

        status = "success" if success else "error"
        self._toast(f"Plugin {name}: {'done' if success else 'failed'}", status)

    # ── Packet capture workflow (v2.4) ──────────────────────────────────────

    def _load_capture_interfaces(self) -> None:
        """Populate the interface Select via `tshark -D`, off the main thread."""
        def _worker():
            import re
            import shutil as shutil_mod
            import subprocess as subprocess_mod

            if shutil_mod.which("tshark") is None:
                self.app.call_from_thread(
                    self._on_interfaces_failed,
                    "tshark not found — install wireshark-cli (see README)",
                )
                return
            try:
                result = subprocess_mod.run(
                    ["tshark", "-D"], shell=False, capture_output=True,
                    text=True, timeout=10,
                )
            except (FileNotFoundError, subprocess_mod.TimeoutExpired) as e:
                self.app.call_from_thread(self._on_interfaces_failed, str(e))
                return

            if result.returncode != 0:
                self.app.call_from_thread(
                    self._on_interfaces_failed, result.stderr.strip() or "tshark -D failed"
                )
                return

            interfaces = []
            for raw_line in result.stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                stripped = re.sub(r"^\d+\.\s*", "", line)
                if not stripped:
                    continue
                name = stripped.split()[0]
                interfaces.append((name, stripped))

            self.app.call_from_thread(self._on_interfaces_loaded, interfaces)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_interfaces_failed(self, message: str) -> None:
        try:
            cv = self.query_one("#page-capture", CaptureView)
            cv.write_output(f"[ERROR] {message}")
        except NoMatches:
            pass
        log_error("capture", "", message)

    def _on_interfaces_loaded(self, interfaces: list[tuple[str, str]]) -> None:
        try:
            cv = self.query_one("#page-capture", CaptureView)
            cv.populate_interfaces(interfaces)
        except NoMatches:
            pass

    def _start_capture(self) -> None:
        if self._capture_engine is not None:
            self._toast("A capture is already running.", "warn")
            return

        try:
            cv = self.query_one("#page-capture", CaptureView)
            interface = str(self.query_one("#capture-interface-select", Select).value)
            bpf_filter = self.query_one("#capture-filter-input", Input).value.strip()
            duration_raw = self.query_one("#capture-duration-input", Input).value.strip() or "0"
        except NoMatches:
            return

        try:
            duration = int(duration_raw)
            if duration < 0:
                raise ValueError
        except ValueError:
            self._toast("Duration must be a non-negative integer.", "error")
            return

        try:
            engine = CaptureEngine(
                interface=interface, bpf_filter=bpf_filter, duration=duration,
                on_event=self._on_capture_event,
            )
        except ValueError as e:
            self._toast(f"Invalid interface: {e}", "error")
            return

        self._capture_engine = engine
        self._capture_start_ts = time.time()

        cv.reset_packet_table()
        cv.write_output(f"[{datetime.now().strftime('%H:%M:%S')}] Starting capture on {interface}…")
        cv.set_status(interface, "0", "Running", "00:00")

        try:
            engine.start()
        except RuntimeError as e:
            cv.write_output(f"[ERROR] {e}")
            self._capture_engine = None
            return

        threading.Thread(target=self._capture_tick, daemon=True).start()
        self.config_manager.set("capture_interface", interface)
        self.config_manager.set("capture_filter", bpf_filter)
        self.config_manager.set("capture_duration", duration)
        self.config_manager.save()

    def _capture_tick(self) -> None:
        while self._capture_engine is not None:
            engine = self._capture_engine
            elapsed = int(time.time() - self._capture_start_ts)
            mm, ss = elapsed // 60, elapsed % 60
            try:
                count = engine.get_packet_count()
            except Exception:
                count = "—"
            self.app.call_from_thread(
                self._update_capture_status, engine.interface, str(count),
                "Running" if engine.status == "running" else engine.status.capitalize(),
                f"{mm:02d}:{ss:02d}",
            )
            if engine.status in ("stopped", "failed"):
                self.app.call_from_thread(self._on_capture_finished)
                break
            time.sleep(0.5)

    def _update_capture_status(self, interface: str, packets: str,
                               status: str, elapsed: str) -> None:
        try:
            self.query_one("#page-capture", CaptureView).set_status(
                interface, packets, status, elapsed
            )
        except NoMatches:
            pass

    def _on_capture_event(self, level: str, message: str) -> None:
        self.app.call_from_thread(self._write_capture_event, level, message)

    def _write_capture_event(self, level: str, message: str) -> None:
        try:
            cv = self.query_one("#page-capture", CaptureView)
            cv.write_output(f"[{level}] {message}")
        except NoMatches:
            pass

    def _stop_capture(self) -> None:
        if self._capture_engine is None:
            self._toast("No capture running.", "warn")
            return
        self._capture_engine.stop()

    def _on_capture_finished(self) -> None:
        engine = self._capture_engine
        if engine is None:
            return

        elapsed = time.time() - self._capture_start_ts
        try:
            cap_id = log_capture(
                interface=engine.interface, bpf_filter=engine.bpf_filter,
                display_filter="", duration=elapsed,
                packet_count=engine.get_packet_count(),
                filepath=engine.output_file, status=engine.status,
            )
        except Exception as e:
            cap_id = None
            log_error("capture", engine.interface, "DB log_capture failed", e)

        try:
            cv = self.query_one("#page-capture", CaptureView)
            cv.write_output(
                f"[DONE] Capture saved — {engine.get_packet_count()} packets, "
                f"{engine.output_file}"
            )
        except NoMatches:
            pass

        self._toast(
            f"Capture {'complete' if engine.status == 'stopped' else 'failed'} — "
            f"{engine.get_packet_count()} packet(s)",
            "success" if engine.status == "stopped" else "error",
        )

        self._capture_engine = None

    def _get_last_scan_id(self) -> Optional[int]:
        history = get_scan_history(1)
        return history[0]["id"] if history else None

    # ── UI helpers ────────────────────────────────────────────────────────────

    def _log_event(self, level: str, message: str) -> None:
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {message}"
        try:
            log = self.query_one("#telemetry-log", Log)
            log.write_line(line)
        except NoMatches:
            pass

    def _set_status(self, status: str) -> None:
        try:
            self.query_one("#sb-status").update(status)
        except NoMatches:
            pass

    def _set_status_bar(self, target: str, mode: str, status: str, elapsed: str) -> None:
        try:
            self.query_one("#sb-target").update(target)
            self.query_one("#sb-mode").update(mode)
            self.query_one("#sb-status").update(status)
            self.query_one("#sb-elapsed").update(elapsed)
        except NoMatches:
            pass

    def _set_progress(self, value: int) -> None:
        try:
            pb = self.query_one("#scan-progress", ProgressBar)
            pb.progress = float(max(0, min(value, 100)))
        except NoMatches:
            pass

    def _toggle_scan_buttons(self, scanning: bool) -> None:
        try:
            self.query_one("#scan-btn").styles.display  = "none"  if scanning else "block"
            self.query_one("#stop-btn").styles.display  = "block" if scanning else "none"
        except NoMatches:
            pass

    def _toast(self, message: str, kind: str = "success") -> None:
        try:
            self.query_one("#toast", Toast).show(message, kind)
        except NoMatches:
            pass

    def _apply_theme(self, theme_key: str, silent: bool = False) -> None:
        from ui.themes import THEMES, THEME_LABELS
        if theme_key not in THEMES:
            return
        colors = THEMES[theme_key]
        for var, val in colors.items():
            self.styles.__dict__[var] = val
        if not silent:
            self._toast(f"Theme: {THEME_LABELS.get(theme_key, theme_key)}")

    # ── Key bindings ─────────────────────────────────────────────────────────

    def action_show_help(self)      -> None: self._show_page("help")
    def action_show_dashboard(self) -> None: self._show_page("dashboard")
    def action_show_reports(self)   -> None: self._show_page("reports")
    def action_show_plugins(self)   -> None: self._show_page("plugins")

    def action_refresh_view(self) -> None:
        page = self._current_page
        if page == "history":
            try:
                self.query_one("#page-history", HistoryView).refresh_data()
            except NoMatches:
                pass
        elif page == "database":
            try:
                self.query_one("#page-database", DatabaseView).load_all()
            except NoMatches:
                pass
        elif page == "reports":
            try:
                self.query_one("#page-reports", ReportsView).load_reports()
            except NoMatches:
                pass
        self._toast("Refreshed.")

    def action_go_back(self) -> None:
        self._show_page("dashboard")

    def action_quit_safe(self) -> None:
        self._scanning = False
        self.exit()


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

def main():
    try:
        init_db()  # must run before ShadowPortApp() — SystemView.compose()
                   # queries the DB during the initial widget tree build,
                   # which happens before App.on_mount() fires.
    except Exception as exc:
        log_error("main", "", "Startup DB init failed", exc)

    try:
        app = ShadowPortApp()
        app.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Goodbye.")
        sys.exit(0)
    except Exception as exc:
        log_error("main", "", str(exc), exc)
        print(f"\n[ERROR] Crash: {exc}")
        print("Details saved to Log/error.log")
        sys.exit(1)


if __name__ == "__main__":
    main()
