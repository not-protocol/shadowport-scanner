"""
output.py — ShadowPort Scanner v2.1.0
Terminal UI: banner, menus, results table, progress bar,
history table, scan comparison view.

v2.1.0 additions:
  - print_profiles_menu() renders ScanProfile dataclasses
  - print_change_report() wraps change_detector output
  - print_service_kb_panel() shows ServiceInfo for a port
  - ScanProgress.stop(state=) — done / timeout / cancel / error
  - _print_no_ports() with diagnostic suggestions
"""

import sys
import threading
import time

from colorama import Fore, Style, init

from config.settings import VERSION, TOOL_NAME, SCAN_MODES, EXIT_OPTION

init(autoreset=True)


# ─── Colour helpers ───────────────────────────────────────────────────────────

def _c(colour, text):
    return f"{colour}{text}{Style.RESET_ALL}"

def print_banner():
    print(_c(Fore.RED,    "─" * 72))
    print(_c(Fore.CYAN,   f"{'ShadowPort Scanner — Network Reconnaissance':^72}"))
    print(_c(Fore.YELLOW, f"{'v' + VERSION + '  ·  Use ONLY on authorized systems':^72}"))
    print(_c(Fore.RED,    "─" * 72))
    print()

def print_info(msg):    print(_c(Fore.CYAN,   f"[*] {msg}"))
def print_success(msg): print(_c(Fore.GREEN,  f"[+] {msg}"))
def print_warning(msg): print(_c(Fore.YELLOW, f"[!] {msg}"))
def print_error(msg):   print(_c(Fore.RED,    f"[ERROR] {msg}"))


# ─── Main menu ────────────────────────────────────────────────────────────────

def print_menu(is_root: bool = False):
    print(_c(Fore.CYAN, "  ┌─ Scan Modes " + "─" * 53 + "┐"))
    for key, cfg in SCAN_MODES.items():
        root_tag = _c(Fore.RED, " [root]") if cfg["root"] else ""
        unavail  = _c(Fore.RED, " ✗") if (cfg["root"] and not is_root) else ""
        print(
            f"  │  [{key}] {cfg['name']:<22}"
            f" {cfg['description']:<32}{root_tag}{unavail}"
        )
    print("  │")
    print("  │  [p] Scan Profiles      [c] Compare Scans     [d] Diff Last Two")
    print("  │  [h] History            [x] Plugins           [9] Exit")
    print(_c(Fore.CYAN, "  └" + "─" * 66 + "┘"))
    print()


# ─── Profiles menu ────────────────────────────────────────────────────────────

def print_profiles_menu(profiles):
    """
    Accepts either a list of ScanProfile dataclasses or a dict of profile dicts.
    """
    print(_c(Fore.CYAN, "\n  ┌─ Scan Profiles " + "─" * 50 + "┐"))
    if isinstance(profiles, list):
        for i, p in enumerate(profiles, 1):
            root_tag = _c(Fore.RED, " [root]") if p.requires_root else ""
            print(f"  │  [{i}] {p.name:<26} {p.description[:36]}{root_tag}")
    else:
        for key, p in profiles.items():
            print(f"  │  [{key[0]}] {p['name']:<26} {p['description']}")
    print("  │  [0] Cancel")
    print(_c(Fore.CYAN, "  └" + "─" * 66 + "┘\n"))


# ─── Plugins menu ─────────────────────────────────────────────────────────────

def print_plugins_menu(registry: dict):
    print(_c(Fore.CYAN, "\n  ┌─ Plugins " + "─" * 56 + "┐"))
    for i, (name, plugin) in enumerate(registry.items(), 1):
        print(f"  │  [{i}] {name:<22} {plugin.description}")
    print(_c(Fore.CYAN, "  └" + "─" * 66 + "┘\n"))


# ─── Progress bar ─────────────────────────────────────────────────────────────

BAR_WIDTH = 20


class ScanProgress:
    """
    Animated progress bar. Always terminates — never hangs.
    States: done | timeout | cancel | error
    """

    def __init__(self, eta_seconds: int, mode_name: str):
        self._eta      = max(eta_seconds, 1)
        self._mode     = mode_name
        self._stop_evt = threading.Event()
        self._thread   = threading.Thread(target=self._run, daemon=True)

    def _bar(self, pct: float, label: str, colour) -> str:
        filled  = int(BAR_WIDTH * pct)
        empty   = BAR_WIDTH - filled
        bar     = "█" * filled + "░" * empty
        pct_str = f"{int(pct * 100):>3}%"
        return _c(colour, f"  [{bar}] {pct_str}  {label}")

    def _run(self):
        start = time.time()
        while not self._stop_evt.is_set():
            elapsed = time.time() - start
            pct     = min(elapsed / self._eta, 0.97)
            line    = self._bar(pct, f"Scanning {self._mode}…", Fore.CYAN)
            sys.stdout.write(f"\r{line}   ")
            sys.stdout.flush()
            time.sleep(0.25)

    def start(self):
        self._thread.start()

    def stop(self, state: str = "done"):
        self._stop_evt.set()
        self._thread.join(timeout=2)

        if state == "done":
            line = self._bar(1.0,  "Scan Complete",          Fore.GREEN)
        elif state == "timeout":
            line = self._bar(0.75, "Timeout — terminated",   Fore.YELLOW)
        elif state == "cancel":
            line = self._bar(0.40, "Cancelled by user",      Fore.YELLOW)
        else:
            line = self._bar(0.0,  "Scan Failed",            Fore.RED)

        sys.stdout.write(f"\r{line}   \n\n")
        sys.stdout.flush()


# ─── Results table ────────────────────────────────────────────────────────────

def print_results_table(scan_data: dict, show_intel: bool = False):
    host     = scan_data.get("host", "N/A")
    hostname = scan_data.get("hostname", "")
    state    = scan_data.get("state", "unknown")
    ports    = scan_data.get("ports", [])
    os_list  = scan_data.get("os_matches", [])
    risk     = scan_data.get("risk", {})
    partial  = scan_data.get("partial", False)

    sep  = "═" * 68
    sep2 = "─" * 68

    print(_c(Fore.RED,  f"\n  {sep}"))
    print(_c(Fore.CYAN, f"  {'SCAN RESULTS':^68}"))
    print(_c(Fore.RED,  f"  {sep}"))

    sc = Fore.GREEN if state == "up" else Fore.RED
    print(
        f"  Target    : {_c(Fore.WHITE, host)}"
        + (f"  ({hostname})" if hostname else "")
    )
    print(
        f"  Status    : {_c(sc, state.upper())}"
        + (_c(Fore.YELLOW, "  ⚠ PARTIAL — timeout") if partial else "")
    )
    print(f"  Mode      : {scan_data.get('mode_name', 'N/A')}")
    print(f"  Duration  : {scan_data.get('duration_seconds', 0):.1f}s")

    if os_list:
        print(f"  OS Match  : {os_list[0]}")

    if risk and risk.get("label") != "N/A":
        score = risk.get("score", 0)
        label = risk.get("label", "")
        rc = Fore.RED if score >= 70 else Fore.YELLOW if score >= 40 else Fore.GREEN
        print(f"  Risk      : {_c(rc, f'{score}/100  [{label}]')}")

    print(f"  {sep2}")

    if not ports:
        _print_no_ports()
        return

    open_ports = [p for p in ports if p.get("state") == "open"]
    if not open_ports and not show_intel:
        _print_no_ports()
        return

    col_p, col_s, col_sv, col_v = 14, 12, 20, 20
    print(
        "  "
        + _c(Fore.CYAN, "PORT".ljust(col_p))
        + _c(Fore.CYAN, "STATE".ljust(col_s))
        + _c(Fore.CYAN, "SERVICE".ljust(col_sv))
        + _c(Fore.CYAN, "VERSION")
    )
    print(f"  {sep2}")

    for p in ports:
        sc2 = (
            Fore.GREEN  if p.get("state") == "open"   else
            Fore.RED    if p.get("state") == "closed"  else
            Fore.YELLOW
        )
        port_col  = _c(sc2, f"{p['port']}/{p.get('proto','tcp')}".ljust(col_p))
        state_col = _c(sc2, p.get("state", "").ljust(col_s))
        svc_col   = p.get("service", "").ljust(col_sv)
        ver_col   = p.get("version", "")[:col_v]
        print(f"  {port_col}{state_col}{svc_col}{ver_col}")

        if show_intel and p.get("state") == "open":
            intel = p.get("intel") or {}
            if intel.get("use"):
                print(f"  {'':>{col_p}} {_c(Fore.CYAN,   'Use :')} {intel['use']}")
            if intel.get("risk"):
                print(f"  {'':>{col_p}} {_c(Fore.YELLOW, 'Risk:')} {intel['risk']}")

    print(f"  {sep2}")
    open_c = sum(1 for p in ports if p.get("state") == "open")
    print(f"  Open ports : {_c(Fore.GREEN, str(open_c))}   Total : {len(ports)}")

    if risk.get("breakdown"):
        print(f"\n  {_c(Fore.YELLOW, 'Risk breakdown:')}")
        for b in risk["breakdown"]:
            print(f"    {b}")

    print(_c(Fore.RED, f"  {sep}\n"))


def _print_no_ports():
    sep = "━" * 56
    print(_c(Fore.YELLOW, f"\n  {sep}"))
    print(_c(Fore.YELLOW, "  No open ports discovered."))
    print()
    print("  Host may be:")
    print("    • Filtered by a firewall")
    print("    • Offline or unreachable")
    print("    • Blocking probes")
    print()
    print("  Suggestions:")
    print("    • Try a different scan mode")
    print("    • Verify the target is reachable: ping <target>")
    print("    • Run with sudo for SYN scan (mode 7)")
    print(_c(Fore.YELLOW, f"  {sep}\n"))


# ─── Service KB panel ─────────────────────────────────────────────────────────

def print_service_kb_panel(port: int):
    from core.service_kb import get_service_info
    info = get_service_info(port)
    risk_colour = (
        Fore.RED    if info.risk_level == "critical" else
        Fore.YELLOW if info.risk_level == "high"     else
        Fore.CYAN   if info.risk_level == "medium"   else
        Fore.GREEN
    )
    sep = "─" * 60
    print(_c(Fore.CYAN, f"\n  {sep}"))
    print(f"  Port {port} — {_c(Fore.WHITE, info.name)}")
    print(f"  {sep}")
    print(f"  Purpose     : {info.purpose}")
    print(f"  Common uses : {', '.join(info.common_uses)}")
    print(f"  Risk level  : {_c(risk_colour, info.risk_level.upper())}")
    print(f"  Notes       : {info.security_notes}")
    print(_c(Fore.CYAN, f"  {sep}\n"))


# ─── History table ────────────────────────────────────────────────────────────

def print_history_table(rows: list[dict]):
    if not rows:
        print_warning("No scan history found.")
        return
    print()
    print(
        _c(Fore.CYAN,
           f"  {'ID':<5} {'Target':<18} {'Scan Type':<22} "
           f"{'Open':<6} {'Risk':<6} {'Status':<10} {'Date'}")
    )
    print("  " + "─" * 76)
    for r in rows:
        partial_tag = " [P]" if r.get("partial") else ""
        print(
            f"  {r['id']:<5} {r['target']:<18} {r['scan_type']:<22} "
            f"{r['open_ports']:<6} {r['risk_score']:<6} "
            f"{r['status']:<10} {r['timestamp']}{partial_tag}"
        )
    print()


# ─── Comparison / diff ────────────────────────────────────────────────────────

def print_comparison(comp: dict):
    """Legacy dict-based comparison display (v2.0 compat)."""
    prev = comp.get("previous", {})
    curr = comp.get("current",  {})
    print(_c(Fore.CYAN, "\n  ┌─ Scan Comparison " + "─" * 48 + "┐"))
    print(f"  │  Previous : {prev.get('timestamp','')}  (open: {prev.get('open_ports',0)})")
    print(f"  │  Current  : {curr.get('timestamp','')}  (open: {curr.get('open_ports',0)})")
    print("  │")

    if comp.get("new_ports"):
        print(_c(Fore.RED, "  │  ✚ New ports detected:"))
        for p in comp["new_ports"]:
            print(_c(Fore.RED, f"  │      → {p}/tcp"))

    if comp.get("closed_ports"):
        print(_c(Fore.GREEN, "  │  ✖ Ports now closed:"))
        for p in comp["closed_ports"]:
            print(_c(Fore.GREEN, f"  │      → {p}/tcp"))

    if comp.get("unchanged"):
        ports_str = ", ".join(str(p) for p in comp["unchanged"])
        print(f"  │  ═ Unchanged: {ports_str}")

    print(_c(Fore.CYAN, "  └" + "─" * 66 + "┘\n"))
