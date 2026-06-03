"""
output.py — ShadowPort Scanner v1.2
Colored terminal output, progress bar, tables, scan summary.
"""

import sys
import time
import threading
from datetime import datetime
from colorama import Fore, Back, Style, init

from config import VERSION

init(autoreset=True)

# ─── Banner ──────────────────────────────────────────────────────────────────

BANNER = r"""
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗  ██████╗ ██████╗ ████████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██████╔╝██║   ██║██████╔╝   ██║
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔═══╝ ██║   ██║██╔══██╗   ██║
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║     ╚██████╔╝██║  ██║   ██║
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝"""

BANNER_SUB = r"""
                    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
                    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
                    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
                    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
                    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
                    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝"""


def print_banner():
    """Print the ShadowPort v1.2 banner."""
    print(Fore.RED + Style.BRIGHT + BANNER)
    print(Fore.CYAN + BANNER_SUB)
    print()
    print(
        Fore.YELLOW + "  " + "─" * 70
        + f"\n  {'Network Reconnaissance & Port Analysis Tool':^70}"
        + f"\n  {f'v{VERSION}  |  Use ONLY on authorized systems':^70}"
        + "\n  " + "─" * 70
    )
    print(Style.RESET_ALL)


# ─── Menus ───────────────────────────────────────────────────────────────────

def print_menu(is_root: bool = False):
    """Print scan mode menu with root indicators."""
    print(Fore.CYAN + Style.BRIGHT + "\n  ╔══════════════════════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT +   "  ║              SELECT SCAN MODE  — v1.2               ║")
    print(Fore.CYAN + Style.BRIGHT +   "  ╠══════════════════════════════════════════════════════╣")

    options = [
        ("1", "Quick Scan       ", "Top 1000 ports",             False),
        ("2", "Full TCP Scan    ", "All 65535 ports",             False),
        ("3", "Service Detection", "Versions & banners",          False),
        ("4", "OS Detection     ", "OS fingerprint  [root]",      True),
        ("5", "Aggressive Scan  ", "OS+svc+scripts  [root]",      True),
        ("6", "Host Discovery   ", "Ping sweep — is host alive?", False),
        ("7", "Stealth SYN Scan ", "Silent SYN scan [root]",      True),
        ("8", "Vuln Scripts     ", "NSE vuln scan",               False),
        ("9", "Exit             ", "Quit ShadowPort",             False),
    ]

    for num, label, desc, needs_root in options:
        if num == "9":
            row_color = Fore.RED
        elif needs_root and not is_root:
            row_color = Fore.YELLOW   # warn: needs root
        else:
            row_color = Fore.GREEN

        root_tag = Fore.MAGENTA + " ⚡" if needs_root else "   "
        not_available = needs_root and not is_root

        avail = Fore.YELLOW + " (needs sudo)" if not_available else ""

        print(
            Fore.CYAN + "  ║  "
            + row_color + Style.BRIGHT + f"[{num}]"
            + Fore.WHITE + f"  {label}  "
            + Fore.YELLOW + f"— {desc}"
            + root_tag
            + avail
            + Fore.CYAN + ""
        )

    print(Fore.CYAN + Style.BRIGHT + "  ╚══════════════════════════════════════════════════════╝\n")

    if not is_root:
        print(Fore.YELLOW + "  [~] Tip: Run with 'sudo python main.py' to unlock root-only modes.\n")


# ─── Status printers ─────────────────────────────────────────────────────────

def print_info(msg: str):
    print(Fore.CYAN + Style.BRIGHT + "[*] " + Style.RESET_ALL + msg)

def print_success(msg: str):
    print(Fore.GREEN + Style.BRIGHT + "[+] " + Style.RESET_ALL + msg)

def print_error(msg: str):
    print(Fore.RED + Style.BRIGHT + "[!] ERROR: " + Style.RESET_ALL + msg)

def print_warning(msg: str):
    print(Fore.YELLOW + Style.BRIGHT + "[~] " + Style.RESET_ALL + msg)

def print_section(title: str):
    width = 54
    print()
    print(Fore.MAGENTA + Style.BRIGHT + "  ┌" + "─" * width + "┐")
    padding = (width - len(title) - 2) // 2
    print(Fore.MAGENTA + Style.BRIGHT + "  │" + " " * padding + f" {title} " + " " * (width - len(title) - 2 - padding) + "│")
    print(Fore.MAGENTA + Style.BRIGHT + "  └" + "─" * width + "┘")
    print()


# ─── Animated progress bar ───────────────────────────────────────────────────

class ScanProgress:
    """
    Threaded animated progress bar displayed while nmap runs.
    Shows phase, elapsed time, and ETA.

    Usage:
        prog = ScanProgress(eta_seconds=30, mode_name="Service Detection")
        prog.start()
        # ... run scan ...
        prog.stop()
    """

    PHASES = [
        "Initializing",
        "Host Discovery",
        "Port Scanning",
        "Service Detection",
        "Parsing Results",
        "Finalizing",
    ]

    SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, eta_seconds: int = 30, mode_name: str = "Scanning"):
        self.eta = eta_seconds
        self.mode_name = mode_name
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._start_time = time.time()
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self._thread.join()
        # Clear the progress line
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    def _format_time(self, seconds: float) -> str:
        s = int(seconds)
        return f"{s // 60:02d}:{s % 60:02d}"

    def _run(self):
        bar_width = 28
        spin_idx  = 0
        phase_idx = 0

        while not self._stop_event.is_set():
            elapsed  = time.time() - self._start_time
            fraction = min(elapsed / max(self.eta, 1), 0.97)   # cap at 97% until done
            filled   = int(bar_width * fraction)
            bar      = "█" * filled + "░" * (bar_width - filled)
            pct      = int(fraction * 100)

            # Advance phase roughly every (eta / num_phases) seconds
            phase_step = max(self.eta / len(self.PHASES), 1)
            phase_idx  = min(int(elapsed / phase_step), len(self.PHASES) - 1)
            phase      = self.PHASES[phase_idx]

            eta_left = max(self.eta - elapsed, 0)
            spinner  = self.SPINNER[spin_idx % len(self.SPINNER)]

            line = (
                f"\r  {Fore.CYAN}{spinner}{Style.RESET_ALL} "
                f"{Fore.YELLOW}[{Fore.GREEN}{bar}{Fore.YELLOW}]{Style.RESET_ALL} "
                f"{Fore.WHITE}{pct:3d}%{Style.RESET_ALL}  "
                f"{Fore.CYAN}Phase:{Style.RESET_ALL} {phase:<20}"
                f"{Fore.CYAN}Elapsed:{Style.RESET_ALL} {self._format_time(elapsed)}  "
                f"{Fore.CYAN}ETA:{Style.RESET_ALL} {self._format_time(eta_left)}"
            )

            sys.stdout.write(line)
            sys.stdout.flush()
            spin_idx += 1
            time.sleep(0.1)


# ─── Results table ────────────────────────────────────────────────────────────

def print_results_table(scan_data: dict):
    """Print a fully formatted scan results table with summary block."""

    host      = scan_data.get("host", "Unknown")
    hostname  = scan_data.get("hostname", "")
    state     = scan_data.get("state", "unknown")
    ports     = scan_data.get("ports", [])
    os_matches= scan_data.get("os_matches", [])
    start_ts  = scan_data.get("start_time", "")
    end_ts    = scan_data.get("end_time", "")
    duration  = scan_data.get("duration_seconds", 0)
    mode_name = scan_data.get("mode_name", "")

    print_section("SCAN RESULTS")

    # ── Host info ─────────────────────────────────────────────────────────────
    print(Fore.CYAN + "  Target    : " + Fore.WHITE + Style.BRIGHT + host)
    if hostname:
        print(Fore.CYAN + "  Hostname  : " + Fore.WHITE + hostname)

    state_color = Fore.GREEN if state == "up" else Fore.RED
    print(Fore.CYAN + "  Status    : " + state_color + Style.BRIGHT + state.upper())

    if mode_name:
        print(Fore.CYAN + "  Scan Mode : " + Fore.WHITE + mode_name)
    if start_ts:
        print(Fore.CYAN + "  Started   : " + Fore.WHITE + start_ts)
    if end_ts:
        print(Fore.CYAN + "  Finished  : " + Fore.WHITE + end_ts)
    if duration:
        print(Fore.CYAN + "  Duration  : " + Fore.WHITE + f"{duration:.1f}s")
    if os_matches:
        print(Fore.CYAN + "  OS Match  : " + Fore.YELLOW + os_matches[0])

    print()

    if not ports:
        print_warning("No open ports found on this host.")
        return

    # ── Port table ────────────────────────────────────────────────────────────
    col_port    = 14
    col_state   = 12
    col_service = 20
    col_version = 32
    total_w = col_port + col_state + col_service + col_version

    print(
        Fore.WHITE + Style.BRIGHT
        + "  " + "PORT".ljust(col_port)
        + "STATE".ljust(col_state)
        + "SERVICE".ljust(col_service)
        + "VERSION"
    )
    print(Fore.CYAN + "  " + "─" * total_w)

    for p in ports:
        port_str = f"{p['port']}/{p['proto']}".ljust(col_port)
        s = p["state"]
        state_color = (
            Fore.GREEN  if s == "open"     else
            Fore.RED    if s == "closed"   else
            Fore.YELLOW
        )
        state_str = s.ljust(col_state)
        svc_str   = p["service"].ljust(col_service)
        ver_str   = p.get("version", "")[:col_version]

        print(
            "  "
            + Fore.WHITE + Style.BRIGHT + port_str
            + state_color + state_str
            + Fore.CYAN  + svc_str
            + Fore.YELLOW + ver_str
        )

    print(Fore.CYAN + "  " + "─" * total_w)

    # ── Summary block ─────────────────────────────────────────────────────────
    open_ports   = [p for p in ports if p["state"] == "open"]
    closed_ports = [p for p in ports if p["state"] == "closed"]
    filtered_ports = [p for p in ports if p["state"] not in ("open", "closed")]

    print()
    print(Fore.WHITE + Style.BRIGHT + "  ── SUMMARY " + "─" * 40)
    print(Fore.GREEN  + f"  Open     : {len(open_ports)}")
    if closed_ports:
        print(Fore.RED   + f"  Closed   : {len(closed_ports)}")
    if filtered_ports:
        print(Fore.YELLOW + f"  Filtered : {len(filtered_ports)}")
    print(Fore.WHITE  + f"  Total    : {len(ports)}")
    print(Fore.WHITE + Style.BRIGHT + "  " + "─" * 50)
    print()

    print_success(f"Scan complete — {len(open_ports)} open port(s) on {host}")
    print()
