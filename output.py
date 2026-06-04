"""
output.py — ShadowPort Scanner v1.3.0
Terminal UI: banner, menus, progress bar, results table,
service intelligence panel, risk score display, scan comparison.
"""

import sys
import time
import threading
from colorama import Fore, Back, Style, init

from config.settings import VERSION, TOOL_NAME

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
    print(Fore.RED + Style.BRIGHT + BANNER)
    print(Fore.CYAN + BANNER_SUB)
    print()
    print(Fore.YELLOW + "  " + "─" * 72)
    print(Fore.YELLOW + f"  {'Network Reconnaissance & Port Analysis Tool':^72}")
    print(Fore.YELLOW + f"  {f'v{VERSION}  ·  Use ONLY on authorized systems':^72}")
    print(Fore.YELLOW + "  " + "─" * 72)
    print(Style.RESET_ALL)


# ─── Status printers ──────────────────────────────────────────────────────────

def print_info(msg: str):
    print(Fore.CYAN + Style.BRIGHT + "[*] " + Style.RESET_ALL + msg)

def print_success(msg: str):
    print(Fore.GREEN + Style.BRIGHT + "[+] " + Style.RESET_ALL + msg)

def print_error(msg: str):
    print(Fore.RED + Style.BRIGHT + "[!] ERROR: " + Style.RESET_ALL + msg)

def print_warning(msg: str):
    print(Fore.YELLOW + Style.BRIGHT + "[~] " + Style.RESET_ALL + msg)

def print_section(title: str):
    width = 56
    print()
    print(Fore.MAGENTA + Style.BRIGHT + "  ┌" + "─" * width + "┐")
    pad = (width - len(title) - 2) // 2
    pad2 = width - len(title) - 2 - pad
    print(Fore.MAGENTA + Style.BRIGHT + "  │" + " " * pad + f" {title} " + " " * pad2 + "│")
    print(Fore.MAGENTA + Style.BRIGHT + "  └" + "─" * width + "┘")
    print()


# ─── Menus ────────────────────────────────────────────────────────────────────

def print_menu(is_root: bool = False):
    print(Fore.CYAN + Style.BRIGHT + "\n  ╔══════════════════════════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT +   "  ║           SELECT SCAN MODE  —  ShadowPort v1.3           ║")
    print(Fore.CYAN + Style.BRIGHT +   "  ╠══════════════════════════════════════════════════════════╣")

    rows = [
        ("1", "Quick Scan        ", "Top 1000 ports",                 False),
        ("2", "Full TCP Scan     ", "All 65535 ports",                False),
        ("3", "Service Detection ", "Versions & banners",             False),
        ("4", "OS Detection      ", "OS fingerprint   [root]",        True ),
        ("5", "Aggressive Scan   ", "OS+svc+scripts   [root]",        True ),
        ("6", "Host Discovery    ", "Ping sweep",                     False),
        ("7", "Stealth SYN Scan  ", "Silent SYN       [root]",        True ),
        ("8", "Vuln Scripts      ", "NSE vuln scan",                  False),
        ("─", None,                 None,                             False),
        ("p", "Scan Profiles     ", "Fast / Deep / Lab / Stealth",   False),
        ("c", "Scan Comparison   ", "Compare target over time",       False),
        ("h", "History           ", "Recent scans from database",     False),
        ("x", "Run Plugins       ", "DNS, Banner Grab + more",        False),
        ("9", "Exit              ", "Quit ShadowPort",                False),
    ]

    for num, label, desc, needs_root in rows:
        if num == "─":
            print(Fore.CYAN + "  ║  " + Fore.CYAN + Style.DIM + "  " + "·" * 54 + Fore.CYAN + Style.BRIGHT + "  ║")
            continue
        if num == "9":
            color = Fore.RED
        elif needs_root and not is_root:
            color = Fore.YELLOW
        else:
            color = Fore.GREEN

        root_tag = Fore.MAGENTA + " ⚡" if needs_root else "   "
        sudo_tag = Fore.YELLOW + " (needs sudo)" if (needs_root and not is_root) else ""

        print(
            Fore.CYAN + "  ║  "
            + color + Style.BRIGHT + f"[{num}]"
            + Fore.WHITE + f"  {label}"
            + Fore.YELLOW + f"— {desc}"
            + root_tag + sudo_tag
        )

    print(Fore.CYAN + Style.BRIGHT + "  ╚══════════════════════════════════════════════════════════╝\n")

    if not is_root:
        print(Fore.YELLOW + "  [~] Tip: sudo python main.py to unlock all modes.\n")


def print_profiles_menu(profiles: dict):
    print(Fore.CYAN + Style.BRIGHT + "\n  ╔══════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT +   "  ║        SCAN PROFILES  v1.3           ║")
    print(Fore.CYAN + Style.BRIGHT +   "  ╠══════════════════════════════════════╣")
    for key, p in profiles.items():
        print(
            Fore.CYAN + "  ║  "
            + Fore.GREEN + Style.BRIGHT + f"[{key[:1]}]"
            + Fore.WHITE + f"  {p['name']:<18}"
            + Fore.YELLOW + f"— {p['description']}"
        )
    print(Fore.CYAN + Style.BRIGHT + "  ╚══════════════════════════════════════╝\n")


def print_plugins_menu(registry: dict):
    if not registry:
        print_warning("No plugins loaded.")
        return
    print(Fore.CYAN + Style.BRIGHT + "\n  ╔══════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT +   "  ║          AVAILABLE PLUGINS            ║")
    print(Fore.CYAN + Style.BRIGHT +   "  ╠══════════════════════════════════════╣")
    for i, (key, plugin) in enumerate(registry.items(), 1):
        print(
            Fore.CYAN + "  ║  "
            + Fore.GREEN + Style.BRIGHT + f"[{i}]"
            + Fore.WHITE + f"  {plugin.name:<20}"
            + Fore.YELLOW + f"— {plugin.description}"
        )
    print(Fore.CYAN + Style.BRIGHT + "  ╚══════════════════════════════════════╝\n")


# ─── Animated progress bar ────────────────────────────────────────────────────

class ScanProgress:
    PHASES  = ["Initializing", "Host Discovery", "Port Scanning",
                "Service Detection", "Parsing Results", "Finalizing"]
    SPINNER = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, eta_seconds: int = 30, mode_name: str = "Scanning"):
        self.eta  = eta_seconds
        self.mode = mode_name
        self._stop  = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._t0 = time.time()
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join()
        sys.stdout.write("\r" + " " * 90 + "\r")
        sys.stdout.flush()

    def _fmt(self, s: float) -> str:
        s = int(s)
        return f"{s//60:02d}:{s%60:02d}"

    def _run(self):
        bar_w = 28
        si    = 0
        while not self._stop.is_set():
            elapsed  = time.time() - self._t0
            frac     = min(elapsed / max(self.eta, 1), 0.97)
            filled   = int(bar_w * frac)
            bar      = "█" * filled + "░" * (bar_w - filled)
            pct      = int(frac * 100)
            ph_idx   = min(int(elapsed / max(self.eta / len(self.PHASES), 1)), len(self.PHASES)-1)
            phase    = self.PHASES[ph_idx]
            eta_left = max(self.eta - elapsed, 0)
            spin     = self.SPINNER[si % len(self.SPINNER)]
            line = (
                f"\r  {Fore.CYAN}{spin}{Style.RESET_ALL} "
                f"{Fore.YELLOW}[{Fore.GREEN}{bar}{Fore.YELLOW}]{Style.RESET_ALL} "
                f"{Fore.WHITE}{pct:3d}%{Style.RESET_ALL}  "
                f"{Fore.CYAN}Phase:{Style.RESET_ALL} {phase:<20}"
                f"{Fore.CYAN}Elapsed:{Style.RESET_ALL} {self._fmt(elapsed)}  "
                f"{Fore.CYAN}ETA:{Style.RESET_ALL} {self._fmt(eta_left)}"
            )
            sys.stdout.write(line)
            sys.stdout.flush()
            si += 1
            time.sleep(0.1)


# ─── Results table ────────────────────────────────────────────────────────────

def print_results_table(scan_data: dict, show_intel: bool = False):
    host       = scan_data.get("host", "Unknown")
    hostname   = scan_data.get("hostname", "")
    state      = scan_data.get("state", "unknown")
    ports      = scan_data.get("ports", [])
    os_matches = scan_data.get("os_matches", [])
    risk       = scan_data.get("risk", {})
    mode_name  = scan_data.get("mode_name", "")

    print_section("SCAN RESULTS")

    print(Fore.CYAN + "  Target    : " + Fore.WHITE + Style.BRIGHT + host)
    if hostname:
        print(Fore.CYAN + "  Hostname  : " + Fore.WHITE + hostname)
    sc = Fore.GREEN if state == "up" else Fore.RED
    print(Fore.CYAN + "  Status    : " + sc + Style.BRIGHT + state.upper())
    if mode_name:
        print(Fore.CYAN + "  Scan Mode : " + Fore.WHITE + mode_name)
    if scan_data.get("start_time"):
        print(Fore.CYAN + "  Started   : " + Fore.WHITE + scan_data["start_time"])
    if scan_data.get("end_time"):
        print(Fore.CYAN + "  Finished  : " + Fore.WHITE + scan_data["end_time"])
    if scan_data.get("duration_seconds"):
        print(Fore.CYAN + "  Duration  : " + Fore.WHITE + f"{scan_data['duration_seconds']:.1f}s")
    if os_matches:
        print(Fore.CYAN + "  OS Match  : " + Fore.YELLOW + os_matches[0])

    # ── Risk score ──────────────────────────────────────────────────────────
    if risk:
        score = risk.get("score", 0)
        label = risk.get("label", "")
        risk_color = (
            Fore.RED    if score >= 70 else
            Fore.YELLOW if score >= 40 else
            Fore.GREEN
        )
        print(Fore.CYAN + "  Risk Score: " + risk_color + Style.BRIGHT + f"{score}/100  [{label}]")

    print()

    if not ports:
        print_warning("No ports found.")
        return

    # ── Port table ────────────────────────────────────────────────────────────
    col_p, col_s, col_sv, col_v = 14, 12, 20, 32
    total_w = col_p + col_s + col_sv + col_v

    print(Fore.WHITE + Style.BRIGHT
          + "  " + "PORT".ljust(col_p) + "STATE".ljust(col_s)
          + "SERVICE".ljust(col_sv) + "VERSION")
    print(Fore.CYAN + "  " + "─" * total_w)

    for p in ports:
        port_str = f"{p['port']}/{p['proto']}".ljust(col_p)
        s = p["state"]
        sc = Fore.GREEN if s == "open" else Fore.RED if s == "closed" else Fore.YELLOW
        print("  "
              + Fore.WHITE + Style.BRIGHT + port_str
              + sc + s.ljust(col_s)
              + Fore.CYAN + p["service"].ljust(col_sv)
              + Fore.YELLOW + p.get("version", "")[:col_v])

        # Service intelligence (educational mode)
        if show_intel and s == "open":
            intel = p.get("intel", {})
            if intel:
                print(Fore.CYAN + Style.DIM
                      + "       ├─ Use : " + Style.RESET_ALL + Fore.WHITE + intel.get("use", ""))
                print(Fore.RED + Style.DIM
                      + "       └─ Risk: " + Style.RESET_ALL + Fore.YELLOW + intel.get("risk", ""))

    print(Fore.CYAN + "  " + "─" * total_w)

    open_c     = sum(1 for p in ports if p["state"] == "open")
    closed_c   = sum(1 for p in ports if p["state"] == "closed")
    filtered_c = sum(1 for p in ports if p["state"] not in ("open","closed"))

    print()
    print(Fore.WHITE + Style.BRIGHT + "  ── SUMMARY " + "─" * 42)
    print(Fore.GREEN  + f"  Open     : {open_c}")
    if closed_c:   print(Fore.RED    + f"  Closed   : {closed_c}")
    if filtered_c: print(Fore.YELLOW + f"  Filtered : {filtered_c}")
    print(Fore.WHITE  + f"  Total    : {len(ports)}")

    if risk and risk.get("breakdown"):
        print(Fore.WHITE + Style.BRIGHT + "\n  ── RISK BREAKDOWN " + "─" * 35)
        for line in risk["breakdown"]:
            print(Fore.YELLOW + f"  {line}")

    print(Fore.WHITE + "  " + "─" * 53)
    print()
    print_success(f"Scan complete — {open_c} open port(s) on {host}")
    print()


# ─── Scan comparison display ──────────────────────────────────────────────────

def print_comparison(comp: dict):
    """Display diff between two scans for the same target."""
    print_section("SCAN COMPARISON")

    prev = comp["previous"]
    curr = comp["current"]

    print(Fore.CYAN + f"  Previous scan : " + Fore.WHITE + prev.get("start_time","?")
          + Fore.CYAN + f"  (open: {prev.get('open_count','?')})")
    print(Fore.CYAN + f"  Current scan  : " + Fore.WHITE + curr.get("start_time","?")
          + Fore.CYAN + f"  (open: {curr.get('open_count','?')})")
    print()

    new_ports    = comp.get("new_ports", [])
    closed_ports = comp.get("closed_ports", [])
    unchanged    = comp.get("unchanged", [])

    if new_ports:
        print(Fore.GREEN + Style.BRIGHT + f"  ✚ New ports detected ({len(new_ports)}):")
        for p in new_ports:
            print(Fore.GREEN + f"      → {p}/tcp")
    else:
        print(Fore.GREEN + "  No new ports since last scan.")

    if closed_ports:
        print(Fore.RED + Style.BRIGHT + f"\n  ✖ Ports closed/filtered since last scan ({len(closed_ports)}):")
        for p in closed_ports:
            print(Fore.RED + f"      → {p}/tcp")
    else:
        print(Fore.RED + "  No ports closed since last scan.")

    if unchanged:
        print(Fore.CYAN + f"\n  ═ Unchanged open ports ({len(unchanged)}): "
              + Fore.WHITE + ", ".join(unchanged))
    print()


# ─── History table ────────────────────────────────────────────────────────────

def print_history_table(rows: list[dict]):
    if not rows:
        print_warning("No scan history in database yet.")
        return

    print_section("SCAN HISTORY")
    print(Fore.WHITE + Style.BRIGHT
          + "  " + "#".ljust(4) + "DATE".ljust(22) + "TARGET".ljust(20)
          + "MODE".ljust(20) + "OPEN".ljust(6) + "RISK".ljust(6) + "DUR")
    print(Fore.CYAN + "  " + "─" * 80)

    for i, row in enumerate(rows, 1):
        score = row.get("risk_score", 0)
        rc = Fore.RED if score >= 70 else Fore.YELLOW if score >= 40 else Fore.GREEN
        print(
            "  "
            + Fore.WHITE + Style.BRIGHT + str(i).ljust(4)
            + Fore.WHITE + str(row.get("start_time","?"))[:19].ljust(22)
            + Fore.CYAN  + str(row.get("target","?"))[:18].ljust(20)
            + Fore.WHITE + str(row.get("mode_name","?"))[:18].ljust(20)
            + Fore.GREEN + str(row.get("open_count","?")).ljust(6)
            + rc + str(score).ljust(6)
            + Fore.WHITE + f"{row.get('duration_s',0):.1f}s"
        )

    print(Fore.CYAN + "  " + "─" * 80)
    print()
