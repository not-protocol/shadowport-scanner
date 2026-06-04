#!/usr/bin/env python3
"""
main.py — ShadowPort Scanner v1.3.0
Entry point: privilege detection, menu, target input,
scan profiles, plugin runner, scan comparison, SQLite history.

Usage:
    python main.py           — standard modes
    sudo python main.py      — full access (OS detect, SYN, Aggressive)

Ethics: Use ONLY on systems you own or are authorized to test.
"""

import sys

from config.settings import SCAN_MODES, EXIT_OPTION, VERSION, PROFILES
from output import (
    print_banner, print_menu, print_info, print_error,
    print_warning, print_success, print_results_table,
    print_history_table, print_comparison,
)
from scanner import run_scan, validate_target, is_root, discover_subnet, ping_host
from reports import prompt_save, save_report
from database import save_scan, get_history, compare_scans, get_stats
from profiles import select_profile
import plugins as plugin_loader
from output import print_plugins_menu


# ─── Ethics notice ────────────────────────────────────────────────────────────

ETHICS_NOTICE = """
  ┌────────────────────────────────────────────────────────────┐
  │               ⚠  ETHICAL USE NOTICE  ⚠                     │
  │                                                            │
  │  ShadowPort Scanner v1.3.0 is for AUTHORIZED USE ONLY:     │
  │   • Systems you personally own                             │
  │   • Networks with written authorization                    │
  │   • Lab environments: VMs, HTB, TryHackMe, DVWA, etc.      │
  │                                                            │
  │  Unauthorized scanning is ILLEGAL in most jurisdictions.   │
  │  You are solely responsible for your use of this tool.     │
  └────────────────────────────────────────────────────────────┘
"""


# ─── Privilege startup check ──────────────────────────────────────────────────

def privilege_check() -> bool:
    """
    Check root status and inform the user.
    If not root, ask if they want to continue.
    Returns True to continue, False to exit.
    """
    root = is_root()

    if root:
        print_success("Running with root privileges — all scan modes available.\n")
        return True

    print_warning("Some scan modes require root privileges.")
    print_warning("Features such as SYN scans, OS detection, and advanced Nmap")
    print_warning("functionality may not work correctly without root.\n")
    print_warning("Affected modes: [4] OS Detection  [5] Aggressive  [7] Stealth SYN\n")

    try:
        cont = input("  Continue without root? (y/n) [y]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if cont in ("n", "no"):
        print_info("Re-run with: sudo python main.py")
        sys.exit(0)

    print()
    return True


# ─── Target input ─────────────────────────────────────────────────────────────

def get_target() -> str:
    """Prompt and validate a target IP, hostname, or CIDR range."""
    while True:
        try:
            target = input("  Enter target IP, hostname, or CIDR (e.g. 192.168.1.0/24): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if validate_target(target):
            return target
        print_warning("Please enter a valid IP, hostname, or CIDR range.\n")


# ─── Subnet handler ───────────────────────────────────────────────────────────

def handle_subnet(target: str, mode: str, root: bool) -> None:
    """Discover active hosts in a subnet then scan each one."""
    active = discover_subnet(target)
    if not active:
        print_warning("No active hosts found in that subnet.")
        return

    print_success(f"Found {len(active)} active host(s):\n")
    for ip in active:
        print(f"    {ip}")
    print()

    try:
        go = input("  Scan all active hosts with selected mode? (y/n): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if go != "y":
        return

    for ip in active:
        print_info(f"\nScanning {ip}…\n")
        scan_data = run_scan(ip, mode)
        if scan_data:
            print_results_table(scan_data)
            risk = scan_data.get("risk", {})
            save_scan(scan_data, risk_score=risk.get("score", 0))
            prompt_save(scan_data)


# ─── Plugin runner ────────────────────────────────────────────────────────────

def run_plugins(target: str, scan_data: dict, registry: dict):
    """Display plugin menu and run selected plugin against the last scan."""
    if not registry:
        print_warning("No plugins available.")
        return

    print_plugins_menu(registry)
    plugin_list = list(registry.values())

    try:
        choice = input(f"  Select plugin [1-{len(plugin_list)}] or [c] cancel: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if choice in ("c", ""):
        return

    try:
        idx    = int(choice) - 1
        plugin = plugin_list[idx]
    except (ValueError, IndexError):
        print_error("Invalid selection.")
        return

    print_info(f"Running plugin: {plugin.name} — {plugin.description}\n")
    result = plugin.run(target, scan_data)
    print()
    print(result.get("output", "(no output)"))
    print()


# ─── Main loop ────────────────────────────────────────────────────────────────

def main():
    print_banner()
    print(ETHICS_NOTICE)

    root = is_root()
    privilege_check()

    # Load plugins at startup
    registry = plugin_loader.load_plugins()
    if registry:
        print_info(f"Loaded {len(registry)} plugin(s): {', '.join(registry.keys())}\n")

    last_scan_data = {}
    last_target    = ""

    valid_modes = set(SCAN_MODES.keys()) | {EXIT_OPTION, "p", "c", "h", "x"}

    while True:

        # ── Target ────────────────────────────────────────────────────────────
        last_target = get_target()
        is_cidr     = "/" in last_target
        print()

        # ── Mode selection ────────────────────────────────────────────────────
        print_menu(is_root=root)
        while True:
            try:
                choice = input("  Select [1-9 / p / c / h / x]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(0)
            if choice in valid_modes:
                break
            print_error(f"Invalid option '{choice}'.\n")

        # ── Exit ─────────────────────────────────────────────────────────────
        if choice == EXIT_OPTION:
            stats = get_stats()
            print()
            print_info(f"Session stats — total scans: {stats['total_scans']}  "
                       f"unique targets: {stats['unique_targets']}  "
                       f"avg open ports: {stats['avg_open_ports']}")
            print_info("Goodbye. Stay legal out there. 👋")
            sys.exit(0)

        # ── History ───────────────────────────────────────────────────────────
        if choice == "h":
            rows = get_history(20)
            print_history_table(rows)
            continue

        # ── Scan comparison ───────────────────────────────────────────────────
        if choice == "c":
            comp = compare_scans(last_target)
            if comp:
                print_comparison(comp)
            else:
                print_warning(f"Need at least 2 scans for {last_target!r} to compare.")
                print_info("Run a scan first, then use [c] again.\n")
            continue

        # ── Profile selection ─────────────────────────────────────────────────
        if choice == "p":
            mode = select_profile(is_root=root)
            if not mode:
                continue
        else:
            mode = choice

        # ── Plugin runner (uses last scan) ────────────────────────────────────
        if choice == "x":
            if not last_scan_data:
                print_warning("Run a scan first to use plugins.\n")
                continue
            run_plugins(last_target, last_scan_data, registry)
            continue

        # ── Subnet vs single host ─────────────────────────────────────────────
        print()
        if is_cidr:
            handle_subnet(last_target, mode, root)
            continue

        # ── Single host scan ──────────────────────────────────────────────────
        print_info(f"Target    : {last_target}")
        print_info(f"Mode      : {SCAN_MODES[mode]['name']}")
        print()

        scan_data = run_scan(last_target, mode)

        if scan_data:
            last_scan_data = scan_data
            risk  = scan_data.get("risk", {})

            # Ask service intel mode
            try:
                intel_q = input("  Show service intelligence? (y/n) [n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                intel_q = "n"
            show_intel = intel_q == "y"

            print_results_table(scan_data, show_intel=show_intel)

            # Save to SQLite
            db_id = save_scan(scan_data, risk_score=risk.get("score", 0))
            print_info(f"Saved to database (id={db_id})\n")

            # Optional file report
            prompt_save(scan_data)

            # Run plugins option
            if registry:
                try:
                    plug_q = input("  Run a plugin on these results? (y/n) [n]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    plug_q = "n"
                if plug_q == "y":
                    run_plugins(last_target, scan_data, registry)

        # ── Loop ──────────────────────────────────────────────────────────────
        print()
        try:
            again = input("  Run another scan? (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if again != "y":
            break
        print("\n" + "─" * 66 + "\n")

    print()
    print_info("Session ended. Goodbye.")


if __name__ == "__main__":
    main()
