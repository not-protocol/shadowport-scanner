#!/usr/bin/env python3
"""
main.py — ShadowPort Scanner v2.0.0
Entry point: privilege detection, menu, target input,
scan profiles, plugin runner, scan comparison, SQLite history.

v2.0.0 changes:
  - Strict target validation with clear rejection messages
  - CTRL+C handled gracefully at every stage — no tracebacks
  - Input sanitization (strip whitespace/newlines)
  - All errors caught; application always returns to menu
  - Error log created automatically in logs/error.log

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
    print_history_table, print_comparison, print_plugins_menu,
)
from scanner import run_scan, validate_target, resolve_hostname, is_root, discover_subnet
from reports import prompt_save
from database import save_scan, get_history, compare_scans, get_stats
from profiles import select_profile
from logger import log_error
import plugins as plugin_loader


# ─── Ethics notice ────────────────────────────────────────────────────────────

ETHICS_NOTICE = """
  ┌────────────────────────────────────────────────────────────┐
  │               ⚠  ETHICAL USE NOTICE  ⚠                     │
  │                                                            │
  │  ShadowPort Scanner v2.0.0 is for AUTHORIZED USE ONLY:     │
  │   • Systems you personally own                             │
  │   • Networks with written authorization                    │
  │   • Lab environments: VMs, HTB, TryHackMe, DVWA, etc.      │
  │                                                            │
  │  Unauthorized scanning is ILLEGAL in most jurisdictions.   │
  │  You are solely responsible for your use of this tool.     │
  └────────────────────────────────────────────────────────────┘
"""


# ─── Safe input helper ────────────────────────────────────────────────────────

def _input(prompt: str) -> str:
    """
    Read a line from stdin.
    Strips whitespace/newlines automatically.
    Raises KeyboardInterrupt on CTRL+C (caller must handle).
    Raises SystemExit on EOF.
    """
    try:
        return input(prompt).strip()
    except EOFError:
        print()
        sys.exit(0)


# ─── Privilege startup check ──────────────────────────────────────────────────

def privilege_check() -> bool:
    root = is_root()
    if root:
        print_success("Running with root privileges — all scan modes available.\n")
        return True

    print_warning("Some scan modes require root privileges.")
    print_warning("Features such as SYN scans, OS detection, and advanced Nmap")
    print_warning("functionality may not work correctly without root.\n")
    print_warning("Affected modes: [4] OS Detection  [5] Aggressive  [7] Stealth SYN\n")

    try:
        cont = _input("  Continue without root? (y/n) [y]: ").lower()
    except KeyboardInterrupt:
        print("\nGoodbye.")
        sys.exit(0)

    if cont in ("n", "no"):
        print_info("Re-run with: sudo python main.py")
        sys.exit(0)

    print()
    return True


# ─── Target input ─────────────────────────────────────────────────────────────

def get_target() -> str:
    """Prompt for a target, validate strictly, return only on success."""
    while True:
        try:
            raw = _input("  Enter target IP, hostname, or CIDR (e.g. 192.168.1.0/24): ")
        except KeyboardInterrupt:
            print("\n  Returning to menu…\n")
            return ""

        if not raw:
            print_warning("Target cannot be empty. Please try again.\n")
            continue

        ok, reason = validate_target(raw)
        if ok:
            return raw

        print_error("Invalid IP address or hostname.")
        print()
        print("  Please enter:")
        print("    • Valid IPv4 address    e.g. 192.168.1.100")
        print("    • Valid hostname        e.g. scanme.nmap.org")
        print("    • Valid CIDR range      e.g. 192.168.1.0/24")
        print(f"\n  Reason: {reason}\n")


# ─── Subnet handler ───────────────────────────────────────────────────────────

def handle_subnet(target: str, mode: str) -> None:
    try:
        active = discover_subnet(target)
    except KeyboardInterrupt:
        print_warning("\nSubnet discovery cancelled.")
        return

    if not active:
        print_warning("No active hosts found in that subnet.")
        return

    print_success(f"Found {len(active)} active host(s):\n")
    for ip in active:
        print(f"    {ip}")
    print()

    try:
        go = _input("  Scan all active hosts with selected mode? (y/n): ").lower()
    except KeyboardInterrupt:
        print_warning("\nCancelled.")
        return

    if go != "y":
        return

    for ip in active:
        print_info(f"\nScanning {ip}…\n")
        try:
            scan_data = run_scan(ip, mode)
        except KeyboardInterrupt:
            print_warning("\nScan cancelled by user. Returning to menu…\n")
            return
        except Exception as exc:
            print_error(f"Unexpected error scanning {ip}: {exc}")
            log_error(target=ip, mode=mode, error=str(exc), exc=exc)
            continue

        if scan_data:
            print_results_table(scan_data)
            risk = scan_data.get("risk", {})
            save_scan(scan_data, risk_score=risk.get("score", 0))
            try:
                prompt_save(scan_data)
            except KeyboardInterrupt:
                pass


# ─── Plugin runner ────────────────────────────────────────────────────────────

def run_plugins(target: str, scan_data: dict, registry: dict):
    if not registry:
        print_warning("No plugins available.")
        return

    print_plugins_menu(registry)
    plugin_list = list(registry.values())

    try:
        choice = _input(f"  Select plugin [1-{len(plugin_list)}] or [c] cancel: ").lower()
    except KeyboardInterrupt:
        print_warning("\nCancelled.")
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
    try:
        result = plugin.run(target, scan_data)
        print()
        print(result.get("output", "(no output)"))
        print()
    except KeyboardInterrupt:
        print_warning("\nPlugin cancelled.")
    except Exception as exc:
        print_error(f"Plugin error: {exc}")
        log_error(target=target, mode=f"plugin:{plugin.name}", error=str(exc), exc=exc)


# ─── Main loop ────────────────────────────────────────────────────────────────

def main():
    print_banner()
    print(ETHICS_NOTICE)

    root = is_root()
    privilege_check()

    # Load plugins at startup
    try:
        registry = plugin_loader.load_plugins()
        if registry:
            print_info(f"Loaded {len(registry)} plugin(s): {', '.join(registry.keys())}\n")
    except Exception as exc:
        registry = {}
        print_warning(f"Plugin loading failed: {exc}")
        log_error(mode="startup", error="Plugin load failed", exc=exc)

    last_scan_data = {}
    last_target    = ""
    valid_modes    = set(SCAN_MODES.keys()) | {EXIT_OPTION, "p", "c", "h", "x"}

    while True:

        # ── Target ────────────────────────────────────────────────────────────
        last_target = get_target()
        if not last_target:
            continue  # user hit CTRL+C at target prompt

        is_cidr = "/" in last_target
        print()

        # ── Mode selection ────────────────────────────────────────────────────
        print_menu(is_root=root)
        while True:
            try:
                choice = _input("  Select [1-9 / p / c / h / x]: ").lower()
            except KeyboardInterrupt:
                print("\n  Returning to target prompt…\n")
                choice = ""
                break
            if choice in valid_modes:
                break
            print_error(f"Invalid option '{choice}'.\n")

        if not choice:
            continue

        # ── Exit ─────────────────────────────────────────────────────────────
        if choice == EXIT_OPTION:
            try:
                stats = get_stats()
                print()
                print_info(
                    f"Session stats — total scans: {stats['total_scans']}  "
                    f"unique targets: {stats['unique_targets']}  "
                    f"avg open ports: {stats['avg_open_ports']}"
                )
            except Exception:
                pass
            print_info("Goodbye. Stay legal out there. 👋")
            sys.exit(0)

        # ── History ───────────────────────────────────────────────────────────
        if choice == "h":
            try:
                rows = get_history(20)
                print_history_table(rows)
            except Exception as exc:
                print_error(f"Could not load history: {exc}")
                log_error(mode="history", error=str(exc), exc=exc)
            continue

        # ── Scan comparison ───────────────────────────────────────────────────
        if choice == "c":
            try:
                comp = compare_scans(last_target)
                if comp:
                    print_comparison(comp)
                else:
                    print_warning(f"Need at least 2 scans for {last_target!r} to compare.")
                    print_info("Run a scan first, then use [c] again.\n")
            except Exception as exc:
                print_error(f"Comparison failed: {exc}")
                log_error(target=last_target, mode="compare", error=str(exc), exc=exc)
            continue

        # ── Profile selection ─────────────────────────────────────────────────
        if choice == "p":
            try:
                mode = select_profile(is_root=root)
            except KeyboardInterrupt:
                print_warning("\nCancelled.")
                continue
            if not mode:
                continue
        else:
            mode = choice

        # ── Plugin runner ─────────────────────────────────────────────────────
        if choice == "x":
            if not last_scan_data:
                print_warning("Run a scan first to use plugins.\n")
                continue
            run_plugins(last_target, last_scan_data, registry)
            continue

        # ── Subnet vs single host ─────────────────────────────────────────────
        print()
        if is_cidr:
            try:
                handle_subnet(last_target, mode)
            except KeyboardInterrupt:
                print_warning("\nSubnet scan cancelled. Returning to menu…\n")
            continue

        # ── Single host scan ──────────────────────────────────────────────────
        print_info(f"Target    : {last_target}")
        print_info(f"Mode      : {SCAN_MODES[mode]['name']}")
        print()

        try:
            scan_data = run_scan(last_target, mode)
        except KeyboardInterrupt:
            print_warning("\nScan cancelled by user. Returning to menu…\n")
            continue
        except Exception as exc:
            print_error(f"Unexpected error: {exc}")
            log_error(target=last_target, mode=mode, error=str(exc), exc=exc)
            print_warning("Returning to menu…\n")
            continue

        if scan_data:
            last_scan_data = scan_data
            risk = scan_data.get("risk", {})

            try:
                intel_q   = _input("  Show service intelligence? (y/n) [n]: ").lower()
                show_intel = intel_q == "y"
            except KeyboardInterrupt:
                show_intel = False

            print_results_table(scan_data, show_intel=show_intel)

            try:
                db_id = save_scan(scan_data, risk_score=risk.get("score", 0))
                print_info(f"Saved to database (id={db_id})\n")
            except Exception as exc:
                print_warning(f"Could not save to database: {exc}")
                log_error(target=last_target, mode=mode, error="DB save failed", exc=exc)

            try:
                prompt_save(scan_data)
            except KeyboardInterrupt:
                print_warning("\nReport skipped.")

            if registry:
                try:
                    plug_q = _input("  Run a plugin on these results? (y/n) [n]: ").lower()
                    if plug_q == "y":
                        run_plugins(last_target, scan_data, registry)
                except KeyboardInterrupt:
                    pass

        # ── Loop ──────────────────────────────────────────────────────────────
        print()
        try:
            again = _input("  Run another scan? (y/n): ").lower()
        except KeyboardInterrupt:
            print()
            break
        if again != "y":
            break
        print("\n" + "─" * 66 + "\n")

    print()
    print_info("Session ended. Goodbye.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted. Goodbye.")
        sys.exit(0)
    except Exception as exc:
        log_error(mode="main", error=str(exc), exc=exc)
        print(f"\n[ERROR] Unexpected crash: {exc}")
        print("Details saved to logs/error.log")
        sys.exit(1)
