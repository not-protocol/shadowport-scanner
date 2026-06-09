#!/usr/bin/env python3
"""
main.py — ShadowPort Scanner v2.1.0
Entry point: startup checks, DB init, Excel audit, full scan workflow.

Usage:
    python main.py           — standard modes
    sudo python main.py      — full access (OS detect, SYN, Aggressive)

Ethics: Use ONLY on systems you own or are authorized to test.
"""

import sys

from config.settings import SCAN_MODES, EXIT_OPTION, VERSION, PROFILES
from db.database import init_db, save_scan, get_scan_history, get_stats
from core.excel_logger import log_scan_to_excel, audit_log_consistency
from core.change_detector import compare_scans, format_change_report
from core.scan_profiles import ALL_PROFILES, get_profile_by_index, print_profiles_menu
from scanner import run_scan, validate_target, is_root, discover_subnet
from reports import prompt_save
from logger import log_error
from output import (
    print_banner, print_menu, print_info, print_error,
    print_warning, print_success, print_results_table,
    print_history_table,
)
import plugins as plugin_loader


ETHICS_NOTICE = """
  ┌────────────────────────────────────────────────────────────┐
  │               ⚠  ETHICAL USE NOTICE  ⚠                     │
  │                                                            │
  │  ShadowPort Scanner v2.1.0 is for AUTHORIZED USE ONLY:     │
  │   • Systems you personally own                             │
  │   • Networks with written authorization                    │
  │   • Lab environments: VMs, HTB, TryHackMe, DVWA, etc.      │
  │                                                            │
  │  Unauthorized scanning is ILLEGAL in most jurisdictions.   │
  │  You are solely responsible for your use of this tool.     │
  └────────────────────────────────────────────────────────────┘
"""


def _input(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        print()
        sys.exit(0)


def _startup() -> None:
    """Run all startup checks silently."""
    # Init / migrate DB
    actions = init_db()
    if actions:
        for a in actions:
            print_info(a)

    # Excel/SQLite consistency audit in background
    try:
        audit = audit_log_consistency()
        if audit["discrepancy"]:
            print_warning(f"Log audit: {audit['message']}")
    except Exception as exc:
        log_error(mode="startup", error="Audit failed", exc=exc)


def privilege_check() -> None:
    if is_root():
        print_success("Running with root privileges — all scan modes available.\n")
        return
    print_warning("Some scan modes require root (SYN, OS detection, Aggressive).\n")
    try:
        cont = _input("  Continue without root? (y/n) [y]: ").lower()
    except KeyboardInterrupt:
        print("\nGoodbye.")
        sys.exit(0)
    if cont in ("n", "no"):
        print_info("Re-run with: sudo python main.py")
        sys.exit(0)
    print()


def get_target() -> str:
    while True:
        try:
            raw = _input("  Enter target IP, hostname, or CIDR: ")
        except KeyboardInterrupt:
            print("\n  Returning to menu…\n")
            return ""
        if not raw:
            print_warning("Target cannot be empty.\n")
            continue
        result = validate_target(raw)
        if result.valid:
            return raw
        print_error("Invalid target.")
        print(f"  Reason : {result.reason}")
        print("  Examples: 192.168.1.1 | scanme.nmap.org | 192.168.1.0/24\n")


def handle_subnet(target: str, mode: str) -> None:
    try:
        active = discover_subnet(target)
    except KeyboardInterrupt:
        print_warning("\nSubnet discovery cancelled.")
        return
    if not active:
        print_warning("No active hosts found.")
        return
    print_success(f"Found {len(active)} active host(s):")
    for ip in active:
        print(f"    {ip}")
    print()
    try:
        go = _input("  Scan all with selected mode? (y/n): ").lower()
    except KeyboardInterrupt:
        return
    if go != "y":
        return
    for ip in active:
        print_info(f"\nScanning {ip}…")
        try:
            scan_data = run_scan(ip, mode)
        except KeyboardInterrupt:
            print_warning("\nCancelled.")
            return
        except Exception as exc:
            print_error(f"Error scanning {ip}: {exc}")
            log_error(target=ip, mode=mode, error=str(exc), exc=exc)
            continue
        if scan_data:
            print_results_table(scan_data)
            risk = scan_data.get("risk", {})
            rs   = risk.get("score", 0)
            save_scan(scan_data, risk_score=rs)
            log_scan_to_excel(scan_data, risk_score=rs)


def run_plugins_menu(target: str, scan_data: dict, registry: dict) -> None:
    if not registry:
        print_warning("No plugins loaded.")
        return
    plugin_list = list(registry.values())
    print("\n  Plugins:")
    for i, p in enumerate(plugin_list, 1):
        print(f"    [{i}] {p.name} — {p.description}")
    print()
    try:
        choice = _input(f"  Select [1-{len(plugin_list)}] or [c] cancel: ").lower()
    except KeyboardInterrupt:
        return
    if choice in ("c", ""):
        return
    try:
        plugin = plugin_list[int(choice) - 1]
    except (ValueError, IndexError):
        print_error("Invalid selection.")
        return
    try:
        result = plugin.run(target, scan_data)
        print(result.get("output", "(no output)"))
    except Exception as exc:
        print_error(f"Plugin error: {exc}")
        log_error(target=target, mode=f"plugin:{plugin.name}", error=str(exc), exc=exc)


def main():
    print_banner()
    print(ETHICS_NOTICE)
    _startup()
    privilege_check()

    try:
        registry = plugin_loader.load_plugins()
        if registry:
            print_info(f"Loaded {len(registry)} plugin(s): {', '.join(registry.keys())}\n")
    except Exception as exc:
        registry = {}
        log_error(mode="startup", error="Plugin load failed", exc=exc)

    last_scan_data = {}
    last_target    = ""
    valid_choices  = set(SCAN_MODES.keys()) | {EXIT_OPTION, "p", "c", "h", "x", "d"}

    while True:
        last_target = get_target()
        if not last_target:
            continue
        is_cidr = "/" in last_target
        print()

        print_menu(is_root=is_root())
        while True:
            try:
                choice = _input("  Select [1-9 / p / c / h / x / d]: ").lower()
            except KeyboardInterrupt:
                print("\n  Back to target prompt…\n")
                choice = ""
                break
            if choice in valid_choices:
                break
            print_error(f"Invalid option '{choice}'.\n")

        if not choice:
            continue

        if choice == EXIT_OPTION:
            try:
                stats = get_stats()
                print_info(
                    f"Session: {stats['total_scans']} scans | "
                    f"{stats['unique_targets']} targets | "
                    f"avg risk {stats['avg_risk_score']}"
                )
            except Exception:
                pass
            print_info("Goodbye. Stay legal. 👋")
            sys.exit(0)

        if choice == "h":
            try:
                rows = get_scan_history(20)
                print_history_table(rows)
            except Exception as exc:
                print_error(f"History error: {exc}")
                log_error(mode="history", error=str(exc), exc=exc)
            continue

        if choice == "c":
            # Scan comparison
            scans = get_scan_history(10)
            if len(scans) < 2:
                print_warning("Need at least 2 scans to compare.")
                continue
            print_info("Recent scans:")
            for s in scans[:5]:
                print(f"    [{s['id']}] {s['target']} — {s['scan_type']} — {s['timestamp']}")
            try:
                old_id = int(_input("  Old scan id: "))
                new_id = int(_input("  New scan id: "))
            except (ValueError, KeyboardInterrupt):
                print_warning("Cancelled.")
                continue
            report = compare_scans(old_id, new_id)
            print(format_change_report(report))
            continue

        if choice == "d":
            # Change detection shortcut: last two scans for target
            from db.database import get_scans_for_target
            scans = get_scans_for_target(last_target)
            if len(scans) < 2:
                print_warning(f"Need at least 2 scans for {last_target!r}.")
                continue
            report = compare_scans(scans[-2]["id"], scans[-1]["id"])
            print(format_change_report(report))
            continue

        if choice == "p":
            print_profiles_menu()
            try:
                idx = int(_input("  Select profile [1-5] or 0 to cancel: "))
            except (ValueError, KeyboardInterrupt):
                continue
            if idx == 0:
                continue
            profile = get_profile_by_index(idx)
            if not profile:
                print_error("Invalid profile.")
                continue
            if profile.requires_root and not is_root():
                print_warning(f"Profile '{profile.name}' requires root.")
            mode = None
            for k, cfg in SCAN_MODES.items():
                if cfg["args"] == profile.nmap_flags:
                    mode = k
                    break
            if not mode:
                mode = "1"
            print_info(f"Profile: {profile.name}\n")
        else:
            mode = choice

        if choice == "x":
            if not last_scan_data:
                print_warning("Run a scan first.\n")
                continue
            run_plugins_menu(last_target, last_scan_data, registry)
            continue

        print()
        if is_cidr:
            try:
                handle_subnet(last_target, mode)
            except KeyboardInterrupt:
                print_warning("\nCancelled.")
            continue

        # ── Single host scan ──────────────────────────────────────────────────
        print_info(f"Target : {last_target}")
        print_info(f"Mode   : {SCAN_MODES[mode]['name']}\n")

        try:
            scan_data = run_scan(last_target, mode)
        except KeyboardInterrupt:
            print_warning("\nScan cancelled. Returning to menu…\n")
            continue
        except Exception as exc:
            print_error(f"Unexpected error: {exc}")
            log_error(target=last_target, mode=mode, error=str(exc), exc=exc)
            continue

        if scan_data:
            if scan_data.get("error"):
                print_error(scan_data["error"])
                continue

            last_scan_data = scan_data
            risk = scan_data.get("risk", {})
            rs   = risk.get("score", 0)

            try:
                show_intel = _input("  Show service intelligence? (y/n) [n]: ").lower() == "y"
            except KeyboardInterrupt:
                show_intel = False

            print_results_table(scan_data, show_intel=show_intel)

            # Dual-write: SQLite + Excel immediately
            try:
                db_id = save_scan(scan_data, risk_score=rs)
                print_info(f"Saved to database (id={db_id})")
            except Exception as exc:
                print_warning(f"DB save failed: {exc}")
                log_error(target=last_target, mode=mode, error="DB save", exc=exc)

            ok, msg = log_scan_to_excel(scan_data, risk_score=rs)
            if ok:
                print_info(msg)
            else:
                print_warning(f"Excel log: {msg}")

            try:
                prompt_save(scan_data)
            except KeyboardInterrupt:
                pass

            if registry:
                try:
                    if _input("  Run a plugin? (y/n) [n]: ").lower() == "y":
                        run_plugins_menu(last_target, scan_data, registry)
                except KeyboardInterrupt:
                    pass

        print()
        try:
            if _input("  Run another scan? (y/n): ").lower() != "y":
                break
        except KeyboardInterrupt:
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
        print("Details saved to Log/error.log")
        sys.exit(1)
