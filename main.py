#!/usr/bin/env python3
"""
main.py — ShadowPort Scanner
Entry point: menu, user input, and workflow controller.

Usage:
    python main.py
    sudo python main.py   ← required for OS detection (-O) and SYN scans

Author  : ShadowPort Project
License : MIT
Ethics  : Use ONLY on systems you own or are authorized to test.
"""

import sys

from output import (
    print_banner,
    print_menu,
    print_info,
    print_error,
    print_warning,
    print_results_table,
)
from scanner import run_scan, validate_target, SCAN_MODES
from report import prompt_save


# ─── Ethics notice ──────────────────────────────────────────────────────────

ETHICS_NOTICE = """
  ┌─────────────────────────────────────────────────────┐
  │              ⚠  ETHICAL USE NOTICE  ⚠               │
  │                                                     │
  │  ShadowPort Scanner is intended ONLY for:           │
  │   • Systems you personally own                      │
  │   • Networks you have written authorization for     │
  │   • Personal lab environments (VMs, HTB, THM, etc.) │
  │                                                     │
  │  Unauthorized scanning is ILLEGAL in most           │
  │  jurisdictions. You are solely responsible for      │
  │  how you use this tool.                             │
  └─────────────────────────────────────────────────────┘
"""


# ─── Input helpers ───────────────────────────────────────────────────────────

def get_target() -> str:
    """Prompt user for target and validate. Returns clean target string."""
    while True:
        try:
            target = input("  Enter target IP or hostname: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if validate_target(target):
            return target
        print_warning("Please enter a valid IP address or hostname.\n")


def get_scan_mode() -> str:
    """Display the menu and get a valid scan mode from the user."""
    print_menu()
    valid = set(SCAN_MODES.keys()) | {"6"}
    while True:
        try:
            choice = input("  Select mode [1-6]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if choice in valid:
            return choice
        print_error(f"Invalid option '{choice}'. Please choose 1–6.\n")


# ─── Main workflow ───────────────────────────────────────────────────────────

def main():
    print_banner()
    print(ETHICS_NOTICE)

    while True:
        # ── Get target ──────────────────────────────────────────────────────
        target = get_target()
        print()

        # ── Get mode ────────────────────────────────────────────────────────
        mode = get_scan_mode()

        if mode == "6":
            print_info("Goodbye. Stay legal out there.")
            sys.exit(0)

        mode_name = SCAN_MODES[mode]["name"]
        print()
        print_info(f"Target    : {target}")
        print_info(f"Scan mode : {mode_name}")
        print()

        # ── Run scan ────────────────────────────────────────────────────────
        scan_data = run_scan(target, mode)

        # ── Display results ─────────────────────────────────────────────────
        if scan_data:
            print_results_table(scan_data)

            # ── Optionally save ──────────────────────────────────────────────
            prompt_save(scan_data)

        # ── Continue or exit ─────────────────────────────────────────────────
        print()
        try:
            again = input("  Run another scan? (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if again != "y":
            break

        print("\n" + "─" * 60 + "\n")

    print()
    print_info("Session ended. Goodbye.")


if __name__ == "__main__":
    main()
