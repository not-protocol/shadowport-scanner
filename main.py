#!/usr/bin/env python3
"""
main.py — ShadowPort Scanner v1.2
Entry point: menu, user input, privilege detection, workflow controller.

Usage:
    python main.py          ← basic modes (1, 2, 3, 6, 8)
    sudo python main.py     ← full access (all modes including 4, 5, 7)

Author  : ShadowPort Project
License : MIT
Ethics  : Use ONLY on systems you own or have written authorization to test.
"""

import sys

from config import SCAN_MODES, EXIT_OPTION, VERSION
from output import (
    print_banner,
    print_menu,
    print_info,
    print_error,
    print_warning,
    print_success,
    print_results_table,
)
from scanner import run_scan, validate_target, is_root
from report import prompt_save, show_history


# ─── Ethics / startup notice ─────────────────────────────────────────────────

ETHICS_NOTICE = """
  ┌──────────────────────────────────────────────────────────┐
  │                ⚠  ETHICAL USE NOTICE  ⚠                  │
  │                                                          │
  │  ShadowPort Scanner is for AUTHORIZED USE ONLY:          │
  │   • Systems you personally own                           │
  │   • Networks with written authorization                  │
  │   • Lab environments: VMs, HTB, TryHackMe, etc.          │
  │                                                          │
  │  Unauthorized scanning is ILLEGAL in most jurisdictions. │
  │  You are solely responsible for your use of this tool.   │
  └──────────────────────────────────────────────────────────┘
"""


# ─── Input helpers ────────────────────────────────────────────────────────────

def get_target() -> str:
    """Prompt for and validate target IP or hostname."""
    while True:
        try:
            target = input("  Enter target IP or hostname: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if validate_target(target):
            return target
        print_warning("Please enter a valid IP address or resolvable hostname.\n")


def get_scan_mode(root: bool) -> str:
    """Display menu and collect a valid mode choice from the user."""
    print_menu(is_root=root)

    valid = set(SCAN_MODES.keys()) | {EXIT_OPTION, "h"}

    while True:
        try:
            choice = input("  Select mode [1-9] or [h] history: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if choice in valid:
            return choice
        print_error(f"Invalid option '{choice}'. Choose 1–9 or h.\n")


# ─── Main workflow ────────────────────────────────────────────────────────────

def main():
    print_banner()
    print(ETHICS_NOTICE)

    root = is_root()
    if root:
        print_success("Running as root — all scan modes available.\n")
    else:
        print_warning("Running without root — modes 4, 5, 7 may give incomplete results.\n")

    while True:

        # ── Get target ────────────────────────────────────────────────────────
        target = get_target()
        print()

        # ── Get mode ──────────────────────────────────────────────────────────
        mode = get_scan_mode(root)

        if mode == EXIT_OPTION:
            print_info("Goodbye. Stay legal out there. 👋")
            sys.exit(0)

        if mode == "h":
            show_history()
            continue

        mode_cfg  = SCAN_MODES[mode]
        mode_name = mode_cfg["name"]

        print()
        print_info(f"Target    : {target}")
        print_info(f"Mode      : {mode_name}")
        print()

        # ── Run scan ──────────────────────────────────────────────────────────
        scan_data = run_scan(target, mode)

        # ── Display results ───────────────────────────────────────────────────
        if scan_data:
            print_results_table(scan_data)
            prompt_save(scan_data)

        # ── Continue or exit ──────────────────────────────────────────────────
        print()
        try:
            again = input("  Run another scan? (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if again != "y":
            break

        print("\n" + "─" * 64 + "\n")

    print()
    print_info("Session ended. Goodbye.")


if __name__ == "__main__":
    main()
