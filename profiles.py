"""
profiles.py — ShadowPort Scanner v1.3.0
One-click scan profile presets: Fast, Deep, Lab, Stealth.
"""

from config.settings import PROFILES, SCAN_MODES
from output import print_profiles_menu, print_info, print_error, print_warning


def select_profile(is_root: bool) -> str | None:
    """
    Display the profile menu and return the corresponding scan mode key,
    or None if the user cancels.
    """
    print_profiles_menu(PROFILES)

    keys = {k[0]: k for k in PROFILES}   # first letter → full key
    prompt_keys = "/".join(k[0] for k in PROFILES) + "/cancel"

    while True:
        try:
            choice = input(f"  Select profile [{prompt_keys}]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None

        if choice in ("c", "cancel", ""):
            return None

        matched = keys.get(choice)
        if not matched:
            print_error(f"Invalid choice '{choice}'. Try again.\n")
            continue

        profile   = PROFILES[matched]
        mode_key  = profile["mode"]
        mode_cfg  = SCAN_MODES[mode_key]

        if mode_cfg["root"] and not is_root:
            print_warning(
                f"Profile '{profile['name']}' uses {mode_cfg['name']} which requires root.\n"
                f"  Re-run with: sudo python main.py"
            )
            print_warning("Continuing anyway — results may be limited.\n")

        print_info(f"Profile selected: {profile['name']} → {mode_cfg['name']}\n")
        return mode_key
