"""
report.py — ShadowPort Scanner
Handles saving scan results to TXT, JSON, and XML files.
"""

import json
import os
from datetime import datetime

from output import print_success, print_error, print_info


REPORTS_DIR = "reports"


def _ensure_reports_dir():
    """Create the reports/ directory if it doesn't exist."""
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _timestamp() -> str:
    """Return a filesystem-safe timestamp string."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _build_txt_content(scan_data: dict) -> str:
    """Convert scan_data dict to a human-readable text report."""
    lines = []
    sep = "=" * 56

    lines.append(sep)
    lines.append("  SHADOWPORT SCANNER — Scan Report")
    lines.append(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(sep)
    lines.append(f"  Target    : {scan_data.get('host', 'N/A')}")
    if scan_data.get("hostname"):
        lines.append(f"  Hostname  : {scan_data['hostname']}")
    lines.append(f"  Status    : {scan_data.get('state', 'unknown').upper()}")
    if scan_data.get("os_matches"):
        lines.append(f"  OS        : {scan_data['os_matches'][0]}")
    lines.append(sep)
    lines.append("")

    ports = scan_data.get("ports", [])
    if not ports:
        lines.append("  No open ports detected.")
    else:
        col_port    = 12
        col_state   = 10
        col_service = 18
        col_version = 30
        lines.append(
            "  "
            + "PORT".ljust(col_port)
            + "STATE".ljust(col_state)
            + "SERVICE".ljust(col_service)
            + "VERSION"
        )
        lines.append("  " + "-" * (col_port + col_state + col_service + col_version))
        for p in ports:
            lines.append(
                "  "
                + f"{p['port']}/{p['proto']}".ljust(col_port)
                + p["state"].ljust(col_state)
                + p["service"].ljust(col_service)
                + p.get("version", "")[:col_version]
            )
        lines.append("  " + "-" * (col_port + col_state + col_service + col_version))
        open_count = sum(1 for p in ports if p["state"] == "open")
        lines.append(f"\n  Total open ports: {open_count}")

    lines.append("")
    lines.append(sep)
    lines.append("  ShadowPort Scanner — github.com/your-username/shadowport")
    lines.append("  Use only on systems you own or are authorized to test.")
    lines.append(sep)

    return "\n".join(lines)


def save_report(scan_data: dict, fmt: str = "txt") -> str | None:
    """
    Save scan_data to a file in the given format.

    Args:
        scan_data : dict returned by scanner.run_scan()
        fmt       : "txt", "json", or "xml"

    Returns:
        Path to saved file, or None on failure.
    """
    _ensure_reports_dir()
    fmt = fmt.lower().strip()
    ts  = _timestamp()
    host_safe = scan_data.get("host", "unknown").replace(".", "-")

    filename = f"scan_{host_safe}_{ts}.{fmt}"
    filepath = os.path.join(REPORTS_DIR, filename)

    try:
        if fmt == "txt":
            content = _build_txt_content(scan_data)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

        elif fmt == "json":
            report_obj = {
                "meta": {
                    "tool":      "ShadowPort Scanner v1.0",
                    "generated": datetime.now().isoformat(),
                },
                "scan": scan_data,
            }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report_obj, f, indent=2)

        elif fmt == "xml":
            # Build minimal XML by hand (no external dependency)
            ports = scan_data.get("ports", [])
            port_lines = []
            for p in ports:
                port_lines.append(
                    f'      <port protocol="{p["proto"]}" portid="{p["port"]}">'
                    f'<state state="{p["state"]}"/>'
                    f'<service name="{p["service"]}" version="{p.get("version","")}" />'
                    f'</port>'
                )
            ports_block = "\n".join(port_lines)

            xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<shadowport_scan>
  <meta>
    <tool>ShadowPort Scanner v1.0</tool>
    <generated>{datetime.now().isoformat()}</generated>
  </meta>
  <host>
    <address addr="{scan_data.get('host','')}" addrtype="ipv4"/>
    <hostname>{scan_data.get('hostname','')}</hostname>
    <status state="{scan_data.get('state','')}"/>
    <ports>
{ports_block}
    </ports>
  </host>
</shadowport_scan>
"""
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(xml)

        else:
            print_error(f"Unknown format '{fmt}'. Choose: txt, json, xml")
            return None

        print_success(f"Report saved → {filepath}")
        return filepath

    except OSError as exc:
        print_error(f"Could not write report: {exc}")
        return None


def prompt_save(scan_data: dict):
    """
    Interactively ask the user whether to save a report and in which format.
    """
    print()
    try:
        choice = input("  Save results? (y/n): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if choice != "y":
        return

    print()
    print_info("Choose format:")
    print("    [1] TXT  — plain text")
    print("    [2] JSON — machine-readable")
    print("    [3] XML  — structured markup")
    print()

    try:
        fmt_choice = input("  Format (1/2/3) [default: 1]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    fmt_map = {"1": "txt", "2": "json", "3": "xml", "": "txt"}
    fmt = fmt_map.get(fmt_choice, "txt")

    save_report(scan_data, fmt)
