"""
scanner.py — ShadowPort Scanner
Handles Nmap execution, scan logic, and result parsing.
"""

import shutil
import socket
import re
import nmap

from output import print_info, print_error, print_warning


# ─── Scan mode definitions ─────────────────────────────────────────────────

SCAN_MODES = {
    "1": {
        "name": "Quick Scan",
        "args": "",
        "description": "Scans top 1000 common ports",
    },
    "2": {
        "name": "Full TCP Scan",
        "args": "-p-",
        "description": "Scans all 65535 TCP ports",
    },
    "3": {
        "name": "Service Detection",
        "args": "-sV",
        "description": "Detects services and versions",
    },
    "4": {
        "name": "OS Detection",
        "args": "-O",
        "description": "Attempts OS fingerprinting (requires root)",
    },
    "5": {
        "name": "Aggressive Scan",
        "args": "-A",
        "description": "OS, version, scripts, traceroute",
    },
}


# ─── Validation helpers ─────────────────────────────────────────────────────

def is_nmap_installed() -> bool:
    """Return True if nmap binary is found on PATH."""
    return shutil.which("nmap") is not None


def validate_target(target: str) -> bool:
    """
    Validate that target is a non-empty IP address or resolvable hostname.
    Returns True if valid, False otherwise.
    """
    target = target.strip()
    if not target:
        print_error("Target cannot be empty.")
        return False

    # Check valid IPv4 pattern
    ipv4_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    if ipv4_pattern.match(target):
        parts = target.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return True
        print_error(f"Invalid IP address: {target}")
        return False

    # Try to resolve hostname
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        print_error(f"Cannot resolve host: '{target}'")
        return False


# ─── Core scanner ───────────────────────────────────────────────────────────

def run_scan(target: str, mode: str) -> dict | None:
    """
    Execute an Nmap scan against `target` using the given mode key.

    Args:
        target: IP address or hostname to scan.
        mode:   Key from SCAN_MODES (e.g. "1", "2", …).

    Returns:
        A dict with scan results, or None on failure.
        Dict structure:
          {
            "host":       str,
            "hostname":   str,
            "state":      str,   # "up" / "down"
            "ports":      list[dict],
            "os_matches": list[str],
          }
        Each port dict:
          { "port": str, "proto": str, "state": str,
            "service": str, "version": str }
    """
    if not is_nmap_installed():
        print_error("Nmap is not installed. Install it and try again.")
        print_warning("  Fedora/RHEL : sudo dnf install nmap")
        print_warning("  Debian/Ubuntu: sudo apt install nmap")
        return None

    if mode not in SCAN_MODES:
        print_error(f"Unknown scan mode: {mode}")
        return None

    scan_cfg = SCAN_MODES[mode]
    nmap_args = scan_cfg["args"]

    print_info(f"Mode      : {scan_cfg['name']} — {scan_cfg['description']}")
    print_info(f"Nmap args : nmap {nmap_args} {target}")
    print_info("Launching scanner… this may take a while.\n")

    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=target, arguments=nmap_args)
    except nmap.PortScannerError as exc:
        print_error(f"Nmap error: {exc}")
        print_warning("OS/stealth scans may require root privileges. Try: sudo python main.py")
        return None
    except Exception as exc:
        print_error(f"Unexpected error during scan: {exc}")
        return None

    # Collect scanned hosts
    hosts = nm.all_hosts()
    if not hosts:
        print_warning(f"Host {target!r} appears to be down or unreachable.")
        return {
            "host": target,
            "hostname": "",
            "state": "down",
            "ports": [],
            "os_matches": [],
        }

    # Use the first (and usually only) host
    host_ip = hosts[0]
    host_data = nm[host_ip]

    hostname = ""
    hostnames = host_data.get("hostnames", [])
    if hostnames:
        hostname = hostnames[0].get("name", "")

    state = host_data.state()

    # Parse ports
    ports = []
    for proto in host_data.all_protocols():
        port_list = sorted(host_data[proto].keys())
        for port in port_list:
            port_info = host_data[proto][port]
            ports.append({
                "port":    str(port),
                "proto":   proto,
                "state":   port_info.get("state", "unknown"),
                "service": port_info.get("name", ""),
                "version": (
                    port_info.get("product", "")
                    + " " + port_info.get("version", "")
                    + " " + port_info.get("extrainfo", "")
                ).strip(),
            })

    # OS detection (may be empty without root)
    os_matches = []
    try:
        os_raw = host_data.get("osmatch", [])
        os_matches = [
            f"{m.get('name', '')} ({m.get('accuracy', '?')}% accuracy)"
            for m in os_raw
        ]
    except Exception:
        pass

    return {
        "host":       host_ip,
        "hostname":   hostname,
        "state":      state,
        "ports":      ports,
        "os_matches": os_matches,
    }
