"""
scanner.py — ShadowPort Scanner v1.2
Nmap execution, scan logic, result parsing, root detection, host discovery.
"""

import os
import re
import shutil
import socket
import time
from datetime import datetime

import nmap

from config import SCAN_MODES
from output import print_info, print_error, print_warning, ScanProgress


# ─── Privilege detection ─────────────────────────────────────────────────────

def is_root() -> bool:
    """Return True if the process is running as root/administrator."""
    return os.geteuid() == 0


def is_nmap_installed() -> bool:
    """Return True if nmap binary is available on PATH."""
    return shutil.which("nmap") is not None


# ─── Input validation ─────────────────────────────────────────────────────────

def validate_target(target: str) -> bool:
    """
    Validate target as a non-empty IPv4 address or resolvable hostname.
    Returns True if valid, prints error and returns False otherwise.
    """
    target = target.strip()
    if not target:
        print_error("Target cannot be empty.")
        return False

    # IPv4 address check
    ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if ipv4.match(target):
        parts = target.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return True
        print_error(f"Invalid IP address: {target}")
        return False

    # Hostname DNS resolution check
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        print_error(f"Cannot resolve host: '{target}'")
        return False


# ─── Host discovery (ping sweep) ────────────────────────────────────────────

def ping_host(target: str) -> bool:
    """
    Quick ping sweep to check if host is alive before a full scan.
    Returns True if host responds, False if unreachable.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments="-sn")
        hosts = nm.all_hosts()
        if not hosts:
            return False
        return nm[hosts[0]].state() == "up"
    except Exception:
        return False


# ─── Core scan engine ─────────────────────────────────────────────────────────

def run_scan(target: str, mode: str) -> dict | None:
    """
    Execute an Nmap scan against `target` using the given mode key.

    v1.2 additions:
      - Root privilege check with warning for root-required modes
      - Animated progress bar with ETA
      - Scan start/end timestamps and duration
      - Host discovery pre-check (skipped for mode 6)
      - mode_name embedded in result dict

    Returns a scan_data dict or None on failure.
    """

    # ── Pre-flight checks ────────────────────────────────────────────────────
    if not is_nmap_installed():
        print_error("Nmap is not installed.")
        print_warning("  Fedora/RHEL  : sudo dnf install nmap")
        print_warning("  Debian/Ubuntu: sudo apt install nmap")
        return None

    if mode not in SCAN_MODES:
        print_error(f"Unknown scan mode: '{mode}'")
        return None

    cfg      = SCAN_MODES[mode]
    nmap_args = cfg["args"]
    mode_name = cfg["name"]
    eta       = cfg["eta"]
    needs_root = cfg["root"]

    # Root mode warning (non-blocking — nmap will just fail gracefully)
    if needs_root and not is_root():
        print_warning(f"'{mode_name}' works best as root. Some results may be incomplete.")
        print_warning("  Re-run with: sudo python main.py\n")

    # ── Host discovery pre-check (skip for ping-sweep mode itself) ────────────
    if mode != "6":
        print_info("Running host discovery ping sweep…")
        alive = ping_host(target)
        if not alive:
            print_warning(f"Host {target!r} did not respond to ping.")
            print_warning("Host may be firewalled. Continuing scan anyway…\n")
        else:
            print_info(f"Host {target!r} is UP — proceeding with scan.\n")

    # ── Scan info summary ────────────────────────────────────────────────────
    print_info(f"Mode      : {mode_name} — {cfg['description']}")
    print_info(f"Command   : nmap {nmap_args} {target}")
    print_info(f"ETA       : ~{eta}s  (may vary by target)\n")

    # ── Record start time ─────────────────────────────────────────────────────
    start_dt   = datetime.now()
    start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    wall_start = time.time()

    # ── Launch progress bar ──────────────────────────────────────────────────
    progress = ScanProgress(eta_seconds=eta, mode_name=mode_name)
    progress.start()

    # ── Run Nmap ─────────────────────────────────────────────────────────────
    nm = nmap.PortScanner()
    scan_error = None
    try:
        nm.scan(hosts=target, arguments=nmap_args)
    except nmap.PortScannerError as exc:
        scan_error = str(exc)
    except Exception as exc:
        scan_error = str(exc)
    finally:
        progress.stop()

    # ── Record end time ───────────────────────────────────────────────────────
    wall_end  = time.time()
    end_dt    = datetime.now()
    end_time  = end_dt.strftime("%Y-%m-%d %H:%M:%S")
    duration  = wall_end - wall_start

    if scan_error:
        print_error(f"Nmap error: {scan_error}")
        print_warning("Some modes require root. Try: sudo python main.py")
        return None

    # ── Parse results ─────────────────────────────────────────────────────────
    hosts = nm.all_hosts()
    if not hosts:
        print_warning(f"No hosts returned — {target!r} may be down.")
        return {
            "host":             target,
            "hostname":         "",
            "state":            "down",
            "ports":            [],
            "os_matches":       [],
            "start_time":       start_time,
            "end_time":         end_time,
            "duration_seconds": round(duration, 2),
            "mode_name":        mode_name,
        }

    host_ip   = hosts[0]
    host_data = nm[host_ip]

    # Hostname
    hostname   = ""
    hostnames  = host_data.get("hostnames", [])
    if hostnames:
        hostname = hostnames[0].get("name", "")

    state = host_data.state()

    # Ports
    ports = []
    for proto in host_data.all_protocols():
        for port in sorted(host_data[proto].keys()):
            info = host_data[proto][port]
            version_str = " ".join(filter(None, [
                info.get("product", ""),
                info.get("version", ""),
                info.get("extrainfo", ""),
            ])).strip()
            ports.append({
                "port":    str(port),
                "proto":   proto,
                "state":   info.get("state", "unknown"),
                "service": info.get("name", ""),
                "version": version_str,
            })

    # OS detection
    os_matches = []
    try:
        for m in host_data.get("osmatch", []):
            os_matches.append(
                f"{m.get('name', '')} ({m.get('accuracy', '?')}% accuracy)"
            )
    except Exception:
        pass

    return {
        "host":             host_ip,
        "hostname":         hostname,
        "state":            state,
        "ports":            ports,
        "os_matches":       os_matches,
        "start_time":       start_time,
        "end_time":         end_time,
        "duration_seconds": round(duration, 2),
        "mode_name":        mode_name,
    }
