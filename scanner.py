"""
scanner.py — ShadowPort Scanner v1.3.0
Core engine: privilege detection, host validation, scan execution,
service intelligence, risk scoring, network/subnet discovery.
"""

import os
import re
import shutil
import socket
import time
from datetime import datetime

import nmap

from config.settings import SCAN_MODES, SERVICE_INTEL, RISK_WEIGHTS, RISK_BASE, RISK_MAX
from output import print_info, print_error, print_warning, print_success, ScanProgress


# ─── Privilege detection ──────────────────────────────────────────────────────

def is_root() -> bool:
    """Return True if running as root/administrator."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False  # Windows fallback


def is_nmap_installed() -> bool:
    return shutil.which("nmap") is not None


# ─── Target validation ────────────────────────────────────────────────────────

def validate_target(target: str) -> bool:
    """Accept IPv4, hostname, or CIDR notation. Returns True if valid."""
    target = target.strip()
    if not target:
        print_error("Target cannot be empty.")
        return False

    # CIDR range  e.g. 192.168.1.0/24
    cidr = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
    if cidr.match(target):
        return True

    # Plain IPv4
    ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if ipv4.match(target):
        if all(0 <= int(p) <= 255 for p in target.split(".")):
            return True
        print_error(f"Invalid IP address: {target}")
        return False

    # Hostname / domain
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        print_error(f"Cannot resolve host: '{target}'")
        return False


# ─── Service intelligence ─────────────────────────────────────────────────────

def enrich_port(port_dict: dict) -> dict:
    """
    Add 'intel' key to a port dict with use/risk info from SERVICE_INTEL.
    """
    svc = port_dict.get("service", "").lower()
    intel = SERVICE_INTEL.get(svc) or SERVICE_INTEL.get("unknown")
    return {**port_dict, "intel": intel}


# ─── Risk scoring ─────────────────────────────────────────────────────────────

def calculate_risk(ports: list[dict]) -> dict:
    """
    Compute an informational risk score (0–100) based on open services.
    Returns {"score": int, "label": str, "breakdown": list[str]}
    """
    open_ports = [p for p in ports if p["state"] == "open"]
    score      = RISK_BASE
    breakdown  = []

    for p in open_ports:
        svc     = p.get("service", "").lower()
        weight  = RISK_WEIGHTS.get(svc, 4)
        score  += weight
        breakdown.append(f"{p['port']}/{p['proto']} ({svc}) +{weight}")

    score = min(score, RISK_MAX)

    if score >= 70:
        label = "HIGH EXPOSURE"
    elif score >= 40:
        label = "MEDIUM EXPOSURE"
    elif score > 0:
        label = "LOW EXPOSURE"
    else:
        label = "MINIMAL"

    return {"score": score, "label": label, "breakdown": breakdown}


# ─── Host discovery ───────────────────────────────────────────────────────────

def ping_host(target: str) -> bool:
    """Quick ping to check host liveness. Returns True if up."""
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments="-sn")
        hosts = nm.all_hosts()
        return bool(hosts) and nm[hosts[0]].state() == "up"
    except Exception:
        return False


def discover_subnet(cidr: str) -> list[str]:
    """
    Run a ping sweep over a CIDR subnet.
    Returns list of active IP strings.
    """
    nm = nmap.PortScanner()
    print_info(f"Running subnet discovery on {cidr}…")
    try:
        nm.scan(hosts=cidr, arguments="-sn")
        active = [h for h in nm.all_hosts() if nm[h].state() == "up"]
        return active
    except Exception as exc:
        print_error(f"Subnet discovery failed: {exc}")
        return []


# ─── Core scan engine ─────────────────────────────────────────────────────────

def run_scan(target: str, mode: str) -> dict | None:
    """
    Execute one Nmap scan. Returns enriched scan_data dict or None on failure.

    v1.3 additions vs v1.2:
      - Port intel enrichment (SERVICE_INTEL)
      - Risk score calculation
      - Risk label in result
      - Cleaner privilege error handling
    """
    if not is_nmap_installed():
        print_error("Nmap is not installed.")
        print_warning("  Fedora/RHEL  : sudo dnf install nmap")
        print_warning("  Debian/Ubuntu: sudo apt install nmap")
        return None

    if mode not in SCAN_MODES:
        print_error(f"Unknown scan mode: '{mode}'")
        return None

    cfg        = SCAN_MODES[mode]
    nmap_args  = cfg["args"]
    mode_name  = cfg["name"]
    eta        = cfg["eta"]
    needs_root = cfg["root"]

    # Root warning
    if needs_root and not is_root():
        print_warning(f"'{mode_name}' requires root. Results may be incomplete.")
        print_warning("  Re-run with: sudo python main.py\n")

    # Pre-check: ping sweep (skip for mode 6 = ping sweep itself)
    if mode != "6":
        alive = ping_host(target)
        if not alive:
            print_warning(f"{target!r} did not respond to ping. Continuing anyway…\n")
        else:
            print_info(f"Host {target!r} is UP — proceeding.\n")

    print_info(f"Mode      : {mode_name} — {cfg['description']}")
    print_info(f"Command   : nmap {nmap_args} {target}")
    print_info(f"ETA       : ~{eta}s\n")

    start_dt   = datetime.now()
    start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    wall_start = time.time()

    progress = ScanProgress(eta_seconds=eta, mode_name=mode_name)
    progress.start()

    nm  = nmap.PortScanner()
    err = None
    try:
        nm.scan(hosts=target, arguments=nmap_args)
    except nmap.PortScannerError as exc:
        err = str(exc)
    except Exception as exc:
        err = str(exc)
    finally:
        progress.stop()

    duration = time.time() - wall_start
    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if err:
        print_error(f"Nmap error: {err}")
        print_warning("Root-only scans need: sudo python main.py")
        return None

    hosts = nm.all_hosts()
    if not hosts:
        print_warning(f"No hosts returned — {target!r} appears down.")
        return {
            "host": target, "hostname": "", "state": "down",
            "ports": [], "os_matches": [], "risk": {"score": 0, "label": "N/A", "breakdown": []},
            "start_time": start_time, "end_time": end_time,
            "duration_seconds": round(duration, 2), "mode_name": mode_name,
        }

    host_ip   = hosts[0]
    host_data = nm[host_ip]

    hostname  = ""
    hostnames = host_data.get("hostnames", [])
    if hostnames:
        hostname = hostnames[0].get("name", "")

    state = host_data.state()

    # Parse and enrich ports
    ports = []
    for proto in host_data.all_protocols():
        for port in sorted(host_data[proto].keys()):
            info = host_data[proto][port]
            version_str = " ".join(filter(None, [
                info.get("product", ""),
                info.get("version", ""),
                info.get("extrainfo", ""),
            ])).strip()
            raw = {
                "port":    str(port),
                "proto":   proto,
                "state":   info.get("state", "unknown"),
                "service": info.get("name", ""),
                "version": version_str,
            }
            ports.append(enrich_port(raw))

    os_matches = []
    try:
        for m in host_data.get("osmatch", []):
            os_matches.append(f"{m.get('name','')} ({m.get('accuracy','?')}% accuracy)")
    except Exception:
        pass

    risk = calculate_risk(ports)

    return {
        "host":             host_ip,
        "hostname":         hostname,
        "state":            state,
        "ports":            ports,
        "os_matches":       os_matches,
        "risk":             risk,
        "start_time":       start_time,
        "end_time":         end_time,
        "duration_seconds": round(duration, 2),
        "mode_name":        mode_name,
    }
