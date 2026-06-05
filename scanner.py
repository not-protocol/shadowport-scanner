"""
scanner.py — ShadowPort Scanner v2.0.0
Core engine: privilege detection, target validation, DNS pre-check,
scan execution with timeout protection, service intel, risk scoring,
subnet discovery.

v2.0.0 changes vs v1.3.0:
  - Strict target validation (rejects garbage inputs)
  - DNS pre-check before every hostname scan
  - Per-mode timeout enforcement via threading.Timer
  - All Nmap errors caught and displayed cleanly
  - Partial result recovery on crash/timeout
  - Silent error logging to logs/error.log
"""

import os
import re
import shutil
import socket
import threading
import time
from datetime import datetime

import nmap

from config.settings import SCAN_MODES, SERVICE_INTEL, RISK_WEIGHTS, RISK_BASE, RISK_MAX
from logger import log_error
from output import print_info, print_error, print_warning, print_success, ScanProgress


# ─── Privilege detection ──────────────────────────────────────────────────────

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def is_nmap_installed() -> bool:
    return shutil.which("nmap") is not None


# ─── Target validation ────────────────────────────────────────────────────────

# Valid hostname: labels separated by dots, each label alphanumeric + hyphens
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$")


def _is_valid_ipv4(target: str) -> bool:
    m = _IPV4_RE.match(target)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def _is_valid_cidr(target: str) -> bool:
    m = _CIDR_RE.match(target)
    if not m:
        return False
    ip_part = target.split("/")[0]
    prefix  = int(target.split("/")[1])
    return _is_valid_ipv4(ip_part) and 0 <= prefix <= 32


def _is_valid_hostname(target: str) -> bool:
    return bool(_HOSTNAME_RE.match(target)) and len(target) <= 253


def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate a target string.
    Returns (True, "") on success or (False, reason) on failure.

    Accepted: valid IPv4, valid CIDR, resolvable hostname.
    Rejected: everything else — single words, partial IPs, garbage, etc.
    """
    target = target.strip()

    if not target:
        return False, "Target cannot be empty."

    # Block obviously invalid single tokens that aren't IPs or hostnames
    if " " in target:
        return False, f"Target contains spaces: '{target}'"

    # CIDR
    if "/" in target:
        if _is_valid_cidr(target):
            return True, ""
        return False, f"Invalid CIDR range: '{target}'"

    # IPv4
    if _IPV4_RE.match(target):
        if _is_valid_ipv4(target):
            return True, ""
        return False, f"Invalid IP address (octet out of range): '{target}'"

    # Hostname — must look like a real domain (at least one dot, valid chars)
    if _is_valid_hostname(target):
        return True, ""

    return False, f"Not a valid IP address, hostname, or CIDR range: '{target}'"


# ─── DNS pre-check ────────────────────────────────────────────────────────────

def resolve_hostname(target: str) -> tuple[bool, str]:
    """
    Attempt to resolve a hostname to an IP.
    Returns (True, ip) or (False, error_message).
    Skips resolution for raw IPs and CIDRs.
    """
    # Raw IPv4 or CIDR — no DNS needed
    if _IPV4_RE.match(target) or "/" in target:
        return True, target

    try:
        ip = socket.gethostbyname(target)
        return True, ip
    except socket.gaierror as e:
        return False, str(e)


# ─── Service intelligence ─────────────────────────────────────────────────────

def enrich_port(port_dict: dict) -> dict:
    svc   = port_dict.get("service", "").lower()
    intel = SERVICE_INTEL.get(svc) or SERVICE_INTEL.get("unknown")
    return {**port_dict, "intel": intel}


# ─── Risk scoring ─────────────────────────────────────────────────────────────

def calculate_risk(ports: list[dict]) -> dict:
    open_ports = [p for p in ports if p["state"] == "open"]
    score      = RISK_BASE
    breakdown  = []

    for p in open_ports:
        svc    = p.get("service", "").lower()
        weight = RISK_WEIGHTS.get(svc, 4)
        score += weight
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
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments="-sn")
        hosts = nm.all_hosts()
        return bool(hosts) and nm[hosts[0]].state() == "up"
    except Exception:
        return False


def discover_subnet(cidr: str) -> list[str]:
    nm = nmap.PortScanner()
    print_info(f"Running subnet discovery on {cidr}…")
    try:
        nm.scan(hosts=cidr, arguments="-sn")
        return [h for h in nm.all_hosts() if nm[h].state() == "up"]
    except Exception as exc:
        print_error(f"Subnet discovery failed: {exc}")
        log_error(target=cidr, mode="Host Discovery", error=str(exc), exc=exc)
        return []


# ─── Timeout-protected scan ───────────────────────────────────────────────────

class _ScanRunner:
    """
    Runs nmap.scan() in a background thread with a hard timeout.
    Stores result or exception; caller checks after join().
    """

    def __init__(self, nm: nmap.PortScanner, target: str, args: str):
        self._nm     = nm
        self._target = target
        self._args   = args
        self.error   = None
        self.done    = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            self._nm.scan(hosts=self._target, arguments=self._args)
        except Exception as exc:
            self.error = exc
        finally:
            self.done = True

    def start(self):
        self._thread.start()

    def join(self, timeout: float):
        self._thread.join(timeout=timeout)
        return self._thread.is_alive()  # True = still running = timed out


# ─── Core scan engine ─────────────────────────────────────────────────────────

def run_scan(target: str, mode: str) -> dict | None:
    """
    Execute one Nmap scan with full error handling and timeout protection.
    Returns enriched scan_data dict or None on unrecoverable failure.
    """

    # ── Pre-flight checks ────────────────────────────────────────────────────
    if not is_nmap_installed():
        print_error("Nmap executable not found.")
        print_info("  Fedora/RHEL  : sudo dnf install nmap")
        print_info("  Debian/Ubuntu: sudo apt install nmap")
        log_error(target=target, mode=mode, error="Nmap not installed")
        return None

    if mode not in SCAN_MODES:
        print_error(f"Unknown scan mode: '{mode}'")
        return None

    cfg        = SCAN_MODES[mode]
    nmap_args  = cfg["args"]
    mode_name  = cfg["name"]
    eta        = cfg["eta"]
    timeout    = cfg["timeout"]
    needs_root = cfg["root"]

    if needs_root and not is_root():
        print_warning(f"'{mode_name}' requires root. Results may be incomplete.")
        print_warning("  Re-run with: sudo python main.py\n")

    # ── DNS pre-check ────────────────────────────────────────────────────────
    if mode != "6":
        ok, result = resolve_hostname(target)
        if not ok:
            print_error(f"Hostname could not be resolved: '{target}'")
            print_info(f"  Reason: {result}")
            print_info("  Check the hostname and your internet connection.")
            log_error(target=target, mode=mode_name, error=f"DNS resolution failed: {result}")
            return None

        # Ping sweep (skip for the ping-sweep mode itself)
        alive = ping_host(target)
        if not alive:
            print_warning(f"{target!r} did not respond to ping. Continuing anyway…\n")
        else:
            print_info(f"Host {target!r} is UP — proceeding.\n")

    print_info(f"Mode      : {mode_name} — {cfg['description']}")
    print_info(f"Command   : nmap {nmap_args} {target}")
    print_info(f"ETA       : ~{eta}s  |  Timeout: {timeout}s\n")

    start_dt   = datetime.now()
    start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    wall_start = time.time()

    progress = ScanProgress(eta_seconds=eta, mode_name=mode_name)
    progress.start()

    nm     = nmap.PortScanner()
    runner = _ScanRunner(nm, target, nmap_args)
    runner.start()

    timed_out = runner.join(timeout=timeout)

    duration = time.time() - wall_start
    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if timed_out:
        progress.stop(state="timeout")
        msg = f"Scan timeout exceeded ({timeout}s)."
        print_warning(msg)
        print_warning("Scan terminated safely. Partial results may be available.")
        log_error(target=target, mode=mode_name, error=msg)
        # Fall through — nm may still have partial data

    else:
        progress.stop(state="done" if not runner.error else "error")

    if runner.error:
        err = runner.error
        err_str = str(err)

        if "permission" in err_str.lower() or "root" in err_str.lower():
            print_error("Permission denied.")
            print_info("  This scan mode requires root privileges.")
            print_info("  Re-run with: sudo python main.py")
        elif "not found" in err_str.lower() or "nmap" in err_str.lower():
            print_error("Nmap executable not found.")
            print_info("  sudo dnf install nmap   (Fedora)")
            print_info("  sudo apt install nmap   (Debian/Ubuntu)")
        else:
            print_error(f"Nmap error: {err_str}")
            print_warning("Re-run with: sudo python main.py  if this is a permissions issue.")

        log_error(target=target, mode=mode_name, error=err_str, exc=err)
        return None

    # ── Parse results ────────────────────────────────────────────────────────
    try:
        hosts = nm.all_hosts()
    except Exception:
        hosts = []

    if not hosts:
        if timed_out:
            print_warning("No hosts in partial results after timeout.")
        else:
            print_warning(f"No hosts returned — {target!r} appears down or filtered.")

        return {
            "host": target, "hostname": "", "state": "down",
            "ports": [], "os_matches": [],
            "risk": {"score": 0, "label": "N/A", "breakdown": []},
            "start_time": start_time, "end_time": end_time,
            "duration_seconds": round(duration, 2),
            "mode_name": mode_name,
            "partial": timed_out,
        }

    host_ip   = hosts[0]
    host_data = nm[host_ip]

    hostname  = ""
    hostnames = host_data.get("hostnames", [])
    if hostnames:
        hostname = hostnames[0].get("name", "")

    state = host_data.state()

    ports = []
    try:
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
    except Exception as exc:
        print_warning("Partial port data recovered after error.")
        log_error(target=target, mode=mode_name, error="Port parse error", exc=exc)

    os_matches = []
    try:
        for m in host_data.get("osmatch", []):
            os_matches.append(f"{m.get('name','')} ({m.get('accuracy','?')}% accuracy)")
    except Exception:
        pass

    risk = calculate_risk(ports)

    if timed_out:
        print_warning("Scan interrupted unexpectedly. Partial results recovered.")
        print_info("Displaying available data…\n")

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
        "partial":          timed_out,
    }
