"""
scanner.py — ShadowPort Scanner v2.1.0

Core engine:
  - Strict target validation (ValidationResult)
  - DNS pre-check before every scan
  - Per-mode timeout via threading
  - All Nmap invocations use list args, never shell=True
  - Root check before SYN / OS scans
  - Silent error logging
"""

import os
import re
import shlex
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import nmap

from config.settings import SCAN_MODES, SERVICE_INTEL, RISK_WEIGHTS, RISK_BASE, RISK_MAX
from logger import log_error

# ─── ValidationResult ─────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    valid:  bool
    reason: str = ""


_IPV4_RE    = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_CIDR_RE    = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$")
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _is_valid_ipv4(target: str) -> bool:
    m = _IPV4_RE.match(target)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def _is_valid_cidr(target: str) -> bool:
    if not _CIDR_RE.match(target):
        return False
    ip_part = target.split("/")[0]
    prefix  = int(target.split("/")[1])
    return _is_valid_ipv4(ip_part) and 0 <= prefix <= 32


def validate_target(target: str) -> ValidationResult:
    """
    Full validation pipeline. Returns ValidationResult(valid, reason).
    Accepts: valid IPv4, CIDR, resolvable hostname.
    Rejects: everything else including shell-injection attempts.
    """
    target = target.strip()

    if not target:
        return ValidationResult(False, "Target cannot be empty.")

    # Block shell metacharacters — extra layer of defence
    if any(c in target for c in (";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r")):
        return ValidationResult(False, f"Target contains illegal characters: '{target}'")

    if " " in target:
        return ValidationResult(False, f"Target must not contain spaces: '{target}'")

    # Unicode check — only ASCII allowed
    try:
        target.encode("ascii")
    except UnicodeEncodeError:
        return ValidationResult(False, "Target must contain only ASCII characters.")

    if "/" in target:
        if _is_valid_cidr(target):
            return ValidationResult(True)
        return ValidationResult(False, f"Invalid CIDR range: '{target}'")

    if _IPV4_RE.match(target):
        if _is_valid_ipv4(target):
            return ValidationResult(True)
        return ValidationResult(False, f"Invalid IP (octet out of range): '{target}'")

    if _HOSTNAME_RE.match(target) and len(target) <= 253:
        return ValidationResult(True)

    return ValidationResult(False, f"Not a valid IP, hostname, or CIDR: '{target}'")


# ─── Privilege detection ──────────────────────────────────────────────────────

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def is_nmap_installed() -> bool:
    return shutil.which("nmap") is not None


# ─── DNS pre-check ────────────────────────────────────────────────────────────

def resolve_hostname(target: str) -> tuple[bool, str]:
    """Returns (ok, ip_or_error). Skips resolution for raw IPs and CIDRs."""
    if _IPV4_RE.match(target) or "/" in target:
        return True, target
    try:
        ip = socket.gethostbyname(target)
        return True, ip
    except socket.gaierror as exc:
        return False, str(exc)


# ─── Service intelligence ─────────────────────────────────────────────────────

def enrich_port(port_dict: dict) -> dict:
    svc   = port_dict.get("service", "").lower()
    intel = SERVICE_INTEL.get(svc) or SERVICE_INTEL.get("unknown")
    return {**port_dict, "intel": intel}


# ─── Risk scoring ─────────────────────────────────────────────────────────────

def calculate_risk(ports: list[dict]) -> dict:
    open_ports = [p for p in ports if p.get("state") == "open"]
    score      = RISK_BASE
    breakdown  = []
    for p in open_ports:
        svc    = p.get("service", "").lower()
        weight = RISK_WEIGHTS.get(svc, 4)
        score += weight
        breakdown.append(f"{p['port']}/{p['proto']} ({svc}) +{weight}")
    score = min(score, RISK_MAX)
    label = (
        "HIGH EXPOSURE"   if score >= 70 else
        "MEDIUM EXPOSURE" if score >= 40 else
        "LOW EXPOSURE"    if score > 0  else
        "MINIMAL"
    )
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
    try:
        nm.scan(hosts=cidr, arguments="-sn")
        return [h for h in nm.all_hosts() if nm[h].state() == "up"]
    except Exception as exc:
        log_error(target=cidr, mode="Host Discovery", error=str(exc), exc=exc)
        return []


# ─── Timeout-protected scan thread ───────────────────────────────────────────

class _ScanRunner:
    def __init__(self, nm: nmap.PortScanner, target: str, args: str):
        self._nm     = nm
        self._target = target
        self._args   = args
        self.error   = None
        self.done    = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            # nmap-python internally calls nmap via subprocess with list args
            self._nm.scan(hosts=self._target, arguments=self._args)
        except Exception as exc:
            self.error = exc
        finally:
            self.done = True

    def start(self):
        self._thread.start()

    def join(self, timeout: float) -> bool:
        """Returns True if still running (timed out)."""
        self._thread.join(timeout=timeout)
        return self._thread.is_alive()


# ─── Core scan engine ─────────────────────────────────────────────────────────

def run_scan(target: str, mode: str, on_port_found=None) -> Optional[dict]:
    """
    Execute one Nmap scan with full error handling and timeout protection.
    on_port_found(port, protocol, service, state): optional callback for live events.
    Returns enriched scan_data dict or None on failure.
    Subprocess is never called with shell=True.
    """
    if not is_nmap_installed():
        log_error(target=target, mode=mode, error="Nmap not installed")
        return None

    if mode not in SCAN_MODES:
        log_error(target=target, mode=mode, error=f"Unknown mode: {mode}")
        return None

    cfg        = SCAN_MODES[mode]
    nmap_args  = cfg["args"]
    mode_name  = cfg["name"]
    timeout    = cfg["timeout"]
    needs_root = cfg["root"]

    # Root check before privileged scans — never auto-invoke sudo
    if needs_root and not is_root():
        log_error(target=target, mode=mode_name, error="Scan requires root privileges")
        return {
            "host": target, "state": "error",
            "error": f"'{mode_name}' requires root. Re-run with: sudo python main.py",
            "ports": [], "os_matches": [], "partial": False,
            "risk": {"score": 0, "label": "N/A", "breakdown": []},
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": 0.0, "mode_name": mode_name,
        }

    # DNS pre-check
    if mode != "6":
        ok, result = resolve_hostname(target)
        if not ok:
            log_error(target=target, mode=mode_name, error=f"DNS failed: {result}")
            return None

    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    wall_start = time.time()

    nm     = nmap.PortScanner()
    runner = _ScanRunner(nm, target, nmap_args)
    runner.start()
    timed_out = runner.join(timeout=float(timeout))

    duration = time.time() - wall_start
    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if runner.error:
        err_str = str(runner.error)
        log_error(target=target, mode=mode_name, error=err_str, exc=runner.error)
        return None

    try:
        hosts = nm.all_hosts()
    except Exception:
        hosts = []

    if not hosts:
        return {
            "host": target, "hostname": "", "state": "down",
            "ports": [], "os_matches": [],
            "risk": {"score": 0, "label": "N/A", "breakdown": []},
            "start_time": start_time, "end_time": end_time,
            "duration_seconds": round(duration, 2),
            "mode_name": mode_name, "partial": timed_out,
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
                    "banner":  info.get("script", {}).get("banner", ""),
                }
                enriched = enrich_port(raw)
                ports.append(enriched)
                if on_port_found and raw["state"] == "open":
                    on_port_found(
                        raw["port"], proto, raw["service"], raw["state"]
                    )
    except Exception as exc:
        log_error(target=target, mode=mode_name, error="Port parse error", exc=exc)

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
        "partial":          timed_out,
        "raw_output":       "",
    }
