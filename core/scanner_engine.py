"""
core/scanner_engine.py — ShadowPort Scanner v2.3.0
Nmap engine with live event callbacks for TUI telemetry.
"""

import os
import re
import shutil
import socket
import threading
import time
from datetime import datetime
from typing import Callable, Optional

import nmap

from config.settings import SCAN_MODES, SERVICE_INTEL, RISK_WEIGHTS, RISK_BASE, RISK_MAX
from core.logger import log_error

# ── Validation ────────────────────────────────────────────────────────────────

_IPV4_RE    = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_CIDR_RE    = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$")
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_SHELL_CHARS = set(";|&`$()<>\n\r")


def validate_target(target: str) -> tuple[bool, str]:
    t = target.strip()
    if not t:
        return False, "Target cannot be empty."
    if any(c in t for c in _SHELL_CHARS):
        return False, "Target contains illegal characters."
    if " " in t:
        return False, "Target must not contain spaces."
    try:
        t.encode("ascii")
    except UnicodeEncodeError:
        return False, "Target must contain only ASCII characters."
    if "/" in t:
        if not _CIDR_RE.match(t):
            return False, f"Invalid CIDR: '{t}'"
        ip, prefix = t.split("/")
        if not _is_valid_ip(ip) or not (0 <= int(prefix) <= 32):
            return False, f"Invalid CIDR range: '{t}'"
        return True, ""
    if _IPV4_RE.match(t):
        if _is_valid_ip(t):
            return True, ""
        return False, f"Invalid IP (octet out of range): '{t}'"
    if _HOSTNAME_RE.match(t) and len(t) <= 253:
        return True, ""
    return False, f"Not a valid IP, hostname, or CIDR: '{t}'"


def _is_valid_ip(ip: str) -> bool:
    m = _IPV4_RE.match(ip)
    return bool(m) and all(0 <= int(g) <= 255 for g in m.groups())


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def is_nmap_installed() -> bool:
    return shutil.which("nmap") is not None


def resolve_hostname(target: str) -> tuple[bool, str]:
    if _IPV4_RE.match(target) or "/" in target:
        return True, target
    try:
        return True, socket.gethostbyname(target)
    except socket.gaierror as e:
        return False, str(e)


# ── Enrichment ────────────────────────────────────────────────────────────────

def enrich_port(p: dict) -> dict:
    svc   = p.get("service", "").lower()
    intel = SERVICE_INTEL.get(svc) or SERVICE_INTEL.get("unknown")
    return {**p, "intel": intel}


def calculate_risk(ports: list[dict]) -> dict:
    open_p    = [p for p in ports if p.get("state") == "open"]
    score     = RISK_BASE
    breakdown = []
    for p in open_p:
        svc    = p.get("service", "").lower()
        w      = RISK_WEIGHTS.get(svc, 4)
        score += w
        breakdown.append(f"{p['port']}/{p.get('proto','tcp')} ({svc}) +{w}")
    score = min(score, RISK_MAX)
    label = ("HIGH EXPOSURE"   if score >= 70 else
             "MEDIUM EXPOSURE" if score >= 40 else
             "LOW EXPOSURE"    if score > 0  else "MINIMAL")
    return {"score": score, "label": label, "breakdown": breakdown}


# ── Background scan thread ────────────────────────────────────────────────────

class _Runner:
    def __init__(self, nm, target, args):
        self._nm, self._target, self._args = nm, target, args
        self.error = None
        self._t    = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            self._nm.scan(hosts=self._target, arguments=self._args)
        except Exception as e:
            self.error = e

    def start(self):
        self._t.start()

    def join(self, timeout) -> bool:
        self._t.join(timeout=timeout)
        return self._t.is_alive()


# ── Public scan API ───────────────────────────────────────────────────────────

def run_scan(
    target: str,
    mode:   str,
    on_event: Optional[Callable[[str, str], None]] = None,
) -> Optional[dict]:
    """
    Execute one Nmap scan.
    on_event(level, message) is called for live TUI telemetry.
    Returns enriched scan_data dict or None on failure.
    """
    def evt(level: str, msg: str):
        if on_event:
            on_event(level, msg)

    if not is_nmap_installed():
        evt("ERROR", "Nmap not found. Install: sudo dnf install nmap")
        log_error("scanner", target, "Nmap not installed")
        return None

    if mode not in SCAN_MODES:
        evt("ERROR", f"Unknown scan mode: {mode}")
        return None

    cfg       = SCAN_MODES[mode]
    nmap_args = cfg["args"]
    mode_name = cfg["name"]
    timeout   = cfg["timeout"]

    if cfg["root"] and not is_root():
        evt("ERROR", f"'{mode_name}' requires root. Re-run: sudo python main.py")
        return None

    ok, err = resolve_hostname(target)
    if not ok:
        evt("ERROR", f"DNS resolution failed: {err}")
        log_error("scanner", target, f"DNS failed: {err}")
        return None

    evt("INFO", f"Starting {mode_name} on {target}")
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    wall_start = time.time()

    nm     = nmap.PortScanner()
    runner = _Runner(nm, target, nmap_args)
    runner.start()

    # Poll every 2s to emit progress events
    elapsed = 0.0
    while runner._t.is_alive():
        time.sleep(2.0)
        elapsed += 2.0
        pct = min(int(elapsed / timeout * 100), 97)
        evt("PROGRESS", f"{pct}")
        if elapsed >= timeout:
            evt("WARNING", f"Timeout after {timeout}s — collecting partial results")
            break

    timed_out = runner.join(timeout=1.0)
    duration  = time.time() - wall_start
    end_time  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if runner.error:
        evt("ERROR", f"Nmap error: {runner.error}")
        log_error("scanner", target, str(runner.error))
        return None

    try:
        hosts = nm.all_hosts()
    except Exception:
        hosts = []

    if not hosts:
        evt("WARNING", "No hosts returned — target may be down or filtered")
        return {
            "host": target, "hostname": "", "state": "down",
            "ports": [], "os_matches": [],
            "risk": {"score": 0, "label": "N/A", "breakdown": []},
            "start_time": start_time, "end_time": end_time,
            "duration_seconds": round(duration, 2),
            "mode_name": mode_name, "partial": timed_out, "raw_output": "",
        }

    host_ip   = hosts[0]
    host_data = nm[host_ip]
    hostname  = (host_data.get("hostnames") or [{}])[0].get("name", "")
    state     = host_data.state()
    ports     = []

    try:
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                info = host_data[proto][port]
                ver  = " ".join(filter(None, [
                    info.get("product",""), info.get("version",""), info.get("extrainfo","")
                ])).strip()
                raw = {
                    "port":    str(port), "proto": proto,
                    "state":   info.get("state","unknown"),
                    "service": info.get("name",""),
                    "version": ver, "banner": "",
                }
                enriched = enrich_port(raw)
                ports.append(enriched)
                if raw["state"] == "open":
                    svc_str = f" ({raw['service']})" if raw["service"] else ""
                    evt("PORT", f"{port}/{proto}{svc_str} — open")
    except Exception as e:
        evt("WARNING", f"Port parse error: {e}")
        log_error("scanner", target, f"Port parse: {e}")

    os_matches = []
    try:
        for m in host_data.get("osmatch", []):
            os_matches.append(f"{m.get('name','')} ({m.get('accuracy','?')}% accuracy)")
    except Exception:
        pass

    risk = calculate_risk(ports)
    evt("PROGRESS", "100")
    evt("INFO", f"Scan complete — {sum(1 for p in ports if p.get('state')=='open')} open ports")

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
