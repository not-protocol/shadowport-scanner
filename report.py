"""
report.py — ShadowPort Scanner v1.2
Save reports (TXT, JSON, XML, HTML) and maintain a scan history log.
"""

import json
import os
import csv
from datetime import datetime

from config import REPORTS_DIR, LOGS_DIR, TOOL_NAME, VERSION
from output import print_success, print_error, print_info, print_warning


# ─── Directory setup ─────────────────────────────────────────────────────────

def _ensure_dirs():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)


def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _host_safe(host: str) -> str:
    return host.replace(".", "-").replace(":", "-")


# ─── TXT report ──────────────────────────────────────────────────────────────

def _build_txt(scan_data: dict) -> str:
    sep  = "═" * 60
    sep2 = "─" * 60
    lines = [
        sep,
        f"  {TOOL_NAME} v{VERSION} — Scan Report",
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        sep,
        f"  Target    : {scan_data.get('host', 'N/A')}",
    ]
    if scan_data.get("hostname"):
        lines.append(f"  Hostname  : {scan_data['hostname']}")
    lines += [
        f"  Status    : {scan_data.get('state', 'unknown').upper()}",
        f"  Scan Mode : {scan_data.get('mode_name', 'N/A')}",
        f"  Started   : {scan_data.get('start_time', 'N/A')}",
        f"  Finished  : {scan_data.get('end_time', 'N/A')}",
        f"  Duration  : {scan_data.get('duration_seconds', 0):.1f}s",
    ]
    if scan_data.get("os_matches"):
        lines.append(f"  OS Match  : {scan_data['os_matches'][0]}")
    lines += [sep, ""]

    ports = scan_data.get("ports", [])
    if not ports:
        lines.append("  No open ports detected.")
    else:
        col_p, col_s, col_sv, col_v = 14, 12, 20, 32
        lines.append(
            "  " + "PORT".ljust(col_p) + "STATE".ljust(col_s)
            + "SERVICE".ljust(col_sv) + "VERSION"
        )
        lines.append("  " + sep2)
        for p in ports:
            lines.append(
                "  "
                + f"{p['port']}/{p['proto']}".ljust(col_p)
                + p["state"].ljust(col_s)
                + p["service"].ljust(col_sv)
                + p.get("version", "")[:col_v]
            )
        lines.append("  " + sep2)

        open_c = sum(1 for p in ports if p["state"] == "open")
        lines += [
            "",
            f"  Open ports   : {open_c}",
            f"  Total scanned: {len(ports)}",
        ]

    lines += [
        "",
        sep,
        f"  {TOOL_NAME} — Use only on authorized systems.",
        sep,
    ]
    return "\n".join(lines)


# ─── HTML report ─────────────────────────────────────────────────────────────

def _build_html(scan_data: dict) -> str:
    host      = scan_data.get("host", "N/A")
    hostname  = scan_data.get("hostname", "")
    state     = scan_data.get("state", "unknown")
    ports     = scan_data.get("ports", [])
    os_match  = scan_data.get("os_matches", ["N/A"])[0] if scan_data.get("os_matches") else "N/A"
    open_c    = sum(1 for p in ports if p["state"] == "open")

    state_color = "#00ff88" if state == "up" else "#ff4455"

    rows = ""
    for p in ports:
        sc = ("#00ff88" if p["state"] == "open"
              else "#ff4455" if p["state"] == "closed"
              else "#ffcc00")
        rows += (
            f"<tr>"
            f"<td>{p['port']}/{p['proto']}</td>"
            f"<td style='color:{sc}'>{p['state']}</td>"
            f"<td>{p['service']}</td>"
            f"<td>{p.get('version','')}</td>"
            f"</tr>\n"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ShadowPort Scan — {host}</title>
<style>
  :root {{
    --bg: #0a0e1a; --panel: #111827; --border: #1e3a5f;
    --green: #00ff88; --cyan: #00cfff; --yellow: #ffcc00;
    --red: #ff4455; --text: #c9d1e0; --dim: #607090;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text);
          font-family: 'Courier New', monospace; padding: 2rem; }}
  h1 {{ color: var(--red); font-size: 1.6rem; letter-spacing: 3px;
        text-transform: uppercase; margin-bottom: 0.3rem; }}
  .sub {{ color: var(--cyan); font-size: 0.85rem; margin-bottom: 2rem; }}
  .card {{ background: var(--panel); border: 1px solid var(--border);
           border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .card h2 {{ color: var(--cyan); font-size: 0.9rem; letter-spacing: 2px;
              text-transform: uppercase; margin-bottom: 1rem;
              border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
  .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }}
  .meta-row {{ display: flex; gap: 1rem; }}
  .meta-label {{ color: var(--dim); min-width: 110px; }}
  .meta-val   {{ color: var(--text); font-weight: bold; }}
  .status-up  {{ color: var(--green); }}
  .status-dn  {{ color: var(--red); }}
  .summary {{ display: flex; gap: 2rem; }}
  .stat {{ text-align: center; }}
  .stat-num {{ font-size: 2rem; font-weight: bold; color: var(--green); }}
  .stat-lbl {{ font-size: 0.75rem; color: var(--dim); text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th {{ background: #0d1929; color: var(--cyan); padding: 0.6rem 0.8rem;
        text-align: left; letter-spacing: 1px; text-transform: uppercase; }}
  td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid #1a2740; }}
  tr:hover td {{ background: #151f35; }}
  .footer {{ color: var(--dim); font-size: 0.75rem; text-align: center;
             margin-top: 2rem; }}
</style>
</head>
<body>
<h1>⚡ ShadowPort Scanner</h1>
<div class="sub">v{VERSION} — Network Reconnaissance &amp; Port Analysis</div>

<div class="card">
  <h2>Host Information</h2>
  <div class="meta-grid">
    <div class="meta-row"><span class="meta-label">Target</span>
      <span class="meta-val">{host}</span></div>
    <div class="meta-row"><span class="meta-label">Hostname</span>
      <span class="meta-val">{hostname or '—'}</span></div>
    <div class="meta-row"><span class="meta-label">Status</span>
      <span class="meta-val {'status-up' if state=='up' else 'status-dn'}">{state.upper()}</span></div>
    <div class="meta-row"><span class="meta-label">OS Match</span>
      <span class="meta-val">{os_match}</span></div>
    <div class="meta-row"><span class="meta-label">Scan Mode</span>
      <span class="meta-val">{scan_data.get('mode_name','N/A')}</span></div>
    <div class="meta-row"><span class="meta-label">Duration</span>
      <span class="meta-val">{scan_data.get('duration_seconds',0):.1f}s</span></div>
    <div class="meta-row"><span class="meta-label">Started</span>
      <span class="meta-val">{scan_data.get('start_time','N/A')}</span></div>
    <div class="meta-row"><span class="meta-label">Finished</span>
      <span class="meta-val">{scan_data.get('end_time','N/A')}</span></div>
  </div>
</div>

<div class="card">
  <h2>Summary</h2>
  <div class="summary">
    <div class="stat">
      <div class="stat-num" style="color:var(--green)">{open_c}</div>
      <div class="stat-lbl">Open</div>
    </div>
    <div class="stat">
      <div class="stat-num" style="color:var(--red)">
        {sum(1 for p in ports if p['state']=='closed')}</div>
      <div class="stat-lbl">Closed</div>
    </div>
    <div class="stat">
      <div class="stat-num" style="color:var(--yellow)">
        {sum(1 for p in ports if p['state'] not in ('open','closed'))}</div>
      <div class="stat-lbl">Filtered</div>
    </div>
    <div class="stat">
      <div class="stat-num" style="color:var(--cyan)">{len(ports)}</div>
      <div class="stat-lbl">Total</div>
    </div>
  </div>
</div>

<div class="card">
  <h2>Port Details</h2>
  {"<p style='color:var(--dim)'>No ports found.</p>" if not ports else f'''
  <table>
    <thead>
      <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>'''}
</div>

<div class="footer">
  Generated by {TOOL_NAME} v{VERSION} — Use only on systems you own or are authorized to test.
</div>
</body>
</html>"""


# ─── History log ─────────────────────────────────────────────────────────────

def _append_history(scan_data: dict, filepath: str):
    """Append a one-line summary to the scan history CSV log."""
    log_file = os.path.join(LOGS_DIR, "scan_history.csv")
    is_new   = not os.path.exists(log_file)

    open_c = sum(1 for p in scan_data.get("ports", []) if p["state"] == "open")
    row = {
        "date":       scan_data.get("start_time", datetime.now().isoformat()),
        "target":     scan_data.get("host", ""),
        "hostname":   scan_data.get("hostname", ""),
        "status":     scan_data.get("state", ""),
        "mode":       scan_data.get("mode_name", ""),
        "open_ports": open_c,
        "duration_s": scan_data.get("duration_seconds", 0),
        "report":     filepath,
    }

    with open(log_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if is_new:
            writer.writeheader()
        writer.writerow(row)


# ─── Public API ──────────────────────────────────────────────────────────────

def save_report(scan_data: dict, fmt: str = "txt") -> str | None:
    """
    Save scan_data to a file in the given format.

    Supported formats: txt, json, xml, html
    Returns path to saved file, or None on failure.
    """
    _ensure_dirs()
    fmt      = fmt.lower().strip()
    ts       = _timestamp()
    host_tag = _host_safe(scan_data.get("host", "unknown"))
    filename = f"scan_{host_tag}_{ts}.{fmt}"
    filepath = os.path.join(REPORTS_DIR, filename)

    try:
        if fmt == "txt":
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(_build_txt(scan_data))

        elif fmt == "json":
            payload = {
                "meta": {
                    "tool":      f"{TOOL_NAME} v{VERSION}",
                    "generated": datetime.now().isoformat(),
                },
                "scan": scan_data,
            }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)

        elif fmt == "xml":
            ports = scan_data.get("ports", [])
            port_xml = "\n".join(
                f'      <port protocol="{p["proto"]}" portid="{p["port"]}">'
                f'<state state="{p["state"]}"/>'
                f'<service name="{p["service"]}" version="{p.get("version","")}"/>'
                f'</port>'
                for p in ports
            )
            xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<shadowport_scan>
  <meta>
    <tool>{TOOL_NAME} v{VERSION}</tool>
    <generated>{datetime.now().isoformat()}</generated>
  </meta>
  <host>
    <address addr="{scan_data.get('host','')}" addrtype="ipv4"/>
    <hostname>{scan_data.get('hostname','')}</hostname>
    <status state="{scan_data.get('state','')}"/>
    <scan_mode>{scan_data.get('mode_name','')}</scan_mode>
    <start_time>{scan_data.get('start_time','')}</start_time>
    <end_time>{scan_data.get('end_time','')}</end_time>
    <duration_seconds>{scan_data.get('duration_seconds',0)}</duration_seconds>
    <ports>
{port_xml}
    </ports>
  </host>
</shadowport_scan>
"""
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(xml)

        elif fmt == "html":
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(_build_html(scan_data))

        else:
            print_error(f"Unknown format '{fmt}'. Choose: txt, json, xml, html")
            return None

        print_success(f"Report saved  → {filepath}")

        # Append to history log regardless of format
        _append_history(scan_data, filepath)
        print_info(f"History log   → {os.path.join(LOGS_DIR, 'scan_history.csv')}")

        return filepath

    except OSError as exc:
        print_error(f"Could not write report: {exc}")
        return None


def prompt_save(scan_data: dict):
    """Interactively ask the user if they want to save and in which format."""
    print()
    try:
        choice = input("  Save results? (y/n): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if choice != "y":
        return

    print()
    print_info("Choose format:")
    print("    [1] TXT  — plain text report")
    print("    [2] JSON — machine-readable")
    print("    [3] XML  — structured markup")
    print("    [4] HTML — styled browser report  ← NEW in v1.2")
    print()

    try:
        fmt_choice = input("  Format (1/2/3/4) [default: 1]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    fmt_map = {"1": "txt", "2": "json", "3": "xml", "4": "html", "": "txt"}
    fmt = fmt_map.get(fmt_choice, "txt")
    save_report(scan_data, fmt)


def show_history():
    """Print the last 10 scans from the history log."""
    log_file = os.path.join(LOGS_DIR, "scan_history.csv")
    if not os.path.exists(log_file):
        print_warning("No scan history found yet.")
        return

    print_info("Recent scan history:\n")
    with open(log_file, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    recent = reader[-10:]
    for i, row in enumerate(reversed(recent), 1):
        print(
            f"  {i:2}. "
            f"\033[96m{row.get('date','?')}\033[0m  "
            f"\033[97m{row.get('target','?'):<18}\033[0m "
            f"\033[92m{row.get('mode','?'):<22}\033[0m "
            f"open: \033[92m{row.get('open_ports','?'):<4}\033[0m "
            f"{row.get('duration_s','?')}s"
        )
    print()
