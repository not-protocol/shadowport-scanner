"""
reports.py — ShadowPort Scanner v2.3.0
Export scan results: TXT, JSON, XML, HTML.
Every saved report is logged to SQLite + JSON history.
Never crashes — all exceptions caught and logged.
"""

import json
import os
import stat
from datetime import datetime

from config.settings import REPORTS_DIR, LOG_DIR, TOOL_NAME, VERSION
from core.logger import log_error
from core.json_history import record_report
from db.database import log_report as db_log_report


# ── Directory setup ───────────────────────────────────────────────────────────

def _ensure_dirs():
    for d in (REPORTS_DIR, LOG_DIR):
        os.makedirs(d, exist_ok=True)
        try:
            mode = os.stat(d).st_mode
            os.chmod(d, mode | stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
        except PermissionError:
            pass


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _safe_host(host: str) -> str:
    return host.replace(".", "-").replace(":", "-").replace("/", "-")


# ── TXT ───────────────────────────────────────────────────────────────────────

def _build_txt(scan_data: dict) -> str:
    sep  = "═" * 64
    sep2 = "─" * 64
    risk    = scan_data.get("risk", {})
    partial = scan_data.get("partial", False)

    lines = [
        sep,
        f"  {TOOL_NAME} v{VERSION} — Scan Report",
        f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        sep,
        f"  Target     : {scan_data.get('host', 'N/A')}",
    ]
    if scan_data.get("hostname"):
        lines.append(f"  Hostname   : {scan_data['hostname']}")
    lines += [
        f"  Status     : {scan_data.get('state', 'unknown').upper()}",
        f"  Scan Mode  : {scan_data.get('mode_name', 'N/A')}",
        f"  Started    : {scan_data.get('start_time', 'N/A')}",
        f"  Finished   : {scan_data.get('end_time', 'N/A')}",
        f"  Duration   : {scan_data.get('duration_seconds', 0):.1f}s",
    ]
    if partial:
        lines.append("  NOTE       : ⚠ Partial results — scan interrupted by timeout.")
    if scan_data.get("os_matches"):
        lines.append(f"  OS Match   : {scan_data['os_matches'][0]}")
    if risk:
        lines.append(f"  Risk Score : {risk.get('score', 0)}/100  [{risk.get('label', '')}]")
    lines += [sep, ""]

    ports = scan_data.get("ports", [])
    if not ports:
        lines.append("  No open ports discovered.")
        lines.append("  Host may be filtered, offline, or blocking probes.")
    else:
        col_p, col_s, col_sv, col_v = 14, 12, 20, 30
        lines.append(
            "  " + "PORT".ljust(col_p) + "STATE".ljust(col_s)
            + "SERVICE".ljust(col_sv) + "VERSION"
        )
        lines.append("  " + sep2)
        for p in ports:
            lines.append(
                "  "
                + f"{p['port']}/{p.get('proto','tcp')}".ljust(col_p)
                + p.get("state", "").ljust(col_s)
                + p.get("service", "").ljust(col_sv)
                + p.get("version", "")[:col_v]
            )
            intel = p.get("intel")
            if intel and p.get("state") == "open":
                lines.append(f"       Use : {intel.get('use', '')}")
                lines.append(f"       Risk: {intel.get('risk', '')}")
        lines.append("  " + sep2)
        open_c = sum(1 for p in ports if p.get("state") == "open")
        lines += [f"\n  Open ports : {open_c}", f"  Total      : {len(ports)}"]

        if risk.get("breakdown"):
            lines += ["", "  Risk Breakdown:"]
            for b in risk["breakdown"]:
                lines.append(f"    {b}")

    lines += ["", sep, f"  {TOOL_NAME} — Use only on authorized systems.", sep]
    return "\n".join(lines)


# ── HTML ──────────────────────────────────────────────────────────────────────

def _build_html(scan_data: dict) -> str:
    host       = scan_data.get("host", "N/A")
    hostname   = scan_data.get("hostname", "")
    state      = scan_data.get("state", "unknown")
    ports      = scan_data.get("ports", [])
    os_match   = (scan_data.get("os_matches") or ["N/A"])[0]
    risk       = scan_data.get("risk", {})
    partial    = scan_data.get("partial", False)
    open_c     = sum(1 for p in ports if p.get("state") == "open")
    closed_c   = sum(1 for p in ports if p.get("state") == "closed")
    filt_c     = sum(1 for p in ports if p.get("state") not in ("open", "closed"))
    score      = risk.get("score", 0)
    risk_label = risk.get("label", "N/A")
    risk_color = "#ff4455" if score >= 70 else "#ffcc00" if score >= 40 else "#00ff88"

    rows = ""
    for p in ports:
        sc = (
            "#00ff88" if p.get("state") == "open"   else
            "#ff4455" if p.get("state") == "closed"  else
            "#ffcc00"
        )
        intel     = p.get("intel") or {}
        intel_row = ""
        if p.get("state") == "open" and intel:
            intel_row = (
                f"<tr class='intel-row'><td colspan='2'></td><td colspan='2'>"
                f"<span class='intel-use'>📋 {intel.get('use','')}</span><br>"
                f"<span class='intel-risk'>⚠ {intel.get('risk','')}</span>"
                f"</td></tr>"
            )
        rows += (
            f"<tr>"
            f"<td><b>{p['port']}/{p.get('proto','tcp')}</b></td>"
            f"<td style='color:{sc}'>{p.get('state','')}</td>"
            f"<td>{p.get('service','')}</td>"
            f"<td>{p.get('version','')}</td>"
            f"</tr>{intel_row}\n"
        )

    breakdown_html = "".join(f"<li>{b}</li>" for b in risk.get("breakdown", []))
    partial_banner = (
        "<div class='partial-banner'>⚠ Partial results — "
        "scan was interrupted by timeout.</div>"
        if partial else ""
    )
    no_ports_html = (
        "<div class='no-ports'>No open ports discovered.<br>"
        "<span class='dim'>Host may be filtered, offline, or blocking probes.</span></div>"
        if not ports else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ShadowPort — {host}</title>
<style>
  :root {{
    --bg:#0a0e1a; --panel:#111827; --border:#1e3a5f;
    --green:#00ff88; --cyan:#00cfff; --yellow:#ffcc00;
    --red:#ff4455; --text:#c9d1e0; --dim:#607090;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;padding:2rem}}
  h1{{color:var(--red);font-size:1.7rem;letter-spacing:3px;text-transform:uppercase;margin-bottom:.3rem}}
  .sub{{color:var(--cyan);font-size:.85rem;margin-bottom:2rem}}
  .card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;
         padding:1.5rem;margin-bottom:1.5rem}}
  .card h2{{color:var(--cyan);font-size:.9rem;letter-spacing:2px;text-transform:uppercase;
            margin-bottom:1rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}}
  .meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:.5rem}}
  .meta-row{{display:flex;gap:1rem}}
  .meta-label{{color:var(--dim);min-width:120px}}
  .meta-val{{color:var(--text);font-weight:bold}}
  .summary{{display:flex;gap:2rem;flex-wrap:wrap}}
  .stat{{text-align:center;min-width:80px}}
  .stat-num{{font-size:2rem;font-weight:bold}}
  .stat-lbl{{font-size:.75rem;color:var(--dim);text-transform:uppercase}}
  .risk-bar-bg{{background:#1a2740;border-radius:4px;height:18px;margin-top:1rem}}
  .risk-bar-fill{{height:18px;border-radius:4px}}
  table{{width:100%;border-collapse:collapse;font-size:.88rem}}
  th{{background:#0d1929;color:var(--cyan);padding:.6rem .8rem;text-align:left;
      letter-spacing:1px;text-transform:uppercase}}
  td{{padding:.5rem .8rem;border-bottom:1px solid #1a2740}}
  tr:hover td{{background:#151f35}}
  .intel-row td{{padding:.2rem .8rem .6rem 2rem;background:#0d1929}}
  .intel-use{{color:var(--cyan);font-size:.8rem}}
  .intel-risk{{color:var(--yellow);font-size:.8rem}}
  .breakdown{{margin-top:.5rem;padding-left:1.2rem}}
  .breakdown li{{color:var(--yellow);font-size:.85rem;margin:.2rem 0}}
  .partial-banner{{background:#332200;border:1px solid var(--yellow);border-radius:6px;
                   padding:.7rem 1rem;margin-bottom:1rem;color:var(--yellow);font-size:.85rem}}
  .no-ports{{color:var(--yellow);padding:1rem}}
  .dim{{color:var(--dim);font-size:.85rem}}
  .footer{{color:var(--dim);font-size:.75rem;text-align:center;margin-top:2rem}}
</style>
</head>
<body>
<h1>⚡ ShadowPort Scanner</h1>
<div class="sub">v{VERSION} — Network Reconnaissance &amp; Port Analysis | {TOOL_NAME}</div>

{partial_banner}

<div class="card">
  <h2>Host Information</h2>
  <div class="meta-grid">
    <div class="meta-row"><span class="meta-label">Target</span>
      <span class="meta-val">{host}</span></div>
    <div class="meta-row"><span class="meta-label">Hostname</span>
      <span class="meta-val">{hostname or '—'}</span></div>
    <div class="meta-row"><span class="meta-label">Status</span>
      <span class="meta-val" style="color:{'var(--green)' if state=='up' else 'var(--red)'}">{state.upper()}</span></div>
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
  <h2>Port Summary</h2>
  <div class="summary">
    <div class="stat"><div class="stat-num" style="color:var(--green)">{open_c}</div>
      <div class="stat-lbl">Open</div></div>
    <div class="stat"><div class="stat-num" style="color:var(--red)">{closed_c}</div>
      <div class="stat-lbl">Closed</div></div>
    <div class="stat"><div class="stat-num" style="color:var(--yellow)">{filt_c}</div>
      <div class="stat-lbl">Filtered</div></div>
    <div class="stat"><div class="stat-num" style="color:var(--cyan)">{len(ports)}</div>
      <div class="stat-lbl">Total</div></div>
  </div>
</div>

<div class="card">
  <h2>Risk Assessment</h2>
  <div class="meta-row">
    <span class="meta-label">Score</span>
    <span class="meta-val" style="color:{risk_color}">{score}/100 — {risk_label}</span>
  </div>
  <div class="risk-bar-bg">
    <div class="risk-bar-fill" style="width:{score}%;background:{risk_color}"></div>
  </div>
  {"<ul class='breakdown'>" + breakdown_html + "</ul>" if breakdown_html else ""}
  <p style="color:var(--dim);font-size:.75rem;margin-top:.8rem">
    ℹ Informational only. Not a vulnerability assessment.
  </p>
</div>

<div class="card">
  <h2>Port Details</h2>
  {no_ports_html if not ports else f"""
  <table>
    <thead>
      <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>"""}
</div>

<div class="footer">
  Generated by {TOOL_NAME} v{VERSION}
  at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  — Use only on systems you own or are authorized to test.
</div>
</body>
</html>"""


# ── Public API ────────────────────────────────────────────────────────────────

def save_report(scan_data: dict, fmt: str = "txt",
                scan_id: int = None) -> str | None:
    """
    Save scan in requested format.
    Logs result to SQLite reports_log and JSON history.
    Returns filepath or None on failure.
    """
    try:
        _ensure_dirs()
    except Exception as exc:
        log_error("reports", scan_data.get("host",""), str(exc), exc)
        return None

    fmt      = fmt.lower().strip()
    host_tag = _safe_host(scan_data.get("host", "unknown"))
    filename = f"scan_{host_tag}_{_ts()}.{fmt}"
    filepath = os.path.join(REPORTS_DIR, filename)
    target   = scan_data.get("host","")

    try:
        if fmt == "txt":
            content = _build_txt(scan_data)

        elif fmt == "json":
            content = json.dumps({
                "meta": {
                    "tool":      f"{TOOL_NAME} v{VERSION}",
                    "generated": datetime.now().isoformat(),
                    "partial":   scan_data.get("partial", False),
                    "version":   VERSION,
                },
                "scan": scan_data,
            }, indent=2)

        elif fmt == "xml":
            ports    = scan_data.get("ports", [])
            port_xml = "\n".join(
                f'      <port protocol="{p.get("proto","tcp")}" portid="{p["port"]}">'
                f'<state state="{p.get("state","")}"/>'
                f'<service name="{p.get("service","")}" version="{p.get("version","")}" />'
                f'</port>'
                for p in ports
            )
            risk    = scan_data.get("risk", {})
            partial = str(scan_data.get("partial", False)).lower()
            content = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<shadowport_scan version="{VERSION}" partial="{partial}">\n'
                f'  <meta>\n'
                f'    <tool>{TOOL_NAME} v{VERSION}</tool>\n'
                f'    <generated>{datetime.now().isoformat()}</generated>\n'
                f'  </meta>\n'
                f'  <host>\n'
                f'    <address addr="{scan_data.get("host","")}" addrtype="ipv4"/>\n'
                f'    <hostname>{scan_data.get("hostname","")}</hostname>\n'
                f'    <status state="{scan_data.get("state","")}" />\n'
                f'    <scan_mode>{scan_data.get("mode_name","")}</scan_mode>\n'
                f'    <start_time>{scan_data.get("start_time","")}</start_time>\n'
                f'    <end_time>{scan_data.get("end_time","")}</end_time>\n'
                f'    <duration_seconds>{scan_data.get("duration_seconds",0)}</duration_seconds>\n'
                f'    <risk score="{risk.get("score",0)}" label="{risk.get("label","")}"/>\n'
                f'    <ports>\n{port_xml}\n    </ports>\n'
                f'  </host>\n'
                f'</shadowport_scan>\n'
            )

        elif fmt == "html":
            content = _build_html(scan_data)

        else:
            log_error("reports", target, f"Unknown format: {fmt}")
            return None

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        try:
            os.chmod(filepath, 0o644)
        except PermissionError:
            pass

        # Log to SQLite
        try:
            db_log_report(scan_id, target, fmt, filepath, success=True)
        except Exception as exc:
            log_error("reports", target, f"DB report log failed: {exc}", exc)

        # Log to JSON history
        try:
            record_report(target, fmt, filepath)
        except Exception as exc:
            log_error("reports", target, f"JSON report log failed: {exc}", exc)

        return filepath

    except PermissionError as exc:
        log_error("reports", target, str(exc), exc)
        try:
            db_log_report(scan_id, target, fmt, "", success=False)
        except Exception:
            pass
        return None

    except Exception as exc:
        log_error("reports", target, str(exc), exc)
        return None
