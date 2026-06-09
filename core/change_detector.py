"""
core/change_detector.py — ShadowPort Scanner v2.1.0

Compares two scans by pulling normalised port records from the SQLite
ports table. Returns a structured ChangeReport.
"""

from dataclasses import dataclass, field
from typing import Optional

from db.database import get_scan_by_id, get_ports_for_scan


@dataclass
class PortRecord:
    port:     str
    protocol: str
    service:  str
    state:    str
    banner:   str


@dataclass
class ChangeReport:
    scan_id_old:      int
    scan_id_new:      int
    target:           str

    new_ports:         list[PortRecord] = field(default_factory=list)
    closed_ports:      list[PortRecord] = field(default_factory=list)
    new_services:      list[str]        = field(default_factory=list)
    removed_services:  list[str]        = field(default_factory=list)
    unchanged_ports:   list[PortRecord] = field(default_factory=list)

    error: Optional[str] = None

    @property
    def has_changes(self) -> bool:
        return bool(self.new_ports or self.closed_ports)

    def summary(self) -> str:
        if self.error:
            return f"Error: {self.error}"
        parts = []
        if self.new_ports:
            ports_str = ", ".join(f"{p.port}/{p.protocol}" for p in self.new_ports)
            parts.append(f"New: {ports_str}")
        if self.closed_ports:
            ports_str = ", ".join(f"{p.port}/{p.protocol}" for p in self.closed_ports)
            parts.append(f"Closed: {ports_str}")
        if not parts:
            return "No port changes detected."
        return " | ".join(parts)


def _port_key(p: dict) -> str:
    return f"{p['port']}/{p['protocol']}"


def compare_scans(scan_id_old: int, scan_id_new: int) -> ChangeReport:
    """
    Compare two scans by id using the normalised ports table.

    Returns a ChangeReport with:
      - new_ports:        open in new, not in old
      - closed_ports:     open in old, not in new
      - new_services:     services appearing in new scan
      - removed_services: services disappearing from old scan
      - unchanged_ports:  open in both
    """
    scan_old = get_scan_by_id(scan_id_old)
    scan_new = get_scan_by_id(scan_id_new)

    if not scan_old:
        return ChangeReport(scan_id_old, scan_id_new, "", error=f"Scan {scan_id_old} not found")
    if not scan_new:
        return ChangeReport(scan_id_old, scan_id_new, "", error=f"Scan {scan_id_new} not found")

    target = scan_new.get("target", "")

    old_rows = get_ports_for_scan(scan_id_old)
    new_rows = get_ports_for_scan(scan_id_new)

    old_open = {
        _port_key(p): PortRecord(
            port=p["port"], protocol=p["protocol"],
            service=p["service"], state=p["state"], banner=p["banner"]
        )
        for p in old_rows if p["state"] == "open"
    }

    new_open = {
        _port_key(p): PortRecord(
            port=p["port"], protocol=p["protocol"],
            service=p["service"], state=p["state"], banner=p["banner"]
        )
        for p in new_rows if p["state"] == "open"
    }

    old_keys = set(old_open.keys())
    new_keys = set(new_open.keys())

    new_ports      = [new_open[k] for k in sorted(new_keys - old_keys)]
    closed_ports   = [old_open[k] for k in sorted(old_keys - new_keys)]
    unchanged      = [new_open[k] for k in sorted(new_keys & old_keys)]

    old_services = {p.service for p in old_open.values() if p.service}
    new_services = {p.service for p in new_open.values() if p.service}

    return ChangeReport(
        scan_id_old=scan_id_old,
        scan_id_new=scan_id_new,
        target=target,
        new_ports=new_ports,
        closed_ports=closed_ports,
        unchanged_ports=unchanged,
        new_services=sorted(new_services - old_services),
        removed_services=sorted(old_services - new_services),
    )


def format_change_report(report: ChangeReport) -> str:
    """Format a ChangeReport as a terminal-printable string."""
    if report.error:
        return f"[ERROR] {report.error}"

    sep  = "─" * 60
    lines = [
        sep,
        f"  Change Detection: {report.target}",
        f"  Comparing scan #{report.scan_id_old} → #{report.scan_id_new}",
        sep,
    ]

    if report.new_ports:
        lines.append("  ✚ New open ports:")
        for p in report.new_ports:
            svc = f" ({p.service})" if p.service else ""
            lines.append(f"      → {p.port}/{p.protocol}{svc}")

    if report.closed_ports:
        lines.append("  ✖ Ports now closed:")
        for p in report.closed_ports:
            svc = f" ({p.service})" if p.service else ""
            lines.append(f"      → {p.port}/{p.protocol}{svc}")

    if report.new_services:
        lines.append(f"  ✚ New services: {', '.join(report.new_services)}")

    if report.removed_services:
        lines.append(f"  ✖ Removed services: {', '.join(report.removed_services)}")

    if report.unchanged_ports:
        keys = ", ".join(f"{p.port}/{p.protocol}" for p in report.unchanged_ports)
        lines.append(f"  ═ Unchanged: {keys}")

    if not report.has_changes:
        lines.append("  No changes detected between scans.")

    lines.append(sep)
    return "\n".join(lines)
