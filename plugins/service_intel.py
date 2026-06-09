"""
plugins/service_intel.py — ShadowPort Scanner v2.1.0
Built-in plugin: shows Service Knowledge Base info for each open port.
Integrates core/service_kb.py into the plugin system.
"""

from plugins.base import BasePlugin
from core.service_kb import get_service_info


class ServiceIntelPlugin(BasePlugin):
    name        = "service_intel"
    description = "Show Service Knowledge Base details for every open port"
    version     = "1.0"

    def run(self, target: str, scan_data: dict) -> dict:
        open_ports = [
            p for p in scan_data.get("ports", [])
            if p.get("state") == "open"
        ]

        if not open_ports:
            return {"output": "  No open ports to analyse."}

        lines = [f"  Service Intelligence for {target}\n"]
        sep   = "  " + "─" * 58

        for p in open_ports:
            try:
                port_num = int(p["port"])
            except (ValueError, KeyError):
                continue

            info = get_service_info(port_num)
            risk_tag = {
                "critical": "🔴 CRITICAL",
                "high":     "🟠 HIGH",
                "medium":   "🟡 MEDIUM",
                "low":      "🟢 LOW",
            }.get(info.risk_level, info.risk_level.upper())

            lines.append(sep)
            lines.append(
                f"  Port {p['port']}/{p.get('proto','tcp')}"
                f"  {info.name}"
                f"  [{risk_tag}]"
            )
            lines.append(f"  Purpose     : {info.purpose}")
            lines.append(f"  Common uses : {', '.join(info.common_uses)}")
            lines.append(f"  Notes       : {info.security_notes}")

        lines.append(sep)
        return {"output": "\n".join(lines)}
