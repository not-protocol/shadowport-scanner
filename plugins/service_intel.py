"""plugins/service_intel.py — ShadowPort Scanner v2.3.0"""

from plugins.base import BasePlugin
from config.settings import SERVICE_INTEL


class ServiceIntelPlugin(BasePlugin):
    name        = "service_intel"
    description = "Show security intel for every open port"
    version     = "1.0"

    RISK_ICON = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}

    def run(self, target: str, scan_data: dict) -> dict:
        open_ports = [p for p in scan_data.get("ports",[]) if p.get("state")=="open"]
        if not open_ports:
            return {"output": "  No open ports to analyse."}
        lines = [f"  Service Intelligence — {target}\n"]
        sep   = "  " + "─" * 58
        for p in open_ports:
            svc   = p.get("service","").lower()
            intel = SERVICE_INTEL.get(svc) or SERVICE_INTEL.get("unknown")
            lines.append(sep)
            lines.append(f"  {p['port']}/{p.get('proto','tcp')}  {svc.upper()}")
            lines.append(f"  Use  : {intel.get('use','')}")
            lines.append(f"  Risk : {intel.get('risk','')}")
        lines.append(sep)
        return {"output": "\n".join(lines)}
