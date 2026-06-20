"""plugins/dns_lookup.py — ShadowPort Scanner v2.3.0"""

import socket
from plugins.base import BasePlugin


class DnsLookupPlugin(BasePlugin):
    name        = "dns_lookup"
    description = "DNS forward + reverse lookup for the target"
    version     = "1.1"

    def run(self, target: str, scan_data: dict) -> dict:
        lines = []
        try:
            ip = socket.gethostbyname(target)
            lines.append(f"  Forward : {target} → {ip}")
        except socket.gaierror as e:
            lines.append(f"  Forward : FAILED ({e})")
            ip = target
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            lines.append(f"  Reverse : {ip} → {hostname}")
            if aliases:
                lines.append(f"  Aliases : {', '.join(aliases)}")
        except socket.herror:
            lines.append("  Reverse : No PTR record")
        try:
            info     = socket.getaddrinfo(target, None)
            families = {i[0].name for i in info}
            lines.append(f"  Family  : {', '.join(sorted(families))}")
        except Exception:
            pass
        return {"output": "\n".join(lines)}
