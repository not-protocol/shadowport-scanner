"""
plugins/dns_lookup.py — ShadowPort Scanner v1.3.0
Built-in plugin: DNS record lookup for a target hostname or IP.
"""

import socket
from plugins.base import BasePlugin


class DnsLookupPlugin(BasePlugin):
    name        = "dns_lookup"
    description = "Resolve hostname → IP and reverse-lookup IP → hostname"
    version     = "1.0"

    def run(self, target: str, scan_data: dict) -> dict:
        lines = []
        try:
            ip = socket.gethostbyname(target)
            lines.append(f"  Forward lookup : {target} → {ip}")
        except socket.gaierror as e:
            lines.append(f"  Forward lookup : FAILED ({e})")
            ip = target

        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            lines.append(f"  Reverse lookup : {ip} → {hostname}")
            if aliases:
                lines.append(f"  Aliases        : {', '.join(aliases)}")
        except socket.herror:
            lines.append(f"  Reverse lookup : No PTR record found")

        try:
            info = socket.getaddrinfo(target, None)
            families = {i[0].name for i in info}
            lines.append(f"  Address family : {', '.join(sorted(families))}")
        except Exception:
            pass

        return {"output": "\n".join(lines)}
