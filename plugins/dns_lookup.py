"""
plugins/dns_lookup.py — ShadowPort Scanner v2.1.0
Built-in plugin: DNS forward and reverse lookup for a target.
"""

import socket

from plugins.base import BasePlugin


class DnsLookupPlugin(BasePlugin):
    name        = "dns_lookup"
    description = "Resolve hostname → IP and reverse-lookup IP → hostname"
    version     = "1.1"

    def run(self, target: str, scan_data: dict) -> dict:
        lines = []

        # Forward lookup
        try:
            ip = socket.gethostbyname(target)
            lines.append(f"  Forward lookup : {target} → {ip}")
        except socket.gaierror as exc:
            lines.append(f"  Forward lookup : FAILED ({exc})")
            ip = target

        # Reverse lookup
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            lines.append(f"  Reverse lookup : {ip} → {hostname}")
            if aliases:
                lines.append(f"  Aliases        : {', '.join(aliases)}")
        except socket.herror:
            lines.append("  Reverse lookup : No PTR record found")

        # Address family
        try:
            info     = socket.getaddrinfo(target, None)
            families = {i[0].name for i in info}
            lines.append(f"  Address family : {', '.join(sorted(families))}")
        except Exception:
            pass

        return {"output": "\n".join(lines)}
