"""
plugins/banner_grabber.py — ShadowPort Scanner v2.1.0
Built-in plugin: TCP service banner grabbing.
Max 5s per host as per production checklist requirement.
Caps at 10 ports to avoid long waits on full scans.
"""

import socket

from plugins.base import BasePlugin


class BannerGrabberPlugin(BasePlugin):
    name        = "banner_grabber"
    description = "Grab service banners from open TCP ports"
    version     = "1.1"

    TIMEOUT   = 5   # max 5s per host (production checklist requirement)
    PORT_CAP  = 10  # max ports to attempt per scan

    def run(self, target: str, scan_data: dict) -> dict:
        open_ports = [
            int(p["port"])
            for p in scan_data.get("ports", [])
            if p.get("state") == "open" and p.get("proto") == "tcp"
        ]

        if not open_ports:
            return {"output": "  No open TCP ports to grab banners from."}

        capped = open_ports[: self.PORT_CAP]
        lines  = [
            f"  Grabbing banners from {len(capped)} port(s)"
            f" (capped at {self.PORT_CAP})…\n"
        ]

        for port in capped:
            banner = self._grab(target, port)
            if banner:
                lines.append(f"  {port}/tcp  →  {banner[:120]}")
            else:
                lines.append(f"  {port}/tcp  →  (no banner)")

        return {"output": "\n".join(lines)}

    def _grab(self, host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=self.TIMEOUT) as s:
                s.sendall(b"\r\n")
                data = s.recv(1024)
                return data.decode("utf-8", errors="replace").strip().split("\n")[0]
        except Exception:
            return ""
