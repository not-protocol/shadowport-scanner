"""
plugins/banner_grabber.py — ShadowPort Scanner v1.3.0
Built-in plugin: grab service banners from open TCP ports.
"""

import socket
from plugins.base import BasePlugin


class BannerGrabberPlugin(BasePlugin):
    name        = "banner_grabber"
    description = "Grab service banners from open TCP ports"
    version     = "1.0"

    TIMEOUT = 3  # seconds per port

    def run(self, target: str, scan_data: dict) -> dict:
        open_ports = [
            int(p["port"]) for p in scan_data.get("ports", [])
            if p["state"] == "open" and p["proto"] == "tcp"
        ]

        if not open_ports:
            return {"output": "  No open TCP ports to grab banners from."}

        lines = [f"  Grabbing banners from {len(open_ports)} open port(s)...\n"]
        for port in open_ports[:10]:   # cap at 10 to avoid long waits
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
