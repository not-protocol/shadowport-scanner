"""plugins/banner_grabber.py — ShadowPort Scanner v2.3.0"""

import socket
from plugins.base import BasePlugin


class BannerGrabberPlugin(BasePlugin):
    name        = "banner_grabber"
    description = "Grab TCP service banners from open ports"
    version     = "1.1"
    TIMEOUT     = 5
    CAP         = 10

    def run(self, target: str, scan_data: dict) -> dict:
        open_ports = [
            int(p["port"]) for p in scan_data.get("ports", [])
            if p.get("state") == "open" and p.get("proto") == "tcp"
        ]
        if not open_ports:
            return {"output": "  No open TCP ports."}
        lines = [f"  Grabbing {min(len(open_ports),self.CAP)} port(s)…\n"]
        for port in open_ports[:self.CAP]:
            banner = self._grab(target, port)
            lines.append(f"  {port}/tcp → {banner[:120] if banner else '(no banner)'}")
        return {"output": "\n".join(lines)}

    def _grab(self, host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=self.TIMEOUT) as s:
                s.sendall(b"\r\n")
                data = s.recv(1024)
                return data.decode("utf-8", errors="replace").strip().split("\n")[0]
        except Exception:
            return ""
