"""
plugins/base.py — ShadowPort Scanner v1.3.0
Abstract base class every plugin must inherit from.
"""

from abc import ABC, abstractmethod


class BasePlugin(ABC):
    """
    All ShadowPort plugins inherit from BasePlugin.

    Required class attributes:
        name        (str)  — unique short identifier, e.g. "dns_lookup"
        description (str)  — one-line description shown in the plugin menu
        version     (str)  — plugin version string, e.g. "1.0"

    Required method:
        run(target: str, scan_data: dict) -> dict
            target    — the IP or hostname being investigated
            scan_data — the full scan result dict from scanner.run_scan()
            returns   — dict with at least {"output": str} for display
    """

    name:        str = "unnamed_plugin"
    description: str = "No description."
    version:     str = "1.0"

    @abstractmethod
    def run(self, target: str, scan_data: dict) -> dict:
        """Execute the plugin and return a result dict."""
        ...

    def __repr__(self) -> str:
        return f"<Plugin [{self.name}] v{self.version}: {self.description}>"
