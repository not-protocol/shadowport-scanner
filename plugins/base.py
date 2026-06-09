"""
plugins/base.py — ShadowPort Scanner v2.1.0
Abstract base class every plugin must inherit from.
"""

from abc import ABC, abstractmethod


class BasePlugin(ABC):
    name:        str = "unnamed_plugin"
    description: str = "No description."
    version:     str = "1.0"

    @abstractmethod
    def run(self, target: str, scan_data: dict) -> dict:
        """
        Execute the plugin.
        Returns dict with at least {"output": str}.
        """
        ...

    def __repr__(self) -> str:
        return f"<Plugin [{self.name}] v{self.version}: {self.description}>"
