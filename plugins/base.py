"""plugins/base.py — ShadowPort Scanner v2.3.0"""

from abc import ABC, abstractmethod


class BasePlugin(ABC):
    name:        str = "unnamed_plugin"
    description: str = "No description."
    version:     str = "1.0"

    @abstractmethod
    def run(self, target: str, scan_data: dict) -> dict:
        """Execute plugin. Returns {'output': str}."""
        ...

    def __repr__(self) -> str:
        return f"<Plugin [{self.name}] v{self.version}>"
