"""
plugins/__init__.py — ShadowPort Scanner v2.1.0
Auto-discovery plugin loader using importlib.
Failed imports are skipped with a warning — never crash the app.
"""

import importlib
import inspect
import os

from plugins.base import BasePlugin


def load_plugins() -> dict:
    """
    Scan plugins/ directory for BasePlugin subclasses.
    Returns {plugin_name: plugin_instance}.
    """
    registry    = {}
    plugins_dir = os.path.dirname(__file__)

    for filename in sorted(os.listdir(plugins_dir)):
        if filename.startswith("_") or not filename.endswith(".py"):
            continue

        module_name = f"plugins.{filename[:-3]}"
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            print(f"  [!] Could not load plugin '{filename}': {exc}")
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                try:
                    instance = obj()
                    registry[instance.name] = instance
                except Exception as exc:
                    print(f"  [!] Could not instantiate '{obj.__name__}': {exc}")

    return registry
