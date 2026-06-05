"""
plugins/__init__.py — ShadowPort Scanner v2.0.0
Auto-discovery plugin loader.
"""

import importlib
import inspect
import os

from plugins.base import BasePlugin


def load_plugins() -> dict:
    """
    Scan the plugins/ directory for BasePlugin subclasses.
    Returns {plugin_name: plugin_instance}.
    Skips files that fail to import — never crashes.
    """
    registry    = {}
    plugins_dir = os.path.dirname(__file__)

    for filename in sorted(os.listdir(plugins_dir)):
        if filename.startswith("_") or not filename.endswith(".py"):
            continue

        module_name = f"plugins.{filename[:-3]}"
        try:
            module = importlib.import_module(module_name)
        except Exception as e:
            print(f"  [!] Could not load plugin '{filename}': {e}")
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                try:
                    instance = obj()
                    registry[instance.name] = instance
                except Exception as e:
                    print(f"  [!] Could not instantiate '{obj.__name__}': {e}")

    return registry
