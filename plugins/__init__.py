# plugins package — auto-discovery loader

import importlib
import inspect
import os

from plugins.base import BasePlugin


def load_plugins() -> dict:
    from core.logger import log_error  # local import avoids any load-order issues

    registry    = {}
    plugins_dir = os.path.dirname(__file__)
    for fname in sorted(os.listdir(plugins_dir)):
        if fname.startswith("_") or not fname.endswith(".py"):
            continue
        module_name = f"plugins.{fname[:-3]}"
        try:
            module = importlib.import_module(module_name)
        except Exception as e:
            print(f"  [!] Plugin load failed '{fname}': {e}")
            log_error("plugin_loader", fname, f"Plugin module import failed: {e}", e)
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                try:
                    inst = obj()
                    registry[inst.name] = inst
                except Exception as e:
                    print(f"  [!] Plugin instantiate failed '{obj.__name__}': {e}")
                    log_error("plugin_loader", obj.__name__, f"Plugin instantiate failed: {e}", e)
    return registry
