"""
config/config_manager.py

ConfigManager persists user preferences (active theme, capture defaults) to
a JSON file at ~/.shadowport/config.json. Writes are atomic (tmp file +
os.replace) so a crash mid-write can never corrupt the config on disk.

This is the fix for the v2.3 "theme doesn't persist" bug: previously
nothing wrote the user's theme choice anywhere durable.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from config.settings import (
    DEFAULT_THEME,
    DEFAULT_CAPTURE_INTERFACE,
    DEFAULT_CAPTURE_FILTER,
    DEFAULT_CAPTURE_DURATION,
)


class ConfigManager:
    """Loads, holds, and atomically persists ShadowPort user configuration.

    Attributes:
        CONFIG_PATH: Location of the JSON config file
            (~/.shadowport/config.json).
        DEFAULTS: Default values used when a key is missing or the config
            file does not yet exist / is corrupted. Sourced from
            config/settings.py so there is exactly one place that defines
            "what theme/capture settings ship by default" — this class
            never invents its own copy of those values.
    """

    CONFIG_PATH = Path.home() / ".shadowport" / "config.json"

    DEFAULTS: dict[str, Any] = {
        "theme": DEFAULT_THEME,
        "capture_interface": DEFAULT_CAPTURE_INTERFACE,
        "capture_filter": DEFAULT_CAPTURE_FILTER,
        "capture_duration": DEFAULT_CAPTURE_DURATION,
    }

    def __init__(self) -> None:
        """Initialise the manager and load existing config (or defaults)."""
        self._data: dict[str, Any] = {}
        self.load()

    def load(self) -> dict:
        """Load configuration from disk, creating it if missing.

        If the config file does not exist, it is created with DEFAULTS.
        If it exists but contains invalid JSON, it is treated as corrupt:
        the error is swallowed and DEFAULTS are used instead (and written
        back out), rather than crashing the app on startup.

        Returns:
            The loaded configuration dict, merged with DEFAULTS so any
            keys missing from an older config file are filled in.
        """
        if not self.CONFIG_PATH.exists():
            self._data = dict(self.DEFAULTS)
            self.save()
            return dict(self._data)

        try:
            raw_text = self.CONFIG_PATH.read_text(encoding="utf-8")
            loaded = json.loads(raw_text)
            if not isinstance(loaded, dict):
                raise ValueError("config.json did not contain a JSON object")
        except (json.JSONDecodeError, ValueError, OSError):
            # Corrupt or unreadable config — reset to safe defaults rather
            # than propagate the error up into app startup.
            self._data = dict(self.DEFAULTS)
            self.save()
            return dict(self._data)

        merged = dict(self.DEFAULTS)
        merged.update(loaded)
        self._data = merged
        return dict(self._data)

    def save(self) -> None:
        """Atomically write the current configuration to disk.

        Ensures the parent directory (~/.shadowport/) exists, writes to a
        temporary file in the same directory, then uses os.replace() to
        atomically move it into place. This guarantees config.json is
        never left half-written if the process is interrupted mid-save.
        """
        self.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(
            dir=str(self.CONFIG_PATH.parent),
            prefix="config.json.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                json.dump(self._data, tmp_file, indent=2, sort_keys=True)
                tmp_file.write("\n")
            os.replace(tmp_path, self.CONFIG_PATH)
        except Exception:
            # Clean up the temp file if the atomic replace never happened.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def get(self, key: str, default: Any = None) -> Any:
        """Fetch a configuration value.

        Args:
            key: Configuration key to read.
            default: Value to return if the key is absent.

        Returns:
            The stored value, or `default` if the key does not exist.
        """
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value in memory (does not persist on its own).

        Args:
            key: Configuration key to set.
            value: New value for the key.

        Note:
            Call save() afterwards to persist the change to disk. Callers
            that change multiple keys together should call set() for each
            and save() once at the end.
        """
        self._data[key] = value
