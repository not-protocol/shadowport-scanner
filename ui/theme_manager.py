"""
ui/theme_manager.py

ThemeManager adds persistence around ShadowPortApp._apply_theme(), which
already exists in main.py and writes CSS variable values directly into
self.styles.__dict__. This file does NOT use Textual's built-in App.theme
attribute, because ShadowPort v2.3 never adopted that mechanism — it has
its own ui/themes.py THEMES dict of CSS-variable-name -> hex-value
mappings, applied by hand via _apply_theme().

This is the fix for the v2.3 "theme doesn't persist" bug: _apply_theme()
mutates self.styles.__dict__ for the current process only and never writes
the choice anywhere durable, so on next launch the app always starts on
DEFAULT_THEME from config/settings.py regardless of what was last picked.
ThemeManager wraps that same call with a read-on-startup / write-on-switch
layer backed by ConfigManager, without duplicating the CSS-mutation logic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ui.themes import THEMES, THEME_LABELS

if TYPE_CHECKING:
    from textual.app import App

    from config.config_manager import ConfigManager


class ThemeManager:
    """Applies and persists the active CSS-variable theme.

    Attributes:
        app: The running ShadowPortApp instance whose self.styles dict is
            being mutated (same target _apply_theme() already writes to).
        config: The ConfigManager used to persist the chosen theme key.
    """

    def __init__(self, app: "App", config: "ConfigManager") -> None:
        """Initialise the ThemeManager.

        Args:
            app: The Textual App instance (ShadowPortApp).
            config: A ConfigManager instance used to read/write the saved
                theme preference.
        """
        self.app = app
        self.config = config

    def _apply(self, theme_key: str, silent: bool = False) -> bool:
        """Apply a theme by delegating to ShadowPortApp._apply_theme().

        Deliberately delegates rather than reimplementing the CSS-variable
        mutation here, so there is exactly one place (main.py's existing
        _apply_theme) that knows how to paint a theme onto self.styles —
        this class only adds persistence around that single source of truth.

        Args:
            theme_key: One of the keys in ui.themes.THEMES
                (e.g. "cyber_green", "blue_team", "dark", "light").
            silent: If True, suppresses the "Theme: ..." toast — used for
                startup restoration, where popping a toast before the user
                has done anything would be noise, not feedback.

        Returns:
            True if theme_key was valid and applied, False otherwise.
        """
        if theme_key not in THEMES:
            return False
        self.app._apply_theme(theme_key, silent=silent)
        return True

    def apply_saved_theme(self) -> None:
        """Apply the theme stored in config to the running app.

        Intended to be called once from App.on_mount(), before the first
        paint, so the saved theme is visible from the very first frame
        rather than flashing the hardcoded default first. Applied silently
        — no toast — since this happens before the user has interacted
        with anything.

        Falls back to config.DEFAULTS["theme"] if the stored value isn't
        a valid key in ui.themes.THEMES, so a corrupted or hand-edited
        config file can never crash startup.
        """
        saved_theme = self.config.get("theme", self.config.DEFAULTS["theme"])
        if not self._apply(saved_theme, silent=True):
            self._apply(self.config.DEFAULTS["theme"], silent=True)

    def switch(self, theme_key: str) -> None:
        """Switch to a theme by key, persist the choice, and toast as usual.

        Args:
            theme_key: The already-stripped theme key, matching exactly
                what ShadowPortApp.on_button_pressed() extracts from a
                "theme-<key>" button id before calling _apply_theme()
                today (e.g. button id "theme-blue_team" -> "blue_team").

        Note:
            Invalid keys are silently ignored (no crash, no partial
            apply, nothing persisted) — same defensive behavior as the
            existing _apply_theme() in main.py, which also no-ops on an
            unrecognised key.
        """
        if not self._apply(theme_key, silent=False):
            return

        self.config.set("theme", theme_key)
        self.config.save()

    def label_for(self, theme_key: str) -> str:
        """Look up the human-readable label for a theme key.

        Args:
            theme_key: A key from ui.themes.THEMES.

        Returns:
            The matching entry from ui.themes.THEME_LABELS, or the raw
            key itself if no label is registered.
        """
        return THEME_LABELS.get(theme_key, theme_key)
