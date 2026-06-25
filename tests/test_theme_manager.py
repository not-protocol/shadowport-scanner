"""tests/test_theme_manager.py — ShadowPort Scanner v2.4.0"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from ui.theme_manager import ThemeManager
from ui.themes import THEMES


class _FakeStyles:
    def __init__(self):
        self.__dict__.clear()


class _FakeApp:
    """Stand-in for ShadowPortApp exposing the real _apply_theme contract.

    Mirrors main.py's ShadowPortApp._apply_theme(theme_key, silent=False)
    exactly: writes CSS vars into self.styles.__dict__, toasts unless
    silent. ThemeManager delegates to this method rather than reimplementing
    the mutation, so the fake must implement the same signature for these
    tests to mean anything.
    """

    def __init__(self):
        self.styles = _FakeStyles()
        self.toasts = []

    def _apply_theme(self, theme_key: str, silent: bool = False) -> None:
        if theme_key not in THEMES:
            return
        for var, val in THEMES[theme_key].items():
            self.styles.__dict__[var] = val
        if not silent:
            self.toasts.append(theme_key)


class _FakeConfig:
    DEFAULTS = {"theme": "cyber_green"}

    def __init__(self):
        self._data = {}
        self.saved = False

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value

    def save(self):
        self.saved = True


@pytest.fixture
def app():
    return _FakeApp()


@pytest.fixture
def config():
    return _FakeConfig()


def test_apply_saved_theme_uses_config_value(app, config):
    config._data["theme"] = "blue_team"
    tm = ThemeManager(app, config)
    tm.apply_saved_theme()
    assert app.styles.__dict__["--primary"] == THEMES["blue_team"]["--primary"]

def test_apply_saved_theme_is_silent(app, config):
    config._data["theme"] = "blue_team"
    tm = ThemeManager(app, config)
    tm.apply_saved_theme()
    assert app.toasts == []  # no toast on startup restoration

def test_apply_saved_theme_falls_back_on_invalid(app, config):
    config._data["theme"] = "not_a_theme"
    tm = ThemeManager(app, config)
    tm.apply_saved_theme()
    assert app.styles.__dict__["--primary"] == THEMES["cyber_green"]["--primary"]

def test_switch_applies_and_toasts(app, config):
    tm = ThemeManager(app, config)
    tm.switch("purple_neon")
    assert app.styles.__dict__["--primary"] == THEMES["purple_neon"]["--primary"]
    assert app.toasts == ["purple_neon"]  # manual switch DOES toast

def test_switch_persists_to_config(app, config):
    tm = ThemeManager(app, config)
    tm.switch("dark")
    assert config.get("theme") == "dark"
    assert config.saved is True

def test_switch_invalid_key_is_safe_noop(app, config):
    tm = ThemeManager(app, config)
    tm.switch("garbage")
    assert "--primary" not in app.styles.__dict__
    assert config.get("theme") is None
    assert config.saved is False

def test_label_for_known_and_unknown():
    tm = ThemeManager(_FakeApp(), _FakeConfig())
    assert tm.label_for("dark") == "Dark Mode"
    assert tm.label_for("nonexistent_key") == "nonexistent_key"
