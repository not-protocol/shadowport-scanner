"""tests/test_config_manager.py — ShadowPort Scanner v2.4.0"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from config.config_manager import ConfigManager


@pytest.fixture(autouse=True)
def isolated_config_path(tmp_path, monkeypatch):
    fake_path = tmp_path / ".shadowport" / "config.json"
    monkeypatch.setattr(ConfigManager, "CONFIG_PATH", fake_path)
    return fake_path


def test_load_creates_file_with_defaults():
    cm = ConfigManager()
    assert ConfigManager.CONFIG_PATH.exists()
    assert cm.get("theme") == ConfigManager.DEFAULTS["theme"]
    assert cm.get("capture_interface") == ConfigManager.DEFAULTS["capture_interface"]
    assert cm.get("capture_duration") == ConfigManager.DEFAULTS["capture_duration"]

def test_defaults_match_settings():
    """ConfigManager must source defaults from config/settings.py, not its own copy."""
    import config.settings as s
    assert ConfigManager.DEFAULTS["theme"] == s.DEFAULT_THEME
    assert ConfigManager.DEFAULTS["capture_interface"] == s.DEFAULT_CAPTURE_INTERFACE
    assert ConfigManager.DEFAULTS["capture_duration"] == s.DEFAULT_CAPTURE_DURATION

def test_load_recovers_from_corrupt_json():
    ConfigManager.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    ConfigManager.CONFIG_PATH.write_text("{not valid json", encoding="utf-8")

    cm = ConfigManager()
    assert cm.get("theme") == ConfigManager.DEFAULTS["theme"]

    on_disk = json.loads(ConfigManager.CONFIG_PATH.read_text(encoding="utf-8"))
    assert on_disk["theme"] == ConfigManager.DEFAULTS["theme"]

def test_save_is_atomic_no_leftover_tmp():
    cm = ConfigManager()
    cm.set("theme", "blue_team")
    cm.save()

    leftover = list(ConfigManager.CONFIG_PATH.parent.glob("*.tmp"))
    assert leftover == []

    on_disk = json.loads(ConfigManager.CONFIG_PATH.read_text(encoding="utf-8"))
    assert on_disk["theme"] == "blue_team"

def test_set_get_save_reload_roundtrip():
    cm = ConfigManager()
    cm.set("capture_duration", 120)
    cm.set("capture_interface", "wlan0")
    cm.save()

    cm2 = ConfigManager()
    assert cm2.get("capture_duration") == 120
    assert cm2.get("capture_interface") == "wlan0"

def test_get_returns_default_for_missing_key():
    cm = ConfigManager()
    assert cm.get("nonexistent", "fallback") == "fallback"

def test_creates_parent_dir_if_missing():
    cm = ConfigManager()
    assert ConfigManager.CONFIG_PATH.parent.is_dir()
