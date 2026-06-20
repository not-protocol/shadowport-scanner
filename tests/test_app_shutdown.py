"""
tests/test_app_shutdown.py — ShadowPort Scanner v2.3.0

Regression test for the App._registry / plugin-dict naming collision.

Textual's own App class keeps an internal `_registry: set[Widget]` it uses to
track every mounted widget for cleanup on shutdown. ShadowPortApp previously
also used `self._registry` (a dict) for its plugin lookup table, silently
overwriting Textual's set and crashing every exit with:

    AttributeError: 'dict' object has no attribute 'discard'

The fix renamed the app's plugin table to `self._plugin_registry`. This test
locks that fix in: it asserts Textual's `_registry` is a `set` both before and
after a full simulated scan, and confirms a clean app shutdown (no exception)
via Textual's async test harness.

NOTE: requires `textual` + `pytest` + `pytest-asyncio` installed
(`pip install textual pytest pytest-asyncio --break-system-packages`).
This file was not executed in the authoring sandbox (no network access to
install Textual there) — run it locally with:

    pytest tests/test_app_shutdown.py -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import patch

import main as main_mod
from main import ShadowPortApp
from textual.widgets import Input


FAKE_SCAN_RESULT = {
    "host": "127.0.0.1", "hostname": "localhost", "state": "up",
    "ports": [
        {"port": "22", "proto": "tcp", "state": "open", "service": "ssh",
         "version": "OpenSSH", "banner": "",
         "intel": {"use": "Secure remote shell", "risk": "Ensure key-based auth."}},
    ],
    "os_matches": [],
    "risk": {"score": 6, "label": "LOW EXPOSURE", "breakdown": ["22/tcp (ssh) +6"]},
    "start_time": "2026-06-19 00:00:00", "end_time": "2026-06-19 00:00:01",
    "duration_seconds": 1.0, "mode_name": "Quick Scan",
    "partial": False, "raw_output": "",
}


def _fake_run_scan(target, mode, on_event=None):
    """Stand-in for core.scanner_engine.run_scan — no real Nmap call."""
    if on_event:
        on_event("INFO", f"Starting Quick Scan on {target}")
        on_event("PORT", "22/tcp (ssh) — open")
        on_event("PROGRESS", "100")
        on_event("INFO", "Scan complete — 1 open ports")
    return FAKE_SCAN_RESULT


@pytest.fixture(autouse=True)
def _isolate_storage(tmp_path, monkeypatch):
    """Redirect every on-disk write target so the test never touches real
    Log/ files, mirroring the isolation pattern used by the other test
    modules (test_database.py, test_excel_logger.py, test_json_history.py)."""
    import config.settings as s
    for mod in (s, main_mod):
        monkeypatch.setattr(mod, "LOG_DIR", str(tmp_path), raising=False)
    monkeypatch.setattr(s, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(s, "EXCEL_PATH", str(tmp_path / "test.xlsx"))
    monkeypatch.setattr(s, "JSON_HIST", str(tmp_path / "history.json"))


@pytest.mark.asyncio
async def test_registry_survives_full_scan_and_shutdown():
    """
    Mounts the real app, confirms Textual's internal `_registry` is a set
    before any scan runs, drives a full Quick Scan through the actual UI
    (target input + Scan button) with `run_scan` mocked, waits for the
    background thread to report back via call_from_thread, re-confirms
    `_registry` is still a set (i.e. never replaced by the plugin dict),
    and then lets the `run_test()` context exit — which triggers the exact
    same App._shutdown() -> _close_all() -> _prune() path as Ctrl+C.
    If the collision regressed, that exit raises AttributeError here.
    """
    with patch.object(main_mod, "run_scan", side_effect=_fake_run_scan):
        app = ShadowPortApp()
        async with app.run_test(size=(120, 40)) as pilot:
            # Pre-scan invariant: Textual owns this attribute, not us.
            assert isinstance(app._registry, set)
            assert isinstance(app._plugin_registry, dict)

            target_input = app.query_one("#target-input", Input)
            target_input.value = "127.0.0.1"
            await pilot.pause()

            await pilot.click("#scan-btn")

            # Background scan thread reports back via call_from_thread;
            # give the event loop a few ticks to receive it.
            for _ in range(30):
                await pilot.pause()
                if not app._scanning:
                    break

            assert app._scan_data is not None, "scan never completed"

            # Post-scan invariant: still untouched.
            assert isinstance(app._registry, set)
            assert isinstance(app._plugin_registry, dict)

    # Context manager exit above = full app shutdown. Reaching this line
    # without an AttributeError is itself the regression assertion.


@pytest.mark.asyncio
async def test_shutdown_with_no_scan_run():
    """Sanity baseline: shutdown must also be clean when no scan ever runs,
    isolating the plugin-loading path (on_mount) as a separate suspect."""
    app = ShadowPortApp()
    async with app.run_test() as pilot:
        assert isinstance(app._registry, set)
        assert isinstance(app._plugin_registry, dict)
        await pilot.pause()
    # Clean exit = pass.
