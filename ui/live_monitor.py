"""
ui/live_monitor.py — ShadowPort Scanner v2.1.0

Textual TUI widgets for live scan monitoring:
  - ScanStatusPanel : target, mode, elapsed timer (live updating)
  - LiveEventsLog   : scrollable event log, max 100 entries,
                      thread-safe deduplication by port+protocol key

All UI updates use app.call_from_thread() — no direct widget mutation
from background threads.
"""

import threading
import time
from datetime import datetime

from textual.app import ComposeResult
from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Label, Log, Static
from textual.containers import Vertical


# ─── Messages ─────────────────────────────────────────────────────────────────

class ScanStarted(Message):
    def __init__(self, target: str, mode: str) -> None:
        super().__init__()
        self.target = target
        self.mode   = mode


class ScanEvent(Message):
    """Posted from background thread for each discovered port / event."""
    def __init__(self, port: str, protocol: str, service: str, state: str) -> None:
        super().__init__()
        self.port     = port
        self.protocol = protocol
        self.service  = service
        self.state    = state
        self.key      = f"{port}/{protocol}"


class ScanFinished(Message):
    def __init__(self, open_count: int, duration: float) -> None:
        super().__init__()
        self.open_count = open_count
        self.duration   = duration


# ─── ScanStatusPanel ─────────────────────────────────────────────────────────

class ScanStatusPanel(Static):
    """
    Shows: Target | Mode | Elapsed | Status
    Updates every second via a background timer thread.
    Never mutated from outside the UI thread.
    """

    DEFAULT_CSS = """
    ScanStatusPanel {
        border: solid $primary;
        padding: 1 2;
        height: 7;
    }
    """

    _target:    reactive[str]   = reactive("—")
    _mode:      reactive[str]   = reactive("—")
    _status:    reactive[str]   = reactive("Idle")
    _elapsed:   reactive[float] = reactive(0.0)
    _start_ts:  float           = 0.0
    _running:   bool            = False
    _timer_thread: threading.Thread | None = None

    def compose(self) -> ComposeResult:
        yield Label(id="sp-target")
        yield Label(id="sp-mode")
        yield Label(id="sp-elapsed")
        yield Label(id="sp-status")

    def watch__target(self, value: str) -> None:
        self.query_one("#sp-target", Label).update(f"Target  : {value}")

    def watch__mode(self, value: str) -> None:
        self.query_one("#sp-mode", Label).update(f"Mode    : {value}")

    def watch__status(self, value: str) -> None:
        self.query_one("#sp-status", Label).update(f"Status  : {value}")

    def watch__elapsed(self, value: float) -> None:
        mins = int(value) // 60
        secs = int(value) % 60
        self.query_one("#sp-elapsed", Label).update(f"Elapsed : {mins:02d}:{secs:02d}")

    def _tick(self) -> None:
        """Background thread — posts elapsed updates to UI thread."""
        while self._running:
            elapsed = time.time() - self._start_ts
            self.app.call_from_thread(setattr, self, "_elapsed", elapsed)
            time.sleep(1.0)

    def start_scan(self, target: str, mode: str) -> None:
        """Called from UI thread when a scan starts."""
        self._target   = target
        self._mode     = mode
        self._status   = "Scanning…"
        self._elapsed  = 0.0
        self._start_ts = time.time()
        self._running  = True
        self._timer_thread = threading.Thread(target=self._tick, daemon=True)
        self._timer_thread.start()

    def finish_scan(self, open_count: int, duration: float) -> None:
        """Called from UI thread when scan finishes."""
        self._running = False
        self._elapsed = duration
        self._status  = f"Done — {open_count} open port(s)"

    def reset(self) -> None:
        self._running = False
        self._target  = "—"
        self._mode    = "—"
        self._status  = "Idle"
        self._elapsed = 0.0

    def on_unmount(self) -> None:
        self._running = False


# ─── LiveEventsLog ────────────────────────────────────────────────────────────

class LiveEventsLog(Vertical):
    """
    Scrollable log of scan events. Max 100 entries.
    Thread-safe deduplication by port+protocol key.
    """

    DEFAULT_CSS = """
    LiveEventsLog {
        border: solid $accent;
        padding: 0 1;
        height: 20;
    }
    """

    MAX_EVENTS = 100

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._seen_keys:  set[str]  = set()
        self._event_count: int      = 0
        self._lock = threading.Lock()

    def compose(self) -> ComposeResult:
        yield Log(id="events-log", auto_scroll=True)

    def _get_log(self) -> Log:
        return self.query_one("#events-log", Log)

    def add_event(self, port: str, protocol: str, service: str, state: str) -> None:
        """
        Add one event line. Must be called from the UI thread
        (use app.call_from_thread(add_event, ...) from background threads).

        Deduplicates by port+protocol key.
        Enforces MAX_EVENTS buffer cap.
        """
        key = f"{port}/{protocol}"

        with self._lock:
            if key in self._seen_keys:
                return
            if self._event_count >= self.MAX_EVENTS:
                return
            self._seen_keys.add(key)
            self._event_count += 1

        ts  = datetime.now().strftime("%H:%M:%S")
        svc = f" ({service})" if service else ""
        log = self._get_log()
        log.write_line(f"[{ts}]  {port}/{protocol:<6}  {state:<8}{svc}")

    def clear(self) -> None:
        with self._lock:
            self._seen_keys.clear()
            self._event_count = 0
        self._get_log().clear()

    def add_message(self, text: str) -> None:
        """Add a plain status message (not a port event)."""
        ts = datetime.now().strftime("%H:%M:%S")
        self._get_log().write_line(f"[{ts}]  {text}")
