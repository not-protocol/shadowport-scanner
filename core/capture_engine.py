"""
core/capture_engine.py

CaptureEngine wraps `tshark` (the Wireshark CLI) the same way scanner_engine.py
wraps Nmap: strict input validation, subprocess in list-form only (never
shell=True), background-thread execution so the Textual UI never blocks, and
an on_event(level, msg) callback mirroring the existing scanner telemetry
pattern.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from config.settings import CAPTURES_DIR

# Matches tshark's summary line, e.g. "1234 packets captured" / "1 packet captured"
_PACKET_COUNT_RE = re.compile(r"(\d+)\s+packets?\s+captured", re.IGNORECASE)

# Same interface-name allow-list used by the UI validation layer
# (kept here too so CaptureEngine is safe even if called directly, not just from the UI).
_INTERFACE_RE = re.compile(r"^[a-zA-Z0-9_:.-]{1,15}$")


class CaptureEngine:
    """Manages a single tshark packet-capture subprocess.

    Mirrors the design of core/scanner_engine.py: validation up front,
    subprocess in argv-list form only, a background thread so the Textual
    UI stays responsive, and progress reported via an on_event callback.

    Attributes:
        interface: Network interface name to capture on (e.g. "eth0").
        bpf_filter: Optional BPF capture filter (e.g. "tcp port 443").
        output_file: Destination .pcapng path. Auto-generated if empty.
        duration: Capture duration in seconds. 0 means unbounded (manual stop).
        on_event: Optional callback `on_event(level: str, msg: str)` invoked
            for INFO/ERROR/DONE style progress events, mirroring the pattern
            used in scanner_engine.py.
        status: One of "idle", "running", "stopped", "failed".
    """

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "",
        output_file: str = "",
        duration: int = 0,
        on_event: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        """Initialise a CaptureEngine.

        Args:
            interface: Network interface name (validated against
                ^[a-zA-Z0-9_:.-]{1,15}$ before any subprocess is launched).
            bpf_filter: Optional BPF filter string, passed to tshark as a
                single argv element (never shell-interpolated).
            output_file: Destination file path for the capture. If empty,
                a path is auto-generated under Log/captures/.
            duration: Capture duration in seconds. 0 disables the autostop
                flag and the capture runs until stop() is called.
            on_event: Optional (level, message) callback for progress/errors.

        Raises:
            ValueError: If interface fails the allow-list regex.
        """
        if not _INTERFACE_RE.match(interface):
            raise ValueError(
                f"Invalid interface name '{interface}' — must match "
                f"{_INTERFACE_RE.pattern}"
            )

        self.interface = interface
        self.bpf_filter = bpf_filter
        self.duration = duration
        self.on_event = on_event
        self.status = "idle"

        self.output_file = output_file or self._generate_output_path()

        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._running_lock = threading.Lock()
        self._packet_count = 0
        self._packet_count_lock = threading.Lock()

    def _generate_output_path(self) -> str:
        """Build the default capture file path.

        Returns:
            A path string under config.settings.CAPTURES_DIR of the form
            capture_{interface}_{YYYYmmdd_HHMMSS}.pcapng.
        """
        capture_dir = Path(CAPTURES_DIR)
        capture_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_{self.interface}_{timestamp}.pcapng"
        return str(capture_dir / filename)

    def _emit(self, level: str, msg: str) -> None:
        """Safely invoke the on_event callback, if one was provided.

        Args:
            level: Severity/level label, e.g. "INFO", "ERROR", "DONE".
            msg: Human-readable message describing the event.
        """
        if self.on_event is not None:
            try:
                self.on_event(level, msg)
            except Exception:
                # A misbehaving callback must never take down the capture thread.
                pass

    def _check_tshark(self) -> None:
        """Verify that the tshark binary is available on PATH.

        Raises:
            RuntimeError: If tshark cannot be located via shutil.which().
        """
        if shutil.which("tshark") is None:
            raise RuntimeError(
                "tshark not found on PATH — install wireshark-cli "
                "(see README, 'Packet Capture' section)"
            )

    def _build_command(self) -> list[str]:
        """Construct the tshark argv list for this capture.

        Always uses ring-buffer flags (-b filesize / -b files) so a long or
        unbounded capture cannot exhaust disk space. Appends an autostop
        duration flag only when self.duration > 0.

        Returns:
            A list of command-line arguments suitable for subprocess.Popen,
            never a shell string.
        """
        cmd = ["tshark", "-i", self.interface]

        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]

        cmd += ["-w", self.output_file]

        # Ring buffer: rotate at 50MB, keep at most 5 files, to bound disk usage.
        cmd += ["-b", "filesize:51200", "-b", "files:5"]

        if self.duration and self.duration > 0:
            cmd += ["-a", f"duration:{self.duration}"]

        return cmd

    def start(self) -> None:
        """Start the capture in a background daemon thread.

        Raises:
            RuntimeError: If a capture is already running on this engine
                instance, or if tshark is not installed.
        """
        with self._running_lock:
            if self._running:
                raise RuntimeError(
                    "Capture already running — call stop() before starting a new one"
                )
            self._check_tshark()
            self._running = True
            self.status = "running"

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        """Launch tshark and poll its stderr for progress until it exits.

        Runs entirely on the background thread started by start(). Reads
        stderr line-by-line (never a tight spin loop — readline() blocks
        until a line or EOF arrives), updates the cached packet count, and
        reports terminal status via on_event.
        """
        try:
            self._emit("INFO", f"Starting capture on {self.interface}...")
            self._proc = subprocess.Popen(
                self._build_command(),
                shell=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )

            if self._proc.stderr is not None:
                for line in self._proc.stderr:
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    match = _PACKET_COUNT_RE.search(line)
                    if match:
                        with self._packet_count_lock:
                            self._packet_count = int(match.group(1))
                    self._emit("INFO", line)

            self._proc.wait()

            if self._proc.returncode == 0:
                self.status = "stopped"
                self._emit("DONE", f"Capture finished — saved to {self.output_file}")
            else:
                self.status = "failed"
                self._emit(
                    "ERROR",
                    f"tshark exited with code {self._proc.returncode}",
                )

        except (FileNotFoundError, PermissionError) as exc:
            self.status = "failed"
            self._emit("ERROR", str(exc))
        except Exception as exc:  # noqa: BLE001 - a malformed line/unexpected
            # condition must never crash the capture thread silently.
            self.status = "failed"
            self._emit("ERROR", f"Unexpected capture error: {exc}")
        finally:
            with self._running_lock:
                self._running = False

    def stop(self) -> None:
        """Stop a running capture, gracefully then forcefully if needed.

        Sends SIGTERM via proc.terminate(), waits up to 5 seconds for the
        process to exit (allowing tshark to flush the capture file cleanly),
        and falls back to proc.kill() if it has not exited in time.
        """
        if self._proc is None:
            return

        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        except Exception as exc:  # noqa: BLE001
            self._emit("ERROR", f"Error while stopping capture: {exc}")
        finally:
            with self._running_lock:
                self._running = False
            if self.status == "running":
                self.status = "stopped"

    def get_packet_count(self) -> int:
        """Return the most recently observed packet count.

        Returns:
            The latest packet count parsed from tshark's stderr output, or
            0 if no count has been observed yet. Never raises.
        """
        with self._packet_count_lock:
            return self._packet_count
