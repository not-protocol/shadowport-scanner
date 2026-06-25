"""tests/test_capture_engine.py — ShadowPort Scanner v2.4.0"""

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import core.capture_engine as ce
from core.capture_engine import CaptureEngine, _PACKET_COUNT_RE


@pytest.fixture
def engine(tmp_path):
    return CaptureEngine(
        interface="eth0", bpf_filter="port 80",
        output_file=str(tmp_path / "test_capture.pcapng"), duration=0,
    )


# ── validation ────────────────────────────────────────────────────────────────

def test_invalid_interface_rejected():
    with pytest.raises(ValueError):
        CaptureEngine(interface="eth0; rm -rf /")

def test_valid_interface_with_alias_accepted():
    # eth0:1-style aliases are explicitly supported by the allow-list.
    e = CaptureEngine(interface="eth0:1")
    assert e.interface == "eth0:1"


# ── command construction ───────────────────────────────────────────────────────

def test_build_command_with_filter(engine):
    cmd = engine._build_command()
    assert cmd[0] == "tshark"
    assert cmd[cmd.index("-i") + 1] == "eth0"
    assert cmd[cmd.index("-f") + 1] == "port 80"
    assert cmd[cmd.index("-w") + 1] == engine.output_file

def test_build_command_ring_buffer(engine):
    cmd = engine._build_command()
    assert "filesize:51200" in cmd
    assert "files:5" in cmd

def test_build_command_no_duration_flag_when_zero(engine):
    cmd = engine._build_command()
    assert "-a" not in cmd

def test_build_command_duration_flag_when_set(tmp_path):
    e = CaptureEngine(interface="eth0", output_file=str(tmp_path / "x.pcapng"), duration=30)
    cmd = e._build_command()
    assert cmd[cmd.index("-a") + 1] == "duration:30"


# ── tshark availability ────────────────────────────────────────────────────────

def test_check_tshark_missing(monkeypatch, engine):
    monkeypatch.setattr(ce.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError):
        engine._check_tshark()

def test_check_tshark_present(monkeypatch, engine):
    monkeypatch.setattr(ce.shutil, "which", lambda name: "/usr/bin/tshark")
    engine._check_tshark()  # should not raise


# ── output path ────────────────────────────────────────────────────────────────

def test_output_path_auto_generated(monkeypatch, tmp_path):
    import config.settings as s
    monkeypatch.setattr(ce, "CAPTURES_DIR", str(tmp_path / "Log" / "captures"))
    e = CaptureEngine(interface="eth0")
    assert str(tmp_path / "Log" / "captures") in e.output_file
    assert e.output_file.endswith(".pcapng")
    assert os.path.isdir(os.path.dirname(e.output_file))


# ── packet count parsing ────────────────────────────────────────────────────────

def test_packet_count_regex():
    m = _PACKET_COUNT_RE.search("1234 packets captured")
    assert m and int(m.group(1)) == 1234

def test_get_packet_count_default_zero(engine):
    assert engine.get_packet_count() == 0


# ── start/stop lifecycle (mocked subprocess) ───────────────────────────────────

def test_double_start_raises(monkeypatch, engine):
    """A second start() while the first is genuinely still running must raise.

    Uses a process whose wait() blocks briefly, so the background thread is
    still inside _run() when the test's second start() call arrives — a
    mock that returns instantly would let the thread clear _running before
    the second call, masking the guard entirely.
    """
    monkeypatch.setattr(ce.shutil, "which", lambda name: "/usr/bin/tshark")

    class SlowProc:
        stderr = iter([])
        returncode = 0
        def wait(self, timeout=None):
            time.sleep(0.3)
            return 0
        def terminate(self):
            pass

    monkeypatch.setattr(ce.subprocess, "Popen", lambda *a, **k: SlowProc())

    engine.start()
    time.sleep(0.05)
    with pytest.raises(RuntimeError):
        engine.start()
    engine.stop()

def test_on_event_called_on_failure(monkeypatch, engine):
    events = []
    engine.on_event = lambda level, msg: events.append((level, msg))
    monkeypatch.setattr(ce.shutil, "which", lambda name: "/usr/bin/tshark")

    class FailingProc:
        stderr = iter([])
        returncode = 1
        def wait(self, timeout=None):
            return 1
        def terminate(self):
            pass

    monkeypatch.setattr(ce.subprocess, "Popen", lambda *a, **k: FailingProc())

    engine.start()
    engine._thread.join(timeout=2)

    assert any(level == "ERROR" for level, _ in events)
    assert engine.status == "failed"

def test_stop_terminates_and_waits(engine):
    class FakeProc:
        terminated = False
        waited = False
        def terminate(self):
            self.terminated = True
        def wait(self, timeout=None):
            self.waited = True
            return 0

    fake = FakeProc()
    engine._proc = fake
    engine._running = True
    engine.status = "running"

    engine.stop()

    assert fake.terminated
    assert fake.waited

def test_stop_kills_on_timeout(engine):
    import subprocess as sp

    class HangingProc:
        terminated = False
        killed = False
        wait_calls = 0
        def terminate(self):
            self.terminated = True
        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise sp.TimeoutExpired(cmd="tshark", timeout=timeout)
            return 0
        def kill(self):
            self.killed = True

    fake = HangingProc()
    engine._proc = fake
    engine._running = True
    engine.status = "running"

    engine.stop()

    assert fake.terminated
    assert fake.killed
