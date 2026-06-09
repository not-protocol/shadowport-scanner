"""
tests/test_excel_logger.py — ShadowPort Scanner v2.1.0
Full Excel logger test suite covering new file, append, retry, directory creation.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from openpyxl import load_workbook
import core.excel_logger as excel_mod
from core.excel_logger import log_scan_to_excel, HEADER_COLUMNS


SAMPLE_SCAN = {
    "host":             "192.168.1.1",
    "mode_name":        "Quick Scan",
    "state":            "up",
    "duration_seconds": 12.5,
    "ports": [
        {"port": "22",  "proto": "tcp", "state": "open",   "service": "ssh"},
        {"port": "80",  "proto": "tcp", "state": "open",   "service": "http"},
        {"port": "443", "proto": "tcp", "state": "closed", "service": "https"},
    ],
    "risk": {"score": 14, "label": "LOW EXPOSURE", "breakdown": []},
}


@pytest.fixture(autouse=True)
def temp_excel(tmp_path, monkeypatch):
    excel_path = str(tmp_path / "scannerhistory.xlsx")
    logs_dir   = str(tmp_path)
    monkeypatch.setattr(excel_mod, "EXCEL_PATH", excel_path)
    monkeypatch.setattr(excel_mod, "LOGS_DIR",   logs_dir)
    import config.settings as s
    monkeypatch.setattr(s, "EXCEL_PATH", excel_path)
    monkeypatch.setattr(s, "LOGS_DIR",   logs_dir)


# ─── New file creation ────────────────────────────────────────────────────────

def test_creates_new_file(tmp_path):
    ok, msg = log_scan_to_excel(SAMPLE_SCAN, risk_score=14)
    assert ok, msg
    assert os.path.exists(excel_mod.EXCEL_PATH)

def test_new_file_has_header():
    log_scan_to_excel(SAMPLE_SCAN, risk_score=14)
    wb = load_workbook(excel_mod.EXCEL_PATH)
    ws = wb.active
    headers = [ws.cell(1, i).value for i in range(1, len(HEADER_COLUMNS) + 1)]
    assert headers == HEADER_COLUMNS
    wb.close()

def test_new_file_first_row_is_scan_1():
    log_scan_to_excel(SAMPLE_SCAN, risk_score=14)
    wb = load_workbook(excel_mod.EXCEL_PATH)
    ws = wb.active
    assert ws.cell(2, 1).value == 1  # Scan #
    wb.close()

def test_creates_log_directory(tmp_path, monkeypatch):
    new_dir   = str(tmp_path / "NewLog")
    new_excel = str(tmp_path / "NewLog" / "scannerhistory.xlsx")
    monkeypatch.setattr(excel_mod, "EXCEL_PATH", new_excel)
    monkeypatch.setattr(excel_mod, "LOGS_DIR",   new_dir)
    ok, _ = log_scan_to_excel(SAMPLE_SCAN, risk_score=0)
    assert ok
    assert os.path.exists(new_excel)


# ─── Append to existing ───────────────────────────────────────────────────────

def test_append_increments_scan_number():
    log_scan_to_excel(SAMPLE_SCAN, risk_score=14)
    log_scan_to_excel(SAMPLE_SCAN, risk_score=14)
    wb = load_workbook(excel_mod.EXCEL_PATH)
    ws = wb.active
    assert ws.cell(2, 1).value == 1
    assert ws.cell(3, 1).value == 2
    wb.close()

def test_append_does_not_duplicate_header():
    log_scan_to_excel(SAMPLE_SCAN, risk_score=14)
    log_scan_to_excel(SAMPLE_SCAN, risk_score=14)
    wb = load_workbook(excel_mod.EXCEL_PATH)
    ws = wb.active
    assert ws.max_row == 3  # 1 header + 2 data rows
    wb.close()

def test_data_row_correct_values():
    log_scan_to_excel(SAMPLE_SCAN, risk_score=14)
    wb = load_workbook(excel_mod.EXCEL_PATH)
    ws = wb.active
    row = [ws.cell(2, i).value for i in range(1, 11)]
    assert row[3] == "192.168.1.1"   # Target
    assert row[4] == "Quick Scan"    # Scan Type
    assert row[5] == 2               # Open Ports
    assert row[6] == 3               # Total Ports
    assert row[7] == 14              # Risk Score
    assert row[8] == 12.5            # Duration
    assert row[9] == "up"            # Status
    wb.close()


# ─── Missing Log/ directory ───────────────────────────────────────────────────

def test_missing_directory_auto_created(tmp_path, monkeypatch):
    deep_dir  = str(tmp_path / "deep" / "nested" / "Log")
    deep_file = str(tmp_path / "deep" / "nested" / "Log" / "scannerhistory.xlsx")
    monkeypatch.setattr(excel_mod, "EXCEL_PATH", deep_file)
    monkeypatch.setattr(excel_mod, "LOGS_DIR",   deep_dir)
    ok, _ = log_scan_to_excel(SAMPLE_SCAN, risk_score=0)
    assert ok
    assert os.path.exists(deep_file)


# ─── Return values ────────────────────────────────────────────────────────────

def test_returns_true_on_success():
    ok, msg = log_scan_to_excel(SAMPLE_SCAN, risk_score=0)
    assert ok is True
    assert isinstance(msg, str)

def test_returns_false_on_bad_path(monkeypatch):
    monkeypatch.setattr(excel_mod, "EXCEL_PATH", "/root/no_permission/test.xlsx")
    monkeypatch.setattr(excel_mod, "LOGS_DIR",   "/root/no_permission")
    ok, msg = log_scan_to_excel(SAMPLE_SCAN, risk_score=0)
    assert ok is False
    assert msg != ""
