"""
core/excel_logger.py — ShadowPort Scanner v2.1.0

Dual-write Excel logger using openpyxl exclusively.
  - Writes immediately after every scan (never on exit)
  - Auto-creates Log/ directory and file if missing
  - Styled header row (bold, coloured)
  - Thread-safe via threading.Lock
  - PermissionError retry: 3 attempts × 1s delay
  - Auto-increments Scan# from existing row count
  - Returns (success: bool, message: str)
"""

import os
import threading
import time
from datetime import datetime
from typing import Tuple

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

from config.settings import EXCEL_PATH, LOGS_DIR

_excel_lock = threading.Lock()

HEADER_COLUMNS = [
    "Scan #",
    "Date",
    "Time",
    "Target",
    "Scan Type",
    "Open Ports",
    "Total Ports",
    "Risk Score",
    "Duration (s)",
    "Status",
]

_HEADER_FILL  = PatternFill(start_color="1F3864", end_color="1F3864", fill_type="solid")
_HEADER_FONT  = Font(bold=True, color="FFFFFF", size=11)
_HEADER_ALIGN = Alignment(horizontal="center", vertical="center")

_COL_WIDTHS = [8, 12, 10, 22, 20, 12, 12, 12, 14, 12]


def _apply_header(ws) -> None:
    ws.append(HEADER_COLUMNS)
    for col_idx, (width, cell) in enumerate(
        zip(_COL_WIDTHS, ws[1]), start=1
    ):
        cell.font      = _HEADER_FONT
        cell.fill      = _HEADER_FILL
        cell.alignment = _HEADER_ALIGN
        ws.column_dimensions[get_column_letter(col_idx)].width = width
    ws.row_dimensions[1].height = 20


def _create_new_workbook() -> Workbook:
    wb = Workbook()
    ws = wb.active
    ws.title = "Scan History"
    _apply_header(ws)
    return wb


def _load_or_create() -> Tuple[Workbook, bool]:
    """
    Returns (workbook, was_created).
    If the file is corrupt or unreadable, creates a fresh one.
    """
    if os.path.exists(EXCEL_PATH):
        try:
            return load_workbook(EXCEL_PATH), False
        except Exception:
            return _create_new_workbook(), True
    return _create_new_workbook(), True


def _next_scan_number(ws) -> int:
    """Auto-increment: count data rows (excluding header)."""
    return max(ws.max_row - 1, 0) + 1


def log_scan_to_excel(scan_data: dict, risk_score: int = 0) -> Tuple[bool, str]:
    """
    Append one scan row to the Excel log.
    Called immediately after every scan completes.

    Returns (success, message).
    """
    os.makedirs(LOGS_DIR, exist_ok=True)

    now       = datetime.now()
    target    = scan_data.get("host", "")
    scan_type = scan_data.get("mode_name", "")
    ports     = scan_data.get("ports", [])
    open_c    = sum(1 for p in ports if p.get("state") == "open")
    total_c   = len(ports)
    duration  = round(float(scan_data.get("duration_seconds", 0.0)), 1)
    status    = scan_data.get("state", "unknown")

    last_error = ""
    for attempt in range(1, 4):
        try:
            with _excel_lock:
                wb, _ = _load_or_create()
                ws     = wb.active

                # Ensure header exists (handles corrupt/empty files)
                if ws.max_row == 0 or ws.cell(1, 1).value != "Scan #":
                    ws.delete_rows(1, ws.max_row)
                    _apply_header(ws)

                scan_num = _next_scan_number(ws)

                row = [
                    scan_num,
                    now.strftime("%Y-%m-%d"),
                    now.strftime("%H:%M:%S"),
                    target,
                    scan_type,
                    open_c,
                    total_c,
                    int(risk_score),
                    duration,
                    status,
                ]
                ws.append(row)
                wb.save(EXCEL_PATH)
                wb.close()

            return True, f"Excel row {scan_num} written to {EXCEL_PATH}"

        except PermissionError as exc:
            last_error = str(exc)
            if attempt < 3:
                time.sleep(1.0)
            continue
        except Exception as exc:
            return False, f"Excel write failed: {exc}"

    return False, f"Excel write failed after 3 attempts (file locked?): {last_error}"


def audit_log_consistency() -> dict:
    """
    Compare SQLite scan count vs Excel row count.
    Runs as a background health check on startup.
    Returns dict with counts and any discrepancy flag.
    """
    from db.database import get_stats

    result = {
        "sqlite_count": 0,
        "excel_count":  0,
        "discrepancy":  False,
        "message":      "",
    }

    try:
        stats = get_stats()
        result["sqlite_count"] = stats["total_scans"]
    except Exception as exc:
        result["message"] = f"SQLite read error: {exc}"
        return result

    if not os.path.exists(EXCEL_PATH):
        result["message"] = "Excel file not found — will be created on next scan."
        result["discrepancy"] = result["sqlite_count"] > 0
        return result

    try:
        with _excel_lock:
            wb = load_workbook(EXCEL_PATH, read_only=True)
            ws = wb.active
            excel_rows = max(ws.max_row - 1, 0)  # subtract header
            wb.close()
        result["excel_count"] = excel_rows
    except Exception as exc:
        result["message"] = f"Excel read error: {exc}"
        return result

    if result["sqlite_count"] != result["excel_count"]:
        result["discrepancy"] = True
        result["message"] = (
            f"Discrepancy: SQLite has {result['sqlite_count']} scans, "
            f"Excel has {result['excel_count']} rows."
        )
    else:
        result["message"] = "Logs consistent."

    return result
