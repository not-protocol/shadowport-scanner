"""
logger.py — ShadowPort Scanner v2.0.0
Centralised error logging to logs/error.log.
Never shown to the user; written silently in the background.
"""

import os
import traceback
from datetime import datetime

from config.settings import ERROR_LOG, LOGS_DIR


def _ensure_log():
    os.makedirs(LOGS_DIR, exist_ok=True)
    if not os.path.exists(ERROR_LOG):
        with open(ERROR_LOG, "w", encoding="utf-8") as f:
            f.write(f"# ShadowPort Scanner error log — created {datetime.now()}\n")


def log_error(target: str = "", mode: str = "", error: str = "", exc: Exception = None):
    """
    Append one structured error entry to logs/error.log.

    Parameters
    ----------
    target : str   — IP / hostname being scanned when error occurred
    mode   : str   — scan mode name
    error  : str   — short human description of the error
    exc    : Exception (optional) — if provided, full traceback is appended
    """
    try:
        _ensure_log()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        trace = ""
        if exc:
            trace = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

        entry = (
            f"\n[{ts}]\n"
            f"  TARGET : {target or '—'}\n"
            f"  MODE   : {mode or '—'}\n"
            f"  ERROR  : {error}\n"
        )
        if trace:
            entry += f"  TRACE  :\n"
            for line in trace.splitlines():
                entry += f"    {line}\n"
        entry += "  " + "─" * 60 + "\n"

        with open(ERROR_LOG, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass  # logging must never crash the app
