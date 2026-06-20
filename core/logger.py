"""
core/logger.py — ShadowPort Scanner v2.3.0
Unified silent error logging to Log/error.log + SQLite errors_log.
"""

import os
import traceback
from datetime import datetime

from config.settings import ERROR_LOG, LOG_DIR


def _ensure():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(ERROR_LOG):
        with open(ERROR_LOG, "w", encoding="utf-8") as f:
            f.write(f"# ShadowPort Scanner error log — created {datetime.now()}\n")


def log_error(module: str = "", target: str = "",
              message: str = "", exc: Exception = None) -> None:
    try:
        _ensure()
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        trace = ""
        if exc:
            trace = "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            )
        entry = (
            f"\n[{ts}]\n"
            f"  MODULE : {module or '—'}\n"
            f"  TARGET : {target or '—'}\n"
            f"  ERROR  : {message}\n"
        )
        if trace:
            for line in trace.splitlines():
                entry += f"    {line}\n"
        entry += "  " + "─" * 60 + "\n"
        with open(ERROR_LOG, "a", encoding="utf-8") as f:
            f.write(entry)

        # Also write to DB errors_log (import here to avoid circular)
        try:
            from db.database import log_db_error
            log_db_error(module, target, message, trace)
        except Exception:
            pass
    except Exception:
        pass
