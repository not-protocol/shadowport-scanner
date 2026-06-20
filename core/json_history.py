"""
core/json_history.py — ShadowPort Scanner v2.3.0
Append-only JSON history file for all scan, plugin, and report activity.
"""

import json
import os
import threading
from datetime import datetime

from config.settings import JSON_HIST, LOG_DIR

_lock = threading.Lock()


def _ensure():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(JSON_HIST):
        with open(JSON_HIST, "w", encoding="utf-8") as f:
            json.dump([], f)


def _append(entry: dict) -> None:
    _ensure()
    with _lock:
        try:
            with open(JSON_HIST, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = []
        data.append(entry)
        with open(JSON_HIST, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


def record_scan(scan_data: dict, risk_score: int) -> None:
    ports  = scan_data.get("ports", [])
    open_c = sum(1 for p in ports if p.get("state") == "open")
    _append({
        "type":       "scan",
        "timestamp":  datetime.now().isoformat(),
        "target":     scan_data.get("host",""),
        "mode":       scan_data.get("mode_name",""),
        "open_ports": open_c,
        "risk_score": risk_score,
        "status":     scan_data.get("state","unknown"),
        "partial":    scan_data.get("partial", False),
    })


def record_plugin(target: str, plugin_name: str,
                  output: str, success: bool) -> None:
    _append({
        "type":       "plugin",
        "timestamp":  datetime.now().isoformat(),
        "target":     target,
        "plugin":     plugin_name,
        "success":    success,
        "preview":    output[:120],
    })


def record_report(target: str, fmt: str, filepath: str) -> None:
    _append({
        "type":      "report",
        "timestamp": datetime.now().isoformat(),
        "target":    target,
        "format":    fmt,
        "filepath":  filepath,
    })


def get_history(limit: int = 100) -> list[dict]:
    _ensure()
    with _lock:
        try:
            with open(JSON_HIST, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data[-limit:][::-1]
        except Exception:
            return []
