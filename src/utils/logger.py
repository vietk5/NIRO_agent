"""
logger.py — SHA-256 tamper-evident audit logger
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

_LOG_FILE  = Path("logs/audit.jsonl")
_TOOL_LOG  = Path("logs/tool_audit.jsonl")
_PREV_HASH = "0" * 64


def _write(path: Path, entry: dict):
    global _PREV_HASH
    path.parent.mkdir(parents=True, exist_ok=True)
    entry["prev_hash"] = _PREV_HASH
    raw = json.dumps(entry, ensure_ascii=False)
    _PREV_HASH = hashlib.sha256(raw.encode()).hexdigest()
    entry["hash"] = _PREV_HASH
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def log_event(event_type: str, data: dict):
    _write(_LOG_FILE, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        **data,
    })


def log_alert_received(alert: dict):
    log_event("ALERT_RECEIVED", {
        "alert_id": alert.get("alert_id"),
        "src_ip":   alert.get("src_ip"),
        "rf_class": alert.get("rf_class"),
    })


def log_agent_start(name: str, info: str = ""):
    log_event("AGENT_START", {"agent": name, "info": info})


def log_agent_complete(name: str, summary: str, iterations: int = 0, tokens: int = 0):
    log_event("AGENT_COMPLETE", {
        "agent":      name,
        "summary":    summary,
        "iterations": iterations,
        "tokens":     tokens,
    })


def log_pipeline_complete(incident_id: str, outcome: str, duration: float):
    log_event("PIPELINE_COMPLETE", {
        "incident_id": incident_id,
        "outcome":     outcome,
        "duration_sec": round(duration, 2),
    })


def log_tool_call(tool: str, args: dict, result: dict, duration_ms: int):
    _write(_TOOL_LOG, {
        "ts":          datetime.now(timezone.utc).isoformat(),
        "tool":        tool,
        "args":        args,
        "result":      result,
        "duration_ms": duration_ms,
    })


def verify_audit_chain(log_file: str = None) -> tuple[bool, str]:
    path = Path(log_file) if log_file else _LOG_FILE
    if not path.exists():
        return True, "No audit log yet"
    prev = "0" * 64
    count = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry  = json.loads(line)
            stored = entry.pop("hash", "")
            if entry.get("prev_hash") != prev:
                return False, f"Chain broken at entry {count+1}"
            raw    = json.dumps(entry, ensure_ascii=False)
            actual = hashlib.sha256(raw.encode()).hexdigest()
            if actual != stored:
                return False, f"Hash mismatch at entry {count+1}"
            prev = stored
            count += 1
    return True, f"{count} entries verified"
