"""
response_tools.py — Công cụ thực thi phòng thủ

QUAN TRỌNG: Tất cả destructive actions (block_ip_address, isolate_host,
revoke_credentials) cần phải qua human approval trước khi gọi.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path


BLOCKLIST_FILE = Path("data/blocklist.txt")
TICKET_DIR     = Path("data/tickets")


def block_ip_address(ip: str, reason: str, duration_hours: int = 24) -> dict:
    """
    Block IP trong blocklist (ghi file).
    Trên production: gọi Firewall API.
    """
    BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry = f"{ip}  # {reason}  blocked_at={datetime.now(timezone.utc).isoformat()}"
    with open(BLOCKLIST_FILE, "a") as f:
        f.write(entry + "\n")
    return {
        "status":   "blocked",
        "ip":       ip,
        "reason":   reason,
        "duration": f"{duration_hours}h",
        "note":     "Written to data/blocklist.txt — sync với firewall thủ công",
    }


def create_incident_ticket(
    alert_id: str, severity: str, summary: str, assigned_to: str = "SOC-TEAM"
) -> dict:
    """Tạo ticket sự cố."""
    TICKET_DIR.mkdir(parents=True, exist_ok=True)
    ticket_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{alert_id}"
    ticket = {
        "ticket_id":   ticket_id,
        "alert_id":    alert_id,
        "severity":    severity,
        "summary":     summary,
        "assigned_to": assigned_to,
        "status":      "OPEN",
        "created_at":  datetime.now(timezone.utc).isoformat(),
    }
    path = TICKET_DIR / f"{ticket_id}.json"
    path.write_text(json.dumps(ticket, indent=2))
    return ticket


def notify_analyst(message: str, channel: str = "security-alerts") -> dict:
    """Gửi thông báo tới analyst (log ra console + file)."""
    ts = datetime.now(timezone.utc).isoformat()
    print(f"\n  [NOTIFY → #{channel}] {message}", flush=True)
    log_path = Path("logs/notifications.jsonl")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a") as f:
        f.write(json.dumps({"ts": ts, "channel": channel, "message": message}) + "\n")
    return {"sent": True, "channel": channel, "ts": ts}


def isolate_host(host_ip: str, reason: str) -> dict:
    """
    Cô lập host khỏi mạng.
    Trên production: gọi EDR/NAC API.
    """
    return {
        "status":  "isolation_requested",
        "host_ip": host_ip,
        "reason":  reason,
        "note":    "Manual action required: isolate via EDR/NAC console",
    }
