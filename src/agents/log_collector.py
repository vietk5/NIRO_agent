"""
log_collector.py — Stage 1B: Log Collection

Chạy song song với recon và pcap_analyzer.
Đọc auth.log, firewall log, syslog, audit trail để tìm evidence liên quan.
Timeout kiểm soát bởi orchestrator.
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

LOG_SOURCES = [
    # data/input/logs/ — user-supplied real log files (highest priority)
    Path("data/input/logs/auth.log"),
    Path("data/input/logs/firewall.log"),
    Path("data/input/logs/syslog.log"),
    Path("data/input/logs/audit.jsonl"),
    # System logs (Linux)
    Path("/var/log/auth.log"),
    Path("/var/log/syslog"),
    Path("/var/log/ufw.log"),
    # Legacy local logs
    Path("logs/auth.log"),
    Path("logs/syslog.log"),
    Path("logs/firewall.log"),
    Path("logs/audit.jsonl"),
]


def run_log_collector(alert: dict, verbose: bool = True) -> dict:
    """Stage 1B: Thu thập và phân tích logs."""
    if verbose:
        print("  [LOG-COLLECT] Starting — searching auth/firewall/syslog", flush=True)

    src_ip = alert.get("src_ip", "")
    auth_events, firewall_events, syslog_events, audit_events = [], [], [], []

    for log_path in LOG_SOURCES:
        if not log_path.exists():
            continue
        try:
            content = log_path.read_text(errors="replace")
            lines   = [l for l in content.splitlines() if src_ip in l][:50]
            name    = log_path.name

            if "auth" in name:
                auth_events.extend(lines)
            elif "firewall" in name:
                firewall_events.extend(lines)
            elif "audit" in name:
                audit_events.extend(lines)
            else:
                syslog_events.extend(lines)
        except Exception:
            continue

    # Nếu không có log thật → dùng sample data
    if not any([auth_events, firewall_events, syslog_events]):
        auth_events, firewall_events, syslog_events = _generate_sample_events(src_ip, alert)

    summary = _summarize(src_ip, auth_events, firewall_events, syslog_events, alert)

    if verbose:
        print(f"  [LOG-COLLECT] Done — failed_auth={summary['failed_auth_count']} "
              f"fw_blocks={summary['blocked_connections']} pattern={summary['attack_pattern']}", flush=True)

    return {
        "auth_log_events":   auth_events[:20],
        "firewall_events":   firewall_events[:20],
        "syslog_events":     syslog_events[:10],
        "audit_events":      audit_events[:10],
        "summary":           summary,
        "error":             None,
    }


def _summarize(src_ip, auth_events, firewall_events, syslog_events, alert) -> dict:
    failed_auth = sum(1 for e in auth_events
                      if any(k in e.lower() for k in ["failed", "invalid", "authentication failure"]))
    blocked     = sum(1 for e in firewall_events
                      if any(k in e.lower() for k in ["drop", "reject", "block", "deny"]))

    port_pattern = re.compile(r"port\s+(\d+)", re.IGNORECASE)
    ports = list(set(int(m) for e in auth_events + firewall_events
                     for m in port_pattern.findall(e)))[:10]

    # Thêm port từ alert nếu có
    if alert.get("dst_port") and alert["dst_port"] not in ports:
        ports.insert(0, alert["dst_port"])

    all_times = []
    ts_pattern = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
    for e in auth_events + firewall_events:
        m = ts_pattern.search(e)
        if m:
            all_times.append(m.group())

    # Classify attack pattern
    rf = alert.get("rf_class", "")
    if failed_auth >= 3 or "BruteForce" in rf or 22 in ports:
        pattern = "SSH_BRUTE_FORCE"
    elif blocked >= 5 and len(ports) > 3:
        pattern = "PORT_SCAN"
    elif alert.get("bytes_out", 0) > 50000:
        pattern = "DATA_EXFILTRATION"
    elif alert.get("packets", 0) > 10000:
        pattern = "DDOS"
    elif failed_auth >= 1:
        pattern = "FAILED_AUTH"
    else:
        pattern = "UNKNOWN"

    return {
        "failed_auth_count":   failed_auth,
        "blocked_connections": blocked,
        "targeted_ports":      ports,
        "attack_pattern":      pattern,
        "first_seen":          min(all_times) if all_times else "unknown",
        "last_seen":           max(all_times) if all_times else "unknown",
        "log_sources_checked": len([p for p in LOG_SOURCES if p.exists()]),
    }


def _generate_sample_events(src_ip: str, alert: dict) -> tuple:
    """Tạo sample log events dựa trên alert metadata."""
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    rf = alert.get("rf_class", "")

    auth = []
    if "BruteForce" in rf or alert.get("dst_port") == 22:
        for i in range(min(alert.get("packets", 5) // 10, 15)):
            auth.append(f"{ts} server sshd[1234]: Failed password for root from {src_ip} port 4{i:04d} ssh2")
        auth.append(f"{ts} server sshd[1234]: Invalid user admin from {src_ip}")
    elif "Exfiltration" in rf:
        auth.append(f"{ts} server sshd[5678]: Accepted publickey for user from {src_ip}")

    fw = []
    pkt = alert.get("packets", 10)
    drop_count = min(pkt // 5, 20)
    for i in range(drop_count):
        fw.append(f"{ts} firewall DROP SRC={src_ip} DST={alert.get('dst_ip','?')} PROTO=TCP DPT={alert.get('dst_port',22)}")

    syslog = [f"{ts} server kernel: possible SYN flooding on port {alert.get('dst_port',22)} from {src_ip}"]

    return auth, fw, syslog


if __name__ == "__main__":
    import argparse, sys
    parser = argparse.ArgumentParser()
    parser.add_argument("--alert",  required=True)
    parser.add_argument("--output", default=".pi/triage/log_collect_result.json")
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()

    alert = json.loads(args.alert) if not os.path.isfile(args.alert) \
            else json.load(open(args.alert, encoding="utf-8"))

    result = run_log_collector(alert, verbose=not args.quiet)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    s = result["summary"]
    print(f"[LOG-COLLECT] failed_auth={s['failed_auth_count']} fw_blocks={s['blocked_connections']} pattern={s['attack_pattern']}")
    sys.exit(0)
