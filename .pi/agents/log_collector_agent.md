---
name: log-collector-agent
model: none
description: >
  Stage 1B — Log Collection.
  Chạy SONG SONG với recon-agent và pcap-agent.
  Đọc file log từ data/input/logs/ — không cần Elasticsearch/Splunk.
---

## Nhiệm vụ
Thu thập logs liên quan đến alert: auth.log, firewall log, syslog.

## Data Sources (thực tế)
- `data/input/logs/auth.log`     — SSH failed logins, sudo events
- `data/input/logs/firewall.log` — blocked/allowed connections
- `data/input/logs/syslog.log`   — system events
- Fallback: synthetic events từ alert metadata nếu file không tồn tại

Không dùng Elasticsearch/Splunk — đọc file trực tiếp từ thư mục dự án.

## Protocol

```bash
python3 -m src.agents.log_collector \
  --alert '{{alert_json}}' \
  --output .pi/triage/log_collect_result.json
```

## Output Schema

```json
{
  "summary": {
    "failed_auth_count":   0,
    "blocked_connections": 0,
    "targeted_ports":      [],
    "attack_pattern":      "SSH_BRUTE_FORCE|PORT_SCAN|DATA_EXFILTRATION|DDOS|UNKNOWN",
    "first_seen":          "...",
    "last_seen":           "..."
  },
  "auth_log_events":  [],
  "firewall_events":  [],
  "syslog_events":    []
}
```

## Cần lưu ý
- Log được lọc theo `src_ip` từ alert — chỉ lấy dòng liên quan đến IP nguồn
- Nếu file log không tồn tại → trả empty summary, KHÔNG báo lỗi
- `attack_pattern` là rule-based (đếm failed_auth, fw_blocks) — không dùng LLM
