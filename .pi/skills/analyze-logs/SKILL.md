---
description: "Phân tích log files trong data/input/logs/ để tìm dấu hiệu tấn công"
---

# Skill: analyze-logs

Phân tích log files từ `data/input/logs/` — tìm evidence của attack.

## Khi nào dùng
- User thêm log files vào `data/input/logs/`
- User hỏi "phân tích log này", "có gì đáng ngờ trong log không"
- User muốn extract evidence trước khi tạo alert

## Data Input Structure

```
data/input/logs/
├── auth.log        ← SSH failed logins, sudo events
├── firewall.log    ← DROP/REJECT entries, blocked connections
├── syslog.log      ← General system events
└── audit.jsonl     ← Structured audit events (JSON lines)
```

## Cách thực hiện

### Bước 1 — Kiểm tra files có trong data/input/logs/
```
List files in data/input/logs/
```

### Bước 2 — Phân tích từng file

Đọc và phân tích log files:
- **auth.log**: đếm failed password, invalid user, tìm IP nguồn
- **firewall.log**: đếm DROP/REJECT, tìm IP lặp lại
- **syslog.log**: tìm kernel warnings, connection floods

### Bước 3 — Extract thông tin và suggest alert

Từ log data, tạo alert JSON:
```json
{
  "src_ip":        "<IP tìm được>",
  "rf_class":      "<loại attack>",
  "ml_confidence": 0.85,
  "description":   "Found in logs: X failed auths, Y fw blocks"
}
```

### Bước 4 — Hỏi user
"Tôi tìm thấy evidence của [attack_type] từ IP [ip].
Bạn có muốn chạy full pipeline không?"

Nếu có → gọi skill `run-pipeline` với alert vừa tạo.

## Pattern nhận diện trong logs

| Log Pattern | Attack Type |
|---|---|
| "Failed password for" × nhiều lần | SSH Brute Force |
| "Invalid user" × nhiều lần | Credential Stuffing |
| "DROP SRC=x.x.x.x" × nhiều lần | Port Scan / DDoS |
| Bytes_out >> Bytes_in | Data Exfiltration |
| "SYN flooding on port" | DDoS |
