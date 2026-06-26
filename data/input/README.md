# Data Input Directory

Đặt dữ liệu thực tế vào đây để NIRO xử lý.

## Cấu trúc

```
data/input/
├── alerts/          ← File JSON alert từ IDS/SIEM
│   └── example.json
├── logs/            ← Log files thực tế
│   ├── auth.log     ← SSH failed logins (/var/log/auth.log)
│   ├── firewall.log ← Firewall DROP/REJECT entries
│   └── syslog.log   ← System events (/var/log/syslog)
└── pcap/            ← PCAP files (optional)
    └── README.md
```

## Cách thêm dữ liệu

### Alert JSON
```json
{
  "alert_id":      "MY-ALERT-001",
  "src_ip":        "x.x.x.x",
  "dst_ip":        "192.168.1.10",
  "dst_port":      22,
  "rf_class":      "BruteForce",
  "ml_confidence": 0.90,
  "bytes_in":      5000,
  "bytes_out":     500,
  "packets":       100,
  "duration":      30.0,
  "description":   "Mô tả ngắn"
}
```

### Log Files
Copy log files thực tế vào đây:
```bash
# Trên Linux
cp /var/log/auth.log data/input/logs/auth.log
cp /var/log/syslog data/input/logs/syslog.log

# Trên Windows (nếu có WSL)
wsl cat /var/log/auth.log > data/input/logs/auth.log
```

Format log được hỗ trợ:
- **auth.log**: `Dec 11 10:23:45 server sshd[1234]: Failed password for root from 1.2.3.4`
- **firewall.log**: `Dec 11 10:23:45 firewall DROP SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP DPT=22`
- **syslog.log**: Standard syslog format

## Chạy qua PI

Mở Claude Code trong thư mục `niro-pi/`, sau đó:
```
/run-pipeline    → xử lý alert từ data/input/alerts/
/analyze-logs    → phân tích logs từ data/input/logs/
/run-batch       → xử lý tất cả alerts
/triage-alert    → triage nhanh
```
