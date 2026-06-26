---
name: response-agent
model: none
description: >
  Stage 3A — Containment & Response.
  SEQUENTIAL — không chạy song song.
  CẦN HUMAN APPROVAL trước khi thực hiện destructive actions.
---

## Nhiệm vụ
Thực thi các bước ngăn chặn dựa trên kết quả Stage 2.

## ⚠️ Human-in-the-Loop

Trước khi block IP hoặc isolate host, hệ thống dùng mô hình **sys.exit(2) + --resume**:

1. Ghi action cần approve → `logs/pending_approval.json`
2. Gọi `sys.exit(2)` — pipeline DỪNG HOÀN TOÀN, trả exit code 2
3. Analyst đọc `logs/pending_approval.json`, đưa ra quyết định
4. Analyst tạo file `logs/approval_response.txt` với nội dung `APPROVED` hoặc `REJECTED`
5. Chạy lại pipeline với `--resume` → Stage 3A đọc response, thực thi hoặc bỏ qua
6. `NIRO_AUTO_APPROVE=1` → bỏ qua toàn bộ flow này (lab only)

```bash
# Analyst approve:
echo "APPROVED" > logs/approval_response.txt

# Analyst reject:
echo "REJECTED" > logs/approval_response.txt

# Resume pipeline sau khi approve/reject:
python3 scripts/test_full_pipeline.py --alert <file> --resume --save
```

**Không có timeout polling** — pipeline không chờ. Timeout 300s trong pipeline.yaml
chỉ áp dụng cho toàn bộ Stage 3A execution nếu dùng `--resume`.

## Protocol

```bash
python3 -m src.agents.response_agent \
  --triage-result .pi/triage/triage_result.json \
  --stage2-result .pi/triage/stage2_merged.json \
  --alert '{{alert_json}}' \
  --output .pi/triage/response_result.json
```

## Actions

| Action | Approval Required | Điều kiện |
|---|---|---|
| create_incident_ticket | Không | severity HIGH/CRITICAL |
| notify_analyst | Không | luôn |
| block_ip_address | **CÓ** | HIGH/CRITICAL + safe_to_block |
| isolate_host | **CÓ** | CRITICAL + EXFIL/C2 |

## Safety Guards
- RFC-1918 IPs (192.168.x, 10.x, 172.16-31.x) → KHÔNG BAO GIỜ block
- Critical services (8.8.8.8, 1.1.1.1) → cần manual review
- Mọi action đều được log với SHA-256 hash

## Output Schema

```json
{
  "ticket_id":     "INC-20260611-DEMO-001",
  "actions_taken": ["created_ticket:INC-...", "notified_analyst", "blocked_ip:x.x.x.x"],
  "blocked_ips":   ["x.x.x.x"],
  "severity":      "CRITICAL"
}
```
