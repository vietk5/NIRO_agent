---
name: triage-agent
model: none
description: >
  Stage 0 — Alert Ingestion & Triage. PI orchestrator gọi Python.
  Chuẩn hóa alert, đánh giá sơ bộ, routing.
---

## Nhiệm vụ
Tiếp nhận alert, gọi Python triage agent, lưu kết quả.

## Protocol

```bash
python3 -m src.agents.triage_agent \
  --alert '{{alert_json}}' \
  --output .pi/triage/triage_result.json
```

## Routing từ output

```json
// .pi/triage/triage_result.json
{
  "routing": {
    "action":        "escalate|monitor|close_fp",
    "priority":      8,
    "justification": "..."
  }
}
```

## Next step

- `close_fp`  → pipeline DỪNG HOÀN TOÀN tại Stage 0, không chạy Stage 1/2/3
- `monitor`   → tiếp tục Stage 1 (recon + log + pcap)
- `escalate`  → tiếp tục Stage 1 (recon + log + pcap)
