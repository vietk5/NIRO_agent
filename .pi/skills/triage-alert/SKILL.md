---
description: "Triage nhanh một alert hoặc IP — đánh giá sơ bộ mà không cần chạy full pipeline"
---

# Skill: triage-alert

Triage nhanh một alert — chỉ chạy Stage 0, không chạy full pipeline.

## Khi nào dùng
- User muốn đánh giá sơ bộ nhanh một IP hoặc alert
- User hỏi "IP này có nguy hiểm không", "nên escalate không"
- Muốn kiểm tra routing trước khi chạy full pipeline

## Cách thực hiện

```bash
python3 -m src.agents.triage_agent \
  --alert '<alert_json>' \
  --output .pi/triage/triage_result.json
```

Sau đó đọc `.pi/triage/triage_result.json` và giải thích:
- `action`: escalate / monitor / close_fp
- `priority`: 1–10
- `justification`: lý do

## Output cho user

```
🔍 Triage Result:
  IP:          185.220.101.34
  Decision:    ESCALATE
  Priority:    9/10
  Reason:      High-confidence BruteForce (94%), suspicious source IP
  Next step:   Chạy full pipeline? → dùng skill run-pipeline
```
