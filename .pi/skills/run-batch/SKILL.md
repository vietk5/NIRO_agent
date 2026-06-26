---
description: "Xử lý batch tất cả alerts trong data/input/alerts/ cùng một lúc"
---

# Skill: run-batch (Parallel Subagent Mode)

Xử lý batch alerts — **mỗi alert là 1 subagent subprocess độc lập**, chạy song song.

## Kiến trúc

```
run-batch skill
    │
    └── batch_parallel.py  (orchestrator)
          │
          ├── Semaphore(MAX_CONCURRENT)
          │
          ├── subprocess → full_pipeline.py --alert alert_001.json  [Worker 1]
          ├── subprocess → full_pipeline.py --alert alert_002.json  [Worker 2]
          ├── subprocess → full_pipeline.py --alert alert_003.json  [Worker 3]
          │                   (queue, chờ slot trống)
          └── asyncio.gather() → summary table

Mỗi worker chạy full pipeline:
  Stage 0 Triage → Stage 1 parallel → Stage 2 parallel → Stage 2C Subagent → Stage 3A Response → Stage 3B Report
```

## Khi nào dùng
- User muốn xử lý nhiều alerts cùng lúc
- User nói "chạy hết", "process all alerts", "batch mode"
- Có nhiều file .json trong `data/input/alerts/`

## Chế độ approval

**Auto approve (mặc định):** Pipeline tự approve block action, không hỏi từng alert.
```bash
python3 scripts/batch_parallel.py --dir data/input/alerts/ --max-concurrent 3
```

**Human review (production mode):** Thêm `--no-auto-approve` khi user nói:
- "no auto approve", "production mode", "hỏi tôi từng cái", "cần review", "không tự approve"
```bash
python3 scripts/batch_parallel.py --dir data/input/alerts/ --max-concurrent 3 --no-auto-approve
```
Khi dùng `--no-auto-approve`, mỗi alert cần approval riêng — pipeline sẽ dừng và hỏi analyst trước khi block IP.

## Cấu hình (flags)

| Flag | Default | Ý nghĩa |
|---|---|---|
| `--max-concurrent` | 3 | Số subagent chạy song song cùng lúc |
| `--timeout` | 300 | Timeout mỗi pipeline (giây) — pipeline đơn ~116s, cần buffer khi chạy song song |
| `--no-auto-approve` | False | Yêu cầu human approval per alert |
| `--dir` | data/input/alerts/ | Thư mục chứa alert files |
| `--file` | — | File JSON chứa list alerts |

## Cách thực hiện

### Bước 1 — Kiểm tra input
Liệt kê files trong `data/input/alerts/`:
- Nếu không có → báo user cần đặt alert JSON vào thư mục đó
- Nếu có → tiếp tục

### Bước 2 — Chạy parallel batch

**Trường hợp thông thường (alerts từng file riêng):**
```bash
python3 scripts/batch_parallel.py --dir data/input/alerts/ --max-concurrent 3
```

**Trường hợp có file batch sẵn:**
```bash
python3 scripts/batch_parallel.py --file data/input/alerts/_batch.json
```

**Tùy chỉnh concurrency và timeout:**
```bash
python3 scripts/batch_parallel.py --max-concurrent 5 --timeout 180
```

**Cần human approval (production mode):**
```bash
python3 scripts/batch_parallel.py --no-auto-approve
```

### Bước 3 — Đọc summary và báo cáo

Script tự in summary table khi xong. Đọc thêm từ `results/batch_<timestamp>.json`:

```python
import json
from pathlib import Path
result = json.loads(sorted(Path("results").glob("batch_*.json"))[-1].read_text())
```

Báo cáo cho user dạng bảng:

| Alert ID | IP | Outcome | Severity | Time | Report |
|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... |

## Notes
- **Isolation**: lỗi 1 subagent không ảnh hưởng subagent khác
- **Timeout**: mỗi pipeline có timeout riêng, không block toàn bộ batch
- Reports lưu trong `reports/`
- Batch result JSON lưu trong `results/batch_<timestamp>.json`
- File tạm được dọn tự động sau khi worker hoàn thành
