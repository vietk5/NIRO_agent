---
name: batch-worker
description: >
  Subagent xử lý 1 alert độc lập trong batch pipeline.
  Được spawn bởi batch orchestrator, chạy full NIRO pipeline,
  lưu kết quả và thoát.
---

# Batch Worker Subagent

Đây là **subagent worker** — chạy như một PI instance độc lập cho 1 alert.
Được gọi bởi `run-batch` skill thông qua `batch_parallel.py`.

## Nhiệm vụ

Nhận 1 alert JSON → chạy full pipeline → lưu report → return kết quả.

## Input

```json
{
  "alert_id": "AUTO-001",
  "src_ip":   "185.220.101.34",
  "rf_class": "BruteForce",
  "ml_confidence": 0.91
}
```

## Execution

```bash
python3 scripts/test_full_pipeline.py --alert <alert_tmp_file> --save
```

## Output

- Report: `reports/<alert_id>_report.md`
- Pipeline cache: `logs/pipeline_cache/<alert_id>.json`
- Audit log: `logs/niro_audit.log` (SHA-256 tamper-evident chain)

## Isolation

- Mỗi worker chạy trong subprocess riêng → lỗi 1 alert không ảnh hưởng alert khác
- Không share state với worker khác
- Timeout: 300s mặc định (configurable trong pipeline.yaml → stage3a_response.timeout_sec)

## Concurrency Model

```
Orchestrator (batch_parallel.py)
  │
  ├── asyncio.Semaphore(MAX_CONCURRENT=3)
  │
  ├── Worker-01 subprocess ─── Alert-001
  ├── Worker-02 subprocess ─── Alert-002
  ├── Worker-03 subprocess ─── Alert-003
  │                            (chờ semaphore)
  ├── Worker-04 subprocess ─── Alert-004  ← start khi 1 trong 3 xong
  └── Worker-05 subprocess ─── Alert-005
```

## Khi nào dùng trực tiếp

Không nên gọi agent này trực tiếp. Dùng skill `run-batch` thay thế:

```
Bạn: chạy hết alert trong data/input/alerts/
PI:  [dùng skill run-batch → gọi batch_parallel.py → spawn workers]
```
