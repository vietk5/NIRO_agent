---
description: "Chạy toàn bộ NIRO pipeline cho một alert hoặc IP"
---

# Skill: run-pipeline

Chạy toàn bộ NIRO pipeline cho một alert.

## Khi nào dùng
- User muốn xử lý một alert cụ thể
- User paste JSON alert vào chat
- User nói "xử lý alert này", "chạy pipeline", "analyze IP này"

## Cách thực hiện

### Bước 1 — Lấy alert input
Tìm alert JSON từ:
1. Nội dung user vừa paste vào chat
2. Files trong `data/input/alerts/` (đọc file mới nhất)
3. Nếu user chỉ cung cấp IP → tự tạo alert JSON từ IP đó

### Bước 2 — Chạy pipeline (Parallel + Subagent Mode)
Dùng `full_pipeline.py` — luồng đầy đủ:
- Stage 0: Triage
- Stage 1: **parallel** recon + log_collector + pcap_analyzer
- Stage 2: **parallel** ml_classifier + mitre_mapper
- Stage 2C: OrchestratorAgent (LLM subagent)
- Stage 3: Report

**QUAN TRỌNG**: Script chỉ có 3 flags: `--alert`, `--save`, `--quiet`. KHÔNG có `--auto-approve`.

**LUÔN xóa approval file cũ trước khi chạy** — nếu không, pipeline sẽ tự approve ngay mà không hỏi:
```bash
cd "D:/HK2_Y3/Lập trình mạng (use LLM for cyber)/cuoiky/niro-pi"
rm -f logs/approval_response.txt logs/pending_approval.json
PYTHONIOENCODING=utf-8 python3 scripts/full_pipeline.py --alert data/input/alerts/<filename>.json --save 2>&1 | tee logs/last_run.log
```

Nếu user paste JSON alert trực tiếp, ghi ra file tạm rồi chạy:
```bash
echo '<alert_json>' > data/input/alerts/_tmp.json
PYTHONIOENCODING=utf-8 python3 scripts/full_pipeline.py --alert data/input/alerts/_tmp.json --save 2>&1 | tee logs/last_run.log
```

**Output dài**: PI tự collapse output — bình thường. Full log luôn được lưu tại `logs/last_run.log`. Sau khi chạy xong, đọc log:
```bash
cat logs/last_run.log
```

**Lưu ý**: Khi output có dòng `NIRO_WAITING_FOR_APPROVAL`, pipeline đã dừng lại và cần analyst approve. Xử lý như sau:

1. Đọc dòng `NIRO_WAITING_FOR_APPROVAL alert=<file>` để lấy alert file path
2. Hỏi user: "Pipeline muốn block IP <ip>. Bạn có approve không?"
3. Nếu user nói approve/yes/có — ghi approve VÀ resume (CHỈ chạy Stage 3A+3B, không lặp lại Stage 0-2C):
```bash
echo approve > logs/approval_response.txt
PYTHONIOENCODING=utf-8 python3 scripts/full_pipeline.py --alert <alert_file> --save --resume
```
4. Nếu user nói reject/no/không:
```bash
echo reject > logs/approval_response.txt
```
Không cần chạy lại — pipeline đã kết thúc với action bị từ chối.

**QUAN TRỌNG**: Dùng `--resume` (không phải full pipeline) để tránh lặp lại Stage 0-2C (~2 phút). `--resume` chỉ mất vài giây.

### Bước 3 — Báo cáo kết quả
Sau khi chạy xong:
1. Đọc file report mới nhất trong `reports/`
2. Tóm tắt kết quả cho user: IP, severity, MITRE technique, actions taken
3. Hiển thị path đến full report

## Ví dụ

User: "chạy pipeline cho IP 185.220.101.34 đang SSH brute force"

→ Tạo alert:
```json
{
  "src_ip": "185.220.101.34",
  "dst_port": 22,
  "rf_class": "BruteForce",
  "ml_confidence": 0.95,
  "packets": 300,
  "duration": 60.0
}
```
→ Chạy: `PYTHONIOENCODING=utf-8 python3 scripts/full_pipeline.py --alert data/input/alerts/_tmp.json --save`
→ Đọc và tóm tắt report

## Notes
- Script CHỈ nhận `--alert` và `--save`. Không có `--auto-approve` hay flag nào khác.
- Nếu cần approve BLOCK action → analyst gõ: `echo approve > logs/approval_response.txt`
