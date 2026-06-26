# NIRO-PI — Network Incident Response Orchestrator

Hệ thống phân tích và phản ứng sự cố mạng tự động sử dụng LLM.
Chạy trên **PI framework** — mở Claude Code trong thư mục này để dùng.

## Quick Start

### 1. Cài đặt
```bash
pip install -r requirements.txt
```

### 2. Cấu hình API key
```bash
cp .env.example .env
# Chỉnh .env: OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL
```

### 3. Thêm dữ liệu vào data/input/
```
data/input/
├── alerts/    ← Đặt file JSON alert từ IDS/SIEM vào đây
├── logs/      ← Đặt auth.log, firewall.log, syslog.log vào đây
└── pcap/      ← Đặt file PCAP vào đây (optional)
```

### 4. Chạy qua PI skills
Mở Claude Code trong thư mục `niro-pi/`, gõ:

| Lệnh | Chức năng |
|------|-----------|
| `/run-pipeline` | Xử lý alert từ `data/input/alerts/` qua full pipeline |
| `/analyze-logs` | Phân tích logs từ `data/input/logs/`, tìm attack evidence |
| `/run-batch` | Xử lý batch tất cả alerts |
| `/triage-alert` | Triage nhanh một alert |

---

## Kiến trúc Pipeline

```
Alert → Stage 0: Triage (serial, 20s timeout)
            ↓
        Stage 1: Scatter × 3 (parallel, 30s timeout mỗi task)
        ├── Recon (AbuseIPDB + port scan + whois)
        ├── Log Collection (data/input/logs/ → auth/fw/syslog)
        └── PCAP Analysis (scapy / metadata fallback)
            ↓
        Stage 2: Scatter × 2 (parallel, 60s timeout mỗi task)
        ├── ML Classifier (DeepSeek LLM → severity + containment)
        └── MITRE Mapper (cosine similarity → ATT&CK technique)
            ↓
        Stage 3A: Response (conditional — human approval required)
        Stage 3B: Report (always runs → reports/ folder)
```

## Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|------|----------|---------|
| `OPENAI_API_KEY` | — | DeepSeek/OpenAI API key |
| `OPENAI_BASE_URL` | `https://api.deepseek.com` | API endpoint |
| `OPENAI_MODEL` | `deepseek-chat` | Model name |
| `STAGE1_TIMEOUT_SEC` | `30` | Timeout Stage 1 (giây) |
| `STAGE2_TIMEOUT_SEC` | `60` | Timeout Stage 2 (giây) |
| `APPROVAL_TIMEOUT_SEC` | `120` | Human approval timeout |
| `NIRO_AUTO_APPROVE` | `0` | Set `1` để tự động approve (lab mode) |

## Human Approval

Khi response agent cần block IP hoặc isolate host:
1. Ghi `logs/pending_approval.json` — chứa action cần approve
2. Chờ user tạo `logs/approval_response.txt` với nội dung `APPROVED` hoặc `REJECTED`
3. Timeout → action bị skip

**Lab mode** (bỏ qua approval): `NIRO_AUTO_APPROVE=1 python3 scripts/test_full_pipeline.py ...`

## Chạy trực tiếp (không qua PI)

```bash
# Single alert từ file
PYTHONIOENCODING=utf-8 python3 scripts/test_full_pipeline.py --alert data/input/alerts/bruteforce.json --save

# Auto approve + quiet
NIRO_AUTO_APPROVE=1 PYTHONIOENCODING=utf-8 python3 scripts/test_full_pipeline.py --alert data/input/alerts/bruteforce.json --save --quiet

# Batch (nhiều alerts song song)
PYTHONIOENCODING=utf-8 python3 scripts/batch_parallel.py --dir data/input/alerts/ --max-concurrent 3
```

## Output

- **Reports**: `reports/<alert_id>_report.md` — Markdown IR report
- **Audit log**: `logs/niro_audit.log` — SHA-256 tamper-evident chain
- **Approval**: `logs/pending_approval.json` — pending action (nếu có)

## File quan trọng

- `src/orchestrator.py` — asyncio scatter/gather pipeline
- `src/agents/mitre_mapper.py` — Stage 2B: NLP/cosine similarity → MITRE ATT&CK
- `src/agents/response_agent.py` — Stage 3A: human-in-the-loop approval
- `src/agents/log_collector.py` — Stage 1B: đọc từ `data/input/logs/`
- `.pi/chains/incident_response_chain.md` — PI chain definition
- `.pi/skills/` — 4 PI skills: run-pipeline, analyze-logs, run-batch, triage-alert

## Cấu trúc thư mục

```
niro-pi/
├── .pi/
│   ├── agents/          ← PI agent docs
│   ├── chains/          ← Pipeline chain config
│   ├── prompts/         ← LLM system prompts
│   └── skills/          ← PI skills
├── src/
│   ├── agents/          ← Python agent implementations
│   ├── tools/           ← Network + response tools
│   └── utils/           ← Logger, safety, agent loop
├── data/
│   ├── input/           ← ĐẶT DỮ LIỆU THỰC TẾ VÀO ĐÂY
│   └── sample_alerts.json
├── logs/                ← Runtime logs + approval files
├── reports/             ← Generated IR reports
└── requirements.txt
```
