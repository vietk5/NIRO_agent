# NIRO-PI — Network Incident Response Orchestrator

Hệ thống phân tích và phản ứng sự cố mạng tự động sử dụng LLM.
Chạy trên **PI framework** 

## Quick Start

### 1. Cài đặt
```bash
pip install -r requirements.txt
```

### 2. Cấu hình API key
Tạo file `.env` ở thư mục gốc (chưa có sẵn `.env.example` trong repo). `get_llm_client()` tự chọn backend theo key nào tồn tại — ưu tiên Anthropic trước:
```bash
# Dùng Claude (ưu tiên nếu có cả 2 key)
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-5      # optional, đây là default

# Hoặc dùng OpenAI-compatible (OpenAI, DeepSeek, ...)
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.deepseek.com   # optional, default là api.openai.com/v1
OPENAI_MODEL=deepseek-chat                 # optional, default là gpt-4o
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
            ↓ (action != close_fp)
        Stage 1: Scatter × 3 (parallel, 30s timeout mỗi task)
        ├── 1A Recon (AbuseIPDB + VirusTotal + port scan + whois — LLM tool-loop)
        ├── 1B Log Collection (data/input/logs/ → auth/fw/syslog, rule-based)
        └── 1C PCAP Analysis (scapy / metadata fallback, rule-based)
            ↓
        Stage 2: Scatter × 2 (parallel, 60s timeout mỗi task)
        ├── 2A ML Classifier (LLM phân loại + MITRE_KB containment playbook)
        └── 2B MITRE Mapper (RandomForest/cosine similarity + IsolationForest anomaly check)
            ↓
        Stage 2C: Orchestrator + Investigator Subagents (sequential, 120s timeout)
        ├── So sánh 2A vs 2B → AGREE (xác nhận) hay CONFLICT (cần giải quyết)
        ├── spawn_subagent() → bruteforce / ddos / portscan / general investigator
        └── finalize_investigation() → verdict cuối cùng (ưu tiên cao nhất)
            ↓
        Stage 3A: Response (conditional — human approval cho block_ip/isolate_host)
        Stage 3B: Report (always runs → reports/ + results/ folder)
```

Toàn bộ pipeline được khai báo và có thể chỉnh trực tiếp ở **`pipeline.yaml`** (bật/tắt từng stage hoặc từng agent, parallel ↔ sequential, timeout mỗi stage).

## Biến môi trường

| Biến | Mặc định (trong code) | Ý nghĩa |
|------|----------|---------|
| `ANTHROPIC_API_KEY` | — | Dùng backend Claude, được ưu tiên nếu có |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-5` | Model Claude |
| `OPENAI_API_KEY` | — | Dùng backend OpenAI-compatible (OpenAI, DeepSeek, ...) nếu không có ANTHROPIC_API_KEY |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | Đổi sang `https://api.deepseek.com` để dùng DeepSeek |
| `OPENAI_MODEL` | `gpt-4o` | Đổi sang `deepseek-chat` nếu dùng DeepSeek |
| `STAGE1_TIMEOUT_SEC` | `30` | Timeout Stage 1 (giây) |
| `STAGE2_TIMEOUT_SEC` | `60` | Timeout Stage 2 (giây) |
| `APPROVAL_TIMEOUT_SEC` | `120` | Human approval timeout |
| `NIRO_AUTO_APPROVE` | `0` | Set `1` để tự động approve (lab mode) |

## Human Approval

Khi response agent cần block IP hoặc isolate host:
1. Ghi `logs/pending_approval.json` — chứa action cần approve
2. Chờ user tạo `logs/approval_response.txt` với nội dung `APPROVED` hoặc `REJECTED`
3. Timeout → action bị skip

**Lab mode** (bỏ qua approval): `NIRO_AUTO_APPROVE=1 python3 scripts/full_pipeline.py ...`

## Chạy trực tiếp (không qua PI)

```bash
# Single alert từ file
PYTHONIOENCODING=utf-8 python3 scripts/full_pipeline.py --alert data/input/alerts/bruteforce.json --save

# Auto approve + quiet
NIRO_AUTO_APPROVE=1 PYTHONIOENCODING=utf-8 python3 scripts/full_pipeline.py --alert data/input/alerts/bruteforce.json --save --quiet

# Resume sau khi đã approve (chỉ chạy lại Stage 3A+3B, dùng state cache)
PYTHONIOENCODING=utf-8 python3 scripts/full_pipeline.py --alert data/input/alerts/bruteforce.json --save --resume

# Batch (nhiều alerts song song)
PYTHONIOENCODING=utf-8 python3 scripts/batch_parallel.py --dir data/input/alerts/ --max-concurrent 3
```

## Output

- **Reports**: `reports/{ip}_{timestamp}_incident.md` — Markdown IR report (khi có `--save`)
- **Pipeline results**: `results/{ip}_{timestamp}_pipeline.json` — raw output, dùng làm dữ liệu training sau này
- **Audit log**: `logs/audit.jsonl` — tamper-evident chain các action đã thực hiện
- **Pipeline cache**: `logs/pipeline_cache/{alert_id}.json` — state trước Stage 3A, dùng cho `--resume`
- **Approval**: `logs/pending_approval.json` — pending action (nếu có)

## File quan trọng

- `scripts/full_pipeline.py` — entry point, asyncio scatter/gather toàn bộ 6 stage
- `src/agents/ml_classifier.py` — Stage 2A: LLM classify + tra `MITRE_KB` lấy containment steps
- `src/agents/mitre_mapper.py` — Stage 2B: RandomForest/cosine similarity → MITRE ATT&CK + IsolationForest anomaly check
- `src/agents/orchestrator_agent.py` — Stage 2C: Orchestrator LLM điều phối Investigator subagents
- `src/agents/investigators/` — 4 investigator subagent (bruteforce, ddos, portscan, general)
- `src/agents/response_agent.py` — Stage 3A: human-in-the-loop approval
- `src/agents/log_collector.py` — Stage 1B: đọc từ `data/input/logs/`
- `scripts/train_sklearn.py` / `scripts/train_isolation.py` — train model cho Stage 2B (xem `data/training/README.md`)
- `pipeline.yaml` — bật/tắt stage, agent, đổi parallel/sequential, timeout
- `.pi/chains/niro_pipeline_chain.md` — PI chain definition (đặc tả đầy đủ 6 stage)
- `.pi/skills/` — 4 PI skills: run-pipeline, analyze-logs, run-batch, triage-alert

## Cấu trúc thư mục

```
niro-pi/
├── .pi/
│   ├── agents/          ← PI agent docs (1 file mô tả mỗi agent)
│   ├── chains/          ← Pipeline chain config (niro_pipeline_chain.md)
│   ├── prompts/         ← LLM system prompts
│   └── skills/          ← PI skills (run-pipeline, analyze-logs, run-batch, triage-alert)
├── src/
│   ├── agents/          ← Python agent implementations (kể cả investigators/)
│   ├── tools/           ← Network + threat-intel + response tools
│   └── utils/           ← Logger, safety, agent_loop (LLM tool-call loop), pipeline_config
├── scripts/             ← full_pipeline.py, batch_parallel.py, các script train_*.py
├── data/
│   ├── input/           ← ĐẶT DỮ LIỆU THỰC TẾ VÀO ĐÂY (alerts/ logs/ pcap/)
│   └── training/        ← labeled.jsonl + sklearn_model.pkl + isolation_model.pkl
├── logs/                ← Runtime logs, pipeline_cache/, approval files
├── reports/             ← Generated IR reports (.md)
├── results/             ← Raw pipeline JSON (nguồn dữ liệu training)
├── pipeline.yaml        ← Config bật/tắt stage + parallel/sequential
└── requirements.txt
```
