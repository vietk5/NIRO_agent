---
name: niro-pipeline-chain
version: "4.0.0"
description: >
  Full 6-stage incident response pipeline theo mô hình Scatter/Gather + LLM Subagent Pattern.
  Entry point: scripts/full_pipeline.py (asyncio).
  Hỗ trợ --resume để skip Stage 0-2C sau khi nhận approval.
input_schema:  alert_json
output_schema: incident_report_md
state_dir:     logs/pipeline_cache/
---

## Kiến trúc tổng thể

```
Alert JSON (data/input/alerts/*.json)
         │
         ▼
╔════════════════════════════════════════════════════════════╗
║  STAGE 0: Triage Agent (serial, ~10s)                     ║
║  Entry:   run_triage(alert)                               ║
║  LLM:     run_agent() max_iterations=10                   ║
║  Tool:    route_alert(action, priority, justification)    ║
║  Output:  routing = { action, priority, justification }   ║
║                                                            ║
║  action = "close_fp"  → dừng pipeline, return ngay        ║
║  action = "monitor"   → tiếp tục (priority thấp)          ║
║  action = "escalate"  → tiếp tục đầy đủ (priority 7-10)  ║
╚══════════════════════════╦═════════════════════════════════╝
                           │ action != close_fp
                           ▼
╔════════════════════════════════════════════════════════════╗
║  STAGE 1: Parallel Data Gathering — SCATTER × 3           ║
║  asyncio.gather(recon_task, log_task, pcap_task)          ║
║  Mỗi task: loop.run_in_executor(None, lambda: ...)        ║
║                                                            ║
║  ┌──────────────────┐ ┌─────────────────┐ ┌────────────┐  ║
║  │ 1A: Recon Agent  │ │ 1B: Log Collect │ │ 1C: PCAP   │  ║
║  │ run_recon()      │ │ run_log_coll.() │ │ run_pcap() │  ║
║  │                  │ │                 │ │            │  ║
║  │ check_ip_rep.    │ │ Đọc auth.log    │ │ Flow feats │  ║
║  │ check_virustotal │ │ firewall.log    │ │ IsoForest  │  ║
║  │ scan_ports       │ │ syslog.log      │ │ sig match  │  ║
║  │ whois_lookup     │ │ → failed_auth   │ │ → anomaly  │  ║
║  │ grab_banner      │ │   fw_blocks     │ │   risk_sc. │  ║
║  │ gen_risk_profile │ │   pattern       │ │   pcap_sig │  ║
║  │                  │ │                 │ │            │  ║
║  │ Bottleneck ~30s  │ │ ~1-2s           │ │ ~1s        │  ║
║  └──────────────────┘ └─────────────────┘ └────────────┘  ║
║                                                            ║
║  GATHER 1: merge → stage1 = { recon, log_collect, pcap }  ║
║  Exception handling: lỗi 1 agent → fallback data,         ║
║                      2 agent còn lại vẫn chạy bình thường ║
╚══════════════════════════╦═════════════════════════════════╝
                           │ stage1 dict
                           ▼
╔════════════════════════════════════════════════════════════╗
║  STAGE 2: Parallel Analysis — SCATTER × 2                 ║
║  asyncio.gather(ml_task, mitre_task)                      ║
║                                                            ║
║  ┌──────────────────────────┐ ┌──────────────────────────┐ ║
║  │ 2A: ML Classifier        │ │ 2B: MITRE Mapper         │ ║
║  │ run_ml_classifier()      │ │ run_mitre_mapper()        │ ║
║  │                          │ │                          │ ║
║  │ RandomForest (sklearn)   │ │ Build 10-dim vector:     │ ║
║  │ + LLM reasoning          │ │ [threat_score,           │ ║
║  │ (singleton client,       │ │  failed_auth, fw_blocks, │ ║
║  │  threading.Lock)         │ │  pps, bpkt, sym_ratio,   │ ║
║  │                          │ │  entropy, is_tor,        │ ║
║  │ → incident_type          │ │  anomaly_cnt, ml_conf]   │ ║
║  │   severity               │ │                          │ ║
║  │   mitre_technique        │ │ sklearn_model.pkl →      │ ║
║  │   confidence             │ │   predict_proba (ưu tiên)│ ║
║  │   rationale              │ │ signatures.json →        │ ║
║  │   containment_steps      │ │   cosine similarity      │ ║
║  │                          │ │ IsolationForest →        │ ║
║  │ ~8-10s (LLM bottleneck)  │ │   anomaly detection      │ ║
║  └──────────────────────────┘ │ ~0.1-2s                  │ ║
║                               └──────────────────────────┘ ║
║                                                            ║
║  GATHER 2: stage2 = { ml, mitre }                         ║
║  So sánh: mitre_2a vs mitre_2b                            ║
║    → [AGREE]    : cùng technique                          ║
║    → [CONFLICT] : khác technique → 2C giải quyết          ║
╚══════════════════════════╦═════════════════════════════════╝
                           │ stage2 dict + AGREE/CONFLICT flag
                           ▼
╔════════════════════════════════════════════════════════════╗
║  STAGE 2C: OrchestratorAgent — LLM Subagent Pattern       ║
║  run_orchestrator(enriched_alert, stage2)                 ║
║                                                            ║
║  enriched_alert = alert + stage1_* fields + stage2_* fields║
║  _build_stage2_context() → context block 3 phần:          ║
║    Stage 1 data | Stage 2A verdict | Stage 2B verdict     ║
║                                                            ║
║  Orchestrator LLM (max_iterations=12):                    ║
║  ┌─────────────────────────────────────────────────────┐  ║
║  │  Tool: spawn_subagent(investigator_type, brief)     │  ║
║  │    → Chạy investigator (blocking, ThreadPool)       │  ║
║  │    → Trả findings về orchestrator                   │  ║
║  │                                                     │  ║
║  │  Tool: finalize_investigation(overall_risk,         │  ║
║  │         final_action, verdict_summary,              │  ║
║  │         key_findings, mitre_technique)              │  ║
║  └─────────────────────────────────────────────────────┘  ║
║                                                            ║
║  INVESTIGATOR_REGISTRY:                                   ║
║  ┌───────────────┬──────────────────────────────────────┐ ║
║  │ "bruteforce"  │ BruteForceInvestigator               │ ║
║  │               │ check_auth_log, check_ip_reputation  │ ║
║  │               │ check_virustotal, check_targeted_acc │ ║
║  ├───────────────┼──────────────────────────────────────┤ ║
║  │ "ddos"        │ DDoSInvestigator                     │ ║
║  │               │ analyze_traffic_vol, check_amplif.   │ ║
║  ├───────────────┼──────────────────────────────────────┤ ║
║  │ "portscan"    │ PortScanInvestigator                 │ ║
║  │               │ check_firewall_log, analyze_scan_pat │ ║
║  ├───────────────┼──────────────────────────────────────┤ ║
║  │ "general"     │ GeneralInvestigator                  │ ║
║  │               │ whois_lookup, port_scan,             │ ║
║  │               │ check_combined_logs                  │ ║
║  └───────────────┴──────────────────────────────────────┘ ║
║                                                            ║
║  Mỗi investigator: InvestigatorSubagent.run()             ║
║    LLM riêng (max_iterations=10) + submit_findings() tool ║
║                                                            ║
║  Priority chain:                                          ║
║    verdict(2C) > clf(2A) > cosine(2B)                     ║
║                                                            ║
║  Output: investigation = { verdict, subagent_findings,    ║
║                            spawn_log, iterations }        ║
╚══════════════════════════╦═════════════════════════════════╝
                           │ verdict + investigation
                           ▼
╔════════════════════════════════════════════════════════════╗
║  CACHE STATE (trước Stage 3A)                             ║
║  logs/pipeline_cache/{alert_id}.json                      ║
║  Lưu: alert, routing, stage1, stage2, verdict, clf...     ║
║  Dùng cho: --resume flag (skip Stage 0-2C)                ║
╚══════════════════════════╦═════════════════════════════════╝
                           │
                           ▼
╔════════════════════════════════════════════════════════════╗
║  STAGE 3A: Response Agent — Human-in-the-Loop             ║
║  run_response(risk_profile, triage_result, alert)         ║
║                                                            ║
║  final_severity: verdict.overall_risk > clf.severity      ║
║  final_mitre:    verdict.mitre > clf.mitre > cosine.mitre ║
║                                                            ║
║  Non-destructive (chạy ngay, không cần approve):          ║
║    create_incident_ticket() → INC-{date}-{alert_id}       ║
║    notify_analyst()        → #security-alerts             ║
║                                                            ║
║  Destructive (cần approve):                               ║
║    block_ip_address()  ← severity HIGH/CRITICAL           ║
║    isolate_host()      ← severity CRITICAL + EXFIL/C2     ║
║                                                            ║
║  request_approval_sync() flow:                            ║
║    1. NIRO_AUTO_APPROVE=1  → (True, False) ngay           ║
║    2. approval_response.txt tồn tại → đọc, xóa file      ║
║       → "approve/yes/y/1" → (True, False)                 ║
║       → khác             → (False, False)                 ║
║    3. Chưa có file → ghi pending_approval.json            ║
║       → print NIRO_WAITING_FOR_APPROVAL                   ║
║       → return (False, True) → sys.exit(2)                ║
║                                                            ║
║  PI phát hiện exit(2) + marker → hỏi user → ghi file     ║
║  → chạy lại với --resume (chỉ Stage 3A+3B, ~0.3s)        ║
╚══════════════════════════╦═════════════════════════════════╝
                           │
                           ▼
╔════════════════════════════════════════════════════════════╗
║  STAGE 3B: Report Agent (luôn chạy)                       ║
║  run_report(alert, triage, recon_for_report, response,    ║
║             pipeline_duration_sec)                        ║
║                                                            ║
║  Input tổng hợp từ tất cả stages:                         ║
║    risk_profile + ml_classification + mitre_techniques    ║
║    log_summary + pcap_summary + subagent_findings         ║
║    response_result (ticket, blocked_ips, actions)         ║
║                                                            ║
║  Output: reports/{ip}_{timestamp}_incident.md             ║
║  Ghi khi: --save flag được truyền                         ║
╚════════════════════════════════════════════════════════════╝
```

## Routing Logic

```python
# Stage 0 output
if action == "close_fp":
    return {"action": "close_fp"}        # pipeline dừng

# Stage 3A điều kiện chạy
should_block = (
    action == "escalate"
    and final_severity in ("HIGH", "CRITICAL")
    and is_safe_to_block(src_ip)          # không block private IP
)

# final_severity priority chain
final_severity = verdict.overall_risk.upper() or clf.severity or "LOW"

# final_mitre priority chain
final_mitre = verdict.mitre_technique or clf.mitre_technique or techniques[0].id
```

## Resume Flow (--resume flag)

```
PI ghi: echo approve > logs/approval_response.txt
PI chạy: python3 scripts/full_pipeline.py --alert <file> --save --resume

resume_from_cache(cache_file):
    1. Load logs/pipeline_cache/{alert_id}.json
    2. Recompute final_severity + final_mitre từ cached verdict/clf
    3. Chạy Stage 3A  → request_approval_sync() đọc approval_response.txt → approve
    4. Chạy Stage 3B  → tạo report
    5. cache_file.unlink()   # xóa cache sau khi xong
    6. Nếu vẫn pending → sys.exit(2)  # chưa có file
```

## State Schema

```json
{
  "alert": {
    "alert_id": "BF-001",
    "src_ip": "185.220.101.34",
    "dst_port": 22,
    "rf_class": "BruteForce",
    "ml_confidence": 0.96
  },
  "routing": {
    "action": "escalate",
    "priority": 9,
    "justification": "..."
  },
  "stage1": {
    "recon": {
      "risk_profile": {
        "threat_score": 100,
        "risk_level": "critical",
        "isTor": true,
        "open_ports": [80]
      }
    },
    "log_collect": {
      "summary": {
        "failed_auth_count": 12,
        "blocked_connections": 9,
        "attack_pattern": "SSH_BRUTE_FORCE"
      }
    },
    "pcap": {
      "flow_signature_match": "SSH_BRUTE_FORCE",
      "risk_score": 0.72,
      "anomaly_indicators": ["SSH_HIGH_RATE"],
      "flow_features": { "packets_per_sec": 9.3, "bytes_per_packet": 33.6 }
    }
  },
  "stage2": {
    "ml": {
      "classification": {
        "incident_type": "SSH_BRUTE_FORCE",
        "severity": "CRITICAL",
        "mitre_technique": "T1110.001",
        "confidence": 0.98
      },
      "containment_steps": ["Block IP", "Enable MFA", "..."]
    },
    "mitre": {
      "best_technique": "BENIGN",
      "best_similarity": 0.765,
      "is_anomaly": true,
      "anomaly_score": -0.675,
      "model_used": "sklearn:RandomForestClassifier",
      "top_techniques": [{ "technique_id": "BENIGN", "similarity": 0.765 }]
    }
  },
  "verdict": {
    "overall_risk": "critical",
    "final_action": "block",
    "mitre_technique": "T1110.001",
    "verdict_summary": "...",
    "key_findings": ["..."]
  },
  "investigation": {
    "spawn_log": [{ "investigator_type": "bruteforce", "brief": "..." }],
    "subagent_findings": [{ "subagent": "BruteForce-Investigator", "risk_level": "high" }]
  }
}
```

## Timeout & Error Handling

```
STAGE1_TIMEOUT_SEC=30   # recon, log_collect, pcap — mỗi agent riêng
STAGE2_TIMEOUT_SEC=60   # ml_classifier (LLM call)

asyncio.gather(..., return_exceptions=True)
  → Exception từ agent → fallback empty dict, pipeline tiếp tục
  → Không bao giờ block toàn bộ stage vì 1 agent lỗi
```

## Environment Variables

```
ANTHROPIC_API_KEY     → Anthropic Claude backend (ưu tiên)
OPENAI_API_KEY        → OpenAI / DeepSeek backend (fallback)
OPENAI_BASE_URL       → mặc định: https://api.deepseek.com
OPENAI_MODEL          → mặc định: deepseek-chat
STAGE1_TIMEOUT_SEC    → mặc định: 30
STAGE2_TIMEOUT_SEC    → mặc định: 60
APPROVAL_TIMEOUT_SEC  → mặc định: 120
NIRO_AUTO_APPROVE     → "1" = tự approve (lab mode)
```

## CLI Usage

```bash
# Full pipeline
python3 scripts/full_pipeline.py --alert data/input/alerts/bruteforce.json --save

# Quiet mode (ít output hơn)
python3 scripts/full_pipeline.py --alert data/input/alerts/ddos.json --save --quiet

# Resume sau khi approve (chỉ Stage 3A+3B, ~0.3s)
echo approve > logs/approval_response.txt
python3 scripts/full_pipeline.py --alert data/input/alerts/bruteforce.json --save --resume

# Lab mode (auto approve, không hỏi)
NIRO_AUTO_APPROVE=1 python3 scripts/full_pipeline.py --alert data/input/alerts/bruteforce.json --save

# Batch nhiều alerts song song
python3 scripts/batch_parallel.py --dir data/input/alerts/ --max-concurrent 3
```

## Output Files

```
reports/{ip}_{timestamp}_incident.md    ← IR report đầy đủ
logs/niro_audit.log                     ← SHA-256 tamper-evident audit trail
logs/pipeline_cache/{alert_id}.json     ← State cache trước Stage 3A (tự xóa sau resume)
logs/pending_approval.json              ← Pending action details (tự xóa sau approve)
logs/last_run.log                       ← Full output của lần chạy gần nhất (tee)
```
