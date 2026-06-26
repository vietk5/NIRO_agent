---
name: ml-classifier-agent
model: none
description: >
  Stage 2A — ML Classification.
  Chạy SONG SONG/tuần tự với mitre-mapper-agent.
  DeepSeek LLM phân loại incident type + severity.
  Singleton client — không load lại model mỗi lần.
---

## Nhiệm vụ
Phân loại sự cố dựa trên toàn bộ dữ liệu Stage 1 (recon + logs + PCAP).

## Quan trọng: Singleton Pattern
LLM client được khởi tạo một lần (`_CLIENT_CACHE`) và tái sử dụng.
Không gọi `get_llm_client()` nhiều lần — tránh overhead connection.

## Protocol

```bash
python3 -m src.agents.ml_classifier \
  --alert '{{alert_json}}' \
  --stage1-result .pi/triage/stage1_merged.json \
  --output .pi/triage/ml_result.json
```

## Classification Criteria

| Điều kiện | Severity |
|---|---|
| threat_score ≥ 80 AND 2+ Stage 1 nguồn đồng ý | CRITICAL |
| threat_score 60–79 OR evidence từ 1 nguồn mạnh | HIGH |
| threat_score 40–59 OR circumstantial evidence | MEDIUM |
| threat_score < 40 OR weak/single indicator | LOW |

## Output Schema

```json
{
  "classification": {
    "incident_type":    "SSH_BRUTE_FORCE",
    "severity":         "CRITICAL",
    "mitre_technique":  "T1110.001",
    "mitre_tactic":     "Credential Access",
    "confidence":       0.95,
    "is_true_positive": true,
    "rationale":        "..."
  },
  "containment_steps": ["...", "..."],
  "mitre_details":     { "name": "...", "containment": [] }
}
```

## Fallback
Nếu LLM fail → rule-based classify dựa trên rf_class và threat_score.
