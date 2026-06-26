---
name: mitre-mapper-agent
model: none
description: >
  Stage 2B — MITRE ATT&CK Mapping via ML + Embedding Scoring.
  Chạy SONG SONG với ml-classifier-agent.
  Thuần Python, không cần LLM — cực nhanh (~1s).
---

## Nhiệm vụ
Ánh xạ alert + Stage 1 data → MITRE ATT&CK techniques bằng ML model đã train
hoặc cosine similarity (fallback). Chạy hoàn toàn local, không gọi API.

## Phương pháp — Thứ tự ưu tiên

Hệ thống tự chọn phương pháp tốt nhất có sẵn theo thứ tự:

### Ưu tiên 1 — RandomForestClassifier (đang dùng thực tế)
- Model file: `data/training/sklearn_model.pkl`
- Train trên: `data/training/labeled.jsonl` (20,435 mẫu từ CICIDS2017)
- Accuracy: 86% (weighted avg), BENIGN 96%, DDoS 95%, BruteForce 84%
- Output: probability vector cho mỗi class → top-5 theo probability
- `best_similarity` = max(proba) thay vì cosine score

### Ưu tiên 2 — Cosine similarity với trained centroids (fallback)
- Model file: `data/training/signatures.json`
- Centroid vectors tính từ training data thực tế
- Dùng khi không có `sklearn_model.pkl`

### Ưu tiên 3 — Cosine similarity với hand-crafted signatures (fallback cuối)
- Hardcode trong `src/agents/mitre_mapper.py` → `MITRE_SIGNATURES`
- 9 technique vectors thiết kế thủ công (không train)
- Dùng khi không có cả 2 model file trên

## Anomaly Detection (chạy độc lập với classify)
- Model: `data/training/isolation_model.pkl` (IsolationForest, contamination=5%)
- Chạy TRƯỚC khi classify, kết quả KHÔNG thay đổi output classify
- Chỉ thêm field `is_anomaly` và `anomaly_score` vào output
- Score càng âm = càng bất thường (threshold: -1 = anomaly)

## Ngưỡng
- `best_similarity ≥ 0.70` AND `best_technique != "BENIGN"` → `is_known_technique = True`
- Nếu `is_known_technique = False` → Stage 2C sẽ override bằng investigator findings

## MITRE Classes được support
| Class | MITRE ID | Tactic |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1110.001-TOR | Brute Force via Tor | Credential Access |
| T1595.001 | Active Scanning: IP Blocks | Reconnaissance |
| T1595.002 | Active Scanning: Vuln Scan | Reconnaissance |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1071.004 | Application Layer: DNS (Tunneling) | Command and Control |
| T1498 | Network Denial of Service | Impact |
| T1071.001 | Application Layer: Web Protocol (C2) | Command and Control |
| BENIGN | False Positive / Benign Traffic | N/A |

## Feature Vector (10 dimensions)
| Dim | Feature | Source | Ghi chú |
|---|---|---|---|
| 0 | threat_score / 100 | Recon (AbuseIPDB) | 0 = IP chưa có lịch sử xấu |
| 1 | log1p(failed_auth) / log1p(100) | Logs | Log scale, cao = brute force |
| 2 | log1p(fw_blocks) / log1p(50) | Logs | Số lần firewall chặn |
| 3 | log1p(pps) / log1p(500) | PCAP | Packets/sec, cao = scan/flood |
| 4 | bytes_per_packet / 1500 | PCAP | Nhỏ = brute/scan, lớn = exfil |
| 5 | log1p(bytes_out/bytes_in) / log1p(100) | PCAP | Asymmetry, cao = exfil |
| 6 | payload_entropy / 8.0 | PCAP | Cao = encrypted/C2/exfil |
| 7 | is_tor (0.0 hoặc 1.0) | Recon | Tor exit node |
| 8 | anomaly_count / 6.0 | PCAP | Số anomaly indicators |
| 9 | ml_confidence | Alert gốc | Confidence từ IDS ban đầu |

## Lưu ý quan trọng
- `threat_score` (dim 0) có ảnh hưởng lớn trong RandomForest — IP mới/chưa biết
  sẽ có score=0 dù đang tấn công, khiến model dễ classify sai thành BENIGN
- Trường hợp này xảy ra với DDOS-001: score=0 → RF → BENIGN, nhưng Stage 2C
  override đúng thành T1498.001 dựa trên traffic pattern thực tế

## Protocol

```bash
python3 -m src.agents.mitre_mapper \
  --alert '{{alert_json}}' \
  --stage1-result .pi/triage/stage1_merged.json \
  --output .pi/triage/mitre_result.json
```

## Output Schema

```json
{
  "query_vector":        [0.0, 0.0, 0.0, 0.85, 0.04, 0.01, 0.56, 0.0, 0.5, 0.95],
  "top_techniques":      [
    {"technique_id": "T1498", "name": "Network DoS", "tactic": "Impact", "similarity": 0.92},
    {"technique_id": "T1595.001", "name": "Active Scanning", "tactic": "Recon", "similarity": 0.71}
  ],
  "best_technique":      "T1498",
  "best_technique_name": "Network Denial of Service",
  "best_tactic":         "Impact",
  "best_similarity":     0.92,
  "is_known_technique":  true,
  "is_anomaly":          false,
  "anomaly_score":       -0.52,
  "model_used":          "sklearn:RandomForestClassifier",
  "technique_risk_score": 0.74
}
```
