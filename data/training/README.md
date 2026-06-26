# Training Data — NIRO ML Pipeline

Thư mục này chứa dữ liệu training và trained models cho NIRO classifier.

## Cấu trúc

```
data/training/
├── labeled.jsonl         ← Labeled training samples (thêm vào sau mỗi incident)
├── signatures.json       ← Trained centroid vectors (output của train_signatures.py)
├── sklearn_model.pkl     ← Trained RandomForest/SVM (output của train_sklearn.py)
└── isolation_model.pkl   ← Trained IsolationForest (output của train_isolation.py)
```

## Quy trình Training — 3 bước

### Bước 1: Thu thập dữ liệu

**Tự động từ pipeline results:**
```bash
python3 scripts/collect_training_data.py
```
Script đọc tất cả `results/*_pipeline.json`, extract feature vector + label, append vào `labeled.jsonl`.

**Thêm thủ công** (khi có log thực):
```jsonl
{"feature_vector":[0.8,0.9,0.7,0.3,0.08,0.05,0.4,0.0,0.6,0.95],"true_label":"T1110.001","incident_type":"SSH_BRUTE_FORCE","severity":"HIGH","source":"my_incident_001","confirmed":true}
```

Sau khi collect, **mở `labeled.jsonl` và set `confirmed: true`** cho các samples đã verify.

### Bước 2: Train

**Tầng 1 — Centroid (nhanh, không cần cài thêm):**
```bash
python3 scripts/train_signatures.py --visualize
```

**Tầng 2 — RandomForest (tốt hơn khi có ≥20 samples mỗi class):**
```bash
pip install scikit-learn --break-system-packages
python3 scripts/train_sklearn.py --model rf --visualize
```

**Tầng 3 — Isolation Forest (phát hiện zero-day):**
```bash
python3 scripts/train_isolation.py --test
```

### Bước 3: Verify

Chạy pipeline với alert test và kiểm tra kết quả:
```bash
python3 scripts/test_full_pipeline.py --alert data/input/alerts/example.json --save
```

Kết quả in ra `model_used` cho biết đang dùng model nào:
- `sklearn:RandomForestClassifier` — đang dùng trained RF
- `cosine_similarity` — đang dùng centroid/hand-crafted vectors

---

## Format labeled.jsonl

Mỗi dòng là một JSON object:

```json
{
  "feature_vector": [0.8, 0.9, 0.7, 0.3, 0.08, 0.05, 0.4, 0.0, 0.6, 0.95],
  "true_label":     "T1110.001",
  "incident_type":  "SSH_BRUTE_FORCE",
  "severity":       "HIGH",
  "source":         "incident_20241211_001",
  "confirmed":      true
}
```

**Feature vector (10 chiều):**

| Index | Feature | Range | Ý nghĩa |
|-------|---------|-------|---------|
| 0 | threat_score | 0–1 | AbuseIPDB score / 100 |
| 1 | failed_auth | 0–1 | log1p(failed logins) normalized |
| 2 | fw_blocks | 0–1 | log1p(firewall drops) normalized |
| 3 | pps | 0–1 | packets per second normalized |
| 4 | bytes_per_pkt | 0–1 | avg packet size / 1500 |
| 5 | sym_ratio | 0–1 | bytes_out/bytes_in normalized |
| 6 | entropy | 0–1 | payload entropy / 8 |
| 7 | is_tor | 0 or 1 | Tor exit node flag |
| 8 | anomaly_cnt | 0–1 | PCAP anomaly count / 6 |
| 9 | ml_confidence | 0–1 | Alert ML confidence |

**Labels hợp lệ:**
- `T1110.001` — SSH Brute Force
- `T1110.001-TOR` — SSH Brute Force via Tor
- `T1595.001` — Port Scan
- `T1595.002` — Vulnerability Scan
- `T1041` — Data Exfiltration
- `T1071.001` — Malware C2 (Web)
- `T1071.004` — DNS Tunneling
- `T1498` — DDoS
- `BENIGN` — False Positive / Normal traffic

---

## Khi nào nên retrain?

- Sau mỗi 10–20 incidents mới được confirm
- Khi accuracy của pipeline giảm (nhiều FP hoặc FN)
- Khi thêm loại attack mới vào môi trường
- Định kỳ 1 lần/tuần nếu có nhiều traffic

## Model priority trong mitre_mapper.py

```
sklearn_model.pkl  →  (tốt nhất, cần ≥20 samples/class)
    ↓ không có
signatures.json    →  (centroid từ train_signatures.py)
    ↓ không có
MITRE_SIGNATURES   →  (hand-crafted vectors trong code)
```

IsolationForest chạy SONG SONG với classifier (không thay thế) — chỉ thêm flag `is_anomaly`.
