"""
train_isolation.py — Tầng 3: Isolation Forest (Anomaly Detection)

Train IsolationForest trên normal/known traffic
→ ghi ra data/training/isolation_model.pkl

IsolationForest phát hiện traffic bất thường (zero-day, novel attack)
mà không cần nhãn — unsupervised.

Cách dùng:
    pip install scikit-learn --break-system-packages
    python scripts/train_isolation.py
    python scripts/train_isolation.py --contamination 0.05

Kết quả: data/training/isolation_model.pkl
         Mitre mapper sẽ gọi predict → flag "ANOMALY" trước khi classify
"""

import argparse
import json
from pathlib import Path

LABELED_PATH  = Path("data/training/labeled.jsonl")
ISO_MODEL_OUT = Path("data/training/isolation_model.pkl")
REPORT_OUT    = Path("data/training/isolation_report.txt")

# Các class coi là "normal" để train IsolationForest
NORMAL_LABELS = {"BENIGN"}

# Feature vector cho benign/normal traffic để seed training
SYNTHETIC_NORMAL = [
    # [threat_score, failed_auth, fw_blocks, pps, bpp, sym_ratio, entropy, is_tor, anomaly_cnt, ml_conf]
    [0.0, 0.0, 0.0, 0.15, 0.85, 0.9,  0.55, 0.0, 0.0, 0.2],   # HTTP backup
    [0.0, 0.0, 0.0, 0.20, 0.78, 0.95, 0.60, 0.0, 0.0, 0.3],   # HTTPS sync
    [0.0, 0.0, 0.0, 0.10, 0.92, 0.88, 0.45, 0.0, 0.0, 0.15],  # NFS backup
    [0.05,0.0, 0.0, 0.25, 0.70, 0.80, 0.50, 0.0, 0.0, 0.25],  # Monitoring
    [0.0, 0.0, 0.0, 0.18, 0.82, 0.92, 0.58, 0.0, 0.0, 0.20],  # API call
    [0.1, 0.0, 0.0, 0.30, 0.65, 0.85, 0.52, 0.0, 0.0, 0.35],  # DevOps deploy
    [0.0, 0.0, 0.0, 0.12, 0.90, 0.95, 0.48, 0.0, 0.0, 0.10],  # DB sync
]


def load_known_vectors(path: Path, benign_only: bool = True) -> list[list[float]]:
    """Đọc vectors từ labeled.jsonl.

    benign_only=True (default): chỉ lấy BENIGN rows để IsolationForest
    học đúng baseline "bình thường".
    """
    vecs = []
    skipped = 0
    if not path.exists():
        return vecs
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            obj = json.loads(line)
            if not obj.get("confirmed", True):
                continue
            if benign_only and obj.get("true_label", "BENIGN") != "BENIGN":
                skipped += 1
                continue
            vecs.append(obj["feature_vector"])
    if benign_only and skipped:
        print(f"[TRAIN] Bỏ qua {skipped} attack samples — chỉ dùng BENIGN để train baseline")
    return vecs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",         default=str(LABELED_PATH))
    parser.add_argument("--output",        default=str(ISO_MODEL_OUT))
    parser.add_argument("--contamination", type=float, default=0.1,
                        help="Tỷ lệ anomaly dự kiến trong dữ liệu (0.05–0.2)")
    parser.add_argument("--n-estimators",  type=int,   default=200,
                        help="Số trees trong forest")
    parser.add_argument("--test",          action="store_true",
                        help="Chạy test với sample attacks để xem score")
    args = parser.parse_args()

    try:
        from sklearn.ensemble import IsolationForest
        import pickle
    except ImportError:
        print("[ERROR] scikit-learn chưa cài. Chạy: pip install scikit-learn --break-system-packages")
        return 1

    output_path = Path(args.output)

    # Dữ liệu training: CHỈ BENIGN + synthetic normal
    # IsolationForest học "bình thường" là gì → attack sẽ bị cô lập
    labeled_vecs = load_known_vectors(Path(args.input), benign_only=True)
    X_train = SYNTHETIC_NORMAL + labeled_vecs
    print(f"[TRAIN] BENIGN samples từ dataset: {len(labeled_vecs)}")
    print(f"[TRAIN] Synthetic normal: {len(SYNTHETIC_NORMAL)}")

    print(f"[TRAIN] Training IsolationForest on {len(X_train)} vectors")
    print(f"[TRAIN] contamination={args.contamination}, n_estimators={args.n_estimators}")

    iso = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_train)

    # Test: score các loại traffic
    if args.test:
        print("\nAnomaly Scores (thấp hơn = dị thường hơn, -1 = anomaly):")
        test_cases = {
            "Normal HTTP backup":   [0.0,  0.0, 0.0, 0.15, 0.85, 0.9,  0.55, 0.0, 0.0, 0.2],
            "SSH BruteForce":       [0.75, 0.87,0.82,0.28, 0.07, 0.05, 0.38, 0.0, 0.5, 0.94],
            "BruteForce via Tor":   [1.0,  0.95,0.85,0.32, 0.06, 0.04, 0.41, 1.0, 0.67,0.97],
            "Port Scan":            [0.38, 0.0, 0.55,0.88, 0.04, 0.04, 0.18, 0.0, 0.58,0.87],
            "DDoS SYN flood":       [0.82, 0.0, 0.92,1.0,  0.04, 0.02, 0.14, 0.0, 0.83,0.91],
            "Data Exfiltration":    [0.65, 0.0, 0.22,0.22, 0.78, 0.92, 0.91, 0.0, 0.42,0.72],
            "Novel/Unknown":        [0.45, 0.3, 0.4, 0.6,  0.3,  0.5,  0.7,  0.0, 0.4, 0.55],
        }
        for name, vec in test_cases.items():
            score     = iso.score_samples([vec])[0]
            decision  = iso.predict([vec])[0]
            label     = "ANOMALY" if decision == -1 else "normal"
            bar       = "🔴" if decision == -1 else "🟢"
            print(f"  {bar} {name:<25s} score={score:+.3f}  [{label}]")
        print()

    # Ghi report ra file .txt
    report_lines = [
        "NIRO — IsolationForest Training Report",
        f"Dataset: {args.input}  |  Train vectors: {len(X_train)}",
        f"contamination={args.contamination}  n_estimators={args.n_estimators}",
        "=" * 55,
    ]
    test_cases = {
        "Normal HTTP backup":   [0.0,  0.0, 0.0, 0.15, 0.85, 0.9,  0.55, 0.0, 0.0, 0.2],
        "SSH BruteForce":       [0.75, 0.87,0.82,0.28, 0.07, 0.05, 0.38, 0.0, 0.5, 0.94],
        "BruteForce via Tor":   [1.0,  0.95,0.85,0.32, 0.06, 0.04, 0.41, 1.0, 0.67,0.97],
        "Port Scan":            [0.38, 0.0, 0.55,0.88, 0.04, 0.04, 0.18, 0.0, 0.58,0.87],
        "DDoS SYN flood":       [0.82, 0.0, 0.92,1.0,  0.04, 0.02, 0.14, 0.0, 0.83,0.91],
        "Data Exfiltration":    [0.65, 0.0, 0.22,0.22, 0.78, 0.92, 0.91, 0.0, 0.42,0.72],
        "Novel/Unknown":        [0.45, 0.3, 0.4, 0.6,  0.3,  0.5,  0.7,  0.0, 0.4, 0.55],
    }
    for name, vec in test_cases.items():
        score    = iso.score_samples([vec])[0]
        decision = iso.predict([vec])[0]
        label    = "ANOMALY" if decision == -1 else "normal"
        report_lines.append(f"  [{label:^7s}] {name:<25s} score={score:+.3f}")
    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text("\n".join(report_lines), encoding="utf-8")
    print(f"[TRAIN] Report saved → {REPORT_OUT}")

    # Save model
    output_path.parent.mkdir(parents=True, exist_ok=True)
    model_data = {"model": iso, "contamination": args.contamination,
                  "n_train": len(X_train)}
    with output_path.open("wb") as f:
        pickle.dump(model_data, f)

    print(f"[TRAIN] IsolationForest saved → {output_path}")
    print(f"[TRAIN] Scorer tự động flag ANOMALY nếu score < threshold\n")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
