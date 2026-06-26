"""
train_signatures.py — Tầng 1: Centroid Training

Đọc labeled.jsonl → tính centroid vector cho từng MITRE class
→ ghi ra data/training/signatures.json

Cách dùng:
    python scripts/train_signatures.py
    python scripts/train_signatures.py --input data/training/labeled.jsonl --visualize

Kết quả: data/training/signatures.json được tải tự động bởi mitre_mapper.py
"""

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path


LABELED_PATH    = Path("data/training/labeled.jsonl")
SIGNATURES_OUT  = Path("data/training/signatures.json")
REPORT_OUT      = Path("data/training/signatures_report.txt")

# Tên chiều của feature vector — để in báo cáo
FEATURE_NAMES = [
    "threat_score", "failed_auth", "fw_blocks", "pps",
    "bytes_per_pkt", "sym_ratio", "entropy", "is_tor",
    "anomaly_cnt", "ml_confidence",
]

# Map label → metadata (để output đầy đủ)
LABEL_META = {
    "T1110.001":     {"name": "Brute Force: Password Guessing",         "tactic": "Credential Access"},
    "T1110.001-TOR": {"name": "Brute Force via Tor",                    "tactic": "Credential Access"},
    "T1595.001":     {"name": "Active Scanning: Scanning IP Blocks",    "tactic": "Reconnaissance"},
    "T1595.002":     {"name": "Active Scanning: Vulnerability Scanning","tactic": "Reconnaissance"},
    "T1041":         {"name": "Exfiltration Over C2 Channel",           "tactic": "Exfiltration"},
    "T1071.004":     {"name": "Application Layer Protocol: DNS",        "tactic": "Command and Control"},
    "T1498":         {"name": "Network Denial of Service",              "tactic": "Impact"},
    "T1071.001":     {"name": "Application Layer Protocol: Web",        "tactic": "Command and Control"},
    "BENIGN":        {"name": "False Positive / Benign Traffic",        "tactic": "N/A"},
}


def load_labeled(path: Path) -> list[dict]:
    """Đọc labeled.jsonl — chỉ lấy sample đã confirmed."""
    samples = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            obj = json.loads(line)
            if obj.get("confirmed", True):
                samples.append(obj)
    return samples


def compute_centroids(samples: list[dict]) -> dict[str, list[float]]:
    """Tính centroid (mean vector) cho từng class."""
    buckets: dict[str, list[list[float]]] = defaultdict(list)
    for s in samples:
        label = s.get("true_label", "UNKNOWN")
        vec   = s["feature_vector"]
        buckets[label].append(vec)

    centroids = {}
    for label, vecs in buckets.items():
        n = len(vecs)
        dim = len(vecs[0])
        centroid = [round(sum(vecs[i][d] for i in range(n)) / n, 4) for d in range(dim)]
        centroids[label] = centroid
    return centroids


def print_report(centroids: dict, samples: list):
    """In báo cáo đẹp ra stdout."""
    counts = defaultdict(int)
    for s in samples:
        counts[s["true_label"]] += 1

    print("\n" + "="*65)
    print(f"  NIRO Training Report — Centroid Signatures")
    print("="*65)
    print(f"  {'Class':<20s} {'Samples':>7s}  {'Top-3 features (max dim)'}")
    print("-"*65)

    for label, vec in centroids.items():
        n = counts.get(label, 0)
        # Top 3 dimensions by value
        top3 = sorted(enumerate(vec), key=lambda x: x[1], reverse=True)[:3]
        top3_str = ", ".join(f"{FEATURE_NAMES[i]}={v:.2f}" for i, v in top3)
        print(f"  {label:<20s} {n:>7d}  {top3_str}")

    print("="*65)
    print(f"  Total samples: {len(samples)}  |  Classes: {len(centroids)}")
    print("="*65 + "\n")


def visualize_vectors(centroids: dict):
    """Heatmap ASCII đơn giản để xem sự khác biệt giữa classes."""
    print("Feature Vector Heatmap (0=░  0.5=▒  1=█)")
    print(f"  {'':20s} " + " ".join(f"{n[:4]:>4s}" for n in FEATURE_NAMES))
    for label, vec in centroids.items():
        bar = " ".join(_shade(v) + "   " for v in vec)
        print(f"  {label:<20s} {bar}")
    print()


def _shade(v: float) -> str:
    if v < 0.25:  return "░"
    if v < 0.5:   return "▒"
    if v < 0.75:  return "▓"
    return "█"


def build_signatures_json(centroids: dict) -> dict:
    """Tạo dict theo format MITRE_SIGNATURES của mitre_mapper.py."""
    result = {}
    for label, vec in centroids.items():
        meta = LABEL_META.get(label, {"name": label, "tactic": "Unknown"})
        result[label] = {
            "name":        meta["name"],
            "tactic":      meta["tactic"],
            "vector":      vec,
            "description": f"Learned centroid from training data ({label})",
            "trained":     True,
        }
    return result


def main():
    parser = argparse.ArgumentParser(description="Train MITRE signature vectors from labeled data")
    parser.add_argument("--input",     default=str(LABELED_PATH), help="Path to labeled.jsonl")
    parser.add_argument("--output",    default=str(SIGNATURES_OUT), help="Output signatures.json")
    parser.add_argument("--visualize", action="store_true", help="Print ASCII heatmap")
    parser.add_argument("--min-samples", type=int, default=1,
                        help="Bỏ qua class có ít hơn N samples")
    args = parser.parse_args()

    input_path  = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"[ERROR] Không tìm thấy {input_path}")
        print("Hãy đặt labeled samples vào file này theo format:")
        print('  {"feature_vector":[...10 nums...],"true_label":"T1110.001","confirmed":true}')
        return 1

    # Load + filter
    samples = load_labeled(input_path)
    if not samples:
        print("[ERROR] Không có sample nào (confirmed=true) trong file")
        return 1

    # Filter by min samples
    counts = defaultdict(int)
    for s in samples:
        counts[s["true_label"]] += 1
    samples = [s for s in samples if counts[s["true_label"]] >= args.min_samples]

    print(f"[TRAIN] Loaded {len(samples)} confirmed samples")

    # Compute
    centroids  = compute_centroids(samples)
    signatures = build_signatures_json(centroids)

    # Report
    print_report(centroids, samples)
    if args.visualize:
        visualize_vectors(centroids)

    # Ghi report ra file .txt
    counts = defaultdict(int)
    for s in samples:
        counts[s["true_label"]] += 1
    lines = [
        "NIRO — Centroid Signatures Training Report",
        f"Dataset: {args.input}  |  Samples: {len(samples)}",
        "=" * 65,
        f"  {'Class':<20s} {'Samples':>7s}  {'Top-3 features (max dim)'}",
        "-" * 65,
    ]
    for label, vec in centroids.items():
        n    = counts.get(label, 0)
        top3 = sorted(enumerate(vec), key=lambda x: x[1], reverse=True)[:3]
        top3_str = ", ".join(f"{FEATURE_NAMES[i]}={v:.2f}" for i, v in top3)
        lines.append(f"  {label:<20s} {n:>7d}  {top3_str}")
    lines += ["=" * 65, f"  Total: {len(samples)} samples  |  {len(centroids)} classes"]
    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"[TRAIN] Report saved → {REPORT_OUT}")

    # Save signatures JSON
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(signatures, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[TRAIN] Signatures saved → {output_path}")
    print(f"[TRAIN] mitre_mapper.py sẽ tự load file này khi chạy pipeline\n")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
