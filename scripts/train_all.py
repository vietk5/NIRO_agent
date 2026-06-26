"""
train_all.py — Unified training pipeline cho NIRO

Chạy tất cả 3 bước training theo thứ tự:
  1. Centroid signatures (train_signatures.py)
  2. Sklearn RandomForest  (train_sklearn.py)
  3. Isolation Forest      (train_isolation.py)

Cách dùng:
    # Train tất cả từ labeled.jsonl hiện có:
    python3 scripts/train_all.py

    # Train kèm test + visualize:
    python3 scripts/train_all.py --visualize --test

    # Train với test-split 20%:
    python3 scripts/train_all.py --test-split 0.2

    # Chỉ train 1 model:
    python3 scripts/train_all.py --only signatures
    python3 scripts/train_all.py --only sklearn
    python3 scripts/train_all.py --only isolation
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

LABELED = Path("data/training/labeled.jsonl")
SKLEARN_PKL = Path("data/training/sklearn_model.pkl")
SIGNATURES_JSON = Path("data/training/signatures.json")
ISO_PKL = Path("data/training/isolation_model.pkl")


def count_dataset():
    if not LABELED.exists():
        return 0, {}
    from collections import Counter
    counts = Counter()
    total = 0
    with LABELED.open() as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    s = json.loads(line)
                    if s.get("confirmed", True):
                        counts[s.get("true_label", "?")] += 1
                        total += 1
                except:
                    pass
    return total, dict(counts)


def run_step(name: str, cmd: list[str]) -> bool:
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")
    t0 = time.time()
    result = subprocess.run(cmd, capture_output=False)
    elapsed = time.time() - t0
    ok = result.returncode == 0
    status = "OK" if ok else f"FAILED (exit {result.returncode})"
    print(f"\n  → {status} [{elapsed:.1f}s]")
    return ok


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data",          default=str(LABELED),     help="Path đến labeled.jsonl (default: data/training/labeled.jsonl)")
    parser.add_argument("--model",         default="rf",              choices=["rf", "svm", "knn"])
    parser.add_argument("--test-split",    type=float, default=0.2,   help="Fraction cho test set")
    parser.add_argument("--visualize",     action="store_true",       help="Show feature heatmap")
    parser.add_argument("--test",          action="store_true",       help="Test models sau khi train")
    parser.add_argument("--only",          default=None,
                        choices=["signatures", "sklearn", "isolation"],
                        help="Chỉ train 1 model cụ thể")
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="IsolationForest contamination (default: 0.05)")
    args = parser.parse_args()

    # Check data
    total, dist = count_dataset()
    print(f"\n[TRAIN_ALL] Dataset: {total} confirmed samples")
    if total == 0:
        print("[ERROR] Không có training data!")
        print("\nBạn cần chạy 1 trong 2 bước sau trước:")
        print("  Option A — NSL-KDD (nhanh):")
        print("    wget https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt")
        print("    python scripts/convert_nsl_kdd.py --train KDDTrain+.txt")
        print("\n  Option B — CICIDS2017 (nhiều class hơn):")
        print("    python scripts/convert_cicids.py --dir MachineLearningCSV/ --split")
        return 1

    print("  Distribution:")
    for label, n in sorted(dist.items(), key=lambda x: -x[1]):
        bar = "█" * min(n // 20, 30)
        print(f"    {label:<22s} {n:6d}  {bar}")

    # Warnings
    min_samples = min(dist.values()) if dist else 0
    if min_samples < 5:
        print(f"\n[WARN] Class có ít nhất {min_samples} samples — sklearn accuracy sẽ thấp")
        print("       Nên có ≥20 samples/class để có kết quả tốt")
    if total < 50:
        print(f"\n[WARN] Tổng {total} samples — khuyến nghị ≥200 để train tốt")

    results = {}
    steps = args.only or "all"

    # Step 1: Centroid signatures
    if steps in ("all", "signatures"):
        cmd = [sys.executable, "scripts/train_signatures.py", "--input", args.data]
        if args.visualize:
            cmd.append("--visualize")
        ok = run_step("BƯỚC 1/3: Centroid Signatures", cmd)
        results["signatures"] = ok

    # Step 2: Sklearn
    if steps in ("all", "sklearn"):
        cmd = [sys.executable, "scripts/train_sklearn.py",
               "--input", args.data,
               "--model", args.model,
               "--test-split", str(args.test_split)]
        if args.visualize:
            cmd.append("--visualize")
        ok = run_step(f"BƯỚC 2/3: Sklearn ({args.model.upper()})", cmd)
        results["sklearn"] = ok

    # Step 3: Isolation Forest
    if steps in ("all", "isolation"):
        cmd = [sys.executable, "scripts/train_isolation.py",
               "--input", args.data,
               "--contamination", str(args.contamination)]
        if args.test:
            cmd.append("--test")
        ok = run_step("BƯỚC 3/3: Isolation Forest", cmd)
        results["isolation"] = ok

    # Summary
    print(f"\n{'='*60}")
    print("  TRAINING SUMMARY")
    print(f"{'='*60}")
    all_ok = True
    for name, ok in results.items():
        icon = "✓" if ok else "✗"
        print(f"  {icon} {name}")
        if not ok:
            all_ok = False

    print(f"\n  Models saved to data/training/:")
    if SIGNATURES_JSON.exists():
        sz = SIGNATURES_JSON.stat().st_size
        print(f"    signatures.json     {sz:8,} bytes")
    if SKLEARN_PKL.exists():
        sz = SKLEARN_PKL.stat().st_size
        print(f"    sklearn_model.pkl   {sz:8,} bytes")
    if ISO_PKL.exists():
        sz = ISO_PKL.stat().st_size
        print(f"    isolation_model.pkl {sz:8,} bytes")

    if all_ok:
        print(f"\n[TRAIN_ALL] Hoàn thành! Kiểm tra với:")
        print(f"  python3 scripts/test_full_pipeline.py --alert data/input/alerts/example.json --save")
    else:
        print(f"\n[TRAIN_ALL] Có lỗi ở một số bước — kiểm tra output phía trên")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
