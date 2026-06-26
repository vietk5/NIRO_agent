"""
convert_cicids.py — Convert CICIDS2017 dataset → NIRO labeled.jsonl

DOWNLOAD DATASET (chọn 1 trong 2):
    Option A — CIC website (chậm):
        https://www.unb.ca/cic/datasets/ids-2017.html
        → Download "GeneratedLabelledFlows.zip" (~500MB)

    Option B — Kaggle (nhanh, cần account free):
        https://www.kaggle.com/datasets/cicdataset/cicids2017
        kaggle datasets download -d cicdataset/cicids2017

    Files cần dùng (CSV trong MachineLearningCSV/):
        Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv  ← DDoS
        Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv ← PortScan
        Tuesday-WorkingHours.pcap_ISCX.csv                ← BruteForce
        Wednesday-workingHours.pcap_ISCX.csv              ← DoS

Cách dùng:
    # Convert 1 file:
    python scripts/convert_cicids.py --input Friday-DDos.csv

    # Convert tất cả CSV trong 1 thư mục:
    python scripts/convert_cicids.py --dir MachineLearningCSV/ --max-per-class 1000

    # Tự động split train/test 80/20:
    python scripts/convert_cicids.py --dir MachineLearningCSV/ --split
"""

import argparse
import csv
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

OUTPUT_TRAIN = Path("data/training/labeled.jsonl")
OUTPUT_TEST  = Path("data/training/labeled_test.jsonl")

# ── CICIDS2017 label → MITRE mapping ──────────────────────────────────────────
LABEL_MAP = {
    "benign":                   "BENIGN",
    # DDoS
    "ddos":                     "T1498",
    "dos hulk":                 "T1498",
    "dos goldeneye":            "T1498",
    "dos slowloris":            "T1498",
    "dos slowhttptest":         "T1498",
    "heartbleed":               "T1498",
    # Port Scan
    "portscan":                 "T1595.001",
    # Brute Force / Credential
    "ftp-patator":              "T1110.001",
    "ssh-patator":              "T1110.001",
    "brute force":              "T1110.001",
    "web attacks \x96 brute force": "T1110.001",
    "web attacks – brute force":"T1110.001",
    # Web attacks → exfil/c2
    "web attacks \x96 xss":    "T1041",
    "web attacks – xss":       "T1041",
    "web attacks \x96 sql injection": "T1041",
    "web attacks – sql injection": "T1041",
    "xss":                      "T1041",
    "sql injection":            "T1041",
    # Bot / Infiltration → C2
    "bot":                      "T1071.001",
    "infiltration":             "T1071.001",
}

INCIDENT_MAP = {
    "T1498":     "DDOS",
    "T1595.001": "PORT_SCAN",
    "T1110.001": "SSH_BRUTE_FORCE",
    "T1041":     "DATA_EXFILTRATION",
    "T1071.001": "MALWARE_C2",
    "BENIGN":    "UNKNOWN",
}

SEVERITY_MAP = {
    "T1498":     "CRITICAL",
    "T1595.001": "MEDIUM",
    "T1110.001": "HIGH",
    "T1041":     "HIGH",
    "T1071.001": "HIGH",
    "BENIGN":    "LOW",
}

# ── Column name aliases (CICIDS2017 có spaces và capitalization khác nhau) ────
def _col(row: dict, *aliases, default=0.0):
    for a in aliases:
        for k in row:
            if k.strip().lower() == a.lower():
                try: return float(row[k])
                except: return default
    return default


def row_to_vector(row: dict) -> list[float]:
    """Map CICIDS2017 row → NIRO 10-dim feature vector."""
    # Flow Packets/s
    pps_raw = _col(row, "Flow Packets/s", "flow packets/s")
    # Average Packet Size
    avg_pkt = _col(row, "Average Packet Size", "average packet size", default=500)
    # Bytes
    fwd_bytes = _col(row, "Total Length of Fwd Packets", "total length of fwd packets")
    bwd_bytes = _col(row, "Total Length of Bwd Packets", "total length of bwd packets")
    total_pkts = max(_col(row, "Total Fwd Packets") + _col(row, "Total Backward Packets"), 1)
    # Flag counts
    syn_flag  = _col(row, "SYN Flag Count", "syn flag count")
    rst_flag  = _col(row, "RST Flag Count", "rst flag count")
    fin_flag  = _col(row, "FIN Flag Count", "fin flag count")
    # Packet length stats
    pkt_mean  = _col(row, "Packet Length Mean", "packet length mean", default=100)
    pkt_std   = _col(row, "Packet Length Std",  "packet length std",  default=50)
    # Init window size
    init_win  = _col(row, "Init_Win_bytes_forward", "init_win_bytes_forward", default=65535)

    # 0. threat_score: syn+rst intensity as proxy for reputation score
    threat = min((syn_flag / max(total_pkts, 1)) * 0.5 + (rst_flag / max(total_pkts, 1)) * 0.5, 1.0)

    # 1. failed_auth: not available directly → use RST rate as proxy for failed connections
    failed_proxy = rst_flag / max(total_pkts, 1)
    feat_auth = min(math.log1p(failed_proxy * 50) / math.log1p(100), 1.0)

    # 2. fw_blocks: RST count as blocked connections proxy
    feat_fw = min(math.log1p(rst_flag) / math.log1p(50), 1.0)

    # 3. pps: packets per second
    feat_pps = min(math.log1p(max(pps_raw, 0)) / math.log1p(500), 1.0)

    # 4. bytes_per_packet
    bpp = (fwd_bytes + bwd_bytes) / total_pkts
    feat_bpp = min(bpp / 1500.0, 1.0)

    # 5. sym_ratio: bwd/fwd bytes
    sym = bwd_bytes / max(fwd_bytes, 1)
    feat_sym = min(math.log1p(sym) / math.log1p(100), 1.0)

    # 6. entropy: coefficient of variation of packet length as entropy proxy
    if pkt_mean > 0:
        cv = pkt_std / pkt_mean  # coefficient of variation
        feat_ent = min(cv / 3.0, 1.0)
    else:
        feat_ent = 0.4

    # 7. is_tor: not available
    feat_tor = 0.0

    # 8. anomaly_count: various flags
    flags = sum([
        syn_flag > total_pkts * 0.8,
        rst_flag > total_pkts * 0.5,
        fin_flag > total_pkts * 0.8,
        pps_raw > 1000,
        avg_pkt < 60,
        init_win == 0,
    ])
    feat_anom = min(flags / 6.0, 1.0)

    # 9. ml_confidence: 1.0 vì đây là labeled data
    feat_conf = 1.0

    return [round(v, 4) for v in [
        threat, feat_auth, feat_fw, feat_pps, feat_bpp,
        feat_sym, feat_ent, feat_tor, feat_anom, feat_conf
    ]]


def convert_csv(path: Path, max_per_class: int) -> tuple[list, int]:
    samples_by_class = defaultdict(list)
    skipped = 0

    with path.open(encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Find label column (various spellings)
            label_raw = ""
            for k in row:
                if "label" in k.lower():
                    label_raw = row[k].strip().lower()
                    break
            if not label_raw:
                skipped += 1
                continue

            # Normalize label
            true_label = None
            for key in LABEL_MAP:
                if key in label_raw or label_raw in key:
                    true_label = LABEL_MAP[key]
                    break
            if true_label is None:
                skipped += 1
                continue

            try:
                vec = row_to_vector(row)
            except Exception:
                skipped += 1
                continue

            sample = {
                "feature_vector": vec,
                "true_label":     true_label,
                "incident_type":  INCIDENT_MAP.get(true_label, "UNKNOWN"),
                "severity":       SEVERITY_MAP.get(true_label, "LOW"),
                "source":         f"cicids_{path.stem}_{label_raw[:20]}",
                "confirmed":      True,
                "raw_label":      label_raw,
            }
            samples_by_class[true_label].append(sample)

    result = []
    for cls, items in samples_by_class.items():
        random.shuffle(items)
        result.extend(items[:max_per_class])

    return result, skipped


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input",  help="Single CSV file")
    group.add_argument("--dir",    help="Thư mục chứa nhiều CSV files")
    parser.add_argument("--output-train",  default=str(OUTPUT_TRAIN))
    parser.add_argument("--output-test",   default=str(OUTPUT_TEST))
    parser.add_argument("--max-per-class", type=int, default=1000)
    parser.add_argument("--split",  action="store_true", help="Tự split 80/20 train/test")
    parser.add_argument("--append", action="store_true", help="Append vào labeled.jsonl thay vì overwrite")
    parser.add_argument("--seed",   type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)

    # Collect CSV files
    csv_files = []
    if args.input:
        csv_files = [Path(args.input)]
    else:
        # Dùng resolved path để dedup (Windows không phân biệt hoa/thường)
        seen = set()
        csv_files = []
        for p in list(Path(args.dir).glob("*.csv")) + list(Path(args.dir).glob("*.CSV")):
            key = p.resolve()
            if key not in seen:
                seen.add(key)
                csv_files.append(p)

    if not csv_files:
        print("[ERROR] Không tìm thấy CSV files")
        return 1

    print(f"[CONVERT] Processing {len(csv_files)} file(s)...")

    all_samples = []
    for csv_path in csv_files:
        print(f"  Reading {csv_path.name}...", end=" ", flush=True)
        samples, skipped = convert_csv(csv_path, args.max_per_class)
        print(f"{len(samples)} samples ({skipped} skipped)")
        all_samples.extend(samples)

    if not all_samples:
        print("[ERROR] Không có samples nào được convert")
        return 1

    random.shuffle(all_samples)

    # Split or just save train
    if args.split:
        split_idx = int(len(all_samples) * 0.8)
        train_data = all_samples[:split_idx]
        test_data  = all_samples[split_idx:]
    else:
        train_data = all_samples
        test_data  = []

    # Save
    out_train = Path(args.output_train)
    out_train.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"
    with out_train.open(mode, encoding="utf-8") as f:
        for s in train_data:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    counts = Counter(s["true_label"] for s in train_data)
    print(f"\n[CONVERT] Train → {out_train} ({len(train_data)} samples)")
    for label, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {label:<22s} {n:6d}  {'█' * min(n // 50, 30)}")

    if test_data:
        out_test = Path(args.output_test)
        with out_test.open("w", encoding="utf-8") as f:
            for s in test_data:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"[CONVERT] Test  → {out_test} ({len(test_data)} samples)")

    print(f"\n[CONVERT] Done. Bước tiếp theo:")
    print(f"  python scripts/train_signatures.py --visualize")
    print(f"  python scripts/train_sklearn.py --model rf --visualize --test-split 0.2")
    print(f"  python scripts/train_isolation.py --test\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
