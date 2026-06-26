"""
collect_training_data.py — Thu thập dữ liệu training từ pipeline results

Đọc file JSON trong results/ → extract feature vector + label
→ append vào data/training/labeled.jsonl để train

Cách dùng:
    # Thu thập từ tất cả pipeline results
    python scripts/collect_training_data.py

    # Chỉ thu thập results đã confirmed (human reviewed)
    python scripts/collect_training_data.py --confirmed-only

    # Xem statistics của training set hiện tại
    python scripts/collect_training_data.py --stats
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

RESULTS_DIR   = Path("results")
LABELED_PATH  = Path("data/training/labeled.jsonl")

# Map incident_type → MITRE technique (dùng nếu không có trong result)
INCIDENT_TO_MITRE = {
    "SSH_BRUTE_FORCE":  "T1110.001",
    "PORT_SCAN":        "T1595.001",
    "DATA_EXFILTRATION":"T1041",
    "DDOS":             "T1498",
    "MALWARE_C2":       "T1071.001",
    "UNKNOWN":          None,
}


def extract_sample(pipeline_state: dict) -> dict | None:
    """Trích xuất feature vector + label từ một pipeline state JSON."""
    s2 = pipeline_state.get("stage2_results", {})
    s1 = pipeline_state.get("stage1_results", {})

    mitre_result = s2.get("mitre_map", {})
    ml_result    = s2.get("ml_classify", {})
    clf          = ml_result.get("classification", {})

    query_vec = mitre_result.get("query_vector")
    if not query_vec or len(query_vec) != 10:
        return None  # không có feature vector → skip

    # Xác định true_label
    # Ưu tiên: ml_classify.classification.mitre_technique > mitre_map.best_technique
    mitre_from_ml  = clf.get("mitre_technique", "")
    mitre_from_map = mitre_result.get("best_technique", "")

    # Nếu outcome là FALSE_POSITIVE → label = BENIGN
    outcome = pipeline_state.get("outcome", "")
    if outcome == "FALSE_POSITIVE":
        true_label = "BENIGN"
    elif mitre_from_ml and mitre_from_ml != "T1046":
        true_label = mitre_from_ml
    elif mitre_from_map and mitre_from_map != "UNKNOWN":
        true_label = mitre_from_map
    else:
        incident_t = clf.get("incident_type", "UNKNOWN")
        true_label = INCIDENT_TO_MITRE.get(incident_t)
        if not true_label:
            return None  # không xác định được label → skip

    alert = pipeline_state.get("alert", {})
    return {
        "feature_vector":  [round(v, 4) for v in query_vec],
        "true_label":      true_label,
        "incident_type":   clf.get("incident_type", "UNKNOWN"),
        "severity":        clf.get("severity", "LOW"),
        "source":          f"pipeline_{alert.get('alert_id', 'unknown')}",
        "confirmed":       False,   # Analyst phải set True sau khi review
        "src_ip":          alert.get("src_ip", ""),
        "ml_confidence":   clf.get("confidence", 0.5),
        "best_similarity": round(mitre_result.get("best_similarity", 0.0), 4),
    }


def load_existing_sources(path: Path) -> set[str]:
    """Đọc các source đã có trong labeled.jsonl để tránh duplicate."""
    sources = set()
    if not path.exists():
        return sources
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    obj = json.loads(line)
                    sources.add(obj.get("source", ""))
                except Exception:
                    pass
    return sources


def print_stats(path: Path):
    """In thống kê dataset hiện tại."""
    samples = []
    if path.exists():
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        samples.append(json.loads(line))
                    except Exception:
                        pass

    total     = len(samples)
    confirmed = sum(1 for s in samples if s.get("confirmed"))
    labels    = Counter(s.get("true_label") for s in samples)

    print(f"\n{'='*50}")
    print(f"  Training Dataset: {path}")
    print(f"{'='*50}")
    print(f"  Total samples:     {total}")
    print(f"  Confirmed:         {confirmed}")
    print(f"  Unconfirmed:       {total - confirmed}")
    print(f"\n  Label distribution:")
    for label, count in sorted(labels.items(), key=lambda x: -x[1]):
        bar = "█" * count
        print(f"    {label:<22s} {count:3d} {bar}")
    print(f"{'='*50}\n")

    if total > 0 and confirmed < total:
        print("  ⚠️  Có samples chưa confirmed. Mở labeled.jsonl,")
        print('     set "confirmed": true sau khi verify từng sample.\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir",    default=str(RESULTS_DIR))
    parser.add_argument("--output",         default=str(LABELED_PATH))
    parser.add_argument("--confirmed-only", action="store_true")
    parser.add_argument("--stats",          action="store_true")
    args = parser.parse_args()

    output_path  = Path(args.output)
    results_path = Path(args.results_dir)

    if args.stats:
        print_stats(output_path)
        return 0

    if not results_path.exists():
        print(f"[INFO] Không có thư mục {results_path} — chạy pipeline trước để tạo results")
        return 0

    result_files = list(results_path.glob("**/*_pipeline.json"))
    if not result_files:
        print(f"[INFO] Không tìm thấy *_pipeline.json trong {results_path}")
        return 0

    existing_sources = load_existing_sources(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    added = 0
    skipped_dup = 0
    skipped_no_vec = 0

    with output_path.open("a", encoding="utf-8") as out_f:
        for fpath in result_files:
            try:
                state = json.loads(fpath.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[WARN] Cannot read {fpath}: {e}")
                continue

            sample = extract_sample(state)
            if sample is None:
                skipped_no_vec += 1
                continue

            source = sample["source"]
            if source in existing_sources:
                skipped_dup += 1
                continue

            out_f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            added += 1
            existing_sources.add(source)
            print(f"  [+] {source} → {sample['true_label']} (confirmed=False)")

    print(f"\n[COLLECT] Added: {added}  |  Skipped (dup): {skipped_dup}  |  Skipped (no vec): {skipped_no_vec}")
    if added > 0:
        print(f"[COLLECT] Mở {output_path} và set confirmed=true cho các samples đã verify")
        print(f"[COLLECT] Sau đó chạy: python scripts/train_signatures.py\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
