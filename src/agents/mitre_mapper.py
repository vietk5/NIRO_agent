"""
mitre_mapper.py — Stage 2B: MITRE ATT&CK Mapping via NLP/Embedding

Chạy song song với ml_classifier trong Stage 2.
Dùng cosine similarity để ánh xạ alert + logs → MITRE ATT&CK techniques.
Không cần LLM — thuần Python, không có latency API.

Kiến trúc:
  - Mỗi MITRE technique có một "signature vector" 10 chiều pre-computed
  - Alert + Stage 1 data → normalize → 10-dim query vector
  - Cosine similarity vs tất cả signatures → top matches
  - best_similarity ≥ 0.70 → is_known_technique = True
"""

import json
import math
import os
import pickle
from pathlib import Path

# ── Trained model loader (tự động dùng model tốt nhất có sẵn) ────────────────
# Thứ tự ưu tiên: sklearn model > trained centroids > hand-crafted vectors
_SKLEARN_MODEL_PATH  = Path("data/training/sklearn_model.pkl")
_CENTROIDS_PATH      = Path("data/training/signatures.json")
_ISO_MODEL_PATH      = Path("data/training/isolation_model.pkl")

_sklearn_model   = None   # (model, label_encoder) hoặc None
_isolation_model = None   # IsolationForest hoặc None
_trained_loaded  = False


def _load_trained_models():
    global _sklearn_model, _isolation_model, _trained_loaded
    if _trained_loaded:
        return
    _trained_loaded = True

    # Load sklearn classifier nếu có
    if _SKLEARN_MODEL_PATH.exists():
        try:
            with _SKLEARN_MODEL_PATH.open("rb") as f:
                data = pickle.load(f)
            _sklearn_model = (data["model"], data["label_encoder"])
        except Exception as e:
            pass

    # Load Isolation Forest nếu có
    if _ISO_MODEL_PATH.exists():
        try:
            with _ISO_MODEL_PATH.open("rb") as f:
                data = pickle.load(f)
            _isolation_model = data["model"]
        except Exception as e:
            pass


def _load_signatures() -> dict:
    """Tải signatures: trained centroids nếu có, ngược lại dùng hand-crafted."""
    if _CENTROIDS_PATH.exists():
        try:
            data = json.loads(_CENTROIDS_PATH.read_text(encoding="utf-8"))
            if data:
                return data
        except Exception:
            pass
    return MITRE_SIGNATURES   # fallback sang hand-crafted


# ── Pre-computed MITRE technique signatures (10-dim vectors) ──────────────────
# Dimensions:
# [threat_score, failed_auth, fw_blocks, pps, bpkt, sym_ratio,
#  entropy, is_tor, anomaly_count, ml_confidence]

MITRE_SIGNATURES = {
    "T1110.001": {
        "name":    "Brute Force: Password Guessing",
        "tactic":  "Credential Access",
        "vector":  [0.7, 1.0, 0.8, 0.3, 0.1, 0.1, 0.4, 0.0, 0.6, 0.85],
        "description": "Nhiều lần auth fail, dst_port=22, packet nhỏ, tần suất cao",
    },
    "T1110.001-TOR": {
        "name":    "Brute Force via Tor",
        "tactic":  "Credential Access",
        "vector":  [1.0, 1.0, 0.8, 0.3, 0.1, 0.1, 0.4, 1.0, 0.7, 0.9],
        "description": "Brute force từ Tor exit node — automated credential stuffing",
    },
    "T1595.001": {
        "name":    "Active Scanning: Scanning IP Blocks",
        "tactic":  "Reconnaissance",
        "vector":  [0.4, 0.0, 0.6, 0.9, 0.05, 0.05, 0.2, 0.0, 0.6, 0.85],
        "description": "Port scan — SYN rate cao, payload nhỏ",
    },
    "T1595.002": {
        "name":    "Active Scanning: Vulnerability Scanning",
        "tactic":  "Reconnaissance",
        "vector":  [0.5, 0.0, 0.7, 1.0, 0.05, 0.05, 0.2, 0.0, 0.7, 0.9],
        "description": "Aggressive scan — nmap -A, masscan",
    },
    "T1041": {
        "name":    "Exfiltration Over C2 Channel",
        "tactic":  "Exfiltration",
        "vector":  [0.6, 0.0, 0.2, 0.2, 0.8, 0.9, 0.9, 0.0, 0.5, 0.7],
        "description": "bytes_out >> bytes_in, high entropy, encrypted channel",
    },
    "T1071.004": {
        "name":    "Application Layer Protocol: DNS",
        "tactic":  "Command and Control",
        "vector":  [0.5, 0.0, 0.1, 0.4, 0.3, 0.7, 0.95, 0.0, 0.4, 0.65],
        "description": "DNS tunneling — entropy cao trong queries",
    },
    "T1498": {
        "name":    "Network Denial of Service",
        "tactic":  "Impact",
        "vector":  [0.8, 0.0, 0.9, 1.0, 0.05, 0.02, 0.15, 0.0, 0.8, 0.95],
        "description": "SYN flood — packet rate cực cao, payload nhỏ",
    },
    "T1071.001": {
        "name":    "Application Layer Protocol: Web Protocols",
        "tactic":  "Command and Control",
        "vector":  [0.65, 0.0, 0.1, 0.1, 0.5, 0.3, 0.8, 0.3, 0.4, 0.6],
        "description": "C2 beacon — periodic, low-volume, high entropy",
    },
    "BENIGN": {
        "name":    "False Positive / Benign Traffic",
        "tactic":  "N/A",
        "vector":  [0.0, 0.0, 0.0, 0.2, 0.8, 0.8, 0.6, 0.0, 0.0, 0.3],
        "description": "Backup, sync, monitoring traffic từ IP nội bộ",
    },
}

SIMILARITY_THRESHOLD = 0.70


def run_mitre_mapper(alert: dict, stage1_results: dict, verbose: bool = True) -> dict:
    """
    Stage 2B: NLP/Embedding scoring → MITRE ATT&CK mapping.

    Args:
        alert:          Alert gốc
        stage1_results: Kết quả từ recon, log_collect, pcap (Stage 1)

    Returns:
        {query_vector, top_techniques, best_technique, best_similarity,
         is_known_technique, technique_risk_score, error}
    """
    if verbose:
        print("  [MITRE-MAP   ] Starting — building feature vector", flush=True)

    # Load trained models (cached sau lần đầu)
    _load_trained_models()

    try:
        query_vec = _build_feature_vector(alert, stage1_results)

        # ── Isolation Forest: check anomaly trước ─────────────────────────────
        anomaly_score = None
        is_anomaly    = False
        if _isolation_model is not None:
            anomaly_score = float(_isolation_model.score_samples([query_vec])[0])
            is_anomaly    = bool(_isolation_model.predict([query_vec])[0] == -1)
            if verbose and is_anomaly:
                print(f"  [MITRE-MAP   ] ⚠️  ANOMALY detected (score={anomaly_score:.3f})", flush=True)

        # ── Classifier: sklearn nếu có, ngược lại cosine similarity ───────────
        if _sklearn_model is not None:
            model, le = _sklearn_model
            proba = model.predict_proba([query_vec])[0] if hasattr(model, "predict_proba") else None
            pred_enc = model.predict([query_vec])[0]
            best_id  = le.inverse_transform([pred_enc])[0]
            if proba is not None:
                best_sim = float(max(proba))
                # Top 5 bằng probability
                class_proba = sorted(zip(le.classes_, proba), key=lambda x: -x[1])[:5]
                ranked = [(cls, float(p)) for cls, p in class_proba]
            else:
                best_sim = 1.0
                ranked = [(best_id, 1.0)]
            model_used = f"sklearn:{type(model).__name__}"
        else:
            # Cosine similarity (fallback hoặc default)
            sigs = _load_signatures()
            scores = {
                tech_id: _cosine_similarity(query_vec, sig["vector"])
                for tech_id, sig in sigs.items()
            }
            ranked  = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            best_id, best_sim = ranked[0]
            model_used = "cosine_similarity"

        # Tra cứu metadata từ MITRE_SIGNATURES (hand-crafted) hoặc trained sigs
        all_sigs = {**MITRE_SIGNATURES, **(_load_signatures() if _CENTROIDS_PATH.exists() else {})}

        top_techniques = []
        for tech_id, sim in ranked[:5]:
            sig = all_sigs.get(tech_id, {"name": tech_id, "tactic": "Unknown", "description": ""})
            top_techniques.append({
                "technique_id": tech_id,
                "name":         sig["name"],
                "tactic":       sig["tactic"],
                "similarity":   round(sim, 4),
                "description":  sig.get("description", ""),
            })

        is_known = best_sim >= SIMILARITY_THRESHOLD and best_id != "BENIGN"
        best_sig = all_sigs.get(best_id, {"name": best_id, "tactic": "Unknown"})

        if verbose:
            anomaly_str = f" ⚠️ANOMALY={anomaly_score:.2f}" if is_anomaly else ""
            print(f"  [MITRE-MAP   ] Done — best={best_id} ({best_sig['name']}) "
                  f"sim={best_sim:.3f} known={is_known} [{model_used}]{anomaly_str}", flush=True)

        return {
            "query_vector":        query_vec,
            "top_techniques":      top_techniques,
            "best_technique":      best_id,
            "best_technique_name": best_sig["name"],
            "best_tactic":         best_sig["tactic"],
            "best_similarity":     round(best_sim, 4),
            "is_known_technique":  is_known,
            "is_anomaly":          is_anomaly,
            "anomaly_score":       round(anomaly_score, 4) if anomaly_score is not None else None,
            "model_used":          model_used,
            "technique_risk_score": round(best_sim * (0.3 if best_id == "BENIGN" else 0.8), 3),
            "error":               None,
        }

    except Exception as e:
        if verbose:
            print(f"  [MITRE-MAP   ] ERROR: {e}", flush=True)
        return {
            "query_vector": [], "top_techniques": [], "best_technique": "UNKNOWN",
            "best_technique_name": "Unknown", "best_tactic": "Unknown",
            "best_similarity": 0.0, "is_known_technique": False,
            "is_anomaly": False, "anomaly_score": None, "model_used": "error",
            "technique_risk_score": 0.0, "error": str(e),
        }


def _build_feature_vector(alert: dict, stage1: dict) -> list:
    """10-dim normalized feature vector."""
    recon  = stage1.get("recon", {})
    logs   = stage1.get("log_collect", {})
    pcap   = stage1.get("pcap", {})
    rp     = recon.get("risk_profile", {})
    ls     = logs.get("summary", {})
    ff     = pcap.get("flow_features", {})

    # 1. threat_score 0–100 → 0–1
    feat_threat = rp.get("threat_score", 0) / 100.0

    # 2. failed_auth log1p scale
    failed = ls.get("failed_auth_count", 0)
    feat_auth = min(math.log1p(failed) / math.log1p(100), 1.0)

    # 3. fw_blocks
    blocks = ls.get("blocked_connections", 0)
    feat_fw = min(math.log1p(blocks) / math.log1p(50), 1.0)

    # 4. packets_per_sec
    pps = ff.get("packets_per_sec", 0)
    feat_pps = min(math.log1p(pps) / math.log1p(500), 1.0)

    # 5. bytes_per_packet (small = brute/scan, large = exfil)
    bpp = ff.get("bytes_per_packet", 500)
    feat_bpp = min(bpp / 1500.0, 1.0)

    # 6. flow symmetry (bytes_out / bytes_in)
    bout = ff.get("bytes_out", alert.get("bytes_out", 100))
    binp = ff.get("bytes_in",  alert.get("bytes_in",  1000))
    sym  = bout / max(binp, 1)
    feat_sym = min(math.log1p(sym) / math.log1p(100), 1.0)

    # 7. payload entropy 0–8 → 0–1
    feat_ent = ff.get("payload_entropy", 4.5) / 8.0

    # 8. is_tor
    feat_tor = float(bool(rp.get("isTor", False)))

    # 9. anomaly count 0–6+ → 0–1
    anomalies = len(pcap.get("anomaly_indicators", []))
    feat_anom = min(anomalies / 6.0, 1.0)

    # 10. ml_confidence từ alert
    feat_conf = alert.get("ml_confidence", 0.5)

    return [round(v, 4) for v in [
        feat_threat, feat_auth, feat_fw, feat_pps, feat_bpp,
        feat_sym, feat_ent, feat_tor, feat_anom, feat_conf
    ]]


def _cosine_similarity(a: list, b: list) -> float:
    if len(a) != len(b):
        n = min(len(a), len(b))
        a, b = a[:n], b[:n]
    dot   = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(y * y for y in b))
    return dot / (mag_a * mag_b) if mag_a and mag_b else 0.0


if __name__ == "__main__":
    import argparse, sys
    parser = argparse.ArgumentParser()
    parser.add_argument("--alert",         required=True)
    parser.add_argument("--stage1-result", required=True)
    parser.add_argument("--output",        default=".pi/triage/mitre_result.json")
    parser.add_argument("--quiet",         action="store_true")
    args = parser.parse_args()

    alert  = json.loads(args.alert) if not os.path.isfile(args.alert) \
             else json.load(open(args.alert, encoding="utf-8"))
    stage1 = json.load(open(args.stage1_result, encoding="utf-8"))

    result = run_mitre_mapper(alert, stage1, verbose=not args.quiet)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[MITRE-MAP] best={result['best_technique']} ({result['best_technique_name']}) "
          f"sim={result['best_similarity']} known={result['is_known_technique']}")
    sys.exit(0)
