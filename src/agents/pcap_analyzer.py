"""
pcap_analyzer.py — Stage 1C: PCAP Feature Extraction

Trích xuất flow features từ PCAP (dùng scapy nếu có).
Nếu không có file PCAP thật → tính features từ alert metadata.
Chạy song song với recon và log_collector.
"""

import json
import math
import os
from pathlib import Path


def run_pcap_analyzer(alert: dict, pcap_path: str = None, verbose: bool = True) -> dict:
    """Stage 1C: Trích xuất PCAP features."""
    if verbose:
        print("  [PCAP        ] Starting — extracting flow features", flush=True)

    try:
        if pcap_path and Path(pcap_path).exists():
            features = _extract_from_pcap(pcap_path, alert)
        else:
            features = _derive_from_alert(alert)

        anomalies  = _detect_anomalies(features)
        sig_match  = _match_flow_signature(features, alert)
        risk_score = _compute_risk(features, anomalies, sig_match)

        if verbose:
            print(f"  [PCAP        ] Done — sig={sig_match} risk={risk_score:.2f} "
                  f"anomalies={len(anomalies)}", flush=True)

        return {
            "flow_features":      features,
            "anomaly_indicators": anomalies,
            "flow_signature_match": sig_match,
            "risk_score":         risk_score,
            "error":              None,
        }
    except Exception as e:
        if verbose:
            print(f"  [PCAP        ] ERROR: {e}", flush=True)
        return {"flow_features": {}, "anomaly_indicators": [], "flow_signature_match": "UNKNOWN",
                "risk_score": 0.0, "error": str(e)}


def _extract_from_pcap(pcap_path: str, alert: dict) -> dict:
    """Dùng scapy để đọc PCAP thật.

    Fallback về _derive_from_alert() nếu:
      - scapy chưa cài (ImportError)
      - libpcap/Npcap chưa cài trên Windows (OSError, Scapy exception)
      - File đọc được nhưng rỗng
    """
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")   # tắt "No libpcap provider" warning
            from scapy.all import rdpcap, IP, TCP, UDP

        packets = rdpcap(pcap_path)
        if not packets:
            print("  [PCAP        ] File empty — fallback to derived", flush=True)
            return _derive_from_alert(alert)

        total_bytes = sum(len(p) for p in packets)
        duration    = float(packets[-1].time - packets[0].time) or 1.0
        pps         = len(packets) / duration
        bpp         = total_bytes / len(packets)

        syn_count = sum(1 for p in packets if TCP in p and (p[TCP].flags & 0x02))
        bytes_out = sum(len(p) for p in packets
                        if IP in p and str(p[IP].src) == alert.get("dst_ip", ""))

        print(f"  [PCAP        ] Scapy read OK — {len(packets)} pkts, {duration:.1f}s", flush=True)
        return {
            "packet_count":     len(packets),
            "total_bytes":      total_bytes,
            "duration_sec":     round(duration, 2),
            "packets_per_sec":  round(pps, 2),
            "bytes_per_packet": round(bpp, 1),
            "bytes_per_sec":    round(total_bytes / duration, 1),
            "dst_port":         alert.get("dst_port", 0),
            "syn_count":        syn_count,
            "bytes_out":        bytes_out,
            "payload_entropy":  _calc_entropy(packets),
        }
    except ImportError:
        print("  [PCAP        ] scapy not installed — fallback to derived", flush=True)
        return _derive_from_alert(alert)
    except Exception as e:
        # OSError, Scapy Scapy exception, v.v. (thường do thiếu Npcap trên Windows)
        print(f"  [PCAP        ] scapy read failed ({type(e).__name__}: {e}) — fallback to derived", flush=True)
        return _derive_from_alert(alert)


def _derive_from_alert(alert: dict) -> dict:
    """Tính toán features từ alert metadata khi không có PCAP."""
    packets  = alert.get("packets", 100)
    bytes_in = alert.get("bytes_in", 10000)
    bytes_out= alert.get("bytes_out", 1000)
    duration = alert.get("duration", 10.0) or 1.0
    total    = bytes_in + bytes_out

    pps  = packets / duration
    bpp  = total / packets if packets else 500
    bps  = total / duration

    # Entropy ước tính từ rf_class
    rf = alert.get("rf_class", "")
    entropy_map = {"Exfiltration": 7.2, "DDoS": 2.1, "BruteForce": 4.5, "PortScan": 3.0}
    entropy = entropy_map.get(rf, 4.5)

    return {
        "packet_count":     packets,
        "total_bytes":      total,
        "duration_sec":     duration,
        "packets_per_sec":  round(pps, 2),
        "bytes_per_packet": round(bpp, 1),
        "bytes_per_sec":    round(bps, 1),
        "dst_port":         alert.get("dst_port", 0),
        "bytes_in":         bytes_in,
        "bytes_out":        bytes_out,
        "payload_entropy":  entropy,
        "syn_count":        int(packets * 0.8) if rf in ("DDoS", "PortScan") else 0,
        "source": "derived_from_alert",
    }


def _detect_anomalies(ff: dict) -> list:
    """Phát hiện bất thường trong flow features."""
    anomalies = []
    pps  = ff.get("packets_per_sec", 0)
    bpp  = ff.get("bytes_per_packet", 500)
    bps  = ff.get("bytes_per_sec", 0)
    ent  = ff.get("payload_entropy", 4.5)
    syn  = ff.get("syn_count", 0)
    bout = ff.get("bytes_out", 0)
    binp = ff.get("bytes_in", 1)

    if pps > 100:   anomalies.append("HIGH_PACKET_RATE")
    if bpp < 100 and pps > 50: anomalies.append("SMALL_PACKETS_HIGH_FREQ")
    if bout / max(binp, 1) > 10: anomalies.append("ASYMMETRIC_FLOW_OUT")
    if syn > 200:   anomalies.append("HIGH_SYN_COUNT")
    if bps > 100_000: anomalies.append("HIGH_BANDWIDTH")
    if ent > 7.0:   anomalies.append("HIGH_PAYLOAD_ENTROPY")
    if ff.get("dst_port") == 22 and pps > 5: anomalies.append("SSH_HIGH_RATE")

    return anomalies


def _match_flow_signature(ff: dict, alert: dict) -> str:
    """Khớp với signature đã biết."""
    rf   = alert.get("rf_class", "")
    pps  = ff.get("packets_per_sec", 0)
    bpp  = ff.get("bytes_per_packet", 500)
    port = ff.get("dst_port", 0)
    bout = ff.get("bytes_out", 0)
    ent  = ff.get("payload_entropy", 4.5)

    if port == 22 and pps > 3 and bpp < 200:       return "SSH_BRUTE_FORCE"
    if pps > 50 and bpp < 100 and ff.get("syn_count", 0) > 50: return "PORT_SCAN"
    if bout > 10000 and ent > 6.5:                  return "DATA_EXFILTRATION"
    if pps > 500:                                   return "DDOS_SYN_FLOOD"
    if "BruteForce"   in rf:                        return "SSH_BRUTE_FORCE"
    if "PortScan"     in rf:                        return "PORT_SCAN"
    if "Exfiltration" in rf:                        return "DATA_EXFILTRATION"
    if "DDoS"         in rf:                        return "DDOS_SYN_FLOOD"
    return "UNKNOWN"


def _compute_risk(ff: dict, anomalies: list, sig: str) -> float:
    """Risk score 0–1."""
    base    = len(anomalies) * 0.12
    sig_map = {"SSH_BRUTE_FORCE": 0.6, "PORT_SCAN": 0.5, "DATA_EXFILTRATION": 0.75, "DDOS_SYN_FLOOD": 0.8}
    base   += sig_map.get(sig, 0.2)
    return round(min(base, 1.0), 3)


def _calc_entropy(packets) -> float:
    """Shannon entropy của payload bytes."""
    try:
        all_bytes = b"".join(bytes(p) for p in packets[:100])
        if not all_bytes:
            return 4.5
        freq = {}
        for b in all_bytes:
            freq[b] = freq.get(b, 0) + 1
        total = len(all_bytes)
        return round(-sum((c/total) * math.log2(c/total) for c in freq.values()), 3)
    except Exception:
        return 4.5


if __name__ == "__main__":
    import argparse, sys
    parser = argparse.ArgumentParser()
    parser.add_argument("--alert",  required=True)
    parser.add_argument("--pcap",   default=None)
    parser.add_argument("--output", default=".pi/triage/pcap_result.json")
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()

    alert = json.loads(args.alert) if not os.path.isfile(args.alert) \
            else json.load(open(args.alert, encoding="utf-8"))

    result = run_pcap_analyzer(alert, args.pcap, verbose=not args.quiet)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[PCAP] sig={result['flow_signature_match']} risk={result['risk_score']} anomalies={len(result['anomaly_indicators'])}")
    sys.exit(0)
