"""
parse_log_to_alerts.py — Đọc file log hỗn hợp → tự detect tấn công → sinh alert JSON

Cách dùng:
    python scripts/parse_log_to_alerts.py --log data/input/logs/mixed_realistic.log
    python scripts/parse_log_to_alerts.py --log data/input/logs/mixed_realistic.log --run
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

OUTPUT_DIR = Path("data/input/alerts/parsed")

# ── Regex patterns ─────────────────────────────────────────────────────────────
RE_FAILED_AUTH  = re.compile(r"Failed password|Invalid user", re.I)
RE_SSH_IP       = re.compile(r"from (\d+\.\d+\.\d+\.\d+) port")
RE_UFW_BLOCK    = re.compile(r"\[UFW BLOCK\].*SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)")
RE_CONNTRACK    = re.compile(r"nf_conntrack.*dropping packet from (\d+\.\d+\.\d+\.\d+)")
RE_SYN_FLOOD    = re.compile(r"SYN flood|SYN flooding", re.I)
RE_DNS_TUNNEL   = re.compile(r"client (\d+\.\d+\.\d+\.\d+).*query:.*\.(tunnel|c2|exfil|badactor|malware)", re.I)
RE_LARGE_XFER   = re.compile(r"large outbound transfer.*?(\d+\.\d+\.\d+\.\d+) to (\d+\.\d+\.\d+\.\d+) bytes=(\d+)")
RE_VULN_SCAN    = re.compile(r'(\d+\.\d+\.\d+\.\d+).*"GET /(wp-admin|phpmyadmin|\.env|config\.php|backup\.sql|shell\.php|xmlrpc\.php|\.git)')
RE_TIMESTAMP    = re.compile(r"^(\w{3}\s+\d+\s+[\d:]+)")

RFC1918 = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
           "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


def is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in RFC1918)


def parse_log(path: Path) -> list[dict]:
    stats = defaultdict(lambda: {
        "failed_auth": 0, "fw_blocks": 0, "ports": set(),
        "conntrack": 0, "syn_flood": False,
        "dns_queries": 0, "bytes_out": 0,
        "vuln_scan_hits": 0, "dst_ip": "192.168.1.10",
        "timestamps": [], "raw_lines": 0,
    })

    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue

            # SSH failed auth
            if RE_FAILED_AUTH.search(line):
                m = RE_SSH_IP.search(line)
                if m:
                    ip = m.group(1)
                    stats[ip]["failed_auth"] += 1
                    stats[ip]["raw_lines"] += 1

            # UFW BLOCK
            m = RE_UFW_BLOCK.search(line)
            if m:
                ip, port = m.group(1), int(m.group(2))
                stats[ip]["fw_blocks"] += 1
                stats[ip]["ports"].add(port)
                stats[ip]["raw_lines"] += 1

            # Conntrack / SYN flood
            m = RE_CONNTRACK.search(line)
            if m:
                stats[m.group(1)]["conntrack"] += 1
                stats[m.group(1)]["raw_lines"] += 1
            if RE_SYN_FLOOD.search(line):
                m2 = re.search(r"source: (\d+\.\d+\.\d+\.\d+)", line)
                if m2:
                    stats[m2.group(1)]["syn_flood"] = True

            # DNS tunneling
            m = RE_DNS_TUNNEL.search(line)
            if m:
                stats[m.group(1)]["dns_queries"] += 1
                stats[m.group(1)]["raw_lines"] += 1

            # Large outbound (exfil)
            m = RE_LARGE_XFER.search(line)
            if m:
                src, dst, b = m.group(1), m.group(2), int(m.group(3))
                stats[src]["bytes_out"] += b
                stats[src]["dst_ip"] = dst
                stats[src]["raw_lines"] += 1

            # Vuln scan
            m = RE_VULN_SCAN.search(line)
            if m:
                stats[m.group(1)]["vuln_scan_hits"] += 1
                stats[m.group(1)]["raw_lines"] += 1

    # Classify each IP
    alerts = []
    alert_num = 1
    for ip, s in stats.items():
        rf_class, confidence, description = _classify(ip, s)
        if rf_class is None:
            continue  # benign / không đủ evidence

        alert = {
            "alert_id":      f"AUTO-{alert_num:03d}",
            "src_ip":        ip,
            "dst_ip":        s["dst_ip"],
            "dst_port":      min(s["ports"]) if s["ports"] else 0,
            "protocol":      "TCP",
            "rf_class":      rf_class,
            "ml_confidence": round(confidence, 2),
            "bytes_in":      s.get("bytes_in", 0),
            "bytes_out":     s["bytes_out"],
            "packets":       s["fw_blocks"] + s["failed_auth"],
            "duration":      60.0,
            "description":   description,
            "_evidence": {
                "failed_auth":    s["failed_auth"],
                "fw_blocks":      s["fw_blocks"],
                "ports_hit":      sorted(s["ports"])[:10],
                "conntrack_drops": s["conntrack"],
                "dns_queries":    s["dns_queries"],
                "bytes_out":      s["bytes_out"],
                "vuln_scan_hits": s["vuln_scan_hits"],
            },
        }
        alerts.append(alert)
        alert_num += 1

    return alerts


def _classify(ip: str, s: dict):
    """Trả về (rf_class, confidence, description) hoặc (None, 0, '') nếu benign."""

    # DDoS — conntrack + syn flood
    if s["conntrack"] >= 5 or s["syn_flood"]:
        conf = min(0.70 + s["conntrack"] * 0.02, 0.99)
        return "DDoS", conf, f"SYN flood from {ip}: {s['conntrack']} conntrack drops"

    # SSH Brute Force — nhiều failed auth
    if s["failed_auth"] >= 5:
        conf = min(0.75 + s["failed_auth"] * 0.02, 0.99)
        return "BruteForce", conf, f"SSH brute force: {s['failed_auth']} failed logins from {ip}"

    # DNS Tunneling
    if s["dns_queries"] >= 5:
        conf = min(0.65 + s["dns_queries"] * 0.03, 0.95)
        return "DNSTunnel", conf, f"DNS tunneling: {s['dns_queries']} suspicious queries from {ip}"

    # Data Exfiltration — internal host, large bytes_out
    if s["bytes_out"] >= 1_000_000 and is_internal(ip):
        conf = min(0.60 + s["bytes_out"] / 50_000_000, 0.95)
        mb = s["bytes_out"] / 1_048_576
        return "Exfiltration", conf, f"Large outbound transfer {mb:.1f}MB from internal {ip}"

    # Port Scan — nhiều fw_blocks trên nhiều port khác nhau
    if s["fw_blocks"] >= 8 and len(s["ports"]) >= 6:
        conf = min(0.65 + len(s["ports"]) * 0.02, 0.95)
        return "PortScan", conf, f"Port scan: {len(s['ports'])} ports hit from {ip}"

    # Vulnerability Scan — nhiều 404 trên paths nhạy cảm
    if s["vuln_scan_hits"] >= 5:
        conf = min(0.60 + s["vuln_scan_hits"] * 0.03, 0.92)
        return "VulnScan", conf, f"Web vuln scan: {s['vuln_scan_hits']} sensitive paths probed from {ip}"

    return None, 0, ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log",   required=True, help="Path đến log file")
    parser.add_argument("--out",   default=str(OUTPUT_DIR), help="Output dir cho alert JSONs")
    parser.add_argument("--run",   action="store_true", help="Chạy NIRO ngay sau khi parse")
    parser.add_argument("--auto-approve", action="store_true")
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"[ERROR] Không tìm thấy {log_path}")
        return 1

    print(f"[PARSE] Đọc {log_path}...")
    alerts = parse_log(log_path)

    if not alerts:
        print("[PARSE] Không phát hiện tấn công nào")
        return 0

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[PARSE] Phát hiện {len(alerts)} incident(s):\n")
    batch = []
    for a in alerts:
        ev = a.pop("_evidence")
        print(f"  [{a['alert_id']}] {a['rf_class']:<15s} from {a['src_ip']:<18s} conf={a['ml_confidence']:.0%}")
        print(f"         → {a['description']}")
        print(f"         evidence: failed_auth={ev['failed_auth']} fw_blocks={ev['fw_blocks']} "
              f"ports={len(ev['ports_hit'])} dns={ev['dns_queries']} bytes_out={ev['bytes_out']:,}")
        print()
        batch.append(a)

    # Lưu batch file
    batch_path = out_dir / "batch_alerts.json"
    with batch_path.open("w", encoding="utf-8") as f:
        json.dump(batch, f, indent=2, ensure_ascii=False)
    print(f"[PARSE] Saved → {batch_path}")

    if args.run:
        print(f"\n[PARSE] Chạy NIRO batch pipeline...\n")
        cmd = [sys.executable, "-m", "src.main", "--file", str(batch_path), "--batch"]
        if args.auto_approve:
            cmd.append("--auto-approve")
        subprocess.run(cmd)

    else:
        print(f"\nChạy pipeline:")
        print(f"  python3 -m src.main --file {batch_path} --batch --auto-approve")

    return 0


if __name__ == "__main__":
    sys.exit(main())
