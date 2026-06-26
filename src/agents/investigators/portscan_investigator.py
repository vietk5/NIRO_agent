"""
portscan_investigator.py — Subagent chuyên điều tra Port Scan / Reconnaissance

Được spawn khi phát hiện port scanning activity.
Tools: AbuseIPDB, VirusTotal, firewall log analysis, port pattern.
"""

import re
from pathlib import Path
from .base import InvestigatorSubagent
from src.tools.threat_intel_tools import check_ip_reputation, check_virustotal
from src.tools.network_tools import whois_lookup, scan_ports


class PortScanInvestigator(InvestigatorSubagent):
    NAME = "PortScan-Investigator"
    SYSTEM = """Bạn là chuyên gia điều tra Port Scan / Reconnaissance của NIRO.

Nhiệm vụ: Xác định mục đích của việc scan port và đánh giá nguy cơ tấn công tiếp theo.

Chiến lược điều tra:
1. check_firewall_log → đếm số port bị scan, thời gian scan
2. check_ip_reputation → xem IP có phải scanner/pen-tester không
3. check_virustotal → xem có phải attack infrastructure không
4. analyze_scan_pattern → phân tích loại scan (stealth/aggressive/service discovery)
5. whois_lookup → xác định nguồn gốc
6. submit_findings

PortScan indicators:
- Số port bị scan > 100 trong 1 phút = aggressive scan
- Chỉ scan well-known ports (22, 80, 443, 3389) = targeted recon
- Sequential port scan = automated tool
- Random port scan = evasion technique

risk_level:
- critical: scan kết hợp với exploit attempt trên port tìm được
- high:     aggressive scan (>1000 ports) từ known-bad IP
- medium:   scan có chủ đích vào service cụ thể
- low:      scan nhỏ, IP sạch, có thể là legitimate scanner
"""

    def _build_tools(self) -> list:
        return [
            {"type": "function", "function": {
                "name": "check_firewall_log",
                "description": "Phân tích firewall.log — đếm số port bị scan từ IP nguồn, liệt kê ports",
                "parameters": {"type": "object",
                               "properties": {
                                   "src_ip":   {"type": "string"},
                                   "log_path": {"type": "string", "default": "data/input/logs/firewall.log"},
                               }, "required": ["src_ip"]}}},
            {"type": "function", "function": {
                "name": "check_ip_reputation",
                "description": "Kiểm tra IP trên AbuseIPDB",
                "parameters": {"type": "object",
                               "properties": {"ip": {"type": "string"}},
                               "required": ["ip"]}}},
            {"type": "function", "function": {
                "name": "check_virustotal",
                "description": "Kiểm tra IP trên VirusTotal",
                "parameters": {"type": "object",
                               "properties": {"ip": {"type": "string"}},
                               "required": ["ip"]}}},
            {"type": "function", "function": {
                "name": "analyze_scan_pattern",
                "description": "Phân tích loại scan dựa trên danh sách ports bị scan",
                "parameters": {"type": "object",
                               "properties": {
                                   "ports_scanned": {"type": "array", "items": {"type": "integer"}},
                                   "duration_sec":  {"type": "number"},
                               }, "required": ["ports_scanned"]}}},
            {"type": "function", "function": {
                "name": "whois_lookup",
                "description": "Tra cứu WHOIS",
                "parameters": {"type": "object",
                               "properties": {"ip": {"type": "string"}},
                               "required": ["ip"]}}},
        ]

    def _build_tool_map(self) -> dict:
        return {
            "check_ip_reputation": check_ip_reputation,
            "check_virustotal":    check_virustotal,
            "whois_lookup":        whois_lookup,
            "check_firewall_log":  self._check_firewall_log,
            "analyze_scan_pattern": self._analyze_scan_pattern,
        }

    @staticmethod
    def _check_firewall_log(src_ip: str, log_path: str = "data/input/logs/firewall.log") -> dict:
        path = Path(log_path)
        if not path.exists():
            return {"src_ip": src_ip, "ports_scanned": [], "blocked_count": 0,
                    "note": f"Firewall log not found: {log_path}"}
        try:
            text  = path.read_text(encoding="utf-8", errors="replace")
            lines = [l for l in text.splitlines() if src_ip in l]
            ports = []
            for l in lines:
                m = re.search(r"DPT=(\d+)", l)
                if m:
                    ports.append(int(m.group(1)))
            blocked = sum(1 for l in lines if "DROP" in l or "REJECT" in l)
            return {
                "src_ip": src_ip,
                "ports_scanned": sorted(set(ports)),
                "unique_ports": len(set(ports)),
                "blocked_count": blocked,
                "total_packets": len(lines),
            }
        except Exception as e:
            return {"src_ip": src_ip, "ports_scanned": [], "error": str(e)}

    @staticmethod
    def _analyze_scan_pattern(ports_scanned: list, duration_sec: float = 60.0) -> dict:
        if not ports_scanned:
            return {"scan_type": "unknown", "intensity": "unknown"}

        n = len(ports_scanned)
        well_known = [p for p in ports_scanned if p <= 1024]
        rate = n / max(duration_sec, 1)

        # Sequential check
        sorted_ports = sorted(ports_scanned)
        sequential = all(sorted_ports[i+1] - sorted_ports[i] == 1
                         for i in range(min(len(sorted_ports)-1, 10)))

        scan_type = "SEQUENTIAL" if sequential else \
                    "SERVICE_DISCOVERY" if len(well_known) > n * 0.7 else \
                    "AGGRESSIVE_SWEEP" if n > 1000 else "TARGETED"

        intensity = "critical" if rate > 100 else "high" if rate > 20 else \
                    "medium" if rate > 5 else "low"

        return {
            "total_ports": n,
            "well_known_ports": len(well_known),
            "scan_rate_per_sec": round(rate, 2),
            "scan_type": scan_type,
            "intensity": intensity,
            "sample_ports": sorted_ports[:20],
        }
