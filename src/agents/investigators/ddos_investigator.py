"""
ddos_investigator.py — Subagent chuyên điều tra DDoS / DoS attacks

Được spawn bởi OrchestratorAgent khi phát hiện dấu hiệu DDoS.
Tools: AbuseIPDB, VirusTotal, network traffic analysis.
KHÔNG cần log auth hay PCAP detail — tập trung vào volume/rate.
"""

from .base import InvestigatorSubagent
from src.tools.threat_intel_tools import check_ip_reputation, check_virustotal
from src.tools.network_tools import whois_lookup


class DDoSInvestigator(InvestigatorSubagent):
    NAME = "DDoS-Investigator"
    SYSTEM = """Bạn là chuyên gia điều tra DDoS/DoS attacks của NIRO.

Nhiệm vụ: Xác nhận và đánh giá mức độ nghiêm trọng của cuộc tấn công DDoS.

Chiến lược điều tra:
1. check_ip_reputation → xem IP nguồn có trong blacklist không, có phải Tor không
2. check_virustotal → xem detection ratio, có phải botnet C2 không
3. whois_lookup → xác định ASN, country, có phải hosting/VPS provider không
4. analyze_traffic_pattern → phân tích đặc điểm traffic (pps, syn ratio, packet size)
5. submit_findings → tổng hợp kết quả

DDoS indicators cần tìm:
- pps (packets/sec) cực cao > 1000
- SYN flag ratio > 80% (SYN flood)
- Packet size rất nhỏ < 64 bytes (amplification)
- IP từ nhiều ASN khác nhau (distributed)
- AbuseScore > 50 hoặc VT malicious > 3

risk_level:
- critical: pps > 10000 hoặc confirmed botnet
- high:     pps > 1000 hoặc abuseScore > 80
- medium:   dấu hiệu DoS nhưng chưa chắc chắn
- low:      có thể là traffic spike bình thường
"""

    def _build_tools(self) -> list:
        return [
            {"type": "function", "function": {
                "name": "check_ip_reputation",
                "description": "Kiểm tra IP trên AbuseIPDB — abuse score, isTor, country",
                "parameters": {"type": "object",
                               "properties": {"ip": {"type": "string"}},
                               "required": ["ip"]}}},
            {"type": "function", "function": {
                "name": "check_virustotal",
                "description": "Kiểm tra IP trên VirusTotal — detection ratio, verdict, botnet tags",
                "parameters": {"type": "object",
                               "properties": {"ip": {"type": "string"}},
                               "required": ["ip"]}}},
            {"type": "function", "function": {
                "name": "whois_lookup",
                "description": "Tra cứu WHOIS — ASN, country, ISP, org",
                "parameters": {"type": "object",
                               "properties": {"ip": {"type": "string"}},
                               "required": ["ip"]}}},
            {"type": "function", "function": {
                "name": "analyze_traffic_pattern",
                "description": "Phân tích đặc điểm traffic từ alert metadata",
                "parameters": {"type": "object",
                               "properties": {
                                   "pps":        {"type": "number", "description": "Packets per second"},
                                   "syn_ratio":  {"type": "number", "description": "Tỷ lệ SYN packets (0-1)"},
                                   "avg_pkt_size": {"type": "number", "description": "Kích thước packet trung bình (bytes)"},
                               }, "required": ["pps"]}}},
        ]

    def _build_tool_map(self) -> dict:
        return {
            "check_ip_reputation":    check_ip_reputation,
            "check_virustotal":       check_virustotal,
            "whois_lookup":           whois_lookup,
            "analyze_traffic_pattern": self._analyze_traffic,
        }

    @staticmethod
    def _analyze_traffic(pps: float, syn_ratio: float = 0.0, avg_pkt_size: float = 500.0) -> dict:
        attack_type = "unknown"
        if syn_ratio > 0.8:
            attack_type = "SYN_FLOOD"
        elif avg_pkt_size < 64:
            attack_type = "AMPLIFICATION"
        elif pps > 1000:
            attack_type = "VOLUMETRIC"

        severity = "critical" if pps > 10000 else "high" if pps > 1000 else "medium" if pps > 100 else "low"
        return {
            "pps": pps, "syn_ratio": syn_ratio, "avg_pkt_size": avg_pkt_size,
            "attack_type": attack_type, "severity": severity,
            "note": f"Traffic rate {pps:.0f} pps — {attack_type}",
        }
