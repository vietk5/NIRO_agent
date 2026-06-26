"""
general_investigator.py — Subagent điều tra đa năng (Unknown / Exfil / C2)

Được spawn khi loại tấn công chưa rõ hoặc là Exfiltration / C2.
Tools: đầy đủ nhất — AbuseIPDB, VT, log, firewall, port scan.
"""

from pathlib import Path
from .base import InvestigatorSubagent
from src.tools.threat_intel_tools import check_ip_reputation, check_virustotal
from src.tools.network_tools import whois_lookup, scan_ports


class GeneralInvestigator(InvestigatorSubagent):
    NAME = "General-Investigator"
    SYSTEM = """Bạn là investigator đa năng của NIRO, xử lý các trường hợp chưa rõ loại tấn công.

Nhiệm vụ: Thu thập bức tranh toàn cảnh về IP đáng ngờ.

Chiến lược linh hoạt — dùng judgment để quyết định tool nào cần:
1. check_ip_reputation + check_virustotal → threat intel cơ bản (luôn làm)
2. whois_lookup → nguồn gốc IP
3. scan_ports → xem IP đang chạy service gì (nếu cần)
4. check_combined_logs → tổng hợp từ auth + firewall log
5. submit_findings

Đặc biệt chú ý dấu hiệu C2 / Exfiltration:
- Kết nối outbound đến IP lạ, port bất thường (4444, 8080, 1337)
- Upload volume lớn bất thường
- Beacon pattern (kết nối định kỳ mỗi X giây)
- DNS query đến domain lạ
- VT tags: "c2", "malware", "ransomware"
"""

    def _build_tools(self) -> list:
        return [
            {"type": "function", "function": {
                "name": "check_ip_reputation",
                "description": "Kiểm tra IP trên AbuseIPDB",
                "parameters": {"type": "object",
                               "properties": {"ip": {"type": "string"}},
                               "required": ["ip"]}}},
            {"type": "function", "function": {
                "name": "check_virustotal",
                "description": "Kiểm tra IP trên VirusTotal — tags, verdict, detection ratio",
                "parameters": {"type": "object",
                               "properties": {"ip": {"type": "string"}},
                               "required": ["ip"]}}},
            {"type": "function", "function": {
                "name": "whois_lookup",
                "description": "Tra cứu WHOIS",
                "parameters": {"type": "object",
                               "properties": {"ip": {"type": "string"}},
                               "required": ["ip"]}}},
            {"type": "function", "function": {
                "name": "scan_ports",
                "description": "Quét port của IP đáng ngờ",
                "parameters": {"type": "object",
                               "properties": {
                                   "target_ip": {"type": "string"},
                                   "ports": {"type": "array", "items": {"type": "integer"}},
                               }, "required": ["target_ip"]}}},
            {"type": "function", "function": {
                "name": "check_combined_logs",
                "description": "Tổng hợp thông tin từ auth.log và firewall.log cho IP nguồn",
                "parameters": {"type": "object",
                               "properties": {"src_ip": {"type": "string"}},
                               "required": ["src_ip"]}}},
        ]

    def _build_tool_map(self) -> dict:
        return {
            "check_ip_reputation": check_ip_reputation,
            "check_virustotal":    check_virustotal,
            "whois_lookup":        whois_lookup,
            "scan_ports":          scan_ports,
            "check_combined_logs": self._check_combined_logs,
        }

    @staticmethod
    def _check_combined_logs(src_ip: str) -> dict:
        result = {"src_ip": src_ip}
        for log_name, log_path in [
            ("auth",     "data/input/logs/auth.log"),
            ("firewall", "data/input/logs/firewall.log"),
            ("syslog",   "data/input/logs/syslog.log"),
        ]:
            path = Path(log_path)
            if path.exists():
                try:
                    lines = [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines()
                             if src_ip in l]
                    result[log_name] = {"found": len(lines), "sample": lines[:3]}
                except Exception as e:
                    result[log_name] = {"error": str(e)}
            else:
                result[log_name] = {"found": 0, "note": "file not found"}
        return result
