"""
bruteforce_investigator.py — Subagent chuyên điều tra BruteForce / Credential attacks

Được spawn khi phát hiện SSH/FTP brute force, password spraying.
Tools: AbuseIPDB, VirusTotal, log analysis, auth pattern checker.
"""

import re
from pathlib import Path
from .base import InvestigatorSubagent
from src.tools.threat_intel_tools import check_ip_reputation, check_virustotal
from src.tools.network_tools import whois_lookup


class BruteForceInvestigator(InvestigatorSubagent):
    NAME = "BruteForce-Investigator"
    SYSTEM = """Bạn là chuyên gia điều tra Brute Force / Credential attacks của NIRO.

Nhiệm vụ: Xác nhận cuộc tấn công brute force và đánh giá nguy cơ tài khoản bị compromise.

Chiến lược điều tra:
1. check_auth_log → đếm failed login attempts từ IP nguồn
2. check_ip_reputation → xem IP có trong blacklist không
3. check_virustotal → xem có phải botnet/credential stuffing tool không
4. check_targeted_accounts → xem tài khoản nào đang bị nhắm tới
5. submit_findings → tổng hợp

BruteForce indicators:
- failed_auth > 50 trong 5 phút = HIGH
- failed_auth > 200 = CRITICAL
- Nhiều username khác nhau (password spraying)
- 1 username, nhiều password (credential stuffing)
- Thành công sau nhiều lần thất bại = COMPROMISE

risk_level:
- critical: có successful login sau brute force (compromise)
- high:     > 200 failed attempts hoặc IP blacklisted
- medium:   50-200 failed attempts
- low:      < 50 attempts, chưa chắc intentional
"""

    def _build_tools(self) -> list:
        return [
            {"type": "function", "function": {
                "name": "check_auth_log",
                "description": "Phân tích auth.log — đếm failed/success login từ IP nguồn, liệt kê usernames bị tấn công",
                "parameters": {"type": "object",
                               "properties": {
                                   "src_ip":   {"type": "string"},
                                   "log_path": {"type": "string", "default": "data/input/logs/auth.log"},
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
                "name": "check_targeted_accounts",
                "description": "Liệt kê các tài khoản bị nhắm tới và phân loại kiểu tấn công (spraying vs stuffing)",
                "parameters": {"type": "object",
                               "properties": {
                                   "src_ip":   {"type": "string"},
                                   "log_path": {"type": "string", "default": "data/input/logs/auth.log"},
                               }, "required": ["src_ip"]}}},
        ]

    def _build_tool_map(self) -> dict:
        return {
            "check_ip_reputation":    check_ip_reputation,
            "check_virustotal":       check_virustotal,
            "check_auth_log":         self._check_auth_log,
            "check_targeted_accounts": self._check_targeted_accounts,
        }

    @staticmethod
    def _check_auth_log(src_ip: str, log_path: str = "data/input/logs/auth.log") -> dict:
        path = Path(log_path)
        if not path.exists():
            return {"src_ip": src_ip, "failed": 0, "success": 0,
                    "note": f"Log file not found: {log_path}"}
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            lines = [l for l in text.splitlines() if src_ip in l]
            failed  = sum(1 for l in lines if "Failed password" in l or "Invalid user" in l)
            success = sum(1 for l in lines if "Accepted password" in l or "Accepted publickey" in l)
            return {
                "src_ip": src_ip, "failed": failed, "success": success,
                "total_lines": len(lines),
                "compromised": success > 0 and failed > 10,
                "severity": "critical" if success > 0 else "high" if failed > 200 else "medium" if failed > 50 else "low",
            }
        except Exception as e:
            return {"src_ip": src_ip, "failed": 0, "success": 0, "error": str(e)}

    @staticmethod
    def _check_targeted_accounts(src_ip: str, log_path: str = "data/input/logs/auth.log") -> dict:
        path = Path(log_path)
        if not path.exists():
            return {"src_ip": src_ip, "usernames": [], "attack_type": "unknown"}
        try:
            text  = path.read_text(encoding="utf-8", errors="replace")
            lines = [l for l in text.splitlines() if src_ip in l and "Failed" in l]
            usernames = []
            for l in lines:
                m = re.search(r"(?:user|invalid user)\s+(\S+)", l, re.IGNORECASE)
                if m:
                    usernames.append(m.group(1))
            unique = list(set(usernames))
            attack_type = "PASSWORD_SPRAYING" if len(unique) > 5 else \
                          "CREDENTIAL_STUFFING" if len(unique) == 1 else "BRUTE_FORCE"
            return {
                "src_ip": src_ip,
                "unique_usernames": len(unique),
                "usernames_sample": unique[:10],
                "total_attempts": len(usernames),
                "attack_type": attack_type,
            }
        except Exception as e:
            return {"src_ip": src_ip, "usernames": [], "attack_type": "unknown", "error": str(e)}
