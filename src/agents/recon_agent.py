"""
recon_agent.py — Stage 1A: Threat Intelligence & Network Recon

Chạy song song với log_collector và pcap_analyzer.
Timeout được kiểm soát từ orchestrator (asyncio.wait_for).

Calls: AbuseIPDB, port scan, WHOIS, DNS
"""

import json
import os
from pathlib import Path

from src.utils.agent_loop import run_agent
from src.utils.logger import log_agent_start, log_agent_complete
from src.tools.threat_intel_tools import check_ip_reputation, check_virustotal
from src.tools.network_tools import scan_ports, grab_banner, resolve_dns, whois_lookup

_SYSTEM = """Bạn là recon agent của NIRO. Nhiệm vụ của bạn là thu thập thông tin
tình báo về một địa chỉ IP đang nghi ngờ.

Quy trình:
1. check_ip_reputation — lấy AbuseIPDB score, kiểm tra Tor exit node
2. check_virustotal — lấy VirusTotal detection ratio, verdict, tags
3. scan_ports — quét các cổng phổ biến
4. whois_lookup — thông tin WHOIS (country, ISP, org)
5. Nếu cần, dùng grab_banner hoặc resolve_dns để bổ sung
6. generate_risk_profile — tổng hợp thành hồ sơ rủi ro (BẮT BUỘC gọi cuối cùng)

Khi tổng hợp threat_score:
- AbuseIPDB abuseScore >= 80 → +40 điểm
- VirusTotal malicious >= 5  → +30 điểm, verdict=MALICIOUS → +20 điểm
- isTor = true               → +20 điểm
- tags chứa "tor" hoặc "vpn" → +10 điểm

QUAN TRỌNG: Luôn gọi generate_risk_profile() làm bước cuối cùng.
"""

_TOOLS = [
    {"type": "function", "function": {
        "name": "check_ip_reputation",
        "description": "Tra cứu reputation của IP trên AbuseIPDB (abuse score, isTor, country, ISP)",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}}, "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "check_virustotal",
        "description": "Tra cứu IP trên VirusTotal — lấy detection ratio (malicious/total), verdict (MALICIOUS/SUSPICIOUS/CLEAN), reputation score, tags (tor, vpn, ...)",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}}, "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "scan_ports",
        "description": "Quét cổng TCP phổ biến của một IP",
        "parameters": {"type": "object", "properties": {
            "target_ip": {"type": "string"},
            "ports": {"type": "array", "items": {"type": "integer"}}},
            "required": ["target_ip"]}}},
    {"type": "function", "function": {
        "name": "grab_banner",
        "description": "Lấy banner của một service trên port cụ thể",
        "parameters": {"type": "object", "properties": {
            "target_ip": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["target_ip", "port"]}}},
    {"type": "function", "function": {
        "name": "whois_lookup",
        "description": "Tra cứu WHOIS cho một IP",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}}, "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "resolve_dns",
        "description": "Phân giải DNS hostname",
        "parameters": {"type": "object", "properties": {
            "hostname": {"type": "string"}}, "required": ["hostname"]}}},
    {"type": "function", "function": {
        "name": "generate_risk_profile",
        "description": "Tổng hợp tất cả thông tin recon thành hồ sơ rủi ro",
        "parameters": {"type": "object", "properties": {
            "target_ip":           {"type": "string"},
            "threat_score":        {"type": "integer", "minimum": 0, "maximum": 100},
            "risk_level":          {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "isTor":               {"type": "boolean"},
            "country":             {"type": "string"},
            "isp":                 {"type": "string"},
            "open_ports":          {"type": "array", "items": {"type": "integer"}},
            "recommended_action":  {"type": "string"},
            "summary":             {"type": "string"},
        }, "required": ["target_ip", "threat_score", "risk_level", "recommended_action", "summary"]}}},
]

_TOOL_MAP = {
    "check_ip_reputation":   check_ip_reputation,
    "check_virustotal":      check_virustotal,
    "scan_ports":            scan_ports,
    "grab_banner":           grab_banner,
    "whois_lookup":          whois_lookup,
    "resolve_dns":           resolve_dns,
    "generate_risk_profile": lambda **kw: kw,
}


def run_recon(target_ip: str, alert: dict, verbose: bool = True) -> dict:
    log_agent_start("recon", target_ip)

    request = f"""Thu thập thông tin trinh sát về IP: {target_ip}

Alert context:
{json.dumps(alert, indent=2, ensure_ascii=False)}

Bắt đầu bằng check_ip_reputation và check_virustotal (cả hai để có threat intel đầy đủ),
sau đó scan_ports và whois_lookup.
Kết thúc bằng generate_risk_profile với threat_score tổng hợp từ cả AbuseIPDB lẫn VirusTotal.
"""
    result = run_agent(
        system_prompt=_SYSTEM,
        user_request=request,
        tools=_TOOLS,
        tool_map=_TOOL_MAP,
        max_iterations=8,
        verbose=verbose,
    )

    risk_profile = {}
    for call in reversed(result.get("tool_call_log", [])):
        if call["tool"] == "generate_risk_profile":
            risk_profile = call["result"]
            break

    if not risk_profile:
        risk_profile = _fallback_risk_profile(target_ip, alert)

    log_agent_complete("recon", f"risk={risk_profile.get('risk_level')} score={risk_profile.get('threat_score')}",
                       result.get("iterations", 0), result.get("total_tokens", 0))
    return {"risk_profile": risk_profile, "tool_log": result.get("tool_call_log", []),
            "error": result.get("error")}


def _fallback_risk_profile(ip: str, alert: dict) -> dict:
    conf = alert.get("ml_confidence", 0.5)
    score = int(conf * 60)
    return {
        "target_ip": ip, "threat_score": score,
        "risk_level": "high" if score >= 60 else "medium" if score >= 40 else "low",
        "isTor": False, "country": "?", "isp": "unknown", "open_ports": [],
        "recommended_action": "investigate",
        "summary": f"Fallback profile (conf={conf:.0%})",
    }


if __name__ == "__main__":
    import argparse, sys
    from dotenv import load_dotenv; load_dotenv()

    parser = argparse.ArgumentParser()
    parser.add_argument("--alert",         required=True)
    parser.add_argument("--triage-result", required=True)
    parser.add_argument("--output",        default=".pi/triage/recon_result.json")
    parser.add_argument("--quiet",         action="store_true")
    args = parser.parse_args()

    alert = json.loads(args.alert) if not os.path.isfile(args.alert) \
            else json.load(open(args.alert, encoding="utf-8"))

    result = run_recon(alert.get("src_ip", ""), alert, verbose=not args.quiet)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    rp = result.get("risk_profile", {})
    print(f"[RECON] risk={rp.get('risk_level')} score={rp.get('threat_score')} isTor={rp.get('isTor')}")
    sys.exit(0)
