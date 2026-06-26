"""
ml_classifier.py — Stage 2A: ML Classification

Dùng DeepSeek LLM để phân loại incident type và severity
dựa trên dữ liệu từ Stage 1 (recon + logs + PCAP).

LLM client được khởi tạo một lần (singleton) và tái sử dụng
cho tất cả các lần gọi, tránh overhead tạo connection liên tục.
"""

import json
import threading
from pathlib import Path
from typing import Optional

from src.utils.agent_loop import run_agent, get_llm_client
from src.utils.logger import log_agent_start, log_agent_complete


# ── Singleton LLM client - pre-loaded  ────────────────
_CLIENT_LOCK   = threading.Lock()
_CLIENT_CACHE: Optional[tuple] = None   # (backend, client)

def _get_client():
    global _CLIENT_CACHE
    with _CLIENT_LOCK:
        if _CLIENT_CACHE is None:
            _CLIENT_CACHE = get_llm_client()
        return _CLIENT_CACHE


# ── MITRE ATT&CK Knowledge Base ───────────────────────────────────────────────
MITRE_KB = {
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "containment": [
            "Block source IP tại firewall 24h",
            "Bật account lockout policy (≤5 attempts)",
            "Bắt buộc MFA cho tất cả remote access",
            "Rotate credentials của tài khoản bị tấn công",
            "Deploy fail2ban hoặc tương đương",
        ],
    },
    "T1595.001": {
        "name": "Active Scanning: Scanning IP Blocks",
        "tactic": "Reconnaissance",
        "containment": [
            "Block source IP tại firewall",
            "Rate-limit SYN packets từ IP lạ",
            "Review dịch vụ đang expose — đóng port không cần thiết",
            "Cài đặt network segmentation",
        ],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "containment": [
            "Lập tức block destination IP/domain",
            "Cô lập máy chủ nguồn khỏi mạng",
            "Capture và phân tích egress traffic",
            "Tìm và xoá malware/backdoor",
            "Kiểm tra dữ liệu nào đã bị lấy đi",
            "Báo cáo DPO nếu có PII bị exfil",
        ],
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "containment": [
            "Rate-limit traffic từ ASN nguồn",
            "Bật DDoS mitigation (Cloudflare/AWS Shield)",
            "Liên hệ upstream ISP để null-route",
            "Kích hoạt traffic scrubbing",
        ],
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "containment": [
            "Block C2 domain/IP tại DNS và firewall",
            "Cô lập host nghi ngờ",
            "Phân tích memory dump để tìm malware",
            "Review tất cả outbound HTTPS connections",
        ],
    },
}

_SYSTEM_PATH = Path(".pi/prompts/ml_classifier_system.md")
_SYSTEM_FALLBACK = """Bạn là ML classification agent của NIRO.

Phân loại incident dựa trên tất cả dữ liệu Stage 1 (recon + logs + PCAP).
LUÔN gọi classify_incident() làm bước cuối cùng.

incident_type: SSH_BRUTE_FORCE | PORT_SCAN | DATA_EXFILTRATION | DDOS | MALWARE_C2 | UNKNOWN
severity: LOW | MEDIUM | HIGH | CRITICAL (dựa vào threat_score và evidence từ nhiều nguồn)
"""

_CLASSIFY_TOOL = {
    "type": "function",
    "function": {
        "name": "classify_incident",
        "description": "Ghi lại kết quả phân loại cuối cùng",
        "parameters": {
            "type": "object",
            "properties": {
                "incident_type":    {"type": "string",
                    "enum": ["SSH_BRUTE_FORCE","PORT_SCAN","DATA_EXFILTRATION","DDOS","MALWARE_C2","UNKNOWN"]},
                "severity":         {"type": "string", "enum": ["LOW","MEDIUM","HIGH","CRITICAL"]},
                "mitre_technique":  {"type": "string"},
                "mitre_tactic":     {"type": "string"},
                "confidence":       {"type": "number", "minimum": 0, "maximum": 1},
                "is_true_positive": {"type": "boolean"},
                "rationale":        {"type": "string"},
                "secondary_techniques": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["incident_type","severity","mitre_technique","confidence","is_true_positive","rationale"],
        },
    },
}


def run_ml_classifier(alert: dict, stage1_results: dict, verbose: bool = True) -> dict:
    """Stage 2A: Phân loại incident bằng LLM."""
    if verbose:
        print(f"  [ML-CLASSIFY ] Starting — {alert.get('rf_class')} conf={alert.get('ml_confidence',0):.0%}", flush=True)

    try:
        system = _SYSTEM_PATH.read_text(encoding="utf-8") if _SYSTEM_PATH.exists() else _SYSTEM_FALLBACK
        request = _build_request(alert, stage1_results)

        result = run_agent(
            system_prompt=system,
            user_request=request,
            tools=[_CLASSIFY_TOOL],
            tool_map={"classify_incident": lambda **kw: kw},
            max_iterations=5,
            verbose=verbose,
            llm_client=_get_client(),   # dùng singleton — không tạo client mới
        )

        clf = {}
        for call in reversed(result.get("tool_call_log", [])):
            if call["tool"] == "classify_incident":
                clf = call["result"]
                break

        if not clf:
            clf = _fallback_classify(alert, stage1_results)

        # Clamp confidence về [0, 1]
        clf["confidence"] = max(0.0, min(1.0, float(clf.get("confidence", 0.5))))

        mitre_id           = clf.get("mitre_technique", "")
        secondary_ids      = clf.get("secondary_techniques", [])
        mitre_details      = MITRE_KB.get(mitre_id, {})
        containment        = mitre_details.get("containment", _default_containment(clf))
        # Gom containment từ secondary techniques nếu primary không có trong KB
        if not mitre_details:
            for sec_id in secondary_ids:
                sec_details = MITRE_KB.get(sec_id, {})
                if sec_details.get("containment"):
                    containment = sec_details["containment"]
                    mitre_details = sec_details
                    break

        if verbose:
            print(f"  [ML-CLASSIFY ] Done — {clf.get('incident_type')} | {clf.get('severity')} "
                  f"| {clf.get('mitre_technique')} | conf={clf.get('confidence',0):.0%}", flush=True)

        log_agent_complete("ml-classifier",
                           f"{clf.get('incident_type')} {clf.get('severity')} {clf.get('mitre_technique')}",
                           result.get("iterations", 0), result.get("total_tokens", 0))

        return {
            "classification":      clf,
            "containment_steps":   containment,
            "mitre_details":       mitre_details,
            "secondary_techniques": secondary_ids,
            "error":               result.get("error"),
        }

    except Exception as e:
        if verbose:
            print(f"  [ML-CLASSIFY ] ERROR (using fallback): {e}", flush=True)
        clf = _fallback_classify(alert, stage1_results)
        mitre_id = clf.get("mitre_technique", "")
        return {"classification": clf,
                "containment_steps": MITRE_KB.get(mitre_id, {}).get("containment", []),
                "mitre_details": MITRE_KB.get(mitre_id, {}), "error": str(e)}


def _build_request(alert: dict, s1: dict) -> str:
    recon  = s1.get("recon", {})
    logs   = s1.get("log_collect", {})
    pcap   = s1.get("pcap", {})
    rp     = recon.get("risk_profile", {})
    ls     = logs.get("summary", {})
    ff     = pcap.get("flow_features", {})

    return f"""Phân loại incident dựa trên ALL dữ liệu Stage 1:

## Alert gốc
{json.dumps(alert, indent=2)}

## Stage 1A — Recon
- IP: {rp.get('target_ip', alert.get('src_ip'))}
- AbuseIPDB Score: {rp.get('threat_score', 0)}/100
- Risk Level: {rp.get('risk_level', '?')}
- Is Tor: {rp.get('isTor', False)}
- Country: {rp.get('country', '?')}
- Open Ports: {rp.get('open_ports', [])}

## Stage 1B — Logs
- Failed Auth: {ls.get('failed_auth_count', 0)}
- Firewall Blocks: {ls.get('blocked_connections', 0)}
- Targeted Ports: {ls.get('targeted_ports', [])}
- Attack Pattern (logs): {ls.get('attack_pattern', '?')}

## Stage 1C — PCAP
- Packets/sec: {ff.get('packets_per_sec', 0)}
- Bytes/packet: {ff.get('bytes_per_packet', 0)}
- Flow signature: {pcap.get('flow_signature_match', '?')}
- Anomalies: {pcap.get('anomaly_indicators', [])}

Gọi classify_incident() với đánh giá cuối cùng."""


def _fallback_classify(alert: dict, s1: dict) -> dict:
    rf    = alert.get("rf_class", "")
    score = s1.get("recon", {}).get("risk_profile", {}).get("threat_score", 0)
    conf  = alert.get("ml_confidence", 0.5)

    mapping = {
        "BruteForce":   ("SSH_BRUTE_FORCE",  "T1110.001", "Credential Access"),
        "PortScan":     ("PORT_SCAN",         "T1595.001", "Reconnaissance"),
        "Exfiltration": ("DATA_EXFILTRATION", "T1041",     "Exfiltration"),
        "DDoS":         ("DDOS",              "T1498",     "Impact"),
    }
    for k, (itype, mitre, tactic) in mapping.items():
        if k in rf:
            sev = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW"
            return {"incident_type": itype, "severity": sev, "mitre_technique": mitre,
                    "mitre_tactic": tactic, "confidence": conf, "is_true_positive": score >= 30,
                    "rationale": f"Rule-based: {rf}, score={score}"}

    return {"incident_type": "UNKNOWN", "severity": "LOW", "mitre_technique": "T1046",
            "mitre_tactic": "Discovery", "confidence": 0.3, "is_true_positive": False,
            "rationale": "Cannot determine incident type"}


def _default_containment(clf: dict) -> list:
    sev = clf.get("severity", "LOW")
    steps = ["Ghi chép findings vào incident ticket"]
    if sev in ("HIGH", "CRITICAL"):
        steps += ["Block source IP tại perimeter firewall", "Notify SOC team ngay",
                  "Preserve evidence (logs, PCAP, memory dump)"]
    elif sev == "MEDIUM":
        steps += ["Monitor source IP 48h", "Review firewall rules"]
    return steps


if __name__ == "__main__":
    import argparse, sys, os
    from dotenv import load_dotenv; load_dotenv()

    parser = argparse.ArgumentParser()
    parser.add_argument("--alert",         required=True)
    parser.add_argument("--stage1-result", required=True)
    parser.add_argument("--output",        default=".pi/triage/ml_result.json")
    parser.add_argument("--quiet",         action="store_true")
    args = parser.parse_args()

    alert  = json.loads(args.alert) if not os.path.isfile(args.alert) \
             else json.load(open(args.alert, encoding="utf-8"))
    stage1 = json.load(open(args.stage1_result, encoding="utf-8"))

    result = run_ml_classifier(alert, stage1, verbose=not args.quiet)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    c = result["classification"]
    print(f"[ML-CLASSIFY] {c.get('incident_type')} | {c.get('severity')} | {c.get('mitre_technique')} | conf={c.get('confidence',0):.0%}")
    sys.exit(0)
