"""
report_agent.py — Stage 3B: Incident Report Generation

Luôn chạy — tổng hợp toàn bộ pipeline thành IR Report chuẩn.
Output: Markdown file tại reports/{ip}_{timestamp}_incident.md
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def run_report(
    alert: dict,
    triage_result: dict,
    recon_result: dict,
    response_result: dict = None,
    pipeline_duration_sec: float = 0,
    verbose: bool = True,
) -> dict:
    """Stage 3B: Tạo IR Report."""
    if verbose:
        print("  [REPORT      ] Generating IR report...", flush=True)

    ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    src_ip      = alert.get("src_ip", "unknown").replace(".", "_")
    incident_id = f"INC-{ts}-{alert.get('alert_id', 'UNK')}"

    report_dir  = Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"{src_ip}_{ts}_incident.md"

    content = _build_report(incident_id, alert, triage_result, recon_result,
                             response_result, pipeline_duration_sec)
    report_path.write_text(content, encoding="utf-8")

    routing = triage_result.get("routing", {})
    rp      = recon_result.get("risk_profile", {})
    clf     = recon_result.get("ml_classification", {})
    outcome = _determine_outcome(routing, rp, clf, response_result)

    if verbose:
        print(f"  [REPORT      ] Done → {report_path}", flush=True)

    return {
        "incident_id": incident_id,
        "report_path": str(report_path),
        "outcome":     outcome,
        "error":       None,
    }


def _determine_outcome(routing, rp, clf, response):
    action   = routing.get("action", "monitor")
    severity = clf.get("severity", rp.get("risk_level", "low")).upper()

    if action == "close_fp":
        return "FALSE_POSITIVE"
    if response and response.get("blocked_ips"):
        return "BLOCKED"
    if severity in ("HIGH", "CRITICAL") and action == "escalate":
        return "ESCALATED"
    return "MONITORED"


def _build_report(incident_id, alert, triage, recon, response, duration) -> str:
    ts       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    routing  = triage.get("routing", {})
    rp       = recon.get("risk_profile", {})
    clf      = recon.get("ml_classification", {})
    mitre    = recon.get("mitre_techniques", [])
    log_sum  = recon.get("log_summary", {})
    pcap_sum = recon.get("pcap_summary", {})
    contain  = recon.get("containment_steps", [])
    resp     = response or {}

    # MITRE ATT&CK section — highlight selected technique
    selected_mitre = clf.get("mitre_technique", "")
    mitre_sec = ""
    if mitre:
        rows = []
        for t in mitre[:5]:
            tid = t.get("technique_id", "?")
            mark = " [*]" if tid == selected_mitre else ""
            bold = "**" if tid == selected_mitre else ""
            rows.append(
                f"| {bold}{tid}{mark}{bold} | {bold}{t.get('name','?')}{bold} | {t.get('tactic','?')} | {t.get('similarity',0):.0%} |"
            )
        mitre_sec = "\n".join(rows)
    if not mitre_sec and selected_mitre:
        mitre_sec = f"| **{selected_mitre} [*]** | **{clf.get('mitre_tactic','?')}** | — | ML selected |"

    containment_md = "\n".join(f"- [ ] {step}" for step in contain) if contain \
                     else "- [ ] Điều tra thủ công"

    actions_md = "\n".join(f"- `{a}`" for a in resp.get("actions_taken", [])) if resp.get("actions_taken") \
                 else "- Không có action tự động"

    # Final verdict
    incident_type = clf.get("incident_type", alert.get("rf_class", "UNKNOWN"))
    severity      = clf.get("severity", "UNKNOWN")
    final_mitre   = clf.get("mitre_technique", "—")
    outcome_str   = _determine_outcome(routing, rp, clf, response)
    outcome_icon  = {"BLOCKED": "[!!] BLOCKED", "ESCALATED": "[!] ESCALATED",
                     "MONITORED": "[~] MONITORED", "FALSE_POSITIVE": "[OK] FALSE POSITIVE"}.get(outcome_str, outcome_str)

    return f"""# Incident Report — {incident_id}

**Generated**: {ts}
**Pipeline duration**: {duration:.1f}s

---

## ⚡ Attack Summary

| Field | Value |
|---|---|
| **Attack Type** | **{incident_type}** |
| **Severity** | **{severity}** |
| **MITRE Technique** | **{final_mitre}** |
| **Outcome** | **{outcome_icon}** |
| **Source IP** | `{alert.get('src_ip', '?')}` |

---

## 1. Alert Summary

| Field | Value |
|---|---|
| Alert ID | `{alert.get('alert_id', '?')}` |
| Source IP | `{alert.get('src_ip', '?')}` |
| Destination | `{alert.get('dst_ip', '?')}:{alert.get('dst_port', '?')}` |
| RF Class | `{alert.get('rf_class', '?')}` |
| ML Confidence | `{alert.get('ml_confidence', 0):.0%}` |
| Description | {alert.get('description', '—')} |

---

## 2. Triage Decision

| Field | Value |
|---|---|
| Action | **{routing.get('action', '?').upper()}** |
| Priority | {routing.get('priority', '?')}/10 |
| Justification | {routing.get('justification', '?')} |

---

## 3. Stage 1 — Threat Intelligence & Recon

### 3.1 IP Reputation (AbuseIPDB)
| Field | Value |
|---|---|
| Threat Score | {rp.get('threat_score', '?')}/100 |
| Risk Level | **{rp.get('risk_level', '?').upper()}** |
| Is Tor Exit Node | {rp.get('isTor', False)} |
| Country / ISP | {rp.get('country', '?')} / {rp.get('isp', '?')} |
| Open Ports | {rp.get('open_ports', [])} |

### 3.2 Log Analysis
| Field | Value |
|---|---|
| Failed Auth Count | {log_sum.get('failed_auth_count', 0)} |
| Firewall Blocks | {log_sum.get('blocked_connections', 0)} |
| Attack Pattern | `{log_sum.get('attack_pattern', '?')}` |
| Targeted Ports | {log_sum.get('targeted_ports', [])} |

### 3.3 PCAP Analysis
| Field | Value |
|---|---|
| Flow Signature | `{pcap_sum.get('flow_signature', '?')}` |
| PCAP Risk Score | {pcap_sum.get('risk_score', '?')} |
| Anomaly Indicators | {pcap_sum.get('anomalies', [])} |

---

## 4. Stage 2 — ML Classification & MITRE ATT&CK

| Field | Value |
|---|---|
| Incident Type | **{clf.get('incident_type', '?')}** |
| Severity | **{clf.get('severity', '?')}** |
| Confidence | {clf.get('confidence', 0):.0%} |
| Is True Positive | {clf.get('is_true_positive', '?')} |
| Rationale | {clf.get('rationale', clf.get('classification_rationale', '?'))} |

### MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Similarity |
|---|---|---|---|
{mitre_sec if mitre_sec else "| — | — | — | — |"}

---

## 5. Stage 3 — Containment Steps

{containment_md}

---

## 6. Response Actions Taken

{actions_md}

{f"**Ticket**: `{resp.get('ticket_id', '—')}`" if resp.get('ticket_id') else ""}
{f"**Blocked IPs**: {resp.get('blocked_ips', [])}" if resp.get('blocked_ips') else ""}

---

## 7. Recommendations

{_recommendations(rp, clf)}

---

*NIRO — Network Incident Response Orchestrator*
*Report ID: {incident_id}*
"""


def _recommendations(rp: dict, clf: dict) -> str:
    sev = clf.get("severity", "LOW")
    itype = clf.get("incident_type", "UNKNOWN")

    lines = []
    if rp.get("isTor"):
        lines.append("- Block toàn bộ Tor exit node ranges (list tại https://check.torproject.org/exit-addresses)")
    if sev == "CRITICAL":
        lines.append("- Escalate ngay tới CISO và team ứng cứu sự cố")
        lines.append("- Preserve forensic evidence trước khi remediate")
    if itype == "DATA_EXFILTRATION":
        lines.append("- Kiểm tra toàn bộ dữ liệu nhạy cảm có thể bị lấy")
        lines.append("- Báo cáo DPO theo yêu cầu GDPR nếu có PII")
    if itype in ("SSH_BRUTE_FORCE",):
        lines.append("- Review SSH config: disable root login, dùng key-based auth")
        lines.append("- Triển khai MFA cho tất cả remote access")
    if not lines:
        lines.append("- Monitor IP này trong 72h tiếp theo")
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse, sys
    parser = argparse.ArgumentParser()
    parser.add_argument("--alert",           required=True)
    parser.add_argument("--triage-result",   required=True)
    parser.add_argument("--recon-result",    required=True)
    parser.add_argument("--response-result", default=None)
    parser.add_argument("--duration",        type=float, default=0)
    parser.add_argument("--output",          default=".pi/triage/report_result.json")
    parser.add_argument("--quiet",           action="store_true")
    args = parser.parse_args()

    alert  = json.loads(args.alert) if not os.path.isfile(args.alert) \
             else json.load(open(args.alert, encoding="utf-8"))
    triage = json.load(open(args.triage_result, encoding="utf-8"))
    recon  = json.load(open(args.recon_result, encoding="utf-8"))
    resp   = json.load(open(args.response_result, encoding="utf-8")) if args.response_result else None

    result = run_report(alert, triage, recon, resp, args.duration, verbose=not args.quiet)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[REPORT] → {result['report_path']}  outcome={result['outcome']}")
    sys.exit(0)
