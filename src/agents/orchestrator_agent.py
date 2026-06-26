"""
orchestrator_agent.py — LLM Orchestrator điều phối Investigator Subagents

Luồng hoạt động:
  1. OrchestratorAgent (LLM) nhận alert
  2. LLM phân tích và gọi spawn_subagent() với loại investigator phù hợp
  3. Mỗi subagent chạy LLM riêng, tự gọi tools, báo findings về
  4. OrchestratorAgent tổng hợp tất cả findings → final verdict

Đây là SUBAGENT PATTERN thực sự:
  - Orchestrator KHÔNG biết trước subagent nào sẽ chạy
  - LLM quyết định dựa trên nội dung alert
  - Mỗi subagent có agency riêng (tự suy luận, tự chọn tools)
"""

import json
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

from src.utils.agent_loop import run_agent
from src.utils.logger import log_agent_start, log_agent_complete
from src.agents.investigators.ddos_investigator       import DDoSInvestigator
from src.agents.investigators.bruteforce_investigator import BruteForceInvestigator
from src.agents.investigators.portscan_investigator   import PortScanInvestigator
from src.agents.investigators.general_investigator    import GeneralInvestigator


# ── Subagent registry ─────────────────────────────────────────────────────────
INVESTIGATOR_REGISTRY = {
    "ddos":        DDoSInvestigator,
    "bruteforce":  BruteForceInvestigator,
    "portscan":    PortScanInvestigator,
    "general":     GeneralInvestigator,
}

# ── OrchestratorAgent system prompt ──────────────────────────────────────────
_SYSTEM = """Bạn là Orchestrator Agent của NIRO — hệ thống ứng cứu sự cố mạng.

Nhiệm vụ: Tổng hợp kết quả Stage 1+2, điều phối Investigator Subagents để XÁC NHẬN
hoặc BÁC BỎ các phân loại từ ML classifier và MITRE mapper, rồi ra final verdict.

=== Bạn nhận được 3 nguồn thông tin ===
1. Stage 1 (Raw data): threat_score, log pattern, PCAP signature, anomalies
2. Stage 2A (ML Classifier): phân loại incident_type + severity + MITRE theo LLM
3. Stage 2B (MITRE Mapper): top MITRE matches theo cosine similarity

=== Quy trình ===
Bước 1: So sánh Stage 2A và 2B — chúng có đồng thuận không?
  - Nếu ĐỒNG THUẬN (cùng MITRE, cùng loại) → spawn 1 investigator chuyên biệt để CONFIRM
  - Nếu MÂU THUẪN → spawn thêm "general" để phân giải

Bước 2: Spawn investigator(s) phù hợp với brief ĐẦY ĐỦ gồm Stage 1+2 findings.

Bước 3: Sau khi nhận findings → finalize_investigation() với:
  - Giải thích tại sao chọn MITRE technique này (dựa trên nguồn nào)
  - Nếu investigator mâu thuẫn với Stage 2A/2B → ưu tiên investigator (có tool evidence)

=== Investigators ===
- "ddos"       : SYN flood, amplification, volumetric attack
- "bruteforce" : Failed auth, SSH/FTP/RDP brute force, credential stuffing
- "portscan"   : Recon, service discovery, aggressive sweep
- "general"    : Exfiltration, C2, Bot, Unknown, hoặc khi 2A/2B mâu thuẫn

=== Nguyên tắc ưu tiên evidence ===
Investigator findings > Stage 2A/2B (vì có tool evidence thực tế)
Stage 2A (LLM reasoning) > Stage 2B (cosine similarity đơn thuần)
"""

_ORCHESTRATOR_TOOLS = [
    {"type": "function", "function": {
        "name": "spawn_subagent",
        "description": "Spawn một investigator subagent để điều tra. Subagent có LLM riêng và tự quyết định tools nào cần dùng.",
        "parameters": {
            "type": "object",
            "properties": {
                "investigator_type": {
                    "type": "string",
                    "enum": ["ddos", "bruteforce", "portscan", "general"],
                    "description": "Loại investigator cần spawn",
                },
                "brief": {
                    "type": "string",
                    "description": "Brief gửi cho subagent: mô tả alert, IP cần điều tra, dấu hiệu đáng ngờ",
                },
            },
            "required": ["investigator_type", "brief"],
        },
    }},
    {"type": "function", "function": {
        "name": "finalize_investigation",
        "description": "Tổng hợp tất cả findings từ các subagents thành verdict cuối cùng.",
        "parameters": {
            "type": "object",
            "properties": {
                "overall_risk":   {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "final_action":   {"type": "string", "enum": ["block", "monitor", "escalate", "close_fp"],
                                  "description": "block=chặn IP ngay, monitor=theo dõi, escalate=leo thang lên SOC, close_fp=đóng false positive"},
                "verdict_summary":{"type": "string", "description": "Tóm tắt toàn bộ cuộc điều tra"},
                "key_findings":   {"type": "array", "items": {"type": "string"},
                                  "description": "Top 5 phát hiện quan trọng nhất"},
                "mitre_technique":{"type": "string", "description": "MITRE ATT&CK technique ID phù hợp nhất"},
            },
            "required": ["overall_risk", "final_action", "verdict_summary", "key_findings"],
        },
    }},
]


def _build_stage2_context(alert: dict, stage2: dict) -> str:
    """
    Tạo section mô tả kết quả Stage 1+2 cho orchestrator LLM.
    Dùng enriched_alert fields nếu stage2=None.
    """
    lines = ["=== Kết quả phân tích trước đó ===", ""]

    # Stage 1 từ enriched_alert fields
    lines.append("--- Stage 1 (Raw Data) ---")
    lines.append(f"  Threat score : {alert.get('stage1_threat_score', '?')}/100")
    lines.append(f"  Risk level   : {alert.get('stage1_risk_level', '?')}")
    lines.append(f"  Is Tor       : {alert.get('stage1_is_tor', '?')}")
    lines.append(f"  Log pattern  : {alert.get('stage1_log_pattern', '?')}")
    lines.append(f"  Failed auth  : {alert.get('stage1_failed_auth', '?')}")
    lines.append(f"  PCAP sig     : {alert.get('stage1_pcap_sig', '?')}")
    lines.append(f"  Anomalies    : {alert.get('stage1_anomalies', [])}")
    lines.append("")

    # Stage 2A — từ stage2 dict hoặc enriched_alert fields
    ml_type   = alert.get("stage2_ml_type", "?")
    ml_sev    = alert.get("stage2_ml_severity", "?")
    ml_mitre  = alert.get("stage2_ml_mitre", "?")
    ml_conf   = "?"
    ml_rat    = "?"
    if stage2:
        clf      = stage2.get("ml", {}).get("classification", {})
        ml_type  = clf.get("incident_type", ml_type)
        ml_sev   = clf.get("severity", ml_sev)
        ml_mitre = clf.get("mitre_technique", ml_mitre)
        ml_conf  = f"{clf.get('confidence', 0):.0%}"
        ml_rat   = clf.get("rationale", "")[:120]

    lines.append("--- Stage 2A (ML Classifier — LLM reasoning) ---")
    lines.append(f"  Incident type : {ml_type}")
    lines.append(f"  Severity      : {ml_sev}")
    lines.append(f"  MITRE         : {ml_mitre}")
    lines.append(f"  Confidence    : {ml_conf}")
    if ml_rat:
        lines.append(f"  Rationale     : {ml_rat}")
    lines.append("")

    # Stage 2B — top MITRE từ cosine similarity
    mitre_top   = alert.get("stage2_mitre_top", "?")
    mitre_top2  = "?"
    mitre_agree = "?"
    if stage2:
        techs = stage2.get("mitre", {}).get("techniques", [])
        if techs:
            mitre_top  = techs[0].get("technique_id", mitre_top)
            mitre_top2 = techs[1].get("technique_id", "?") if len(techs) > 1 else "?"
        mitre_agree = "YES" if mitre_top == ml_mitre else "NO — mau thuan!"

    lines.append("--- Stage 2B (MITRE Mapper — cosine similarity) ---")
    lines.append(f"  Top match  : {mitre_top}")
    lines.append(f"  2nd match  : {mitre_top2}")
    lines.append(f"  Dong thuan voi 2A? : {mitre_agree}")
    lines.append("")

    return "\n".join(lines)


def _run_investigator(investigator_type: str, brief: str, verbose: bool) -> dict:
    """Chạy 1 investigator subagent (blocking). Dùng trong ThreadPoolExecutor."""
    cls = INVESTIGATOR_REGISTRY.get(investigator_type)
    if cls is None:
        return {"error": f"Unknown investigator: {investigator_type}", "subagent": investigator_type}
    return cls().run(brief=brief, verbose=verbose)


def run_orchestrator(alert: dict, stage2: dict = None, verbose: bool = True) -> dict:
    """
    Entry point: OrchestratorAgent LLM phân tích alert → spawn subagents → finalize.

    Returns:
        {
            "verdict": { overall_risk, final_action, verdict_summary, key_findings, mitre_technique },
            "subagent_findings": [ { subagent, summary, risk_level, indicators, ... }, ... ],
            "spawn_log": [ { investigator_type, brief }, ... ],
            "iterations": int,
            "error": str | None,
        }
    """
    log_agent_start("orchestrator", alert.get("src_ip", "?"))
    t0 = time.perf_counter()

    # State chia sẻ giữa orchestrator LLM và subagents
    spawn_log        = []   # danh sách subagents được spawn
    subagent_findings = []  # findings từ từng subagent

    # ── Tool implementations ──────────────────────────────────────────────────
    def spawn_subagent(investigator_type: str, brief: str) -> dict:
        """Orchestrator gọi tool này → subagent chạy → trả findings."""
        print(f"\n  ┌─ [SPAWN] {investigator_type.upper()}-Investigator", flush=True)
        print(f"  │  Brief: {brief[:120]}{'...' if len(brief) > 120 else ''}", flush=True)

        spawn_log.append({"investigator_type": investigator_type, "brief": brief})

        findings = _run_investigator(investigator_type, brief, verbose=verbose)
        subagent_findings.append(findings)

        print(f"  └─ [{findings.get('subagent','?')}] risk={findings.get('risk_level','?')} "
              f"conf={findings.get('confidence',0):.0%}", flush=True)

        # Trả summary về orchestrator LLM để nó suy luận tiếp
        return {
            "subagent":   findings.get("subagent"),
            "risk_level": findings.get("risk_level"),
            "summary":    findings.get("summary"),
            "indicators": findings.get("indicators", []),
            "recommended_action": findings.get("recommended_action"),
            "confidence": findings.get("confidence"),
        }

    def finalize_investigation(**kw) -> dict:
        return kw

    tool_map = {
        "spawn_subagent":        spawn_subagent,
        "finalize_investigation": finalize_investigation,
    }

    # ── Build Stage 2 context section ────────────────────────────────────────
    stage2_section = _build_stage2_context(alert, stage2)

    # ── Orchestrator LLM request ──────────────────────────────────────────────
    request = f"""Điều phối điều tra cho alert sau. Bạn đã có kết quả Stage 1+2 — hãy dùng
chúng để spawn đúng investigator và ra final verdict có cơ sở.

{stage2_section}

=== Alert gốc ===
{json.dumps({k: v for k, v in alert.items() if not k.startswith("stage")}, indent=2, ensure_ascii=False)}

Bước 1: So sánh Stage 2A vs 2B — đồng thuận hay mâu thuẫn?
Bước 2: Spawn investigator phù hợp, brief phải gồm tóm tắt Stage 1+2 để investigator có context.
Bước 3: finalize_investigation() — giải thích tại sao chọn MITRE/risk/action này.
"""

    result = run_agent(
        system_prompt=_SYSTEM,
        user_request=request,
        tools=_ORCHESTRATOR_TOOLS,
        tool_map=tool_map,
        max_iterations=12,
        verbose=verbose,
    )

    # Lấy verdict từ finalize_investigation call
    verdict = {}
    for call in reversed(result.get("tool_call_log", [])):
        if call["tool"] == "finalize_investigation":
            verdict = call["result"]
            break

    if not verdict:
        verdict = {
            "overall_risk": "medium",
            "final_action": "monitor",
            "verdict_summary": "Orchestrator could not finalize",
            "key_findings": [],
            "error": result.get("error"),
        }

    duration = time.perf_counter() - t0
    log_agent_complete("orchestrator", verdict.get("final_action", "?"),
                       result.get("iterations", 0), result.get("total_tokens", 0))

    print(f"\n  ══ ORCHESTRATOR VERDICT ══", flush=True)
    print(f"  Risk:    {verdict.get('overall_risk','?').upper()}", flush=True)
    print(f"  Action:  {verdict.get('final_action','?').upper()}", flush=True)
    print(f"  MITRE:   {verdict.get('mitre_technique','N/A')}", flush=True)
    print(f"  Subagents spawned: {len(spawn_log)}", flush=True)
    print(f"  Duration: {duration:.1f}s", flush=True)

    return {
        "verdict":           verdict,
        "subagent_findings": subagent_findings,
        "spawn_log":         spawn_log,
        "iterations":        result.get("iterations", 0),
        "total_tokens":      result.get("total_tokens", 0),
        "duration_sec":      round(duration, 2),
        "error":             result.get("error"),
    }
