"""
test_full_pipeline.py — NIRO-PI Full Pipeline (Parallel + Subagent)

Luong thuc thi:
  alert.json
      |
  [Stage 0] Triage Agent           -> escalate / monitor / close_fp
      |
  [Stage 1] PARALLEL (asyncio.gather):
      +--> 1A: recon_agent          -> IP reputation + port scan
      +--> 1B: log_collector        -> auth/firewall/syslog analysis
      +--> 1C: pcap_analyzer        -> flow features + anomaly detection
      |
  [Stage 2] PARALLEL (asyncio.gather):
      +--> 2A: ml_classifier        -> incident type + MITRE (LLM)
      +--> 2B: mitre_mapper         -> cosine similarity embedding
      |
  [Stage 2C] OrchestratorAgent     -> LLM subagent spawner
      |
  [Stage 3] Report Agent           -> IR report .md

Cach dung:
  python3 scripts/test_full_pipeline.py --alert data/input/alerts/bruteforce.json
  python3 scripts/test_full_pipeline.py --alert data/input/alerts/ddos.json --save
"""

import argparse
import asyncio
import io
import json
import os
import sys
import time
from pathlib import Path

PIPELINE_CACHE_DIR = Path("logs/pipeline_cache")

# Fix Windows cp1252 encoding TRUOC KHI lam bat cu thu gi
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from dotenv import load_dotenv
load_dotenv()
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agents.triage_agent        import run_triage
from src.agents.recon_agent         import run_recon
from src.agents.log_collector       import run_log_collector
from src.agents.pcap_analyzer       import run_pcap_analyzer
from src.agents.ml_classifier       import run_ml_classifier
from src.agents.mitre_mapper        import run_mitre_mapper
from src.agents.orchestrator_agent  import run_orchestrator
from src.agents.response_agent      import run_response
from src.agents.report_agent        import run_report
from src.utils.pipeline_config      import (
    stage_mode, stage_timeout, stage_enabled, agent_enabled,
    print_config_summary, reload_config, get_config,
)

DIVIDER = "=" * 65


def banner(title: str):
    print(f"\n{DIVIDER}", flush=True)
    print(f"  {title}", flush=True)
    print(DIVIDER, flush=True)


def section(label: str, value: str):
    print(f"  {label:<18}: {value}", flush=True)


# ─────────────────────────────────────────────────────────
# STAGE 1 — recon + log + pcap  (mode từ pipeline.yaml)
# ─────────────────────────────────────────────────────────

def _find_pcap(alert: dict) -> str | None:
    """
    Tìm file PCAP trong data/input/pcap/ khớp với alert.
    Thử theo thứ tự:
      1. data/input/pcap/{alert_id}.pcap
      2. data/input/pcap/{rf_class}_{alert_id}.pcap  (ví dụ: bruteforce_BF-001.pcap)
      3. data/input/pcap/*{src_ip}*.pcap
      4. Bất kỳ file .pcap nào trong thư mục
    """
    pcap_dir  = Path("data/input/pcap")
    alert_id  = alert.get("alert_id", "")
    src_ip    = alert.get("src_ip", "").replace(".", "_")
    rf_class  = alert.get("rf_class", "").lower()

    candidates = [
        pcap_dir / f"{alert_id}.pcap",
        pcap_dir / f"{rf_class}_{alert_id}.pcap",
        pcap_dir / f"{alert_id}.pcap",
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    # Tìm theo src_ip hoặc alert_id trong tên file
    if pcap_dir.exists():
        for f in sorted(pcap_dir.glob("*.pcap")):
            if alert_id and alert_id.lower() in f.name.lower():
                return str(f)
            if src_ip and src_ip in f.name:
                return str(f)
        # Fallback: file pcap duy nhất trong thư mục
        all_pcaps = list(pcap_dir.glob("*.pcap"))
        if len(all_pcaps) == 1:
            return str(all_pcaps[0])

    return None


async def _run_stage1(alert: dict, verbose: bool) -> dict:
    """
    Chay 3 agents theo mode doc tu pipeline.yaml:
      parallel   -> asyncio.gather (chay dong thoi)
      sequential -> chay tung cai mot
    Agent bi disabled (enabled: false) se bi bo qua.
    """
    loop = asyncio.get_event_loop()
    mode = stage_mode("stage1_collection")

    recon_enabled = agent_enabled("stage1_collection", "recon")
    log_enabled   = agent_enabled("stage1_collection", "log_collect")
    pcap_enabled  = agent_enabled("stage1_collection", "pcap")

    # Tìm file PCAP tương ứng với alert này
    pcap_path = _find_pcap(alert)
    if pcap_path:
        print(f"  [PCAP        ] Found: {pcap_path}", flush=True)
    else:   
        print(f"  [PCAP        ] No file found → will derive from alert metadata", flush=True)

    active = [a for a, e in [("recon", recon_enabled), ("log_collect", log_enabled), ("pcap", pcap_enabled)] if e]
    print(f"  [STAGE1      ] mode={mode}  agents={active}", flush=True)
    t0 = time.perf_counter()

    empty_recon = {"risk_profile": {}, "skipped": True}
    empty_log   = {"summary": {}, "skipped": True}
    empty_pcap  = {"flow_features": {}, "anomaly_indicators": [], "skipped": True}

    if mode == "parallel":
        tasks = []
        if recon_enabled:
            tasks.append(loop.run_in_executor(None, lambda: run_recon(alert.get("src_ip", ""), alert, verbose=verbose)))
        if log_enabled:
            tasks.append(loop.run_in_executor(None, lambda: run_log_collector(alert, verbose=verbose)))
        if pcap_enabled:
            tasks.append(loop.run_in_executor(None, lambda: run_pcap_analyzer(alert, pcap_path, verbose=verbose)))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        idx = 0
        recon_result = results[idx] if recon_enabled else empty_recon; idx += recon_enabled
        log_result   = results[idx] if log_enabled   else empty_log;   idx += log_enabled
        pcap_result  = results[idx] if pcap_enabled  else empty_pcap
        label = "concurrently"
    else:
        recon_result = run_recon(alert.get("src_ip", ""), alert, verbose=verbose) if recon_enabled else empty_recon
        log_result   = run_log_collector(alert, verbose=verbose)                  if log_enabled   else empty_log
        pcap_result  = run_pcap_analyzer(alert, pcap_path, verbose=verbose)       if pcap_enabled  else empty_pcap
        label = "sequentially"

    # Xu ly exception
    if isinstance(recon_result, Exception):
        print(f"  [RECON       ] ERROR: {recon_result}", flush=True)
        recon_result = {"risk_profile": {}, "error": str(recon_result)}
    if isinstance(log_result, Exception):
        print(f"  [LOG-COLLECT ] ERROR: {log_result}", flush=True)
        log_result = {"summary": {}, "error": str(log_result)}
    if isinstance(pcap_result, Exception):
        print(f"  [PCAP        ] ERROR: {pcap_result}", flush=True)
        pcap_result = {"flow_features": {}, "anomaly_indicators": [], "error": str(pcap_result)}

    elapsed = time.perf_counter() - t0
    print(f"  [STAGE1      ] Done in {elapsed:.1f}s ({label})", flush=True)

    return {"recon": recon_result, "log_collect": log_result, "pcap": pcap_result}


# ─────────────────────────────────────────────────────────
# STAGE 2 — ml_classifier + mitre_mapper  (mode từ pipeline.yaml)
# ─────────────────────────────────────────────────────────

async def _run_stage2(alert: dict, stage1: dict, verbose: bool) -> dict:
    """
    Chay 2 agents theo mode doc tu pipeline.yaml:
      parallel   -> asyncio.gather
      sequential -> chay tung cai mot
    Agent bi disabled se bi bo qua.
    """
    loop = asyncio.get_event_loop()

    # Đọc trực tiếp từ config dict để tránh cache stale
    _cfg        = get_config()
    _stage2_cfg = _cfg.get("stage2_analysis", {})
    _agents_cfg = _stage2_cfg.get("agents", {})
    mode        = _stage2_cfg.get("mode", "parallel")

    ml_enabled    = bool(_agents_cfg.get("ml_classify", {}).get("enabled", True))
    mitre_enabled = bool(_agents_cfg.get("mitre_map",   {}).get("enabled", True))

    # Debug: in raw value để verify với pipeline.yaml
    print(f"  [STAGE2-CFG  ] ml_classify.enabled={ml_enabled}  mitre_map.enabled={mitre_enabled}", flush=True)

    active = [a for a, e in [("ml_classify", ml_enabled), ("mitre_map", mitre_enabled)] if e]
    print(f"  [STAGE2      ] mode={mode}  agents={active}", flush=True)
    t0 = time.perf_counter()

    empty_ml    = {"classification": {}, "containment_steps": [], "skipped": True}
    empty_mitre = {"techniques": [], "skipped": True}

    if mode == "parallel":
        tasks = []
        if ml_enabled:
            tasks.append(loop.run_in_executor(None, lambda: run_ml_classifier(alert, stage1, verbose=verbose)))
        if mitre_enabled:
            tasks.append(loop.run_in_executor(None, lambda: run_mitre_mapper(alert, stage1, verbose=verbose)))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        idx = 0
        ml_result    = results[idx] if ml_enabled    else empty_ml;    idx += ml_enabled
        mitre_result = results[idx] if mitre_enabled else empty_mitre
        label = "concurrently"
    else:
        ml_result    = run_ml_classifier(alert, stage1, verbose=verbose) if ml_enabled    else empty_ml
        mitre_result = run_mitre_mapper(alert, stage1, verbose=verbose)  if mitre_enabled else empty_mitre
        label = "sequentially"

    if isinstance(ml_result, Exception):
        print(f"  [ML-CLASSIFY ] ERROR: {ml_result}", flush=True)
        ml_result = {"classification": {}, "containment_steps": [], "error": str(ml_result)}
    if isinstance(mitre_result, Exception):
        print(f"  [MITRE-MAP   ] ERROR: {mitre_result}", flush=True)
        mitre_result = {"techniques": [], "error": str(mitre_result)}

    elapsed = time.perf_counter() - t0
    print(f"  [STAGE2      ] Done in {elapsed:.1f}s ({label})", flush=True)

    return {"ml": ml_result, "mitre": mitre_result}


# ─────────────────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────────────────

async def run_full_pipeline(alert: dict, save: bool, verbose: bool, alert_path: str = "?") -> dict:
    t_total = time.perf_counter()

    # Force đọc lại pipeline.yaml mỗi lần chạy — tránh cache cũ
    reload_config()

    print(f"\n{'#'*65}", flush=True)
    print(f"  NIRO-PI -- Full Pipeline (Parallel + Subagent)", flush=True)
    print(f"{'#'*65}", flush=True)
    section("Alert ID",  alert.get("alert_id", "?"))
    section("Source IP", alert.get("src_ip", "?"))
    section("RF Class",  f"{alert.get('rf_class','?')}  conf={alert.get('ml_confidence',0):.0%}")
    section("Desc",      alert.get("description", "")[:70])
    print_config_summary()

    # ══════════════════════════════════════════════════════════════════
    # STAGE 0 — TRIAGE
    # ══════════════════════════════════════════════════════════════════
    banner("STAGE 0 -- TRIAGE AGENT")
    t0 = time.perf_counter()
    triage_result = run_triage(alert, verbose=False)
    routing  = triage_result.get("routing", {})
    action   = routing.get("action", "monitor")
    priority = routing.get("priority", 5)
    section("Action",   action.upper())
    section("Priority", f"{priority}/10")
    section("Reason",   routing.get("justification", "")[:70])
    section("Duration", f"{time.perf_counter()-t0:.1f}s")

    if action == "close_fp":
        print(f"\n  [OK] False Positive -- pipeline stopped.", flush=True)
        return {"triage": routing, "action": "close_fp",
                "total_sec": round(time.perf_counter()-t_total, 1)}

    # ══════════════════════════════════════════════════════════════════
    # STAGE 1 — PARALLEL: recon + log_collector + pcap_analyzer
    # ══════════════════════════════════════════════════════════════════
    banner(f"STAGE 1 -- [{stage_mode('stage1_collection').upper()}]: recon + log_collector + pcap_analyzer")
    t1 = time.perf_counter()
    stage1 = await _run_stage1(alert, verbose=verbose)

    rp  = stage1["recon"].get("risk_profile", {})
    ls  = stage1["log_collect"].get("summary", {})
    pcap= stage1["pcap"]

    print(f"\n  -- Stage 1 Summary --", flush=True)
    section("IP Risk",      f"score={rp.get('threat_score','?')} level={rp.get('risk_level','?')} tor={rp.get('isTor',False)}")
    section("Log Pattern",  f"failed_auth={ls.get('failed_auth_count',0)} fw_blocks={ls.get('blocked_connections',0)} pattern={ls.get('attack_pattern','?')}")
    section("PCAP Sig",     f"sig={pcap.get('flow_signature_match','?')} risk={pcap.get('risk_score','?')} anomalies={len(pcap.get('anomaly_indicators',[]))}")
    section("Duration",     f"{time.perf_counter()-t1:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # STAGE 2 — PARALLEL: ml_classifier + mitre_mapper
    # ══════════════════════════════════════════════════════════════════
    banner(f"STAGE 2 -- [{stage_mode('stage2_analysis').upper()}]: ml_classifier + mitre_mapper")
    t2 = time.perf_counter()
    stage2 = await _run_stage2(alert, stage1, verbose=verbose)

    clf         = stage2["ml"].get("classification", {})
    containment = stage2["ml"].get("containment_steps", [])
    # mitre_mapper trả về "top_techniques", không phải "techniques"
    techniques  = stage2["mitre"].get("top_techniques", stage2["mitre"].get("techniques", []))

    mitre_2a     = clf.get("mitre_technique", "?")
    mitre_2b_top = techniques[0].get("technique_id", "?") if techniques else "?"
    mitre_2b_best = stage2["mitre"].get("best_technique", mitre_2b_top)
    agree = "[AGREE]" if mitre_2a == mitre_2b_best else "[CONFLICT] -> 2C will resolve"

    print(f"\n  -- Stage 2 Summary --", flush=True)
    section("Incident Type",   clf.get("incident_type", "?"))
    section("Severity (2A)",   clf.get("severity", "?"))
    section("MITRE 2A (ML)",   mitre_2a)
    section("MITRE 2B (best)", f"{mitre_2b_best}  (top={mitre_2b_top}  sim={stage2['mitre'].get('best_similarity','?')})")
    section("2A vs 2B",        agree)
    section("Confidence",      f"{clf.get('confidence',0):.0%}")
    section("Duration",        f"{time.perf_counter()-t2:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # STAGE 2C — ORCHESTRATOR AGENT (SUBAGENT PATTERN)
    # ══════════════════════════════════════════════════════════════════
    banner("STAGE 2C -- ORCHESTRATOR + INVESTIGATOR SUBAGENTS")
    t2c = time.perf_counter()

    enriched_alert = {
        **alert,
        "stage1_threat_score":  rp.get("threat_score", 0),
        "stage1_risk_level":    rp.get("risk_level", "unknown"),
        "stage1_is_tor":        rp.get("isTor", False),
        "stage1_log_pattern":   ls.get("attack_pattern", "UNKNOWN"),
        "stage1_failed_auth":   ls.get("failed_auth_count", 0),
        "stage1_pcap_sig":      pcap.get("flow_signature_match", "UNKNOWN"),
        "stage1_anomalies":     pcap.get("anomaly_indicators", []),
        "stage2_ml_type":       clf.get("incident_type", ""),
        "stage2_ml_severity":   clf.get("severity", ""),
        "stage2_ml_mitre":      clf.get("mitre_technique", ""),
        "stage2_mitre_top":     mitre_2b_best,
    }

    if stage_enabled("stage2c_orchestrator"):
        investigation = run_orchestrator(enriched_alert, stage2=stage2, verbose=True)
        verdict       = investigation.get("verdict", {})
        print(f"\n  -- Subagent Summary --", flush=True)
        section("Subagents spawned", str(len(investigation.get("spawn_log", []))))
        for sp in investigation.get("spawn_log", []):
            print(f"    >> {sp['investigator_type']}", flush=True)
        section("Overall Risk",  verdict.get("overall_risk", "?").upper())
        section("Recommended",   verdict.get("final_action", "?").upper())
        section("MITRE (final)", verdict.get("mitre_technique", "N/A"))
    else:
        print("  [STAGE2C     ] SKIPPED (disabled in pipeline.yaml)", flush=True)
        investigation = {"verdict": {}, "spawn_log": [], "subagent_findings": []}
        verdict       = {}

    section("Duration", f"{time.perf_counter()-t2c:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # CACHE STATE — luu truoc Stage 3A de resume khi can approve
    # ══════════════════════════════════════════════════════════════════
    PIPELINE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    alert_id_safe = alert.get("alert_id", "unknown").replace("/", "_")
    cache_file = PIPELINE_CACHE_DIR / f"{alert_id_safe}.json"
    cache_data = {
        "alert":        alert,
        "alert_path":   alert_path,
        "save":         save,
        "verbose":      verbose,
        "routing":      routing,
        "action":       action,
        "priority":     priority,
        "stage1":       stage1,
        "rp":           rp,
        "ls":           ls,
        "pcap":         pcap,
        "stage2":       stage2,
        "clf":          clf,
        "containment":  containment,
        "techniques":   techniques,
        "investigation": investigation,
        "verdict":      verdict,
    }
    cache_file.write_text(json.dumps(cache_data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    # ══════════════════════════════════════════════════════════════════
    # STAGE 3A — RESPONSE AGENT (human-in-the-loop)
    # ══════════════════════════════════════════════════════════════════
    banner("STAGE 3A -- RESPONSE AGENT (containment)")
    t3a = time.perf_counter()

    # Chon final severity: verdict (2C) > clf (2A) > fallback
    final_severity = (verdict.get("overall_risk") or "").upper() or clf.get("severity", "LOW")
    # Chon final MITRE: verdict (2C) > clf (2A) > mitre_mapper (2B)
    final_mitre = (verdict.get("mitre_technique")
                   or clf.get("mitre_technique")
                   or (techniques[0].get("technique_id") if techniques else ""))

    response_risk_profile = {
        "incident_type":    clf.get("incident_type", alert.get("rf_class", "UNKNOWN")),
        "severity":         final_severity,
        "mitre_technique":  final_mitre,
        "threat_score":     rp.get("threat_score", 0),
        "isTor":            rp.get("isTor", False),
    }

    if stage_enabled("stage3a_response"):
        response_result = run_response(
            risk_profile=response_risk_profile,
            triage_result=routing,
            alert=alert,
            verbose=verbose,
        )

        if response_result.get("status") == "WAITING_APPROVAL":
            pending_ip = response_result.get("pending_ip", "?")
            print(f"\n  {'#'*65}", flush=True)
            print(f"  PIPELINE PAUSED — WAITING FOR APPROVAL", flush=True)
            print(f"  {'#'*65}", flush=True)
            print(f"  Action  : block_ip_address", flush=True)
            print(f"  IP      : {pending_ip}", flush=True)
            print(f"  Ticket  : {response_result.get('ticket_id') or 'none'}", flush=True)
            print(f"  NIRO_WAITING_FOR_APPROVAL alert={alert_path}", flush=True)
            sys.exit(2)

        section("Ticket",   response_result.get("ticket_id") or "(none)")
        section("Actions",  str(response_result.get("actions_taken", [])))
        section("Blocked",  str(response_result.get("blocked_ips", [])))
    else:
        print("  [STAGE3A     ] SKIPPED (disabled in pipeline.yaml)", flush=True)
        response_result = {"actions_taken": [], "blocked_ips": [], "ticket_id": None, "skipped": True}

    section("Duration", f"{time.perf_counter()-t3a:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # STAGE 3B — REPORT AGENT
    # ══════════════════════════════════════════════════════════════════
    banner("STAGE 3B -- REPORT AGENT")
    t3 = time.perf_counter()

    # Gom du lieu tu tat ca stages cho report
    recon_for_report = {
        "risk_profile": {
            **rp,
            "recommended_action": verdict.get("final_action", rp.get("recommended_action","monitor")),
            "summary": verdict.get("verdict_summary", rp.get("summary", "")),
        },
        "ml_classification": {
            "incident_type":     clf.get("incident_type", alert.get("rf_class", "UNKNOWN")),
            "severity":          final_severity,
            "mitre_technique":   final_mitre,
            "mitre_tactic":      clf.get("mitre_tactic", ""),
            "confidence":        clf.get("confidence", alert.get("ml_confidence", 0.8)),
            "is_true_positive":  clf.get("is_true_positive", True),
            # Rationale: ket hop ly giai tu ca 2A va 2C
            "rationale":         verdict.get("verdict_summary", clf.get("rationale", "")),
            "containment_steps": containment,
            # Them truong cho biet nguon MITRE
            "mitre_source":      ("2C-investigator" if verdict.get("mitre_technique")
                                  else "2A-ml_classifier" if clf.get("mitre_technique")
                                  else "2B-cosine"),
            "stage2a_mitre":     clf.get("mitre_technique", ""),
            "stage2b_mitre":     techniques[0].get("technique_id", "") if techniques else "",
            "stage2c_mitre":     verdict.get("mitre_technique", ""),
        },
        "mitre_techniques":  techniques,
        "containment_steps": containment,
        "log_summary":       ls,
        "pcap_summary": {
            "flow_signature": pcap.get("flow_signature_match", "?"),
            "risk_score":     pcap.get("risk_score", 0),
            "anomalies":      pcap.get("anomaly_indicators", []),
        },
        "subagent_findings": investigation.get("subagent_findings", []),
    }

    if stage_enabled("stage3b_report"):
        report_result = run_report(
            alert=alert,
            triage_result=routing,
            recon_result=recon_for_report,
            response_result=response_result,
            pipeline_duration_sec=round(time.perf_counter()-t_total, 1),
            verbose=True,
        )
        report_path = report_result.get("report_path", "")
        if save and report_path:
            section("Report saved", report_path)
    else:
        print("  [STAGE3B     ] SKIPPED (disabled in pipeline.yaml)", flush=True)
        report_result = {"report_path": "", "skipped": True}
        report_path   = ""

    section("Duration", f"{time.perf_counter()-t3:.1f}s")

    # ══════════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ══════════════════════════════════════════════════════════════════
    total = time.perf_counter() - t_total
    print(f"\n{'#'*65}", flush=True)
    print(f"  PIPELINE COMPLETE", flush=True)
    print(f"{'#'*65}", flush=True)
    section("Alert",     alert.get("alert_id", "?"))
    section("Triage",    f"{action.upper()} (priority {priority})")
    section("Stage 1",   f"recon + log + pcap (parallel)")
    section("Stage 2",   f"ML={clf.get('incident_type','?')} MITRE={clf.get('mitre_technique','?')} (parallel)")
    section("Subagents", f"{len(investigation.get('spawn_log',[]))} investigators spawned")
    section("Verdict",   f"{verdict.get('overall_risk','?').upper()} -> {verdict.get('final_action','?').upper()}")
    section("MITRE",     verdict.get("mitre_technique", "N/A"))
    section("Response",  f"ticket={response_result.get('ticket_id') or 'none'} blocked={response_result.get('blocked_ips',[])}")
    section("Total time",f"{total:.1f}s")
    if report_path:
        section("IR Report", report_path)
    print()

    return {
        "triage":       routing,
        "stage1":       stage1,
        "stage2":       stage2,
        "investigation":investigation,
        "verdict":      verdict,
        "report":       report_result,
        "total_sec":    round(total, 1),
    }


def resume_from_cache(cache_file: Path, verbose: bool = True):
    """
    Resume pipeline tu Stage 3A sau khi nhan duoc approval.
    Doc state da cache, chay Stage 3A + 3B, khong lap lai Stage 0-2C.
    """
    c = json.loads(cache_file.read_text(encoding="utf-8"))

    alert        = c["alert"]
    alert_path   = c["alert_path"]
    save         = c["save"]
    routing      = c["routing"]
    action       = c["action"]
    priority     = c["priority"]
    stage1       = c["stage1"]
    rp           = c["rp"]
    ls           = c["ls"]
    pcap         = c["pcap"]
    stage2       = c["stage2"]
    clf          = c["clf"]
    containment  = c["containment"]
    techniques   = c["techniques"]
    investigation = c["investigation"]
    verdict      = c["verdict"]

    print(f"\n{'#'*65}", flush=True)
    print(f"  NIRO-PI -- RESUME FROM STAGE 3A (approval received)", flush=True)
    print(f"{'#'*65}", flush=True)
    print(f"  Alert: {alert.get('alert_id','?')}  IP: {alert.get('src_ip','?')}", flush=True)
    print(f"  (Stages 0-2C da hoan thanh, chi chay lai Stage 3A+3B)", flush=True)

    # Recompute final values
    final_severity = (verdict.get("overall_risk") or "").upper() or clf.get("severity", "LOW")
    final_mitre    = (verdict.get("mitre_technique")
                      or clf.get("mitre_technique")
                      or (techniques[0].get("technique_id") if techniques else ""))

    response_risk_profile = {
        "incident_type":   clf.get("incident_type", alert.get("rf_class", "UNKNOWN")),
        "severity":        final_severity,
        "mitre_technique": final_mitre,
        "threat_score":    rp.get("threat_score", 0),
        "isTor":           rp.get("isTor", False),
    }

    banner = lambda title: print(f"\n{'='*65}\n  {title}\n{'='*65}", flush=True)
    section = lambda k, v: print(f"  {k:<18}: {v}", flush=True)

    # ── Stage 3A ──────────────────────────────────────────────────
    banner("STAGE 3A -- RESPONSE AGENT (containment) [RESUME]")
    t3a = time.perf_counter()

    response_result = run_response(
        risk_profile=response_risk_profile,
        triage_result=routing,
        alert=alert,
        verbose=verbose,
    )

    if response_result.get("status") == "WAITING_APPROVAL":
        # Van con pending (user reject hoac file bi xoa)
        pending_ip = response_result.get("pending_ip", "?")
        print(f"\n  NIRO_WAITING_FOR_APPROVAL alert={alert_path}", flush=True)
        sys.exit(2)

    section("Ticket",   response_result.get("ticket_id") or "(none)")
    section("Actions",  str(response_result.get("actions_taken", [])))
    section("Blocked",  str(response_result.get("blocked_ips", [])))
    section("Duration", f"{time.perf_counter()-t3a:.1f}s")

    # ── Stage 3B ──────────────────────────────────────────────────
    banner("STAGE 3B -- REPORT AGENT [RESUME]")
    t3 = time.perf_counter()

    recon_for_report = {
        "risk_profile": {
            **rp,
            "recommended_action": verdict.get("final_action", rp.get("recommended_action","monitor")),
            "summary": verdict.get("verdict_summary", rp.get("summary", "")),
        },
        "ml_classification": {
            "incident_type":     clf.get("incident_type", alert.get("rf_class", "UNKNOWN")),
            "severity":          final_severity,
            "mitre_technique":   final_mitre,
            "confidence":        clf.get("confidence", alert.get("ml_confidence", 0.8)),
            "rationale":         verdict.get("verdict_summary", clf.get("rationale", "")),
            "containment_steps": containment,
        },
        "mitre_techniques":  techniques,
        "containment_steps": containment,
        "log_summary":       ls,
        "pcap_summary": {
            "flow_signature": pcap.get("flow_signature_match", "?"),
            "risk_score":     pcap.get("risk_score", 0),
            "anomalies":      pcap.get("anomaly_indicators", []),
        },
        "subagent_findings": investigation.get("subagent_findings", []),
    }

    report_result = run_report(
        alert=alert,
        triage_result=routing,
        recon_result=recon_for_report,
        response_result=response_result,
        pipeline_duration_sec=0,
        verbose=True,
    )

    report_path = report_result.get("report_path", "")
    if save and report_path:
        section("Report saved", report_path)
    section("Duration", f"{time.perf_counter()-t3:.1f}s")

    # Xoa cache sau khi hoan thanh
    cache_file.unlink(missing_ok=True)

    print(f"\n{'#'*65}", flush=True)
    print(f"  PIPELINE COMPLETE (resumed)", flush=True)
    print(f"{'#'*65}", flush=True)
    blocked = response_result.get("blocked_ips", [])
    section("Verdict",  f"{verdict.get('overall_risk','?').upper()} -> {verdict.get('final_action','?').upper()}")
    section("Blocked",  str(blocked) if blocked else "none")
    section("Response", f"ticket={response_result.get('ticket_id') or 'none'}")
    if report_path:
        section("IR Report", report_path)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="NIRO-PI Full Pipeline: Parallel Stages + Subagent"
    )
    parser.add_argument("--alert",  required=True, help="Path to alert JSON file")
    parser.add_argument("--save",   action="store_true", help="Save IR report to reports/")
    parser.add_argument("--quiet",  action="store_true", help="Suppress verbose agent output")
    parser.add_argument("--resume", action="store_true",
                        help="Resume tu Stage 3A sau khi approval (dung cache, bo qua Stage 0-2C)")
    args = parser.parse_args()

    alert_path = Path(args.alert)

    if args.resume:
        if not alert_path.exists():
            print(f"[ERROR] Alert file not found: {args.alert}", flush=True)
            sys.exit(1)
        alert = json.loads(alert_path.read_text(encoding="utf-8"))
        alert_id_safe = alert.get("alert_id", "unknown").replace("/", "_")
        cache_file = PIPELINE_CACHE_DIR / f"{alert_id_safe}.json"
        if not cache_file.exists():
            print(f"[ERROR] Khong tim thay pipeline cache: {cache_file}", flush=True)
            print(f"        Hay chay lai full pipeline (khong dung --resume)", flush=True)
            sys.exit(1)
        resume_from_cache(cache_file, verbose=not args.quiet)
        return

    if not alert_path.exists():
        print(f"[ERROR] Alert file not found: {args.alert}", flush=True)
        sys.exit(1)

    alert = json.loads(alert_path.read_text(encoding="utf-8"))
    asyncio.run(run_full_pipeline(alert, save=args.save, verbose=not args.quiet, alert_path=args.alert))


if __name__ == "__main__":
    main()
