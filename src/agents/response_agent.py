"""
response_agent.py — Stage 3A: Containment & Response

HUMAN-IN-THE-LOOP:
  Trước khi thực hiện bất kỳ destructive action nào (block IP, isolate host),
  hệ thống phải được con người phê duyệt.

Approval gate:
  1. Ghi pending action → logs/pending_approval.json
  2. Chờ analyst ghi "approve" hoặc "reject" vào logs/approval_response.txt
  3. Nếu timeout (mặc định 120s) → KHÔNG thực hiện action
  4. NIRO_AUTO_APPROVE=1 → bỏ qua (chỉ dùng lab)
"""

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.utils.agent_loop import run_agent
from src.utils.logger import log_agent_start, log_agent_complete
from src.utils.safety import is_safe_to_block
from src.tools.response_tools import block_ip_address, create_incident_ticket, notify_analyst, isolate_host

PENDING_APPROVAL_FILE  = Path("logs/pending_approval.json")
APPROVAL_RESPONSE_FILE = Path("logs/approval_response.txt")
APPROVAL_TIMEOUT_SEC   = float(os.getenv("APPROVAL_TIMEOUT_SEC", "120"))


# ── Human-in-the-loop approval gate ───────────────────────────────────────────

async def wait_for_approval(action: str, details: dict,
                            timeout_sec: float = APPROVAL_TIMEOUT_SEC) -> bool:
    """
    Yêu cầu phê duyệt từ analyst trước khi thực hiện action.

    Returns:
        True  → approved
        False → rejected hoặc timeout
    """
    # Lab mode: auto-approve
    if os.getenv("NIRO_AUTO_APPROVE") == "1":
        print(f"  [AUTO-APPROVE] {action} — LAB MODE", flush=True)
        return True

    # Ghi pending request
    PENDING_APPROVAL_FILE.parent.mkdir(parents=True, exist_ok=True)
    request = {
        "action":    action,
        "details":   details,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status":    "PENDING",
        "timeout":   f"{timeout_sec}s",
    }
    PENDING_APPROVAL_FILE.write_text(json.dumps(request, indent=2, ensure_ascii=False))
    APPROVAL_RESPONSE_FILE.unlink(missing_ok=True)

    print(f"\n  {'='*54}", flush=True)
    print(f"  [!] HUMAN APPROVAL REQUIRED", flush=True)
    print(f"      Action  : {action}", flush=True)
    print(f"      Details : {json.dumps(details)[:120]}", flush=True)
    print(f"      Timeout : {timeout_sec}s", flush=True)
    print(f"      Approve : echo 'approve' > logs/approval_response.txt", flush=True)
    print(f"      Reject  : echo 'reject'  > logs/approval_response.txt", flush=True)
    print(f"  {'='*54}", flush=True)

    # Poll cho response
    deadline = time.perf_counter() + timeout_sec
    while time.perf_counter() < deadline:
        if APPROVAL_RESPONSE_FILE.exists():
            try:
                # Thử utf-8-sig trước (handles BOM từ PowerShell), fallback utf-16
                try:
                    response = APPROVAL_RESPONSE_FILE.read_text(encoding="utf-8-sig").strip().lower()
                except UnicodeDecodeError:
                    response = APPROVAL_RESPONSE_FILE.read_text(encoding="utf-16").strip().lower()
            except Exception:
                response = ""
            if response in ("approve", "yes", "y", "1"):
                print(f"  [OK] Analyst APPROVED: {action}", flush=True)
                return True
            elif response:
                print(f"  [X] Analyst REJECTED: {action} (response='{response}')", flush=True)
                return False
        await asyncio.sleep(2.0)

    print(f"  [!] TIMEOUT — {action} NOT executed (no response in {timeout_sec}s)", flush=True)
    return False


def request_approval_sync(action: str, details: dict,
                           timeout_sec: float = APPROVAL_TIMEOUT_SEC) -> tuple:
    """
    Non-blocking approval gate cho PI integration.

    Returns:
        (approved: bool, is_pending: bool)
        - (True,  False) → approved (auto-approve hoặc file có sẵn)
        - (False, False) → rejected
        - (False, True)  → đang chờ — pipeline nên dừng lại, PI hỏi user
    """
    if os.getenv("NIRO_AUTO_APPROVE") == "1":
        print(f"  [AUTO-APPROVE] {action}", flush=True)
        return True, False

    PENDING_APPROVAL_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Kiểm tra nếu đã có approval response từ trước (PI đã ghi approve)
    if APPROVAL_RESPONSE_FILE.exists():
        try:
            try:
                resp = APPROVAL_RESPONSE_FILE.read_text(encoding="utf-8-sig").strip().lower()
            except UnicodeDecodeError:
                resp = APPROVAL_RESPONSE_FILE.read_text(encoding="utf-16").strip().lower()
            APPROVAL_RESPONSE_FILE.unlink(missing_ok=True)   # consume file
            PENDING_APPROVAL_FILE.unlink(missing_ok=True)
            if resp in ("approve", "yes", "y", "1"):
                print(f"  [OK] Approved: {action}", flush=True)
                return True, False
            else:
                print(f"  [X] Rejected: {action} (response='{resp}')", flush=True)
                return False, False
        except Exception:
            pass

    # Chưa có response — ghi pending file và báo PI dừng chờ
    request = {
        "action":    action,
        "details":   details,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status":    "PENDING",
    }
    PENDING_APPROVAL_FILE.write_text(json.dumps(request, indent=2, ensure_ascii=False))

    print(f"\n  {'='*54}", flush=True)
    print(f"  [!] APPROVAL REQUIRED", flush=True)
    print(f"      Action  : {action}", flush=True)
    print(f"      IP      : {details.get('ip', details.get('host_ip', '?'))}", flush=True)
    print(f"      Reason  : {details.get('reason', '?')}", flush=True)
    print(f"  NIRO_WAITING_FOR_APPROVAL", flush=True)
    print(f"  {'='*54}", flush=True)

    return False, True   # pending — pipeline nên exit


# ── Main response function ─────────────────────────────────────────────────────

def run_response(risk_profile: dict, triage_result: dict,
                 alert: dict, verbose: bool = True) -> dict:
    """
    Stage 3A: Quyết định và thực thi các bước containment.

    Mọi destructive action đều cần human approval.
    Non-destructive actions (create_ticket, notify) thực hiện ngay.
    """
    log_agent_start("response", alert.get("alert_id", "?"))

    src_ip    = alert.get("src_ip", "")
    severity  = risk_profile.get("severity", "LOW")
    incident  = risk_profile.get("incident_type", "UNKNOWN")
    mitre     = risk_profile.get("mitre_technique", "")
    alert_id  = alert.get("alert_id", "UNKNOWN")

    actions_taken = []
    blocked_ips   = []
    ticket_id     = None

    # ── 1. Tạo incident ticket (không cần approval) ────────────────────────────
    if severity in ("HIGH", "CRITICAL"):
        try:
            ticket = create_incident_ticket(
                alert_id=alert_id,
                severity=severity,
                summary=f"{incident} from {src_ip} | MITRE: {mitre}",
            )
            ticket_id = ticket.get("ticket_id")
            actions_taken.append(f"created_ticket:{ticket_id}")
            if verbose:
                print(f"  [RESPONSE    ] Ticket created: {ticket_id}", flush=True)
        except Exception as e:
            if verbose:
                print(f"  [RESPONSE    ] Ticket creation failed: {e}", flush=True)

    # ── 2. Notify analyst (không cần approval) ────────────────────────────────
    notify_analyst(
        f"[{severity}] {incident} detected from {src_ip} | Alert: {alert_id} | MITRE: {mitre}",
        channel="security-alerts",
    )
    actions_taken.append("notified_analyst")

    # ── 3. Block IP (CẦN human approval) ──────────────────────────────────────
    safe_to_block, reason = is_safe_to_block(src_ip)

    if severity in ("HIGH", "CRITICAL") and safe_to_block:
        approved, is_pending = request_approval_sync(
            action="block_ip_address",
            details={"ip": src_ip, "reason": f"{incident} — {mitre}", "duration_hours": 24},
        )
        if is_pending:
            # PI cần hỏi user, pipeline dừng lại
            return {
                "status":         "WAITING_APPROVAL",
                "pending_action": "block_ip_address",
                "pending_ip":     src_ip,
                "ticket_id":      ticket_id,
                "actions_taken":  actions_taken,
                "blocked_ips":    [],
                "severity":       severity,
                "error":          None,
            }
        if approved:
            try:
                block_ip_address(src_ip, reason=f"{incident} — {mitre}", duration_hours=24)
                blocked_ips.append(src_ip)
                actions_taken.append(f"blocked_ip:{src_ip}")
                if verbose:
                    print(f"  [RESPONSE    ] IP blocked: {src_ip}", flush=True)
            except Exception as e:
                if verbose:
                    print(f"  [RESPONSE    ] Block failed: {e}", flush=True)
        else:
            actions_taken.append(f"block_rejected:{src_ip}")
    elif not safe_to_block:
        actions_taken.append(f"block_skipped:{reason}")
        if verbose:
            print(f"  [RESPONSE    ] Block skipped — {reason}", flush=True)

    # ── 4. Isolate host nếu CRITICAL (CẦN approval) ───────────────────────────
    dst_ip = alert.get("dst_ip", "")
    if (severity == "CRITICAL" and incident in ("DATA_EXFILTRATION", "MALWARE_C2")
            and dst_ip and not dst_ip.endswith("/24")):
        iso_approved, iso_pending = request_approval_sync(
            action="isolate_host",
            details={"host_ip": dst_ip, "reason": f"Compromised host — {incident}"},
        )
        if iso_pending:
            return {
                "status":         "WAITING_APPROVAL",
                "pending_action": "isolate_host",
                "pending_ip":     dst_ip,
                "ticket_id":      ticket_id,
                "actions_taken":  actions_taken,
                "blocked_ips":    blocked_ips,
                "severity":       severity,
                "error":          None,
            }
        if iso_approved:
            try:
                isolate_host(dst_ip, reason=f"Compromised — {incident}")
                actions_taken.append(f"isolated_host:{dst_ip}")
                if verbose:
                    print(f"  [RESPONSE    ] Host isolated: {dst_ip}", flush=True)
            except Exception as e:
                if verbose:
                    print(f"  [RESPONSE    ] Isolate failed: {e}", flush=True)
        else:
            actions_taken.append(f"isolate_rejected:{dst_ip}")

    log_agent_complete("response", f"actions={len(actions_taken)} blocked={len(blocked_ips)}")

    return {
        "ticket_id":     ticket_id,
        "actions_taken": actions_taken,
        "blocked_ips":   blocked_ips,
        "severity":      severity,
        "error":         None,
    }


if __name__ == "__main__":
    import argparse, sys
    from dotenv import load_dotenv; load_dotenv()

    parser = argparse.ArgumentParser()
    parser.add_argument("--triage-result",   required=True)
    parser.add_argument("--stage2-result",   required=True)
    parser.add_argument("--alert",           required=True)
    parser.add_argument("--output",          default=".pi/triage/response_result.json")
    parser.add_argument("--quiet",           action="store_true")
    args = parser.parse_args()

    alert        = json.loads(args.alert) if not os.path.isfile(args.alert) \
                   else json.load(open(args.alert, encoding="utf-8"))
    triage       = json.load(open(args.triage_result, encoding="utf-8"))
    stage2       = json.load(open(args.stage2_result, encoding="utf-8"))

    ml  = stage2.get("ml_classify", {})
    clf = ml.get("classification", {})
    rp  = {**clf, **stage2.get("mitre_map", {}).get("best_technique", {})}

    result = run_response(rp, triage.get("routing", {}), alert, verbose=not args.quiet)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[RESPONSE] ticket={result.get('ticket_id')} actions={result.get('actions_taken')}")
    sys.exit(0)
