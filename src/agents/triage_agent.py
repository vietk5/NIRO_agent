"""
triage_agent.py — Stage 0: Alert Ingestion & Triage

Chuẩn hóa alert, đánh giá sơ bộ, quyết định:
  - escalate  → chạy full pipeline (Stage 1 → 2 → 3)
  - monitor   → Stage 1 + 2 nhưng không block
  - close_fp  → bỏ qua, chỉ ghi report
"""

import json
import os
from pathlib import Path
from src.utils.agent_loop import run_agent
from src.utils.logger import log_agent_start, log_agent_complete

_SYSTEM = """Bạn là triage agent của hệ thống NIRO.

Nhiệm vụ: Đánh giá nhanh một cảnh báo mạng và quyết định mức độ ưu tiên.

Dùng tool route_alert() để trả kết quả. LUÔN gọi tool này.

Tiêu chí định tuyến:
- escalate (priority 8-10): Threat score cao, attack rõ ràng, cần phản ứng ngay
- monitor  (priority 4-7):  Nghi ngờ nhưng chưa chắc, theo dõi thêm
- close_fp (priority 1-3):  RFC-1918, confidence thấp, nhiều khả năng là FP
"""

_ROUTE_TOOL = {
    "type": "function",
    "function": {
        "name": "route_alert",
        "description": "Phân loại alert và quyết định luồng xử lý tiếp theo",
        "parameters": {
            "type": "object",
            "properties": {
                "action":        {"type": "string", "enum": ["escalate", "monitor", "close_fp"]},
                "priority":      {"type": "integer", "minimum": 1, "maximum": 10},
                "justification": {"type": "string"},
                "key_indicators":{"type": "array", "items": {"type": "string"}},
            },
            "required": ["action", "priority", "justification"],
        },
    },
}


def run_triage(alert: dict, verbose: bool = True) -> dict:
    log_agent_start("triage", alert.get("alert_id", "?"))

    # Fast path: RFC-1918 với confidence thấp → close_fp ngay
    src_ip = alert.get("src_ip", "")
    if (src_ip.startswith("192.168.") or src_ip.startswith("10.")
            or src_ip.startswith("172.")):
        if alert.get("ml_confidence", 1.0) < 0.70:
            return {"routing": {"action": "close_fp", "priority": 2,
                                "justification": "RFC-1918 source, low confidence",
                                "key_indicators": ["private_ip", "low_confidence"]},
                    "error": None}

    request = f"""Triage cảnh báo này:

{json.dumps(alert, indent=2, ensure_ascii=False)}

Đánh giá nhanh và gọi route_alert() với quyết định của bạn."""

    result = run_agent(
        system_prompt=_SYSTEM,
        user_request=request,
        tools=[_ROUTE_TOOL],
        tool_map={"route_alert": lambda **kw: kw},
        max_iterations=4,
        verbose=verbose,
    )

    routing = {}
    for call in reversed(result.get("tool_call_log", [])):
        if call.get("tool") == "route_alert":
            routing = call.get("result", {})
            break

    # Fallback nếu LLM không gọi tool
    if not routing:
        conf = alert.get("ml_confidence", 0.5)
        routing = {
            "action":        "escalate" if conf >= 0.85 else "monitor",
            "priority":      8 if conf >= 0.85 else 5,
            "justification": f"Rule-based fallback (conf={conf:.0%})",
        }

    log_agent_complete("triage", routing.get("action", "?"), result.get("iterations", 0))
    return {"routing": routing, "alert": alert, "error": result.get("error")}


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse, sys
    from dotenv import load_dotenv
    load_dotenv()

    parser = argparse.ArgumentParser()
    parser.add_argument("--alert",  required=True)
    parser.add_argument("--output", default=".pi/triage/triage_result.json")
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()

    alert = json.loads(args.alert) if not os.path.isfile(args.alert) \
            else json.load(open(args.alert, encoding="utf-8"))

    result = run_triage(alert, verbose=not args.quiet)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[TRIAGE] → {result['routing']['action']}  priority={result['routing']['priority']}")
    sys.exit(0)
