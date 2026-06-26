"""
batch_parallel.py — Parallel Batch Orchestrator (Subagent pattern)

Spawn mỗi alert như một subprocess độc lập, chạy song song với asyncio.
Parent thu kết quả và in summary table.

Cách dùng:
    python3 scripts/batch_parallel.py
    python3 scripts/batch_parallel.py --dir data/input/alerts/
    python3 scripts/batch_parallel.py --file data/input/alerts/_batch.json
    python3 scripts/batch_parallel.py --max-concurrent 5 --timeout 180
    python3 scripts/batch_parallel.py --no-auto-approve   # yêu cầu human approval

Cấu hình:
    MAX_CONCURRENT   = 3     # số subagent chạy song song cùng lúc
    TIMEOUT_SEC      = 300   # timeout mỗi pipeline (giây) — pipeline đơn ~116s, cộng buffer
    AUTO_APPROVE     = True  # tự approve (False = cần analyst gõ approve)
"""

import argparse
import asyncio
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Fix Windows console encoding (cp1252 -> utf-8)
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_ALERT_DIR   = Path("data/input/alerts")
RESULTS_DIR         = Path("results")
REPORTS_DIR         = Path("reports")
MAX_CONCURRENT      = 3
TIMEOUT_SEC         = 120
AUTO_APPROVE        = True


# ── Worker (1 alert = 1 subprocess / subagent) ─────────────────────────────────
async def run_single_alert(
    alert: dict,
    alert_index: int,
    semaphore: asyncio.Semaphore,
    timeout: int,
    auto_approve: bool,
) -> dict:
    """
    Chạy full NIRO pipeline cho 1 alert trong subprocess riêng.
    Return dict kết quả: alert_id, outcome, severity, report_path, duration, error.
    """
    alert_id = alert.get("alert_id", f"ALERT-{alert_index:03d}")
    src_ip   = alert.get("src_ip", "unknown")

    async with semaphore:  # giới hạn concurrent
        t_start = time.monotonic()
        print(f"  [WORKER {alert_index+1:02d}] START  {alert_id}  ({src_ip})", flush=True)

        # Ghi alert ra file tạm cho subprocess đọc
        tmp_dir = Path("data/input/alerts/.tmp")
        tmp_dir.mkdir(parents=True, exist_ok=True)
        tmp_file = tmp_dir / f"alert_{alert_index:03d}_{alert_id}.json"
        tmp_file.write_text(json.dumps(alert, ensure_ascii=False), encoding="utf-8")

        cmd = [
            sys.executable, "scripts/test_full_pipeline.py",
            "--alert", str(tmp_file),
            "--save",
        ]

        # Truyền UTF-8 encoding xuống subprocess để tránh Windows cp1252 crash
        # Auto-approve qua env var (test_full_pipeline.py không có --auto-approve flag)
        worker_env = os.environ.copy()
        worker_env["PYTHONIOENCODING"] = "utf-8"
        if auto_approve:
            worker_env["NIRO_AUTO_APPROVE"] = "1"

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=worker_env,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                duration = time.monotonic() - t_start
                print(f"  [WORKER {alert_index+1:02d}] TIMEOUT after {timeout}s — {alert_id}", flush=True)
                return {
                    "alert_id": alert_id, "src_ip": src_ip,
                    "outcome": "TIMEOUT", "severity": "?",
                    "report_path": None, "duration": duration,
                    "error": f"Timeout after {timeout}s",
                }

            duration = time.monotonic() - t_start

            # Đọc report mới nhất của alert này
            report_path, outcome, severity = _find_report(src_ip)

            status = "✓" if proc.returncode == 0 else "✗"
            print(
                f"  [WORKER {alert_index+1:02d}] {status} DONE   {alert_id}  "
                f"outcome={outcome}  sev={severity}  {duration:.1f}s",
                flush=True,
            )
            return {
                "alert_id": alert_id, "src_ip": src_ip,
                "outcome": outcome, "severity": severity,
                "report_path": str(report_path) if report_path else None,
                "duration": duration, "error": None,
            }

        except Exception as e:
            duration = time.monotonic() - t_start
            print(f"  [WORKER {alert_index+1:02d}] ERROR  {alert_id} — {e}", flush=True)
            return {
                "alert_id": alert_id, "src_ip": src_ip,
                "outcome": "ERROR", "severity": "?",
                "report_path": None, "duration": duration,
                "error": str(e),
            }
        finally:
            # Dọn file tạm
            try:
                tmp_file.unlink(missing_ok=True)
            except Exception:
                pass


def _find_report(src_ip: str):
    """Tìm report file mới nhất của IP này."""
    ip_slug = src_ip.replace(".", "_")
    reports = sorted(
        REPORTS_DIR.glob(f"{ip_slug}_*_incident.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not reports:
        return None, "UNKNOWN", "?"

    report = reports[0]
    # Parse outcome và severity từ file
    try:
        text = report.read_text(encoding="utf-8")
        outcome = "UNKNOWN"
        severity = "?"
        for line in text.splitlines():
            if "[!!] BLOCKED"      in line: outcome = "BLOCKED";    break
            if "[!] ESCALATED"     in line: outcome = "ESCALATED";  break
            if "[~] MONITORED"     in line: outcome = "MONITORED";  break
            if "[OK] FALSE"        in line: outcome = "FALSE_POS";  break
        for line in text.splitlines():
            if "**Severity**" in line:
                parts = line.split("|")
                if len(parts) >= 3:
                    severity = parts[2].strip().strip("*").strip()
                    break
    except Exception:
        outcome, severity = "UNKNOWN", "?"

    return report, outcome, severity


# ── Load alerts ────────────────────────────────────────────────────────────────
def load_alerts(alert_dir: Path = None, alert_file: Path = None) -> list[dict]:
    alerts = []

    if alert_file and alert_file.exists():
        data = json.loads(alert_file.read_text(encoding="utf-8"))
        if isinstance(data, list):
            alerts.extend(data)
        else:
            alerts.append(data)
        print(f"[BATCH] Loaded {len(alerts)} alert(s) from {alert_file}")
        return alerts

    if alert_dir and alert_dir.exists():
        files = sorted(alert_dir.glob("*.json"))
        # bỏ file _batch.json và _tmp
        files = [f for f in files if not f.name.startswith("_")]
        for f in files:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    alerts.extend(data)
                else:
                    alerts.append(data)
            except Exception as e:
                print(f"  [WARN] Bỏ qua {f.name}: {e}")
        print(f"[BATCH] Loaded {len(alerts)} alert(s) from {len(files)} file(s) in {alert_dir}")
        return alerts

    return []


# ── Summary table ──────────────────────────────────────────────────────────────
def print_summary(results: list[dict], total_elapsed: float):
    outcome_icon = {
        "BLOCKED":   "🔴", "ESCALATED": "🟠",
        "MONITORED": "🟡", "FALSE_POS": "🟢",
        "TIMEOUT":   "⏱️", "ERROR":     "💥", "UNKNOWN": "❓",
    }

    print(f"\n{'='*80}")
    print(f"  BATCH SUMMARY — {len(results)} alert(s)  |  Total time: {total_elapsed:.1f}s")
    print(f"{'='*80}")
    print(f"  {'Alert ID':<20} {'IP':<18} {'Outcome':<14} {'Severity':<10} {'Time':>6}  Report")
    print(f"  {'-'*78}")

    counts = {}
    for r in results:
        icon    = outcome_icon.get(r["outcome"], "❓")
        dur     = f"{r['duration']:.1f}s"
        report  = Path(r["report_path"]).name if r["report_path"] else "—"
        outcome_display = f"{icon} {r['outcome']}"
        print(f"  {r['alert_id']:<20} {r['src_ip']:<18} {outcome_display:<14} {r['severity']:<10} {dur:>6}  {report}")
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1

    print(f"\n  Tổng kết:")
    for outcome, n in sorted(counts.items()):
        icon = outcome_icon.get(outcome, "❓")
        print(f"    {icon} {outcome}: {n}")

    errors = [r for r in results if r["error"]]
    if errors:
        print(f"\n  Lỗi:")
        for r in errors:
            print(f"    [{r['alert_id']}] {r['error']}")

    print(f"\n  Reports: {REPORTS_DIR.resolve()}")
    print(f"{'='*80}\n")


# ── Save batch result JSON ─────────────────────────────────────────────────────
def save_batch_result(results: list[dict]):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = RESULTS_DIR / f"batch_{ts}.json"
    out.write_text(
        json.dumps({"timestamp": ts, "results": results}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"  [BATCH] Kết quả lưu → {out}")


# ── Main ───────────────────────────────────────────────────────────────────────
async def main_async(args):
    alerts = load_alerts(
        alert_dir  = Path(args.dir)  if args.dir  else DEFAULT_ALERT_DIR,
        alert_file = Path(args.file) if args.file else None,
    )

    if not alerts:
        print("[BATCH] Không tìm thấy alert nào. Đặt file .json vào data/input/alerts/")
        return 1

    max_concurrent = args.max_concurrent
    timeout        = args.timeout
    auto_approve   = not args.no_auto_approve

    print(f"[BATCH] {len(alerts)} alert(s) | max_concurrent={max_concurrent} | "
          f"timeout={timeout}s | auto_approve={auto_approve}")
    print(f"[BATCH] Khởi động {min(len(alerts), max_concurrent)} subagent(s)...\n")

    semaphore = asyncio.Semaphore(max_concurrent)
    t0 = time.monotonic()

    tasks = [
        run_single_alert(alert, i, semaphore, timeout, auto_approve)
        for i, alert in enumerate(alerts)
    ]
    results = await asyncio.gather(*tasks)

    total_elapsed = time.monotonic() - t0
    print_summary(list(results), total_elapsed)
    save_batch_result(list(results))
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Parallel batch processor — mỗi alert là 1 subagent subprocess"
    )
    parser.add_argument("--dir",  default=None,
                        help="Thư mục chứa alert JSON files (default: data/input/alerts/)")
    parser.add_argument("--file", default=None,
                        help="File JSON chứa list alerts")
    parser.add_argument("--max-concurrent", type=int, default=MAX_CONCURRENT,
                        help=f"Số subagent chạy cùng lúc (default: {MAX_CONCURRENT})")
    parser.add_argument("--timeout", type=int, default=TIMEOUT_SEC,
                        help=f"Timeout mỗi pipeline giây (default: {TIMEOUT_SEC})")
    parser.add_argument("--no-auto-approve", action="store_true",
                        help="Yêu cầu human approval (mặc định: auto-approve)")
    args = parser.parse_args()

    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
