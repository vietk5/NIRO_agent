---
name: report-agent
model: none
max_iterations: 0
description: >
  Stage 3B — IR Report Generation. Luôn chạy. Không dùng LLM.
  Tổng hợp toàn bộ pipeline thành Incident Response Report chuẩn.
---

## Nhiệm vụ
Tạo Markdown IR Report với: triage decision, recon data, MITRE ATT&CK, containment playbook.

## Protocol

```bash
python3 -m src.agents.report_agent \
  --alert '{{alert_json}}' \
  --triage-result .pi/triage/triage_result.json \
  --recon-result  .pi/triage/stage_merged.json \
  --response-result .pi/triage/response_result.json \
  --duration {{pipeline_duration_sec}} \
  --output .pi/triage/report_result.json
```

## Output

File Markdown tại: `reports/{ip}_{timestamp}_incident.md`

### Report Structure
1. Alert Summary
2. Triage Decision (action, priority, justification)
3. Stage 1 — Threat Intel & Recon
   - IP Reputation (AbuseIPDB)
   - Log Analysis
   - PCAP Analysis
4. Stage 2 — ML + MITRE ATT&CK
5. Containment Steps (checklist)
6. Response Actions Taken
7. Recommendations

## Outcome Values
| Outcome | Điều kiện |
|---|---|
| FALSE_POSITIVE | action = close_fp |
| BLOCKED | response.blocked_ips not empty |
| ESCALATED | escalate + HIGH/CRITICAL + no block |
| MONITORED | monitor hoặc severity thấp |
