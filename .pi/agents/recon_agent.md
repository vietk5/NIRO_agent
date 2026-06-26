---
name: recon-agent
model: none
description: >
  Stage 1A — Threat Intelligence & Network Recon.
  Chạy SONG SONG / Tuần tự với log-collector và pcap-agent.
  Timeout: STAGE1_TIMEOUT_SEC (mặc định 30s).
---

## Nhiệm vụ
Thu thập threat intel về IP nguồn: AbuseIPDB, port scan, WHOIS, DNS.

## Quan trọng về Timeout
Tất cả external API calls (AbuseIPDB, socket scan) có thể bị slow.
Nếu timeout → trả fallback data, KHÔNG block toàn bộ Stage 1.

## Protocol

```bash
python3 -m src.agents.recon_agent \
  --alert '{{alert_json}}' \
  --triage-result .pi/triage/triage_result.json \
  --output .pi/triage/recon_result.json
```

## Output Schema

```json
{
  "risk_profile": {
    "target_ip":     "...",
    "threat_score":  0,
    "risk_level":    "low|medium|high|critical",
    "isTor":         false,
    "country":       "...",
    "isp":           "...",
    "open_ports":    [],
    "summary":       "..."
  }
}
```

## Chạy song song với
- `log-collector-agent.md` (Stage 1B)
- `pcap-agent.md` (Stage 1C)
