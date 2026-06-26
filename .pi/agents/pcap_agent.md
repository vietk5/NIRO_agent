---
name: pcap-agent
model: none
description: >
  Stage 1C — PCAP Feature Extraction.
  Chạy SONG SONG/ tuàn tự với recon-agent và log-collector.
  Trích xuất flow features, anomaly detection, signature matching.
---

## Nhiệm vụ
Phân tích network traffic: flow features, anomaly indicators, flow signature.

## Tools
- **scapy** (nếu có file PCAP thật): rdpcap, IP, TCP, UDP layers
- **Fallback**: Tính features từ alert metadata (packets, bytes_in, bytes_out, duration)

## Protocol

```bash
# Không có PCAP file
python3 -m src.agents.pcap_analyzer \
  --alert '{{alert_json}}' \
  --output .pi/triage/pcap_result.json

# Có PCAP file
python3 -m src.agents.pcap_analyzer \
  --alert '{{alert_json}}' \
  --pcap path/to/capture.pcap \
  --output .pi/triage/pcap_result.json
```

## Output Schema

```json
{
  "flow_features": {
    "packet_count":     0,
    "total_bytes":      0,
    "packets_per_sec":  0.0,
    "bytes_per_packet": 0.0,
    "payload_entropy":  0.0
  },
  "anomaly_indicators":   ["HIGH_PACKET_RATE", "SMALL_PACKETS_HIGH_FREQ"],
  "flow_signature_match": "SSH_BRUTE_FORCE|PORT_SCAN|DATA_EXFILTRATION|DDOS_SYN_FLOOD|UNKNOWN",
  "risk_score":           0.0
}
```

## Flow Signatures
| Signature | Điều kiện |
|---|---|
| SSH_BRUTE_FORCE | dst_port=22, pps>3, bpp<200 |
| PORT_SCAN | pps>50, bpp<100, syn_count>50 |
| DATA_EXFILTRATION | bytes_out>10000, entropy>6.5 |
| DDOS_SYN_FLOOD | pps>500 |
