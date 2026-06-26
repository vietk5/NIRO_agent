"""
threat_intel_tools.py — AbuseIPDB + VirusTotal threat intelligence
"""

import os
import requests


ABUSEIPDB_URL  = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def check_ip_reputation(ip: str) -> dict:
    """
    Tra cứu IP trên AbuseIPDB.
    Nếu không có API key → trả mock data.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key or api_key == "your_key_here":
        return _mock_reputation(ip)

    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "ip":             data.get("ipAddress", ip),
            "abuseScore":     data.get("abuseConfidenceScore", 0),
            "isTor":          data.get("isTor", False),
            "country":        data.get("countryCode", ""),
            "isp":            data.get("isp", ""),
            "totalReports":   data.get("totalReports", 0),
            "lastReportedAt": data.get("lastReportedAt", ""),
            "usageType":      data.get("usageType", ""),
        }
    except Exception as e:
        return {"ip": ip, "abuseScore": 0, "error": str(e), **_mock_reputation(ip)}


# ── VirusTotal ────────────────────────────────────────────────────────────────

def check_virustotal(ip: str) -> dict:
    """
    Tra cứu IP trên VirusTotal v3 API.
    Trả về: malicious count, suspicious count, reputation score, country, AS owner, tags.
    Nếu không có API key → trả mock data.

    API key miễn phí: https://www.virustotal.com/gui/sign-in → My API Key
    Giới hạn free: 4 requests/phút, 500/ngày.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key or api_key == "your_key_here":
        return _mock_virustotal(ip)

    try:
        resp = requests.get(
            VIRUSTOTAL_URL.format(ip=ip),
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if resp.status_code == 404:
            return {"ip": ip, "malicious": 0, "suspicious": 0, "reputation": 0,
                    "error": "IP not found in VirusTotal"}
        resp.raise_for_status()

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious   = stats.get("malicious", 0)
        suspicious  = stats.get("suspicious", 0)
        harmless    = stats.get("harmless", 0)
        undetected  = stats.get("undetected", 0)
        total       = malicious + suspicious + harmless + undetected or 1

        return {
            "ip":           ip,
            "malicious":    malicious,
            "suspicious":   suspicious,
            "harmless":     harmless,
            "undetected":   undetected,
            "detection_ratio": f"{malicious}/{total}",
            "reputation":   attrs.get("reputation", 0),       # âm = xấu
            "country":      attrs.get("country", ""),
            "as_owner":     attrs.get("as_owner", ""),        # tên ISP/ASN
            "tags":         attrs.get("tags", []),            # ["tor", "vpn", ...]
            "verdict":      _vt_verdict(malicious, suspicious),
        }
    except Exception as e:
        return {"ip": ip, "malicious": 0, "suspicious": 0, "reputation": 0,
                "error": str(e), **_mock_virustotal(ip)}


def _vt_verdict(malicious: int, suspicious: int) -> str:
    """Đánh giá tổng hợp từ VirusTotal stats."""
    if malicious >= 5:
        return "MALICIOUS"
    elif malicious >= 1 or suspicious >= 3:
        return "SUSPICIOUS"
    else:
        return "CLEAN"


def _mock_virustotal(ip: str) -> dict:
    """Mock data khi không có VT API key."""
    KNOWN = {
        "185.220.101.34": {"malicious": 18, "suspicious": 3, "reputation": -85,
                           "country": "DE", "as_owner": "Tor Exit Node",
                           "tags": ["tor"], "verdict": "MALICIOUS"},
        "45.33.32.156":   {"malicious": 2,  "suspicious": 1, "reputation": -15,
                           "country": "US", "as_owner": "Akamai Technologies",
                           "tags": [], "verdict": "SUSPICIOUS"},
        "198.51.100.42":  {"malicious": 0,  "suspicious": 0, "reputation": 0,
                           "country": "US", "as_owner": "RFC5737",
                           "tags": [], "verdict": "CLEAN"},
        "203.0.113.99":   {"malicious": 8,  "suspicious": 2, "reputation": -60,
                           "country": "CN", "as_owner": "Unknown AS",
                           "tags": [], "verdict": "MALICIOUS"},
    }
    base = KNOWN.get(ip, {"malicious": 0, "suspicious": 0, "reputation": 0,
                          "country": "?", "as_owner": "Unknown",
                          "tags": [], "verdict": "CLEAN"})
    if ip.startswith(("192.168.", "10.", "172.")):
        base = {"malicious": 0, "suspicious": 0, "reputation": 0,
                "country": "LAN", "as_owner": "Private", "tags": [], "verdict": "CLEAN"}
    total = base["malicious"] + base["suspicious"] + 10
    return {"ip": ip, "harmless": 10, "undetected": 5,
            "detection_ratio": f"{base['malicious']}/{total}",
            **base, "mock": True}


# ── Mock AbuseIPDB ────────────────────────────────────────────────────────────

def _mock_reputation(ip: str) -> dict:
    """Mock data khi không có AbuseIPDB API key."""
    KNOWN = {
        "185.220.101.34": {"abuseScore": 100, "isTor": True,  "country": "DE", "isp": "Tor Exit Node"},
        "45.33.32.156":   {"abuseScore": 42,  "isTor": False, "country": "US", "isp": "Linode"},
        "198.51.100.42":  {"abuseScore": 25,  "isTor": False, "country": "US", "isp": "RFC5737"},
        "203.0.113.99":   {"abuseScore": 65,  "isTor": False, "country": "CN", "isp": "Unknown"},
    }
    base = KNOWN.get(ip, {"abuseScore": 0, "isTor": False, "country": "?", "isp": "Unknown"})
    if ip.startswith(("192.168.", "10.", "172.")):
        base = {"abuseScore": 0, "isTor": False, "country": "LAN", "isp": "Private"}
    return {"ip": ip, "totalReports": 0, **base, "mock": True}
