"""
network_tools.py — Network recon tools: port scan, DNS, WHOIS, banner grab
"""

import json
import socket
import subprocess
from datetime import datetime, timezone
from typing import Optional

from src.utils.safety import is_valid_ip, sanitize_shell_arg


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]


def scan_ports(target_ip: str, ports: list = None, timeout: float = 1.0) -> dict:
    """Quét cổng TCP."""
    if not is_valid_ip(target_ip):
        return {"error": f"Invalid IP: {target_ip}"}
    ports = ports or COMMON_PORTS
    open_ports, closed_ports = [], []
    for port in ports:
        try:
            with socket.create_connection((target_ip, port), timeout=timeout):
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            closed_ports.append(port)
    return {"target": target_ip, "open_ports": open_ports, "scanned": len(ports)}


def grab_banner(target_ip: str, port: int, timeout: float = 2.0) -> dict:
    """Lấy banner service."""
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            sock.sendall(b"\r\n")
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
        return {"target": target_ip, "port": port, "banner": banner[:200]}
    except Exception as e:
        return {"target": target_ip, "port": port, "banner": None, "error": str(e)}


def resolve_dns(hostname: str) -> dict:
    """DNS lookup."""
    try:
        addr = socket.gethostbyname(hostname)
        return {"hostname": hostname, "ip": addr}
    except Exception as e:
        return {"hostname": hostname, "ip": None, "error": str(e)}


def whois_lookup(ip: str) -> dict:
    """WHOIS lookup via subprocess."""
    if not is_valid_ip(ip):
        return {"error": f"Invalid IP: {ip}"}
    safe_ip = sanitize_shell_arg(ip)
    try:
        result = subprocess.run(
            ["whois", safe_ip], capture_output=True, text=True, timeout=10
        )
        output = result.stdout[:1500]
        # Parse key fields
        info = {"raw": output[:500]}
        for line in output.splitlines():
            lower = line.lower()
            if "country" in lower and ":" in line:
                info["country"] = line.split(":", 1)[1].strip()[:5]
            if "netname" in lower and ":" in line:
                info["netname"] = line.split(":", 1)[1].strip()[:50]
            if "orgname" in lower and ":" in line:
                info["org"] = line.split(":", 1)[1].strip()[:80]
        return info
    except FileNotFoundError:
        return {"note": "whois not installed", "ip": ip}
    except Exception as e:
        return {"error": str(e)}
