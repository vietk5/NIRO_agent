"""
safety.py — Kiểm tra an toàn trước khi thực hiện hành động phòng thủ
"""

import ipaddress
import re
from typing import Optional


# IPs nội bộ không được block tự động
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

_CRITICAL_SERVICES = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}


def is_safe_to_block(ip: str) -> tuple[bool, str]:
    """Kiểm tra xem có an toàn để block IP này không."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"Invalid IP: {ip}"

    for net in _RFC1918:
        if addr in net:
            return False, f"RFC-1918 private address — không block IP nội bộ"

    if ip in _CRITICAL_SERVICES:
        return False, f"Critical DNS/infrastructure IP — cần phê duyệt thủ công"

    return True, "OK"


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def sanitize_shell_arg(arg: str) -> str:
    """Loại bỏ ký tự nguy hiểm khỏi shell argument."""
    return re.sub(r"[;&|`$<>\\]", "", str(arg))
