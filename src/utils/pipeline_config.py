"""
pipeline_config.py — Đọc và cung cấp cấu hình pipeline từ pipeline.yaml

Dùng trong orchestrator.py để query mode/timeout/enabled của từng stage/agent.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

# Đường dẫn tìm pipeline.yaml 
_SEARCH_PATHS = [
    Path("pipeline.yaml"),
    Path(__file__).parent.parent.parent / "pipeline.yaml",
]

# Cấu hình mặc định nếu không tìm thấy file hoặc yaml chưa cài
_DEFAULTS: dict[str, Any] = {
    "stage0_triage":       {"name": "Triage",        "mode": "sequential", "timeout_sec": 20,  "enabled": True, "agents": {}},
    "stage1_collection":   {"name": "Data Collection","mode": "parallel",   "timeout_sec": 30,  "enabled": True,
                            "agents": {"recon": {"enabled": True}, "log_collect": {"enabled": True}, "pcap": {"enabled": True}}},
    "stage2_analysis":     {"name": "Analysis",       "mode": "parallel",   "timeout_sec": 60,  "enabled": True,
                            "agents": {"ml_classify": {"enabled": True}, "mitre_map": {"enabled": True}}},
    "stage2c_orchestrator":{"name": "Orchestrator",   "mode": "sequential", "timeout_sec": 120, "enabled": True, "agents": {}},
    "stage3a_response":    {"name": "Response",       "mode": "sequential", "timeout_sec": 300, "enabled": True, "agents": {}},
    "stage3b_report":      {"name": "Report",         "mode": "sequential", "timeout_sec": 60,  "enabled": True, "agents": {}},
}


def _load_yaml() -> dict:
    """Tìm và đọc pipeline.yaml. Trả về dict rỗng nếu không tìm thấy."""
    if not _YAML_AVAILABLE:
        return {}
    for path in _SEARCH_PATHS:
        if path.exists():
            try:
                with path.open(encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                return data.get("stages", {})
            except Exception:
                return {}
    return {}


def _merge(defaults: dict, from_yaml: dict) -> dict:
    """Merge yaml config vào defaults, yaml takes precedence."""
    result = {}
    for stage_id, default_cfg in defaults.items():
        yaml_cfg = from_yaml.get(stage_id, {})
        merged = {**default_cfg, **yaml_cfg}
        # Merge agent-level config
        if "agents" in default_cfg and "agents" in yaml_cfg:
            merged_agents = {}
            for agent_id, agent_default in default_cfg["agents"].items():
                agent_yaml = yaml_cfg["agents"].get(agent_id, {})
                merged_agents[agent_id] = {**agent_default, **agent_yaml}
            merged["agents"] = merged_agents
        result[stage_id] = merged
    return result


# ── Singleton cache ──────────────────────────────────────────────────────────

_CONFIG: dict | None = None


def get_config() -> dict:
    """Trả về config đã merge (cached sau lần đầu load)."""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = _merge(_DEFAULTS, _load_yaml())
    return _CONFIG


def reload_config() -> dict:
    """Force reload từ file (dùng khi file thay đổi lúc runtime)."""
    global _CONFIG
    _CONFIG = None
    return get_config()


# ── Public helpers ────────────────────────────────────────────────────────────

def stage_mode(stage_id: str) -> str:
    """Trả về 'parallel' hoặc 'sequential' cho stage."""
    return get_config().get(stage_id, {}).get("mode", "sequential")


def stage_timeout(stage_id: str) -> float:
    """Trả về timeout (giây) cho stage. Env var override: STAGE1_TIMEOUT_SEC, STAGE2_TIMEOUT_SEC."""
    env_map = {
        "stage0_triage":     "STAGE0_TIMEOUT_SEC",
        "stage1_collection": "STAGE1_TIMEOUT_SEC",
        "stage2_analysis":   "STAGE2_TIMEOUT_SEC",
        "stage3a_response":  "APPROVAL_TIMEOUT_SEC",
        "stage3b_report":    "REPORT_TIMEOUT_SEC",
    }
    env_key = env_map.get(stage_id)
    if env_key and os.getenv(env_key):
        return float(os.getenv(env_key))
    return float(get_config().get(stage_id, {}).get("timeout_sec", 30))


def stage_enabled(stage_id: str) -> bool:
    """Trả về True nếu stage được bật."""
    return bool(get_config().get(stage_id, {}).get("enabled", True))


def agent_enabled(stage_id: str, agent_id: str) -> bool:
    """Trả về True nếu agent cụ thể trong stage được bật."""
    agents = get_config().get(stage_id, {}).get("agents", {})
    return bool(agents.get(agent_id, {}).get("enabled", True))


def active_agents(stage_id: str) -> list[str]:
    """Trả về danh sách agent IDs được bật trong stage."""
    agents = get_config().get(stage_id, {}).get("agents", {})
    return [aid for aid, cfg in agents.items() if cfg.get("enabled", True)]


def print_config_summary():
    """In tóm tắt config hiện tại ra stdout (dùng để debug)."""
    cfg = get_config()
    source = "pipeline.yaml" if _load_yaml() else "defaults (pipeline.yaml not found)"
    print(f"\n  [CONFIG] Loaded from: {source}")
    for stage_id, scfg in cfg.items():
        enabled_mark = "[+]" if scfg.get("enabled") else "[-]"
        mode    = scfg.get("mode", "?")
        timeout = scfg.get("timeout_sec", "?")
        agents  = scfg.get("agents", {})
        if agents:
            parts = []
            for k, a in agents.items():
                m = "[+]" if a.get("enabled") else "[-]"
                parts.append(m + k)
            agent_str = " ".join(parts)
            print(f"  {enabled_mark} {stage_id:<22s} mode={mode:<12s} timeout={timeout}s  agents=[{agent_str}]")
        else:
            print(f"  {enabled_mark} {stage_id:<22s} mode={mode:<12s} timeout={timeout}s")
    print()
