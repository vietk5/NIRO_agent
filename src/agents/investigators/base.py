"""
base.py — Base class cho tất cả Investigator Subagents

Mỗi investigator:
- Có LLM session riêng (system prompt chuyên biệt)
- Có tool set riêng phù hợp với loại tấn công
- Tự quyết định tool nào cần gọi (không hardcode)
- Báo findings về orchestrator qua submit_findings()
"""

from src.utils.agent_loop import run_agent


class InvestigatorSubagent:
    """
    Base investigator. Subclass override:
      - NAME        : tên hiển thị
      - SYSTEM      : system prompt chuyên biệt
      - _build_tools(): danh sách tools LLM có thể gọi
      - _build_tool_map(): map tên tool → Python function
    """
    NAME   = "base"
    SYSTEM = "Bạn ent.là investigator ag"

    def run(self, brief: str, verbose: bool = True) -> dict:
        """
        Nhận brief từ orchestrator, tự suy luận và gọi tools.
        Trả về findings dict.
        """
        tools    = self._build_tools()
        tool_map = self._build_tool_map()

        # Thêm submit_findings vào mọi investigator
        tools.append({
            "type": "function", "function": {
                "name": "submit_findings",
                "description": "Báo cáo kết quả điều tra về orchestrator. Gọi cuối cùng sau khi đã thu thập đủ thông tin.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "summary":       {"type": "string", "description": "Tóm tắt ngắn gọn phát hiện chính"},
                        "risk_level":    {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                        "indicators":    {"type": "array",  "items": {"type": "string"},
                                         "description": "Danh sách dấu hiệu tấn công cụ thể"},
                        "recommended_action": {"type": "string",
                                              "description": "Hành động khuyến nghị: block/monitor/escalate/close"},
                        "confidence":    {"type": "number", "minimum": 0, "maximum": 1},
                        "raw_data":      {"type": "object", "description": "Dữ liệu thô từ các tools"},
                    },
                    "required": ["summary", "risk_level", "indicators", "recommended_action", "confidence"],
                },
            },
        })
        tool_map["submit_findings"] = lambda **kw: kw

        if verbose:
            print(f"    [{self.NAME}] Starting investigation...", flush=True)

        result = run_agent(
            system_prompt=self.SYSTEM,
            user_request=brief,
            tools=tools,
            tool_map=tool_map,
            max_iterations=10,
            verbose=verbose,
        )

        # Lấy findings từ submit_findings call cuối cùng
        findings = {}
        for call in reversed(result.get("tool_call_log", [])):
            if call["tool"] == "submit_findings":
                findings = call["result"]
                break

        if not findings:
            findings = {
                "summary": f"{self.NAME}: investigation incomplete",
                "risk_level": "medium",
                "indicators": [],
                "recommended_action": "monitor",
                "confidence": 0.3,
                "error": result.get("error"),
            }

        findings["subagent"] = self.NAME
        findings["iterations"] = result.get("iterations", 0)
        findings["tokens"] = result.get("total_tokens", 0)

        if verbose:
            print(f"    [{self.NAME}] Done — risk={findings['risk_level']} "
                  f"conf={findings['confidence']:.0%} iter={findings['iterations']}", flush=True)

        return findings

    def _build_tools(self) -> list:
        return []

    def _build_tool_map(self) -> dict:
        return {}
