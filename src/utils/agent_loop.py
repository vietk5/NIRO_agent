"""
agent_loop.py — Observe-Think-Act agent loop (OpenAI / Anthropic)
"""

import json
import os
import time
from typing import Callable


def get_llm_client():
    """Trả về (backend, client) dựa trên API key có sẵn."""
    if os.getenv("ANTHROPIC_API_KEY"):
        import anthropic
        return ("anthropic", anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY")))
    elif os.getenv("OPENAI_API_KEY"):
        from openai import OpenAI
        return ("openai", OpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        ))
    raise EnvironmentError("Cần ANTHROPIC_API_KEY hoặc OPENAI_API_KEY trong .env")


def _default_model(backend: str) -> str:
    if backend == "anthropic":
        return os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
    return os.getenv("OPENAI_MODEL", "gpt-4o")


def run_agent(
    system_prompt: str,
    user_request:  str,
    tools:         list,
    tool_map:      dict[str, Callable],
    max_iterations: int = 15,
    model:          str = None,
    verbose:        bool = True,
    llm_client:     tuple = None,   # truyền (backend, client) từ singleton nếu có
) -> dict:
    """
    Vòng lặp Observe-Think-Act.
    Returns: {final_response, tool_call_log, iterations, total_tokens, error}
    """
    backend, client = llm_client if llm_client is not None else get_llm_client()
    model = model or _default_model(backend)

    messages      = [{"role": "user", "content": user_request}]
    tool_call_log = []
    total_tokens  = 0

    for iteration in range(max_iterations):
        try:
            if backend == "openai":
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "system", "content": system_prompt}] + messages,
                    tools=tools, tool_choice="auto", temperature=0.0,
                )
                message       = response.choices[0].message
                finish_reason = response.choices[0].finish_reason
                total_tokens += response.usage.total_tokens

                asst = {"role": "assistant", "content": message.content or ""}
                if message.tool_calls:
                    asst["tool_calls"] = [tc.model_dump() for tc in message.tool_calls]
                messages.append(asst)

            else:  # anthropic
                response = client.messages.create(
                    model=model,
                    system=system_prompt,
                    messages=_to_anthropic_messages(messages),
                    tools=_openai_tools_to_anthropic(tools),
                    max_tokens=4096, temperature=0.0,
                )
                finish_reason  = "stop" if response.stop_reason == "end_turn" else "tool_calls"
                total_tokens  += response.usage.input_tokens + response.usage.output_tokens
                message        = response
                messages.append(_anthropic_response_to_openai(response))

        except Exception as e:
            return {"error": f"LLM API error: {e}", "tool_call_log": tool_call_log,
                    "iterations": iteration + 1}

        if finish_reason == "tool_calls":
            tool_calls = (message.tool_calls if backend == "openai"
                          else _extract_anthropic_tool_calls(message))
            tool_results = []
            for tc in tool_calls:
                if backend == "openai":
                    name, args, call_id = tc.function.name, json.loads(tc.function.arguments), tc.id
                else:
                    name, args, call_id = tc["name"], tc["input"], tc["id"]

                if verbose:
                    print(f"       → tool_call: {name}({json.dumps(args)[:80]})", flush=True)
                elif name in {"block_ip_address","create_incident_ticket","notify_analyst","route_alert"}:
                    print(f"       >> {name}({json.dumps(args)[:60]})", flush=True)

                t0 = time.perf_counter()
                try:
                    result = tool_map[name](**args) if name in tool_map else {"error": f"Unknown tool: {name}"}
                except Exception as e:
                    result = {"error": str(e)}
                duration_ms = int((time.perf_counter() - t0) * 1000)
                if verbose:
                    print(f"         OK {name} [{duration_ms}ms]", flush=True)

                tool_call_log.append({"iteration": iteration+1, "tool": name,
                                       "args": args, "result": result, "duration_ms": duration_ms})
                tool_results.append((call_id, result))

            if backend == "openai":
                for call_id, result in tool_results:
                    messages.append({"role": "tool", "tool_call_id": call_id,
                                     "content": json.dumps(result)})
            else:
                messages.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": cid, "content": json.dumps(r)}
                    for cid, r in tool_results
                ]})

        elif finish_reason in ("stop", "end_turn"):
            final_text = ((message.content or "") if backend == "openai"
                          else _extract_anthropic_text(message))

            # Nudge nếu model không dùng tool
            nudge_count = sum(1 for m in messages
                              if m.get("role") == "user" and "IMPORTANT" in str(m.get("content", "")))
            if not tool_call_log and tools and nudge_count < 2:
                messages.append({"role": "user", "content":
                    "IMPORTANT: Bạn PHẢI dùng các tools được cung cấp. Hãy gọi tool ngay bây giờ."})
                continue

            return {"final_response": final_text, "tool_call_log": tool_call_log,
                    "iterations": iteration+1, "total_tokens": total_tokens,
                    "messages": messages, "error": None}
        else:
            return {"error": f"Unexpected finish_reason: {finish_reason}",
                    "tool_call_log": tool_call_log}

    return {"error": f"Max iterations ({max_iterations}) reached",
            "tool_call_log": tool_call_log, "iterations": max_iterations}


# ── Format helpers ─────────────────────────────────────────────────────────────

def _openai_tools_to_anthropic(tools):
    return [{"name": t["function"]["name"], "description": t["function"]["description"],
             "input_schema": t["function"]["parameters"]} for t in tools]


def _to_anthropic_messages(messages):
    result, i = [], 0
    while i < len(messages):
        msg, role = messages[i], messages[i]["role"]
        if role == "user":
            content = msg["content"]
            result.append({"role": "user", "content": content if isinstance(content, list) else str(content or "")})
            i += 1
        elif role == "assistant":
            blocks = []
            if msg.get("content"):
                blocks.append({"type": "text", "text": msg["content"]})
            for tc in msg.get("tool_calls", []):
                fn = tc.get("function", tc)
                inp = fn.get("arguments") or tc.get("input", {})
                blocks.append({"type": "tool_use", "id": tc.get("id", ""),
                                "name": fn.get("name") or tc.get("name"),
                                "input": json.loads(inp) if isinstance(inp, str) else inp})
            result.append({"role": "assistant", "content": blocks})
            i += 1
        elif role == "tool":
            tool_blocks = []
            while i < len(messages) and messages[i]["role"] == "tool":
                tm = messages[i]
                tool_blocks.append({"type": "tool_result", "tool_use_id": tm.get("tool_call_id", ""),
                                    "content": tm.get("content", "")})
                i += 1
            result.append({"role": "user", "content": tool_blocks})
        else:
            i += 1
    return result


def _anthropic_response_to_openai(response):
    content, tool_calls = "", []
    for block in response.content:
        if block.type == "text":   content = block.text
        elif block.type == "tool_use":
            tool_calls.append({"id": block.id, "type": "function",
                                "function": {"name": block.name, "arguments": json.dumps(block.input)}})
    return {"role": "assistant", "content": content, "tool_calls": tool_calls}


def _extract_anthropic_tool_calls(response):
    return [{"name": b.name, "input": b.input, "id": b.id}
            for b in response.content if b.type == "tool_use"]


def _extract_anthropic_text(response):
    return " ".join(b.text for b in response.content if b.type == "text")
