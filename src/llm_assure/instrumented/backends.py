"""Model backends that run a tool-use loop for an instrumented app.

A backend answers one user turn: it calls the model, executes any tool calls
through the app's tool layer, feeds the results back, and returns the final
reply text. Tool rounds are internal to the turn; only the text reply goes
back into the conversation history.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Protocol

import httpx

from .tools import ToolSpec

CallTool = Callable[[str, dict[str, Any]], Any]
MAX_TOOL_ROUNDS = 8
REFUSED = "[refused by model safety classifier]"


class Backend(Protocol):
    model: str

    def chat(self, system: str, messages: list[dict[str, str]], tools: list[ToolSpec], call_tool: CallTool) -> str: ...


class AnthropicBackend:
    """Claude via the Messages API.

    No refusal fallback is configured on purpose: the study measures the pinned
    model's own behaviour, so a refusal is recorded as the app's answer.
    """

    def __init__(self, model: str = "claude-opus-5-5", effort: str | None = None,
                 max_tokens: int = 4096, client: Any = None):
        if client is None:
            import anthropic
            client = anthropic.Anthropic()
        self.client, self.model, self.effort, self.max_tokens = client, model, effort, max_tokens

    def chat(self, system, messages, tools, call_tool):
        tool_defs = [{"name": t.name, "description": t.description, "input_schema": t.schema()} for t in tools]
        convo: list[Any] = [dict(m) for m in messages]
        for _ in range(MAX_TOOL_ROUNDS):
            kwargs: dict[str, Any] = {"model": self.model, "max_tokens": self.max_tokens,
                                      "system": system, "messages": convo}
            if tool_defs:
                kwargs["tools"] = tool_defs
            if self.effort:
                kwargs["output_config"] = {"effort": self.effort}
            response = self.client.messages.create(**kwargs)
            if response.stop_reason == "refusal":
                return REFUSED
            uses = [b for b in response.content if b.type == "tool_use"]
            if not uses:
                return "".join(b.text for b in response.content if b.type == "text")
            convo.append({"role": "assistant", "content": response.content})
            convo.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": b.id,
                 "content": json.dumps(call_tool(b.name, dict(b.input)), ensure_ascii=False)}
                for b in uses
            ]})
        return "[app stopped: too many tool rounds]"


class OpenAICompatibleBackend:
    """Any OpenAI-compatible /chat/completions endpoint with function calling (vLLM, Ollama, ...)."""

    def __init__(self, model: str, base_url: str = "http://localhost:11434/v1",
                 api_key_env: str = "OPENAI_API_KEY", timeout: float = 120, http: Any = None):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = os.environ.get(api_key_env, "")
        self.http = http or httpx.Client(timeout=timeout)

    def chat(self, system, messages, tools, call_tool):
        tool_defs = [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                       "parameters": t.schema()}} for t in tools]
        convo: list[dict[str, Any]] = [{"role": "system", "content": system}] + [dict(m) for m in messages]
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        for _ in range(MAX_TOOL_ROUNDS):
            body: dict[str, Any] = {"model": self.model, "messages": convo, "temperature": 0}
            if tool_defs:
                body["tools"] = tool_defs
            resp = self.http.post(f"{self.base_url}/chat/completions", headers=headers, json=body)
            resp.raise_for_status()
            msg = resp.json()["choices"][0]["message"]
            calls = msg.get("tool_calls") or []
            if not calls:
                return msg.get("content") or ""
            convo.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
            for c in calls:
                try:
                    args = json.loads(c["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                convo.append({"role": "tool", "tool_call_id": c["id"],
                              "content": json.dumps(call_tool(c["function"]["name"], args), ensure_ascii=False)})
        return "[app stopped: too many tool rounds]"
