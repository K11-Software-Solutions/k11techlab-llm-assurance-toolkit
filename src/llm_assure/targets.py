"""Target adapters: the LLM application under test.

A target receives the conversation so far (a list of {"role", "content"}
messages, ending with a user turn) and returns the assistant's reply text.

Supported types (``type:`` in the target YAML):

* ``http``      - any JSON HTTP endpoint (your chatbot's own API)
* ``openai``    - any OpenAI-compatible /chat/completions endpoint
* ``anthropic`` - a Claude model with your system prompt
* ``python``    - an in-process callable ``module:function`` (great for unit tests)
"""

from __future__ import annotations

import copy
import importlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable

import httpx
import yaml

Messages = list[dict[str, str]]

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _dig(data: Any, path: str) -> Any:
    """Resolve a dotted path like ``choices.0.message.content``."""
    if not path:
        return data
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(f"cannot resolve '{part}' in response path '{path}'")
    return cur


class Target:
    """Base class for systems under test."""

    type = "base"

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.name: str = config.get("name", "Unnamed target")
        # Context describes the app so probes can be templated and judged:
        # purpose, canary, allowed_topics, forbidden_topics, etc.
        self.context: dict[str, Any] = config.get("context", {}) or {}
        self.timeout: float = float(config.get("timeout", 60))

    def send(self, messages: Messages) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    def close(self) -> None:
        pass


class HttpTarget(Target):
    type = "http"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.url = _expand_env(config["url"])
        self.method = config.get("method", "POST").upper()
        self.headers = _expand_env(config.get("headers", {}) or {})
        self.template = config.get("request_template", {"message": "{{prompt}}"})
        self.response_path = config.get("response_path", "")
        self.client = httpx.Client(timeout=self.timeout)

    def _render(self, node: Any, messages: Messages) -> Any:
        prompt = messages[-1]["content"]
        if isinstance(node, str):
            if node == "{{messages}}":
                return messages
            if node == "{{history}}":
                return messages[:-1]
            return node.replace("{{prompt}}", prompt)
        if isinstance(node, dict):
            return {k: self._render(v, messages) for k, v in node.items()}
        if isinstance(node, list):
            return [self._render(v, messages) for v in node]
        return node

    def send(self, messages: Messages) -> str:
        body = self._render(copy.deepcopy(self.template), messages)
        resp = self.client.request(self.method, self.url, headers=self.headers, json=body)
        resp.raise_for_status()
        try:
            data = resp.json()
        except json.JSONDecodeError:
            return resp.text
        value = _dig(data, self.response_path)
        return value if isinstance(value, str) else json.dumps(value)

    def close(self) -> None:
        self.client.close()


class OpenAICompatibleTarget(Target):
    type = "openai"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.base_url = _expand_env(config.get("base_url", "https://api.openai.com/v1")).rstrip("/")
        self.model = config["model"]
        key_env = config.get("api_key_env", "OPENAI_API_KEY")
        self.api_key = os.environ.get(key_env, "")
        self.system_prompt = config.get("system_prompt", "")
        self.client = httpx.Client(timeout=self.timeout)

    def send(self, messages: Messages) -> str:
        msgs = ([{"role": "system", "content": self.system_prompt}] if self.system_prompt else []) + messages
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        resp = self.client.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json={"model": self.model, "messages": msgs},
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"] or ""

    def close(self) -> None:
        self.client.close()


class AnthropicTarget(Target):
    """Test a Claude-backed assistant defined by a system prompt."""

    type = "anthropic"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Install the 'judge' extra: pip install 'k11-llm-assure[judge]'") from exc
        self.client = anthropic.Anthropic()
        self.model = config.get("model", "claude-opus-5-5")
        self.system_prompt = config.get("system_prompt", "")
        self.max_tokens = int(config.get("max_tokens", 4096))

    def send(self, messages: Messages) -> str:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        }
        if self.system_prompt:
            kwargs["system"] = self.system_prompt
        response = self.client.messages.create(**kwargs)
        if response.stop_reason == "refusal":
            return "[refused by model safety classifier]"
        return "".join(b.text for b in response.content if b.type == "text")


class PythonTarget(Target):
    type = "python"

    def __init__(self, config: dict[str, Any], base_dir: Path | None = None):
        super().__init__(config)
        spec = config["callable"]
        module_name, _, func_name = spec.partition(":")
        search_path = config.get("python_path")
        if search_path:
            p = Path(search_path)
            if not p.is_absolute() and base_dir:
                p = (base_dir / p).resolve()
            if str(p) not in sys.path:
                sys.path.insert(0, str(p))
        module = importlib.import_module(module_name)
        self.fn: Callable[[Messages], str] = getattr(module, func_name or "respond")

    def send(self, messages: Messages) -> str:
        return str(self.fn(messages))


TARGET_TYPES = {
    "http": HttpTarget,
    "openai": OpenAICompatibleTarget,
    "anthropic": AnthropicTarget,
    "python": PythonTarget,
}


def target_from_dict(config: dict[str, Any], base_dir: Path | None = None) -> Target:
    ttype = config.get("type", "http")
    if ttype == "instrumented":  # study targets; imported lazily to keep the core light
        from .instrumented import InstrumentedTarget
        return InstrumentedTarget(config, base_dir=base_dir)
    cls = TARGET_TYPES.get(ttype)
    if cls is None:
        raise ValueError(f"Unknown target type '{ttype}'. Use one of: {', '.join(TARGET_TYPES)}, instrumented")
    if cls is PythonTarget:
        return PythonTarget(config, base_dir=base_dir)
    return cls(config)


def load_target(path: str | Path) -> Target:
    path = Path(path)
    with path.open(encoding="utf-8") as fh:
        config = yaml.safe_load(fh) or {}
    return target_from_dict(config, base_dir=path.parent)
