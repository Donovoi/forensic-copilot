#!/usr/bin/env python3
"""Preflight a llama.cpp OpenAI-compatible backend before OpenCode runs.

This check is intentionally generic: it does not inspect evidence and should not
be pointed at case files. It verifies that the local model server is reachable,
idle, and, when requested, can produce visible content or a visible tool call
after any hidden reasoning.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any


def request_json(base_url: str, path: str, payload: dict[str, Any] | None = None, timeout: int = 20) -> Any:
    url = base_url.rstrip("/") + path
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
    return json.loads(body) if body else {}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def warn(message: str) -> None:
    print(f"WARN: {message}")


def get_models(models_payload: Any) -> set[str]:
    models: set[str] = set()
    if isinstance(models_payload, dict):
        for key in ("data", "models"):
            value = models_payload.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        for field in ("id", "model", "name"):
                            if item.get(field):
                                models.add(str(item[field]))
    return models


def check_slots(base_url: str, require_no_reasoning: bool) -> None:
    try:
        slots = request_json(base_url, "/slots", timeout=10)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        warn(f"could not inspect /slots: {exc}")
        return
    if not isinstance(slots, list):
        warn("/slots did not return a list")
        return
    for slot in slots:
        if not isinstance(slot, dict):
            continue
        slot_id = slot.get("id", "?")
        if slot.get("is_processing"):
            fail(f"llama.cpp slot {slot_id} is still processing; wait for idle before starting OpenCode")
        params = slot.get("params") if isinstance(slot.get("params"), dict) else {}
        reasoning_format = params.get("reasoning_format")
        decoded = (slot.get("next_token") or [{}])[0].get("n_decoded") if isinstance(slot.get("next_token"), list) else None
        if reasoning_format and reasoning_format != "none" and decoded:
            message = (
                f"llama.cpp slot {slot_id} last used reasoning_format={reasoning_format!r}; "
                "run --smoke-tool-call to confirm visible output still emerges after reasoning"
            )
            if require_no_reasoning:
                fail(message)
            warn(message)


def smoke_tool_call(base_url: str, model: str, max_tokens: int, timeout: int) -> None:
    payload = {
        "model": model,
        "temperature": 0,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": "Think if needed, then return one visible tool call."},
            {"role": "user", "content": "Call first_task with description set to ok."},
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "first_task",
                    "description": "Minimal smoke-test tool.",
                    "parameters": {
                        "type": "object",
                        "properties": {"description": {"type": "string"}},
                        "required": ["description"],
                    },
                },
            }
        ],
        "tool_choice": {"type": "function", "function": {"name": "first_task"}},
    }
    response = request_json(base_url, "/v1/chat/completions", payload=payload, timeout=timeout)
    choices = response.get("choices") if isinstance(response, dict) else None
    if not choices:
        fail("smoke request returned no choices")
    message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
    visible_content = bool(message.get("content"))
    visible_tool_calls = bool(message.get("tool_calls"))
    reasoning = bool(message.get("reasoning_content") or message.get("reasoning_details"))
    if reasoning and not (visible_content or visible_tool_calls):
        fail(
            "smoke request produced only hidden reasoning; increase OpenCode output cap, "
            "raise the smoke max tokens, or use a finite llama.cpp --reasoning-budget"
        )
    if not (visible_content or visible_tool_calls):
        fail("smoke request produced no visible content or tool call")


def main() -> int:
    parser = argparse.ArgumentParser(description="Preflight a llama.cpp backend for OpenCode local-model runs.")
    parser.add_argument("--base-url", default=os.environ.get("LLAMACPP_BASE_URL", "http://localhost:8080"))
    parser.add_argument("--model", default=os.environ.get("LLAMACPP_MODEL", "gemma-heretic-bf16"))
    parser.add_argument("--min-context", type=int, default=16000)
    parser.add_argument("--smoke-tool-call", action="store_true", help="send a tool-call request to catch hidden-reasoning-only failures")
    parser.add_argument("--smoke-max-tokens", type=int, default=2048)
    parser.add_argument("--smoke-timeout", type=int, default=1800)
    parser.add_argument("--require-no-reasoning", action="store_true", help="fail if a stale slot shows reasoning was used")
    args = parser.parse_args()

    try:
        health = request_json(args.base_url, "/health", timeout=10)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        fail(f"backend health check failed at {args.base_url}: {exc}")
    status = health.get("status") if isinstance(health, dict) else None
    if status not in ("ok", "no slot available"):
        fail(f"unexpected backend health status: {health!r}")

    models = get_models(request_json(args.base_url, "/v1/models", timeout=10))
    if args.model not in models:
        fail(f"model {args.model!r} not advertised by backend; available={sorted(models)}")

    try:
        props = request_json(args.base_url, "/props", timeout=10)
        n_ctx = int(props.get("default_generation_settings", {}).get("n_ctx", 0))
        if n_ctx and n_ctx < args.min_context:
            fail(f"backend context {n_ctx} is below required minimum {args.min_context}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, AttributeError) as exc:
        warn(f"could not inspect /props context: {exc}")

    check_slots(args.base_url, args.require_no_reasoning)

    if args.smoke_tool_call:
        smoke_tool_call(args.base_url, args.model, args.smoke_max_tokens, args.smoke_timeout)

    print(f"OK: backend {args.base_url} is reachable, idle, and advertises {args.model}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
