#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent

LEAK_PATTERNS = {
    "windows_drive_path": re.compile(r"[A-Za-z]:\\|[A-Za-z]:/"),
    "evidence_ext_or_format": re.compile(r"(?i)(?:\.e01\b|\bE01\b|\bRAW\b|\bVMDK\b)"),
    "bitlocker": re.compile(r"(?i)bitlocker"),
    "raw_users_path": re.compile(r"(?i)\bUsers\\[A-Za-z0-9_. -]+"),
    "credential_word": re.compile(r"(?i)password|credential|secret"),
    "home_path": re.compile(r"/home/[A-Za-z0-9_.-]+"),
}


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def sha256_prefix(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16].upper() if path.exists() else ""


def provider_base_url(base_url: str) -> str:
    trimmed = base_url.rstrip("/")
    return trimmed if trimmed.endswith("/v1") else f"{trimmed}/v1"


def models_url(base_url: str) -> str:
    return provider_base_url(base_url).rstrip("/") + "/models"


def post_models_preflight(base_url: str, model: str, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(models_url(base_url), headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8", errors="replace"))

    advertised: list[str] = []
    for key in ("data", "models"):
        for item in payload.get(key, []) if isinstance(payload, dict) else []:
            if isinstance(item, dict):
                advertised.extend(str(item.get(field, "")) for field in ("id", "name", "model"))
                advertised.extend(str(alias) for alias in item.get("aliases", []) if alias)

    advertised = sorted({item for item in advertised if item})
    return {"ok": model in advertised, "model": model, "advertised": advertised[:20]}


def platform_profiler_prompt() -> str:
    return """# OpenCode Forensic Platform Profiler

Internal helper. Identify the evidence operating system and evidence mode before OS-specific collection or routing.

Rules:
- Identify evidence OS, not just runner OS.
- Separate runner, evidence source, and target host. WSL runner does not mean Linux evidence.
- Classify evidence mode and host role.
- Name filesystem and logging architecture if known.
- Do not mention image format names or extensions. Say `container type` or `image container metadata` instead.
- This helper is text-only on local-model runs; do not request shell, file, web, or task tools.
- Keep output under 10 lines.

Return exactly:
```text
PLATFORM:
- evidence_os:
- runner_boundary:
- mode_role:
- fs_logging:
- priority_artifacts:
- discovery_needed:
- tooling:
```
"""


def one_delegation_prompt() -> str:
    return """# Synthetic One-Delegation Forensic Examiner

You are testing the OpenCode forensic harness with a local model.

Rules:
- Synthetic fixture only. Do not request shell, file, web, read, grep, edit, or write tools.
- First action must be exactly one `task` delegation to `forensic-platform-profiler`.
- Delegate only this synthetic scenario: runner OS is Linux WSL-like OpenCode host; evidence source is a dead-box forensic image representing Windows endpoint workstations; no raw files, paths, credentials, or internet.
- After the helper returns, do not delegate again.
- Return a concise Markdown report with sections: TRACE, HELPER_RESULT, HARNESS_VERDICT.
- HARNESS_VERDICT must say whether exactly one helper delegation completed and whether the helper result is suitable for the next synthetic step.
- Do not mention image format names or extensions. Say `image container metadata` if needed.
"""


def build_config(mode: str, base_url: str, model: str) -> dict[str, Any]:
    agents: dict[str, Any] = {}
    if mode == "isolated-platform-profiler":
        default_agent = "forensic-platform-profiler"
        agents[default_agent] = {
            "description": "Synthetic isolated platform-profiler smoke test.",
            "mode": "primary",
            "prompt": "{file:forensic-platform-profiler.md}",
            "permission": deny_all_permissions(),
        }
    else:
        default_agent = "synthetic-one-delegation-examiner"
        agents[default_agent] = {
            "description": "Synthetic primary examiner that must delegate once to platform profiler.",
            "mode": "primary",
            "prompt": "{file:synthetic-one-delegation-examiner.md}",
            "permission": {
                **deny_all_permissions(),
                "task": {"*": "deny", "forensic-platform-profiler": "allow"},
            },
        }
        agents["forensic-platform-profiler"] = {
            "description": "Synthetic profiler helper.",
            "mode": "subagent",
            "steps": 3,
            "prompt": "{file:forensic-platform-profiler.md}",
            "permission": deny_all_permissions(),
        }

    return {
        "$schema": "https://opencode.ai/config.json",
        "default_agent": default_agent,
        "model": f"llamacpp-local/{model}",
        "small_model": f"llamacpp-local/{model}",
        "disabled_providers": ["gemini", "google"],
        "provider": {
            "llamacpp-local": {
                "options": {
                    "baseURL": provider_base_url(base_url),
                    "timeout": 3600000,
                    "chunkTimeout": 3600000,
                },
                "models": {
                    model: {
                        "reasoning": False,
                        "options": {"textVerbosity": "low", "temperature": 0},
                        "limit": {"context": 16384, "output": 1536},
                    }
                },
            }
        },
        "compaction": {
            "auto": False,
            "prune": False,
        },
        "tool_output": {"max_lines": 100, "max_bytes": 6000},
        "agent": agents,
    }


def deny_all_permissions() -> dict[str, Any]:
    return {
        "read": "deny",
        "list": "deny",
        "glob": "deny",
        "grep": "deny",
        "webfetch": "deny",
        "websearch": "deny",
        "todowrite": "deny",
        "task": "deny",
        "bash": "deny",
        "edit": "deny",
        "write": "deny",
    }


def analyze_output(run_dir: Path) -> dict[str, Any]:
    stdout_path = run_dir / "stdout.jsonl"
    stderr_path = run_dir / "stderr.txt"
    stdout_text = read_text(stdout_path)
    stderr_text = read_text(stderr_path)
    combined = stdout_text + "\n" + stderr_text
    leak_flags = {name: bool(pattern.search(combined)) for name, pattern in LEAK_PATTERNS.items()}

    event_types: dict[str, int] = {}
    task_mentions = 0
    final_like = 0
    parsed_events = 0
    for line in stdout_text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed_events += 1
        event_type = str(event.get("type") or event.get("event") or event.get("kind") or "unknown")
        event_types[event_type] = event_types.get(event_type, 0) + 1
        serialized = json.dumps(event, sort_keys=True)
        if "forensic-platform-profiler" in serialized or '"task"' in serialized.lower():
            task_mentions += 1
        if "PLATFORM:" in serialized or "HARNESS_VERDICT" in serialized:
            final_like += 1

    return {
        "stdout_bytes": len(stdout_text.encode("utf-8")),
        "stderr_bytes": len(stderr_text.encode("utf-8")),
        "stdout_sha256_prefix": sha256_prefix(stdout_path),
        "stderr_sha256_prefix": sha256_prefix(stderr_path),
        "leak_flags": leak_flags,
        "parsed_event_count": parsed_events,
        "event_types": event_types,
        "task_mention_count": task_mentions,
        "final_like_event_count": final_like,
        "stdout_preview": stdout_text[:1200],
        "stderr_preview": stderr_text[:800],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run synthetic local OpenCode forensic harness probes.")
    parser.add_argument(
        "--mode",
        choices=("isolated-platform-profiler", "one-delegation-examiner-profiler"),
        required=True,
    )
    parser.add_argument("--base-url", default=os.environ.get("LLAMACPP_BASE_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--model", default=os.environ.get("LLAMACPP_MODEL", "gemma-heretic-q4_k_m"))
    parser.add_argument("--opencode-command", default="opencode")
    parser.add_argument("--output-root", default="reports/local-model-evals")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--skip-preflight", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    output_dir = (REPO_ROOT / args.output_root / f"{utc_stamp()}-{args.mode}").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    status_path = output_dir / "status.json"

    status: dict[str, Any] = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "started",
        "mode": args.mode,
        "output_dir": str(output_dir),
        "privacy": {
            "synthetic_only": True,
            "case_data_used": False,
            "internet_used": False,
            "raw_prompt_echoed": False,
        },
        "steps": {},
    }
    write_json(status_path, status)

    if not args.skip_preflight:
        try:
            status["steps"]["backend_preflight"] = post_models_preflight(args.base_url, args.model, timeout=30)
        except Exception as exc:
            status["steps"]["backend_preflight"] = {
                "ok": False,
                "error": type(exc).__name__,
                "message": str(exc),
            }
        if not status["steps"]["backend_preflight"].get("ok"):
            status["status"] = "blocked"
            status["blocker"] = "llama.cpp backend preflight failed"
            write_json(status_path, status)
            print(json.dumps({"status": status["status"], "blocker": status["blocker"], "status_path": str(status_path)}))
            return 1

    opencode_path = shutil.which(args.opencode_command)
    status["steps"]["opencode_available"] = {"ok": bool(opencode_path), "command": args.opencode_command}
    if not opencode_path:
        status["status"] = "blocked"
        status["blocker"] = "OpenCode command not found on PATH"
        write_json(status_path, status)
        print(json.dumps({"status": status["status"], "blocker": status["blocker"], "status_path": str(status_path)}))
        return 1

    (output_dir / "forensic-platform-profiler.md").write_text(platform_profiler_prompt(), encoding="utf-8")
    if args.mode == "one-delegation-examiner-profiler":
        (output_dir / "synthetic-one-delegation-examiner.md").write_text(one_delegation_prompt(), encoding="utf-8")
    write_json(output_dir / "opencode.json", build_config(args.mode, args.base_url, args.model))

    agent = "forensic-platform-profiler" if args.mode == "isolated-platform-profiler" else "synthetic-one-delegation-examiner"
    message = (
        "Synthetic fixture only. Runner OS: Linux WSL-like OpenCode host. Evidence source: dead-box forensic image "
        "representing Windows endpoint workstations. No files, no paths, no credentials, no internet. "
        "Do not mention image format names or extensions."
    )
    if args.mode == "one-delegation-examiner-profiler":
        message = (
            "Run the synthetic one-delegation forensic harness probe now. Keep it local, synthetic-only, and stop "
            "after the one platform-profiler helper result. " + message
        )
    command = [
        opencode_path,
        "run",
        "--format",
        "json",
        "--agent",
        agent,
        "--model",
        f"llamacpp-local/{args.model}",
        "--title",
        f"synthetic {args.mode}",
        message,
    ]
    status["steps"]["opencode_plan"] = {
        "ok": True,
        "agent": agent,
        "command_shape": [
            "opencode",
            "run",
            "--format",
            "json",
            "--agent",
            agent,
            "--model",
            f"llamacpp-local/{args.model}",
            "<synthetic-message>",
        ],
    }
    write_json(status_path, status)

    stdout_path = output_dir / "stdout.jsonl"
    stderr_path = output_dir / "stderr.txt"
    try:
        with stdout_path.open("w", encoding="utf-8", errors="replace") as stdout, stderr_path.open(
            "w", encoding="utf-8", errors="replace"
        ) as stderr:
            completed = subprocess.run(
                command,
                cwd=str(output_dir),
                stdout=stdout,
                stderr=stderr,
                text=True,
                timeout=args.timeout,
                check=False,
            )
        status["steps"]["opencode_run"] = {"ok": completed.returncode == 0, "exit_code": completed.returncode}
    except subprocess.TimeoutExpired:
        status["steps"]["opencode_run"] = {"ok": False, "exit_code": 124, "error": "TimeoutExpired"}

    analysis = analyze_output(output_dir)
    status["steps"]["analysis"] = analysis
    leaks_present = any(analysis["leak_flags"].values())
    run_ok = bool(status["steps"]["opencode_run"].get("ok"))
    if not run_ok:
        status["status"] = "blocked"
        status["blocker"] = "OpenCode probe failed or timed out"
    elif leaks_present:
        status["status"] = "needs_harness_adjustment"
        status["blocker"] = "synthetic probe output failed leak checks"
    elif args.mode == "one-delegation-examiner-profiler" and analysis["task_mention_count"] == 0:
        status["status"] = "needs_harness_adjustment"
        status["blocker"] = "no task delegation was visible in OpenCode JSON events"
    else:
        status["status"] = "ok"

    write_json(status_path, status)
    print(json.dumps({"status": status["status"], "status_path": str(status_path)}))
    return 0 if status["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
