#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def run_command(
    command: list[str],
    cwd: Path,
    timeout: int,
    stdout_path: Path,
    stderr_path: Path,
    command_record: list[str] | None = None,
) -> dict:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("w", encoding="utf-8", errors="replace") as stdout, stderr_path.open(
        "w", encoding="utf-8", errors="replace"
    ) as stderr:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            stdout=stdout,
            stderr=stderr,
            text=True,
            timeout=timeout,
            check=False,
        )
    return {
        "command": command_record if command_record is not None else command,
        "exit_code": completed.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "ok": completed.returncode == 0,
    }


def compare_output(report_path: Path, expected_path: Path | None) -> dict:
    if not expected_path:
        return {"status": "skipped", "reason": "no expected JSON supplied"}
    if not report_path.exists():
        return {"status": "blocked", "reason": "model report was not created", "report_path": str(report_path)}

    expected = json.loads(read_text(expected_path))
    text = read_text(report_path)
    failures: list[dict[str, str]] = []
    for item in expected.get("required_substrings", []):
        if item not in text:
            failures.append({"type": "missing_substring", "value": item})
    for item in expected.get("forbidden_substrings", []):
        if item in text:
            failures.append({"type": "forbidden_substring_present", "value": item})

    return {
        "status": "ok" if not failures else "failed",
        "report_path": str(report_path),
        "expected_path": str(expected_path),
        "failures": failures,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a local OpenCode/Gemma forensic investigation regression.")
    parser.add_argument("--base-url", default=os.environ.get("LLAMACPP_BASE_URL", "http://localhost:8080"))
    parser.add_argument("--model", default=os.environ.get("LLAMACPP_MODEL", "gemma-heretic-bf16"))
    parser.add_argument("--opencode-model", default="llamacpp-local/gemma-heretic-bf16")
    parser.add_argument("--opencode-command", default="opencode")
    parser.add_argument("--prompt-file", required=True)
    parser.add_argument("--expected-json", default="")
    parser.add_argument("--output-root", default="reports/local-model-evals")
    parser.add_argument("--report-path", default="")
    parser.add_argument("--title", default="Local Gemma investigation regression")
    parser.add_argument("--skip-smoke", action="store_true")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    output_dir = (REPO_ROOT / args.output_root / utc_stamp()).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    status_path = output_dir / "status.json"
    prompt_path = Path(args.prompt_file).expanduser().resolve()
    expected_path = Path(args.expected_json).expanduser().resolve() if args.expected_json else None
    report_path = Path(args.report_path).expanduser().resolve() if args.report_path else output_dir / "gemma-report.md"

    status: dict[str, Any] = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "started",
        "output_dir": str(output_dir),
        "privacy": {
            "case_facts_to_internet": False,
            "raw_prompt_echoed": False,
            "case_output_local_only": True,
        },
        "steps": {},
    }
    write_json(status_path, status)

    preflight_command = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "check_opencode_llamacpp_backend.py"),
        "--base-url",
        args.base_url,
        "--model",
        args.model,
    ]
    if not args.skip_smoke:
        preflight_command.extend(["--smoke-tool-call", "--smoke-max-tokens", "2048"])

    preflight = run_command(
        preflight_command,
        cwd=REPO_ROOT,
        timeout=min(args.timeout, 1800),
        stdout_path=output_dir / "preflight.stdout.txt",
        stderr_path=output_dir / "preflight.stderr.txt",
    )
    status["steps"]["backend_preflight"] = preflight
    if not preflight["ok"]:
        status["status"] = "blocked"
        status["blocker"] = "llama.cpp backend preflight failed"
        write_json(status_path, status)
        print(json.dumps({"status": status["status"], "blocker": status["blocker"], "status_path": str(status_path)}))
        return 1

    opencode_path = shutil.which(args.opencode_command)
    status["steps"]["opencode_available"] = {
        "ok": bool(opencode_path),
        "command": args.opencode_command,
        "resolved": opencode_path,
    }
    if not opencode_path:
        status["status"] = "blocked"
        status["blocker"] = "OpenCode command not found on PATH"
        write_json(status_path, status)
        print(json.dumps({"status": status["status"], "blocker": status["blocker"], "status_path": str(status_path)}))
        return 1

    prompt_text = read_text(prompt_path)
    task_prompt = (
        f"{prompt_text.rstrip()}\n\n"
        "Write the final local regression report to this exact path:\n"
        f"{report_path}\n"
        "Do not include raw case identifiers, credentials, evidence filenames, recovered filenames, "
        "or case-sensitive paths in the report.\n"
    )
    runtime_prompt_path = output_dir / "prompt.local.txt"
    runtime_prompt_path.write_text(task_prompt, encoding="utf-8")
    opencode_command = [
        opencode_path,
        "run",
        "--agent",
        "forensic-examiner",
        "--model",
        args.opencode_model,
        "--title",
        args.title,
        "Use the attached local prompt file for the investigation regression. Keep all case material local.",
        "--file",
        str(runtime_prompt_path),
    ]
    opencode_command_record = [
        opencode_path,
        "run",
        "--agent",
        "forensic-examiner",
        "--model",
        args.opencode_model,
        "--title",
        args.title,
        "<generic-local-regression-message>",
        "--file",
        str(runtime_prompt_path),
    ]
    status["steps"]["opencode_plan"] = {
        "ok": True,
        "report_path": str(report_path),
        "prompt_path": str(prompt_path),
        "runtime_prompt_path": str(runtime_prompt_path),
        "opencode_model": args.opencode_model,
        "command_preview": opencode_command_record,
    }
    if args.dry_run:
        status["status"] = "dry_run"
        write_json(status_path, status)
        print(json.dumps({"status": status["status"], "status_path": str(status_path)}))
        return 0

    run = run_command(
        opencode_command,
        cwd=REPO_ROOT,
        timeout=args.timeout,
        stdout_path=output_dir / "opencode.stdout.txt",
        stderr_path=output_dir / "opencode.stderr.txt",
        command_record=opencode_command_record,
    )
    status["steps"]["opencode_run"] = run
    if not run["ok"]:
        status["status"] = "blocked"
        status["blocker"] = "OpenCode run failed"
        write_json(status_path, status)
        print(json.dumps({"status": status["status"], "blocker": status["blocker"], "status_path": str(status_path)}))
        return 1

    comparison = compare_output(report_path, expected_path)
    status["steps"]["comparison"] = comparison
    status["status"] = "ok" if comparison["status"] in ("ok", "skipped") else "needs_harness_adjustment"
    write_json(status_path, status)
    print(json.dumps({"status": status["status"], "status_path": str(status_path)}))
    return 0 if status["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
