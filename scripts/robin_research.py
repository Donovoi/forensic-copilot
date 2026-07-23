#!/usr/bin/env python3
"""Run the bounded tooling-research round through Donovoi's Robin fork."""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace


ROBIN_REPOSITORY = "https://github.com/Donovoi/robin.git"
ROBIN_REVISION = "001a84f43f79c073c25660f8364e4416ce03d358"
ROBIN_AGENT = "robin-forensic-researcher"
DEFAULT_MODEL = "openai/gpt-5.5"
DEFAULT_VARIANT = "xhigh"
MAX_RESEARCH_LINES = 7

RESEARCH_INSTRUCTIONS = """You are Robin's research-only DFIR tooling specialist.
Research the supplied forensic tooling question; do not collect or inspect evidence.
Check current official manuals, vendor documentation, maintained upstream repositories,
and release notes before recommending commands or automation. Prefer the configured
SearXNG endpoint with at most three results, then verify important claims against
primary sources. Do not use generic web search. If current sources are unavailable,
return BLOCKED or label an offline source basis with its review-date limit. Separate
recommended, deferred, and rejected tools; include direct source URLs, caveats, and
confidence. Return at most seven non-empty plain-text lines and no preamble."""

ATTRIBUTION_RESEARCH_INSTRUCTIONS = """You are Robin's research-only forensic
attribution specialist. The examiner has authorized public-source lookup of the
minimum identifiers in the supplied question. Use the configured SearXNG endpoint
with at most three results, then verify important claims against public first-party
or authoritative sources. Do not use breach data, paid people-search services,
private accounts, credentials, contact with any person, or access-controlled data.
Distinguish observed account identity, device owner/custodian, hosting subscriber,
operator, and network provider. Preserve contradictions and alternative explanations.
Return direct URLs, access limitations, and calibrated confidence; never upgrade a
name or email match into legal ownership without independent corroboration. Return at
most seven non-empty plain-text lines and no preamble."""


class RobinResearchError(RuntimeError):
    """A safe, user-facing Robin research failure."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_robin_root() -> Path:
    configured = os.getenv("FORENSIC_ROBIN_ROOT")
    if configured:
        return Path(configured).expanduser()
    return repository_root() / "toolcache" / "robin"


def run_git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown git error"
        raise RobinResearchError(f"Robin checkout verification failed: {detail}")
    return result.stdout.strip()


def normalized_repository_url(value: str) -> str:
    normalized = value.strip().lower().removesuffix(".git").rstrip("/")
    if normalized.startswith("git@github.com:"):
        normalized = "https://github.com/" + normalized.removeprefix("git@github.com:")
    return normalized


def verify_robin_checkout(
    root: Path, expected_revision: str = ROBIN_REVISION
) -> dict[str, str]:
    root = root.expanduser().resolve()
    module_path = root / "robin" / "opencode_llm.py"
    if not module_path.is_file():
        raise RobinResearchError(f"Robin OpenCode adapter not found under {root}")

    remote = run_git(root, "remote", "get-url", "origin")
    if normalized_repository_url(remote) != normalized_repository_url(ROBIN_REPOSITORY):
        raise RobinResearchError(
            f"Robin origin must be {ROBIN_REPOSITORY}; found {remote}"
        )

    revision = run_git(root, "rev-parse", "HEAD")
    if revision.lower() != expected_revision.lower():
        raise RobinResearchError(
            f"Robin revision must be {expected_revision}; found {revision}"
        )

    return {
        "repository": ROBIN_REPOSITORY,
        "revision": revision,
        "module": str(module_path),
    }


def setup_robin_checkout(root: Path) -> dict[str, str]:
    root = root.expanduser().resolve()
    if root.exists():
        return verify_robin_checkout(root)

    root.parent.mkdir(parents=True, exist_ok=True)
    clone = subprocess.run(
        ["git", "clone", "--no-checkout", ROBIN_REPOSITORY, str(root)],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if clone.returncode != 0:
        detail = (
            clone.stderr.strip() or clone.stdout.strip() or "unknown git clone error"
        )
        raise RobinResearchError(f"Unable to clone Robin: {detail}")

    try:
        run_git(root, "fetch", "origin", ROBIN_REVISION)
        run_git(root, "checkout", "--detach", ROBIN_REVISION)
        return verify_robin_checkout(root)
    except Exception:
        raise RobinResearchError(
            f"Robin setup did not finish; inspect or remove the incomplete cache at {root}"
        ) from None


def load_robin_module(root: Path) -> ModuleType:
    module_path = root.expanduser().resolve() / "robin" / "opencode_llm.py"
    spec = importlib.util.spec_from_file_location(
        "forensic_copilot_robin_opencode", module_path
    )
    if not spec or not spec.loader:
        raise RobinResearchError(f"Unable to load Robin module at {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def research_instructions(mode: str) -> str:
    if mode == "tooling":
        return RESEARCH_INSTRUCTIONS
    if mode == "attribution":
        return ATTRIBUTION_RESEARCH_INSTRUCTIONS
    raise RobinResearchError(f"Unknown research mode: {mode}")


def build_opencode_config(mode: str = "tooling") -> dict[str, object]:
    instructions = research_instructions(mode)
    denied = {
        "*": "deny",
        "read": "deny",
        "list": "deny",
        "glob": "deny",
        "grep": "deny",
        "websearch": "deny",
        "todowrite": "deny",
        "task": "deny",
        "bash": "deny",
        "edit": "deny",
        "write": "deny",
    }
    return {
        "$schema": "https://opencode.ai/config.json",
        "default_agent": ROBIN_AGENT,
        "instructions": [],
        "agent": {
            ROBIN_AGENT: {
                "description": f"Robin-backed bounded DFIR {mode} researcher.",
                "mode": "primary",
                "steps": 10,
                "prompt": instructions,
                "permission": {**denied, "webfetch": "allow"},
            }
        },
    }


def validate_response(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise RobinResearchError("Robin returned an empty research note")
    if any(
        "MAXIMUM STEPS" in line.upper() and "REACHED" in line.upper() for line in lines
    ):
        raise RobinResearchError("Robin exhausted its bounded research steps")
    if len(lines) > MAX_RESEARCH_LINES:
        raise RobinResearchError(
            f"Robin returned {len(lines)} lines; the harness limit is {MAX_RESEARCH_LINES}"
        )
    return "\n".join(lines)


async def call_robin(
    args: argparse.Namespace, module: ModuleType, workdir: Path
) -> str:
    instructions = research_instructions(args.mode)
    client = module.OpenCodeLLMModel(
        model=args.model,
        variant=args.variant or None,
        command=args.opencode_command,
        agent=ROBIN_AGENT,
        cwd=workdir,
        timeout=args.timeout,
        agent_instructions=instructions,
        web_search_url=args.web_search_url,
    )
    response = await client.call_single(
        [SimpleNamespace(role="user", content=args.question.strip())]
    )
    return validate_response(response.text)


def run_research(args: argparse.Namespace) -> int:
    if not args.question.strip():
        raise RobinResearchError("Research question cannot be empty")
    if args.timeout <= 0:
        raise RobinResearchError("Timeout must be greater than zero")
    robin_root = Path(args.robin_root)
    provenance = verify_robin_checkout(robin_root)
    if (
        not shutil.which(args.opencode_command)
        and not Path(args.opencode_command).is_file()
    ):
        raise RobinResearchError(f"OpenCode command not found: {args.opencode_command}")

    module = load_robin_module(robin_root)
    with tempfile.TemporaryDirectory(prefix="forensic-robin-") as temporary:
        workdir = Path(temporary)
        (workdir / "opencode.json").write_text(
            json.dumps(build_opencode_config(args.mode), indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            result = asyncio.run(call_robin(args, module, workdir))
        except RuntimeError as error:
            raise RobinResearchError(f"Robin OpenCode call failed: {error}") from None

    revision = provenance["revision"][:12]
    print(
        f"ROBIN_BACKEND: Donovoi/robin@{revision} | {args.model} | "
        f"{ROBIN_AGENT} | mode={args.mode}"
    )
    print(result)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("run", "setup", "verify"),
        help="Set up, verify, or execute the pinned Robin research backend.",
    )
    parser.add_argument("--robin-root", default=str(default_robin_root()))
    parser.add_argument("--question", default="")
    parser.add_argument(
        "--mode",
        choices=("tooling", "attribution"),
        default="tooling",
        help="Constrained research policy to apply (default: tooling)",
    )
    parser.add_argument(
        "--model", default=os.getenv("ROBIN_RESEARCH_MODEL", DEFAULT_MODEL)
    )
    parser.add_argument(
        "--variant", default=os.getenv("ROBIN_RESEARCH_VARIANT", DEFAULT_VARIANT)
    )
    parser.add_argument(
        "--opencode-command", default=os.getenv("OPENCODE_COMMAND", "opencode")
    )
    parser.add_argument(
        "--web-search-url",
        default=os.getenv("ROBIN_WEB_SEARCH_URL") or os.getenv("SEARXNG_SEARCH_URL"),
    )
    parser.add_argument("--timeout", type=int, default=600)
    return parser


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    args = build_parser().parse_args()
    try:
        if args.command == "setup":
            details = setup_robin_checkout(Path(args.robin_root))
            print(f"Robin ready: {details['repository']}@{details['revision']}")
            return 0
        if args.command == "verify":
            details = verify_robin_checkout(Path(args.robin_root))
            print(f"Robin verified: {details['repository']}@{details['revision']}")
            return 0
        return run_research(args)
    except (OSError, subprocess.SubprocessError, RobinResearchError) as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
