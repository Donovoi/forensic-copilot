#!/usr/bin/env python3
"""Run bounded, evidence-safe string and pattern analysis jobs.

The orchestrator never invokes a shell and never launches an evidence file. It
supports static FLOSS PE decoding, bstrings extraction/search, and ripgrep
searches over approved trees or previously extracted string files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterable

if os.name != "nt":
    import pty


SCHEMA_VERSION = 1
TOOLS = {"floss", "bstrings", "rg"}
JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
FINAL_NAME = "pattern-analysis.provenance.json"


class PatternError(RuntimeError):
    """Raised for a safety, configuration, or execution contract violation."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def file_sha256(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def require_within(path: Path, roots: Iterable[Path], description: str) -> None:
    if not any(is_relative_to(path, root) for root in roots):
        raise PatternError(f"{description} is outside every approved read root: {path}")


def resolve_tool(value: str, tool: str) -> Path:
    candidate: str | None
    if Path(value).is_absolute() or any(
        separator in value for separator in ("/", "\\")
    ):
        candidate = str(Path(value).expanduser().resolve(strict=True))
    else:
        candidate = shutil.which(value)
    if not candidate:
        raise PatternError(f"{tool} executable was not found: {value}")
    path = Path(candidate).resolve(strict=True)
    if not path.is_file():
        raise PatternError(f"{tool} executable is not a file: {path}")
    return path


def probe_version(executable: Path, tool: str) -> dict[str, Any]:
    arguments = [str(executable), "--version"]
    try:
        result = subprocess.run(
            arguments,
            capture_output=True,
            check=False,
            timeout=15,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"command": arguments, "error": str(exc), "version": None}
    output = (result.stdout + result.stderr)[:65536].decode("utf-8", errors="replace")
    return {
        "command": arguments,
        "exit_code": result.returncode,
        "output_truncated": len(result.stdout) + len(result.stderr) > 65536,
        "version": output.strip() or None,
    }


def validate_pe(path: Path) -> None:
    if path.stat().st_size < 64:
        raise PatternError(f"FLOSS target is too small to be a PE file: {path}")
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise PatternError(f"FLOSS target has no DOS MZ signature: {path}")
        stream.seek(0x3C)
        pe_offset = int.from_bytes(stream.read(4), "little")
        if pe_offset < 64 or pe_offset > path.stat().st_size - 4:
            raise PatternError(f"FLOSS target has an invalid PE header offset: {path}")
        stream.seek(pe_offset)
        if stream.read(4) != b"PE\x00\x00":
            raise PatternError(f"FLOSS target has no PE signature: {path}")


def validate_patterns(job: dict[str, Any], required: bool) -> list[str]:
    raw_patterns = job.get("patterns", [])
    if not isinstance(raw_patterns, list) or any(
        not isinstance(pattern, str) for pattern in raw_patterns
    ):
        raise PatternError("job patterns must be a list of strings")
    if required and not raw_patterns:
        raise PatternError("fixed and regex jobs require at least one pattern")
    if len(raw_patterns) > 1_000:
        raise PatternError("a job cannot contain more than 1,000 patterns")
    for pattern in raw_patterns:
        if not pattern or len(pattern.encode("utf-8")) > 16_384:
            raise PatternError("patterns must be non-empty and no larger than 16 KiB")
        if "\x00" in pattern:
            raise PatternError("patterns cannot contain NUL bytes")
    return raw_patterns


def write_patterns(path: Path, patterns: list[str]) -> dict[str, Any]:
    content = "".join(f"{pattern}\n" for pattern in patterns).encode("utf-8")
    path.write_bytes(content)
    return {
        "count": len(patterns),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }


def target_provenance(
    target: Path, job: dict[str, Any], read_roots: list[Path]
) -> dict[str, Any]:
    if target.is_file():
        return {
            "kind": "file",
            "path": str(target),
            "size_bytes": target.stat().st_size,
            "sha256": file_sha256(target),
        }
    record: dict[str, Any] = {
        "kind": "directory",
        "path": str(target),
        "sha256": None,
        "limitation": (
            "Directory content is not implicitly hashed. Bind a pre-existing "
            "manifest with target_manifest when exact tree provenance is required."
        ),
    }
    manifest_value = job.get("target_manifest")
    if manifest_value:
        manifest_path = Path(manifest_value).expanduser().resolve(strict=True)
        require_within(manifest_path, read_roots, "target manifest")
        if not manifest_path.is_file():
            raise PatternError(f"target manifest is not a file: {manifest_path}")
        record["target_manifest"] = {
            "path": str(manifest_path),
            "size_bytes": manifest_path.stat().st_size,
            "sha256": file_sha256(manifest_path),
        }
    return record


def build_command(
    job: dict[str, Any],
    executable: Path,
    target: Path,
    pattern_path: Path | None,
) -> list[str]:
    tool = job["tool"]
    mode = job["mode"]
    if tool == "floss":
        command = [
            str(executable),
            "-j",
            "--disable-progress",
            "--only",
            "stack",
            "tight",
            "decoded",
        ]
        if target.stat().st_size > 100 * 1024 * 1024:
            if not job.get("allow_large_file", False):
                raise PatternError(
                    "FLOSS target exceeds 100 MiB; set allow_large_file only after "
                    "reviewing the resource and time impact"
                )
            command.append("--large-file")
        command.extend(["--", str(target)])
        return command

    if tool == "bstrings":
        minimum = int(job.get("minimum_length", 4))
        maximum = int(job.get("maximum_length", 4096))
        if minimum < 3 or maximum < minimum or maximum > 1_048_576:
            raise PatternError("invalid bstrings minimum_length/maximum_length")
        command = [
            str(executable),
            "-f",
            str(target),
            "-a",
            "-u",
            "-m",
            str(minimum),
            "-x",
            str(maximum),
            "--off",
            "-q",
        ]
        if mode == "fixed":
            command.extend(["--fs", str(pattern_path)])
        elif mode == "regex":
            command.extend(["--fr", str(pattern_path)])
        return command

    target_kind = job.get("target_kind", "tree")
    if target_kind not in {"tree", "extracted_strings"}:
        raise PatternError("rg target_kind must be tree or extracted_strings")
    command = [
        str(executable),
        "--no-config",
        "--color",
        "never",
        "--with-filename",
        "--line-number",
        "--byte-offset",
        "--hidden",
        "--no-ignore",
        "--no-follow",
        "--no-mmap",
        "--max-columns",
        str(int(job.get("maximum_columns", 4096))),
        "--max-columns-preview",
    ]
    command.append("--binary" if target_kind == "tree" else "--text")
    if mode == "fixed":
        command.append("--fixed-strings")
    command.extend(["--file", str(pattern_path), "--", str(target)])
    return command


class OutputBudget:
    """Thread-safe combined stdout/stderr byte and line budget."""

    def __init__(self, maximum_bytes: int, maximum_lines: int):
        self.maximum_bytes = maximum_bytes
        self.maximum_lines = maximum_lines
        self.bytes_written = 0
        self.lines_written = 0
        self.truncated = False
        self.limit_reason: str | None = None
        self.lock = threading.Lock()
        self.stop = threading.Event()

    def bounded(self, data: bytes) -> bytes:
        with self.lock:
            if self.stop.is_set():
                return b""
            byte_remaining = self.maximum_bytes - self.bytes_written
            line_remaining = self.maximum_lines - self.lines_written
            if byte_remaining <= 0:
                self.truncated = True
                self.limit_reason = "maximum_output_bytes"
                self.stop.set()
                return b""

            bounded = data[:byte_remaining]
            if line_remaining <= 0:
                bounded = b""
            elif bounded.count(b"\n") > line_remaining:
                newline_index = -1
                search_from = 0
                for _ in range(line_remaining):
                    newline_index = bounded.find(b"\n", search_from)
                    if newline_index < 0:
                        break
                    search_from = newline_index + 1
                if newline_index >= 0:
                    bounded = bounded[: newline_index + 1]

            self.bytes_written += len(bounded)
            self.lines_written += bounded.count(b"\n")
            if len(bounded) < len(data):
                self.truncated = True
                self.limit_reason = (
                    "maximum_output_lines"
                    if self.lines_written >= self.maximum_lines
                    else "maximum_output_bytes"
                )
                self.stop.set()
            return bounded


def copy_pipe(pipe: BinaryIO, destination: BinaryIO, budget: OutputBudget) -> None:
    try:
        while data := pipe.read(65536):
            bounded = budget.bounded(data)
            if bounded:
                destination.write(bounded)
                destination.flush()
            if budget.stop.is_set():
                break
    finally:
        pipe.close()


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_bounded(
    command: list[str],
    stdout_path: Path,
    stderr_path: Path,
    working_directory: Path,
    timeout_seconds: int,
    maximum_bytes: int,
    maximum_lines: int,
    tty_stdin: bool = False,
) -> dict[str, Any]:
    budget = OutputBudget(maximum_bytes, maximum_lines)
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(working_directory),
            "TMPDIR": str(working_directory),
            "TEMP": str(working_directory),
            "TMP": str(working_directory),
            "NO_COLOR": "1",
        }
    )
    started = time.monotonic()
    timed_out = False
    pty_master: int | None = None
    pty_slave: int | None = None
    try:
        stdin: int | None = subprocess.DEVNULL
        if tty_stdin:
            if os.name == "nt":
                if not sys.stdin.isatty():
                    raise PatternError(
                        "bstrings requires an interactive Windows console because "
                        "the current upstream build refuses file mode when standard "
                        "input is redirected"
                    )
                stdin = None
            else:
                pty_master, pty_slave = pty.openpty()
                stdin = pty_slave

        with (
            stdout_path.open("wb") as stdout_stream,
            stderr_path.open("wb") as stderr_stream,
        ):
            process = subprocess.Popen(
                command,
                cwd=working_directory,
                env=environment,
                shell=False,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if pty_slave is not None:
                os.close(pty_slave)
                pty_slave = None
            assert process.stdout is not None and process.stderr is not None
            threads = [
                threading.Thread(
                    target=copy_pipe,
                    args=(process.stdout, stdout_stream, budget),
                    daemon=True,
                ),
                threading.Thread(
                    target=copy_pipe,
                    args=(process.stderr, stderr_stream, budget),
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()
            deadline = started + timeout_seconds
            while process.poll() is None:
                if budget.stop.is_set():
                    terminate_process(process)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    terminate_process(process)
                    break
                time.sleep(0.05)
            for thread in threads:
                thread.join(timeout=5)
            exit_code = process.returncode
    finally:
        for descriptor in (pty_slave, pty_master):
            if descriptor is not None:
                os.close(descriptor)

    return {
        "exit_code": exit_code,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "timed_out": timed_out,
        "truncated": budget.truncated,
        "limit_reason": budget.limit_reason,
        "captured_bytes": budget.bytes_written,
        "captured_lines": budget.lines_written,
    }


def classify_execution(tool: str, execution: dict[str, Any]) -> tuple[str, list[str]]:
    """Classify a bounded tool run without treating an intentional cap as a crash."""
    accepted_exit_codes = {0, 1} if tool == "rg" else {0}
    limitations: list[str] = []
    if execution["timed_out"]:
        return "failed", ["tool timeout terminated the job"]
    if execution["truncated"]:
        return (
            "completed_with_limit",
            [
                f"captured output reached {execution['limit_reason']}; "
                "the tool was terminated and results are incomplete"
            ],
        )
    if execution["exit_code"] not in accepted_exit_codes:
        return "failed", [f"tool returned exit code {execution['exit_code']}"]
    if tool == "rg" and execution["exit_code"] == 1:
        limitations.append("ripgrep completed with no matches")
    return "completed", limitations


def load_jobs(
    manifest_path: Path, read_roots: list[Path], output_root: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    require_within(manifest_path, read_roots, "manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PatternError(f"cannot read manifest: {exc}") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != SCHEMA_VERSION
    ):
        raise PatternError(f"manifest schema_version must be {SCHEMA_VERSION}")
    jobs = manifest.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        raise PatternError("manifest jobs must be a non-empty list")

    seen_ids: set[str] = set()
    validated = []
    for index, raw_job in enumerate(jobs):
        if not isinstance(raw_job, dict):
            raise PatternError(f"job {index} is not an object")
        job = dict(raw_job)
        job_id = job.get("id")
        if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
            raise PatternError(f"job {index} has an invalid id")
        if job_id in seen_ids:
            raise PatternError(f"duplicate job id: {job_id}")
        seen_ids.add(job_id)
        tool = job.get("tool")
        if tool not in TOOLS:
            raise PatternError(f"job {job_id} tool must be one of {sorted(TOOLS)}")
        allowed_modes = (
            {"decoded"} if tool == "floss" else {"baseline", "fixed", "regex"}
        )
        mode = job.get("mode")
        if mode not in allowed_modes:
            raise PatternError(
                f"job {job_id} mode must be one of {sorted(allowed_modes)}"
            )
        target_value = job.get("target")
        if not isinstance(target_value, str) or not target_value:
            raise PatternError(f"job {job_id} has no target")
        target = Path(target_value).expanduser().resolve(strict=True)
        require_within(target, read_roots, f"job {job_id} target")
        if is_relative_to(target, output_root):
            raise PatternError(f"job {job_id} target is inside the output root")
        if tool in {"floss", "bstrings"} and not target.is_file():
            raise PatternError(f"job {job_id} requires a regular-file target")
        if tool == "rg" and not (target.is_file() or target.is_dir()):
            raise PatternError(f"job {job_id} target must be a file or directory")
        if tool == "floss":
            validate_pe(target)
        patterns = validate_patterns(job, mode in {"fixed", "regex"})
        job["target_path"] = target
        job["patterns_validated"] = patterns
        validated.append(job)
    return manifest, validated


def analyze(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).expanduser().resolve(strict=True)
    read_roots = [
        Path(value).expanduser().resolve(strict=True) for value in args.allow_read_root
    ]
    output_root = Path(args.output_dir).expanduser().resolve(strict=False)
    for root in read_roots:
        if not root.is_dir():
            raise PatternError(f"approved read root is not a directory: {root}")
        if is_relative_to(output_root, root) or is_relative_to(root, output_root):
            raise PatternError(
                f"output root and approved read root overlap: {output_root} / {root}"
            )
    output_root.mkdir(parents=True, exist_ok=True)
    output_root = output_root.resolve(strict=True)
    final_path = output_root / FINAL_NAME
    if final_path.exists() and not args.force:
        raise PatternError(f"refusing to replace {final_path} without --force")

    manifest, jobs = load_jobs(manifest_path, read_roots, output_root)
    requested_tools = sorted({job["tool"] for job in jobs})
    tool_values = {
        "floss": args.floss,
        "bstrings": args.bstrings,
        "rg": args.rg,
    }
    executables: dict[str, Path] = {}
    versions: dict[str, dict[str, Any]] = {}
    if not args.dry_run:
        for tool in requested_tools:
            executables[tool] = resolve_tool(tool_values[tool], tool)
            versions[tool] = probe_version(executables[tool], tool)

    results = []
    overall_failed = False
    temporary_root = Path(
        tempfile.mkdtemp(prefix=".pattern-analysis-", dir=output_root)
    )
    try:
        for job in jobs:
            job_id = job["id"]
            tool = job["tool"]
            target = job["target_path"]
            job_temp = temporary_root / job_id
            job_temp.mkdir()
            patterns = job["patterns_validated"]
            pattern_record = None
            pattern_path = None
            if patterns:
                pattern_path = job_temp / "patterns.txt"
                pattern_record = write_patterns(pattern_path, patterns)

            maximum_bytes = min(
                args.maximum_output_bytes,
                int(job.get("maximum_output_bytes", args.maximum_output_bytes)),
            )
            maximum_lines = min(
                args.maximum_output_lines,
                int(job.get("maximum_output_lines", args.maximum_output_lines)),
            )
            timeout_seconds = min(
                args.timeout_seconds,
                int(job.get("timeout_seconds", args.timeout_seconds)),
            )
            if min(maximum_bytes, maximum_lines, timeout_seconds) < 1:
                raise PatternError(f"job {job_id} has a non-positive execution bound")

            target_record = target_provenance(target, job, read_roots)
            result: dict[str, Any] = {
                "id": job_id,
                "tool": tool,
                "mode": job["mode"],
                "target": target_record,
                "patterns": pattern_record,
                "bounds": {
                    "maximum_output_bytes": maximum_bytes,
                    "maximum_output_lines": maximum_lines,
                    "timeout_seconds": timeout_seconds,
                },
            }
            if args.dry_run:
                result["status"] = "planned"
                results.append(result)
                continue

            command = build_command(job, executables[tool], target, pattern_path)
            suffix = "json" if tool == "floss" else "txt"
            stdout_partial = output_root / f".{job_id}.stdout.{suffix}.partial"
            stderr_partial = output_root / f".{job_id}.stderr.txt.partial"
            execution = run_bounded(
                command,
                stdout_partial,
                stderr_partial,
                job_temp,
                timeout_seconds,
                maximum_bytes,
                maximum_lines,
                tty_stdin=tool == "bstrings",
            )
            stdout_path = output_root / f"{job_id}.stdout.{suffix}"
            stderr_path = output_root / f"{job_id}.stderr.txt"
            if final_path.exists():
                # Fail closed immediately before replacing the first per-job
                # output.  A later failure then cannot leave stale provenance
                # apparently authenticating a mix of old and new files.
                final_path.unlink()
            os.replace(stdout_partial, stdout_path)
            os.replace(stderr_partial, stderr_path)

            status, limitations = classify_execution(tool, execution)
            if status != "completed":
                overall_failed = True
            result.update(
                {
                    "status": status,
                    "command": command,
                    "execution": execution,
                    "limitations": limitations,
                    "outputs": [
                        {
                            "kind": "stdout",
                            "path": str(stdout_path),
                            "size_bytes": stdout_path.stat().st_size,
                            "sha256": file_sha256(stdout_path),
                        },
                        {
                            "kind": "stderr",
                            "path": str(stderr_path),
                            "size_bytes": stderr_path.stat().st_size,
                            "sha256": file_sha256(stderr_path),
                        },
                    ],
                }
            )
            results.append(result)

        provenance = {
            "schema_version": SCHEMA_VERSION,
            "created_utc": utc_now(),
            "manifest": {
                "path": str(manifest_path),
                "size_bytes": manifest_path.stat().st_size,
                "sha256": file_sha256(manifest_path),
            },
            "safety": {
                "approved_read_roots": [str(root) for root in read_roots],
                "output_root": str(output_root),
                "shell_used": False,
                "evidence_executed": False,
                "static_tooling_only": True,
                "output_caps_enforced": True,
            },
            "tools": {
                tool: {
                    "executable": str(executables[tool]),
                    "version_probe": versions[tool],
                }
                for tool in requested_tools
                if tool in executables
            },
            "dry_run": args.dry_run,
            "jobs": results,
            "runtime": {
                "program": "run_pattern_analysis.py",
                "python": sys.version.split()[0],
            },
        }
        partial = output_root / f".{FINAL_NAME}.partial"
        partial.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if final_path.exists():
            final_path.unlink()
        os.replace(partial, final_path)
        print(
            json.dumps(
                {
                    "jobs": len(results),
                    "failed_or_limited": sum(
                        result["status"] not in {"completed", "planned"}
                        for result in results
                    ),
                    "output": str(final_path),
                },
                sort_keys=True,
            )
        )
        return 2 if overall_failed else 0
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
        for partial in output_root.glob(".*.partial"):
            if partial.is_file() and (
                partial.name.startswith(".pattern-analysis")
                or ".stdout." in partial.name
                or ".stderr." in partial.name
            ):
                partial.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded FLOSS, bstrings, and ripgrep static analysis jobs"
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--allow-read-root", action="append", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--floss", default="floss")
    parser.add_argument("--bstrings", default="bstrings")
    parser.add_argument("--rg", default="rg")
    parser.add_argument("--maximum-output-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--maximum-output-lines", type=int, default=100_000)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if (
        min(
            args.maximum_output_bytes,
            args.maximum_output_lines,
            args.timeout_seconds,
        )
        < 1
    ):
        raise SystemExit("output and timeout bounds must be positive")
    try:
        return analyze(args)
    except (OSError, PatternError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
