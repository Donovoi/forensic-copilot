#!/usr/bin/env python3
"""Preservation-first orchestration for paired VM disk and memory evidence."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


STATE_NAME = "case.json"
CHUNK_SIZE = 16 * 1024 * 1024
SHA256_RE = re.compile(r"(?i)(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
DEFAULT_VOLATILITY_IMAGE = "forensic-copilot/volatility:2.28.0"
DEFAULT_TSK_IMAGE = "forensic-copilot/tsk:ubuntu24.04"
DEFAULT_MEMORY_PLUGINS = (
    "windows.info",
    "windows.pslist",
    "windows.psscan",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
    "windows.svcscan",
    "windows.sessions",
    "windows.getsids",
    "windows.modules",
    "windows.driverscan",
    "windows.malfind",
    "windows.handles",
    "windows.filescan",
    "windows.registry.hivelist",
)


class CaseError(RuntimeError):
    """Raised for a safe, user-actionable case workflow failure."""


class DigestingReader:
    """Read-only wrapper that hashes exactly the compressed bytes consumed."""

    def __init__(self, stream: Any, digest: Any):
        self.stream = stream
        self.digest = digest
        self.name = getattr(stream, "name", "")
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        data = self.stream.read(size)
        self.digest.update(data)
        self.bytes_read += len(data)
        return data


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def safe_name(value: str) -> str:
    normalized = SAFE_NAME_RE.sub("-", value.strip()).strip("-._")
    if not normalized:
        raise CaseError(f"Value cannot be converted to a safe case name: {value!r}")
    return normalized


def resolved(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def validate_boundaries(evidence_root: Path, case_root: Path) -> None:
    if not evidence_root.is_dir():
        raise CaseError(f"Evidence root is not a directory: {evidence_root}")
    if paths_overlap(evidence_root, case_root):
        raise CaseError(
            "Evidence and case roots must not overlap; use a separate output/staging directory"
        )


def evidence_file(path: Path, evidence_root: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise CaseError(f"Evidence symlinks are refused because they can cross scope: {path}")
    if not path.is_file():
        raise CaseError(f"Evidence item is not a regular file: {path}")
    stat = path.stat()
    return {
        "name": path.name,
        "relative_path": path.relative_to(evidence_root).as_posix(),
        "size_bytes": stat.st_size,
        "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def validated_evidence_path(
    evidence_root: Path, record: dict[str, Any]
) -> tuple[Path, os.stat_result]:
    """Recheck a recorded evidence path before each read."""
    relative = Path(record["relative_path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise CaseError(f"Unsafe recorded evidence path: {record['relative_path']}")
    candidate = evidence_root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise CaseError(f"Evidence path now contains a symlink: {candidate}")
    try:
        resolved_candidate = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise CaseError(f"Recorded evidence file is missing: {candidate}") from exc
    if evidence_root != resolved_candidate and evidence_root not in resolved_candidate.parents:
        raise CaseError(f"Recorded evidence path escaped its root: {candidate}")
    if not resolved_candidate.is_file():
        raise CaseError(f"Recorded evidence item is not a regular file: {candidate}")
    return resolved_candidate, resolved_candidate.stat()


def discover_pairs(evidence_root: Path) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []
    case_keys: set[str] = set()
    for directory in sorted(path for path in evidence_root.iterdir() if path.is_dir()):
        if directory.is_symlink():
            raise CaseError(f"Evidence directory symlinks are refused: {directory}")
        disks = sorted(directory.glob("*.img.gz"))
        dumps = sorted(directory.glob("*.dump"))
        manifests = sorted(
            path for path in directory.iterdir() if path.is_file() and "hash" in path.name.lower()
        )
        if not disks and not dumps:
            continue
        if len(disks) != 1 or len(dumps) != 1:
            raise CaseError(
                f"Expected exactly one .img.gz and one .dump in {directory}; "
                f"found {len(disks)} disk image(s) and {len(dumps)} dump(s)"
            )
        case_key = safe_name(directory.name)
        if case_key in case_keys:
            raise CaseError(
                f"Source names collide after safe-name normalization: {directory.name} -> {case_key}"
            )
        case_keys.add(case_key)
        pairs.append(
            {
                "source_name": directory.name,
                "case_key": case_key,
                "disk_gzip": evidence_file(disks[0], evidence_root),
                "memory_dump": evidence_file(dumps[0], evidence_root),
                "hash_manifests": [evidence_file(path, evidence_root) for path in manifests],
            }
        )
    if not pairs:
        raise CaseError(f"No paired .img.gz/.dump evidence directories found in {evidence_root}")
    return pairs


def report_stub(case_id: str, evidence_root: Path, case_root: Path, pairs: list[dict[str, Any]]) -> str:
    inventory = "\n".join(
        f"- `{pair['source_name']}`: `{pair['disk_gzip']['name']}` and "
        f"`{pair['memory_dump']['name']}`"
        for pair in pairs
    )
    return f"""# {case_id} forensic examination

## Executive summary

Examination initialized. Findings have not yet been peer reviewed.

## Findings

No findings recorded yet.

## Conclusions and confidence

Pending analysis.

## Scope and boundaries

- Input/read root: `{evidence_root}`
- Compute/staging and output root: `{case_root}`
- Evidence access mode: read-only file access; no evidence execution
- External sample or hash uploads: prohibited

## Evidence inventory

{inventory}

## Evidence handling and verification

Hash verification pending. Machine-readable state is stored in `{STATE_NAME}`.

## Examination environment and tools

Tool preparation pending.

## Timeline and correlations

Pending analysis.

## Limitations and unresolved questions

- Disk and memory acquisition times and guest clock offsets have not yet been corroborated.
- Guest operating-system versions and filesystem accessibility remain to be verified.
"""


def initialize_case(args: argparse.Namespace) -> int:
    evidence_root = resolved(args.evidence_root)
    case_root = resolved(args.case_root)
    validate_boundaries(evidence_root, case_root)
    state_path = case_root / STATE_NAME
    if state_path.exists() and not args.force:
        raise CaseError(f"Case already initialized: {state_path}")

    pairs = discover_pairs(evidence_root)
    case_root.mkdir(parents=True, exist_ok=True)
    for name in ("logs", "reports", "tool-cache", "tooling"):
        (case_root / name).mkdir(exist_ok=True)
    for pair in pairs:
        source_root = case_root / "sources" / pair["case_key"]
        for relative in ("disk/working", "disk/metadata", "memory", "timeline", "exports"):
            (source_root / relative).mkdir(parents=True, exist_ok=True)

    state = {
        "schema_version": 1,
        "case_id": safe_name(args.case_id),
        "created_utc": utc_now(),
        "updated_utc": utc_now(),
        "evidence_root": str(evidence_root),
        "case_root": str(case_root),
        "boundaries": {
            "input_read_root": str(evidence_root),
            "compute_staging_root": str(case_root),
            "output_report_export_root": str(case_root),
            "evidence_writes_allowed": False,
            "external_sample_or_hash_uploads_allowed": False,
        },
        "sources": pairs,
    }
    atomic_write_json(state_path, state)
    report_path = case_root / "reports" / f"{state['case_id']}.md"
    atomic_write_text(report_path, report_stub(state["case_id"], evidence_root, case_root, pairs))
    print(f"Initialized {state['case_id']} with {len(pairs)} paired source(s)")
    print(f"State: {state_path}")
    print(f"Report: {report_path}")
    return 0


def load_case(case_root_arg: str) -> tuple[Path, Path, dict[str, Any]]:
    case_root = resolved(case_root_arg)
    state_path = case_root / STATE_NAME
    if not state_path.is_file():
        raise CaseError(f"Case state not found: {state_path}")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    evidence_root = resolved(state["evidence_root"])
    recorded_case_root = resolved(state["case_root"])
    if recorded_case_root != case_root:
        raise CaseError(
            f"Case root moved or mismatched: state says {recorded_case_root}, command used {case_root}"
        )
    validate_boundaries(evidence_root, case_root)
    return case_root, evidence_root, state


def select_sources(state: dict[str, Any], requested: Iterable[str] | None) -> list[dict[str, Any]]:
    sources = state["sources"]
    names = set(requested or [])
    if not names:
        return sources
    selected = [
        source
        for source in sources
        if source["source_name"] in names or source["case_key"] in names
    ]
    missing = sorted(names - {item["source_name"] for item in selected} - {item["case_key"] for item in selected})
    if missing:
        raise CaseError(f"Unknown source selector(s): {', '.join(missing)}")
    return selected


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def hash_and_test_gzip_stream(path: Path, output_path: Path | None = None) -> dict[str, Any]:
    started = time.monotonic()
    uncompressed_bytes = 0
    digest = hashlib.sha256()
    raw_digest = hashlib.sha256() if output_path else None
    output_stream = None
    digesting_stream = None
    try:
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_stream = output_path.open("xb")
        with path.open("rb") as compressed_stream:
            digesting_stream = DigestingReader(compressed_stream, digest)
            with gzip.GzipFile(fileobj=digesting_stream, mode="rb") as stream:
                while chunk := stream.read(CHUNK_SIZE):
                    uncompressed_bytes += len(chunk)
                    if output_stream and raw_digest:
                        output_stream.write(chunk)
                        raw_digest.update(chunk)
        if output_stream:
            output_stream.flush()
            os.fsync(output_stream.fileno())
    except (EOFError, OSError) as exc:
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "sha256": digest.hexdigest(),
            "sha256_complete": False,
            "compressed_bytes_read": digesting_stream.bytes_read if digesting_stream else 0,
            "raw_sha256": raw_digest.hexdigest() if raw_digest else None,
            "uncompressed_bytes_read": uncompressed_bytes,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "implementation": "python-gzip-single-pass-sha256",
        }
    finally:
        if output_stream:
            output_stream.close()
    compressed_bytes_read = digesting_stream.bytes_read if digesting_stream else 0
    return {
        "ok": True,
        "error": None,
        "sha256": digest.hexdigest(),
        "sha256_complete": compressed_bytes_read == path.stat().st_size,
        "compressed_bytes_read": compressed_bytes_read,
        "raw_sha256": raw_digest.hexdigest() if raw_digest else None,
        "uncompressed_bytes_read": uncompressed_bytes,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "implementation": "python-gzip-single-pass-sha256",
    }


def parse_hash_manifest(path: Path) -> dict[str, str]:
    results: dict[str, str] = {}
    pending_filename: str | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = SHA256_RE.search(line)
        if not match:
            pending_filename = Path(line).name
            continue
        digest = match.group(1).lower()
        without_digest = (line[: match.start()] + " " + line[match.end() :]).strip(" *:\t")
        candidate = without_digest.removeprefix("sha256").strip(" *:\t")
        filename = Path(candidate).name if candidate else pending_filename
        if filename:
            results[filename] = digest
        pending_filename = None
    return results


def verify_case(args: argparse.Namespace) -> int:
    case_root, evidence_root, state = load_case(args.case_root)
    selected = select_sources(state, args.source)
    if args.skip_gzip_test and getattr(args, "prepare_working_disks", False):
        raise CaseError("--prepare-working-disks cannot be combined with --skip-gzip-test")
    overall_ok = True
    output: dict[str, Any] = {
        "started_utc": utc_now(),
        "algorithm": "SHA-256",
        "sources": [],
    }
    for source in selected:
        expected: dict[str, str] = {}
        manifest_records: list[dict[str, Any]] = []
        for manifest in source["hash_manifests"]:
            manifest_path, _ = validated_evidence_path(evidence_root, manifest)
            parsed = parse_hash_manifest(manifest_path)
            for filename, digest in parsed.items():
                prior = expected.get(filename)
                if prior and prior != digest:
                    raise CaseError(
                        f"Conflicting manifest hashes for {source['source_name']}/{filename}"
                    )
                expected[filename] = digest
            manifest_records.append(
                {
                    "relative_path": manifest["relative_path"],
                    "sha256": file_sha256(manifest_path),
                    "entries": parsed,
                }
            )

        source_result: dict[str, Any] = {
            "source_name": source["source_name"],
            "manifests": manifest_records,
            "items": [],
        }
        output["sources"].append(source_result)
        for role in ("disk_gzip", "memory_dump"):
            record = source[role]
            path, current_stat = validated_evidence_path(evidence_root, record)
            current_mtime = (
                datetime.fromtimestamp(current_stat.st_mtime, timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
            inventory_changed = (
                current_stat.st_size != record["size_bytes"] or current_mtime != record["mtime_utc"]
            )
            if inventory_changed:
                overall_ok = False
            action = "Hashing and validating" if role == "disk_gzip" and not args.skip_gzip_test else "Hashing"
            print(f"{action} {source['source_name']}/{record['name']} ({record['size_bytes']} bytes)")
            started = time.monotonic()
            gzip_test = None
            working_copy: dict[str, Any] | None = None
            if role == "disk_gzip" and not args.skip_gzip_test:
                partial = None
                destination = None
                metadata_path = None
                if getattr(args, "prepare_working_disks", False):
                    free = shutil.disk_usage(case_root).free
                    required_free = int(getattr(args, "minimum_free_gib", 200.0) * 1024**3)
                    if free < required_free:
                        raise CaseError(
                            f"Only {free / 1024**3:.1f} GiB free; --minimum-free-gib requires "
                            f"{getattr(args, 'minimum_free_gib', 200.0):.1f} GiB"
                        )
                    work_root = source_work_root(case_root, source) / "disk" / "working"
                    destination = work_root / "disk.raw"
                    partial = work_root / "disk.raw.partial"
                    metadata_path = work_root / "disk.raw.json"
                    if destination.exists():
                        metadata = validated_working_disk_metadata(case_root, source)
                        working_copy = {"status": "existing", **metadata}
                    else:
                        if partial.exists():
                            if not getattr(args, "restart_partials", False):
                                raise CaseError(
                                    f"Interrupted partial output exists: {partial}; use --restart-partials "
                                    "to remove only this harness-owned partial"
                                )
                            partial.unlink()
                        working_copy = {"status": "partial", "path": str(partial)}
                gzip_test = hash_and_test_gzip_stream(
                    path,
                    partial if partial and not destination.exists() else None,
                )
                if gzip_test["sha256_complete"]:
                    actual = gzip_test["sha256"]
                else:
                    actual = file_sha256(path)
                    gzip_test["whole_file_sha256_fallback"] = actual
            else:
                actual = file_sha256(path)
            expected_digest = expected.get(record["name"])
            status = "match" if expected_digest == actual else "unlisted"
            if expected_digest and expected_digest != actual:
                status = "mismatch"
                overall_ok = False
            item_result: dict[str, Any] = {
                "role": role,
                "relative_path": record["relative_path"],
                "size_bytes": current_stat.st_size,
                "inventory_changed_since_init": inventory_changed,
                "sha256": actual,
                "expected_sha256": expected_digest,
                "manifest_status": status,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            if role == "disk_gzip" and not args.skip_gzip_test:
                item_result["gzip_test"] = gzip_test
                if not item_result["gzip_test"]["ok"]:
                    overall_ok = False
                if working_copy:
                    if (
                        working_copy["status"] == "partial"
                        and gzip_test["ok"]
                        and status != "mismatch"
                        and partial
                        and destination
                        and metadata_path
                    ):
                        os.replace(partial, destination)
                        raw_metadata = {
                            "created_utc": utc_now(),
                            "source_relative_path": record["relative_path"],
                            "working_path": str(destination),
                            "size_bytes": gzip_test["uncompressed_bytes_read"],
                            "sha256": gzip_test["raw_sha256"],
                            "elapsed_seconds": gzip_test["elapsed_seconds"],
                            "atomic_completion": True,
                            "created_during_integrity_verification": True,
                        }
                        atomic_write_json(metadata_path, raw_metadata)
                        working_copy = {"status": "created", **raw_metadata}
                    item_result["working_copy"] = working_copy
            source_result["items"].append(item_result)
            progress = {
                **output,
                "status": "in_progress",
                "updated_utc": utc_now(),
                "note": "Progress only; this file is not an integrity gate.",
            }
            atomic_write_json(case_root / "integrity.progress.json", progress)

    output["completed_utc"] = utc_now()
    output["status"] = "verified" if overall_ok else "failed"
    destination = case_root / "integrity.json"
    atomic_write_json(destination, output)
    progress_path = case_root / "integrity.progress.json"
    if progress_path.exists():
        progress_path.unlink()
    print(f"Integrity status: {output['status']}")
    print(f"Results: {destination}")
    return 0 if overall_ok else 2


def source_work_root(case_root: Path, source: dict[str, Any]) -> Path:
    return case_root / "sources" / source["case_key"]


def validated_working_disk_metadata(
    case_root: Path, source: dict[str, Any]
) -> dict[str, Any]:
    work_root = source_work_root(case_root, source) / "disk" / "working"
    disk_path = work_root / "disk.raw"
    metadata_path = work_root / "disk.raw.json"
    if not disk_path.is_file():
        raise CaseError(f"Working disk does not exist: {disk_path}")
    if not metadata_path.is_file():
        raise CaseError(f"Working disk metadata is missing: {metadata_path}")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise CaseError(f"Working disk metadata cannot be read: {metadata_path}: {exc}") from exc
    expected_source = source["disk_gzip"]["relative_path"]
    if metadata.get("source_relative_path") != expected_source:
        raise CaseError(
            f"Working disk metadata source mismatch for {source['source_name']}: "
            f"{metadata.get('source_relative_path')!r} != {expected_source!r}"
        )
    if resolved(metadata.get("working_path", "")) != disk_path.resolve():
        raise CaseError(f"Working disk metadata path mismatch: {metadata_path}")
    if metadata.get("size_bytes") != disk_path.stat().st_size:
        raise CaseError(f"Working disk size does not match its metadata: {disk_path}")
    if not metadata.get("atomic_completion"):
        raise CaseError(f"Working disk metadata lacks atomic completion: {metadata_path}")
    if not SHA256_RE.fullmatch(str(metadata.get("sha256", ""))):
        raise CaseError(f"Working disk metadata lacks a valid SHA-256: {metadata_path}")
    return metadata


def require_verified_integrity(case_root: Path, selected: list[dict[str, Any]]) -> dict[str, Any]:
    integrity_path = case_root / "integrity.json"
    if not integrity_path.is_file():
        raise CaseError(f"Integrity gate has not run: {integrity_path}")
    integrity = json.loads(integrity_path.read_text(encoding="utf-8"))
    if integrity.get("status") != "verified":
        raise CaseError(f"Integrity gate is not verified: {integrity.get('status', 'unknown')}")
    by_name = {item["source_name"]: item for item in integrity.get("sources", [])}
    for source in selected:
        result = by_name.get(source["source_name"])
        if not result:
            raise CaseError(f"Integrity result is missing source: {source['source_name']}")
        roles = {item.get("role"): item for item in result.get("items", [])}
        for role in ("disk_gzip", "memory_dump"):
            item = roles.get(role)
            if not item:
                raise CaseError(f"Integrity result is missing {source['source_name']}/{role}")
            if item.get("manifest_status") == "mismatch":
                raise CaseError(f"Integrity mismatch for {source['source_name']}/{role}")
        gzip_result = roles["disk_gzip"].get("gzip_test")
        if gzip_result and not gzip_result.get("ok"):
            raise CaseError(f"Gzip integrity failed for {source['source_name']}")
    return integrity


def prepare_disks(args: argparse.Namespace) -> int:
    case_root, evidence_root, state = load_case(args.case_root)
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    required_free = int(args.minimum_free_gib * 1024**3)
    for source in selected:
        free = shutil.disk_usage(case_root).free
        if free < required_free:
            raise CaseError(
                f"Only {free / 1024**3:.1f} GiB free; --minimum-free-gib requires {args.minimum_free_gib:.1f} GiB"
            )
        record = source["disk_gzip"]
        source_path = evidence_root / record["relative_path"]
        work_root = source_work_root(case_root, source) / "disk" / "working"
        destination = work_root / "disk.raw"
        partial = work_root / "disk.raw.partial"
        metadata_path = work_root / "disk.raw.json"
        if destination.exists() and not args.force:
            validated_working_disk_metadata(case_root, source)
            print(f"Working disk already exists; skipping {source['source_name']}: {destination}")
            continue
        if partial.exists():
            if not args.restart:
                raise CaseError(
                    f"Interrupted partial output exists: {partial}; use --restart to remove only this partial"
                )
            partial.unlink()
        if destination.exists() and args.force:
            destination.unlink()

        digest = hashlib.sha256()
        written = 0
        next_progress = 10 * 1024**3
        started = time.monotonic()
        print(f"Decompressing {source['source_name']} to an atomic working copy")
        try:
            with gzip.open(source_path, "rb") as source_stream, partial.open("xb") as output_stream:
                while chunk := source_stream.read(CHUNK_SIZE):
                    output_stream.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
                    if written >= next_progress:
                        print(f"  wrote {written / 1024**3:.1f} GiB")
                        while next_progress <= written:
                            next_progress += 10 * 1024**3
                output_stream.flush()
                os.fsync(output_stream.fileno())
            os.replace(partial, destination)
        except Exception:
            print(f"Partial output retained for explicit review: {partial}", file=sys.stderr)
            raise
        metadata = {
            "created_utc": utc_now(),
            "source_relative_path": record["relative_path"],
            "working_path": str(destination),
            "size_bytes": written,
            "sha256": digest.hexdigest(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "atomic_completion": True,
        }
        atomic_write_json(metadata_path, metadata)
        print(f"Prepared {destination} ({written} bytes, SHA-256 {metadata['sha256']})")
    return 0


def append_command_log(case_root: Path, record: dict[str, Any]) -> None:
    path = case_root / "logs" / "commands.jsonl"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")


def run_recorded(
    case_root: Path,
    label: str,
    command: list[str],
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, Any]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started_utc = utc_now()
    started = time.monotonic()
    with stdout_path.open("w", encoding="utf-8", errors="replace") as stdout, stderr_path.open(
        "w", encoding="utf-8", errors="replace"
    ) as stderr:
        completed = subprocess.run(command, stdout=stdout, stderr=stderr, text=True, check=False)
    record = {
        "label": label,
        "command": command,
        "started_utc": started_utc,
        "completed_utc": utc_now(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "exit_code": completed.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }
    append_command_log(case_root, record)
    return record


def require_command(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise CaseError(f"Required command is not installed or not on PATH: {name}")
    return path


def build_tools(args: argparse.Namespace) -> int:
    case_root, _, _ = load_case(args.case_root)
    require_command("docker")
    repo_root = resolved(args.repo_root)
    definitions = (
        (
            "volatility",
            args.volatility_image,
            repo_root / "tooling" / "paired-vm" / "Dockerfile.volatility",
        ),
        ("tsk", args.tsk_image, repo_root / "tooling" / "paired-vm" / "Dockerfile.tsk"),
    )
    results = []
    for name, tag, dockerfile in definitions:
        if not dockerfile.is_file():
            raise CaseError(f"Dockerfile not found: {dockerfile}")
        command = ["docker", "build", "--pull", "-t", tag, "-f", str(dockerfile), str(repo_root)]
        print(f"Building {name} image as {tag}")
        record = run_recorded(
            case_root,
            f"build-{name}",
            command,
            case_root / "tooling" / f"build-{name}.stdout.log",
            case_root / "tooling" / f"build-{name}.stderr.log",
        )
        results.append(record)
        if record["exit_code"] != 0:
            raise CaseError(f"Docker build failed for {name}; see {record['stderr_path']}")

    inspect = subprocess.run(
        ["docker", "image", "inspect", args.volatility_image, args.tsk_image],
        capture_output=True,
        text=True,
        check=False,
    )
    if inspect.returncode != 0:
        raise CaseError(f"Docker image inspection failed: {inspect.stderr.strip()}")
    image_metadata = json.loads(inspect.stdout)
    version_commands = {
        "volatility3": [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            args.volatility_image,
            "-c",
            "import importlib.metadata; print(importlib.metadata.version('volatility3'))",
        ],
        "volatility3-python-packages": [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            args.volatility_image,
            "-m",
            "pip",
            "freeze",
            "--all",
        ],
        "sleuthkit": ["docker", "run", "--rm", args.tsk_image, "mmls", "-V"],
    }
    versions: dict[str, Any] = {}
    for name, command in version_commands.items():
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        versions[name] = {
            "command": command,
            "exit_code": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
        if completed.returncode != 0:
            raise CaseError(f"Version check failed for {name}: {completed.stderr.strip()}")
    atomic_write_json(
        case_root / "tooling" / "images.json",
        {
            "recorded_utc": utc_now(),
            "images": image_metadata,
            "versions": versions,
            "builds": results,
        },
    )
    print(f"Built and recorded {len(results)} tool image(s)")
    return 0


def docker_user_args() -> list[str]:
    if os.name == "posix" and hasattr(os, "getuid") and hasattr(os, "getgid"):
        return ["--user", f"{os.getuid()}:{os.getgid()}"]
    return []


def volatility_command(
    image: str,
    evidence_directory: Path,
    memory_name: str,
    output_directory: Path,
    cache_directory: Path,
    plugin: str,
    allow_network: bool,
    parallelism: str,
) -> list[str]:
    command = ["docker", "run", "--rm"]
    command.extend(docker_user_args())
    if not allow_network:
        command.extend(["--network", "none"])
    command.extend(
        [
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=1g",
            "-e",
            "HOME=/home/ANALYST",
            "-v",
            f"{evidence_directory}:/evidence:ro",
            "-v",
            f"{output_directory}:/output:rw",
            "-v",
            f"{cache_directory}:/home/ANALYST/.cache/volatility3:rw",
            image,
            "-q",
            "--parallelism",
            parallelism,
            "-f",
            f"/evidence/{memory_name}",
            "-r",
            "json",
            "-o",
            "/output",
            plugin,
        ]
    )
    if not allow_network:
        command.insert(command.index("-f"), "--offline")
    return command


def run_memory_plugins(args: argparse.Namespace) -> int:
    case_root, evidence_root, state = load_case(args.case_root)
    require_command("docker")
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    plugins = args.plugin or (["windows.info"] if args.info_only else list(DEFAULT_MEMORY_PLUGINS))
    any_failure = False
    for source in selected:
        evidence_record = source["memory_dump"]
        evidence_path = evidence_root / evidence_record["relative_path"]
        output_root = source_work_root(case_root, source) / "memory"
        cache_root = case_root / "tool-cache" / "volatility3"
        output_root.mkdir(parents=True, exist_ok=True)
        cache_root.mkdir(parents=True, exist_ok=True)
        source_runs = []
        for plugin in plugins:
            slug = safe_name(plugin)
            command = volatility_command(
                args.volatility_image,
                evidence_path.parent,
                evidence_path.name,
                output_root,
                cache_root,
                plugin,
                args.allow_network,
                args.parallelism,
            )
            print(f"Running {plugin} for {source['source_name']}")
            record = run_recorded(
                case_root,
                f"{source['case_key']}-{plugin}",
                command,
                output_root / f"{slug}.json",
                output_root / f"{slug}.stderr.log",
            )
            source_runs.append(record)
            if record["exit_code"] != 0:
                any_failure = True
                print(f"  failed with exit {record['exit_code']}; continuing independent plugins")
        atomic_write_json(
            output_root / "run-summary.json",
            {
                "completed_utc": utc_now(),
                "source_name": source["source_name"],
                "image": args.volatility_image,
                "network_allowed_for_symbol_resolution": args.allow_network,
                "runs": source_runs,
            },
        )
    return 2 if any_failure else 0


def disk_layout(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    require_command("docker")
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    any_failure = False
    for source in selected:
        source_root = source_work_root(case_root, source)
        disk_path = source_root / "disk" / "working" / "disk.raw"
        validated_working_disk_metadata(case_root, source)
        metadata_root = source_root / "disk" / "metadata"
        command = ["docker", "run", "--rm", "--network", "none", "--read-only"]
        command.extend(docker_user_args())
        command.extend(
            [
                "-v",
                f"{disk_path.parent}:/evidence:ro",
                args.tsk_image,
                "mmls",
                "-B",
                "-i",
                "raw",
                "/evidence/disk.raw",
            ]
        )
        print(f"Reading partition layout for {source['source_name']}")
        record = run_recorded(
            case_root,
            f"{source['case_key']}-mmls",
            command,
            metadata_root / "mmls.txt",
            metadata_root / "mmls.stderr.log",
        )
        atomic_write_json(metadata_root / "mmls.run.json", record)
        if record["exit_code"] != 0:
            any_failure = True
    return 2 if any_failure else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Initialize, verify, prepare, and triage paired VM disk/RAM forensic evidence."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Discover evidence pairs and initialize case state")
    init.add_argument("--evidence-root", required=True)
    init.add_argument("--case-root", required=True)
    init.add_argument("--case-id", required=True)
    init.add_argument("--force", action="store_true", help="Replace existing case state/report only")
    init.set_defaults(func=initialize_case)

    verify = subparsers.add_parser("verify", help="Hash evidence and verify supplied manifests/gzip")
    verify.add_argument("--case-root", required=True)
    verify.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    verify.add_argument("--skip-gzip-test", action="store_true")
    verify.add_argument(
        "--prepare-working-disks",
        action="store_true",
        help="Create atomic raw working copies during the verified gzip pass",
    )
    verify.add_argument("--minimum-free-gib", type=float, default=200.0)
    verify.add_argument(
        "--restart-partials",
        action="store_true",
        help="Remove only interrupted disk.raw.partial files before the pass",
    )
    verify.set_defaults(func=verify_case)

    prepare = subparsers.add_parser("prepare-disks", help="Create atomic decompressed working disks")
    prepare.add_argument("--case-root", required=True)
    prepare.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    prepare.add_argument("--minimum-free-gib", type=float, default=200.0)
    prepare.add_argument("--restart", action="store_true", help="Remove only an interrupted .partial output")
    prepare.add_argument("--force", action="store_true", help="Replace a completed working disk")
    prepare.set_defaults(func=prepare_disks)

    build = subparsers.add_parser("build-tools", help="Build and record pinned analysis containers")
    build.add_argument("--case-root", required=True)
    build.add_argument("--repo-root", default=str(Path(__file__).resolve().parent.parent))
    build.add_argument("--volatility-image", default=DEFAULT_VOLATILITY_IMAGE)
    build.add_argument("--tsk-image", default=DEFAULT_TSK_IMAGE)
    build.set_defaults(func=build_tools)

    memory = subparsers.add_parser("memory", help="Run Volatility information or baseline plugins")
    memory.add_argument("--case-root", required=True)
    memory.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    memory.add_argument("--plugin", action="append", help="Override plugin list; repeat as needed")
    memory.add_argument("--info-only", action="store_true", help="Run only windows.info")
    memory.add_argument(
        "--allow-network",
        action="store_true",
        help="Allow outbound access for symbol resolution; evidence remains mounted read-only",
    )
    memory.add_argument("--volatility-image", default=DEFAULT_VOLATILITY_IMAGE)
    memory.add_argument(
        "--parallelism",
        choices=("off", "threads", "processes"),
        default="processes",
        help="Volatility parallelism mode",
    )
    memory.set_defaults(func=run_memory_plugins)

    layout = subparsers.add_parser("disk-layout", help="Record partition layouts with The Sleuth Kit")
    layout.add_argument("--case-root", required=True)
    layout.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    layout.add_argument("--tsk-image", default=DEFAULT_TSK_IMAGE)
    layout.set_defaults(func=disk_layout)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except CaseError as exc:
        print(f"paired_vm_case.py: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("paired_vm_case.py: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
