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
DEFAULT_ELF2DMP_IMAGE = "forensic-copilot/elf2dmp:11.0.2"
DEFAULT_PLASO_IMAGE = (
    "log2timeline/plaso:20260512@"
    "sha256:16baaa7645e03381b0b246315d6ded08ff28f78f0a5b1c2f062bba42714852c8"
)
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
    "windows.malware.malfind",
    "windows.handles",
    "windows.filescan",
    "windows.registry.hivelist",
)
EXTENDED_MEMORY_PLUGINS = (
    "windows.malware.psxview",
    "windows.cmdscan",
    "windows.consoles",
    "windows.envars",
    "windows.privileges",
    "windows.malware.suspicious_threads",
    "windows.malware.hollowprocesses",
    "windows.malware.processghosting",
    "windows.registry.scheduled_tasks",
    "windows.registry.userassist",
    "windows.shimcachemem",
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


def require_docker_image(image: str) -> None:
    completed = subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise CaseError(
            f"Required Docker image is not prepared locally: {image}; run build-tools first"
        )


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
        (
            "elf2dmp",
            args.elf2dmp_image,
            repo_root / "tooling" / "paired-vm" / "Dockerfile.elf2dmp",
        ),
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

    print(f"Pulling digest-pinned Plaso image {args.plaso_image}")
    plaso_pull = run_recorded(
        case_root,
        "pull-plaso",
        ["docker", "pull", args.plaso_image],
        case_root / "tooling" / "pull-plaso.stdout.log",
        case_root / "tooling" / "pull-plaso.stderr.log",
    )
    results.append(plaso_pull)
    if plaso_pull["exit_code"] != 0:
        raise CaseError(f"Docker pull failed for Plaso; see {plaso_pull['stderr_path']}")

    inspect = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            args.volatility_image,
            args.tsk_image,
            args.elf2dmp_image,
            args.plaso_image,
        ],
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
        "elf2dmp-source": [
            "docker",
            "image",
            "inspect",
            "--format",
            '{{ index .Config.Labels "org.opencontainers.image.version" }}',
            args.elf2dmp_image,
        ],
        "plaso": [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            args.plaso_image,
            "log2timeline",
            "--version",
        ],
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
    print(f"Prepared and recorded {len(results)} tool image operation(s)")
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
    symbol_directory: Path,
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
            "-v",
            f"{symbol_directory}:/symbols:rw",
            image,
            "-q",
            "-s",
            "/symbols",
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


def validated_converted_memory_metadata(
    case_root: Path, source: dict[str, Any]
) -> tuple[Path, dict[str, Any]]:
    conversion_root = source_work_root(case_root, source) / "memory" / "converted"
    dump_path = conversion_root / "windows.dmp"
    metadata_path = conversion_root / "windows.dmp.json"
    if not dump_path.is_file() or not metadata_path.is_file():
        raise CaseError(
            f"Converted Windows dump is missing; run memory-convert first: {dump_path}"
        )
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise CaseError(f"Converted dump metadata cannot be read: {metadata_path}: {exc}") from exc
    if metadata.get("source_relative_path") != source["memory_dump"]["relative_path"]:
        raise CaseError(f"Converted dump source mismatch: {metadata_path}")
    if resolved(metadata.get("converted_path", "")) != dump_path.resolve():
        raise CaseError(f"Converted dump path mismatch: {metadata_path}")
    if metadata.get("size_bytes") != dump_path.stat().st_size:
        raise CaseError(f"Converted dump size does not match its metadata: {dump_path}")
    if not metadata.get("atomic_completion"):
        raise CaseError(f"Converted dump metadata lacks atomic completion: {metadata_path}")
    if not SHA256_RE.fullmatch(str(metadata.get("sha256", ""))):
        raise CaseError(f"Converted dump metadata lacks a valid SHA-256: {metadata_path}")
    return dump_path, metadata


def elf2dmp_command(
    image: str, evidence_path: Path, conversion_root: Path, partial_name: str
) -> list[str]:
    command = ["docker", "run", "--rm", "--read-only"]
    command.extend(docker_user_args())
    command.extend(
        [
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=1g",
            "-e",
            "HOME=/tmp",
            "-v",
            f"{evidence_path.parent}:/evidence:ro",
            "-v",
            f"{conversion_root}:/output:rw",
            "-w",
            "/output",
            image,
            f"/evidence/{evidence_path.name}",
            f"/output/{partial_name}",
        ]
    )
    return command


def convert_memory(args: argparse.Namespace) -> int:
    case_root, evidence_root, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.elf2dmp_image)
    selected = select_sources(state, args.source)
    integrity = require_verified_integrity(case_root, selected)
    if not args.allow_network:
        raise CaseError(
            "QEMU elf2dmp requires Microsoft symbol access; rerun with explicit --allow-network"
        )
    integrity_by_name = {item["source_name"]: item for item in integrity["sources"]}
    any_failure = False
    for source in selected:
        source_path, _ = validated_evidence_path(evidence_root, source["memory_dump"])
        source_integrity = integrity_by_name[source["source_name"]]
        memory_integrity = next(
            item for item in source_integrity["items"] if item.get("role") == "memory_dump"
        )
        conversion_root = source_work_root(case_root, source) / "memory" / "converted"
        conversion_root.mkdir(parents=True, exist_ok=True)
        destination = conversion_root / "windows.dmp"
        partial = conversion_root / "windows.dmp.partial"
        metadata_path = conversion_root / "windows.dmp.json"
        if destination.exists() and not args.force:
            validated_converted_memory_metadata(case_root, source)
            print(f"Converted dump already exists; skipping {source['source_name']}: {destination}")
            continue
        if partial.exists():
            if not args.restart:
                raise CaseError(
                    f"Interrupted conversion output exists: {partial}; use --restart to remove only it"
                )
            partial.unlink()
        command = elf2dmp_command(
            args.elf2dmp_image, source_path, conversion_root, partial.name
        )
        print(f"Converting verified QEMU ELF memory for {source['source_name']}")
        record = run_recorded(
            case_root,
            f"{source['case_key']}-elf2dmp",
            command,
            conversion_root / "elf2dmp.stdout.log",
            conversion_root / "elf2dmp.stderr.log",
        )
        if record["exit_code"] != 0 or not partial.is_file():
            any_failure = True
            print(f"  conversion failed with exit {record['exit_code']}; partial retained if present")
            continue
        print(f"Hashing derived Windows dump for {source['source_name']}")
        digest = file_sha256(partial)
        size_bytes = partial.stat().st_size
        os.replace(partial, destination)
        atomic_write_json(
            metadata_path,
            {
                "created_utc": utc_now(),
                "source_relative_path": source["memory_dump"]["relative_path"],
                "source_sha256": memory_integrity["sha256"],
                "converted_path": str(destination),
                "size_bytes": size_bytes,
                "sha256": digest,
                "image": args.elf2dmp_image,
                "network_allowed_for_microsoft_symbol_resolution": True,
                "atomic_completion": True,
                "run": record,
            },
        )
        print(f"Prepared {destination} ({size_bytes} bytes, SHA-256 {digest})")
    return 2 if any_failure else 0


def memory_run_kind(args: argparse.Namespace) -> str:
    if args.plugin:
        plugin_key = "\n".join(args.plugin).encode("utf-8")
        return f"custom-{len(args.plugin)}-{hashlib.sha256(plugin_key).hexdigest()[:12]}"
    if args.info_only:
        return "info"
    if args.extended:
        return "extended"
    return "baseline"


def run_memory_plugins(args: argparse.Namespace) -> int:
    case_root, evidence_root, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.volatility_image)
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    if args.plugin:
        plugins = args.plugin
    elif args.info_only:
        plugins = ["windows.info"]
    elif args.extended:
        plugins = list(DEFAULT_MEMORY_PLUGINS + EXTENDED_MEMORY_PLUGINS)
    else:
        plugins = list(DEFAULT_MEMORY_PLUGINS)
    run_kind = memory_run_kind(args)
    any_failure = False
    for source in selected:
        if args.input == "converted":
            evidence_path, _ = validated_converted_memory_metadata(case_root, source)
        else:
            evidence_record = source["memory_dump"]
            evidence_path, _ = validated_evidence_path(evidence_root, evidence_record)
        output_root = source_work_root(case_root, source) / "memory" / f"analysis-{args.input}"
        cache_root = case_root / "tool-cache" / "volatility3"
        symbol_root = cache_root / "symbols"
        output_root.mkdir(parents=True, exist_ok=True)
        cache_root.mkdir(parents=True, exist_ok=True)
        symbol_root.mkdir(parents=True, exist_ok=True)
        (symbol_root / "windows").mkdir(parents=True, exist_ok=True)
        source_runs = []
        for plugin in plugins:
            slug = safe_name(plugin)
            command = volatility_command(
                args.volatility_image,
                evidence_path.parent,
                evidence_path.name,
                output_root,
                cache_root,
                symbol_root,
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
        summary = {
            "completed_utc": utc_now(),
            "source_name": source["source_name"],
            "image": args.volatility_image,
            "input_kind": args.input,
            "input_path": str(evidence_path),
            "run_kind": run_kind,
            "network_allowed_for_symbol_resolution": args.allow_network,
            "runs": source_runs,
        }
        atomic_write_json(output_root / f"run-summary-{run_kind}.json", summary)
        atomic_write_json(output_root / "run-summary.json", summary)
    return 2 if any_failure else 0


def disk_layout(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.tsk_image)
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


MMLS_PARTITION_RE = re.compile(
    r"^\d+:\s+\d+:\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+(.+?)\s*$"
)


def parse_mmls_partitions(text: str) -> list[dict[str, Any]]:
    partitions = []
    for line in text.splitlines():
        match = MMLS_PARTITION_RE.match(line)
        if not match:
            continue
        start, end, length, description = match.groups()
        partitions.append(
            {
                "start_sector": int(start),
                "end_sector": int(end),
                "length_sectors": int(length),
                "description": description,
            }
        )
    return partitions


def disk_filesystems(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.tsk_image)
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    any_failure = False
    for source in selected:
        source_root = source_work_root(case_root, source)
        validated_working_disk_metadata(case_root, source)
        disk_path = source_root / "disk" / "working" / "disk.raw"
        metadata_root = source_root / "disk" / "metadata"
        mmls_path = metadata_root / "mmls.txt"
        if not mmls_path.is_file():
            raise CaseError(f"Partition layout is missing; run disk-layout first: {mmls_path}")
        partitions = parse_mmls_partitions(mmls_path.read_text(encoding="utf-8", errors="replace"))
        if not partitions:
            raise CaseError(f"No allocated partitions parsed from: {mmls_path}")
        runs = []
        for partition in partitions:
            offset = partition["start_sector"]
            command = ["docker", "run", "--rm", "--network", "none", "--read-only"]
            command.extend(docker_user_args())
            command.extend(
                [
                    "-v",
                    f"{disk_path.parent}:/evidence:ro",
                    args.tsk_image,
                    "fsstat",
                    "-i",
                    "raw",
                    "-o",
                    str(offset),
                    "/evidence/disk.raw",
                ]
            )
            print(f"Reading filesystem metadata for {source['source_name']} at sector {offset}")
            record = run_recorded(
                case_root,
                f"{source['case_key']}-fsstat-{offset}",
                command,
                metadata_root / f"fsstat-offset-{offset}.txt",
                metadata_root / f"fsstat-offset-{offset}.stderr.log",
            )
            record["partition"] = partition
            runs.append(record)
            if record["exit_code"] != 0:
                any_failure = True
        atomic_write_json(
            metadata_root / "fsstat.run.json",
            {"completed_utc": utc_now(), "source_name": source["source_name"], "runs": runs},
        )
    return 2 if any_failure else 0


def tsk_recover_command(
    image: str,
    disk_directory: Path,
    output_directory: Path,
    partial_name: str,
    offset: int,
    directory_inum: int | None = None,
) -> list[str]:
    command = ["docker", "run", "--rm", "--network", "none", "--read-only"]
    command.extend(docker_user_args())
    command.extend(
        [
            "-v",
            f"{disk_directory}:/evidence:ro",
            "-v",
            f"{output_directory}:/output:rw",
            image,
            "tsk_recover",
            "-a",
            "-i",
            "raw",
            "-o",
            str(offset),
        ]
    )
    if directory_inum is not None:
        command.extend(["-d", str(directory_inum)])
    command.extend(["/evidence/disk.raw", f"/output/{partial_name}"])
    return command


def directory_tree_stats(root: Path) -> tuple[int, int]:
    file_count = 0
    size_bytes = 0
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in directory_names:
            if (directory_path / name).is_symlink():
                raise CaseError(f"Recovered tree contains a symlink: {directory_path / name}")
        for name in file_names:
            path = directory_path / name
            if path.is_symlink():
                raise CaseError(f"Recovered tree contains a symlink: {path}")
            file_count += 1
            size_bytes += path.stat().st_size
    return file_count, size_bytes


def recovery_basename(offset: int, directory_inum: int | None = None) -> str:
    basename = f"offset-{offset}"
    if directory_inum is not None:
        basename = f"{basename}-dir-{directory_inum}"
    return basename


def validated_recovered_directory_metadata(
    case_root: Path,
    source: dict[str, Any],
    offset: int,
    directory_inum: int | None = None,
) -> tuple[Path, dict[str, Any]]:
    recovery_root = source_work_root(case_root, source) / "disk" / "recovered"
    basename = recovery_basename(offset, directory_inum)
    destination = recovery_root / basename
    metadata_path = recovery_root / f"{basename}.json"
    if not destination.is_dir() or not metadata_path.is_file():
        raise CaseError(f"Completed TSK recovery is missing; run disk-recover first: {destination}")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise CaseError(f"Recovery metadata cannot be read: {metadata_path}: {exc}") from exc
    if resolved(metadata.get("recovered_path", "")) != destination.resolve():
        raise CaseError(f"Recovered directory path mismatch: {metadata_path}")
    if metadata.get("offset_sector") != offset:
        raise CaseError(f"Recovered directory offset mismatch: {metadata_path}")
    if metadata.get("directory_inum") != directory_inum:
        raise CaseError(f"Recovered directory inode mismatch: {metadata_path}")
    if not metadata.get("atomic_completion"):
        raise CaseError(f"Recovery metadata lacks atomic completion: {metadata_path}")
    return destination, metadata


def recover_disk_files(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.tsk_image)
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    any_failure = False
    for source in selected:
        source_root = source_work_root(case_root, source)
        disk_metadata = validated_working_disk_metadata(case_root, source)
        disk_directory = source_root / "disk" / "working"
        recovery_root = source_root / "disk" / "recovered"
        recovery_root.mkdir(parents=True, exist_ok=True)
        basename = recovery_basename(args.offset, args.directory_inum)
        destination = recovery_root / basename
        partial = recovery_root / f"{basename}.partial"
        metadata_path = recovery_root / f"{basename}.json"
        if destination.exists():
            validated_recovered_directory_metadata(
                case_root, source, args.offset, args.directory_inum
            )
            print(f"Recovered directory already exists; skipping {source['source_name']}: {destination}")
            continue
        if partial.exists():
            if not args.restart:
                raise CaseError(
                    f"Interrupted recovery directory exists: {partial}; use --restart to remove only it"
                )
            shutil.rmtree(partial)
        command = tsk_recover_command(
            args.tsk_image,
            disk_directory,
            recovery_root,
            partial.name,
            args.offset,
            args.directory_inum,
        )
        scope = f"directory inode {args.directory_inum}" if args.directory_inum else "volume"
        print(
            f"Recovering allocated files for {source['source_name']} at sector "
            f"{args.offset} ({scope})"
        )
        record = run_recorded(
            case_root,
            f"{source['case_key']}-tsk-recover-{basename}",
            command,
            recovery_root / f"{basename}.stdout.log",
            recovery_root / f"{basename}.stderr.log",
        )
        if record["exit_code"] != 0 or not partial.is_dir():
            any_failure = True
            print(f"  recovery failed with exit {record['exit_code']}; partial retained if present")
            continue
        file_count, size_bytes = directory_tree_stats(partial)
        os.replace(partial, destination)
        atomic_write_json(
            metadata_path,
            {
                "created_utc": utc_now(),
                "source_working_disk": str(disk_directory / "disk.raw"),
                "source_working_disk_sha256": disk_metadata["sha256"],
                "offset_sector": args.offset,
                "directory_inum": args.directory_inum,
                "recovered_path": str(destination),
                "allocated_files_only": True,
                "file_count": file_count,
                "logical_size_bytes": size_bytes,
                "image": args.tsk_image,
                "atomic_completion": True,
                "run": record,
            },
        )
        print(f"Prepared {destination} ({file_count} files, {size_bytes} logical bytes)")
    return 2 if any_failure else 0


def plaso_command(
    image: str,
    disk_directory: Path,
    output_directory: Path,
    storage_name: str,
    partitions: str,
    vss_stores: str,
) -> list[str]:
    command = ["docker", "run", "--rm", "--network", "none", "--read-only"]
    command.extend(docker_user_args())
    command.extend(
        [
            "--tmpfs",
            "/tmp:rw,nosuid,size=8g",
            "--shm-size",
            "2g",
            "-e",
            "HOME=/tmp",
            "-v",
            f"{disk_directory}:/evidence:ro",
            "-v",
            f"{output_directory}:/output:rw",
            image,
            "log2timeline",
            "--storage-file",
            f"/output/{storage_name}",
            "--logfile",
            f"/output/{storage_name}.log.gz",
            "--unattended",
            "--partitions",
            partitions,
            "--vss_stores",
            vss_stores,
            "/evidence/disk.raw",
        ]
    )
    return command


def plaso_completion_errors(stdout_path: Path, internal_log_path: Path) -> list[str]:
    indicators = []
    stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
    if "Processing completed with errors." in stdout_text:
        indicators.append("processing_completed_with_errors")
    if "Path specifications that could not be processed:" in stdout_text:
        indicators.append("unprocessed_path_specifications")
    if internal_log_path.is_file():
        try:
            with gzip.open(internal_log_path, "rt", encoding="utf-8", errors="replace") as stream:
                internal_log_text = stream.read()
        except (gzip.BadGzipFile, OSError) as exc:
            indicators.append(f"internal_log_unreadable:{type(exc).__name__}")
        else:
            if "[ERROR]" in internal_log_text:
                indicators.append("internal_log_error")
    return indicators


def disk_timeline(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.plaso_image)
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    any_failure = False
    for source in selected:
        source_root = source_work_root(case_root, source)
        validated_working_disk_metadata(case_root, source)
        disk_directory = source_root / "disk" / "working"
        output_root = source_root / "timeline"
        output_root.mkdir(parents=True, exist_ok=True)
        destination = output_root / "timeline.plaso"
        partial = output_root / "timeline.plaso.partial"
        metadata_path = output_root / "timeline.plaso.json"
        if destination.exists():
            if not args.force:
                print(f"Timeline already exists; skipping {source['source_name']}: {destination}")
                continue
        if partial.exists():
            if not args.restart:
                raise CaseError(
                    f"Interrupted timeline output exists: {partial}; use --restart to remove only it"
                )
            partial.unlink()
        command = plaso_command(
            args.plaso_image,
            disk_directory,
            output_root,
            partial.name,
            args.partitions,
            args.vss_stores,
        )
        print(f"Building Plaso timeline for {source['source_name']}")
        record = run_recorded(
            case_root,
            f"{source['case_key']}-log2timeline",
            command,
            output_root / "log2timeline.stdout.log",
            output_root / "log2timeline.stderr.log",
        )
        internal_log_path = output_root / f"{partial.name}.log.gz"
        if record["exit_code"] != 0:
            any_failure = True
            print(f"  failed with exit {record['exit_code']}; partial output retained if present")
            continue
        if not partial.is_file():
            any_failure = True
            print("  command succeeded but produced no Plaso storage file")
            continue
        completion_errors = plaso_completion_errors(
            Path(record["stdout_path"]), internal_log_path
        )
        if completion_errors:
            any_failure = True
            atomic_write_json(
                output_root / "timeline.plaso.partial.json",
                {
                    "created_utc": utc_now(),
                    "status": "incomplete",
                    "source_working_disk": str(disk_directory / "disk.raw"),
                    "storage_path": str(partial),
                    "image": args.plaso_image,
                    "partitions": args.partitions,
                    "vss_stores": args.vss_stores,
                    "completion_errors": completion_errors,
                    "atomic_completion": False,
                    "run": record,
                },
            )
            print(
                "  Plaso reported incomplete processing; partial retained: "
                + ", ".join(completion_errors)
            )
            continue
        print(f"Hashing derived timeline for {source['source_name']}")
        digest = file_sha256(partial)
        size_bytes = partial.stat().st_size
        os.replace(partial, destination)
        atomic_write_json(
            metadata_path,
            {
                "created_utc": utc_now(),
                "source_working_disk": str(disk_directory / "disk.raw"),
                "storage_path": str(destination),
                "size_bytes": size_bytes,
                "sha256": digest,
                "image": args.plaso_image,
                "partitions": args.partitions,
                "vss_stores": args.vss_stores,
                "completion_errors": [],
                "atomic_completion": True,
                "run": record,
            },
        )
        print(f"Prepared {destination} ({size_bytes} bytes, SHA-256 {digest})")
    return 2 if any_failure else 0


def plaso_recovered_command(
    image: str,
    recovered_directory: Path,
    output_directory: Path,
    storage_name: str,
    file_filter: Path | None = None,
) -> list[str]:
    command = ["docker", "run", "--rm", "--network", "none", "--read-only"]
    command.extend(docker_user_args())
    command.extend(
        [
            "--tmpfs",
            "/tmp:rw,nosuid,size=8g",
            "--shm-size",
            "2g",
            "-e",
            "HOME=/tmp",
            "-v",
            f"{recovered_directory}:/evidence:ro",
            "-v",
            f"{output_directory}:/output:rw",
            image,
            "log2timeline",
        ]
    )
    if file_filter is not None:
        command[command.index(image) : command.index(image)] = [
            "-v",
            f"{file_filter}:/config/file-filter.txt:ro",
        ]
        command.extend(["--filter-file", "/config/file-filter.txt"])
    command.extend(
        [
            "--storage-file",
            f"/output/{storage_name}",
            "--logfile",
            f"/output/{storage_name}.log.gz",
            "--unattended",
            "/evidence",
        ]
    )
    return command


def recovered_disk_timeline(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.plaso_image)
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    any_failure = False
    file_filter = None
    file_filter_sha256 = None
    if args.file_filter:
        candidate = Path(args.file_filter).expanduser()
        if candidate.is_symlink() or not candidate.is_file():
            raise CaseError(f"Plaso file filter must be a regular, non-symlink file: {candidate}")
        file_filter = candidate.resolve()
        file_filter_sha256 = file_sha256(file_filter)
    for source in selected:
        recovered_directory, recovery_metadata = validated_recovered_directory_metadata(
            case_root, source, args.offset, args.directory_inum
        )
        output_root = source_work_root(case_root, source) / "timeline"
        output_root.mkdir(parents=True, exist_ok=True)
        recovery_name = recovery_basename(args.offset, args.directory_inum)
        storage_basename = f"recovered-{recovery_name}.plaso"
        destination = output_root / storage_basename
        partial = output_root / f"{storage_basename}.partial"
        metadata_path = output_root / f"{storage_basename}.json"
        if destination.exists() and not args.force:
            print(f"Recovered-files timeline already exists; skipping {source['source_name']}")
            continue
        if partial.exists():
            if not args.restart:
                raise CaseError(
                    f"Interrupted recovered-files timeline exists: {partial}; use --restart"
                )
            partial.unlink()
        command = plaso_recovered_command(
            args.plaso_image, recovered_directory, output_root, partial.name, file_filter
        )
        print(f"Building recovered-files Plaso timeline for {source['source_name']}")
        record = run_recorded(
            case_root,
            f"{source['case_key']}-log2timeline-{recovery_name}",
            command,
            output_root / f"{storage_basename}.stdout.log",
            output_root / f"{storage_basename}.stderr.log",
        )
        internal_log_path = output_root / f"{partial.name}.log.gz"
        if record["exit_code"] != 0 or not partial.is_file():
            any_failure = True
            print(f"  failed with exit {record['exit_code']}; partial retained if present")
            continue
        completion_errors = plaso_completion_errors(
            Path(record["stdout_path"]), internal_log_path
        )
        if completion_errors:
            any_failure = True
            atomic_write_json(
                output_root / f"{storage_basename}.partial.json",
                {
                    "created_utc": utc_now(),
                    "status": "incomplete",
                    "recovered_path": str(recovered_directory),
                    "storage_path": str(partial),
                    "file_filter_path": str(file_filter) if file_filter else None,
                    "file_filter_sha256": file_filter_sha256,
                    "completion_errors": completion_errors,
                    "atomic_completion": False,
                    "run": record,
                },
            )
            print(
                "  Plaso reported incomplete recovered-file processing; partial retained: "
                + ", ".join(completion_errors)
            )
            continue
        digest = file_sha256(partial)
        size_bytes = partial.stat().st_size
        os.replace(partial, destination)
        atomic_write_json(
            metadata_path,
            {
                "created_utc": utc_now(),
                "input_kind": "tsk_recovered_allocated_files",
                "recovered_path": str(recovered_directory),
                "recovery_offset_sector": args.offset,
                "recovery_directory_inum": args.directory_inum,
                "source_working_disk_sha256": recovery_metadata["source_working_disk_sha256"],
                "storage_path": str(destination),
                "size_bytes": size_bytes,
                "sha256": digest,
                "image": args.plaso_image,
                "file_filter_path": str(file_filter) if file_filter else None,
                "file_filter_sha256": file_filter_sha256,
                "completion_errors": [],
                "atomic_completion": True,
                "run": record,
            },
        )
        print(f"Prepared {destination} ({size_bytes} bytes, SHA-256 {digest})")
    return 2 if any_failure else 0


def validated_timeline_metadata(
    case_root: Path, source: dict[str, Any], storage_name: str = "timeline.plaso"
) -> tuple[Path, dict[str, Any]]:
    timeline_root = source_work_root(case_root, source) / "timeline"
    storage_path = timeline_root / storage_name
    metadata_path = timeline_root / f"{storage_name}.json"
    if not storage_path.is_file() or not metadata_path.is_file():
        raise CaseError(f"Completed Plaso timeline is missing; run timeline first: {storage_path}")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise CaseError(f"Timeline metadata cannot be read: {metadata_path}: {exc}") from exc
    if resolved(metadata.get("storage_path", "")) != storage_path.resolve():
        raise CaseError(f"Timeline storage path mismatch: {metadata_path}")
    if metadata.get("size_bytes") != storage_path.stat().st_size:
        raise CaseError(f"Timeline size does not match its metadata: {storage_path}")
    if not metadata.get("atomic_completion"):
        raise CaseError(f"Timeline metadata lacks atomic completion: {metadata_path}")
    if not SHA256_RE.fullmatch(str(metadata.get("sha256", ""))):
        raise CaseError(f"Timeline metadata lacks a valid SHA-256: {metadata_path}")
    return storage_path, metadata


def psort_slice_command(
    image: str,
    timeline_directory: Path,
    storage_name: str,
    output_directory: Path,
    output_name: str,
    slice_time: str,
    slice_size: int,
    output_time_zone: str,
) -> list[str]:
    command = ["docker", "run", "--rm", "--network", "none", "--read-only"]
    command.extend(docker_user_args())
    command.extend(
        [
            "--tmpfs",
            "/tmp:rw,nosuid,size=2g",
            "-e",
            "HOME=/tmp",
            "-v",
            f"{timeline_directory}:/timeline:ro",
            "-v",
            f"{output_directory}:/output:rw",
            image,
            "psort",
            "--unattended",
            "--status_view",
            "linear",
            "--logfile",
            f"/output/{output_name}.psort.log.gz",
            "--output_format",
            "dynamic",
            "--dynamic_time",
            "--output_time_zone",
            output_time_zone,
            "--slice",
            slice_time,
            "--slice_size",
            str(slice_size),
            "--write",
            f"/output/{output_name}",
            f"/timeline/{storage_name}",
        ]
    )
    return command


def psort_query_command(
    image: str,
    timeline_directory: Path,
    storage_name: str,
    output_directory: Path,
    output_name: str,
    event_filter: str,
    output_time_zone: str,
) -> list[str]:
    command = ["docker", "run", "--rm", "--network", "none", "--read-only"]
    command.extend(docker_user_args())
    command.extend(
        [
            "--tmpfs",
            "/tmp:rw,nosuid,size=2g",
            "-e",
            "HOME=/tmp",
            "-v",
            f"{timeline_directory}:/timeline:ro",
            "-v",
            f"{output_directory}:/output:rw",
            image,
            "psort",
            "--unattended",
            "--status_view",
            "linear",
            "--include_all",
            "--logfile",
            f"/output/{output_name}.psort.log.gz",
            "--output_format",
            "dynamic",
            "--dynamic_time",
            "--output_time_zone",
            output_time_zone,
            "--write",
            f"/output/{output_name}",
            f"/timeline/{storage_name}",
            event_filter,
        ]
    )
    return command


def timeline_query(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.plaso_image)
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    if Path(args.storage_name).name != args.storage_name or safe_name(args.storage_name) != args.storage_name:
        raise CaseError("--storage-name must be a safe filename within the timeline directory")
    basename = safe_name(args.name)
    if not basename or basename != args.name:
        raise CaseError("--name must be a safe output basename")
    if not args.filter.strip():
        raise CaseError("--filter cannot be empty")
    any_failure = False
    for source in selected:
        storage_path, timeline_metadata = validated_timeline_metadata(
            case_root, source, args.storage_name
        )
        timeline_root = storage_path.parent
        output_root = source_work_root(case_root, source) / "reports" / "timeline-queries"
        output_root.mkdir(parents=True, exist_ok=True)
        destination = output_root / f"{basename}.csv"
        partial = output_root / f"{basename}.csv.partial"
        metadata_path = output_root / f"{basename}.csv.json"
        if destination.exists() and not args.force:
            print(f"Timeline query already exists; skipping {source['source_name']}: {destination}")
            continue
        if partial.exists():
            if not args.restart:
                raise CaseError(
                    f"Interrupted timeline query exists: {partial}; use --restart to remove only it"
                )
            partial.unlink()
        command = psort_query_command(
            args.plaso_image,
            timeline_root,
            args.storage_name,
            output_root,
            partial.name,
            args.filter,
            args.output_time_zone,
        )
        print(f"Querying Plaso timeline for {source['source_name']}: {args.filter}")
        record = run_recorded(
            case_root,
            f"{source['case_key']}-psort-query-{basename}",
            command,
            output_root / f"{basename}.stdout.log",
            output_root / f"{basename}.stderr.log",
        )
        if record["exit_code"] != 0 or not partial.is_file():
            any_failure = True
            print(f"  query failed with exit {record['exit_code']}; partial retained if present")
            continue
        digest = file_sha256(partial)
        size_bytes = partial.stat().st_size
        os.replace(partial, destination)
        atomic_write_json(
            metadata_path,
            {
                "created_utc": utc_now(),
                "timeline_storage_path": str(storage_path),
                "timeline_storage_sha256": timeline_metadata["sha256"],
                "output_path": str(destination),
                "size_bytes": size_bytes,
                "sha256": digest,
                "image": args.plaso_image,
                "event_filter": args.filter,
                "include_all_events": True,
                "output_time_zone": args.output_time_zone,
                "atomic_completion": True,
                "run": record,
            },
        )
        print(f"Prepared {destination} ({size_bytes} bytes, SHA-256 {digest})")
    return 2 if any_failure else 0


def timeline_slice(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.plaso_image)
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    if args.slice_size < 0:
        raise CaseError("--slice-size must be zero or greater")
    if Path(args.storage_name).name != args.storage_name or safe_name(args.storage_name) != args.storage_name:
        raise CaseError("--storage-name must be a safe filename within the timeline directory")
    any_failure = False
    for source in selected:
        storage_path, timeline_metadata = validated_timeline_metadata(
            case_root, source, args.storage_name
        )
        timeline_root = storage_path.parent
        output_root = source_work_root(case_root, source) / "reports" / "timeline-slices"
        output_root.mkdir(parents=True, exist_ok=True)
        basename = args.name or f"slice-{safe_name(args.slice)}-{args.slice_size}m"
        basename = safe_name(basename)
        if not basename:
            raise CaseError("Timeline slice output name is empty after sanitization")
        destination = output_root / f"{basename}.csv"
        partial = output_root / f"{basename}.csv.partial"
        metadata_path = output_root / f"{basename}.csv.json"
        if destination.exists() and not args.force:
            print(f"Timeline slice already exists; skipping {source['source_name']}: {destination}")
            continue
        if partial.exists():
            if not args.restart:
                raise CaseError(
                    f"Interrupted timeline slice exists: {partial}; use --restart to remove only it"
                )
            partial.unlink()
        command = psort_slice_command(
            args.plaso_image,
            timeline_root,
            args.storage_name,
            output_root,
            partial.name,
            args.slice,
            args.slice_size,
            args.output_time_zone,
        )
        print(f"Exporting Plaso time slice for {source['source_name']} around {args.slice}")
        record = run_recorded(
            case_root,
            f"{source['case_key']}-psort-{basename}",
            command,
            output_root / f"{basename}.stdout.log",
            output_root / f"{basename}.stderr.log",
        )
        if record["exit_code"] != 0 or not partial.is_file():
            any_failure = True
            print(f"  export failed with exit {record['exit_code']}; partial retained if present")
            continue
        digest = file_sha256(partial)
        size_bytes = partial.stat().st_size
        os.replace(partial, destination)
        atomic_write_json(
            metadata_path,
            {
                "created_utc": utc_now(),
                "timeline_storage_path": str(storage_path),
                "timeline_storage_sha256": timeline_metadata["sha256"],
                "output_path": str(destination),
                "size_bytes": size_bytes,
                "sha256": digest,
                "image": args.plaso_image,
                "slice": args.slice,
                "slice_size_minutes": args.slice_size,
                "output_time_zone": args.output_time_zone,
                "atomic_completion": True,
                "run": record,
            },
        )
        print(f"Prepared {destination} ({size_bytes} bytes, SHA-256 {digest})")
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
    build.add_argument("--elf2dmp-image", default=DEFAULT_ELF2DMP_IMAGE)
    build.add_argument("--plaso-image", default=DEFAULT_PLASO_IMAGE)
    build.set_defaults(func=build_tools)

    memory = subparsers.add_parser("memory", help="Run Volatility information or baseline plugins")
    memory.add_argument("--case-root", required=True)
    memory.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    memory.add_argument("--plugin", action="append", help="Override plugin list; repeat as needed")
    memory.add_argument("--info-only", action="store_true", help="Run only windows.info")
    memory.add_argument(
        "--extended",
        action="store_true",
        help="Add cross-view, console, persistence, and process-tampering plugins",
    )
    memory.add_argument(
        "--allow-network",
        action="store_true",
        help="Allow outbound access for symbol resolution; evidence remains mounted read-only",
    )
    memory.add_argument("--volatility-image", default=DEFAULT_VOLATILITY_IMAGE)
    memory.add_argument("--input", choices=("original", "converted"), default="original")
    memory.add_argument(
        "--parallelism",
        choices=("off", "threads", "processes"),
        default="off",
        help="Volatility parallelism mode",
    )
    memory.set_defaults(func=run_memory_plugins)

    convert = subparsers.add_parser(
        "memory-convert", help="Convert verified QEMU ELF memory to a derived Windows dump"
    )
    convert.add_argument("--case-root", required=True)
    convert.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    convert.add_argument("--elf2dmp-image", default=DEFAULT_ELF2DMP_IMAGE)
    convert.add_argument(
        "--allow-network",
        action="store_true",
        help="Allow QEMU elf2dmp to retrieve the required Microsoft PDB",
    )
    convert.add_argument("--restart", action="store_true", help="Remove only an interrupted conversion")
    convert.add_argument("--force", action="store_true", help="Atomically replace a completed conversion")
    convert.set_defaults(func=convert_memory)

    layout = subparsers.add_parser("disk-layout", help="Record partition layouts with The Sleuth Kit")
    layout.add_argument("--case-root", required=True)
    layout.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    layout.add_argument("--tsk-image", default=DEFAULT_TSK_IMAGE)
    layout.set_defaults(func=disk_layout)

    filesystems = subparsers.add_parser(
        "disk-filesystems", help="Record filesystem metadata for allocated partitions"
    )
    filesystems.add_argument("--case-root", required=True)
    filesystems.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    filesystems.add_argument("--tsk-image", default=DEFAULT_TSK_IMAGE)
    filesystems.set_defaults(func=disk_filesystems)

    recover = subparsers.add_parser(
        "disk-recover", help="Recover allocated files from a partition with The Sleuth Kit"
    )
    recover.add_argument("--case-root", required=True)
    recover.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    recover.add_argument("--offset", required=True, type=int, help="Partition start sector")
    recover.add_argument(
        "--directory-inum",
        type=int,
        help="Recover only this directory inode and its descendants",
    )
    recover.add_argument("--tsk-image", default=DEFAULT_TSK_IMAGE)
    recover.add_argument("--restart", action="store_true", help="Remove only an interrupted recovery")
    recover.set_defaults(func=recover_disk_files)

    timeline = subparsers.add_parser("timeline", help="Build an atomic Plaso disk timeline")
    timeline.add_argument("--case-root", required=True)
    timeline.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    timeline.add_argument("--plaso-image", default=DEFAULT_PLASO_IMAGE)
    timeline.add_argument("--partitions", default="all")
    timeline.add_argument("--vss-stores", default="none")
    timeline.add_argument("--restart", action="store_true", help="Remove only an interrupted timeline")
    timeline.add_argument("--force", action="store_true", help="Replace a completed derived timeline")
    timeline.set_defaults(func=disk_timeline)

    recovered_timeline = subparsers.add_parser(
        "timeline-recovered", help="Build Plaso storage from an atomic TSK recovery directory"
    )
    recovered_timeline.add_argument("--case-root", required=True)
    recovered_timeline.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    recovered_timeline.add_argument("--offset", required=True, type=int)
    recovered_timeline.add_argument(
        "--directory-inum",
        type=int,
        help="Use the matching directory-scoped TSK recovery",
    )
    recovered_timeline.add_argument("--plaso-image", default=DEFAULT_PLASO_IMAGE)
    recovered_timeline.add_argument(
        "--file-filter",
        help="Optional Plaso include filter; mounted as one read-only file and hashed",
    )
    recovered_timeline.add_argument("--restart", action="store_true")
    recovered_timeline.add_argument("--force", action="store_true")
    recovered_timeline.set_defaults(func=recovered_disk_timeline)

    slice_parser = subparsers.add_parser(
        "timeline-slice", help="Export an atomic CSV time slice from a completed Plaso timeline"
    )
    slice_parser.add_argument("--case-root", required=True)
    slice_parser.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    slice_parser.add_argument("--plaso-image", default=DEFAULT_PLASO_IMAGE)
    slice_parser.add_argument("--storage-name", default="timeline.plaso")
    slice_parser.add_argument(
        "--slice", required=True, help="ISO 8601 center time including a UTC offset"
    )
    slice_parser.add_argument("--slice-size", type=int, default=10, help="Minutes before and after")
    slice_parser.add_argument("--output-time-zone", default="UTC")
    slice_parser.add_argument("--name", help="Optional safe output basename")
    slice_parser.add_argument("--restart", action="store_true", help="Remove only an interrupted export")
    slice_parser.add_argument("--force", action="store_true", help="Replace a completed slice export")
    slice_parser.set_defaults(func=timeline_slice)

    query_parser = subparsers.add_parser(
        "timeline-query", help="Export events matching a Plaso event-filter expression"
    )
    query_parser.add_argument("--case-root", required=True)
    query_parser.add_argument("--source", action="append", help="Source name or key; repeat as needed")
    query_parser.add_argument("--plaso-image", default=DEFAULT_PLASO_IMAGE)
    query_parser.add_argument("--storage-name", default="timeline.plaso")
    query_parser.add_argument("--filter", required=True, help="Plaso event-filter expression")
    query_parser.add_argument("--name", required=True, help="Safe output basename")
    query_parser.add_argument("--output-time-zone", default="UTC")
    query_parser.add_argument("--restart", action="store_true", help="Remove only an interrupted export")
    query_parser.add_argument("--force", action="store_true", help="Replace a completed query export")
    query_parser.set_defaults(func=timeline_query)
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
