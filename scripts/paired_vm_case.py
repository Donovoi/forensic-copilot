#!/usr/bin/env python3
"""Preservation-first orchestration for paired VM disk and memory evidence."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import unquote
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


STATE_NAME = "case.json"
CASE_SCHEMA_VERSION = 2
CHUNK_SIZE = 16 * 1024 * 1024
SHA256_RE = re.compile(r"(?i)(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\)]+?))\s*\)")
REQUIRED_REPORT_SECTIONS = (
    "Executive summary",
    "Findings",
    "Conclusions and confidence",
    "Scope and boundaries",
    "Evidence inventory and links",
    "Evidence handling and verification",
    "Examination environment and tools",
    "File carving",
    "Repair attempts",
    "User and owner attribution",
    "Timeline and correlations",
    "Limitations and unresolved questions",
)
REPORT_PLACEHOLDERS = (
    "DRAFT — EXAMINATION INCOMPLETE",
    "Examination initialized.",
    "Findings have not yet been peer reviewed.",
    "No findings recorded yet.",
    "Pending analysis.",
    "Hash verification pending.",
    "Tool preparation pending.",
    "Signature-carving analysis pending.",
    "Filesystem damage assessment and safe derivative-repair attempts pending.",
    "Local user analysis and documented best-effort attribution pending.",
)
TERMINAL_WORK_STATUSES = {"completed", "completed_with_limit", "not_applicable"}
WORK_STATUSES = TERMINAL_WORK_STATUSES | {"pending", "running", "blocked", "failed"}
NOT_APPLICABLE_LANES = {"damage_repair_assessment"}
DEFAULT_VOLATILITY_IMAGE = "forensic-copilot/volatility:2.28.0"
DEFAULT_TSK_IMAGE = "forensic-copilot/tsk:ubuntu24.04"
DEFAULT_ELF2DMP_IMAGE = "forensic-copilot/elf2dmp:11.0.2"
DEFAULT_TESTDISK_IMAGE = "forensic-copilot/testdisk:7.2"
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
        raise CaseError(
            f"Evidence symlinks are refused because they can cross scope: {path}"
        )
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
    if (
        evidence_root != resolved_candidate
        and evidence_root not in resolved_candidate.parents
    ):
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
            path
            for path in directory.iterdir()
            if path.is_file() and "hash" in path.name.lower()
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
                "hash_manifests": [
                    evidence_file(path, evidence_root) for path in manifests
                ],
            }
        )
    if not pairs:
        raise CaseError(
            f"No paired .img.gz/.dump evidence directories found in {evidence_root}"
        )
    return pairs


def evidence_item_id(relative_path: str) -> str:
    basename = safe_name(relative_path.replace("/", "-"))[:80]
    suffix = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:10]
    return f"{basename}-{suffix}"


def discover_evidence_inventory(
    evidence_root: Path, pairs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Inventory every regular file while retaining paired-evidence classifications."""
    classifications: dict[str, tuple[str, str, str]] = {}
    for pair in pairs:
        for role in ("disk_gzip", "memory_dump"):
            record = pair[role]
            classifications[record["relative_path"]] = (
                pair["source_name"],
                pair["case_key"],
                role,
            )
        for record in pair["hash_manifests"]:
            classifications[record["relative_path"]] = (
                pair["source_name"],
                pair["case_key"],
                "hash_manifest",
            )

    items: list[dict[str, Any]] = []
    for path in sorted(evidence_root.rglob("*")):
        if path.is_symlink():
            raise CaseError(
                f"Evidence symlinks are refused because they can cross scope: {path}"
            )
        if path.is_dir():
            continue
        if not path.is_file():
            raise CaseError(f"Evidence item is not a regular file: {path}")
        record = evidence_file(path, evidence_root)
        source_name, case_key, role = classifications.get(
            record["relative_path"],
            (
                Path(record["relative_path"]).parts[0]
                if len(Path(record["relative_path"]).parts) > 1
                else "evidence-root",
                safe_name(
                    Path(record["relative_path"]).parts[0]
                    if len(Path(record["relative_path"]).parts) > 1
                    else "evidence-root"
                ),
                "supplemental",
            ),
        )
        items.append(
            {
                "evidence_item_id": evidence_item_id(record["relative_path"]),
                "source_name": source_name,
                "case_key": case_key,
                "role": role,
                **record,
            }
        )
    return items


def required_lanes(role: str) -> tuple[str, ...]:
    if role == "disk_gzip":
        return (
            "integrity",
            "partition_and_filesystem",
            "allocated_file_examination",
            "deleted_unallocated_assessment",
            "damage_repair_assessment",
            "signature_carving",
            "timeline",
            "user_attribution",
            "disk_memory_correlation",
        )
    if role == "memory_dump":
        return (
            "integrity",
            "compatibility_and_os",
            "processes",
            "network",
            "persistence",
            "user_sessions",
            "extended_analysis",
            "disk_memory_correlation",
        )
    if role == "hash_manifest":
        return ("provenance_review",)
    return ("integrity", "examination")


def build_work_items(evidence_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    work_items: list[dict[str, Any]] = []
    for item in evidence_items:
        for lane in required_lanes(item["role"]):
            work_items.append(
                {
                    "work_item_id": f"{item['evidence_item_id']}.{lane}",
                    "evidence_item_id": item["evidence_item_id"],
                    "lane": lane,
                    "required": True,
                    "status": "pending",
                    "artifacts": [],
                    "history": [],
                    "note": None,
                    "updated_utc": None,
                }
            )
    return work_items


def completion_state(
    case_root: Path, evidence_root: Path, state: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    """Upgrade older case state in memory without invalidating existing cases."""
    changed = False
    if "evidence_items" not in state:
        state["evidence_items"] = discover_evidence_inventory(
            evidence_root, state["sources"]
        )
        changed = True
    if "work_items" not in state:
        state["work_items"] = build_work_items(state["evidence_items"])
        changed = True
    if "report" not in state:
        legacy = case_root / "reports" / f"{state['case_id']}.md"
        working = (
            legacy
            if legacy.is_file()
            else case_root / "reports" / f"{state['case_id']}.working.md"
        )
        state["report"] = {
            "status": "working",
            "working_path": str(working),
            "final_path": str(case_root / "reports" / f"{state['case_id']}.final.md"),
        }
        changed = True
    if "lifecycle" not in state:
        state["lifecycle"] = {
            "status": "in_progress",
            "review_bundle_path": None,
            "completion_path": None,
        }
        changed = True
    if state.get("schema_version", 1) < CASE_SCHEMA_VERSION:
        state["schema_version"] = CASE_SCHEMA_VERSION
        changed = True
    return state, changed


def write_case_state(case_root: Path, state: dict[str, Any]) -> None:
    state["updated_utc"] = utc_now()
    atomic_write_json(case_root / STATE_NAME, state)


@contextmanager
def exclusive_file_lock(lock_path: Path):
    """Serialize a filesystem-backed transaction on POSIX and Windows."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as stream:
        if os.name == "posix":
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        else:
            import msvcrt

            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


@contextmanager
def exclusive_case_state_lock(case_root: Path):
    """Serialize read-modify-write updates from concurrent analysis workers."""
    with exclusive_file_lock(case_root / ".case-state.lock"):
        yield


def markdown_evidence_link(report_path: Path, evidence_path: Path, label: str) -> str:
    relative = os.path.relpath(evidence_path, report_path.parent).replace(os.sep, "/")
    safe_label = label.replace("]", "\\]")
    return f"[{safe_label}](<{relative}>)"


def report_stub(
    case_id: str,
    evidence_root: Path,
    case_root: Path,
    pairs: list[dict[str, Any]],
    evidence_items: list[dict[str, Any]] | None = None,
    report_path: Path | None = None,
) -> str:
    report_path = report_path or case_root / "reports" / f"{case_id}.working.md"
    evidence_items = evidence_items or discover_evidence_inventory(evidence_root, pairs)
    inventory = "\n".join(
        "- "
        + markdown_evidence_link(
            report_path,
            evidence_root / item["relative_path"],
            f"{item['source_name']} / {item['name']}",
        )
        + f" — `{item['role']}`; work item `{item['evidence_item_id']}`"
        for item in evidence_items
    )
    return f"""# {case_id} forensic examination

> **DRAFT — EXAMINATION INCOMPLETE.** This working record is not a final report.

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

## Evidence inventory and links

{inventory}

## Evidence handling and verification

Hash verification pending. Machine-readable state is stored in `{STATE_NAME}`.

## Examination environment and tools

Tool preparation pending.

## File carving

Signature-carving analysis pending.

## Repair attempts

Filesystem damage assessment and safe derivative-repair attempts pending.

## User and owner attribution

Local user analysis and documented best-effort attribution pending.

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
    case_id = safe_name(args.case_id)
    if state_path.exists() and not args.force:
        raise CaseError(f"Case already initialized: {state_path}")
    if args.force:
        final_path = case_root / "reports" / f"{case_id}.final.md"
        completion_path = case_root / "completion.json"
        if final_path.exists() or completion_path.exists():
            raise CaseError(
                "Forced reinitialization is refused when finalized artifacts exist; "
                "use a new case root or case ID"
            )
        allowed_files = {
            state_path,
            case_root / ".case-state.lock",
            case_root / "reports" / f"{case_id}.working.md",
        }
        unexpected_files = (
            [
                path
                for path in case_root.rglob("*")
                if (path.is_file() or path.is_symlink()) and path not in allowed_files
            ]
            if case_root.is_dir()
            else []
        )
        if unexpected_files:
            raise CaseError(
                "Forced reinitialization is refused because the case root contains "
                "analysis or provenance files; use a new case root instead: "
                + ", ".join(str(path) for path in unexpected_files[:5])
            )

    pairs = discover_pairs(evidence_root)
    evidence_items = discover_evidence_inventory(evidence_root, pairs)
    case_root.mkdir(parents=True, exist_ok=True)
    for name in ("logs", "reports", "reviews", "tool-cache", "tooling"):
        (case_root / name).mkdir(exist_ok=True)
    for pair in pairs:
        source_root = case_root / "sources" / pair["case_key"]
        for relative in (
            "disk/working",
            "disk/metadata",
            "memory",
            "timeline",
            "exports",
        ):
            (source_root / relative).mkdir(parents=True, exist_ok=True)

    working_report_path = case_root / "reports" / f"{case_id}.working.md"
    final_report_path = case_root / "reports" / f"{case_id}.final.md"
    state = {
        "schema_version": CASE_SCHEMA_VERSION,
        "case_id": case_id,
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
        "evidence_items": evidence_items,
        "work_items": build_work_items(evidence_items),
        "report": {
            "status": "working",
            "working_path": str(working_report_path),
            "final_path": str(final_report_path),
        },
        "lifecycle": {
            "status": "in_progress",
            "review_bundle_path": None,
            "completion_path": None,
        },
    }
    atomic_write_json(state_path, state)
    atomic_write_text(
        working_report_path,
        report_stub(
            state["case_id"],
            evidence_root,
            case_root,
            pairs,
            evidence_items,
            working_report_path,
        ),
    )
    print(f"Initialized {state['case_id']} with {len(pairs)} paired source(s)")
    print(f"State: {state_path}")
    print(f"Working draft: {working_report_path}")
    print("Final report: not created until finalize-report passes")
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
    state, _ = completion_state(case_root, evidence_root, state)
    return case_root, evidence_root, state


def select_sources(
    state: dict[str, Any], requested: Iterable[str] | None
) -> list[dict[str, Any]]:
    sources = state["sources"]
    names = set(requested or [])
    if not names:
        return sources
    selected = [
        source
        for source in sources
        if source["source_name"] in names or source["case_key"] in names
    ]
    missing = sorted(
        names
        - {item["source_name"] for item in selected}
        - {item["case_key"] for item in selected}
    )
    if missing:
        raise CaseError(f"Unknown source selector(s): {', '.join(missing)}")
    return selected


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def hash_and_test_gzip_stream(
    path: Path, output_path: Path | None = None
) -> dict[str, Any]:
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
            "compressed_bytes_read": digesting_stream.bytes_read
            if digesting_stream
            else 0,
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
        without_digest = (line[: match.start()] + " " + line[match.end() :]).strip(
            " *:\t"
        )
        candidate = without_digest.removeprefix("sha256").strip(" *:\t")
        filename = Path(candidate).name if candidate else pending_filename
        if filename:
            results[filename] = digest
        pending_filename = None
    return results


def verify_case(args: argparse.Namespace) -> int:
    case_root, evidence_root, state = load_case(args.case_root)
    if state["lifecycle"].get("status") == "finalized":
        raise CaseError("Case is finalized; integrity state cannot be changed")
    selected = select_sources(state, args.source)
    if args.skip_gzip_test and getattr(args, "prepare_working_disks", False):
        raise CaseError(
            "--prepare-working-disks cannot be combined with --skip-gzip-test"
        )
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
                current_stat.st_size != record["size_bytes"]
                or current_mtime != record["mtime_utc"]
            )
            if inventory_changed:
                overall_ok = False
            action = (
                "Hashing and validating"
                if role == "disk_gzip" and not args.skip_gzip_test
                else "Hashing"
            )
            print(
                f"{action} {source['source_name']}/{record['name']} ({record['size_bytes']} bytes)"
            )
            started = time.monotonic()
            gzip_test = None
            working_copy: dict[str, Any] | None = None
            if role == "disk_gzip" and not args.skip_gzip_test:
                partial = None
                destination = None
                metadata_path = None
                if getattr(args, "prepare_working_disks", False):
                    free = shutil.disk_usage(case_root).free
                    required_free = int(
                        getattr(args, "minimum_free_gib", 200.0) * 1024**3
                    )
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
    update_integrity_work_items(case_root, output, destination)
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
        raise CaseError(
            f"Working disk metadata cannot be read: {metadata_path}: {exc}"
        ) from exc
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
        raise CaseError(
            f"Working disk metadata lacks atomic completion: {metadata_path}"
        )
    if not SHA256_RE.fullmatch(str(metadata.get("sha256", ""))):
        raise CaseError(f"Working disk metadata lacks a valid SHA-256: {metadata_path}")
    return metadata


def require_verified_integrity(
    case_root: Path, selected: list[dict[str, Any]]
) -> dict[str, Any]:
    integrity_path = case_root / "integrity.json"
    if not integrity_path.is_file():
        raise CaseError(f"Integrity gate has not run: {integrity_path}")
    integrity = json.loads(integrity_path.read_text(encoding="utf-8"))
    if integrity.get("status") != "verified":
        raise CaseError(
            f"Integrity gate is not verified: {integrity.get('status', 'unknown')}"
        )
    by_name = {item["source_name"]: item for item in integrity.get("sources", [])}
    for source in selected:
        result = by_name.get(source["source_name"])
        if not result:
            raise CaseError(
                f"Integrity result is missing source: {source['source_name']}"
            )
        roles = {item.get("role"): item for item in result.get("items", [])}
        for role in ("disk_gzip", "memory_dump"):
            item = roles.get(role)
            if not item:
                raise CaseError(
                    f"Integrity result is missing {source['source_name']}/{role}"
                )
            if item.get("manifest_status") == "mismatch":
                raise CaseError(
                    f"Integrity mismatch for {source['source_name']}/{role}"
                )
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
            print(
                f"Working disk already exists; skipping {source['source_name']}: {destination}"
            )
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
            with (
                gzip.open(source_path, "rb") as source_stream,
                partial.open("xb") as output_stream,
            ):
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
            print(
                f"Partial output retained for explicit review: {partial}",
                file=sys.stderr,
            )
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
    with (
        stdout_path.open("w", encoding="utf-8", errors="replace") as stdout,
        stderr_path.open("w", encoding="utf-8", errors="replace") as stderr,
    ):
        completed = subprocess.run(
            command, stdout=stdout, stderr=stderr, text=True, check=False
        )
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
        (
            "testdisk",
            args.testdisk_image,
            repo_root / "tooling" / "paired-vm" / "Dockerfile.testdisk",
        ),
    )
    results = []
    for name, tag, dockerfile in definitions:
        if not dockerfile.is_file():
            raise CaseError(f"Dockerfile not found: {dockerfile}")
        command = [
            "docker",
            "build",
            "--pull",
            "-t",
            tag,
            "-f",
            str(dockerfile),
            str(repo_root),
        ]
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
            raise CaseError(
                f"Docker build failed for {name}; see {record['stderr_path']}"
            )

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
        raise CaseError(
            f"Docker pull failed for Plaso; see {plaso_pull['stderr_path']}"
        )

    inspect = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            args.volatility_image,
            args.tsk_image,
            args.elf2dmp_image,
            args.testdisk_image,
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
        "testdisk": [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            args.testdisk_image,
            "testdisk",
            "/version",
        ],
        "photorec": [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            args.testdisk_image,
            "photorec",
            "/version",
        ],
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
            raise CaseError(
                f"Version check failed for {name}: {completed.stderr.strip()}"
            )
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
        raise CaseError(
            f"Converted dump metadata cannot be read: {metadata_path}: {exc}"
        ) from exc
    if metadata.get("source_relative_path") != source["memory_dump"]["relative_path"]:
        raise CaseError(f"Converted dump source mismatch: {metadata_path}")
    if resolved(metadata.get("converted_path", "")) != dump_path.resolve():
        raise CaseError(f"Converted dump path mismatch: {metadata_path}")
    if metadata.get("size_bytes") != dump_path.stat().st_size:
        raise CaseError(f"Converted dump size does not match its metadata: {dump_path}")
    if not metadata.get("atomic_completion"):
        raise CaseError(
            f"Converted dump metadata lacks atomic completion: {metadata_path}"
        )
    if not SHA256_RE.fullmatch(str(metadata.get("sha256", ""))):
        raise CaseError(
            f"Converted dump metadata lacks a valid SHA-256: {metadata_path}"
        )
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
            item
            for item in source_integrity["items"]
            if item.get("role") == "memory_dump"
        )
        conversion_root = source_work_root(case_root, source) / "memory" / "converted"
        conversion_root.mkdir(parents=True, exist_ok=True)
        destination = conversion_root / "windows.dmp"
        partial = conversion_root / "windows.dmp.partial"
        metadata_path = conversion_root / "windows.dmp.json"
        if destination.exists() and not args.force:
            validated_converted_memory_metadata(case_root, source)
            print(
                f"Converted dump already exists; skipping {source['source_name']}: {destination}"
            )
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
            print(
                f"  conversion failed with exit {record['exit_code']}; partial retained if present"
            )
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
        return (
            f"custom-{len(args.plugin)}-{hashlib.sha256(plugin_key).hexdigest()[:12]}"
        )
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
        output_root = (
            source_work_root(case_root, source) / "memory" / f"analysis-{args.input}"
        )
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
                print(
                    f"  failed with exit {record['exit_code']}; continuing independent plugins"
                )
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
            raise CaseError(
                f"Partition layout is missing; run disk-layout first: {mmls_path}"
            )
        partitions = parse_mmls_partitions(
            mmls_path.read_text(encoding="utf-8", errors="replace")
        )
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
            print(
                f"Reading filesystem metadata for {source['source_name']} at sector {offset}"
            )
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
            {
                "completed_utc": utc_now(),
                "source_name": source["source_name"],
                "runs": runs,
            },
        )
    return 2 if any_failure else 0


def tsk_recover_command(
    image: str,
    disk_directory: Path,
    output_directory: Path,
    partial_name: str,
    offset: int,
    directory_inum: int | None = None,
    recovery_scope: str = "allocated",
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
        ]
    )
    if recovery_scope == "allocated":
        command.append("-a")
    elif recovery_scope == "all":
        command.append("-e")
    elif recovery_scope != "unallocated":
        raise CaseError(f"Unsupported TSK recovery scope: {recovery_scope}")
    command.extend(["-i", "raw", "-o", str(offset)])
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
                raise CaseError(
                    f"Recovered tree contains a symlink: {directory_path / name}"
                )
        for name in file_names:
            path = directory_path / name
            if path.is_symlink():
                raise CaseError(f"Recovered tree contains a symlink: {path}")
            file_count += 1
            size_bytes += path.stat().st_size
    return file_count, size_bytes


def recovery_basename(
    offset: int,
    directory_inum: int | None = None,
    recovery_scope: str = "allocated",
) -> str:
    basename = f"offset-{offset}"
    if directory_inum is not None:
        basename = f"{basename}-dir-{directory_inum}"
    if recovery_scope != "allocated":
        basename = f"{basename}-{safe_name(recovery_scope)}"
    return basename


def validated_recovered_directory_metadata(
    case_root: Path,
    source: dict[str, Any],
    offset: int,
    directory_inum: int | None = None,
    recovery_scope: str = "allocated",
) -> tuple[Path, dict[str, Any]]:
    recovery_root = source_work_root(case_root, source) / "disk" / "recovered"
    basename = recovery_basename(offset, directory_inum, recovery_scope)
    destination = recovery_root / basename
    metadata_path = recovery_root / f"{basename}.json"
    if not destination.is_dir() or not metadata_path.is_file():
        raise CaseError(
            f"Completed TSK recovery is missing; run disk-recover first: {destination}"
        )
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise CaseError(
            f"Recovery metadata cannot be read: {metadata_path}: {exc}"
        ) from exc
    if resolved(metadata.get("recovered_path", "")) != destination.resolve():
        raise CaseError(f"Recovered directory path mismatch: {metadata_path}")
    if metadata.get("offset_sector") != offset:
        raise CaseError(f"Recovered directory offset mismatch: {metadata_path}")
    if metadata.get("directory_inum") != directory_inum:
        raise CaseError(f"Recovered directory inode mismatch: {metadata_path}")
    recorded_scope = metadata.get(
        "recovery_scope",
        "allocated" if metadata.get("allocated_files_only") is True else None,
    )
    if recorded_scope != recovery_scope:
        raise CaseError(f"Recovered directory scope mismatch: {metadata_path}")
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
        basename = recovery_basename(
            args.offset, args.directory_inum, args.recovery_scope
        )
        destination = recovery_root / basename
        partial = recovery_root / f"{basename}.partial"
        metadata_path = recovery_root / f"{basename}.json"
        manifest_path = recovery_root / f"{basename}.sha256"
        if destination.exists():
            validated_recovered_directory_metadata(
                case_root,
                source,
                args.offset,
                args.directory_inum,
                args.recovery_scope,
            )
            print(
                f"Recovered directory already exists; skipping {source['source_name']}: {destination}"
            )
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
            args.recovery_scope,
        )
        target_scope = (
            f"directory inode {args.directory_inum}"
            if args.directory_inum
            else "volume"
        )
        print(
            f"Recovering {args.recovery_scope} files for {source['source_name']} at "
            f"sector {args.offset} ({target_scope})"
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
            print(
                f"  recovery failed with exit {record['exit_code']}; partial retained if present"
            )
            continue
        print(f"Hashing recovered tree for {source['source_name']}")
        manifest = write_carving_manifest(partial, manifest_path)
        file_count = manifest["file_count"]
        size_bytes = manifest["logical_size_bytes"]
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
                "recovery_scope": args.recovery_scope,
                "allocated_files_only": args.recovery_scope == "allocated",
                "file_count": file_count,
                "logical_size_bytes": size_bytes,
                "manifest_path": str(manifest_path),
                "manifest_sha256": manifest["manifest_sha256"],
                "extension_counts": manifest["extension_counts"],
                "image": args.tsk_image,
                "atomic_completion": True,
                "run": record,
            },
        )
        lane = (
            "allocated_file_examination"
            if args.recovery_scope == "allocated"
            else "deleted_unallocated_assessment"
        )
        record_work_result(
            argparse.Namespace(
                case_root=str(case_root),
                work_item=evidence_lane_id(state, source, "disk_gzip", lane),
                status="completed",
                artifact=[str(metadata_path), str(manifest_path)],
                note=None,
            )
        )
        print(
            f"Prepared {destination} ({file_count} files, {size_bytes} logical bytes)"
        )
    return 2 if any_failure else 0


def manifest_completed_recovery(args: argparse.Namespace) -> int:
    """Retrofit a content manifest onto an already completed recovery tree."""
    case_root, _, state = load_case(args.case_root)
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    for source in selected:
        source_root = source_work_root(case_root, source)
        disk_metadata = validated_working_disk_metadata(case_root, source)
        recovery_root = source_root / "disk" / "recovered"
        basename = recovery_basename(
            args.offset, args.directory_inum, args.recovery_scope
        )
        metadata_path = recovery_root / f"{basename}.json"
        manifest_path = recovery_root / f"{basename}.sha256"
        lock_path = recovery_root / f".{basename}.manifest.lock"
        with exclusive_file_lock(lock_path):
            destination, metadata = validated_recovered_directory_metadata(
                case_root,
                source,
                args.offset,
                args.directory_inum,
                args.recovery_scope,
            )
            run = metadata.get("run")
            if not isinstance(run, dict) or run.get("exit_code") != 0:
                raise CaseError(
                    f"Completed recovery lacks a successful recorded run: {metadata_path}"
                )
            recorded_disk_hash = metadata.get("source_working_disk_sha256")
            if recorded_disk_hash and recorded_disk_hash != disk_metadata["sha256"]:
                raise CaseError(
                    f"Recovery source hash does not match the verified working disk: {metadata_path}"
                )
            if manifest_path.exists():
                if metadata.get("manifest_path") != str(manifest_path):
                    raise CaseError(
                        f"Recovery manifest exists but metadata is not bound to it: {metadata_path}"
                    )
                if metadata.get("manifest_sha256") != file_sha256(manifest_path):
                    raise CaseError(
                        f"Recovery manifest hash does not match metadata: {manifest_path}"
                    )
                print(
                    f"Recovery manifest already exists; reusing {source['source_name']}: "
                    f"{manifest_path}"
                )
            else:
                print(f"Hashing completed recovery tree for {source['source_name']}")
                summary = write_carving_manifest(destination, manifest_path)
                for field in ("file_count", "logical_size_bytes"):
                    recorded_value = metadata.get(field)
                    if recorded_value is not None and recorded_value != summary[field]:
                        manifest_path.unlink(missing_ok=True)
                        raise CaseError(
                            f"Recovered tree {field} changed since completion: "
                            f"recorded {recorded_value}, found {summary[field]}"
                        )
                metadata.update(
                    {
                        "source_working_disk_sha256": disk_metadata["sha256"],
                        "file_count": summary["file_count"],
                        "logical_size_bytes": summary["logical_size_bytes"],
                        "manifest_path": str(manifest_path),
                        "manifest_sha256": summary["manifest_sha256"],
                        "extension_counts": summary["extension_counts"],
                        "manifested_utc": utc_now(),
                    }
                )
                atomic_write_json(metadata_path, metadata)
        lane = (
            "allocated_file_examination"
            if args.recovery_scope == "allocated"
            else "deleted_unallocated_assessment"
        )
        record_work_result(
            argparse.Namespace(
                case_root=str(case_root),
                work_item=evidence_lane_id(state, source, "disk_gzip", lane),
                status="completed",
                artifact=[str(metadata_path), str(manifest_path)],
                note=None,
            )
        )
        print(f"Manifested completed recovery: {manifest_path}")
    return 0


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
            with gzip.open(
                internal_log_path, "rt", encoding="utf-8", errors="replace"
            ) as stream:
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
                print(
                    f"Timeline already exists; skipping {source['source_name']}: {destination}"
                )
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
            print(
                f"  failed with exit {record['exit_code']}; partial output retained if present"
            )
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
            raise CaseError(
                f"Plaso file filter must be a regular, non-symlink file: {candidate}"
            )
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
            print(
                f"Recovered-files timeline already exists; skipping {source['source_name']}"
            )
            continue
        if partial.exists():
            if not args.restart:
                raise CaseError(
                    f"Interrupted recovered-files timeline exists: {partial}; use --restart"
                )
            partial.unlink()
        command = plaso_recovered_command(
            args.plaso_image,
            recovered_directory,
            output_root,
            partial.name,
            file_filter,
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
            print(
                f"  failed with exit {record['exit_code']}; partial retained if present"
            )
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
                "source_working_disk_sha256": recovery_metadata[
                    "source_working_disk_sha256"
                ],
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
        raise CaseError(
            f"Completed Plaso timeline is missing; run timeline first: {storage_path}"
        )
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise CaseError(
            f"Timeline metadata cannot be read: {metadata_path}: {exc}"
        ) from exc
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
    if (
        Path(args.storage_name).name != args.storage_name
        or safe_name(args.storage_name) != args.storage_name
    ):
        raise CaseError(
            "--storage-name must be a safe filename within the timeline directory"
        )
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
        output_root = (
            source_work_root(case_root, source) / "reports" / "timeline-queries"
        )
        output_root.mkdir(parents=True, exist_ok=True)
        destination = output_root / f"{basename}.csv"
        partial = output_root / f"{basename}.csv.partial"
        metadata_path = output_root / f"{basename}.csv.json"
        if destination.exists() and not args.force:
            print(
                f"Timeline query already exists; skipping {source['source_name']}: {destination}"
            )
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
            print(
                f"  query failed with exit {record['exit_code']}; partial retained if present"
            )
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
    if (
        Path(args.storage_name).name != args.storage_name
        or safe_name(args.storage_name) != args.storage_name
    ):
        raise CaseError(
            "--storage-name must be a safe filename within the timeline directory"
        )
    any_failure = False
    for source in selected:
        storage_path, timeline_metadata = validated_timeline_metadata(
            case_root, source, args.storage_name
        )
        timeline_root = storage_path.parent
        output_root = (
            source_work_root(case_root, source) / "reports" / "timeline-slices"
        )
        output_root.mkdir(parents=True, exist_ok=True)
        basename = args.name or f"slice-{safe_name(args.slice)}-{args.slice_size}m"
        basename = safe_name(basename)
        if not basename:
            raise CaseError("Timeline slice output name is empty after sanitization")
        destination = output_root / f"{basename}.csv"
        partial = output_root / f"{basename}.csv.partial"
        metadata_path = output_root / f"{basename}.csv.json"
        if destination.exists() and not args.force:
            print(
                f"Timeline slice already exists; skipping {source['source_name']}: {destination}"
            )
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
        print(
            f"Exporting Plaso time slice for {source['source_name']} around {args.slice}"
        )
        record = run_recorded(
            case_root,
            f"{source['case_key']}-psort-{basename}",
            command,
            output_root / f"{basename}.stdout.log",
            output_root / f"{basename}.stderr.log",
        )
        if record["exit_code"] != 0 or not partial.is_file():
            any_failure = True
            print(
                f"  export failed with exit {record['exit_code']}; partial retained if present"
            )
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


def photorec_command(
    image: str,
    disk_directory: Path,
    output_directory: Path,
    output_name: str = "carved",
) -> list[str]:
    """Build a whole-image signature-carving command with read-only evidence."""
    user_args = (
        ["--user", f"{os.getuid()}:{os.getgid()}"]
        if hasattr(os, "getuid") and hasattr(os, "getgid")
        else []
    )
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        *user_args,
        "-v",
        f"{disk_directory}:/evidence:ro",
        "-v",
        f"{output_directory}:/output:rw",
        "-w",
        "/output",
        image,
        "photorec",
        "/log",
        "/debug",
        "/d",
        f"/output/{output_name}",
        "/cmd",
        "/evidence/disk.raw",
        (
            "partition_none,options,paranoid,keep_corrupted_file,"
            "fileopt,everything,enable,wholespace,search"
        ),
    ]


def write_carving_manifest(root: Path, destination: Path) -> dict[str, Any]:
    """Hash every carved file and return reproducible summary statistics."""
    digest = hashlib.sha256()
    file_count = 0
    logical_size_bytes = 0
    extension_counts: dict[str, int] = {}
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".tmp")
    with partial.open("x", encoding="utf-8", newline="\n") as stream:
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            if path.is_symlink():
                raise CaseError(f"Carving output contains a symlink: {path}")
            relative = path.relative_to(root).as_posix()
            size_bytes = path.stat().st_size
            sha256 = file_sha256(path)
            line = f"{sha256}  {size_bytes}  {relative}\n"
            stream.write(line)
            digest.update(line.encode("utf-8"))
            file_count += 1
            logical_size_bytes += size_bytes
            extension = path.suffix.lower() or "[no-extension]"
            extension_counts[extension] = extension_counts.get(extension, 0) + 1
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(partial, destination)
    return {
        "file_count": file_count,
        "logical_size_bytes": logical_size_bytes,
        "manifest_path": str(destination),
        "manifest_sha256": digest.hexdigest(),
        "extension_counts": dict(sorted(extension_counts.items())),
    }


def evidence_lane_id(
    state: dict[str, Any], source: dict[str, Any], role: str, lane: str
) -> str:
    evidence = [
        item
        for item in state["evidence_items"]
        if item.get("case_key") == source["case_key"] and item.get("role") == role
    ]
    if len(evidence) != 1:
        raise CaseError(
            f"Expected one {role} evidence item for {source['source_name']}; found {len(evidence)}"
        )
    return f"{evidence[0]['evidence_item_id']}.{lane}"


def carve_disks(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.testdisk_image)
    selected = select_sources(state, args.source)
    require_verified_integrity(case_root, selected)
    any_failure = False
    for source in selected:
        source_root = source_work_root(case_root, source)
        disk_metadata = validated_working_disk_metadata(case_root, source)
        disk_directory = source_root / "disk" / "working"
        carving_root = source_root / "disk" / "carving"
        destination = carving_root / "photorec-whole-disk"
        partial = carving_root / "photorec-whole-disk.partial"
        metadata_path = carving_root / "photorec-whole-disk.json"
        manifest_path = carving_root / "photorec-whole-disk.sha256"
        if destination.exists() or metadata_path.exists() or manifest_path.exists():
            raise CaseError(
                f"Completed carving output already exists for {source['source_name']}: {destination}"
            )
        if partial.exists():
            if not args.restart:
                raise CaseError(
                    f"Interrupted carving output exists: {partial}; use --restart to remove only it"
                )
            shutil.rmtree(partial)
        partial.mkdir(parents=True)
        command = photorec_command(
            args.testdisk_image, disk_directory, partial, "carved"
        )
        record = run_recorded(
            case_root,
            f"{source['case_key']}-photorec-whole-disk",
            command,
            carving_root / "photorec-whole-disk.stdout.log",
            carving_root / "photorec-whole-disk.stderr.log",
        )
        if record["exit_code"] != 0:
            any_failure = True
            print(
                f"PhotoRec failed for {source['source_name']} with exit {record['exit_code']}; partial retained"
            )
            continue
        photorec_log = partial / "photorec.log"
        if (
            not photorec_log.is_file()
            or "PhotoRec exited normally."
            not in photorec_log.read_text(encoding="utf-8", errors="replace")
        ):
            any_failure = True
            print(
                f"PhotoRec did not record a normal exit for {source['source_name']}; "
                "partial retained"
            )
            continue
        summary = write_carving_manifest(partial, manifest_path)
        os.replace(partial, destination)
        metadata = {
            "created_utc": utc_now(),
            "source_working_disk": str(disk_directory / "disk.raw"),
            "source_working_disk_sha256": disk_metadata["sha256"],
            "scope": "whole raw disk",
            "method": "PhotoRec signature carving with paranoid validation",
            "output_path": str(destination),
            "tool_image": args.testdisk_image,
            "atomic_completion": True,
            "limitations": (
                "Carved files do not by themselves establish original path, timestamps, "
                "account ownership, or completeness; fragmented files can be partial."
            ),
            **summary,
            "run": record,
        }
        atomic_write_json(metadata_path, metadata)
        record_work_result(
            argparse.Namespace(
                case_root=str(case_root),
                work_item=evidence_lane_id(
                    state, source, "disk_gzip", "signature_carving"
                ),
                status="completed",
                artifact=[str(metadata_path), str(manifest_path)],
                note=None,
            )
        )
        print(
            f"Prepared {destination} ({summary['file_count']} files, "
            f"{summary['logical_size_bytes']} logical bytes)"
        )
    return 2 if any_failure else 0


def finalize_external_carving(args: argparse.Namespace) -> int:
    """Promote a completed PhotoRec partial launched by an external supervisor."""
    case_root, _, state = load_case(args.case_root)
    selected = select_sources(state, args.source)
    if len(selected) != 1:
        raise CaseError(
            "carve-finalize-external requires exactly one --source because one "
            "supervisor exit and run log cannot prove multiple independent runs"
        )
    require_verified_integrity(case_root, selected)
    if args.exit_code != 0:
        raise CaseError(
            "External PhotoRec exit code is not zero; partial must be retained"
        )
    run_log = resolved(args.run_log)
    if not run_log.is_relative_to(case_root) or not run_log.is_file():
        raise CaseError("--run-log must be a regular file inside the case root")
    run_log_text = run_log.read_text(encoding="utf-8", errors="replace")
    run_log_normal_exit = "PhotoRec exited normally." in run_log_text

    for source in selected:
        source_root = source_work_root(case_root, source)
        disk_metadata = validated_working_disk_metadata(case_root, source)
        disk_directory = source_root / "disk" / "working"
        carving_root = source_root / "disk" / "carving"
        destination = carving_root / "photorec-whole-disk"
        partial = carving_root / "photorec-whole-disk.partial"
        metadata_path = carving_root / "photorec-whole-disk.json"
        manifest_path = carving_root / "photorec-whole-disk.sha256"
        if destination.exists() or metadata_path.exists() or manifest_path.exists():
            raise CaseError(
                f"Completed carving output already exists for {source['source_name']}: {destination}"
            )
        if not partial.is_dir():
            raise CaseError(f"PhotoRec partial is missing: {partial}")
        photorec_log = partial / "photorec.log"
        if (
            not photorec_log.is_file()
            or "PhotoRec exited normally."
            not in photorec_log.read_text(encoding="utf-8", errors="replace")
        ):
            raise CaseError(f"PhotoRec output lacks a normal-exit log: {photorec_log}")

        print(f"Hashing completed PhotoRec output for {source['source_name']}")
        summary = write_carving_manifest(partial, manifest_path)
        os.replace(partial, destination)
        log_record = work_artifact_record(
            str(run_log), case_root, resolved(state["evidence_root"])
        )
        metadata = {
            "created_utc": utc_now(),
            "source_working_disk": str(disk_directory / "disk.raw"),
            "source_working_disk_sha256": disk_metadata["sha256"],
            "scope": "whole raw disk",
            "method": "PhotoRec signature carving with paranoid validation",
            "output_path": str(destination),
            "tool_image": args.testdisk_image,
            "atomic_completion": True,
            "limitations": (
                "Carved files do not by themselves establish original path, timestamps, "
                "account ownership, or completeness; fragmented files can be partial."
            ),
            **summary,
            "run": {
                "supervisor": "external",
                "declared_exit_code": args.exit_code,
                "run_log": log_record,
                "run_log_normal_exit_marker": run_log_normal_exit,
                "normal_exit_marker_verified": True,
                "expected_command_shape": photorec_command(
                    args.testdisk_image,
                    disk_directory,
                    carving_root / "photorec-whole-disk.partial",
                    "carved",
                ),
            },
        }
        atomic_write_json(metadata_path, metadata)
        record_work_result(
            argparse.Namespace(
                case_root=str(case_root),
                work_item=evidence_lane_id(
                    state, source, "disk_gzip", "signature_carving"
                ),
                status="completed_with_limit",
                artifact=[str(metadata_path), str(manifest_path), str(run_log)],
                note=(
                    "Signature recovery completed and every carved file was hashed; "
                    "original paths/timestamps and completeness cannot be reconstructed "
                    "from signature carving alone."
                ),
            )
        )
        print(
            f"Prepared {destination} ({summary['file_count']} files, "
            f"{summary['logical_size_bytes']} logical bytes)"
        )
    return 0


def copy_partition_range(
    source: Path, destination: Path, offset_bytes: int, length_bytes: int
) -> dict[str, Any]:
    """Create and hash an atomic byte-for-byte partition derivative."""
    if offset_bytes < 0 or length_bytes <= 0:
        raise CaseError(
            "Partition offset must be non-negative and length must be positive"
        )
    if offset_bytes + length_bytes > source.stat().st_size:
        raise CaseError("Requested partition range extends beyond the working disk")
    partial = destination.with_name(destination.name + ".partial")
    if partial.exists():
        raise CaseError(f"Interrupted partition-copy output exists: {partial}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    written = 0
    started = time.monotonic()
    try:
        with source.open("rb") as source_stream, partial.open("xb") as output_stream:
            source_stream.seek(offset_bytes)
            remaining = length_bytes
            while remaining:
                chunk = source_stream.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise CaseError(
                        "Unexpected end of working disk while copying partition"
                    )
                output_stream.write(chunk)
                digest.update(chunk)
                written += len(chunk)
                remaining -= len(chunk)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        os.replace(partial, destination)
    except Exception:
        print(f"Partial partition copy retained: {partial}", file=sys.stderr)
        raise
    return {
        "size_bytes": written,
        "sha256": digest.hexdigest(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def create_repair_copy(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    selected = select_sources(state, args.source)
    if len(selected) != 1:
        raise CaseError("disk-repair-copy requires exactly one --source")
    source = selected[0]
    require_verified_integrity(case_root, selected)
    source_root = source_work_root(case_root, source)
    disk_metadata = validated_working_disk_metadata(case_root, source)
    working_disk = source_root / "disk" / "working" / "disk.raw"
    basename = (
        f"offset-{args.offset}-length-{args.length}-copy-{safe_name(args.copy_id)}"
    )
    repair_root = source_root / "disk" / "repair" / basename
    destination = repair_root / "partition.raw"
    metadata_path = repair_root / "partition.json"
    if repair_root.exists():
        raise CaseError(f"Repair-copy target already exists: {repair_root}")
    result = copy_partition_range(
        working_disk,
        destination,
        args.offset * 512,
        args.length * 512,
    )
    metadata = {
        "created_utc": utc_now(),
        "source_working_disk": str(working_disk),
        "source_working_disk_sha256": disk_metadata["sha256"],
        "offset_sector": args.offset,
        "length_sectors": args.length,
        "copy_id": safe_name(args.copy_id),
        "repair_copy_path": str(destination),
        "pre_repair_sha256": result["sha256"],
        "size_bytes": result["size_bytes"],
        "elapsed_seconds": result["elapsed_seconds"],
        "atomic_completion": True,
        "repair_status": "not_attempted",
    }
    atomic_write_json(metadata_path, metadata)
    print(f"Prepared repair copy: {destination} (SHA-256 {result['sha256']})")
    return 0


def testdisk_repair_command(image: str, repair_root: Path) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{repair_root}:/repair:rw",
        "-w",
        "/repair",
        image,
        "testdisk",
        "/debug",
        "/log",
        "/cmd",
        "/repair/partition.raw",
        "partition_none,advanced,boot,repairmft",
    ]


def changed_sector_ranges(
    original_disk: Path,
    original_offset_bytes: int,
    derivative: Path,
    sector_size: int = 512,
) -> tuple[list[dict[str, int]], int]:
    """Compare a derivative with its source slice and report changed sector runs."""
    derivative_size = derivative.stat().st_size
    if derivative_size == 0:
        raise CaseError("Repair copy is empty")
    if derivative_size % sector_size:
        raise CaseError("Repair copy length is not sector aligned")

    ranges: list[dict[str, int]] = []
    changed_count = 0
    current_start: int | None = None
    current_end: int | None = None
    sector_index = 0
    # Comparing every sector in a large, mostly unchanged partition is needlessly
    # expensive in Python.  Skip equal 8 MiB chunks and inspect sectors only in
    # chunks that differ.  The chunk size is sector-aligned by construction.
    chunk_size = 8 * 1024 * 1024
    with original_disk.open("rb") as original, derivative.open("rb") as repaired:
        original.seek(original_offset_bytes)
        while True:
            right = repaired.read(chunk_size)
            if not right:
                break
            left = original.read(len(right))
            if len(left) != len(right):
                raise CaseError("Source is shorter than the repair copy")
            sectors_in_chunk = len(right) // sector_size
            if left == right:
                if current_start is not None:
                    ranges.append(
                        {
                            "start_sector": current_start,
                            "end_sector": current_end
                            if current_end is not None
                            else current_start,
                        }
                    )
                    current_start = None
                    current_end = None
                sector_index += sectors_in_chunk
                continue

            for offset in range(0, len(right), sector_size):
                left_sector = left[offset : offset + sector_size]
                right_sector = right[offset : offset + sector_size]
                if left_sector != right_sector:
                    changed_count += 1
                    if current_start is None:
                        current_start = sector_index
                    current_end = sector_index
                elif current_start is not None:
                    ranges.append(
                        {
                            "start_sector": current_start,
                            "end_sector": current_end
                            if current_end is not None
                            else current_start,
                        }
                    )
                    current_start = None
                    current_end = None
                sector_index += 1
    if current_start is not None:
        ranges.append(
            {
                "start_sector": current_start,
                "end_sector": current_end if current_end is not None else current_start,
            }
        )
    return ranges, changed_count


def tsk_partition_validation_command(
    image: str,
    repair_root: Path,
    tool: str,
    extra_arguments: Iterable[str] = (),
) -> list[str]:
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "-v",
        f"{repair_root}:/repair:ro",
        image,
        tool,
    ]
    command.extend(extra_arguments)
    command.extend(
        [
            "-i",
            "raw",
            "/repair/partition.raw",
        ]
    )
    return command


def repair_partition_with_testdisk(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    selected = select_sources(state, args.source)
    if len(selected) != 1:
        raise CaseError("disk-repair-testdisk requires exactly one --source")
    source = selected[0]
    basename = (
        f"offset-{args.offset}-length-{args.length}-copy-{safe_name(args.copy_id)}"
    )
    repair_root = source_work_root(case_root, source) / "disk" / "repair" / basename
    with exclusive_file_lock(repair_root / ".repair.lock"):
        return _repair_partition_with_testdisk_locked(args)


def _repair_partition_with_testdisk_locked(args: argparse.Namespace) -> int:
    case_root, _, state = load_case(args.case_root)
    require_command("docker")
    require_docker_image(args.testdisk_image)
    require_docker_image(args.tsk_image)
    selected = select_sources(state, args.source)
    if len(selected) != 1:
        raise CaseError("disk-repair-testdisk requires exactly one --source")
    source = selected[0]
    require_verified_integrity(case_root, selected)
    source_root = source_work_root(case_root, source)
    working_disk = source_root / "disk" / "working" / "disk.raw"
    working_metadata = validated_working_disk_metadata(case_root, source)
    basename = (
        f"offset-{args.offset}-length-{args.length}-copy-{safe_name(args.copy_id)}"
    )
    repair_root = source_root / "disk" / "repair" / basename
    partition = repair_root / "partition.raw"
    metadata_path = repair_root / "partition.json"
    if not partition.is_file() or not metadata_path.is_file():
        raise CaseError(
            f"Repair copy is missing; run disk-repair-copy first: {repair_root}"
        )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected_copy_fields = {
        "source_working_disk": str(working_disk),
        "source_working_disk_sha256": working_metadata["sha256"],
        "offset_sector": args.offset,
        "length_sectors": args.length,
        "copy_id": safe_name(args.copy_id),
        "repair_copy_path": str(partition),
        "size_bytes": args.length * 512,
    }
    for field, expected in expected_copy_fields.items():
        if metadata.get(field) != expected:
            raise CaseError(
                f"Repair-copy metadata does not match the requested {field}: "
                f"{metadata.get(field)!r} != {expected!r}"
            )
    if metadata.get("repair_status") != "not_attempted":
        raise CaseError(
            f"Repair has already been attempted on this copy: {repair_root}"
        )
    before_sha256 = file_sha256(partition)
    if before_sha256 != metadata.get("pre_repair_sha256"):
        raise CaseError("Repair copy changed before the recorded repair attempt")
    metadata["repair_status"] = "running"
    metadata["repair_started_utc"] = utc_now()
    atomic_write_json(metadata_path, metadata)
    record = run_recorded(
        case_root,
        f"{source['case_key']}-testdisk-mft-repair",
        testdisk_repair_command(args.testdisk_image, repair_root),
        repair_root / "testdisk.stdout.log",
        repair_root / "testdisk.stderr.log",
    )
    if partition.stat().st_size != metadata.get("size_bytes"):
        raise CaseError("Repair tool changed the repair copy length")
    after_sha256 = file_sha256(partition)
    original_disk = working_disk
    if after_sha256 == before_sha256:
        ranges, changed_count = [], 0
    else:
        ranges, changed_count = changed_sector_ranges(
            original_disk, args.offset * 512, partition
        )
    validations = []
    validation_specs: list[tuple[str, list[str], str]] = [
        ("fsstat", [], "fsstat"),
        ("fls", ["-r"], "fls-recursive"),
    ]
    for inum in args.validation_inum or []:
        validation_specs.append(("istat", [str(inum)], f"istat-{inum}"))
    for tool, extra_arguments, label in validation_specs:
        validation = run_recorded(
            case_root,
            f"{source['case_key']}-repaired-{label}",
            tsk_partition_validation_command(
                args.tsk_image, repair_root, tool, extra_arguments
            ),
            repair_root / f"{label}.stdout.log",
            repair_root / f"{label}.stderr.log",
        )
        validations.append(validation)
    metadata.update(
        {
            "repair_attempted_utc": utc_now(),
            "repair_status": (
                "tool_completed_with_changes"
                if record["exit_code"] == 0 and changed_count
                else "tool_completed_no_change"
                if record["exit_code"] == 0
                else "tool_failed"
            ),
            "repair_tool": args.testdisk_image,
            "repair_command": record,
            "post_repair_sha256": after_sha256,
            "changed_sector_count": changed_count,
            "changed_sector_ranges": ranges,
            "validation_runs": validations,
            "validation_ok": all(item["exit_code"] == 0 for item in validations),
            "validation_inums": args.validation_inum or [],
            "limitations": (
                "$MFTMirr normally covers only the first NTFS records; a high-numbered "
                "attribute-list defect may remain. TSK validation does not replace a retry "
                "of the exact parser that first reported damage. TestDisk output is a "
                "reconstructed derivative."
            ),
        }
    )
    atomic_write_json(metadata_path, metadata)
    limited = record["exit_code"] != 0 or not metadata["validation_ok"]
    note = None
    if limited:
        note = (
            "TestDisk repair or independent TSK validation did not complete successfully; "
            "the attempt and retained derivative are documented."
        )
    elif changed_count == 0:
        limited = True
        note = "TestDisk completed but made no changes; the original parse defect may remain."
    elif not args.validation_inum:
        limited = True
        note = (
            "TestDisk changed the derivative, but no reported failing MFT record was supplied "
            "for exact validation."
        )
    repair_artifacts = [
        str(metadata_path),
        str(partition),
        str(repair_root / "testdisk.stdout.log"),
        str(repair_root / "testdisk.stderr.log"),
        str(repair_root / "testdisk.log"),
    ]
    repair_artifacts.extend(
        str(repair_root / f"{label}.{stream}.log")
        for _, _, label in validation_specs
        for stream in ("stdout", "stderr")
    )
    record_work_result(
        argparse.Namespace(
            case_root=str(case_root),
            work_item=evidence_lane_id(
                state, source, "disk_gzip", "damage_repair_assessment"
            ),
            status="completed_with_limit" if limited else "completed",
            artifact=repair_artifacts,
            note=note,
        )
    )
    print(
        f"Repair attempt {metadata['repair_status']}; changed sectors: {changed_count}; "
        f"validation_ok={metadata['validation_ok']}"
    )
    return 0 if record["exit_code"] == 0 else 2


def path_is_within(path: Path, roots: Iterable[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def work_artifact_record(
    path_arg: str, case_root: Path, evidence_root: Path
) -> dict[str, Any]:
    candidate = Path(path_arg).expanduser()
    if not candidate.is_absolute():
        candidate = case_root / candidate
    path = candidate.resolve(strict=True)
    if path.is_symlink():
        raise CaseError(f"Work-result artifact cannot be a symlink: {path}")
    if not path_is_within(path, (case_root, evidence_root)):
        raise CaseError(f"Work-result artifact is outside approved roots: {path}")
    record: dict[str, Any] = {
        "path": str(path),
        "kind": "directory" if path.is_dir() else "file",
    }
    if path.is_file():
        record["size_bytes"] = path.stat().st_size
        record["sha256"] = file_sha256(path)
    elif not path.is_dir():
        raise CaseError(f"Work-result artifact is not a file or directory: {path}")
    return record


def update_integrity_work_items(
    case_root: Path,
    integrity: dict[str, Any],
    integrity_path: Path,
) -> None:
    """Reflect deterministic integrity/provenance results in the completion ledger."""
    with exclusive_case_state_lock(case_root):
        _, evidence_root, state = load_case(str(case_root))
        if state["lifecycle"].get("status") == "finalized":
            raise CaseError("Case was finalized while integrity verification ran")
        artifact = work_artifact_record(str(integrity_path), case_root, evidence_root)
        evidence_by_relative = {
            item["relative_path"]: item["evidence_item_id"]
            for item in state["evidence_items"]
        }
        work_by_key = {
            (item["evidence_item_id"], item["lane"]): item
            for item in state["work_items"]
        }

        def update(
            evidence_id: str, lane: str, status: str, note: str | None = None
        ) -> None:
            work_item = work_by_key.get((evidence_id, lane))
            if not work_item:
                return
            work_item.setdefault("history", []).append(
                {
                    "recorded_utc": utc_now(),
                    "status": work_item.get("status", "pending"),
                    "note": work_item.get("note"),
                    "artifacts": work_item.get("artifacts", []),
                }
            )
            work_item["status"] = status
            work_item["note"] = note
            work_item["artifacts"] = [artifact]
            work_item["updated_utc"] = utc_now()

        for source in integrity.get("sources", []):
            for manifest in source.get("manifests", []):
                evidence_id = evidence_by_relative.get(manifest.get("relative_path"))
                if evidence_id:
                    update(evidence_id, "provenance_review", "completed")
            for item in source.get("items", []):
                evidence_id = evidence_by_relative.get(item.get("relative_path"))
                if not evidence_id:
                    continue
                reasons = []
                if item.get("inventory_changed_since_init"):
                    reasons.append("inventory changed since initialization")
                if item.get("manifest_status") == "mismatch":
                    reasons.append("manifest hash mismatch")
                gzip_result = item.get("gzip_test")
                if gzip_result and not gzip_result.get("ok"):
                    reasons.append("gzip stream validation failed")
                update(
                    evidence_id,
                    "integrity",
                    "failed" if reasons else "completed",
                    "; ".join(reasons) if reasons else None,
                )
        state["lifecycle"]["status"] = "in_progress"
        state["lifecycle"]["review_bundle_path"] = None
        write_case_state(case_root, state)


def record_work_result(args: argparse.Namespace) -> int:
    requested_case_root = resolved(args.case_root)
    with exclusive_case_state_lock(requested_case_root):
        case_root, evidence_root, state = load_case(args.case_root)
        if state["lifecycle"].get("status") == "finalized":
            raise CaseError("Case is finalized; work results cannot be changed")
        if args.status not in WORK_STATUSES:
            raise CaseError(f"Unknown work-item status: {args.status}")
        matches = [
            item
            for item in state["work_items"]
            if item["work_item_id"] == args.work_item
        ]
        if not matches:
            raise CaseError(f"Unknown work item: {args.work_item}")
        if args.status in {"completed", "completed_with_limit"} and not args.artifact:
            raise CaseError(f"{args.status} requires at least one --artifact")
        if args.status in {
            "completed_with_limit",
            "not_applicable",
            "blocked",
            "failed",
        }:
            if not args.note or not args.note.strip():
                raise CaseError(f"{args.status} requires --note")

        work_item = matches[0]
        if (
            args.status == "not_applicable"
            and work_item.get("lane") not in NOT_APPLICABLE_LANES
        ):
            raise CaseError(
                f"not_applicable is not permitted for required lane "
                f"{work_item.get('lane')}; record a real result or a non-terminal failure"
            )
        work_item.setdefault("history", []).append(
            {
                "recorded_utc": utc_now(),
                "status": work_item.get("status", "pending"),
                "note": work_item.get("note"),
                "artifacts": work_item.get("artifacts", []),
            }
        )
        work_item["status"] = args.status
        work_item["note"] = args.note.strip() if args.note else None
        work_item["artifacts"] = [
            work_artifact_record(value, case_root, evidence_root)
            for value in (args.artifact or [])
        ]
        work_item["updated_utc"] = utc_now()
        state["lifecycle"]["status"] = "in_progress"
        state["lifecycle"]["review_bundle_path"] = None
        write_case_state(case_root, state)
    print(f"Recorded {work_item['work_item_id']}: {work_item['status']}")
    return 0


def validate_work_completion(state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected: dict[tuple[str, str], str] = {}
    for evidence in state["evidence_items"]:
        evidence_id = evidence["evidence_item_id"]
        for lane in required_lanes(evidence["role"]):
            expected[(evidence_id, lane)] = f"{evidence_id}.{lane}"

    actual: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for work_item in state["work_items"]:
        key = (work_item.get("evidence_item_id"), work_item.get("lane"))
        actual.setdefault(key, []).append(work_item)

    for key, expected_id in sorted(expected.items()):
        matches = actual.get(key, [])
        if not matches:
            errors.append(f"Required work item is missing: {expected_id}")
            continue
        if len(matches) != 1:
            errors.append(f"Required work item is duplicated: {expected_id}")
            continue
        work_item = matches[0]
        if work_item.get("work_item_id") != expected_id:
            errors.append(
                f"Work-item identity mismatch: expected {expected_id}, "
                f"found {work_item.get('work_item_id')}"
            )
        if work_item.get("status") not in TERMINAL_WORK_STATUSES:
            errors.append(
                f"Work item is not complete: {expected_id} "
                f"({work_item.get('status', 'missing')})"
            )
            continue
        if (
            work_item.get("status") == "not_applicable"
            and work_item.get("lane") not in NOT_APPLICABLE_LANES
        ):
            errors.append(
                f"not_applicable is not permitted for required work item: {expected_id}"
            )
        if work_item.get("status") in {"completed", "completed_with_limit"}:
            artifacts = work_item.get("artifacts") or []
            if not artifacts:
                errors.append(
                    f"Completed work item has no artifacts: {work_item['work_item_id']}"
                )
            for artifact in artifacts:
                path = Path(artifact.get("path", ""))
                if not path.exists():
                    errors.append(
                        f"Work-item artifact is missing: {work_item['work_item_id']} -> {path}"
                    )
                    continue
                expected_sha256 = artifact.get("sha256")
                if expected_sha256 and (
                    not path.is_file() or file_sha256(path) != expected_sha256
                ):
                    errors.append(
                        f"Work-item artifact hash changed: {work_item['work_item_id']} -> {path}"
                    )
        if (
            work_item.get("status") in {"completed_with_limit", "not_applicable"}
            and not str(work_item.get("note") or "").strip()
        ):
            errors.append(
                f"Limited/not-applicable work item lacks a note: {work_item['work_item_id']}"
            )
    for key in sorted(set(actual) - set(expected), key=lambda item: str(item)):
        for work_item in actual[key]:
            errors.append(
                f"Unexpected work item is not part of the required matrix: "
                f"{work_item.get('work_item_id')}"
            )
    return errors


def markdown_link_targets(text: str) -> list[str]:
    targets: list[str] = []
    for match in MARKDOWN_LINK_RE.finditer(text):
        target = (match.group(1) or match.group(2) or "").strip()
        if match.group(1) is None and ' "' in target:
            target = target.split(' "', 1)[0]
        targets.append(unquote(target))
    return targets


def local_link_path(target: str, report_path: Path) -> Path | None:
    lowered = target.lower()
    if (
        not target
        or target.startswith("#")
        or lowered.startswith(("http://", "https://", "mailto:", "data:"))
    ):
        return None
    clean = target.split("#", 1)[0]
    candidate = Path(clean).expanduser()
    if not candidate.is_absolute():
        candidate = report_path.parent / candidate
    return candidate.resolve(strict=False)


def validate_report(
    report_path: Path, case_root: Path, evidence_root: Path, state: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    if not report_path.is_file():
        return [f"Working report is missing: {report_path}"]
    text = report_path.read_text(encoding="utf-8")
    headings = [
        match.group(1).strip() for match in re.finditer(r"^##\s+(.+?)\s*$", text, re.M)
    ]
    if headings[:2] != ["Executive summary", "Findings"]:
        errors.append(
            "The first two H2 sections must be Executive summary and Findings"
        )
    by_casefold = {heading.casefold() for heading in headings}
    for section in REQUIRED_REPORT_SECTIONS:
        if section.casefold() not in by_casefold:
            errors.append(f"Required report section is missing: {section}")
    summary_match = re.search(
        r"^## Executive summary\s*$\n(.*?)(?=^##\s+)", text, re.M | re.S
    )
    if summary_match:
        summary = summary_match.group(1).strip()
        if not summary:
            errors.append("Executive summary is empty")
        elif len(re.findall(r"\b\w+\b", summary)) > 250:
            errors.append("Executive summary exceeds 250 words")
    else:
        errors.append("Executive summary content could not be parsed")
    lowered = text.casefold()
    for placeholder in REPORT_PLACEHOLDERS:
        if placeholder.casefold() in lowered:
            errors.append(f"Report still contains placeholder text: {placeholder}")

    resolved_links: set[Path] = set()
    for target in markdown_link_targets(text):
        link_path = local_link_path(target, report_path)
        if link_path is None:
            continue
        if not path_is_within(link_path, (case_root, evidence_root)):
            errors.append(f"Local report link is outside approved roots: {target}")
            continue
        if not link_path.exists():
            errors.append(f"Local report link is missing: {target}")
            continue
        resolved_links.add(link_path)
    for evidence_item in state["evidence_items"]:
        evidence_path = (evidence_root / evidence_item["relative_path"]).resolve(
            strict=False
        )
        if evidence_path not in resolved_links:
            errors.append(
                f"Evidence item is not linked from the report: {evidence_item['evidence_item_id']}"
            )
    return errors


def integrity_hashes(case_root: Path) -> tuple[dict[str, str], list[str]]:
    """Return verified source hashes recorded by the completed integrity pass."""
    path = case_root / "integrity.json"
    if not path.is_file():
        return {}, [f"Integrity result is missing: {path}"]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [f"Integrity result is invalid: {path}: {exc}"]
    if value.get("status") != "verified":
        return {}, [f"Integrity result is not verified: {path}"]
    hashes: dict[str, str] = {}
    for source in value.get("sources", []):
        for manifest in source.get("manifests", []):
            relative = manifest.get("relative_path")
            digest = manifest.get("sha256")
            if relative and digest:
                hashes[relative] = digest
        for item in source.get("items", []):
            relative = item.get("relative_path")
            digest = item.get("sha256")
            if relative and digest:
                hashes[relative] = digest
    return hashes, []


def validate_current_evidence(
    case_root: Path,
    evidence_root: Path,
    state: dict[str, Any],
    *,
    rehash: bool,
) -> list[str]:
    """Reject evidence-root drift and optionally rehash every inventoried item."""
    errors: list[str] = []
    try:
        current_items = discover_evidence_inventory(evidence_root, state["sources"])
    except CaseError as exc:
        return [str(exc)]
    recorded_by_path = {item["relative_path"]: item for item in state["evidence_items"]}
    current_by_path = {item["relative_path"]: item for item in current_items}
    for relative in sorted(set(recorded_by_path) - set(current_by_path)):
        errors.append(f"Inventoried evidence item is missing: {relative}")
    for relative in sorted(set(current_by_path) - set(recorded_by_path)):
        errors.append(f"New un-inventoried evidence item exists: {relative}")
    stable_fields = (
        "evidence_item_id",
        "source_name",
        "case_key",
        "role",
        "name",
        "size_bytes",
        "mtime_utc",
    )
    for relative in sorted(set(recorded_by_path) & set(current_by_path)):
        recorded = recorded_by_path[relative]
        current = current_by_path[relative]
        changed = [
            field
            for field in stable_fields
            if recorded.get(field) != current.get(field)
        ]
        if changed:
            errors.append(
                f"Evidence inventory changed for {relative}: {', '.join(changed)}"
            )
    if not rehash or errors:
        return errors

    expected_hashes, integrity_errors = integrity_hashes(case_root)
    errors.extend(integrity_errors)
    if integrity_errors:
        return errors
    for relative, item in sorted(recorded_by_path.items()):
        expected = expected_hashes.get(relative)
        if not expected:
            errors.append(
                f"Evidence item has no verified integrity hash: "
                f"{item['evidence_item_id']}"
            )
            continue
        actual = file_sha256(evidence_root / relative)
        if actual != expected:
            errors.append(f"Evidence hash changed after verification: {relative}")
    for source in state["sources"]:
        try:
            metadata = validated_working_disk_metadata(case_root, source)
        except CaseError as exc:
            errors.append(str(exc))
            continue
        working_path = Path(metadata["working_path"])
        if file_sha256(working_path) != metadata["sha256"]:
            errors.append(
                f"Verified working disk changed after creation: {source['source_name']}"
            )
    return errors


def validate_sha256_tree_manifest(manifest_path: Path, root: Path) -> list[str]:
    """Rehash a manifested directory and reject missing, changed, or extra files."""
    errors: list[str] = []
    recorded_paths: set[str] = set()
    try:
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [f"Derived-tree manifest cannot be read: {manifest_path}: {exc}"]
    for line_number, line in enumerate(lines, start=1):
        try:
            digest, size_text, relative = line.split("  ", 2)
            size = int(size_text)
        except ValueError:
            errors.append(
                f"Invalid derived-tree manifest line {line_number}: {manifest_path}"
            )
            continue
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            errors.append(
                f"Unsafe derived-tree manifest path on line {line_number}: {relative}"
            )
            continue
        normalized = relative_path.as_posix()
        if normalized in recorded_paths:
            errors.append(f"Duplicate derived-tree manifest path: {normalized}")
            continue
        recorded_paths.add(normalized)
        path = root / relative_path
        if not path.is_file() or path.is_symlink():
            errors.append(f"Manifested derived file is missing or unsafe: {path}")
            continue
        if path.stat().st_size != size:
            errors.append(f"Manifested derived file size changed: {path}")
            continue
        if file_sha256(path) != digest:
            errors.append(f"Manifested derived file hash changed: {path}")
    actual_paths: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            errors.append(f"Derived tree contains an unsafe symlink: {path}")
        elif path.is_file():
            actual_paths.add(path.relative_to(root).as_posix())
    for relative in sorted(recorded_paths - actual_paths):
        errors.append(f"Manifested derived file is missing: {root / relative}")
    for relative in sorted(actual_paths - recorded_paths):
        errors.append(f"Unmanifested derived file exists: {root / relative}")
    return errors


def validate_derived_tree_artifacts(
    state: dict[str, Any], case_root: Path, *, rehash: bool
) -> list[str]:
    """Require and optionally verify manifests for large recovered/carved trees."""
    errors: list[str] = []
    manifested_lanes = {
        "allocated_file_examination",
        "deleted_unallocated_assessment",
        "signature_carving",
    }
    for work_item in state["work_items"]:
        if work_item.get("lane") not in manifested_lanes or work_item.get(
            "status"
        ) not in {"completed", "completed_with_limit"}:
            continue
        artifacts = [
            Path(item.get("path", "")) for item in work_item.get("artifacts", [])
        ]
        manifests = [path for path in artifacts if path.suffix == ".sha256"]
        metadata_paths = [path for path in artifacts if path.suffix == ".json"]
        if len(manifests) != 1:
            errors.append(
                f"Manifested lane requires exactly one .sha256 artifact: "
                f"{work_item['work_item_id']}"
            )
            continue
        root: Path | None = None
        for metadata_path in metadata_paths:
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            root_value = metadata.get("output_path") or metadata.get("recovered_path")
            if root_value:
                root_candidate = Path(root_value).expanduser()
                if not root_candidate.is_absolute():
                    root_candidate = metadata_path.parent / root_candidate
                if root_candidate.is_symlink():
                    errors.append(
                        f"Derived-tree metadata points to a symlink: "
                        f"{work_item['work_item_id']} -> {root_candidate}"
                    )
                    root = None
                    break
                root = root_candidate.resolve(strict=False)
                break
        if root is None or not root.is_dir():
            errors.append(
                f"Manifested lane lacks metadata bound to a derived tree: "
                f"{work_item['work_item_id']}"
            )
            continue
        if not path_is_within(root, (case_root,)):
            errors.append(
                f"Derived-tree metadata points outside the case root: "
                f"{work_item['work_item_id']} -> {root}"
            )
            continue
        if rehash:
            errors.extend(validate_sha256_tree_manifest(manifests[0], root))
    return errors


def coverage_document(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "case_id": state["case_id"],
        "evidence_items": state["evidence_items"],
        "work_items": state["work_items"],
    }


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def configured_report_path(
    args: argparse.Namespace, case_root: Path, state: dict[str, Any]
) -> Path:
    candidate = (
        Path(args.report).expanduser()
        if getattr(args, "report", None)
        else Path(state["report"]["working_path"])
    )
    if not candidate.is_absolute():
        candidate = case_root / candidate
    report_path = candidate.resolve(strict=False)
    if not path_is_within(report_path, (case_root,)):
        raise CaseError(f"Working report is outside the case root: {report_path}")
    return report_path


def readiness_errors(
    report_path: Path,
    case_root: Path,
    evidence_root: Path,
    state: dict[str, Any],
    *,
    rehash_evidence: bool = False,
) -> list[str]:
    return (
        validate_current_evidence(
            case_root, evidence_root, state, rehash=rehash_evidence
        )
        + validate_work_completion(state)
        + validate_derived_tree_artifacts(state, case_root, rehash=rehash_evidence)
        + validate_report(report_path, case_root, evidence_root, state)
    )


def case_status(args: argparse.Namespace) -> int:
    case_root, evidence_root, state = load_case(args.case_root)
    report_path = configured_report_path(args, case_root, state)
    errors = readiness_errors(report_path, case_root, evidence_root, state)
    counts: dict[str, int] = {}
    for item in state["work_items"]:
        status = item.get("status", "missing")
        counts[status] = counts.get(status, 0) + 1
    print(
        canonical_json(
            {
                "case_id": state["case_id"],
                "lifecycle_status": state["lifecycle"].get("status"),
                "work_item_counts": counts,
                "ready_for_review": not errors,
                "blockers": errors,
                "working_report": str(report_path),
                "final_report": state["report"]["final_path"],
            }
        ),
        end="",
    )
    return 0


def prepare_review(args: argparse.Namespace) -> int:
    requested_case_root = resolved(args.case_root)
    with exclusive_case_state_lock(requested_case_root):
        return _prepare_review_locked(args)


def _prepare_review_locked(args: argparse.Namespace) -> int:
    case_root, evidence_root, state = load_case(args.case_root)
    if state["lifecycle"].get("status") == "finalized":
        raise CaseError("Case is already finalized")
    report_path = configured_report_path(args, case_root, state)
    errors = readiness_errors(
        report_path,
        case_root,
        evidence_root,
        state,
        rehash_evidence=True,
    )
    if errors:
        raise CaseError("Case is not ready for review:\n- " + "\n- ".join(errors))

    reviews_root = case_root / "reviews"
    reviews_root.mkdir(parents=True, exist_ok=True)
    coverage_path = reviews_root / "completion-snapshot.json"
    coverage_text = canonical_json(coverage_document(state))
    atomic_write_text(coverage_path, coverage_text)
    bundle_path = reviews_root / "review-bundle.json"
    bundle = {
        "schema_version": 1,
        "status": "awaiting_peer_review",
        "prepared_utc": utc_now(),
        "report_path": str(report_path),
        "report_sha256": file_sha256(report_path),
        "coverage_path": str(coverage_path),
        "coverage_sha256": text_sha256(coverage_text),
    }
    atomic_write_json(bundle_path, bundle)
    state["report"]["working_path"] = str(report_path)
    state["report"]["status"] = "review_ready"
    state["lifecycle"]["status"] = "review_ready"
    state["lifecycle"]["review_bundle_path"] = str(bundle_path)
    write_case_state(case_root, state)
    print(f"Review bundle: {bundle_path}")
    print(f"Report SHA-256: {bundle['report_sha256']}")
    print(f"Coverage SHA-256: {bundle['coverage_sha256']}")
    return 0


def read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CaseError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CaseError(f"{label} must contain a JSON object: {path}")
    return value


def finalize_report(args: argparse.Namespace) -> int:
    requested_case_root = resolved(args.case_root)
    with exclusive_case_state_lock(requested_case_root):
        return _finalize_report_locked(args)


def _finalize_report_locked(args: argparse.Namespace) -> int:
    case_root, evidence_root, state = load_case(args.case_root)
    if state["lifecycle"].get("status") == "finalized":
        raise CaseError("Case is already finalized")
    report_path = configured_report_path(args, case_root, state)
    errors = readiness_errors(
        report_path,
        case_root,
        evidence_root,
        state,
        rehash_evidence=True,
    )
    if errors:
        raise CaseError("Case is not ready to finalize:\n- " + "\n- ".join(errors))
    bundle_value = state["lifecycle"].get("review_bundle_path")
    if not bundle_value:
        raise CaseError("Review bundle is missing; run prepare-review first")
    bundle_path = Path(bundle_value).resolve(strict=False)
    if not bundle_path.is_file() or not path_is_within(bundle_path, (case_root,)):
        raise CaseError(
            f"Review bundle is missing or outside the case root: {bundle_path}"
        )
    bundle = read_json_object(bundle_path, "Review bundle")
    current_report_sha256 = file_sha256(report_path)
    if (
        bundle.get("report_path") != str(report_path)
        or bundle.get("report_sha256") != current_report_sha256
    ):
        raise CaseError("Working report changed after the review bundle was prepared")

    coverage_path = Path(str(bundle.get("coverage_path", ""))).resolve(strict=False)
    current_coverage_text = canonical_json(coverage_document(state))
    current_coverage_sha256 = text_sha256(current_coverage_text)
    if (
        not coverage_path.is_file()
        or not path_is_within(coverage_path, (case_root,))
        or coverage_path.read_text(encoding="utf-8") != current_coverage_text
        or bundle.get("coverage_sha256") != current_coverage_sha256
    ):
        raise CaseError("Case coverage changed after the review bundle was prepared")

    peer_review_path = Path(args.peer_review).expanduser().resolve(strict=False)
    if not peer_review_path.is_file() or not path_is_within(
        peer_review_path, (case_root,)
    ):
        raise CaseError(
            f"Peer review is missing or outside the case root: {peer_review_path}"
        )
    peer_review = read_json_object(peer_review_path, "Peer review")
    if peer_review.get("recommendation") != "ready":
        raise CaseError("Peer review recommendation must be exactly 'ready'")
    if peer_review.get("report_sha256") != current_report_sha256:
        raise CaseError("Peer review is not bound to the current report hash")
    if peer_review.get("coverage_sha256") != current_coverage_sha256:
        raise CaseError("Peer review is not bound to the current coverage hash")

    final_path = Path(state["report"]["final_path"]).resolve(strict=False)
    if not path_is_within(final_path, (case_root,)):
        raise CaseError(
            f"Configured final report is outside the case root: {final_path}"
        )
    report_text = report_path.read_text(encoding="utf-8")
    if final_path.exists() and file_sha256(final_path) != current_report_sha256:
        raise CaseError(f"A different final report already exists: {final_path}")
    atomic_write_text(final_path, report_text)
    completion_path = case_root / "completion.json"
    completion = {
        "schema_version": 1,
        "status": "finalized",
        "finalized_utc": utc_now(),
        "case_id": state["case_id"],
        "working_report_path": str(report_path),
        "report_path": str(final_path),
        "report_sha256": current_report_sha256,
        "coverage_path": str(coverage_path),
        "coverage_sha256": current_coverage_sha256,
        "peer_review_path": str(peer_review_path),
        "peer_review_sha256": file_sha256(peer_review_path),
        "peer_review_recommendation": "ready",
    }
    atomic_write_json(completion_path, completion)
    state["report"]["status"] = "final"
    state["report"]["finalized_utc"] = completion["finalized_utc"]
    state["report"]["final_sha256"] = current_report_sha256
    state["lifecycle"]["status"] = "finalized"
    state["lifecycle"]["completion_path"] = str(completion_path)
    write_case_state(case_root, state)
    print(f"Final report: {final_path}")
    print(f"Completion manifest: {completion_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Initialize, verify, prepare, and triage paired VM disk/RAM forensic evidence."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser(
        "init", help="Discover evidence pairs and initialize case state"
    )
    init.add_argument("--evidence-root", required=True)
    init.add_argument("--case-root", required=True)
    init.add_argument("--case-id", required=True)
    init.add_argument(
        "--force",
        action="store_true",
        help=(
            "Replace existing case state/report only when no analysis or "
            "provenance files exist"
        ),
    )
    init.set_defaults(func=initialize_case)

    verify = subparsers.add_parser(
        "verify", help="Hash evidence and verify supplied manifests/gzip"
    )
    verify.add_argument("--case-root", required=True)
    verify.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
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

    prepare = subparsers.add_parser(
        "prepare-disks", help="Create atomic decompressed working disks"
    )
    prepare.add_argument("--case-root", required=True)
    prepare.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    prepare.add_argument("--minimum-free-gib", type=float, default=200.0)
    prepare.add_argument(
        "--restart",
        action="store_true",
        help="Remove only an interrupted .partial output",
    )
    prepare.add_argument(
        "--force", action="store_true", help="Replace a completed working disk"
    )
    prepare.set_defaults(func=prepare_disks)

    build = subparsers.add_parser(
        "build-tools", help="Build and record pinned analysis containers"
    )
    build.add_argument("--case-root", required=True)
    build.add_argument(
        "--repo-root", default=str(Path(__file__).resolve().parent.parent)
    )
    build.add_argument("--volatility-image", default=DEFAULT_VOLATILITY_IMAGE)
    build.add_argument("--tsk-image", default=DEFAULT_TSK_IMAGE)
    build.add_argument("--elf2dmp-image", default=DEFAULT_ELF2DMP_IMAGE)
    build.add_argument("--testdisk-image", default=DEFAULT_TESTDISK_IMAGE)
    build.add_argument("--plaso-image", default=DEFAULT_PLASO_IMAGE)
    build.set_defaults(func=build_tools)

    memory = subparsers.add_parser(
        "memory", help="Run Volatility information or baseline plugins"
    )
    memory.add_argument("--case-root", required=True)
    memory.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    memory.add_argument(
        "--plugin", action="append", help="Override plugin list; repeat as needed"
    )
    memory.add_argument(
        "--info-only", action="store_true", help="Run only windows.info"
    )
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
    memory.add_argument(
        "--input", choices=("original", "converted"), default="original"
    )
    memory.add_argument(
        "--parallelism",
        choices=("off", "threads", "processes"),
        default="off",
        help="Volatility parallelism mode",
    )
    memory.set_defaults(func=run_memory_plugins)

    convert = subparsers.add_parser(
        "memory-convert",
        help="Convert verified QEMU ELF memory to a derived Windows dump",
    )
    convert.add_argument("--case-root", required=True)
    convert.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    convert.add_argument("--elf2dmp-image", default=DEFAULT_ELF2DMP_IMAGE)
    convert.add_argument(
        "--allow-network",
        action="store_true",
        help="Allow QEMU elf2dmp to retrieve the required Microsoft PDB",
    )
    convert.add_argument(
        "--restart", action="store_true", help="Remove only an interrupted conversion"
    )
    convert.add_argument(
        "--force", action="store_true", help="Atomically replace a completed conversion"
    )
    convert.set_defaults(func=convert_memory)

    layout = subparsers.add_parser(
        "disk-layout", help="Record partition layouts with The Sleuth Kit"
    )
    layout.add_argument("--case-root", required=True)
    layout.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    layout.add_argument("--tsk-image", default=DEFAULT_TSK_IMAGE)
    layout.set_defaults(func=disk_layout)

    filesystems = subparsers.add_parser(
        "disk-filesystems", help="Record filesystem metadata for allocated partitions"
    )
    filesystems.add_argument("--case-root", required=True)
    filesystems.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    filesystems.add_argument("--tsk-image", default=DEFAULT_TSK_IMAGE)
    filesystems.set_defaults(func=disk_filesystems)

    recover = subparsers.add_parser(
        "disk-recover",
        help="Recover allocated, unallocated, or all files with The Sleuth Kit",
    )
    recover.add_argument("--case-root", required=True)
    recover.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    recover.add_argument(
        "--offset", required=True, type=int, help="Partition start sector"
    )
    recover.add_argument(
        "--directory-inum",
        type=int,
        help="Recover only this directory inode and its descendants",
    )
    recover.add_argument(
        "--recovery-scope",
        choices=("allocated", "unallocated", "all"),
        default="allocated",
        help="File allocation scope (default: allocated)",
    )
    recover.add_argument("--tsk-image", default=DEFAULT_TSK_IMAGE)
    recover.add_argument(
        "--restart", action="store_true", help="Remove only an interrupted recovery"
    )
    recover.set_defaults(func=recover_disk_files)

    recover_manifest = subparsers.add_parser(
        "disk-recover-manifest",
        help="Manifest and record a previously completed TSK recovery tree",
    )
    recover_manifest.add_argument("--case-root", required=True)
    recover_manifest.add_argument(
        "--source", action="append", required=True, help="Source name or key"
    )
    recover_manifest.add_argument(
        "--offset", required=True, type=int, help="Partition start sector"
    )
    recover_manifest.add_argument(
        "--directory-inum",
        type=int,
        help="Completed recovery was limited to this directory inode",
    )
    recover_manifest.add_argument(
        "--recovery-scope",
        choices=("allocated", "unallocated", "all"),
        default="allocated",
        help="Completed recovery allocation scope (default: allocated)",
    )
    recover_manifest.set_defaults(func=manifest_completed_recovery)

    carve = subparsers.add_parser(
        "disk-carve",
        help="Signature-carve each verified working disk with PhotoRec",
    )
    carve.add_argument("--case-root", required=True)
    carve.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    carve.add_argument("--testdisk-image", default=DEFAULT_TESTDISK_IMAGE)
    carve.add_argument(
        "--restart",
        action="store_true",
        help="Remove only an interrupted PhotoRec output directory",
    )
    carve.set_defaults(func=carve_disks)

    carve_finalize = subparsers.add_parser(
        "disk-carve-finalize",
        help="Hash and atomically promote a normally exited supervised PhotoRec partial",
    )
    carve_finalize.add_argument("--case-root", required=True)
    carve_finalize.add_argument(
        "--source", action="append", required=True, help="Source name or key"
    )
    carve_finalize.add_argument("--run-log", required=True)
    carve_finalize.add_argument("--exit-code", required=True, type=int)
    carve_finalize.add_argument("--testdisk-image", default=DEFAULT_TESTDISK_IMAGE)
    carve_finalize.set_defaults(func=finalize_external_carving)

    repair_copy = subparsers.add_parser(
        "disk-repair-copy",
        help="Create a hashed partition derivative for a repair attempt",
    )
    repair_copy.add_argument("--case-root", required=True)
    repair_copy.add_argument("--source", action="append", required=True)
    repair_copy.add_argument("--offset", required=True, type=int)
    repair_copy.add_argument("--length", required=True, type=int)
    repair_copy.add_argument("--copy-id", default="01")
    repair_copy.set_defaults(func=create_repair_copy)

    repair_testdisk = subparsers.add_parser(
        "disk-repair-testdisk",
        help="Attempt TestDisk MFT repair on a separately hashed partition copy",
    )
    repair_testdisk.add_argument("--case-root", required=True)
    repair_testdisk.add_argument("--source", action="append", required=True)
    repair_testdisk.add_argument("--offset", required=True, type=int)
    repair_testdisk.add_argument("--length", required=True, type=int)
    repair_testdisk.add_argument("--copy-id", default="01")
    repair_testdisk.add_argument("--testdisk-image", default=DEFAULT_TESTDISK_IMAGE)
    repair_testdisk.add_argument("--tsk-image", default=DEFAULT_TSK_IMAGE)
    repair_testdisk.add_argument(
        "--validation-inum",
        action="append",
        type=int,
        help="MFT record/inode that previously failed; repeat for exact TSK validation",
    )
    repair_testdisk.set_defaults(func=repair_partition_with_testdisk)

    timeline = subparsers.add_parser(
        "timeline", help="Build an atomic Plaso disk timeline"
    )
    timeline.add_argument("--case-root", required=True)
    timeline.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    timeline.add_argument("--plaso-image", default=DEFAULT_PLASO_IMAGE)
    timeline.add_argument("--partitions", default="all")
    timeline.add_argument("--vss-stores", default="none")
    timeline.add_argument(
        "--restart", action="store_true", help="Remove only an interrupted timeline"
    )
    timeline.add_argument(
        "--force", action="store_true", help="Replace a completed derived timeline"
    )
    timeline.set_defaults(func=disk_timeline)

    recovered_timeline = subparsers.add_parser(
        "timeline-recovered",
        help="Build Plaso storage from an atomic TSK recovery directory",
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
        "timeline-slice",
        help="Export an atomic CSV time slice from a completed Plaso timeline",
    )
    slice_parser.add_argument("--case-root", required=True)
    slice_parser.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    slice_parser.add_argument("--plaso-image", default=DEFAULT_PLASO_IMAGE)
    slice_parser.add_argument("--storage-name", default="timeline.plaso")
    slice_parser.add_argument(
        "--slice", required=True, help="ISO 8601 center time including a UTC offset"
    )
    slice_parser.add_argument(
        "--slice-size", type=int, default=10, help="Minutes before and after"
    )
    slice_parser.add_argument("--output-time-zone", default="UTC")
    slice_parser.add_argument("--name", help="Optional safe output basename")
    slice_parser.add_argument(
        "--restart", action="store_true", help="Remove only an interrupted export"
    )
    slice_parser.add_argument(
        "--force", action="store_true", help="Replace a completed slice export"
    )
    slice_parser.set_defaults(func=timeline_slice)

    query_parser = subparsers.add_parser(
        "timeline-query", help="Export events matching a Plaso event-filter expression"
    )
    query_parser.add_argument("--case-root", required=True)
    query_parser.add_argument(
        "--source", action="append", help="Source name or key; repeat as needed"
    )
    query_parser.add_argument("--plaso-image", default=DEFAULT_PLASO_IMAGE)
    query_parser.add_argument("--storage-name", default="timeline.plaso")
    query_parser.add_argument(
        "--filter", required=True, help="Plaso event-filter expression"
    )
    query_parser.add_argument("--name", required=True, help="Safe output basename")
    query_parser.add_argument("--output-time-zone", default="UTC")
    query_parser.add_argument(
        "--restart", action="store_true", help="Remove only an interrupted export"
    )
    query_parser.add_argument(
        "--force", action="store_true", help="Replace a completed query export"
    )
    query_parser.set_defaults(func=timeline_query)

    status_parser = subparsers.add_parser(
        "case-status", help="Show work-item coverage and finalization blockers"
    )
    status_parser.add_argument("--case-root", required=True)
    status_parser.add_argument("--report", help="Optional working report path override")
    status_parser.set_defaults(func=case_status)

    record_parser = subparsers.add_parser(
        "record-result", help="Record one durable evidence-item work result"
    )
    record_parser.add_argument("--case-root", required=True)
    record_parser.add_argument("--work-item", required=True)
    record_parser.add_argument("--status", required=True, choices=sorted(WORK_STATUSES))
    record_parser.add_argument(
        "--artifact", action="append", help="Output file or directory; repeat"
    )
    record_parser.add_argument(
        "--note", help="Required for limited, not-applicable, or failed work"
    )
    record_parser.set_defaults(func=record_work_result)

    review_parser = subparsers.add_parser(
        "prepare-review",
        help="Freeze complete coverage and a working-report hash for peer review",
    )
    review_parser.add_argument("--case-root", required=True)
    review_parser.add_argument("--report", help="Optional working report path override")
    review_parser.set_defaults(func=prepare_review)

    finalize_parser = subparsers.add_parser(
        "finalize-report",
        help="Create a final report only after exact hash-bound ready review",
    )
    finalize_parser.add_argument("--case-root", required=True)
    finalize_parser.add_argument(
        "--report", help="Optional working report path override"
    )
    finalize_parser.add_argument(
        "--peer-review",
        required=True,
        help="Structured peer-review JSON inside the case root",
    )
    finalize_parser.set_defaults(func=finalize_report)
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
