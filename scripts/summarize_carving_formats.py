#!/usr/bin/env python3
"""Create a deterministic content-type sample from a large carving result."""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(16 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def deterministic_samples(
    root: Path, per_extension: int
) -> tuple[dict[str, int], dict[str, list[Path]]]:
    counts: dict[str, int] = {}
    heaps: dict[str, list[tuple[int, str, Path]]] = {}
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        directory_path = Path(directory)
        for name in file_names:
            path = directory_path / name
            if path.is_symlink():
                raise RuntimeError(f"Refusing symlink in carving output: {path}")
            relative = path.relative_to(root).as_posix()
            extension = path.suffix.casefold() or "[no-extension]"
            counts[extension] = counts.get(extension, 0) + 1
            score = int.from_bytes(
                hashlib.sha256(relative.encode("utf-8")).digest()[:8], "big"
            )
            heap = heaps.setdefault(extension, [])
            item = (-score, relative, path)
            if len(heap) < per_extension:
                heapq.heappush(heap, item)
            elif score < -heap[0][0]:
                heapq.heapreplace(heap, item)
    samples = {
        extension: [item[2] for item in sorted(heap, key=lambda item: -item[0])]
        for extension, heap in heaps.items()
    }
    return dict(sorted(counts.items())), dict(sorted(samples.items()))


def file_identification(path: Path) -> dict[str, Any]:
    record: dict[str, Any] = {
        "size_bytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }
    for label, arguments in (
        ("mime_type", ["file", "--brief", "--mime-type", "--", str(path)]),
        ("description", ["file", "--brief", "--", str(path)]),
    ):
        completed = subprocess.run(
            arguments, capture_output=True, text=True, check=False, timeout=30
        )
        record[label] = completed.stdout.strip()
        record[f"{label}_exit_code"] = completed.returncode
        if completed.stderr.strip():
            record[f"{label}_stderr"] = completed.stderr.strip()
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--per-extension", type=int, default=5)
    args = parser.parse_args()
    if args.per_extension <= 0 or args.per_extension > 100:
        parser.error("--per-extension must be between 1 and 100")
    root = Path(args.root).resolve(strict=True)
    if not root.is_dir():
        parser.error("--root must be a directory")
    output = Path(args.output).resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)

    version = subprocess.run(
        ["file", "--version"], capture_output=True, text=True, check=False
    )
    counts, selected = deterministic_samples(root, args.per_extension)
    samples = []
    for extension, paths in selected.items():
        for path in paths:
            samples.append(
                {
                    "extension": extension,
                    "relative_path": path.relative_to(root).as_posix(),
                    **file_identification(path),
                }
            )
    result = {
        "schema_version": 1,
        "created_utc": utc_now(),
        "carving_root": str(root),
        "sampling_method": (
            "For each extension, retain paths with the lowest deterministic "
            "SHA-256-derived score; identify content with libmagic file."
        ),
        "per_extension_limit": args.per_extension,
        "total_file_count": sum(counts.values()),
        "extension_counts": counts,
        "sample_count": len(samples),
        "file_tool_version": version.stdout.strip(),
        "samples": samples,
        "limitations": [
            "Content-type validation is a deterministic extension-stratified sample, not validation of every carved file.",
            "A valid signature or MIME type does not establish original path, timestamps, ownership, or complete recovery.",
            "PhotoRec filenames and extensions are recovery labels and can include false positives or partial content.",
        ],
    }
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)
    print(
        f"Prepared {output} ({result['total_file_count']} files; "
        f"{result['sample_count']} sampled)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
