#!/usr/bin/env python3
"""Build a provenance-rich cross-source timeline with bounded memory.

The input contract deliberately starts after parser-specific export. Plaso storage
files stay independent and are exported with psort's json_line or dynamic module.
Volatility timeliner results are normalized to one event per JSONL row before use.
This script then normalizes UTC timestamps and performs an external merge sort.
"""

from __future__ import annotations

import argparse
import calendar
import csv
import hashlib
import heapq
import html
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, TextIO


SCHEMA_VERSION = 1
SUPPORTED_FORMATS = {
    "plaso-jsonl",
    "plaso-dynamic-csv",
    "volatility-timeliner-jsonl",
}
OUTPUT_NAMES = (
    "super-timeline.jsonl",
    "super-timeline.csv",
    "super-timeline-summary.csv",
    "super-timeline-summary.html",
    "super-timeline.provenance.json",
)
CSV_FIELDS = (
    "datetime",
    "timestamp",
    "timestamp_desc",
    "message",
    "forensic_evidence",
    "forensic_source",
    "forensic_input_format",
    "parser",
    "data_type",
    "source",
    "source_long",
    "display_name",
    "tag",
)
ISO8601_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ]"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<offset>Z|[+-]\d{2}:\d{2})$"
)


class TimelineError(RuntimeError):
    """Raised for a safety, input, or output contract violation."""


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
        raise TimelineError(
            f"{description} is outside every approved read root: {path}"
        )


def validate_label(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TimelineError(f"{field} must be a non-empty string")
    label = value.strip()
    if len(label) > 160 or any(ord(character) < 32 for character in label):
        raise TimelineError(
            f"{field} contains control characters or exceeds 160 characters"
        )
    return label


def normalize_datetime(value: Any) -> tuple[int, str]:
    """Return nanoseconds since the epoch and a canonical UTC ISO-8601 value."""
    if not isinstance(value, str):
        raise TimelineError("datetime is not a string")
    match = ISO8601_RE.fullmatch(value.strip())
    if not match:
        raise TimelineError(f"datetime is not supported ISO-8601: {value!r}")

    try:
        base = datetime.fromisoformat(f"{match.group('date')}T{match.group('time')}")
        offset_text = match.group("offset")
        if offset_text == "Z":
            offset = timedelta(0)
        else:
            sign = 1 if offset_text[0] == "+" else -1
            hours, minutes = (int(part) for part in offset_text[1:].split(":"))
            offset = sign * timedelta(hours=hours, minutes=minutes)
        aware = base.replace(tzinfo=timezone(offset)).astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise TimelineError(f"datetime value is invalid: {value!r}") from exc
    epoch_seconds = calendar.timegm(aware.utctimetuple())
    fraction = (match.group("fraction") or "").ljust(9, "0")
    epoch_ns = epoch_seconds * 1_000_000_000 + int(fraction or "0")

    canonical = aware.strftime("%Y-%m-%dT%H:%M:%S")
    if fraction:
        canonical += f".{fraction.rstrip('0') or '0'}"
    return epoch_ns, f"{canonical}+00:00"


def normalize_epoch_microseconds(value: Any) -> tuple[int, str]:
    """Normalize a Plaso integer timestamp expressed in epoch microseconds."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise TimelineError("Plaso timestamp is not an integer")
    try:
        epoch_us = int(value)
    except ValueError as exc:
        raise TimelineError("Plaso timestamp is not an integer") from exc
    if isinstance(value, str) and str(epoch_us) != value.strip():
        raise TimelineError("Plaso timestamp is not a canonical integer")
    try:
        aware = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=epoch_us
        )
    except OverflowError as exc:
        raise TimelineError("Plaso timestamp is outside the datetime range") from exc
    canonical = aware.strftime("%Y-%m-%dT%H:%M:%S")
    if aware.microsecond:
        canonical += f".{aware.microsecond:06d}".rstrip("0")
    return epoch_us * 1_000, f"{canonical}+00:00"


def first_text(row: dict[str, Any], names: Iterable[str]) -> str:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def normalize_event(
    row: dict[str, Any],
    input_record: dict[str, Any],
    input_index: int,
    row_number: int,
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    message = first_text(row, ("message", "description", "Description", "display_name"))
    timestamp_desc = first_text(
        row, ("timestamp_desc", "timestamp_description", "Timestamp Description")
    )
    if not message:
        raise TimelineError("event has no message or description")
    if not timestamp_desc:
        raise TimelineError("event has no timestamp_desc")
    if timestamp_desc.casefold() in {"not a time", "not set"}:
        raise TimelineError(f"event has no usable timestamp: {timestamp_desc}")

    if input_record["format"] == "plaso-jsonl":
        date_time_value = row.get("date_time")
        if isinstance(date_time_value, dict) and (
            date_time_value.get("__class_name__") == "NotSet"
            or date_time_value.get("string") == "Not set"
        ):
            raise TimelineError("Plaso event date_time is NotSet")
        epoch_ns, canonical_datetime = normalize_epoch_microseconds(
            row.get("timestamp")
        )
    else:
        datetime_text = first_text(row, ("datetime", "date_time", "DateTime"))
        epoch_ns, canonical_datetime = normalize_datetime(datetime_text)

    event = dict(row)
    event.update(
        {
            "datetime": canonical_datetime,
            "timestamp": epoch_ns // 1_000,
            "timestamp_desc": timestamp_desc,
            "message": message,
            "forensic_evidence": input_record["evidence_label"],
            "forensic_source": input_record["source_label"],
            "forensic_input_format": input_record["format"],
            "forensic_input_index": input_index,
            "forensic_input_row": row_number,
        }
    )
    sort_key = (
        epoch_ns,
        input_record["evidence_label"],
        input_record["source_label"],
        input_index,
        row_number,
    )
    return sort_key, event


def jsonl_rows(
    path: Path, maximum_line_bytes: int
) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open("rb") as stream:
        row_number = 0
        while line := stream.readline(maximum_line_bytes + 1):
            row_number += 1
            if not line.strip():
                continue
            if len(line) > maximum_line_bytes:
                raise TimelineError(
                    f"JSONL row {row_number} exceeds --max-input-line-bytes"
                )
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TimelineError(f"invalid JSONL row {row_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise TimelineError(f"JSONL row {row_number} is not an object")
            yield row_number, value


def csv_rows(
    path: Path, maximum_field_bytes: int
) -> Iterator[tuple[int, dict[str, Any]]]:
    previous_limit = csv.field_size_limit()
    csv.field_size_limit(maximum_field_bytes)
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames:
                raise TimelineError("CSV input has no header")
            for row_number, row in enumerate(reader, start=2):
                yield row_number, dict(row)
    except csv.Error as exc:
        raise TimelineError(f"invalid CSV input: {exc}") from exc
    finally:
        csv.field_size_limit(previous_limit)


def input_rows(
    input_record: dict[str, Any], maximum_line_bytes: int
) -> Iterator[tuple[int, dict[str, Any]]]:
    path = input_record["resolved_path"]
    if input_record["format"] in {"plaso-jsonl", "volatility-timeliner-jsonl"}:
        yield from jsonl_rows(path, maximum_line_bytes)
    else:
        yield from csv_rows(path, maximum_line_bytes)


def write_chunk(
    records: list[tuple[tuple[Any, ...], dict[str, Any]]],
    temporary_root: Path,
    chunk_number: int,
) -> Path:
    records.sort(key=lambda item: item[0])
    chunk_path = temporary_root / f"chunk-{chunk_number:08d}.jsonl"
    with chunk_path.open("w", encoding="utf-8", newline="\n") as stream:
        for sort_key, event in records:
            wrapper = {"sort": sort_key, "event": event}
            stream.write(json.dumps(wrapper, ensure_ascii=False, sort_keys=True))
            stream.write("\n")
    return chunk_path


def read_wrapper(stream: TextIO, path: Path) -> dict[str, Any] | None:
    line = stream.readline()
    if not line:
        return None
    try:
        wrapper = json.loads(line)
    except json.JSONDecodeError as exc:
        raise TimelineError(f"corrupt external-sort chunk {path}: {exc}") from exc
    if not isinstance(wrapper, dict) or "sort" not in wrapper or "event" not in wrapper:
        raise TimelineError(f"invalid external-sort chunk record in {path}")
    return wrapper


def merge_chunks(chunk_paths: list[Path]) -> Iterator[dict[str, Any]]:
    streams: list[TextIO] = []
    heap: list[tuple[tuple[Any, ...], int, dict[str, Any]]] = []
    try:
        for chunk_index, path in enumerate(chunk_paths):
            stream = path.open("r", encoding="utf-8")
            streams.append(stream)
            wrapper = read_wrapper(stream, path)
            if wrapper is not None:
                heapq.heappush(heap, (tuple(wrapper["sort"]), chunk_index, wrapper))
        while heap:
            _, chunk_index, wrapper = heapq.heappop(heap)
            yield wrapper["event"]
            next_wrapper = read_wrapper(streams[chunk_index], chunk_paths[chunk_index])
            if next_wrapper is not None:
                heapq.heappush(
                    heap,
                    (tuple(next_wrapper["sort"]), chunk_index, next_wrapper),
                )
    finally:
        for stream in streams:
            stream.close()


def csv_event(event: dict[str, Any]) -> dict[str, Any]:
    return {field: event.get(field, "") for field in CSV_FIELDS}


def summary_matches(event: dict[str, Any], patterns: list[re.Pattern[str]]) -> bool:
    if not patterns:
        return True
    searchable = "\n".join(
        str(event.get(field, ""))
        for field in (
            "datetime",
            "message",
            "timestamp_desc",
            "forensic_evidence",
            "forensic_source",
            "parser",
            "data_type",
            "source",
            "display_name",
            "tag",
        )
    )
    return any(pattern.search(searchable) for pattern in patterns)


def write_html_summary(path: Path, events: list[dict[str, Any]], title: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(
            '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
            f"<title>{html.escape(title)}</title>"
            "<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#17202a}"
            "table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd1d1;"
            "padding:.35rem;vertical-align:top;text-align:left}th{background:#eef2f3;"
            "position:sticky;top:0}tr:nth-child(even){background:#fafafa}"
            "td:nth-child(4){white-space:pre-wrap;word-break:break-word}</style>"
            "</head><body>"
            f"<h1>{html.escape(title)}</h1>"
            "<p>This is a bounded readable subset. Use the full JSONL or CSV for "
            "complete examination.</p><table><thead><tr>"
        )
        for field in CSV_FIELDS:
            stream.write(f"<th>{html.escape(field)}</th>")
        stream.write("</tr></thead><tbody>")
        for event in events:
            stream.write("<tr>")
            row = csv_event(event)
            for field in CSV_FIELDS:
                stream.write(f"<td>{html.escape(str(row[field]))}</td>")
            stream.write("</tr>")
        stream.write("</tbody></table></body></html>\n")


def load_manifest(
    manifest_path: Path, read_roots: list[Path], output_root: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    require_within(manifest_path, read_roots, "manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TimelineError(f"cannot read manifest: {exc}") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != SCHEMA_VERSION
    ):
        raise TimelineError(f"manifest schema_version must be {SCHEMA_VERSION}")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise TimelineError("manifest inputs must be a non-empty list")

    validated: list[dict[str, Any]] = []
    for index, raw_record in enumerate(inputs):
        if not isinstance(raw_record, dict):
            raise TimelineError(f"manifest input {index} is not an object")
        input_format = raw_record.get("format")
        if input_format not in SUPPORTED_FORMATS:
            raise TimelineError(
                f"manifest input {index} format must be one of {sorted(SUPPORTED_FORMATS)}"
            )
        path_value = raw_record.get("path")
        if not isinstance(path_value, str) or not path_value:
            raise TimelineError(f"manifest input {index} has no path")
        path = Path(path_value).expanduser().resolve(strict=True)
        if not path.is_file():
            raise TimelineError(f"manifest input {index} is not a file: {path}")
        require_within(path, read_roots, f"manifest input {index}")
        if is_relative_to(path, output_root):
            raise TimelineError(f"manifest input {index} is inside the output root")
        digest = file_sha256(path)
        expected = raw_record.get("sha256")
        if expected is not None:
            if not isinstance(expected, str) or not re.fullmatch(
                r"[0-9A-Fa-f]{64}", expected
            ):
                raise TimelineError(
                    f"manifest input {index} sha256 must be 64 hexadecimal characters"
                )
            if expected.lower() != digest:
                raise TimelineError(
                    f"manifest input {index} SHA-256 mismatch: "
                    f"expected {expected}, got {digest}"
                )
        validated.append(
            {
                "format": input_format,
                "evidence_label": validate_label(
                    raw_record.get("evidence_label"), "evidence_label"
                ),
                "source_label": validate_label(
                    raw_record.get("source_label"), "source_label"
                ),
                "path": str(path),
                "resolved_path": path,
                "size_bytes": path.stat().st_size,
                "sha256": digest,
            }
        )
    return manifest, validated


def build_timeline(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).expanduser().resolve(strict=True)
    read_roots = [
        Path(value).expanduser().resolve(strict=True) for value in args.allow_read_root
    ]
    output_root = Path(args.output_dir).expanduser().resolve(strict=False)
    for read_root in read_roots:
        if not read_root.is_dir():
            raise TimelineError(f"approved read root is not a directory: {read_root}")
        if is_relative_to(output_root, read_root) or is_relative_to(
            read_root, output_root
        ):
            raise TimelineError(
                f"output root and approved read root overlap: {output_root} / {read_root}"
            )
    output_root.mkdir(parents=True, exist_ok=True)
    output_root = output_root.resolve(strict=True)

    existing = [
        output_root / name for name in OUTPUT_NAMES if (output_root / name).exists()
    ]
    if existing and not args.force:
        raise TimelineError(
            "refusing to replace completed outputs without --force: "
            + ", ".join(str(path) for path in existing)
        )

    manifest, inputs = load_manifest(manifest_path, read_roots, output_root)
    patterns = []
    for expression in args.summary_regex:
        try:
            patterns.append(re.compile(expression, re.IGNORECASE))
        except re.error as exc:
            raise TimelineError(
                f"invalid --summary-regex {expression!r}: {exc}"
            ) from exc

    partial_paths = {
        name: output_root / f".{name}.partial" for name in OUTPUT_NAMES[:-1]
    }
    provenance_partial = output_root / ".super-timeline.provenance.json.partial"
    temporary_root = Path(
        tempfile.mkdtemp(prefix=".super-timeline-sort-", dir=output_root)
    )
    chunk_paths: list[Path] = []
    records: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    errors: list[dict[str, Any]] = []
    error_count = 0
    input_counts: list[dict[str, int]] = []

    try:
        for input_index, input_record in enumerate(inputs):
            accepted = 0
            rejected = 0
            try:
                rows = input_rows(input_record, args.max_input_line_bytes)
                for row_number, row in rows:
                    try:
                        records.append(
                            normalize_event(row, input_record, input_index, row_number)
                        )
                        accepted += 1
                    except TimelineError as exc:
                        rejected += 1
                        error_count += 1
                        if len(errors) < args.max_recorded_errors:
                            errors.append(
                                {
                                    "input_index": input_index,
                                    "row": row_number,
                                    "error": str(exc),
                                }
                            )
                    if len(records) >= args.chunk_events:
                        chunk_paths.append(
                            write_chunk(records, temporary_root, len(chunk_paths))
                        )
                        records = []
            except TimelineError as exc:
                raise TimelineError(
                    f"input {input_index} ({input_record['path']}) failed: {exc}"
                ) from exc
            input_counts.append({"accepted": accepted, "rejected": rejected})

        if records:
            chunk_paths.append(write_chunk(records, temporary_root, len(chunk_paths)))
        if not chunk_paths:
            raise TimelineError("no valid events were produced")

        summary_events: list[dict[str, Any]] = []
        summary_match_count = 0
        event_count = 0
        with (
            partial_paths["super-timeline.jsonl"].open(
                "w", encoding="utf-8", newline="\n"
            ) as jsonl_stream,
            partial_paths["super-timeline.csv"].open(
                "w", encoding="utf-8", newline=""
            ) as csv_stream,
            partial_paths["super-timeline-summary.csv"].open(
                "w", encoding="utf-8", newline=""
            ) as summary_stream,
        ):
            csv_writer = csv.DictWriter(csv_stream, fieldnames=CSV_FIELDS)
            summary_writer = csv.DictWriter(summary_stream, fieldnames=CSV_FIELDS)
            csv_writer.writeheader()
            summary_writer.writeheader()
            for event in merge_chunks(chunk_paths):
                jsonl_stream.write(
                    json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
                )
                csv_writer.writerow(csv_event(event))
                event_count += 1
                if summary_matches(event, patterns):
                    summary_match_count += 1
                    if len(summary_events) < args.summary_limit:
                        summary_events.append(event)
                        summary_writer.writerow(csv_event(event))

        write_html_summary(
            partial_paths["super-timeline-summary.html"],
            summary_events,
            validate_label(
                manifest.get("title", "Cross-source forensic timeline"), "title"
            ),
        )

        outputs = []
        for name in OUTPUT_NAMES[:-1]:
            partial_path = partial_paths[name]
            outputs.append(
                {
                    "path": str(output_root / name),
                    "size_bytes": partial_path.stat().st_size,
                    "sha256": file_sha256(partial_path),
                }
            )
        provenance = {
            "schema_version": SCHEMA_VERSION,
            "created_utc": utc_now(),
            "manifest": {
                "path": str(manifest_path),
                "size_bytes": manifest_path.stat().st_size,
                "sha256": file_sha256(manifest_path),
            },
            "inputs": [
                {key: value for key, value in record.items() if key != "resolved_path"}
                | input_counts[index]
                for index, record in enumerate(inputs)
            ],
            "normalization": {
                "timezone": "UTC",
                "stable_sort": [
                    "timestamp_nanoseconds",
                    "evidence_label",
                    "source_label",
                    "input_index",
                    "input_row",
                ],
                "external_sort_chunk_events": args.chunk_events,
                "plaso_storages_merged": False,
                "input_contract": sorted(SUPPORTED_FORMATS),
            },
            "event_count": event_count,
            "rejected_event_count": error_count,
            "recorded_errors": errors,
            "recorded_errors_truncated": error_count > len(errors),
            "summary": {
                "event_count": len(summary_events),
                "matching_event_count": summary_match_count,
                "limit": args.summary_limit,
                "truncated": summary_match_count > len(summary_events),
                "selection": (
                    {"regex": args.summary_regex}
                    if args.summary_regex
                    else {"method": "first events in stable chronological order"}
                ),
            },
            "outputs": outputs,
            "runtime": {
                "program": "build_super_timeline.py",
                "python": sys.version.split()[0],
            },
        }
        provenance_partial.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        # Promote the output set only after every output and its provenance have
        # been generated and hashed.  Remove an old provenance record first in
        # forced mode so an interrupted promotion cannot leave stale provenance
        # apparently authenticating a partially replaced output set.
        final_provenance = output_root / "super-timeline.provenance.json"
        if final_provenance.exists():
            final_provenance.unlink()
        for name, partial_path in partial_paths.items():
            os.replace(partial_path, output_root / name)
        os.replace(provenance_partial, output_root / "super-timeline.provenance.json")
        print(
            json.dumps(
                {
                    "event_count": event_count,
                    "rejected_event_count": error_count,
                    "output": str(output_root),
                    "summary_event_count": len(summary_events),
                },
                sort_keys=True,
            )
        )
        return 0 if error_count == 0 else 2
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
        for partial_path in partial_paths.values():
            partial_path.unlink(missing_ok=True)
        provenance_partial.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Externally sort Plaso exports and normalized Volatility timeliner "
            "events into a cross-source UTC timeline"
        )
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--allow-read-root", action="append", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--chunk-events", type=int, default=100_000)
    parser.add_argument("--max-input-line-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--max-recorded-errors", type=int, default=100)
    parser.add_argument("--summary-limit", type=int, default=1_000)
    parser.add_argument("--summary-regex", action="append", default=[])
    parser.add_argument("--force", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.chunk_events < 1:
        raise SystemExit("--chunk-events must be positive")
    if args.max_input_line_bytes < 1024:
        raise SystemExit("--max-input-line-bytes must be at least 1024")
    if args.max_recorded_errors < 0:
        raise SystemExit("--max-recorded-errors cannot be negative")
    if args.summary_limit < 1:
        raise SystemExit("--summary-limit must be positive")
    try:
        return build_timeline(args)
    except (OSError, TimelineError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
