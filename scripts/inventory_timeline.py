#!/usr/bin/env python3
"""Offline inventory metadata overview. Never opens an image or runs a child tool."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import time
import types

VERSION = 1
CONTROL_RESERVE = 2 * 1024 * 1024
CATALOG_BUFFER_BYTES = 64 * 1024
FIELDS = ("atime_epoch", "mtime_epoch", "ctime_epoch", "crtime_epoch")
STAGES = ("mmls", "fsstat", "fls_root", "fls_recursive", "fls_bodyfile", "ils_all", "ils_orphan",
          "version_mmls", "version_fsstat", "version_fls", "version_ils")
LIMITATIONS = [
    "Filesystem timestamps are metadata observations, not human opens, deletion dates or communications.",
    "Directory-entry deletion flags do not independently establish MFT allocation or historical ownership.",
    "Only cataloged names/attributes are covered; fls recursion does not descend deleted directories.",
    "UTC is rendering, not a finding about the source computer timezone or clock accuracy.",
    "Unique stream logical sizes are planning observations, not guaranteed recoverable bytes.",
    "Root paths and extension candidates are name groupings, not findings about drive use.",
    "The image identity is inherited from the completed inventory; no image was opened or independently reverified here.",
]


class TimelineError(RuntimeError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def encode(value):
    return (json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise TimelineError("Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(TimelineError("Nonfinite JSON number")))


def digest(stream):
    stream.seek(0)
    h = hashlib.sha256()
    count = lines = 0
    last = b""
    while data := stream.read(1024 * 1024):
        h.update(data)
        count += len(data)
        lines += data.count(b"\n")
        last = data[-1:]
    stream.seek(0)
    return {"sha256": h.hexdigest(), "bytes": count, "lines": lines + int(bool(last) and last != b"\n")}


def load_gate(path, expected):
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected:
        raise TimelineError("Reviewed inventory module SHA256 mismatch")
    name = "_timeline_reviewed_inventory"
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(payload, str(path), "exec"), module.__dict__)
    return module


def absolute(path):
    return Path(os.path.abspath(path))


def overlap(a, b):
    return a == b or a in b.parents or b in a.parents


def validate_paths(args, gate):
    for name in ("inventory_dir", "inventory_module", "output_dir", "state_dir"):
        path = getattr(args, name)
        gate.require_unaliased(path)
    for root in (args.output_dir, args.state_dir):
        if root.exists() or root.is_symlink() or not root.parent.is_dir():
            raise TimelineError("Output/state roots must be new directories with existing parents")
        for other in (args.inventory_dir, args.inventory_module, args.output_dir, args.state_dir):
            if root != other and overlap(root, other):
                raise TimelineError("Input, output and state roots must be disjoint")
    if args.output_dir == args.state_dir:
        raise TimelineError("Output/state roots must differ")


def bind_inputs(args, gate, stack):
    streams, records, objects = {}, {}, {}
    for name in ("manifest.json", "status.json", "bodyfile-catalog.jsonl"):
        path = args.inventory_dir / name
        gate.require_unaliased(path)
        stream = stack.enter_context(gate.protected_file(path))
        metadata = gate.metadata(os.fstat(stream.fileno()))
        if os.fstat(stream.fileno()).st_nlink != 1:
            raise TimelineError("Inventory inputs must have one hard link")
        if name != "bodyfile-catalog.jsonl" and metadata["size"] > 1024 * 1024:
            raise TimelineError("Inventory sidecar exceeds one MiB")
        records[name] = {"path": str(path), "metadata": metadata, **digest(stream)}
        streams[name] = stream
        if name != "bodyfile-catalog.jsonl":
            objects[name] = strict_json(stream.read())
            stream.seek(0)
            if not isinstance(objects[name], dict):
                raise TimelineError("Inventory sidecar must be an object")
    manifest, status = objects["manifest.json"], objects["status.json"]
    config = manifest.get("configuration", {})
    if type(config.get("schema_version")) is not int or type(status.get("schema_version")) is not int or config["schema_version"] != 1 or status["schema_version"] != 1:
        raise TimelineError("Unsupported inventory schema")
    if status.get("phase") != "complete" or status.get("current_stage") is not None or not status.get("completed_utc"):
        raise TimelineError("Inventory is not complete")
    if config.get("script_sha256") != args.inventory_sha256 or config.get("catalog_bodyfile") is not True:
        raise TimelineError("Inventory producer/catalog configuration does not match reviewed producer")
    if not isinstance(config.get("output_dir"), str) or not gate.same_path(config["output_dir"], args.inventory_dir):
        raise TimelineError("Inventory directory does not match its manifest")
    identity = manifest.get("image_identity")
    if not isinstance(identity, dict) or identity != status.get("image_identity"):
        raise TimelineError("Inventory sidecars disagree on inherited image identity")
    if (not re.fullmatch(r"[0-9a-f]{64}", str(identity.get("sha256", ""))) or
            type(identity.get("size")) is not int or identity["size"] <= 0 or
            not isinstance(identity.get("image"), str) or not isinstance(config.get("image"), str) or
            not gate.same_path(identity["image"], config["image"])):
        raise TimelineError("Inherited image identity is malformed")
    # Only lexical comparisons: never resolve, stat or open any recorded image path.
    for key in ("image", "preservation_state", "preservation_exit_code", "tsk_bin"):
        value = config.get(key)
        if not isinstance(value, str) or not os.path.isabs(value):
            raise TimelineError("Inventory contains malformed source configuration")
        for root in (args.output_dir, args.state_dir):
            if overlap(root, absolute(value)):
                raise TimelineError("Output/state overlaps a recorded upstream location")
    if (type(config.get("sector_size")) is not int or config["sector_size"] not in (512, 1024, 2048, 4096) or
            type(config.get("partition_offset_sectors")) is not int or config["partition_offset_sectors"] < 0):
        raise TimelineError("Invalid inherited inventory geometry")
    stage_names = set(status.get("stages", {}))
    if not set(STAGES).issubset(stage_names):
        raise TimelineError("Inventory required stages missing")
    for stage in status["stages"].values():
        if stage.get("state") != "complete" or type(stage.get("exit_code")) is not int or stage["exit_code"] != 0:
            raise TimelineError("Inventory has a stage that did not complete successfully")
    body_stage = status["stages"]["fls_bodyfile"]
    validation = body_stage.get("validation", {})
    actual = records["bodyfile-catalog.jsonl"]
    recorded = status.get("bodyfile_catalog", {})
    if (not isinstance(recorded.get("path"), str) or not os.path.isabs(recorded["path"]) or
            not gate.same_path(recorded["path"], args.inventory_dir / "bodyfile-catalog.jsonl") or
            type(recorded.get("bytes")) is not int or type(recorded.get("lines")) is not int or
            any(recorded.get(k) != actual[k] for k in ("sha256", "bytes", "lines")) or
            type(validation.get("parse_errors")) is not int or validation["parse_errors"] != 0 or
            type(validation.get("rows")) is not int or validation["rows"] != actual["lines"]):
        raise TimelineError("Completed catalog hash/count/validation binding mismatch")
    body_record = body_stage.get("stdout", {})
    if not re.fullmatch(r"[0-9a-f]{64}", str(body_record.get("sha256", ""))):
        raise TimelineError("Missing source bodyfile reference")
    body_path = body_record.get("path")
    if (not isinstance(body_path, str) or not os.path.isabs(body_path) or
            absolute(body_path).parent != args.inventory_dir / "fls_bodyfile" or
            not re.fullmatch(r"[0-9]+\.stdout\.bin", absolute(body_path).name)):
        raise TimelineError("Source bodyfile reference escapes selected inventory stage")
    return streams, records, {"image_identity": identity, "configuration": config,
                             "bodyfile_reference": body_record,
                             "upstream_limitations": manifest.get("limitations", [])}


class Budget:
    def __init__(self, args, gate):
        self.args, self.gate = args, gate
        self.cached_used = None
        self.last_capacity_check = 0.0

    def used(self):
        total = 0
        for root in (self.args.output_dir, self.args.state_dir):
            self.gate.require_unaliased(root)
            for path in root.iterdir():
                self.gate.safe_mutable_file(path)
                total += path.stat().st_size
        return total

    def check(self, additional=0, control=False):
        cap = self.args.max_output_bytes - (0 if control else CONTROL_RESERVE)
        if self.used() + additional > cap:
            raise TimelineError("Explicit total output budget would be crossed")
        for root in (self.args.output_dir, self.args.state_dir):
            if shutil.disk_usage(root).free < self.args.reserve_bytes + additional:
                raise TimelineError("Free-space reserve would be crossed")

    def write(self, stream, data):
        # The database is frozen while JSONL is emitted. Track exact new bytes,
        # and periodically recheck shared-disk free space and all controlled paths.
        if self.cached_used is None or time.monotonic() - self.last_capacity_check >= 5:
            self.check(len(data))
            self.cached_used = self.used()
            self.last_capacity_check = time.monotonic()
        if self.cached_used + len(data) > self.args.max_output_bytes - CONTROL_RESERVE:
            raise TimelineError("Explicit total output budget would be crossed")
        stream.write(data)
        stream.flush()
        self.cached_used += len(data)

    def database_limit(self, db):
        self.check()
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        current_pages = db.execute("PRAGMA page_count").fetchone()[0]
        available = self.args.max_output_bytes - CONTROL_RESERVE - self.used()
        available = min(available, *(shutil.disk_usage(root).free - self.args.reserve_bytes
                                    for root in (self.args.output_dir, self.args.state_dir)))
        db.execute("PRAGMA max_page_count=" + str(current_pages + max(0, available // page_size)))

    def control(self, path, value):
        data = encode(value)
        if len(data) > CONTROL_RESERVE // 4:
            raise TimelineError("Control record too large")
        self.gate.safe_mutable_file(path)
        temporary = path.with_name(path.name + ".tmp")
        self.check(len(data), control=True)
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        self.cached_used = None


def open_database(path):
    # No shared SQLite temp directory or process-global environment changes.
    # Every ordered/grouped traversal below uses a persistent primary-key index.
    with path.open("xb"):
        pass
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA cache_size=-16384")
    db.execute("PRAGMA temp_store=FILE")
    db.executescript("""
      CREATE TABLE rows(row_id INTEGER PRIMARY KEY, source_line INTEGER UNIQUE, byte_offset INTEGER,
        byte_length INTEGER, row_sha256 TEXT, raw BLOB, path_json TEXT, stream_id TEXT, row_json TEXT);
      CREATE TABLE streams(stream_id TEXT PRIMARY KEY, aliases INTEGER, min_size TEXT, max_size TEXT,
        flag_mask INTEGER, first_row INTEGER, is_data INTEGER) WITHOUT ROWID;
      CREATE TABLE events(bucket INTEGER, digits INTEGER, sort_text TEXT, row_id INTEGER,
        field_order INTEGER, epoch_json TEXT, epoch_decimal TEXT, epoch_status TEXT, utc TEXT,
        year INTEGER, is_negative INTEGER, is_future INTEGER,
        PRIMARY KEY(bucket,digits,sort_text,row_id,field_order)) WITHOUT ROWID;
      CREATE TABLE groups(kind TEXT, name_json TEXT, count INTEGER,
        PRIMARY KEY(kind,name_json)) WITHOUT ROWID;
    """)
    db.commit()
    return db


def timestamp(value, reference_epoch):
    original = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    if type(value) is not int:
        return (3, 0, original, original, None, "invalid_type", None, None, 0, 0)
    decimal = str(value)
    digits = decimal.lstrip("-")
    bucket = 0 if value < 0 else 1 if value == 0 else 2
    order_len = -len(digits) if value < 0 else len(digits)
    order_text = "".join(str(9 - int(x)) for x in digits) if value < 0 else digits
    utc = year = None
    state = "zero_unknown" if value == 0 else "valid"
    if value:
        try:
            date = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=value)
            utc = date.isoformat(timespec="seconds").replace("+00:00", "Z")
            year = date.year
        except (OverflowError, ValueError):
            state = "outside_datetime_range"
    return (bucket, order_len, order_text, original, decimal, state, utc, year,
            int(value < 0), int(value > reference_epoch))


def row_class(row):
    if not row["deletion_corroborated"]:
        return "uncorroborated_name", 8
    if not row["deleted"]:
        return "corroborated_allocated_name", 1
    if row["reallocated"]:
        return "corroborated_deleted_reallocated_name", 4
    return "corroborated_deleted_name", 2


def name_groups(row):
    path = row["full_path"]
    if row["deletion_corroborated"] and row["deleted"]:
        suffix = " (deleted-realloc)" if row["reallocated"] else " (deleted)"
        if path.endswith(suffix):
            path = path[:-len(suffix)]
    parts = path.lstrip("/").split("/")
    root = parts[0] if parts[0] else "/"
    leaf = parts[-1].split(":", 1)[0]
    extension = leaf.rsplit(".", 1)[1].lower() if "." in leaf and not leaf.endswith(".") else ""
    return root, extension


def validate_row(row):
    if not isinstance(row, dict) or type(row.get("schema_version")) is not int or row["schema_version"] != 1:
        raise TimelineError("Malformed catalog row/schema")
    for field in ("full_path", "inode_attribute", "mode", "deletion_basis"):
        if not isinstance(row.get(field), str):
            raise TimelineError("Missing catalog string field: " + field)
    if not re.fullmatch(r"[0-9]+(?:-[0-9]+-[0-9]+)?", row["inode_attribute"]):
        raise TimelineError("Invalid full inode/attribute ID")
    for field in ("source_line", "size", "uid", "gid"):
        if type(row.get(field)) is not int or row[field] < (1 if field == "source_line" else 0):
            raise TimelineError("Invalid catalog integer: " + field)
    if row["source_line"] > 2**63 - 1:
        raise TimelineError("Source line does not fit row-reference index")
    for field in ("deleted", "reallocated", "deletion_corroborated", "deleted_suffix_candidate"):
        if type(row.get(field)) is not bool:
            raise TimelineError("Invalid deletion flag: " + field)
    if not re.fullmatch(r"[0-9a-f]{64}", str(row.get("raw_line_sha256", ""))):
        raise TimelineError("Missing original bodyfile row hash")


def increment(db, kind, name, amount=1):
    key = json.dumps(name, ensure_ascii=True, separators=(",", ":"))
    db.execute("INSERT INTO groups VALUES(?,?,?) ON CONFLICT(kind,name_json) DO UPDATE SET count=count+excluded.count", (kind, key, amount))


def import_rows(args, catalog, db, budget, progress, reference_epoch):
    catalog.seek(0)
    buffered = io.BufferedReader(catalog, buffer_size=CATALOG_BUFFER_BYTES)
    try:
        return import_buffered_rows(args, buffered, db, budget, progress, reference_epoch)
    finally:
        try:
            position = buffered.tell()
        finally:
            buffered.detach()  # The caller's protected context retains lock/close ownership.
        catalog.seek(position)  # Discard read-ahead without changing the logical position.


def import_buffered_rows(args, catalog, db, budget, progress, reference_epoch):
    h = hashlib.sha256()
    row_id = offset = invalid_times = previous_source_line = 0
    last_update = time.monotonic()
    while raw := catalog.readline(args.max_line_bytes + 1):
        if len(raw) > args.max_line_bytes:
            raise TimelineError("Catalog row exceeds explicit line limit")
        h.update(raw)
        row_id += 1
        row = strict_json(raw)
        validate_row(row)
        if row["source_line"] <= previous_source_line:
            raise TimelineError("Completed inventory source lines must increase")
        previous_source_line = row["source_line"]
        row_sha = hashlib.sha256(raw).hexdigest()
        path_json = json.dumps(row["full_path"], ensure_ascii=True)
        row_json = encode(row).decode("ascii").rstrip("\n")
        stream_id = row["inode_attribute"]
        is_data = int(bool(re.fullmatch(r"[0-9]+-128-[0-9]+", stream_id)))
        classification, mask = row_class(row)
        if row_id == 1 or row_id % 128 == 0 or time.monotonic() - last_update >= 5:
            db.commit()
            budget.database_limit(db)
        db.execute("INSERT INTO rows VALUES(?,?,?,?,?,?,?,?,?)", (row_id, row["source_line"], offset, len(raw), row_sha, raw, path_json, stream_id, row_json))
        existing = db.execute("SELECT aliases,min_size,max_size,flag_mask FROM streams WHERE stream_id=?", (stream_id,)).fetchone()
        size = row["size"]
        if existing:
            aliases, smallest, largest, previous_mask = existing
            db.execute("UPDATE streams SET aliases=?,min_size=?,max_size=?,flag_mask=? WHERE stream_id=?",
                       (aliases + 1, str(min(size, int(smallest))), str(max(size, int(largest))), previous_mask | mask, stream_id))
        else:
            db.execute("INSERT INTO streams VALUES(?,?,?,?,?,?,?)", (stream_id, 1, str(size), str(size), mask, row_id, is_data))
        increment(db, "row_attribute_type", stream_id.split("-")[1] if "-" in stream_id else "unspecified")
        increment(db, "row_name_state", classification)
        root, extension = name_groups(row)
        increment(db, "root_path_rows", root)
        if is_data:
            increment(db, "data_root_path_rows", root)
            increment(db, "data_extension_candidate_rows", extension)
        for field_order, field in enumerate(FIELDS):
            value = row.get(field)
            bucket, length, sort_text, original, decimal, state, utc, year, negative, future = timestamp(value, reference_epoch)
            invalid_times += state == "invalid_type"
            db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (bucket, length, sort_text, row_id, field_order, original, decimal, state, utc, year, negative, future))
            increment(db, "timestamp_status", state)
            increment(db, "timestamp_field_status", [field, state])
            if year is not None:
                increment(db, "timestamp_year", year)
                increment(db, "timestamp_field_year", [field, year])
            if negative:
                increment(db, "timestamp_flags", "negative")
            if future:
                increment(db, "timestamp_flags", "future_after_reference")
        offset += len(raw)
        progress.update(catalog_rows=row_id, catalog_bytes=offset, timestamp_records=row_id * 4)
        # Cache and page limits bound pending writes; commit at bounded batches.
        if time.monotonic() - last_update >= 5:
            progress.update(phase="indexing", catalog_rows=row_id, catalog_bytes=offset, timestamp_records=row_id * 4)
            budget.control(args.state_dir / "status.json", progress)
            last_update = time.monotonic()
    db.commit()
    return {"catalog_rows": row_id, "catalog_bytes": offset, "catalog_sha256": h.hexdigest(),
            "timestamp_records": row_id * 4, "invalid_timestamp_fields": invalid_times}


def row_reference(record, catalog_record):
    row_id, source_line, byte_offset, byte_length, row_sha, row_json = record
    row = strict_json(row_json)
    return {"catalog_sha256": catalog_record["sha256"], "catalog_line": row_id,
            "catalog_byte_offset": byte_offset, "catalog_byte_length": byte_length,
            "catalog_raw_line_sha256": row_sha, "bodyfile_source_line": source_line,
            "bodyfile_raw_line_sha256": row["raw_line_sha256"]}, row


def emit_outputs(args, db, budget, catalog_record, progress):
    artifact_names = ("catalog-rows.jsonl", "filesystem-timestamps.jsonl", "streams.jsonl", "groups.jsonl", "summary.md")
    counts = {"unique_stream_ids": 0, "unique_data_stream_ids": 0, "data_size_conflicts": 0,
              "all_size_conflicts": 0, "consistent_data_logical_bytes": 0, "data_alias_rows": 0,
              "data_stream_name_masks": {}, "earliest_valid_year": None, "latest_valid_year": None}
    columns = "row_id,source_line,byte_offset,byte_length,row_sha256,row_json"
    last_progress = time.monotonic()
    def update_progress(phase, count):
        nonlocal last_progress
        if time.monotonic() - last_progress >= 5:
            progress.update(phase=phase, emitted_records_in_phase=count, updated_utc=utc_now())
            budget.control(args.state_dir / "status.json", progress)
            last_progress = time.monotonic()
    with (args.output_dir / artifact_names[0]).open("xb") as out:
        for record in db.execute("SELECT " + columns + " FROM rows ORDER BY row_id"):
            ref, row = row_reference(record, catalog_record)
            budget.write(out, encode({"schema_version": 1, "reference": ref,
                                      "path_encoding": "JSON ASCII escapes; surrogateescape code points retained",
                                      "catalog_row": row}))
            update_progress("emitting_catalog_rows", record[0])
        os.fsync(out.fileno())
    progress.update(phase="emitting_timestamps")
    budget.control(args.state_dir / "status.json", progress)
    with (args.output_dir / artifact_names[1]).open("xb") as out:
        for emitted, event in enumerate(db.execute("SELECT row_id,field_order,epoch_json,epoch_decimal,epoch_status,utc,year,is_negative,is_future FROM events ORDER BY bucket,digits,sort_text,row_id,field_order"), 1):
            row_id, field_order, original, decimal, state, utc, year, negative, future = event
            record = db.execute("SELECT " + columns + " FROM rows WHERE row_id=?", (row_id,)).fetchone()
            ref, row = row_reference(record, catalog_record)
            budget.write(out, encode({"schema_version": 1, "reference": ref, "inode_attribute": row["inode_attribute"],
                                      "full_path": row["full_path"], "timestamp_field": FIELDS[field_order],
                                      "original_epoch": strict_json(original), "original_epoch_decimal": decimal,
                                      "utc": utc, "timestamp_status": state, "negative_epoch": bool(negative),
                                      "future_after_reference": bool(future), "observation_type": "filesystem_metadata_timestamp"}))
            update_progress("emitting_timestamps", emitted)
        os.fsync(out.fileno())
    with (args.output_dir / artifact_names[2]).open("xb") as out:
        for stream_id, aliases, smallest, largest, mask, first_row, is_data in db.execute("SELECT * FROM streams ORDER BY stream_id"):
            conflict = smallest != largest
            counts["unique_stream_ids"] += 1
            counts["all_size_conflicts"] += conflict
            if is_data:
                counts["unique_data_stream_ids"] += 1
                counts["data_size_conflicts"] += conflict
                counts["data_alias_rows"] += aliases
                if not conflict:
                    counts["consistent_data_logical_bytes"] += int(smallest)
                counts["data_stream_name_masks"][str(mask)] = counts["data_stream_name_masks"].get(str(mask), 0) + 1
            budget.write(out, encode({"schema_version": 1, "inode_attribute": stream_id, "is_data_attribute": bool(is_data),
                                      "alias_rows": aliases, "first_catalog_line": first_row,
                                      "minimum_observed_size": int(smallest), "maximum_observed_size": int(largest),
                                      "size_conflict": conflict, "name_state_mask": mask,
                                      "alias_reference": "catalog-rows.jsonl, matching full inode_attribute; original rows also in index.sqlite"}))
            update_progress("emitting_streams", counts["unique_stream_ids"])
        os.fsync(out.fileno())
    top_roots, top_extensions = [], []
    with (args.output_dir / artifact_names[3]).open("xb") as out:
        for kind, name_json, count in db.execute("SELECT * FROM groups ORDER BY kind,name_json"):
            name = strict_json(name_json)
            budget.write(out, encode({"kind": kind, "name": name, "count": count}))
            if kind == "timestamp_year":
                counts["earliest_valid_year"] = min(name, counts["earliest_valid_year"] or name)
                counts["latest_valid_year"] = max(name, counts["latest_valid_year"] or name)
            target = top_roots if kind == "data_root_path_rows" else top_extensions if kind == "data_extension_candidate_rows" else None
            if target is not None:
                target.append((count, name_json))
                target.sort(key=lambda item: (-item[0], item[1]))
                del target[20:]
        os.fsync(out.fileno())
    safe = lambda value: value.replace("`", "\\u0060").replace("<", "\\u003c").replace(">", "\\u003e")
    def markdown_group(count, name_json):
        label = safe(name_json)
        suffix = ""
        if len(label) > 240:
            label = label[:237] + "..."
            suffix = " (display truncated; full name in groups.jsonl and catalog records)"
        return f"- `{label}`: {count}{suffix}"
    lines = ["# Filesystem metadata overview", "", "Catalog metadata observations only. No drive-use, ownership or contact conclusions.", "",
             f"Catalog rows: {progress['catalog_rows']}; timestamp records: {progress['timestamp_records']}; invalid timestamp fields retained: {progress['invalid_timestamp_fields']}.",
             f"Distinct full attribute IDs: {counts['unique_stream_ids']}; DATA IDs: {counts['unique_data_stream_ids']}.",
             f"DATA IDs with conflicting observed sizes: {counts['data_size_conflicts']}.",
             f"Sum of consistent logical DATA sizes, one per ID: {counts['consistent_data_logical_bytes']} bytes (not a recoverability claim).",
             f"UTC-convertible timestamp year span, including outliers: {counts['earliest_valid_year']} to {counts['latest_valid_year']}.", "",
             "## DATA name-state masks", "", "1 = corroborated allocated name; 2 = corroborated deleted name; 4 = deleted/reallocated name; 8 = uncorroborated name. Combined masks retain mixed alias observations.", "",
             "`" + json.dumps(counts["data_stream_name_masks"], sort_keys=True) + "`", "",
             "## Largest root-name groups by DATA catalog rows (up to 20)", ""]
    lines += [markdown_group(count, name) for count, name in top_roots]
    lines += ["", "## Extension candidates by DATA catalog rows (up to 20)", ""]
    lines += [markdown_group(count, name) for count, name in top_extensions]
    lines += ["", "All groups/year counts are in groups.jsonl. Exact aliases, source references and stream IDs are preserved in catalog-rows.jsonl and index.sqlite.", "", "## Limits", ""]
    lines += ["- " + text for text in LIMITATIONS]
    with (args.output_dir / artifact_names[4]).open("xb") as out:
        budget.write(out, ("\n".join(lines) + "\n").encode("utf-8"))
        os.fsync(out.fileno())
    return counts


def run(args):
    gate = load_gate(args.inventory_module, args.inventory_sha256)
    validate_paths(args, gate)
    with ExitStack() as stack:
        streams, records, inherited = bind_inputs(args, gate, stack)
        args.output_dir.mkdir()
        args.state_dir.mkdir()
        budget = Budget(args, gate)
        progress = {"schema_version": VERSION, "phase": "starting", "started_utc": utc_now(),
                    "catalog_rows": 0, "timestamp_records": 0, "output_dir": str(args.output_dir),
                    "state_dir": str(args.state_dir), "max_output_bytes": args.max_output_bytes,
                    "reserve_bytes": args.reserve_bytes}
        db = None
        try:
            reference = datetime.fromisoformat(args.reference_utc.replace("Z", "+00:00"))
            reference_epoch = int((reference - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())
            manifest = {"schema_version": VERSION, "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "producer_module_sha256": args.inventory_sha256, "inputs": records,
                        "inherited_inventory": inherited, "created_utc": progress["started_utc"],
                        "reference_utc": args.reference_utc, "future_rule": "original integer epoch > reference UTC epoch",
                        "sort_rule": "All integer epochs ascending, then catalog line/field order; invalid types last by JSON representation",
                        "timestamp_fields": FIELDS, "name_state_mask": {"1": "corroborated allocated name", "2": "corroborated deleted name", "4": "corroborated deleted/reallocated name", "8": "uncorroborated name"},
                        "output_budget_includes": "output and state files, including SQLite and control records",
                        "limitations": LIMITATIONS, "python": sys.version, "sqlite_version": sqlite3.sqlite_version}
            budget.control(args.state_dir / "manifest.json", manifest)
            budget.control(args.state_dir / "status.json", progress)
            budget.check(65536)
            db = open_database(args.state_dir / "index.sqlite")
            progress.update(import_rows(args, streams["bodyfile-catalog.jsonl"], db, budget, progress, reference_epoch))
            if any(progress["catalog_" + key] != records["bodyfile-catalog.jsonl"][key] for key in ("bytes", "sha256")):
                raise TimelineError("Catalog changed during indexing")
            if progress["catalog_rows"] != records["bodyfile-catalog.jsonl"]["lines"]:
                raise TimelineError("Catalog line count changed during indexing")
            if db.execute("SELECT COUNT(*) FROM events").fetchone()[0] != progress["timestamp_records"]:
                raise TimelineError("Timestamp index count mismatch")
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise TimelineError("SQLite index quick check failed")
            counts = emit_outputs(args, db, budget, records["bodyfile-catalog.jsonl"], progress)
            db.close()
            db = None
            for name, stream in streams.items():
                if gate.metadata(os.fstat(stream.fileno())) != records[name]["metadata"] or digest(stream) != {k: records[name][k] for k in ("sha256", "bytes", "lines")}:
                    raise TimelineError("Input changed before finalization")
            artifacts = []
            for root in (args.output_dir, args.state_dir):
                for path in sorted(root.iterdir()):
                    if path.name in ("status.json", "output-manifest.json"):
                        continue
                    gate.safe_mutable_file(path)
                    with path.open("rb") as stream:
                        artifacts.append({"path": str(path), **digest(stream)})
            budget.control(args.state_dir / "output-manifest.json", {"schema_version": VERSION, "artifacts": artifacts, "summary": counts})
            with (args.state_dir / "output-manifest.json").open("rb") as stream:
                progress["output_manifest"] = digest(stream)
            progress.update(phase="complete" if not progress["invalid_timestamp_fields"] else "incomplete",
                            completed_utc=utc_now(), summary=counts, limitations=LIMITATIONS)
            if progress["invalid_timestamp_fields"]:
                progress["error"] = "Invalid timestamp types were retained; source catalog contract is not fully satisfied"
            budget.control(args.state_dir / "status.json", progress)
            return 0 if progress["phase"] == "complete" else 2
        except BaseException as exc:
            if db is not None:
                db.close()
            progress.update(phase="failed", stopped_utc=utc_now(), error_type=type(exc).__name__, error=str(exc)[:2000])
            try:
                budget.control(args.state_dir / "status.json", progress)
            except Exception:
                pass
            raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory-dir", "inventory-module", "output-dir", "state-dir"):
        parser.add_argument("--" + name, required=True, type=absolute)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--max-output-bytes", required=True, type=int)
    parser.add_argument("--reserve-bytes", type=int, default=1024**3)
    parser.add_argument("--max-line-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--reference-utc", default=utc_now())
    args = parser.parse_args(argv)
    args.inventory_sha256 = args.inventory_sha256.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", args.inventory_sha256):
        parser.error("Require reviewed inventory producer SHA256")
    if args.max_output_bytes < 4 * CONTROL_RESERVE or args.reserve_bytes < 0 or not 1024 <= args.max_line_bytes <= 16 * 1024 * 1024:
        parser.error("Require output budget >= 8 MiB, reserve >= 0, and line limit 1 KiB..16 MiB")
    try:
        reference = datetime.fromisoformat(args.reference_utc.replace("Z", "+00:00"))
        if reference.tzinfo is None or reference.utcoffset() != timedelta(0):
            raise ValueError("Reference must explicitly use UTC")
    except ValueError as exc:
        parser.error(str(exc))
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        return run(args)
    except Exception as exc:
        print(json.dumps({"phase": "failed", "error_type": type(exc).__name__, "error": str(exc)[:2000]}, ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
