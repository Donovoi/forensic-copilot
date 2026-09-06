#!/usr/bin/env python3
"""Bounded NTFS DATA-stream exports from an explicit reviewed JSONL catalog.

Authored 2026-09-06; Python 3.10+, standard library only. Never mounts an image,
executes recovered files, writes to evidence, or performs carving. Generated
code and its pinned inventory-gate dependency require independent review first.
See docs/catalog-recovery.md. All output/state paths contain private case data.
"""
from __future__ import annotations

import argparse
import contextlib
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import types

GIB = 1024 ** 3
VERSION = 1
LIMITATIONS = [
    "Filesystem-directed exports from cataloged NTFS type-128 DATA attributes only; no carving.",
    "Missing orphan/deleted-directory streams outside the catalog remain an explicit coverage gap.",
    "Deleted/reallocated extraction, even with correct size/hash, does not prove clusters were not reused.",
    "Export validation proves byte fidelity to this icat output, not original content or media parseability.",
    "TSK deletion/reallocation suffixes can be ambiguous with literal filenames; original rows are retained.",
]


class RecoveryError(RuntimeError):
    pass


@dataclass
class Config:
    image: Path
    preservation_state: Path
    preservation_exit_code: Path
    tsk_bin: Path
    catalog: Path
    output_dir: Path
    state_dir: Path
    gate_module: Path
    gate_sha256: str
    partition_offset: int
    sector_size: int
    max_output_bytes: int
    all_files: bool = False
    resume: bool = False
    dry_run: bool = False
    reserve_bytes: int = 64 * GIB
    stream_timeout: float = 1800.0
    progress_seconds: float = 5.0
    # Programmatic synthetic fixtures only; CLI always resolves icat from tsk_bin.
    tool_prefix: tuple[str, ...] | None = None


def load_gate(config):
    payload = config.gate_module.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", config.gate_sha256) or digest != config.gate_sha256.lower():
        raise RecoveryError("Reviewed preservation-gate module SHA256 mismatch")
    name = "_reviewed_recovery_gate"
    module = types.ModuleType(name)
    module.__file__ = str(config.gate_module)
    sys.modules[name] = module
    # Compile the already-hashed bytes, not a potentially changed path.
    exec(compile(payload, str(config.gate_module), "exec"), module.__dict__)
    return module


def normalize(config):
    for name in ("image", "preservation_state", "preservation_exit_code", "tsk_bin", "catalog",
                 "output_dir", "state_dir", "gate_module"):
        setattr(config, name, Path(os.path.abspath(getattr(config, name))))
    if config.partition_offset < 0 or config.sector_size not in (512, 1024, 2048, 4096):
        raise RecoveryError("Require nonnegative sector offset and a supported explicit sector size")
    if re.search(r"\.\d+$", config.image.name):
        raise RecoveryError("Numbered-segment image names are refused to prevent implicit sibling reads")
    if config.max_output_bytes <= 0 or config.reserve_bytes < 0:
        raise RecoveryError("Output byte budget must be positive and reserve nonnegative")
    for value in (config.stream_timeout, config.progress_seconds):
        if not math.isfinite(value) or value <= 0:
            raise RecoveryError("Timeout and progress interval must be finite and positive")
    roots = [config.output_dir, config.state_dir]
    inputs = [config.image, config.preservation_state, config.preservation_exit_code,
              config.tsk_bin, config.catalog.parent, config.catalog, config.gate_module]
    for root in roots:
        if root.is_symlink() or not root.parent.is_dir():
            raise RecoveryError("Output/state parent must exist and root may not be a symbolic link")
        for candidate in inputs + [other for other in roots if other != root]:
            if root == candidate or root in candidate.parents or candidate in root.parents:
                raise RecoveryError("Output/state roots must be disjoint from each other and all inputs")
    if config.output_dir == config.state_dir:
        raise RecoveryError("Output and state roots must differ")


def guard_paths(config, gate):
    # The original/partial image is never resolved or stat'ed before its gate.
    gate.require_unaliased(config.image.parent)
    for name in ("preservation_state", "preservation_exit_code", "tsk_bin", "catalog",
                 "output_dir", "state_dir", "gate_module"):
        gate.require_unaliased(getattr(config, name))


def guard_state(config, gate):
    gate.require_unaliased(config.state_dir)
    if config.state_dir.exists():
        for path in config.state_dir.iterdir():
            gate.safe_mutable_file(path)


def guard_database(path, gate):
    for suffix in ("", "-journal", "-wal", "-shm"):
        gate.safe_mutable_file(Path(str(path) + suffix))


def file_record(gate, path):
    gate.require_unaliased(path)
    with gate.protected_file(path) as stream:
        before = gate.metadata(os.fstat(stream.fileno()))
        digest = hashlib.sha256()
        while data := stream.read(1024 * 1024):
            digest.update(data)
        if gate.metadata(os.fstat(stream.fileno())) != before:
            raise RecoveryError("Input changed while hashing")
    return {"path": str(path), "metadata": before, "sha256": digest.hexdigest()}


def tool_records(config, gate):
    executable = config.tsk_bin / ("icat.exe" if os.name == "nt" else "icat")
    prefix = list(config.tool_prefix) if config.tool_prefix else [str(executable)]
    prefix = [str(Path(os.path.abspath(part))) for part in prefix]
    # Check the supplied leaf before resolution can erase a symlink/junction.
    records = [file_record(gate, Path(part)) for part in prefix]
    if not config.tool_prefix:
        records += [file_record(gate, path) for path in sorted(config.tsk_bin.glob("*.dll"))]
    version = subprocess.run([*prefix, "-V"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=False, timeout=15,
                             creationflags=0x08000000 if os.name == "nt" else 0)
    if version.returncode != 0 or len(version.stdout) + len(version.stderr) > 65536:
        raise RecoveryError("icat version check failed or returned excessive output")
    return prefix, records, {"exit_code": version.returncode,
                            "stdout": version.stdout.decode("utf-8", errors="replace"),
                            "stderr": version.stderr.decode("utf-8", errors="replace")}


def json_record(gate, path):
    gate.require_unaliased(path)
    with gate.protected_file(path) as stream:
        before = gate.metadata(os.fstat(stream.fileno()))
        payload = stream.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            raise RecoveryError("Inventory provenance JSON exceeds one MiB")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise RecoveryError("Inventory provenance JSON must be an object")
        if before != gate.metadata(os.fstat(stream.fileno())):
            raise RecoveryError("Inventory provenance changed while reading")
    return value, {"path": str(path), "metadata": before, "sha256": hashlib.sha256(payload).hexdigest()}


def read_inventory_binding(config, gate, preservation, catalog_record):
    """Bind names/inodes to the exact completed inventory of this verified image."""
    inventory_dir = config.catalog.parent
    gate.require_unaliased(inventory_dir)
    manifest, manifest_record = json_record(gate, inventory_dir / "manifest.json")
    status, status_record = json_record(gate, inventory_dir / "status.json")
    producer = manifest.get("configuration")
    if not isinstance(producer, dict) or producer.get("schema_version") != VERSION:
        raise RecoveryError("Inventory configuration/schema is missing or unsupported")
    if status.get("schema_version") != VERSION or status.get("phase") != "complete":
        raise RecoveryError("Catalog inventory is not complete")
    if (manifest.get("image_identity") != preservation or status.get("image_identity") != preservation):
        raise RecoveryError("Inventory image identity differs from current preservation gate")
    for name, expected in (("image", config.image), ("output_dir", inventory_dir),
                           ("preservation_state", config.preservation_state),
                           ("preservation_exit_code", config.preservation_exit_code),
                           ("tsk_bin", config.tsk_bin)):
        value = producer.get(name)
        if not isinstance(value, str) or not os.path.isabs(value) or not gate.same_path(value, expected):
            raise RecoveryError("Inventory configuration path mismatch: " + name)
        gate.require_unaliased(Path(value))
    for name, expected in (("partition_offset_sectors", config.partition_offset),
                           ("sector_size", config.sector_size)):
        if type(producer.get(name)) is not int or producer[name] != expected:
            raise RecoveryError("Inventory geometry mismatch: " + name)
    if producer.get("catalog_bodyfile") is not True:
        raise RecoveryError("Inventory was not configured to produce a bodyfile catalog")
    if producer.get("script_sha256") != config.gate_sha256.lower():
        raise RecoveryError("Inventory producer does not match the approved gate-module hash")
    recorded_catalog = status.get("bodyfile_catalog")
    if not isinstance(recorded_catalog, dict):
        raise RecoveryError("Inventory has no completed bodyfile catalog record")
    path = recorded_catalog.get("path")
    if not isinstance(path, str) or not os.path.isabs(path) or not gate.same_path(path, config.catalog):
        raise RecoveryError("Inventory catalog path differs from selected catalog")
    gate.require_unaliased(Path(path))
    if (recorded_catalog.get("sha256") != catalog_record["sha256"] or
        type(recorded_catalog.get("bytes")) is not int or
        recorded_catalog["bytes"] != catalog_record["metadata"]["size"]):
        raise RecoveryError("Inventory catalog hash/byte count differs from selected catalog")
    return {"directory": str(inventory_dir), "manifest": manifest_record, "status": status_record,
            "producer_script_sha256": producer["script_sha256"], "catalog_record": recorded_catalog}


def ensure_capacity(config, count):
    free = shutil.disk_usage(config.output_dir.parent).free
    if free < count + config.reserve_bytes:
        raise RecoveryError("Output capacity reserve would be crossed")


def safe_output(root, relative, gate):
    if not isinstance(relative, str) or not re.fullmatch(r"[0-9]{12}_[0-9]{4}_[A-Za-z0-9_.-]{1,100}", relative):
        raise RecoveryError("Invalid recorded export path")
    path = root / relative
    if path.parent != root or path.is_symlink():
        raise RecoveryError("Export path escapes root or is a symbolic link")
    gate.require_unaliased(path)
    gate.safe_mutable_file(path)
    return path


def safe_basename(path):
    leaf = re.split(r"[/\\]", path)[-1]
    # Only the display label is shortened; exact original names stay in refs.
    leaf = re.sub(r" \(deleted(?:-realloc)?\)$", "", leaf)
    leaf = re.sub(r"[^A-Za-z0-9_.-]", "_", leaf).strip(" .") or "stream.bin"
    stem, suffix = os.path.splitext(leaf)
    return (stem[:75] or "stream") + suffix[:16]


def valid_row(row):
    if not isinstance(row, dict) or row.get("schema_version") != VERSION:
        return "invalid_schema"
    identifier = row.get("inode_attribute")
    if not isinstance(identifier, str) or not re.fullmatch(r"[0-9]{1,20}(?:-[0-9]{1,20}-[0-9]{1,20})?", identifier):
        return "invalid_attribute_identifier"
    if any(int(part) > 2 ** 64 - 1 for part in identifier.split("-")):
        return "invalid_attribute_identifier"
    path = row.get("full_path")
    if (not isinstance(path, str) or len(path) > 32768 or "\x00" in path or
        ".." in re.split(r"[/\\]", path)):
        return "invalid_original_path"
    if type(row.get("source_line")) is not int or row["source_line"] <= 0:
        return "invalid_source_line"
    if type(row.get("size")) is not int or not 0 <= row["size"] < 2 ** 63:
        return "invalid_size"
    if type(row.get("deleted")) is not bool or type(row.get("reallocated")) is not bool:
        return "invalid_allocation_flags"
    if not isinstance(row.get("mode"), str) or len(row["mode"]) > 64:
        return "invalid_mode"
    for name in ("atime_epoch", "mtime_epoch", "ctime_epoch", "crtime_epoch"):
        value = row.get(name)
        if type(value) not in (int, float) or not math.isfinite(value):
            return "invalid_timestamp"
    return None


def open_database(path, gate):
    class GuardedConnection(sqlite3.Connection):
        def execute(self, *args, **kwargs):
            if not self.in_transaction:
                guard_database(path, gate)
            return super().execute(*args, **kwargs)

        def executescript(self, *args, **kwargs):
            guard_database(path, gate)
            return super().executescript(*args, **kwargs)

        def commit(self):
            guard_database(path, gate)
            return super().commit()

    guard_database(path, gate)
    db = sqlite3.connect(path, factory=GuardedConnection)
    db.row_factory = sqlite3.Row
    db.executescript("""
        PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=FULL;
        PRAGMA temp_store=MEMORY;
        CREATE TABLE IF NOT EXISTS refs (
          catalog_line INTEGER PRIMARY KEY, stream_id INTEGER, raw_json TEXT NOT NULL, problem TEXT);
        CREATE TABLE IF NOT EXISTS streams (
          id INTEGER PRIMARY KEY, inode TEXT UNIQUE NOT NULL, expected_size INTEGER NOT NULL,
          deleted INTEGER NOT NULL, reallocated INTEGER NOT NULL, first_path TEXT NOT NULL,
          alias_count INTEGER NOT NULL, state TEXT NOT NULL, reason TEXT);
        CREATE TABLE IF NOT EXISTS exports (
          id INTEGER PRIMARY KEY, stream_id INTEGER NOT NULL, attempt INTEGER NOT NULL,
          relative_path TEXT UNIQUE NOT NULL, state TEXT NOT NULL, details TEXT NOT NULL);
    """)
    return db


class Recorder:
    def __init__(self, config, gate):
        self.config, self.gate = config, gate
        self.status = {"schema_version": VERSION, "phase": "starting", "started_utc": gate.utc_now(),
                       "recovered_all_selected": False, "limitations": LIMITATIONS}
        self.last = 0.0

    def update(self, force=False, **values):
        self.status.update(values)
        now = time.monotonic()
        if force or now - self.last >= self.config.progress_seconds:
            self.status["updated_utc"] = self.gate.utc_now()
            self.gate.safe_mutable_file(self.config.state_dir / "status.json")
            self.gate.atomic_json(self.config.state_dir / "status.json", self.status)
            self.last = now

    def event(self, name, **values):
        self.gate.safe_mutable_file(self.config.state_dir / "events.jsonl")
        with open(self.config.state_dir / "events.jsonl", "a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps({"utc": self.gate.utc_now(), "event": name, **values}) + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def import_catalog(config, gate, db, recorder):
    last = db.execute("SELECT COALESCE(MAX(catalog_line),0) FROM refs").fetchone()[0]
    with gate.protected_file(config.catalog) as catalog:
        line_number = 0
        while raw := catalog.readline(1024 * 1024 + 1):
            line_number += 1
            if len(raw) > 1024 * 1024:
                raise RecoveryError("Catalog row exceeds one MiB")
            if line_number <= last:
                continue
            try:
                row = json.loads(raw)
                problem = valid_row(row)
            except (ValueError, UnicodeDecodeError):
                row = {"unparsed_catalog_line_sha256": hashlib.sha256(raw).hexdigest()}
                problem = "invalid_json"
            stream_id = None
            if problem is None:
                found = db.execute("SELECT * FROM streams WHERE inode=?", (row["inode_attribute"],)).fetchone()
                if found is None:
                    parts = row["inode_attribute"].split("-")
                    state, reason = "pending", None
                    if len(parts) != 3:
                        if row["mode"].startswith(("d", "V")):
                            state, reason = "inventory_only", "Directory metadata without an explicit DATA attribute"
                        else:
                            state, reason = "unsupported", "NTFS stream lacks explicit attribute type and id"
                    elif int(parts[1]) != 128:
                        state, reason = "inventory_only", "NTFS attribute is not type-128 DATA"
                    elif row.get("deletion_corroborated") is not True:
                        state, reason = "ambiguous_allocation", "Catalog allocation flags are not corroborated"
                    corroborated = row.get("deletion_corroborated") is True
                    cursor = db.execute("INSERT INTO streams VALUES(NULL,?,?,?,?,?,?,?,?)",
                                        (row["inode_attribute"], row["size"], row["deleted"] and corroborated,
                                         row["reallocated"] and corroborated, row["full_path"], 1, state, reason))
                    stream_id = cursor.lastrowid
                else:
                    stream_id = found["id"]
                    conflict = found["expected_size"] != row["size"]
                    corroborated = row.get("deletion_corroborated") is True
                    state, reason = found["state"], found["reason"]
                    if state == "ambiguous_allocation" and corroborated:
                        state, reason = "pending", None
                    if conflict:
                        state, reason = "conflict", "Aliases disagree on expected stream size"
                    db.execute("UPDATE streams SET alias_count=alias_count+1, deleted=MAX(deleted,?), "
                               "reallocated=MAX(reallocated,?), state=?, reason=? WHERE id=?",
                               (row["deleted"] and corroborated, row["reallocated"] and corroborated,
                                state, reason, stream_id))
            db.execute("INSERT INTO refs VALUES(?,?,?,?)", (line_number, stream_id, json.dumps(row), problem))
            if line_number % 500 == 0:
                db.commit()
                recorder.update(phase="importing_catalog", catalog_rows=line_number)
    db.commit()
    if not config.all_files:
        db.execute("UPDATE streams SET state='not_selected',reason='Allocated alias set outside deleted mode' "
                   "WHERE state='pending' AND deleted=0")
    db.commit()
    return line_number


def known_output_bytes(config, gate, db):
    known = {row[0] for row in db.execute("SELECT relative_path FROM exports")}
    actual = {path.name for path in config.output_dir.iterdir()}
    if actual - known:
        raise RecoveryError("Output root contains files not owned by this recovery manifest")
    total = 0
    for name in actual:
        path = safe_output(config.output_dir, name, gate)
        if not path.is_file():
            raise RecoveryError("Recorded output is no longer a regular file")
        total += path.stat().st_size
    return total


def reconcile_interrupted(config, gate, db, recorder):
    for row in db.execute("SELECT * FROM exports WHERE state='running'").fetchall():
        details = json.loads(row["details"])
        path = safe_output(config.output_dir, row["relative_path"], gate)
        details.update(state="interrupted", error="Previous process ended before recording stream completion",
                       reconciliation_utc=gate.utc_now())
        if path.exists():
            details["output_record"] = file_record(gate, path)
            details["actual_size"] = details["output_record"]["metadata"]["size"]
        else:
            details.update(actual_size=0, missing_output=True)
        db.execute("UPDATE exports SET state='interrupted',details=? WHERE id=?",
                   (json.dumps(details), row["id"]))
        recorder.event("interrupted_export_retained", export_id=row["id"], **details)
    db.commit()


def icat_command(config, prefix, stream):
    common = ["-i", "raw", "-f", "ntfs", "-b", str(config.sector_size),
              "-o", str(config.partition_offset)]
    return [*prefix, *common, *(["-r"] if stream["deleted"] else []),
            str(config.image), stream["inode"]]


def copy_tool_output(config, command, path, expected, allowance, recorder):
    """Bound stdout, drain bounded stderr concurrently, and stop hung children."""
    process = None
    threads = []
    halt = threading.Event()
    chunks = queue.Queue(maxsize=2)
    stderr = bytearray()
    stderr_count = [0]
    reader_errors = []
    digest = hashlib.sha256()
    actual = seen = 0
    exit_code = None
    failure = None
    started = time.monotonic()

    def enqueue(value):
        while not halt.is_set():
            try:
                chunks.put(value, timeout=0.1)
                return
            except queue.Full:
                pass

    def read_stdout():
        try:
            while data := process.stdout.read(64 * 1024):
                enqueue(data)
                if halt.is_set():
                    break
        except OSError as error:
            reader_errors.append(str(error))
        finally:
            enqueue(None)

    def read_stderr():
        try:
            while data := process.stderr.read(64 * 1024):
                stderr_count[0] += len(data)
                stderr.extend(data[:max(0, 64 * 1024 - len(stderr))])
        except OSError as error:
            reader_errors.append(str(error))

    try:
        with open(path, "xb", buffering=0) as destination:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, shell=False, cwd=config.state_dir,
                                       creationflags=0x08000000 if os.name == "nt" else 0)
            threads = [threading.Thread(target=read_stdout, daemon=True),
                       threading.Thread(target=read_stderr, daemon=True)]
            for thread in threads:
                thread.start()
            while True:
                if time.monotonic() - started > config.stream_timeout:
                    raise RecoveryError("Stream extraction timed out")
                try:
                    data = chunks.get(timeout=0.25)
                except queue.Empty:
                    continue
                if data is None:
                    break
                seen += len(data)
                if actual + len(data) > expected:
                    raise RecoveryError("icat output exceeds catalog expected size; overflow was not written")
                if actual + len(data) > allowance:
                    raise RecoveryError("Output byte budget exhausted during stream")
                ensure_capacity(config, len(data))
                view = memoryview(data)
                while view:
                    count = destination.write(view)
                    if not count:
                        raise OSError("Destination write made no progress")
                    digest.update(view[:count])
                    actual += count
                    view = view[count:]
                recorder.update(current_stream_bytes=actual)
            process.wait(timeout=max(0.1, config.stream_timeout - (time.monotonic() - started)))
            exit_code = process.returncode
            if exit_code != 0:
                failure = "icat returned a nonzero exit status"
            elif actual != expected:
                failure = "icat output is shorter than catalog expected size"
            destination.flush()
            os.fsync(destination.fileno())
    except (OSError, RecoveryError, subprocess.TimeoutExpired) as error:
        failure = str(error)
    finally:
        halt.set()
        if process is not None:
            if process.poll() is None:
                process.kill()
            exit_code = process.wait(timeout=10)
            for thread in threads:
                thread.join(timeout=5)
            process.stdout.close()
            process.stderr.close()
    if reader_errors:
        failure = failure or "Pipe read error: " + "; ".join(reader_errors)
    return {"state": "complete" if failure is None else "partial" if actual else "failed",
            "actual_size": actual, "stdout_bytes_seen": seen, "stream_sha256": digest.hexdigest(),
            "exit_code": exit_code, "error": failure, "stderr": stderr.decode("utf-8", errors="replace"),
            "stderr_bytes": stderr_count[0], "stderr_truncated": stderr_count[0] > len(stderr)}


def export_one(config, gate, db, recorder, prefix, stream, used):
    prior = db.execute("SELECT * FROM exports WHERE stream_id=? ORDER BY attempt DESC LIMIT 1",
                       (stream["id"],)).fetchone()
    if prior and prior["state"] == "complete":
        details = json.loads(prior["details"])
        path = safe_output(config.output_dir, prior["relative_path"], gate)
        if path.exists() and file_record(gate, path) == details.get("output_record"):
            recorder.event("export_reused", stream_id=stream["id"], path=prior["relative_path"])
            return "complete", 0
        recorder.event("previous_export_changed", stream_id=stream["id"], path=prior["relative_path"])
    if stream["expected_size"] > config.max_output_bytes - used:
        return "deferred", 0
    try:
        ensure_capacity(config, stream["expected_size"])
    except RecoveryError:
        return "deferred", 0
    attempt = prior["attempt"] + 1 if prior else 1
    if attempt > 9999 or stream["id"] > 999999999999:
        raise RecoveryError("Export numbering limit exceeded")
    relative = f"{stream['id']:012d}_{attempt:04d}_{safe_basename(stream['first_path'])}"
    path = safe_output(config.output_dir, relative, gate)
    command = icat_command(config, prefix, stream)
    details = {"started_utc": gate.utc_now(), "command": command, "expected_size": stream["expected_size"],
               "original_path": stream["first_path"], "alias_count": stream["alias_count"],
               "inode_attribute": stream["inode"], "deleted": bool(stream["deleted"]),
               "reallocated": bool(stream["reallocated"]), "actual_size": 0, "exit_code": None}
    cursor = db.execute("INSERT INTO exports VALUES(NULL,?,?,?,?,?)",
                        (stream["id"], attempt, relative, "running", json.dumps(details)))
    export_id = cursor.lastrowid
    db.commit()
    recorder.update(force=True, phase="recovering", current_stream=stream["inode"],
                    current_output=relative, current_stream_bytes=0)
    recorder.event("export_started", stream_id=stream["id"], attempt=attempt, **details)
    try:
        details.update(copy_tool_output(config, command, path, stream["expected_size"],
                                        config.max_output_bytes - used, recorder))
    except BaseException as error:
        details.update(state="interrupted", error=type(error).__name__ + ": " + str(error))
        raise
    finally:
        if path.exists():
            output_record = file_record(gate, path)
            details["output_record"] = output_record
            details["actual_size"] = output_record["metadata"]["size"]
            if details.get("state") == "complete" and (
                details.get("stream_sha256") != output_record["sha256"] or
                details["actual_size"] != stream["expected_size"]):
                details.update(state="failed", error="Independent output hash/size verification failed")
        details["ended_utc"] = gate.utc_now()
        db.execute("UPDATE exports SET state=?,details=? WHERE id=?",
                   (details.get("state", "failed"), json.dumps(details), export_id))
        db.commit()
        recorder.event("export_finished", stream_id=stream["id"], attempt=attempt, **details)
    return details["state"], details["actual_size"]


def write_manifests(config, gate, db):
    guard_state(config, gate)
    for filename, query in (
        ("source-references.jsonl", "SELECT * FROM refs ORDER BY catalog_line"),
        ("recovery-manifest.jsonl", "SELECT * FROM streams ORDER BY id"),
        ("export-attempts.jsonl", "SELECT * FROM exports ORDER BY id"),
    ):
        target = config.state_dir / filename
        gate.safe_mutable_file(target)
        descriptor, temporary = tempfile.mkstemp(prefix=".recovery-manifest-", suffix=".tmp", dir=config.state_dir)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                for row in db.execute(query):
                    value = dict(row)
                    for field in ("raw_json", "details"):
                        if field in value:
                            value[field] = json.loads(value[field])
                    output.write(json.dumps(value) + "\n")
                output.flush()
                os.fsync(output.fileno())
            gate.safe_mutable_file(target)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def run(config):
    normalize(config)
    gate = load_gate(config)
    guard_paths(config, gate)
    if not config.resume or config.dry_run:
        return run_validated(config, gate)
    # Bind ownership before invalidating status; wrong pairs cannot touch another case.
    previous = gate.read_json(config.state_dir / "inputs.json")
    if previous.get("state_dir") != str(config.state_dir) or previous.get("output_dir") != str(config.output_dir):
        raise RecoveryError("Resume arguments do not identify this state/output pair")
    guard_state(config, gate)
    gate.safe_mutable_file(config.state_dir / "run.lock")
    with gate.protected_file(config.state_dir / "run.lock", writable=True):
        recorder = Recorder(config, gate)
        recorder.update(force=True, phase="validating_resume", recovered_all_selected=False)
        try:
            return run_validated(config, gate, recorder=recorder, already_locked=True)
        except BaseException as error:
            if recorder.status.get("phase") != "failed":
                recorder.update(force=True, phase="failed", recovered_all_selected=False,
                                error=type(error).__name__ + ": " + str(error))
                recorder.event("attempt_failed", error=type(error).__name__ + ": " + str(error))
            raise


def run_validated(config, gate, recorder=None, already_locked=False):
    preservation = gate.read_preservation_gate(config)
    if preservation is None:
        raise RecoveryError("Preservation exit marker is absent; no image read or export permitted")
    if config.partition_offset * config.sector_size >= preservation["size"]:
        raise RecoveryError("Filesystem offset is outside the verified image")
    with contextlib.ExitStack() as provenance_locks:
        for path in (config.catalog, config.catalog.parent / "manifest.json", config.catalog.parent / "status.json"):
            gate.require_unaliased(path)
            provenance_locks.enter_context(gate.protected_file(path))
        catalog_record = file_record(gate, config.catalog)
        inventory_binding = read_inventory_binding(config, gate, preservation, catalog_record)
        return run_bound(config, gate, preservation, catalog_record, inventory_binding,
                         recorder=recorder, already_locked=already_locked)


def run_bound(config, gate, preservation, catalog_record, inventory_binding, recorder=None, already_locked=False):
    prefix, tools, tool_version = tool_records(config, gate)
    inputs = {"schema_version": VERSION, "image_gate": preservation, "catalog": catalog_record,
              "inventory_binding": inventory_binding,
              "recovery_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "tool_prefix": prefix, "tools": tools, "tool_version": tool_version,
              "gate_sha256": config.gate_sha256.lower(),
              "partition_offset_sectors": config.partition_offset, "sector_size": config.sector_size,
              "filesystem": "ntfs", "mode": "all" if config.all_files else "deleted",
              "output_dir": str(config.output_dir), "state_dir": str(config.state_dir)}
    if config.dry_run:
        return {"phase": "dry_run", "writes_performed": False, "image_opened": False,
                "inputs": inputs, "max_output_bytes": config.max_output_bytes,
                "reserve_bytes": config.reserve_bytes}
    if config.resume:
        if not config.state_dir.is_dir() or not config.output_dir.is_dir():
            raise RecoveryError("Resume requires original output and state roots")
        if gate.read_json(config.state_dir / "inputs.json") != inputs:
            raise RecoveryError("Resume input/tool/catalog/mode identities differ")
        guard_state(config, gate)
    else:
        if os.path.lexists(config.state_dir) or os.path.lexists(config.output_dir):
            raise RecoveryError("Fresh recovery requires absent state and output roots")
        config.state_dir.mkdir()
        config.output_dir.mkdir()
        gate.safe_mutable_file(config.state_dir / "run.lock")
        with open(config.state_dir / "run.lock", "xb"):
            pass
        gate.safe_mutable_file(config.state_dir / "inputs.json")
        gate.atomic_json(config.state_dir / "inputs.json", inputs)
    recorder = recorder or Recorder(config, gate)
    lock = contextlib.nullcontext() if already_locked else gate.protected_file(config.state_dir / "run.lock", writable=True)
    with lock, contextlib.closing(
            open_database(config.state_dir / "recovery.sqlite3", gate)) as db:
        try:
            recorder.update(force=True, phase="validating", max_output_bytes=config.max_output_bytes,
                            reserve_bytes=config.reserve_bytes)
            recorder.event("attempt_started", resume=config.resume, pid=os.getpid(),
                           script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                           python=sys.version, max_output_bytes=config.max_output_bytes,
                           reserve_bytes=config.reserve_bytes, stream_timeout=config.stream_timeout)
            rows = import_catalog(config, gate, db, recorder)
            if file_record(gate, config.catalog) != catalog_record:
                raise RecoveryError("Catalog changed during import")
            used = known_output_bytes(config, gate, db)
            reconcile_interrupted(config, gate, db, recorder)
            if used > config.max_output_bytes:
                raise RecoveryError("Existing retained outputs already exceed configured budget")
            gate.require_unaliased(config.image)
            with gate.protected_file(config.image) as image:
                gate.check_image_handle(config, preservation, image)
                selected = db.execute("SELECT * FROM streams WHERE state IN "
                                      "('pending','complete','partial','failed','interrupted','deferred') ORDER BY id")
                for stream in selected:
                    gate.check_image_handle(config, preservation, image)
                    state, added = export_one(config, gate, db, recorder, prefix, stream, used)
                    used += added
                    gate.check_image_handle(config, preservation, image)
                    db.execute("UPDATE streams SET state=?,reason=? WHERE id=?",
                               (state, "Output byte budget or free-space reserve" if state == "deferred" else None,
                                stream["id"]))
                    db.commit()
                    recorder.update(output_bytes=used)
                    if state == "deferred":
                        break
                if gate.read_preservation_gate(config) != preservation:
                    raise RecoveryError("Preservation records changed during recovery")
                if read_inventory_binding(config, gate, preservation, catalog_record) != inventory_binding:
                    raise RecoveryError("Inventory provenance changed during recovery")
            for record in tools:
                if file_record(gate, Path(record["path"])) != record:
                    raise RecoveryError("Tool or dependency changed during recovery")
            counts = dict(db.execute("SELECT state,COUNT(*) FROM streams GROUP BY state"))
            invalid = db.execute("SELECT COUNT(*) FROM refs WHERE problem IS NOT NULL").fetchone()[0]
            deferred = counts.get("pending", 0) + counts.get("deferred", 0)
            failures = invalid + sum(counts.get(name, 0) for name in
                                     ("failed", "partial", "conflict", "unsupported", "interrupted", "ambiguous_allocation"))
            phase = "deferred" if deferred else "complete_with_errors" if failures else "complete"
            write_manifests(config, gate, db)
            recorder.update(force=True, phase=phase, counts=counts, invalid_catalog_rows=invalid,
                            catalog_rows=rows, output_bytes=used, recovered_all_selected=phase == "complete",
                            completed_utc=gate.utc_now())
            recorder.event("attempt_finished", phase=phase, counts=counts, output_bytes=used)
            return recorder.status
        except BaseException as error:
            db.commit()
            write_manifests(config, gate, db)
            recorder.update(force=True, phase="failed", recovered_all_selected=False,
                            error=type(error).__name__ + ": " + str(error))
            recorder.event("attempt_failed", error=type(error).__name__ + ": " + str(error))
            raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "preservation-state", "preservation-exit-code", "tsk-bin", "catalog",
                 "output-dir", "state-dir", "gate-module"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--gate-sha256", required=True)
    parser.add_argument("--partition-offset", type=int, required=True, help="Filesystem start in sectors")
    parser.add_argument("--sector-size", type=int, required=True)
    parser.add_argument("--max-output-gib", type=int, required=True, help="Cumulative retained export-byte cap")
    parser.add_argument("--reserve-gib", type=int, default=64)
    parser.add_argument("--all", dest="all_files", action="store_true", help="Include allocated DATA streams")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--stream-timeout", type=float, default=1800)
    args = vars(parser.parse_args(argv))
    args["max_output_bytes"] = args.pop("max_output_gib") * GIB
    args["reserve_bytes"] = args.pop("reserve_gib") * GIB
    return Config(**args)


def main(argv=None):
    try:
        result = run(parse_args(argv))
        display = dict(result)
        if display.get("phase") == "dry_run":
            inputs = display.pop("inputs")
            display.update(catalog_sha256=inputs["catalog"]["sha256"],
                           tool_version=inputs["tool_version"], tool_files=len(inputs["tools"]),
                           gate_sha256=inputs["gate_sha256"], mode=inputs["mode"])
        print(json.dumps(display, indent=2))
        return 0 if result["phase"] in ("complete", "dry_run") else 2
    except KeyboardInterrupt:
        print(json.dumps({"phase": "interrupted"}), file=sys.stderr)
        return 130
    except (OSError, ValueError, RecoveryError, RuntimeError, sqlite3.Error) as error:
        print(json.dumps({"phase": "failed", "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
