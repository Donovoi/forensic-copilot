#!/usr/bin/env python3
"""Collect bounded TSK metadata inventories from an explicitly verified raw copy.

Standard library only. Independent script review and synthetic validation are
required before evidence use. No mount, original-image read, export, or carving.
See docs/image-inventory.md for the preservation gate and coverage limitations.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

VERSION = 1
GIB = 1024 ** 3
LIMITATIONS = [
    "Metadata inventory only; no recovered content or completeness claim.",
    "fls recursion does not descend deleted directories; ils inventories do not recover their contents.",
    "UTC is output rendering for NTFS metadata, not a finding about the evidence system timezone.",
    "Filesystem timestamps do not establish human actions, deletion dates, ownership, or contact.",
    "Only the explicitly selected NTFS partition is inventoried; other partitions and disk gaps remain unexamined.",
    "Bodyfile rows include streams, metadata names, and aliases; summed sizes are not unique export bytes.",
]


class InventoryError(RuntimeError):
    pass


class BodyfileParseError(InventoryError):
    def __init__(self, errors):
        self.parse_error_count = errors["count"]
        self.error_examples = errors["examples"]
        super().__init__(f"Bodyfile has {self.parse_error_count} malformed rows; raw output retained")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def absolute(path):
    # Do not stat or resolve the image while a preservation copy may be partial.
    return Path(os.path.abspath(path))


def same_path(left, right):
    return os.path.normcase(str(absolute(left))) == os.path.normcase(str(absolute(right)))


def require_unaliased(path):
    if not same_path(path.resolve(), path):
        raise InventoryError("Symbolic-link/junction path aliases are not accepted")


def safe_mutable_file(path):
    if path.exists() or path.is_symlink():
        require_unaliased(path)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise InventoryError("Mutable state file must be a regular file with one link")


def metadata(info):
    return {"device": info.st_dev, "inode": info.st_ino,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns}


def digest_file(path):
    digest = hashlib.sha256()
    count = lines = 0
    last = b""
    with open(path, "rb") as stream:
        while data := stream.read(1024 * 1024):
            digest.update(data)
            count += len(data)
            lines += data.count(b"\n")
            last = data[-1:]
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": count,
            "lines": lines + int(bool(last) and last != b"\n")}


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".inventory-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    if path.is_symlink():
        raise InventoryError(f"State file is a symbolic link: {path.name}")
    with open(path, "rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise InventoryError("State JSON exceeds one MiB")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise InventoryError("State JSON must be an object")
    return result


@contextlib.contextmanager
def protected_file(path, writable=False):
    """Deny write/delete sharing on Windows; POSIX cooperative lock only."""
    if os.name != "nt":
        import fcntl
        with open(path, "r+b" if writable else "rb", buffering=0) as stream:
            fcntl.flock(stream, (fcntl.LOCK_EX if writable else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            yield stream
        return
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    handle = create(str(path), 0x80000000 | (0x40000000 if writable else 0),
                    1, None, 3, 0, None)  # FILE_SHARE_READ, OPEN_EXISTING
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_RDWR if writable else os.O_RDONLY))
    except BaseException:
        close(handle)
        raise
    try:
        stream = os.fdopen(fd, "r+b" if writable else "rb", buffering=0)
    except BaseException:
        os.close(fd)
        raise
    with stream:
        yield stream


@dataclass
class Config:
    image: Path
    preservation_state: Path
    preservation_exit_code: Path
    tsk_bin: Path
    output_dir: Path
    sector_size: int
    partition_offset: int
    wait: bool = False
    max_wait_hours: float = 24.0
    max_stage_hours: float = 24.0
    poll_seconds: float = 5.0
    reserve_bytes: int = 64 * GIB
    resume: bool = False
    catalog_bodyfile: bool = False


def validate_config(config):
    if config.sector_size not in (512, 1024, 2048, 4096) or config.partition_offset < 0:
        raise InventoryError("Explicit sector size must be 512/1024/2048/4096; offset must be nonnegative")
    for name in ("max_wait_hours", "max_stage_hours"):
        value = getattr(config, name)
        if not math.isfinite(value) or not 0 < value <= 168:
            raise InventoryError(f"{name} must be finite, positive, and at most 168")
    if not math.isfinite(config.poll_seconds) or not 0 < config.poll_seconds <= 60:
        raise InventoryError("Poll interval must be finite and in (0, 60]")
    if config.reserve_bytes < 0:
        raise InventoryError("Reserve must be nonnegative")
    for name in ("image", "preservation_state", "preservation_exit_code", "tsk_bin", "output_dir"):
        setattr(config, name, absolute(getattr(config, name)))
    for candidate in (config.image, config.preservation_state, config.preservation_exit_code, config.tsk_bin):
        if config.output_dir == candidate or config.output_dir in candidate.parents or candidate in config.output_dir.parents:
            raise InventoryError("Output directory may not overlap input, preservation state, or tools")
    if not config.output_dir.parent.is_dir():
        raise InventoryError("Output parent must already exist")
    if config.output_dir.is_symlink() or config.preservation_state.is_symlink():
        raise InventoryError("Output/state directories may not be symbolic links")
    if re.search(r"\.\d+$", config.image.name):
        raise InventoryError("Numbered-segment image names are refused to prevent implicit sibling reads")
    for path in (config.output_dir, config.preservation_state, config.preservation_exit_code,
                 config.tsk_bin, config.image.parent):
        require_unaliased(path)


def read_preservation_gate(config):
    """Never stat/open image or original. None means copy has not finished yet."""
    exit_path = config.preservation_exit_code
    if not exit_path.exists():
        return None
    if exit_path.is_symlink() or exit_path.stat().st_size > 64:
        raise InventoryError("Invalid preservation exit marker")
    exit_text = exit_path.read_text(encoding="utf-8-sig").strip()
    if exit_text != "0":
        raise InventoryError("Preservation exited unsuccessfully or has an invalid exit marker")
    manifest = read_json(config.preservation_state / "manifest.json")
    status = read_json(config.preservation_state / "status.json")
    if status.get("phase") != "complete" or status.get("verified") is not True:
        raise InventoryError("Exit marker is not backed by complete, verified preservation status")
    if manifest.get("schema_version") != 1 or status.get("schema_version") != 1:
        raise InventoryError("Unsupported preservation schema")
    for document in (manifest, status):
        if not same_path(document.get("destination", ""), config.image):
            raise InventoryError("Preservation destination differs from explicit image")
        # Frozen preservation v1 did not include state_dir in manifest.json.
        # Its status must still bind the explicitly selected canonical directory.
        if document is manifest and "state_dir" not in document:
            continue
        if not same_path(document.get("state_dir", ""), config.preservation_state):
            raise InventoryError("Preservation state identity differs from explicit state directory")
    if not isinstance(manifest.get("source"), str) or same_path(manifest["source"], config.image):
        raise InventoryError("Manifest source must identify a distinct original")
    source = manifest.get("source_metadata", {})
    expected = source.get("size")
    if type(expected) is not int or expected <= 0:
        raise InventoryError("Manifest has no positive expected image size")
    if any(type(source.get(key)) is not int for key in ("device", "inode", "mtime_ns")):
        raise InventoryError("Manifest has incomplete original identity")
    for key in ("source_size", "copied_bytes", "checkpoint_bytes", "destination_verified_bytes"):
        if type(status.get(key)) is not int or status[key] != expected:
            raise InventoryError(f"Preservation byte count mismatch: {key}")
    source_hash = status.get("source_stream_sha256", "")
    if not isinstance(source_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", source_hash):
        raise InventoryError("Invalid source SHA256")
    if source_hash != status.get("destination_sha256"):
        raise InventoryError("Source/destination SHA256 mismatch")
    identity = manifest.get("destination_identity", {})
    if any(type(identity.get(key)) is not int for key in ("device", "inode")):
        raise InventoryError("Manifest has incomplete destination identity")
    if all(identity[key] == source[key] for key in ("device", "inode")):
        raise InventoryError("Original and destination file identity must differ")
    try:
        completed = datetime.fromisoformat(status["completed_utc"].replace("Z", "+00:00"))
        if completed.utcoffset() is None or completed.utcoffset().total_seconds() != 0:
            raise ValueError("not UTC")
    except (KeyError, TypeError, ValueError) as error:
        raise InventoryError("Missing/invalid UTC completion marker") from error
    if completed > datetime.now(timezone.utc):
        raise InventoryError("Preservation completion is in the future")
    final_metadata = manifest.get("final_destination_metadata")
    if final_metadata is not None:
        if (final_metadata != status.get("destination_metadata") or
            manifest.get("last_verified_sha256") != source_hash or
            manifest.get("last_verified_utc") != status["completed_utc"]):
            raise InventoryError("Final preservation metadata/hash/UTC markers disagree")
        if (not isinstance(final_metadata, dict) or final_metadata.get("size") != expected or
            any(final_metadata.get(key) != identity[key] for key in ("device", "inode"))):
            raise InventoryError("Final destination metadata conflicts with manifest identity/size")
    return {"image": str(config.image), "size": expected, "sha256": source_hash,
            "destination_identity": identity, "final_destination_metadata": final_metadata,
            "completed_utc": status["completed_utc"],
            "completion_ns": int(completed.timestamp() * 1000000000),
            "preservation_manifest": digest_file(config.preservation_state / "manifest.json"),
            "preservation_status": digest_file(config.preservation_state / "status.json"),
            "preservation_exit_marker": digest_file(exit_path),
            "metadata_gate": "exact_final_metadata" if final_metadata is not None else "legacy_v1_completion_time_bound",
            "legacy_manifest_state_binding": "state_dir" not in manifest,
            "limitation": None if final_metadata is not None else
                "Legacy preservation lacks final destination mtime; identity/size and mtime <= completion are checked. No new full image hash is performed."}


def check_image_handle(config, gate, stream):
    info = os.fstat(stream.fileno())
    actual = metadata(info)
    if not stat.S_ISREG(info.st_mode) or actual["size"] != gate["size"]:
        raise InventoryError("Opened image is not a regular file of verified size")
    if any(actual[key] != gate["destination_identity"][key] for key in ("device", "inode")):
        raise InventoryError("Opened image identity differs from verified destination")
    if gate["final_destination_metadata"] is not None:
        if actual != gate["final_destination_metadata"]:
            raise InventoryError("Opened image differs from final verified metadata")
    elif actual["mtime_ns"] > gate["completion_ns"]:
        raise InventoryError("Image mtime is newer than legacy verification completion")
    if metadata(config.image.stat()) != actual:
        raise InventoryError("Image path no longer identifies protected handle")
    return actual


@contextlib.contextmanager
def held_verified_image(config):
    """Reusable gate for reviewed downstream tools; yields gate under image lock.

    Caller passes absolute image/preservation_state/preservation_exit_code Paths.
    This helper never waits; downstream callers choose their own bounded waiting.
    The caller must pin/record this module's SHA256 and inspect gate limitations.
    """
    gate = read_preservation_gate(config)
    if gate is None:
        raise InventoryError("Preservation is incomplete; image has not been touched")
    if config.image.is_symlink():
        raise InventoryError("Image may not be a symbolic link")
    with protected_file(config.image) as stream:
        check_image_handle(config, gate, stream)
        yield gate
        check_image_handle(config, gate, stream)
        if read_preservation_gate(config) != gate:
            raise InventoryError("Preservation gate changed during protected use")


def stage_commands(config, tools):
    image = str(config.image)
    common = ["-i", "raw", "-b", str(config.sector_size), "-o", str(config.partition_offset)]
    ntfs = [*common, "-f", "ntfs"]
    return [
        ("mmls", [tools["mmls"], "-i", "raw", "-b", str(config.sector_size), image]),
        ("fsstat", [tools["fsstat"], *ntfs, image]),
        ("fls_root", [tools["fls"], *ntfs, "-p", "-l", "-z", "UTC", image]),
        ("fls_recursive", [tools["fls"], *ntfs, "-r", "-p", "-l", "-z", "UTC", image]),
        ("fls_bodyfile", [tools["fls"], *ntfs, "-r", "-m", "/", "-z", "UTC", image]),
        ("ils_all", [tools["ils"], *ntfs, "-e", image]),
        ("ils_orphan", [tools["ils"], *ntfs, "-p", image]),
    ]


class Recorder:
    def __init__(self, config):
        self.root = config.output_dir
        self.path = self.root / "status.json"
        self.status = {"schema_version": VERSION, "phase": "starting", "started_utc": utc_now(),
                       "stages": {}, "limitations": LIMITATIONS}

    def update(self, **values):
        self.status.update(values, updated_utc=utc_now())
        atomic_json(self.path, self.status)

    def event(self, name, **details):
        safe_mutable_file(self.root / "events.jsonl")
        with open(self.root / "events.jsonl", "a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps({"utc": utc_now(), "event": name, **details}) + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def run_stage(config, recorder, name, command, tool_record):
    previous = recorder.status["stages"].get(name, {})
    if previous.get("state") == "complete":
        if previous.get("command") != command or previous.get("tool_sha256") != tool_record["sha256"]:
            raise InventoryError("Completed stage command/tool differs from current run")
        for key in ("stdout", "stderr"):
            expected = config.output_dir / name / f"{int(previous['attempt']):03d}.{key}.bin"
            if not same_path(previous[key]["path"], expected):
                raise InventoryError("Recorded output is outside expected stage attempt path")
            require_unaliased(expected)
            if digest_file(Path(previous[key]["path"])) != previous[key]:
                raise InventoryError("Completed stage output changed; refusing reuse")
        recorder.event("stage_reused", stage=name)
        return Path(previous["stdout"]["path"])
    stage_root = config.output_dir / name
    stage_root.mkdir(exist_ok=True)
    require_unaliased(stage_root)
    attempt = int(previous.get("attempt", 0)) + 1
    output = stage_root / f"{attempt:03d}.stdout.bin"
    error_path = stage_root / f"{attempt:03d}.stderr.bin"
    stage = {"state": "running", "attempt": attempt, "command": command,
             "tool_sha256": tool_record["sha256"], "tool_version": tool_record.get("version"),
             "started_utc": utc_now(), "exit_code": None, "validation": "pending"}
    recorder.status["stages"][name] = stage
    recorder.update(phase="running", current_stage=name)
    recorder.event("stage_started", stage=name, **stage)
    started = time.monotonic()
    process = None
    failure = None
    try:
        with open(output, "xb", buffering=0) as stdout, open(error_path, "xb", buffering=0) as stderr:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout,
                                       stderr=stderr, shell=False,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            stage["pid"] = process.pid
            while process.poll() is None:
                free = shutil.disk_usage(config.output_dir).free
                stage.update(elapsed_seconds=round(time.monotonic()-started, 3), free_bytes=free,
                             stdout_bytes=output.stat().st_size, stderr_bytes=error_path.stat().st_size)
                recorder.update()
                if free < config.reserve_bytes:
                    raise InventoryError("Output reserve reached; stage incomplete and resumable")
                if time.monotonic() - started >= config.max_stage_hours * 3600:
                    raise InventoryError("Stage time limit reached; stage incomplete and resumable")
                time.sleep(config.poll_seconds)
            stage["exit_code"] = process.returncode
            if process.returncode != 0:
                raise InventoryError(f"Stage {name} exited {process.returncode}; inspect controlled stderr")
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
        stage["validation"] = validate_output(name, output)
        stage["state"] = "complete"
    except BaseException as error:
        failure = error
        if process is not None:
            stop_process(process)
            stage["exit_code"] = process.returncode
        stage.update(state="failed", error_type=type(error).__name__, error=str(error))
        if isinstance(error, BodyfileParseError):
            stage["validation"] = {"parse_errors": error.parse_error_count,
                                   "error_examples": error.error_examples}
    finally:
        stage.update(completed_utc=utc_now(), elapsed_seconds=round(time.monotonic()-started, 3))
        if output.is_file():
            stage["stdout"] = digest_file(output)
        if error_path.is_file():
            stage["stderr"] = digest_file(error_path)
        recorder.update()
        recorder.event("stage_finished", stage=name, **stage)
    if failure is not None:
        raise failure
    return output


def bodyfile_rows(path, errors=None):
    with open(path, "rb") as stream:
        for number, raw in enumerate(stream, 1):
            raw = raw.rstrip(b"\r\n")
            if not raw:
                continue
            try:
                hash_value, remainder = raw.split(b"|", 1)
                fields = remainder.rsplit(b"|", 9)
                if len(fields) != 10:
                    raise ValueError("wrong field count")
                name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime = fields
                if not re.fullmatch(rb"\d+(?:-\d+-\d+)?", inode):
                    raise ValueError("invalid inode/stream")
                parsed_size = int(size)
                if parsed_size < 0:
                    raise ValueError("negative size")
                deleted = name.endswith((b" (deleted)", b" (deleted-realloc)"))
                values = {"schema_version": 1, "source_line": number,
                          "full_path": name.decode("utf-8", errors="surrogateescape"),
                          "inode_attribute": inode.decode("ascii"), "mode": mode.decode("ascii"),
                          "uid": int(uid), "gid": int(gid), "size": parsed_size,
                          "atime_epoch": int(atime), "mtime_epoch": int(mtime),
                          "ctime_epoch": int(ctime), "crtime_epoch": int(crtime),
                          "raw_line_sha256": hashlib.sha256(raw).hexdigest(),
                          "deleted": deleted, "reallocated": name.endswith(b" (deleted-realloc)"),
                          "deleted_suffix_candidate": deleted,
                          "deletion_basis": "TSK bodyfile name suffix; possible literal-name ambiguity"}
                if not mode or not hash_value:
                    raise ValueError("empty mode/hash field")
                yield values
            except (ValueError, UnicodeError) as error:
                if errors is None:
                    raise InventoryError(f"Malformed bodyfile line {number}: {error}") from error
                errors["count"] += 1
                if len(errors["examples"]) < 20:
                    errors["examples"].append({"source_line": number, "error": str(error)})


def validate_output(name, path):
    with open(path, "rb") as stream:
        prefix = stream.read(128 * 1024)
    if name == "mmls" and (b"Slot" not in prefix or b"Start" not in prefix):
        raise InventoryError("mmls output lacks recognizable partition table headings")
    if name == "fsstat" and not re.search(rb"File System Type:\s+NTFS", prefix, re.I):
        raise InventoryError("fsstat did not establish an NTFS filesystem")
    if name.startswith("ils_") and (b"st_ino|st_alloc|" not in prefix):
        raise InventoryError("ils output lacks expected inode/allocation header")
    if name.startswith("version_") and (not prefix.strip() or b"Sleuth Kit" not in prefix):
        raise InventoryError("Tool version output is empty or unrecognized")
    if name == "fls_bodyfile":
        errors = {"count": 0, "examples": []}
        count = sum(1 for _ in bodyfile_rows(path, errors))
        if errors["count"]:
            raise BodyfileParseError(errors)
        return {"method": "all bodyfile rows structurally parsed", "rows": count, "parse_errors": 0,
                "content_authenticity_validated": False}
    return {"method": "required headings checked" if name in ("mmls", "fsstat") or name.startswith("ils_")
            else "raw fls output retained; not interpreted", "empty": path.stat().st_size == 0,
            "content_authenticity_validated": False}


def configuration_identity(config):
    return {key: str(getattr(config, key)) for key in
            ("image", "preservation_state", "preservation_exit_code", "tsk_bin", "output_dir")} | {
        "sector_size": config.sector_size, "partition_offset_sectors": config.partition_offset,
        "catalog_bodyfile": config.catalog_bodyfile,
        "script_sha256": digest_file(Path(__file__))["sha256"], "schema_version": VERSION}


@contextlib.contextmanager
def long_fls_flags(path, scratch_dir, reserve_bytes=0):
    """Corroborate directory-entry flags by exact rendered name and full stream ID.

    A bounded-cache SQLite index retains conflicting flags as distinct records.
    $FILE_NAME bodyfile-only metadata rows may have no exact stream match.
    """
    fd, temporary = tempfile.mkstemp(prefix=".fls-flags-", suffix=".sqlite", dir=scratch_dir)
    os.close(fd)
    connection = sqlite3.connect(temporary)
    try:
        connection.execute("PRAGMA cache_size=-16384")
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("CREATE TABLE flags(inode TEXT, name BLOB, deleted INTEGER, reallocated INTEGER, PRIMARY KEY(inode,name,deleted,reallocated)) WITHOUT ROWID")
        pattern = re.compile(rb"^[^ ]{3} (?P<deleted>\* )?(?P<inode>\d+(?:-\d+-\d+)?)(?P<reallocated>\(realloc\))?:\t(?P<name>[^\t]*)\t")
        with open(path, "rb") as stream:
            for number, raw in enumerate(stream, 1):
                match = pattern.match(raw)
                if match:
                    connection.execute("INSERT OR IGNORE INTO flags VALUES(?,?,?,?)",
                                       (match["inode"].decode("ascii"), b"/" + match["name"],
                                        bool(match["deleted"]), bool(match["reallocated"])))
                if number % 10000 == 0:
                    connection.commit()
                    if shutil.disk_usage(scratch_dir).free < reserve_bytes:
                        raise InventoryError("Output reserve reached while indexing directory-entry flags")
        connection.commit()
        yield connection
    finally:
        connection.close()
        Path(temporary).unlink()


def corroborate_name_flags(row, flags):
    raw_name = row["full_path"]
    candidates = [(raw_name, False, False)]
    for suffix, deleted, reallocated in ((" (deleted)", True, False), (" (deleted-realloc)", True, True)):
        if raw_name.endswith(suffix):
            candidates.append((raw_name[:-len(suffix)], deleted, reallocated))
    matches = set()
    conflicting = False
    for candidate, deleted, reallocated in candidates:
        found = set(flags.execute("SELECT deleted,reallocated FROM flags WHERE inode=? AND name=?",
                                 (row["inode_attribute"], candidate.encode("utf-8", errors="surrogateescape"))))
        if len(found) > 1:
            conflicting = True
        if (deleted, reallocated) in found:
            matches.add((deleted, reallocated))
    if len(matches) == 1 and not conflicting:
        row["deleted"], row["reallocated"] = matches.pop()
        row["deletion_basis"] = "Corroborated exact name/full stream ID against long fls directory-entry flags"
        row["deletion_corroborated"] = True
    else:
        row["deletion_corroborated"] = False
    return row


def inventory(config):
    validate_config(config)
    identity = configuration_identity(config)
    manifest_path = config.output_dir / "manifest.json"
    if config.resume:
        manifest = read_json(manifest_path)
        if manifest.get("configuration") != identity:
            raise InventoryError("Resume does not identify this runner/configuration/output directory")
        if (config.output_dir / "run.lock").is_symlink():
            raise InventoryError("Output lock may not be a symbolic link")
        for name in ("manifest.json", "status.json", "events.jsonl", "run.lock", "bodyfile-catalog.jsonl", "bodyfile-statistics.json"):
            safe_mutable_file(config.output_dir / name)
    else:
        config.output_dir.mkdir(exist_ok=False)
        (config.output_dir / "run.lock").touch(exist_ok=False)
        manifest = {"configuration": identity, "created_utc": utc_now(), "python": sys.version,
                    "limitations": LIMITATIONS}
        atomic_json(manifest_path, manifest)
    with protected_file(config.output_dir / "run.lock", writable=True):
        recorder = Recorder(config)
        if config.resume:
            recorder.status = read_json(recorder.path)
        try:
            recorder.update(phase="waiting_for_preservation", current_stage=None)
            recorder.event("attempt_started", pid=os.getpid(), resume=config.resume,
                           reserve_bytes=config.reserve_bytes, max_stage_hours=config.max_stage_hours,
                           max_wait_hours=config.max_wait_hours)
            started = time.monotonic()
            while (gate := read_preservation_gate(config)) is None:
                if not config.wait:
                    raise InventoryError("Preservation exit marker is absent; image has not been touched")
                if time.monotonic() - started >= config.max_wait_hours * 3600:
                    raise InventoryError("Preservation wait expired; image has not been touched")
                recorder.update(wait_elapsed_seconds=round(time.monotonic()-started, 3))
                time.sleep(config.poll_seconds)
            if manifest.get("image_identity") not in (None, gate):
                raise InventoryError("Verified preservation identity changed since prior inventory attempt")
            if config.partition_offset * config.sector_size >= gate["size"]:
                raise InventoryError("Partition offset is outside verified image")
            if config.image.is_symlink():
                raise InventoryError("Image may not be a symbolic link")
            with protected_file(config.image) as image_handle:
                actual = check_image_handle(config, gate, image_handle)
                manifest.update(image_identity=gate, opened_image_metadata=actual,
                                protection="Windows deny-write/delete sharing" if os.name == "nt" else
                                "POSIX advisory lock only; external write protection required")
                atomic_json(manifest_path, manifest)
                recorder.update(image_identity=gate, protection=manifest["protection"])
                tools = {}
                tool_records = {}
                for name in ("mmls", "fsstat", "fls", "ils"):
                    executable = config.tsk_bin / (name + (".exe" if os.name == "nt" else ""))
                    if not executable.is_file() or executable.is_symlink():
                        raise InventoryError(f"Required TSK executable missing or linked: {name}")
                    tools[name] = str(executable)
                    record = digest_file(executable)
                    version_output = run_stage(config, recorder, "version_"+name, [str(executable), "-V"], record)
                    record["version"] = version_output.read_bytes()[:16384].decode("utf-8", errors="replace").strip()
                    tool_records[name] = record
                manifest["tools"] = tool_records
                atomic_json(manifest_path, manifest)
                for name, command in stage_commands(config, tools):
                    if shutil.disk_usage(config.output_dir).free < config.reserve_bytes:
                        raise InventoryError("Insufficient output reserve before stage")
                    check_image_handle(config, gate, image_handle)
                    tool_name = Path(command[0]).stem
                    if digest_file(Path(command[0]))["sha256"] != tool_records[tool_name]["sha256"]:
                        raise InventoryError("TSK executable changed after version capture")
                    run_stage(config, recorder, name, command, tool_records[tool_name])
                    check_image_handle(config, gate, image_handle)
                body_path = Path(recorder.status["stages"]["fls_bodyfile"]["stdout"]["path"])
                stats = {"rows": 0, "summed_row_sizes": 0, "tsk_deleted_name_suffix_rows": 0,
                         "deletion_corroborated_rows": 0, "parse_errors": 0,
                         "limitation": LIMITATIONS[-1]}
                flags_path = Path(recorder.status["stages"]["fls_recursive"]["stdout"]["path"])
                catalog_path = config.output_dir / "bodyfile-catalog.jsonl"
                # Rewrite only our own derived catalog on an explicitly bound resume.
                if catalog_path.is_symlink():
                    raise InventoryError("Catalog may not be a symbolic link")
                safe_mutable_file(catalog_path)
                with long_fls_flags(flags_path, config.output_dir, config.reserve_bytes) as flags, \
                     (open(catalog_path, "w", encoding="utf-8", newline="\n")
                      if config.catalog_bodyfile else contextlib.nullcontext()) as catalog:
                    for row in bodyfile_rows(body_path):
                        corroborate_name_flags(row, flags)
                        stats["rows"] += 1
                        stats["summed_row_sizes"] += row["size"]
                        stats["tsk_deleted_name_suffix_rows"] += int(row["deleted_suffix_candidate"])
                        stats["deletion_corroborated_rows"] += int(row["deletion_corroborated"])
                        if catalog is not None:
                            catalog.write(json.dumps(row, ensure_ascii=True) + "\n")
                        if stats["rows"] % 10000 == 0:
                            if shutil.disk_usage(config.output_dir).free < config.reserve_bytes:
                                raise InventoryError("Output reserve reached while cataloging")
                            recorder.update(current_stage="bodyfile_statistics", catalog_rows=stats["rows"])
                atomic_json(config.output_dir / "bodyfile-statistics.json", stats)
                recorder.status["bodyfile_statistics"] = digest_file(config.output_dir / "bodyfile-statistics.json")
                if config.catalog_bodyfile:
                    recorder.status["bodyfile_catalog"] = digest_file(catalog_path)
                check_image_handle(config, gate, image_handle)
                # Re-check preservation documents without opening or statting original.
                if read_preservation_gate(config) != gate:
                    raise InventoryError("Preservation gate changed during collection")
            recorder.update(phase="complete", current_stage=None, completed_utc=utc_now())
            recorder.event("inventory_complete")
            return recorder.status
        except BaseException as error:
            recorder.update(phase="failed", error_type=type(error).__name__, error=str(error))
            recorder.event("inventory_failed", error_type=type(error).__name__, error=str(error))
            raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "preservation-state", "preservation-exit-code", "tsk-bin", "output-dir"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--sector-size", type=int, required=True)
    parser.add_argument("--partition-offset", type=int, required=True, help="Filesystem start in explicit device sectors")
    parser.add_argument("--wait", action="store_true", help="Wait finitely for preservation success without touching partial image")
    parser.add_argument("--max-wait-hours", type=float, default=24)
    parser.add_argument("--max-stage-hours", type=float, default=24)
    parser.add_argument("--poll-seconds", type=float, default=5)
    parser.add_argument("--reserve-gib", type=int, default=64)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--catalog-bodyfile", action="store_true")
    args = vars(parser.parse_args(argv))
    args["reserve_bytes"] = args.pop("reserve_gib") * GIB
    return Config(**args)


def main(argv=None):
    try:
        result = inventory(parse_args(argv))
        print(json.dumps({"phase": result["phase"], "completed_utc": result["completed_utc"]}))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"phase": "interrupted"}), file=sys.stderr)
        return 130
    except (OSError, ValueError, InventoryError) as error:
        print(json.dumps({"phase": "failed", "error_type": type(error).__name__, "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
