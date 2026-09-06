#!/usr/bin/env python3
"""Preserve a regular image file with a stream hash and full destination verification.

Authored 2026-09-06. Python 3.10+, standard library only; Windows and POSIX.
Reads only the explicit source; creates a destination and controlled state directory.
This is a logical byte-for-byte FILE copy, not disk acquisition or a recovery parser.
It never sets source attributes/timestamps; the OS may update access metadata on read.
Reviewer approval is required before use against evidence. See docs/image-preservation.md.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone


VERSION = 1
GIB = 1024 ** 3


class PreservationError(RuntimeError):
    """A failed safety or integrity check; incomplete output must not be trusted."""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def identity(info):
    return {"device": info.st_dev, "inode": info.st_ino}


def source_metadata(info):
    return {**identity(info), "size": info.st_size, "mtime_ns": info.st_mtime_ns}


def assert_regular(info, label):
    if not stat.S_ISREG(info.st_mode):
        raise PreservationError(f"{label} must be a regular file")


def open_file(path, mode):
    """Windows denies other writers and deletion for this handle's lifetime.

    Existing Windows writers also prevent this open (bidirectional share checks).
    The destination stays locked through its full re-read verification.
    POSIX locks here protect cooperative script instances only.
    """
    if os.name != "nt":
        stream = open(path, mode, buffering=0)
        try:
            import fcntl
            fcntl.flock(stream, (fcntl.LOCK_SH if mode == "rb" else fcntl.LOCK_EX)
                        | fcntl.LOCK_NB)
        except BaseException:
            stream.close()
            raise
        return stream
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
    access = 0x80000000  # GENERIC_READ
    if mode != "rb":
        access |= 0x40000000  # GENERIC_WRITE
    handle = create(str(path), access, 1, None, 1 if mode == "x+b" else 3,
                    0x08000000, None)  # FILE_SHARE_READ; SEQUENTIAL_SCAN
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_BINARY |
                                  (os.O_RDONLY if mode == "rb" else os.O_RDWR))
    except BaseException:
        close(handle)
        raise
    try:
        return os.fdopen(fd, "rb" if mode == "rb" else "r+b", buffering=0)
    except BaseException:
        os.close(fd)
        raise


@contextlib.contextmanager
def state_lock(path):
    # On Windows the normal file-sharing checks prevent another writable open;
    # no stale PID deletion or user-controlled lock-file removal is needed.
    if not path.exists():
        try:
            with open_file(path, "x+b"):
                pass
        except FileExistsError:
            pass
    with open_file(path, "r+b") as stream:
        yield stream


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".status-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_all(stream, data):
    view = memoryview(data)
    while view:
        count = stream.write(view)
        if not count:
            raise OSError("Destination write made no progress")
        view = view[count:]


def ensure_capacity(parent, remaining, reserve):
    free = shutil.disk_usage(parent).free
    required = remaining + reserve
    if free < required:
        raise PreservationError(f"Insufficient free bytes: {free}; required {required} "
                                f"including reserve {reserve}")
    return free


@dataclass
class Config:
    source: Path
    destination: Path
    state_dir: Path
    resume: bool = False
    dry_run: bool = False
    chunk_bytes: int = 16 * 1024 * 1024
    reserve_bytes: int = 64 * GIB
    progress_seconds: float = 5.0


def preflight(config):
    if config.chunk_bytes <= 0 or config.reserve_bytes < 0 or config.progress_seconds <= 0:
        raise PreservationError("Chunk/progress must be positive; reserve must be nonnegative")
    if config.destination.is_symlink() or config.state_dir.is_symlink():
        raise PreservationError("Destination and state directory may not be symbolic links")
    source = config.source.resolve(strict=True)
    destination = config.destination.resolve()
    state_dir = config.state_dir.resolve()
    if source == destination or source == state_dir or destination == state_dir:
        raise PreservationError("Source, destination, and state directory must differ")
    if not destination.parent.is_dir() or not state_dir.parent.is_dir():
        raise PreservationError("Destination/state parent directories must already exist")
    source_info = source.stat()
    assert_regular(source_info, "Source")
    remaining = source_info.st_size
    if config.resume:
        if not destination.is_file() or not state_dir.is_dir():
            raise PreservationError("Resume requires the existing destination and state directory")
        if os.path.samefile(source, destination):
            raise PreservationError("Source and destination are the same file")
        if not (state_dir / "manifest.json").is_file():
            raise PreservationError("Resume requires the original manifest.json")
        remaining -= destination.stat().st_size
        if remaining < 0:
            raise PreservationError("Destination is longer than source")
    elif os.path.lexists(destination) or os.path.lexists(state_dir):
        raise PreservationError("Fresh copy requires absent destination and state directory; "
                                "use --resume only for this script's existing copy")
    free = ensure_capacity(destination.parent, remaining, config.reserve_bytes)
    return source, destination, state_dir, free


class Recorder:
    def __init__(self, state_dir, manifest, config):
        self.path = state_dir / "status.json"
        self.events = state_dir / "events.jsonl"
        self.started = time.monotonic()
        self.last_update = 0.0
        self.interval = config.progress_seconds
        self.status = {
            "schema_version": VERSION, "phase": "starting", "verified": False,
            "attempt_started_utc": utc_now(), "source_size": manifest["source_metadata"]["size"],
            "destination": manifest["destination"], "state_dir": str(state_dir),
            "copied_bytes": 0, "checkpoint_bytes": 0, "prefix_verified_bytes": 0,
            "destination_verified_bytes": 0, "source_stream_sha256": None,
            "destination_sha256": None,
        }

    def event(self, name, **details):
        with open(self.events, "a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps({"utc": utc_now(), "event": name, **details}) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def update(self, force=False, **values):
        self.status.update(values)
        now = time.monotonic()
        if force or now - self.last_update >= self.interval:
            self.status.update(updated_utc=utc_now(), elapsed_seconds=round(now-self.started, 3))
            atomic_json(self.path, self.status)
            self.last_update = now


def verify_prefix(source, destination, length, digest, config, recorder):
    offset = 0
    while offset < length:
        count = min(config.chunk_bytes, length - offset)
        data = source.read(count)
        previous = destination.read(count)
        if len(data) != count or data != previous:
            raise PreservationError(f"Existing destination prefix mismatch in block at {offset}")
        digest.update(data)
        offset += count
        recorder.update(prefix_verified_bytes=offset)
    return offset


def verify_destination(destination, length, config, recorder):
    # Full second pass, with an independent hash object after flushing the copy.
    # Same protected file handle avoids a close/reopen path replacement race.
    destination.seek(0)
    digest = hashlib.sha256()
    offset = 0
    while offset < length:
        data = destination.read(min(config.chunk_bytes, length - offset))
        if not data:
            raise PreservationError("Unexpected end of destination during verification")
        digest.update(data)
        offset += len(data)
        recorder.update(destination_verified_bytes=offset)
    if destination.read(1):
        raise PreservationError("Destination has extra bytes")
    return digest.hexdigest()


def trusted_resume_manifest(config):
    """Bind selected state to its recorded destination before any state writes.

    A wrong source argument can invalidate this copy's attempted verification;
    a different destination/state pair must never modify an unrelated case.
    Use the recorded absolute destination path for this ownership check, even
    if that path has since become a symlink (preflight will reject it safely).
    """
    if config.state_dir.is_symlink() or not config.state_dir.is_dir():
        raise PreservationError("Resume state directory is missing or is a symbolic link")
    state_dir = config.state_dir.resolve(strict=True)
    for name in ("manifest.json", "run.lock", "status.json", "events.jsonl"):
        if (state_dir / name).is_symlink():
            raise PreservationError("Resume state files may not be symbolic links")
    if not (state_dir / "run.lock").is_file():
        raise PreservationError("Resume requires the original state lock file")
    manifest = json.loads((state_dir / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise PreservationError("Resume manifest must be a JSON object")
    destination = str(Path(os.path.abspath(config.destination)))
    if (manifest.get("destination") != destination or
        manifest.get("state_dir", str(state_dir)) != str(state_dir)):
        raise PreservationError("Resume arguments do not identify this manifest's state/destination pair")
    metadata = manifest.get("source_metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("size"), int):
        raise PreservationError("Resume manifest lacks usable source metadata")
    return state_dir, manifest


def record_failure(recorder, error):
    # Status invalidation and event append are independent: a broken event log
    # must not leave an earlier complete marker looking like the latest attempt.
    try:
        recorder.update(force=True, phase="failed", verified=False,
                        error_type=type(error).__name__, error=str(error))
    except OSError:
        pass
    try:
        recorder.event("failed", error_type=type(error).__name__, error=str(error))
    except OSError:
        pass


def preserve(config):
    if not config.resume or config.dry_run:
        return preserve_locked(config)
    state_dir, manifest = trusted_resume_manifest(config)
    with state_lock(state_dir / "run.lock"):
        # Recheck the binding after lock acquisition before mutating state.
        locked_state_dir, locked_manifest = trusted_resume_manifest(config)
        if locked_state_dir != state_dir or locked_manifest != manifest:
            raise PreservationError("Resume manifest changed while acquiring its lock")
        recorder = Recorder(state_dir, manifest, config)
        try:
            recorder.update(force=True, phase="validating_resume", verified=False)
            recorder.event("resume_validation_started", pid=os.getpid(),
                           requested_source=str(config.source),
                           requested_destination=str(config.destination))
            return preserve_locked(config, recorder=recorder, already_locked=True)
        except BaseException as error:
            record_failure(recorder, error)
            raise


def preserve_locked(config, recorder=None, already_locked=False):
    source_path, destination_path, state_dir, free = preflight(config)
    if config.dry_run:
        return {"phase": "dry_run", "writes_performed": False,
                "source": str(source_path), "destination": str(destination_path),
                "state_dir": str(state_dir), "free_bytes": free,
                "source_size": source_path.stat().st_size, "resume": config.resume,
                "reserve_bytes": config.reserve_bytes,
                "limitation": "No byte reads, locking, manifest, or prefix validation performed"}
    if not config.resume:
        state_dir.mkdir(exist_ok=False)
    lock = contextlib.nullcontext() if already_locked else state_lock(state_dir / "run.lock")
    with lock:
        try:
            with open_file(source_path, "rb") as source:
                original = source_metadata(os.fstat(source.fileno()))
                assert_regular(os.fstat(source.fileno()), "Opened source")
                if config.resume:
                    manifest = json.loads((state_dir / "manifest.json").read_text(encoding="utf-8"))
                    if (manifest.get("schema_version") != VERSION or
                        manifest.get("source") != str(source_path) or
                        manifest.get("destination") != str(destination_path) or
                        manifest.get("source_metadata") != original):
                        raise PreservationError("Resume manifest/source identity or metadata mismatch")
                with open_file(destination_path, "r+b" if config.resume else "x+b") as destination:
                    dest_stat = os.fstat(destination.fileno())
                    assert_regular(dest_stat, "Opened destination")
                    if identity(dest_stat) == identity(os.fstat(source.fileno())):
                        raise PreservationError("Opened source and destination are the same file")
                    if config.resume:
                        if manifest.get("destination_identity") != identity(dest_stat):
                            raise PreservationError("Destination file identity differs from manifest")
                    else:
                        manifest = {
                            "schema_version": VERSION, "created_utc": utc_now(),
                            "source": str(source_path), "destination": str(destination_path),
                            "state_dir": str(state_dir),
                            "source_metadata": original, "destination_identity": identity(dest_stat),
                            "python": sys.version, "platform": platform.platform(),
                            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                            "initial_arguments": {"chunk_bytes": config.chunk_bytes,
                                                  "reserve_bytes": config.reserve_bytes,
                                                  "progress_seconds": config.progress_seconds},
                            "method": "Logical file copy; source-stream SHA256; full destination re-read",
                            "source_protection": "Windows deny-write/delete sharing" if os.name == "nt"
                                                 else "POSIX advisory lock; external write protection required",
                        }
                        atomic_json(state_dir / "manifest.json", manifest)
                    if recorder is None:
                        recorder = Recorder(state_dir, manifest, config)
                    recorder.event("attempt_started", resume=config.resume, pid=os.getpid(),
                                   source=str(source_path), destination=str(destination_path),
                                   config={"chunk_bytes": config.chunk_bytes,
                                           "reserve_bytes": config.reserve_bytes,
                                           "progress_seconds": config.progress_seconds})
                    existing = dest_stat.st_size
                    if existing > original["size"]:
                        raise PreservationError("Opened destination is longer than source")
                    ensure_capacity(destination_path.parent, original["size"] - existing,
                                    config.reserve_bytes)
                    digest = hashlib.sha256()
                    recorder.update(force=True, phase="verifying_resume_prefix" if config.resume
                                    else "copying", copied_bytes=existing)
                    if config.resume:
                        # Verify even an uncheckpointed tail; never truncate or trust it blindly.
                        verify_prefix(source, destination, existing, digest, config, recorder)
                        recorder.event("resume_prefix_verified", bytes=existing)
                    offset = existing
                    recorder.update(force=True, phase="copying", checkpoint_bytes=existing)
                    while offset < original["size"]:
                        data = source.read(min(config.chunk_bytes, original["size"] - offset))
                        if not data:
                            raise PreservationError(f"Unexpected end of source at {offset}")
                        ensure_capacity(destination_path.parent, len(data), config.reserve_bytes)
                        write_all(destination, data)
                        digest.update(data)
                        offset += len(data)
                        recorder.status["copied_bytes"] = offset
                        if time.monotonic() - recorder.last_update >= config.progress_seconds:
                            destination.flush()
                            os.fsync(destination.fileno())
                            recorder.update(force=True, checkpoint_bytes=offset)
                    if source.read(1) or source_metadata(os.fstat(source.fileno())) != original:
                        raise PreservationError("Source size or metadata changed during copy")
                    destination.flush()
                    os.fsync(destination.fileno())
                    source_hash = digest.hexdigest()
                    recorder.update(force=True, phase="verifying_destination", copied_bytes=offset,
                                    checkpoint_bytes=offset, source_stream_sha256=source_hash)
                    dest_hash = verify_destination(destination, original["size"], config, recorder)
                    if source_metadata(os.fstat(source.fileno())) != original:
                        raise PreservationError("Source metadata changed during destination verification")
                    recorder.status["destination_sha256"] = dest_hash
                    if dest_hash != source_hash:
                        raise PreservationError("Destination SHA256 differs from source-stream SHA256")
                    destination_metadata = source_metadata(os.fstat(destination.fileno()))
                    if (identity(os.fstat(destination.fileno())) != manifest["destination_identity"] or
                        destination_metadata["size"] != original["size"]):
                        raise PreservationError("Destination identity or size changed during verification")
                    completed_utc = utc_now()
                    manifest.update(final_destination_metadata=destination_metadata,
                                    last_verified_utc=completed_utc,
                                    last_verified_sha256=dest_hash)
                    atomic_json(state_dir / "manifest.json", manifest)
                    recorder.event("verified_complete", size=offset, sha256=source_hash,
                                   destination_metadata=destination_metadata)
                    recorder.update(force=True, phase="complete", verified=True,
                                    completed_utc=completed_utc, destination_sha256=dest_hash,
                                    destination_metadata=destination_metadata)
                    return recorder.status
        except BaseException as error:
            if recorder and not already_locked:
                record_failure(recorder, error)
            raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--resume", action="store_true",
                        help="Require original manifest and compare/re-hash all retained bytes before append")
    parser.add_argument("--dry-run", action="store_true", help="Read metadata/capacity; do not write or hash bytes")
    parser.add_argument("--chunk-mib", type=int, default=16)
    parser.add_argument("--reserve-gib", type=int, default=64)
    parser.add_argument("--progress-seconds", type=float, default=5.0)
    args = parser.parse_args(argv)
    if not 1 <= args.chunk_mib <= 1024:
        parser.error("--chunk-mib must be between 1 and 1024")
    if args.reserve_gib < 0 or args.progress_seconds <= 0:
        parser.error("reserve must be nonnegative and progress interval positive")
    return Config(args.source, args.destination, args.state_dir, args.resume, args.dry_run,
                  args.chunk_mib * 1024 * 1024, args.reserve_gib * GIB, args.progress_seconds)


def main(argv=None):
    try:
        result = preserve(parse_args(argv))
    except KeyboardInterrupt:
        print(json.dumps({"phase": "interrupted", "verified": False}), file=sys.stderr)
        return 130
    except (OSError, ValueError, PreservationError) as error:
        print(json.dumps({"phase": "failed", "verified": False,
                          "error_type": type(error).__name__, "error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
