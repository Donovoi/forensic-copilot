"""Bounded verified gzip working-copy creation; this is not evidence acquisition.

Manifest: {"items": [{"source": "ABSOLUTE", "expected_sha256": "64 hex",
                      "destination": "ABSOLUTE"}]}
All destination parents must already exist. Existing outputs, partials, and status
files are refused. Failed partials are retained for inspection, never resumed.
Status files include a private 512-byte signature sample; do not publish them.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time
import zlib
from dataclasses import dataclass
from typing import BinaryIO

GIB = 1024**3
CHUNK = 8 * 1024**2
SPARSE_BLOCK = 1024**2


class IntakeError(Exception):
    pass


@dataclass(frozen=True)
class Limits:
    max_output_bytes: int
    reserve_bytes: int
    progress_seconds: float = 3.0

    def validate(self):
        if self.max_output_bytes <= 0 or self.reserve_bytes < 0:
            raise IntakeError("Output limit must be positive and reserve nonnegative")
        if self.progress_seconds <= 0:
            raise IntakeError("Progress interval must be positive")


@dataclass(frozen=True)
class Item:
    source: Path
    expected_sha256: str
    destination: Path

    @property
    def partial(self):
        return self.destination.with_name(self.destination.name + ".partial")

    @property
    def status(self):
        return self.destination.with_name(self.destination.name + ".status.json")


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def stat_identity(s):
    return {k: getattr(s, k) for k in
            ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")}


def same_file_view(left, right):
    # CPython 3.14 on Windows exposes different ctime semantics through fstat
    # and path stat. Compare ctime within each API's before/after observations.
    return all(left[key] == right[key] for key in
               ("st_dev", "st_ino", "st_size", "st_mtime_ns"))


def safe_path(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise IntakeError("Paths must be nonempty strings without NUL")
    path = Path(value)
    if not path.is_absolute():
        raise IntakeError(f"Path must be absolute: {value}")
    # Reject reparse points/symlinks rather than silently redirecting a target.
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise IntakeError(f"Symlink/reparse point is not permitted: {part}")
    if os.name == "nt":
        # Reject alternate data streams and ambiguous Windows names.
        for part in path.parts[1:]:
            if ":" in part or part.endswith((" ", ".")):
                raise IntakeError(f"Ambiguous Windows path: {value}")
    return path.resolve(strict=False)


def validate_manifest(document):
    if not isinstance(document, dict) or set(document) != {"items"}:
        raise IntakeError("Manifest must contain only an items list")
    records = document["items"]
    if not isinstance(records, list) or not records:
        raise IntakeError("Manifest items must be a nonempty list")
    items = []
    occupied = set()
    source_ids = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"source", "expected_sha256", "destination"}:
            raise IntakeError("Each item requires source, expected_sha256, destination only")
        digest = record["expected_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise IntakeError("expected_sha256 must contain exactly 64 hexadecimal characters")
        source = safe_path(record["source"])
        destination = safe_path(record["destination"])
        if not source.is_file() or not stat.S_ISREG(source.stat().st_mode):
            raise IntakeError(f"Source must be an existing regular file: {source}")
        if not destination.parent.is_dir():
            raise IntakeError(f"Destination parent must already exist: {destination.parent}")
        item = Item(source, digest.lower(), destination)
        paths = (source, destination, item.partial, item.status,
                 item.status.with_name(item.status.name + ".tmp"))
        for path in paths:
            safe_path(str(path))
            key = os.path.normcase(str(path))
            if key in occupied:
                raise IntakeError(f"Manifest paths overlap: {path}")
            occupied.add(key)
        source_id = (source.stat().st_dev, source.stat().st_ino)
        if source_id in source_ids:
            raise IntakeError("The manifest contains duplicate source file identities")
        source_ids.add(source_id)
        for path in paths[1:]:
            if path.exists():
                raise IntakeError(f"Refusing existing target: {path}")
        items.append(item)
    return items


def open_locked(path: Path, *, output=False) -> BinaryIO:
    """Windows handle denies other write/delete access while held.

    POSIX uses O_NOFOLLOW where available but cannot impose Windows share locks;
    stat invariance remains checked. This is not a hardware write blocker.
    """
    if os.name != "nt":
        flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL) if output else os.O_RDONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        return os.fdopen(os.open(path, flags, 0o600), "w+b" if output else "rb")
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                       wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    access = 0x80000000 | (0x40000000 if output else 0)
    handle = create(str(path), access, 1, None, 1 if output else 3, 0x08000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, (os.O_RDWR if output else os.O_RDONLY) | os.O_BINARY)
    except BaseException:
        close = kernel.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        close(handle)
        raise
    return os.fdopen(fd, "w+b" if output else "rb")


def enable_sparse(stream):
    if os.name != "nt":
        return True
    import msvcrt
    from ctypes import wintypes
    ioctl = ctypes.WinDLL("kernel32", use_last_error=True).DeviceIoControl
    ioctl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
                      wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                      ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    ioctl.restype = wintypes.BOOL
    returned = wintypes.DWORD()
    return bool(ioctl(msvcrt.get_osfhandle(stream.fileno()), 0x900C4,
                      None, 0, None, 0, ctypes.byref(returned), None))


class HashingReader:
    def __init__(self, raw):
        self.raw = raw
        self.digest = hashlib.sha256()
        self.bytes_read = 0
        self.prefix = bytearray()

    def read(self, size=-1):
        data = self.raw.read(size)
        self.digest.update(data)
        self.bytes_read += len(data)
        if len(self.prefix) < 3:
            self.prefix.extend(data[:3 - len(self.prefix)])
        return data


class Progress:
    def __init__(self, path, state, interval):
        self.path, self.state, self.interval = path, state, interval
        self.last = 0.0
        self.started = time.monotonic()
        # Reserve the status name exclusively; subsequent replace is atomic.
        with path.open("x", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())

    def save(self, force=False):
        now = time.monotonic()
        if not force and now - self.last < self.interval:
            return
        self.state.update(updated_utc=utc_now(), elapsed_seconds=round(now - self.started, 3))
        temp = self.path.with_name(self.path.name + ".tmp")
        with temp.open("x", encoding="utf-8") as stream:
            json.dump(self.state, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, self.path)
        self.last = now


def ensure_space(directory, reserve, upcoming=0):
    free = shutil.disk_usage(directory).free
    if free < reserve + upcoming:
        raise IntakeError(f"Free space {free} is below reserve {reserve} plus next block {upcoming}")
    return free


def write_chunk(stream, chunk, sparse):
    skipped = 0
    if not sparse:
        stream.write(chunk)
        return skipped
    for offset in range(0, len(chunk), SPARSE_BLOCK):
        block = chunk[offset:offset + SPARSE_BLOCK]
        if block.count(0) == len(block):
            stream.seek(len(block), os.SEEK_CUR)
            skipped += len(block)
        else:
            stream.write(block)
    return skipped


def publish(partial, destination):
    # Windows rename refuses an existing destination. POSIX link is atomic and
    # exclusive; unlike rename it cannot silently replace an existing target.
    if os.name == "nt":
        os.rename(partial, destination)
    else:
        os.link(partial, destination)
        os.unlink(partial)


def process_item(item: Item, limits: Limits):
    limits.validate()
    # Revalidate immediately before mutation; a prior item may have run for hours.
    item = validate_manifest({"items": [{"source": str(item.source),
        "expected_sha256": item.expected_sha256, "destination": str(item.destination)}]})[0]
    ensure_space(item.destination.parent, limits.reserve_bytes)
    state = dict(operation="verified gzip working-copy creation; not acquisition",
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        python_version=sys.version, platform=sys.platform,
        stage="starting", source=str(item.source), destination=str(item.destination),
        partial=str(item.partial), started_utc=utc_now(),
        expected_compressed_sha256=item.expected_sha256,
        max_output_bytes=limits.max_output_bytes, reserve_bytes=limits.reserve_bytes,
        compressed_bytes_read=0, output_bytes_written=0, output_bytes_rehashed=0,
        compressed_hash_complete=False, gzip_validated=False,
        independent_output_hash_verified=False, source_stat_unchanged=False,
        signature_first_512_hex="", zero_bytes_skipped=0,
        source_share_lock="deny-write-and-delete" if os.name == "nt" else "unavailable-posix")
    progress = Progress(item.status, state, limits.progress_seconds)
    reader = None
    completed = False
    try:
        with open_locked(item.source) as source:
            initial = stat_identity(os.fstat(source.fileno()))
            initial_path = stat_identity(item.source.stat())
            if not same_file_view(initial, initial_path):
                raise IntakeError("Source path identity changed while opening")
            state["source_stat_before"] = initial
            state["source_path_stat_before"] = initial_path
            reader = HashingReader(source)
            output_digest = hashlib.sha256()
            signature = bytearray()
            state["stage"] = "decompressing"
            with open_locked(item.partial, output=True) as output:
                sparse = enable_sparse(output)
                state["sparse_enabled"] = sparse
                progress.save(force=True)
                with gzip.GzipFile(fileobj=reader, mode="rb") as decoder:
                    while chunk := decoder.read(CHUNK):
                        prospective = state["output_bytes_written"] + len(chunk)
                        if prospective > limits.max_output_bytes:
                            raise IntakeError(f"Decompressed output exceeds {limits.max_output_bytes} bytes")
                        ensure_space(item.destination.parent, limits.reserve_bytes, len(chunk))
                        if len(signature) < 512:
                            signature.extend(chunk[:512 - len(signature)])
                        output_digest.update(chunk)
                        state["zero_bytes_skipped"] += write_chunk(output, chunk, sparse)
                        state["output_bytes_written"] = prospective
                        state["compressed_bytes_read"] = reader.bytes_read
                        state["signature_first_512_hex"] = signature.hex()
                        progress.save()
                # Hash any raw bytes not requested by the decoder. gzip validates
                # every concatenated member; invalid trailing data raises above.
                while reader.read(CHUNK):
                    state["compressed_bytes_read"] = reader.bytes_read
                    progress.save()
                if reader.prefix != b"\x1f\x8b\x08":
                    raise IntakeError("Source does not contain a gzip deflate header")
                state["gzip_validated"] = True
                state["compressed_bytes_read"] = reader.bytes_read
                state["compressed_sha256"] = reader.digest.hexdigest()
                state["compressed_hash_complete"] = reader.bytes_read == initial["st_size"]
                if not state["compressed_hash_complete"]:
                    raise IntakeError("Compressed byte count differs from original source size")
                if state["compressed_sha256"] != item.expected_sha256:
                    raise IntakeError("Compressed SHA-256 does not match expected manifest hash")
                output.truncate(state["output_bytes_written"])
                output.flush()
                os.fsync(output.fileno())
            state["streamed_output_sha256"] = output_digest.hexdigest()
            state["stage"] = "independent-output-rehash"
            progress.save(force=True)
            verification_digest = hashlib.sha256()
            with open_locked(item.partial) as verify:
                output_before = stat_identity(os.fstat(verify.fileno()))
                output_path_before = stat_identity(item.partial.stat())
                if not same_file_view(output_before, output_path_before):
                    raise IntakeError("Output path identity changed while opening")
                while block := verify.read(CHUNK):
                    verification_digest.update(block)
                    state["output_bytes_rehashed"] += len(block)
                    ensure_space(item.destination.parent, limits.reserve_bytes)
                    progress.save()
                if output_before != stat_identity(os.fstat(verify.fileno())):
                    raise IntakeError("Output changed during independent hash reread")
            state["independent_output_sha256"] = verification_digest.hexdigest()
            if (verification_digest.digest() != output_digest.digest() or
                    state["output_bytes_rehashed"] != state["output_bytes_written"]):
                raise IntakeError("Independent output hash or size mismatch")
            state["independent_output_hash_verified"] = True
            final = stat_identity(os.fstat(source.fileno()))
            state["source_stat_after"] = final
            final_path = stat_identity(item.source.stat())
            state["source_path_stat_after"] = final_path
            if initial != final or initial_path != final_path:
                raise IntakeError("Source stat changed during processing")
            state["source_stat_unchanged"] = True
            if output_path_before != stat_identity(item.partial.stat()):
                raise IntakeError("Output identity changed before publication")
            ensure_space(item.destination.parent, limits.reserve_bytes)
            publish(item.partial, item.destination)
            completed = True
            state["stage"] = "complete"
            state["completed_utc"] = utc_now()
            progress.save(force=True)
        return state
    except BaseException as exc:
        state["stage"] = "completed-status-error" if completed else "failed"
        state["error"] = f"{type(exc).__name__}: {exc}"
        if reader is not None:
            state["compressed_bytes_read"] = reader.bytes_read
            state["compressed_sha256_observed"] = reader.digest.hexdigest()
        try:
            progress.save(force=True)
        except BaseException as status_exc:
            print(f"Could not save failure status: {type(status_exc).__name__}: {status_exc}", file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--max-output-gib", type=int, required=True)
    parser.add_argument("--reserve-gib", type=int, required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    try:
        limits = Limits(args.max_output_gib * GIB, args.reserve_gib * GIB)
        limits.validate()
        items = validate_manifest(json.loads(args.manifest.read_text(encoding="utf-8-sig")))
        for item in items:
            ensure_space(item.destination.parent, limits.reserve_bytes)
        if args.validate_only:
            print(json.dumps({"manifest_valid": True, "item_count": len(items),
                "max_output_bytes_per_item": limits.max_output_bytes,
                "reserve_bytes": limits.reserve_bytes, "source_content_read": False}))
            return 0
        for item in items:
            result = process_item(item, limits)
            print(json.dumps({k: result[k] for k in ("stage", "destination",
                "output_bytes_written", "compressed_sha256", "independent_output_sha256")}), flush=True)
        return 0
    except (IntakeError, OSError, EOFError, ValueError, zlib.error) as exc:
        print(f"Intake failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
