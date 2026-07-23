#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


EXPECTED_BASE_ISO_SHA256 = (
    "a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9"
)
DEFAULT_IMAGE = "forensic-copilot/windows-forensic-vm:win11-25h2"
RESULTS_LABEL = "FC_RESULTS"
AUXILIARY_LABEL = "FC_AUX"
SCHEMA_VERSION = 1
BLOCK_SIZE = 1024 * 1024


class SafetyError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def canonical(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def reject_symlink_argument(path: Path, label: str) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise SafetyError(f"{label} path is a symlink: {expanded}")
    return expanded


def sha256_file(path: Path, *, block_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(block_size):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".partial")
    with partial.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    partial.replace(path)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError(f"Cannot read JSON record {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SafetyError(f"Expected a JSON object in {path}")
    return value


def verify_base_iso(path: Path) -> str:
    path = canonical(reject_symlink_argument(path, "Base ISO"))
    if not path.is_file():
        raise SafetyError(f"Base ISO is not a regular, non-symlink file: {path}")
    actual = sha256_file(path)
    if actual != EXPECTED_BASE_ISO_SHA256:
        raise SafetyError(
            "Windows 11 Enterprise Evaluation 25H2 ISO SHA-256 mismatch: "
            f"expected {EXPECTED_BASE_ISO_SHA256}, got {actual}"
        )
    return actual


def copy_derivative(source: Path, output: Path, expected_source_sha256: str) -> Path:
    source = canonical(reject_symlink_argument(source, "Source"))
    output = canonical(reject_symlink_argument(output, "Derivative output"))
    expected = expected_source_sha256.lower()
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise SafetyError("--source-sha256 must be a 64-character hexadecimal SHA-256")
    if source == output:
        raise SafetyError("Derivative path resolves to the source path")
    if not source.is_file():
        raise SafetyError("Source must be a regular, non-symlink file")
    if output.exists():
        raise SafetyError(f"Refusing to overwrite derivative path: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(output.name + ".partial")
    if partial.exists() or partial.is_symlink():
        raise SafetyError(
            f"Review or remove the existing partial derivative: {partial}"
        )

    digest = hashlib.sha256()
    try:
        with source.open("rb") as src, partial.open("xb") as dst:
            while chunk := src.read(8 * 1024 * 1024):
                digest.update(chunk)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        actual = digest.hexdigest()
        if actual != expected:
            raise SafetyError(
                f"Source SHA-256 mismatch: expected {expected}, got {actual}; "
                "partial derivative retained for review"
            )
        partial.replace(output)
    except Exception:
        # A partial copy is evidence of an interrupted or failed operation. Keep
        # it visibly partial for explicit review rather than deleting it.
        raise

    descriptor = output.with_name(output.name + ".forensic-derivative.json")
    atomic_json(
        descriptor,
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "windows-filesystem-repair-derivative",
            "created_utc": utc_now(),
            "source_path": str(source),
            "source_sha256": actual,
            "source_size": source.stat().st_size,
            "derivative_path": str(output),
            "derivative_sha256": actual,
            "derivative_size": output.stat().st_size,
            "original_evidence_writable": False,
        },
    )
    return descriptor


def validate_derivative(
    derivative: Path,
    descriptor_path: Path,
    *,
    actual_sha256: str | None = None,
) -> tuple[dict[str, Any], str]:
    derivative = canonical(reject_symlink_argument(derivative, "Derivative"))
    descriptor = load_json(
        canonical(reject_symlink_argument(descriptor_path, "Derivative descriptor"))
    )
    if descriptor.get("kind") != "windows-filesystem-repair-derivative":
        raise SafetyError(
            "Descriptor is not a Windows filesystem repair derivative record"
        )
    if canonical(Path(str(descriptor.get("derivative_path", "")))) != derivative:
        raise SafetyError("Descriptor derivative path does not resolve to --derivative")
    source_argument = reject_symlink_argument(
        Path(str(descriptor.get("source_path", ""))), "Descriptor source"
    )
    source = canonical(source_argument)
    if source == derivative:
        raise SafetyError("Descriptor identifies the derivative as its own source")
    if not source.is_file():
        raise SafetyError("Descriptor source is no longer a regular, non-symlink file")
    if not derivative.is_file():
        raise SafetyError("Derivative must be a regular, non-symlink file")
    if os.path.samefile(source, derivative):
        raise SafetyError(
            "Derivative and descriptor source are the same filesystem object"
        )
    if derivative.stat().st_size != descriptor.get("derivative_size"):
        raise SafetyError("Derivative size differs from its preparation record")
    actual = actual_sha256 or sha256_file(derivative)
    if actual != descriptor.get("derivative_sha256"):
        raise SafetyError("Derivative SHA-256 differs from its preparation record")
    return descriptor, actual


def write_blockmap(
    path: Path, output: Path, block_size: int = BLOCK_SIZE
) -> tuple[list[dict[str, Any]], str]:
    blocks: list[dict[str, Any]] = []
    file_digest = hashlib.sha256()
    with path.open("rb") as stream:
        index = 0
        offset = 0
        while chunk := stream.read(block_size):
            file_digest.update(chunk)
            blocks.append(
                {
                    "index": index,
                    "offset": offset,
                    "length": len(chunk),
                    "sha256": hashlib.sha256(chunk).hexdigest(),
                }
            )
            index += 1
            offset += len(chunk)
    file_sha256 = file_digest.hexdigest()
    atomic_json(
        output,
        {
            "schema_version": SCHEMA_VERSION,
            "path": str(canonical(path)),
            "file_size": path.stat().st_size,
            "file_sha256": file_sha256,
            "block_size": block_size,
            "blocks": blocks,
        },
    )
    return blocks, file_sha256


def normalize_volume_serial(value: str) -> str:
    normalized = value.upper()
    if not re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}", normalized):
        raise SafetyError("--volume-serial must use the Windows vol format XXXX-XXXX")
    return normalized


def validate_auxiliary_media(
    auxiliary_image: Path, record_path: Path
) -> tuple[dict[str, Any], str]:
    auxiliary_image = canonical(
        reject_symlink_argument(auxiliary_image, "Auxiliary image")
    )
    record = load_json(
        canonical(reject_symlink_argument(record_path, "Auxiliary-media record"))
    )
    if record.get("kind") != "windows-forensic-autounattend-auxiliary-media":
        raise SafetyError("Auxiliary-media record has the wrong kind")
    if record.get("required_official_iso_sha256") != EXPECTED_BASE_ISO_SHA256:
        raise SafetyError(
            "Auxiliary-media record is not bound to the required official ISO hash"
        )
    payload = Path(__file__).resolve().parent / "payload"
    required_payload = {
        "autounattend_sha256": sha256_file(payload / "Autounattend.xml"),
        "repair_script_source_sha256": sha256_file(
            payload / "forensic-repair" / "run.cmd"
        ),
        "filesystem_label": AUXILIARY_LABEL,
    }
    for field, expected in required_payload.items():
        if record.get(field) != expected:
            raise SafetyError(f"Auxiliary-media record has a stale or invalid {field}")
    if canonical(Path(str(record.get("auxiliary_image_path", "")))) != auxiliary_image:
        raise SafetyError(
            "Auxiliary-media record path does not resolve to --auxiliary-image"
        )
    if not auxiliary_image.is_file():
        raise SafetyError("Auxiliary image must be a regular, non-symlink file")
    if auxiliary_image.stat().st_size != record.get("auxiliary_image_size"):
        raise SafetyError("Auxiliary image size differs from its media record")
    actual = sha256_file(auxiliary_image)
    if actual != record.get("auxiliary_image_sha256"):
        raise SafetyError("Auxiliary image hash differs from its media record")
    return record, actual


def changed_extents(
    before: list[dict[str, Any]], after: list[dict[str, Any]], block_size: int
) -> list[dict[str, int]]:
    def extent(first: int, last: int) -> dict[str, int]:
        records = [
            (index, collection[index])
            for index in range(first, last + 1)
            for collection in (before, after)
            if index < len(collection)
        ]
        start_offset = min(
            int(record.get("offset", index * block_size)) for index, record in records
        )
        end_offset = max(
            int(record.get("offset", index * block_size)) + int(record["length"])
            for index, record in records
        )
        return {
            "first_block": first,
            "last_block": last,
            "offset": start_offset,
            "length": end_offset - start_offset,
        }

    changed_indexes: list[int] = []
    count = max(len(before), len(after))
    for index in range(count):
        if index >= len(before) or index >= len(after):
            changed_indexes.append(index)
        elif (
            before[index]["sha256"] != after[index]["sha256"]
            or before[index]["length"] != after[index]["length"]
        ):
            changed_indexes.append(index)
    if not changed_indexes:
        return []

    extents: list[dict[str, int]] = []
    start = previous = changed_indexes[0]
    for index in changed_indexes[1:]:
        if index == previous + 1:
            previous = index
            continue
        extents.append(extent(start, previous))
        start = previous = index
    extents.append(extent(start, previous))
    return extents


def require_local_image(image: str) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SafetyError(
            f"Required local Docker image is absent: {image}. Build it explicitly first."
        )
    values = json.loads(result.stdout)
    return values[0]


def docker_identity_args() -> list[str]:
    if os.name != "posix":
        return []
    args = ["--user", f"{os.getuid()}:{os.getgid()}"]
    kvm = Path("/dev/kvm")
    if kvm.exists():
        args.extend(["--group-add", str(kvm.stat().st_gid)])
    return args


def create_results_image(run_dir: Path, image: str, config: dict[str, Any]) -> Path:
    results = run_dir / "results.img"
    with results.open("xb") as stream:
        stream.truncate(64 * 1024 * 1024)
    config_path = run_dir / "forensic-config.ini"
    config_path.write_text(
        "".join(f"{key}={value}\r\n" for key, value in config.items()),
        encoding="ascii",
        newline="",
    )
    command = [
        "docker",
        "run",
        "--pull",
        "never",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        *docker_identity_args(),
        "--mount",
        f"type=bind,src={run_dir},dst=/output",
        image,
        "sh",
        "-ec",
        f"mkfs.vfat -F 32 -n {RESULTS_LABEL} -i 52534C54 /output/results.img >/dev/null; "
        "mcopy -i /output/results.img /output/forensic-config.ini ::forensic-config.ini",
    ]
    subprocess.run(command, check=True)
    return results


def build_auxiliary_media(args: argparse.Namespace) -> None:
    image_record = require_local_image(args.image)
    output_dir = canonical(
        reject_symlink_argument(args.output_dir, "Auxiliary output directory")
    )
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SafetyError(f"Output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    payload = Path(__file__).resolve().parent / "payload"
    answer_file = payload / "Autounattend.xml"
    repair_script = payload / "forensic-repair" / "run.cmd"
    if not answer_file.is_file() or not repair_script.is_file():
        raise SafetyError("Auxiliary-media payload is incomplete")

    auxiliary_image = output_dir / "windows-forensic-auxiliary.img"
    auxiliary_partial = output_dir / "windows-forensic-auxiliary.partial.img"
    with auxiliary_partial.open("xb") as stream:
        stream.truncate(64 * 1024 * 1024)
    command = [
        "docker",
        "run",
        "--pull",
        "never",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        *docker_identity_args(),
        "--mount",
        f"type=bind,src={output_dir},dst=/output",
        "--mount",
        f"type=bind,src={payload},dst=/payload,readonly",
        args.image,
        "sh",
        "-ec",
        'awk \'{ sub(/\\r$/, ""); printf "%s\\r\\n", $0 }\' '
        "/payload/forensic-repair/run.cmd >/tmp/run.cmd; "
        "printf 'forensic-copilot offline auxiliary media\\r\\n' >/tmp/FORENSIC_AUX.TAG; "
        f"mkfs.vfat -F 32 -n {AUXILIARY_LABEL} -i 41555831 "
        "/output/windows-forensic-auxiliary.partial.img >/dev/null; "
        "mcopy -i /output/windows-forensic-auxiliary.partial.img "
        "/payload/Autounattend.xml ::Autounattend.xml; "
        "mcopy -i /output/windows-forensic-auxiliary.partial.img "
        "/tmp/FORENSIC_AUX.TAG ::FORENSIC_AUX.TAG; "
        "mmd -i /output/windows-forensic-auxiliary.partial.img ::forensic-repair; "
        "mcopy -i /output/windows-forensic-auxiliary.partial.img "
        "/tmp/run.cmd ::forensic-repair/run.cmd",
    ]
    subprocess.run(command, check=True)
    auxiliary_partial.replace(auxiliary_image)
    record = {
        "schema_version": SCHEMA_VERSION,
        "kind": "windows-forensic-autounattend-auxiliary-media",
        "created_utc": utc_now(),
        "required_official_iso_sha256": EXPECTED_BASE_ISO_SHA256,
        "auxiliary_image_path": str(auxiliary_image),
        "auxiliary_image_sha256": sha256_file(auxiliary_image),
        "auxiliary_image_size": auxiliary_image.stat().st_size,
        "filesystem_label": AUXILIARY_LABEL,
        "autounattend_sha256": sha256_file(answer_file),
        "repair_script_source_sha256": sha256_file(repair_script),
        "runtime_image": args.image,
        "runtime_image_id": image_record.get("Id"),
        "network": "none",
        "command": command,
    }
    atomic_json(output_dir / "auxiliary-media.json", record)


def qemu_docker_command(
    *,
    image: str,
    container_name: str,
    official_iso: Path,
    auxiliary_image: Path,
    derivative: Path,
    results_image: Path,
    mode: str,
    memory_mib: int,
    cpus: int,
) -> list[str]:
    derivative_mount_option = ",readonly" if mode == "scan" else ""
    derivative_readonly = "on" if mode == "scan" else "off"
    return [
        "docker",
        "run",
        "--pull",
        "never",
        "--rm",
        "--name",
        container_name,
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--device",
        "/dev/kvm",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        *docker_identity_args(),
        "--mount",
        f"type=bind,src={official_iso},dst=/media/windows-official.iso,readonly",
        "--mount",
        f"type=bind,src={auxiliary_image},dst=/auxiliary/auxiliary.img,readonly",
        "--mount",
        f"type=bind,src={derivative},dst=/evidence/derivative.raw{derivative_mount_option}",
        "--mount",
        f"type=bind,src={results_image},dst=/results/results.img",
        image,
        "qemu-system-x86_64",
        "-machine",
        "pc,accel=kvm",
        "-cpu",
        "host",
        "-smp",
        str(cpus),
        "-m",
        str(memory_mib),
        "-nodefaults",
        "-display",
        "none",
        "-vga",
        "std",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-nic",
        "none",
        "-boot",
        "once=d",
        "-drive",
        "file=/media/windows-official.iso,media=cdrom,if=ide,index=0,readonly=on",
        "-drive",
        f"file=/evidence/derivative.raw,format=raw,if=none,id=derivative,readonly={derivative_readonly},cache=none",
        "-drive",
        "file=/results/results.img,format=raw,if=none,id=results,readonly=off,cache=none",
        "-drive",
        "file=/auxiliary/auxiliary.img,format=raw,if=none,id=auxiliary,readonly=on,cache=none",
        "-device",
        "qemu-xhci,id=xhci",
        "-device",
        "usb-storage,drive=results,removable=on,serial=FORENSIC_RESULTS",
        "-device",
        "usb-storage,drive=auxiliary,removable=on,serial=FORENSIC_AUX",
        "-device",
        "usb-storage,drive=derivative,removable=on,serial=FORENSIC_DERIVATIVE",
    ]


def validate_scan_proof(
    scan_dir: Path,
    derivative_sha256: str,
    *,
    official_iso_sha256: str,
    auxiliary_image_sha256: str,
    runtime_image_id: str | None,
    volume_serial: str,
    disk_number: int,
    partition_number: int,
) -> dict[str, Any]:
    manifest = load_json(canonical(scan_dir) / "run.json")
    if manifest.get("status") != "complete" or manifest.get("mode") != "scan":
        raise SafetyError("Repair requires a completed read-only scan run")
    if manifest.get("derivative_sha256_before") != derivative_sha256:
        raise SafetyError("Scan proof is for a different derivative state")
    if manifest.get("derivative_sha256_after") != derivative_sha256:
        raise SafetyError("Read-only scan proof did not preserve the derivative hash")
    if manifest.get("changed_extents"):
        raise SafetyError("Read-only scan proof reports changed derivative extents")
    required_bindings = {
        "official_iso_sha256": official_iso_sha256,
        "auxiliary_image_sha256": auxiliary_image_sha256,
        "runtime_image_id": runtime_image_id,
        "expected_volume_serial": volume_serial,
        "derivative_disk_number": disk_number,
        "derivative_partition_number": partition_number,
    }
    for field, expected in required_bindings.items():
        if manifest.get(field) != expected:
            raise SafetyError(f"Scan proof does not match the current {field}")
    status_path = canonical(scan_dir) / "guest" / "run-status.txt"
    if not status_path.is_file() or "STATUS=complete" not in status_path.read_text(
        encoding="utf-8", errors="replace"
    ):
        raise SafetyError("Scan proof lacks the guest completion marker")
    if not (canonical(scan_dir) / "guest" / "chkdsk-scan.txt").is_file():
        raise SafetyError("Scan proof lacks chkdsk-scan.txt")
    return manifest


def extract_results(run_dir: Path, image: str) -> None:
    guest = run_dir / "guest"
    guest.mkdir(exist_ok=False)
    command = [
        "docker",
        "run",
        "--pull",
        "never",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        *docker_identity_args(),
        "--mount",
        f"type=bind,src={run_dir},dst=/output",
        image,
        "sh",
        "-ec",
        "mcopy -s -i /output/results.img '::*' /output/guest/",
    ]
    subprocess.run(command, check=True)


def run_vm(args: argparse.Namespace) -> None:
    if os.name != "posix" or not Path("/dev/kvm").exists():
        raise SafetyError("VM execution requires Linux with /dev/kvm")
    if min(args.disk_number, args.partition_number) < 0:
        raise SafetyError("Disk and partition numbers cannot be negative")
    if min(args.memory_mib, args.cpus, args.timeout) < 1:
        raise SafetyError("Memory, CPU, and timeout values must be positive")
    if args.mode == "scan" and args.allow_derivative_write:
        raise SafetyError("Scan mode does not accept --allow-derivative-write")
    if args.mode == "repair" and not args.allow_derivative_write:
        raise SafetyError("Repair mode requires --allow-derivative-write")
    if args.mode == "repair" and not args.scan_run:
        raise SafetyError("Repair mode requires --scan-run")
    volume_serial = normalize_volume_serial(args.volume_serial)
    image_record = require_local_image(args.image)
    official_iso = canonical(reject_symlink_argument(args.official_iso, "Official ISO"))
    official_iso_sha256 = verify_base_iso(official_iso)
    auxiliary_image = canonical(
        reject_symlink_argument(args.auxiliary_image, "Auxiliary image")
    )
    auxiliary_record, auxiliary_image_sha256 = validate_auxiliary_media(
        auxiliary_image, args.auxiliary_media_record
    )
    derivative = canonical(reject_symlink_argument(args.derivative, "Derivative"))
    claimed_descriptor = load_json(
        canonical(
            reject_symlink_argument(args.derivative_descriptor, "Derivative descriptor")
        )
    )
    descriptor, _ = validate_derivative(
        derivative,
        args.derivative_descriptor,
        actual_sha256=str(claimed_descriptor.get("derivative_sha256", "")),
    )
    for attached_path, label in (
        (official_iso, "official ISO"),
        (auxiliary_image, "auxiliary image"),
    ):
        if os.path.samefile(attached_path, derivative):
            raise SafetyError(f"Derivative aliases the {label}")
    if os.path.samefile(official_iso, auxiliary_image):
        raise SafetyError("Official ISO aliases the auxiliary image")

    run_dir = canonical(reject_symlink_argument(args.output, "Run output"))
    if run_dir.exists():
        raise SafetyError(f"Refusing to overwrite run directory: {run_dir}")
    run_dir.mkdir(parents=True)
    before_blocks, before_sha256 = write_blockmap(
        derivative, run_dir / "blockmap-before.json"
    )
    descriptor, _ = validate_derivative(
        derivative,
        args.derivative_descriptor,
        actual_sha256=before_sha256,
    )
    if args.mode == "repair":
        validate_scan_proof(
            args.scan_run,
            before_sha256,
            official_iso_sha256=official_iso_sha256,
            auxiliary_image_sha256=auxiliary_image_sha256,
            runtime_image_id=image_record.get("Id"),
            volume_serial=volume_serial,
            disk_number=args.disk_number,
            partition_number=args.partition_number,
        )
    config = {
        "MODE": args.mode,
        "DERIVATIVE_DISK": args.disk_number,
        "DERIVATIVE_PARTITION": args.partition_number,
        "EXPECTED_VOLUME_SERIAL": volume_serial,
    }
    results_image = create_results_image(run_dir, args.image, config)
    container_name = f"forensic-winpe-{os.getpid()}"
    command = qemu_docker_command(
        image=args.image,
        container_name=container_name,
        official_iso=official_iso,
        auxiliary_image=auxiliary_image,
        derivative=derivative,
        results_image=results_image,
        mode=args.mode,
        memory_mib=args.memory_mib,
        cpus=args.cpus,
    )
    started = utc_now()
    qemu_exit: int | None = None
    failure: str | None = None
    try:
        with (run_dir / "qemu.log").open("w", encoding="utf-8", newline="\n") as log:
            result = subprocess.run(
                command,
                check=False,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=args.timeout,
            )
            qemu_exit = result.returncode
    except subprocess.TimeoutExpired:
        failure = f"QEMU exceeded the {args.timeout}-second timeout"
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    finally:
        after_blocks, after_sha256 = write_blockmap(
            derivative, run_dir / "blockmap-after.json"
        )
        extents = changed_extents(before_blocks, after_blocks, BLOCK_SIZE)
        atomic_json(
            run_dir / "changed-extents.json",
            {"block_size": BLOCK_SIZE, "extents": extents},
        )

    try:
        extract_results(run_dir, args.image)
    except subprocess.CalledProcessError as exc:
        failure = failure or f"Could not extract results image: exit {exc.returncode}"

    guest_status = run_dir / "guest" / "run-status.txt"
    guest_complete = (
        guest_status.is_file()
        and "STATUS=complete"
        in guest_status.read_text(encoding="utf-8", errors="replace")
    )
    if qemu_exit != 0:
        failure = failure or f"QEMU container exit status was {qemu_exit}"
    if not guest_complete:
        failure = failure or "Guest completion marker is absent"
    if args.mode == "scan" and (after_sha256 != before_sha256 or extents):
        failure = failure or "Read-only scan changed the derivative"

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "failed" if failure else "complete",
        "failure": failure,
        "started_utc": started,
        "completed_utc": utc_now(),
        "mode": args.mode,
        "network": "none",
        "official_iso_path": str(official_iso),
        "official_iso_sha256": official_iso_sha256,
        "official_iso_writable": False,
        "auxiliary_image_path": str(auxiliary_image),
        "auxiliary_image_sha256": auxiliary_image_sha256,
        "auxiliary_media_record": str(canonical(args.auxiliary_media_record)),
        "auxiliary_media_writable": False,
        "autounattend_sha256": auxiliary_record.get("autounattend_sha256"),
        "runtime_image": args.image,
        "runtime_image_id": image_record.get("Id"),
        "derivative_descriptor": str(canonical(args.derivative_descriptor)),
        "derivative_source_sha256": descriptor.get("source_sha256"),
        "derivative_sha256_before": before_sha256,
        "derivative_sha256_after": after_sha256,
        "changed_extents": extents,
        "block_size": BLOCK_SIZE,
        "expected_volume_serial": volume_serial,
        "derivative_disk_number": args.disk_number,
        "derivative_partition_number": args.partition_number,
        "qemu_exit_status": qemu_exit,
        "qemu_command": command,
        "original_evidence_attached": False,
        "derivative_writable": args.mode == "repair",
    }
    atomic_json(run_dir / "run.json", manifest)
    if failure:
        raise SafetyError(failure)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evidence-safe Windows 11 25H2 WinPE filesystem repair VM scaffold"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser(
        "verify-media", help="verify the official base ISO hash"
    )
    verify.add_argument("--iso", type=Path, required=True)

    derivative = subparsers.add_parser(
        "prepare-derivative", help="create and hash a separate repair derivative"
    )
    derivative.add_argument("--source", type=Path, required=True)
    derivative.add_argument("--source-sha256", required=True)
    derivative.add_argument("--output", type=Path, required=True)

    media = subparsers.add_parser(
        "build-auxiliary-media",
        help="create the hashed FAT Autounattend auxiliary disk",
    )
    media.add_argument("--output-dir", type=Path, required=True)
    media.add_argument("--image", default=DEFAULT_IMAGE)

    run = subparsers.add_parser(
        "run", help="run an isolated read-only scan or derivative repair"
    )
    run.add_argument("--mode", choices=("scan", "repair"), required=True)
    run.add_argument("--official-iso", type=Path, required=True)
    run.add_argument("--auxiliary-image", type=Path, required=True)
    run.add_argument("--auxiliary-media-record", type=Path, required=True)
    run.add_argument("--derivative", type=Path, required=True)
    run.add_argument("--derivative-descriptor", type=Path, required=True)
    run.add_argument(
        "--volume-serial", required=True, help="expected NTFS serial shown by vol"
    )
    run.add_argument("--disk-number", type=int, default=0)
    run.add_argument(
        "--partition-number",
        type=int,
        default=0,
        help="partition to assign, or 0 for an automounted partition slice",
    )
    run.add_argument("--scan-run", type=Path)
    run.add_argument("--allow-derivative-write", action="store_true")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--image", default=DEFAULT_IMAGE)
    run.add_argument("--memory-mib", type=int, default=8192)
    run.add_argument("--cpus", type=int, default=4)
    run.add_argument("--timeout", type=int, default=1800)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "verify-media":
            print(verify_base_iso(args.iso))
        elif args.command == "prepare-derivative":
            print(copy_derivative(args.source, args.output, args.source_sha256))
        elif args.command == "build-auxiliary-media":
            build_auxiliary_media(args)
        elif args.command == "run":
            run_vm(args)
        else:  # pragma: no cover - argparse enforces the command set
            raise AssertionError(args.command)
    except (OSError, SafetyError, subprocess.CalledProcessError) as exc:
        print(f"forensic_vm.py: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
