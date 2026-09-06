#!/usr/bin/env python3
"""Physical-record observations from one approved, allocated $MFT export.

No image/volume API, external-reference traversal, or logical-file reconstruction.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import time
import types

VERSION = 1
RECORD_SIZE = 1024
SECTOR_SIZE = 512
CONTROL_RESERVE = 2 * 1024 * 1024
MAX_LINE = 1024 * 1024
EPOCH_DELTA_NS = 11644473600000000000
TIME_FIELDS = ("creation", "last_modification", "last_change", "last_access")
DISSECT_FIELDS = ("CreationTime", "LastModificationTime", "LastChangeTime", "LastAccessTime")
LIMITATIONS = [
    "Physical 1024-byte slots of the exported MFT stream only; export offsets are not image offsets.",
    "Base, parent and attribute-list relationships are observed, never resolved or followed.",
    "Physical attribute identifiers are not reconstructed logical stream identifiers.",
    "SI/FN metadata times do not establish human opens, deletion dates, communication or ownership.",
    "UTC renders raw FILETIME; source timezone and clock accuracy are unknown.",
    "Inherited image/catalog identities were not independently verified against any image here.",
    "Empty slots are a coverage category, not proof of MFT allocation status.",
]


class SupplementError(RuntimeError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def encode(value):
    return (json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SupplementError("Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(SupplementError("Nonfinite JSON number")))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(stream):
    stream.seek(0)
    h = hashlib.sha256()
    count = 0
    while data := stream.read(MAX_LINE):
        h.update(data)
        count += len(data)
    stream.seek(0)
    return {"sha256": h.hexdigest(), "bytes": count}


def absolute(path):
    return Path(os.path.abspath(path))


def overlap(a, b):
    return a == b or a in b.parents or b in a.parents


def load_gate(path, expected):
    payload = path.read_bytes()
    if sha(payload) != expected:
        raise SupplementError("Reviewed gate SHA256 mismatch")
    name = "_mft_supplement_reviewed_gate"
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(payload, str(path), "exec"), module.__dict__)
    return module


def reference(value):
    return {"raw_uint64_decimal": str(value), "segment": value & ((1 << 48) - 1),
            "sequence": value >> 48, "resolution": "not_attempted"}


def utf16(data):
    text = data.decode("utf-16le", errors="surrogatepass")
    return {"utf16le_hex": data.hex(), "text": text,
            "encoding": "UTF-16LE; unpaired code units preserved using JSON escapes",
            "unpaired_surrogate": any(0xD800 <= ord(c) <= 0xDFFF for c in text)}


def timestamp(value, reference_ns):
    ns = value * 100 - EPOCH_DELTA_NS
    result = {"filetime_uint64_decimal": str(value), "filetime_le_hex": struct.pack("<Q", value).hex(),
              "unix_ns_decimal": str(ns), "utc": None,
              "sentinel_candidate": "zero" if value == 0 else "all_ones" if value == (1 << 64) - 1 else None,
              "future_of_reference": ns > reference_ns}
    seconds, subsecond_ns = divmod(ns, 1000000000)
    try:
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
        result["utc"] = (f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T{dt.hour:02d}:"
                         f"{dt.minute:02d}:{dt.second:02d}.{subsecond_ns // 100:07d}Z")
        result["conversion"] = "representable"
    except (OverflowError, ValueError):
        result["conversion"] = "outside_datetime_range"
    return result


def span(offset, length, minimum, maximum, label):
    if offset < minimum or length < 0 or offset + length > maximum:
        raise SupplementError(label + " span is out of bounds")
    return (offset, offset + length)


def disjoint(a, b):
    return a[0] == a[1] or b[0] == b[1] or a[1] <= b[0] or b[1] <= a[0]


def parse_record(raw, slot, export_hash, reference_ns):
    """Bounded one-slot parser. Returns complete observations including explicit errors."""
    from dissect.ntfs.mft import MftRecord
    from dissect.ntfs.attr import StandardInformation, FileName

    base = {"schema_version": VERSION, "export_sha256": export_hash,
            "physical_slot": slot, "export_offset": slot * RECORD_SIZE,
            "byte_count": len(raw), "raw_record_sha256": sha(raw), "magic_hex": raw[:4].hex()}
    record, attrs, times, errors = dict(base), [], [], []

    def error(code, message, **detail):
        errors.append({**base, "error_code": code, "message": str(message), **detail})

    if len(raw) != RECORD_SIZE:
        record["parse_state"] = "truncated_tail"
        error("truncated_tail", "Final slot has fewer than 1024 bytes")
        return record, attrs, times, errors
    if not any(raw):
        record["parse_state"] = "empty_or_uninitialized_slot"
        return record, attrs, times, errors
    # Raw fixed-width header observations are retained even when validation fails.
    usa_offset, usa_count = struct.unpack_from("<HH", raw, 4)
    sequence, links, first, flags, used, allocated, base_ref, next_id = struct.unpack_from("<HHHHIIQH", raw, 16)
    record.update(sequence=sequence, reference_count=links, first_attribute_offset=first,
                  flags=flags, in_use_bit=bool(flags & 1), directory_bit=bool(flags & 2),
                  bytes_in_use=used, bytes_allocated=allocated, base_reference=reference(base_ref),
                  next_attribute_instance=next_id, lsn_uint64_decimal=str(struct.unpack_from("<Q", raw, 8)[0]),
                  usa_offset=usa_offset, usa_count=usa_count, header_observation="raw_bytes_before_validation")
    try:
        if raw[:4] != b"FILE":
            raise SupplementError("Nonzero record has wrong FILE signature")
        if usa_count != 3 or usa_offset % 2 or usa_offset < 42 or usa_offset + 6 > 510:
            raise SupplementError("Unsupported or malformed update-sequence array")
        if allocated != RECORD_SIZE or first % 8 or first < 48 or used > allocated or first + 4 > used:
            raise SupplementError("Record header/attribute bounds are invalid")
        if usa_offset + 6 > first:
            raise SupplementError("Update-sequence array overlaps attribute area")
        tag = raw[usa_offset:usa_offset + 2]
        fixed = bytearray(raw)
        mapping = []
        for index, trailer in enumerate((510, 1022), 1):
            replacement = usa_offset + index * 2
            if raw[trailer:trailer + 2] != tag:
                raise SupplementError("Update-sequence trailer mismatch")
            fixed[trailer:trailer + 2] = raw[replacement:replacement + 2]
            mapping.append({"fixed_offset": trailer, "byte_count": 2,
                            "raw_replacement_offset": replacement, "replacement_hex": raw[replacement:replacement + 2].hex()})
        dissect_record = MftRecord.from_bytes(raw, ntfs=None)
        if bytes(dissect_record.data) != bytes(fixed) or dissect_record.ntfs is not None:
            raise SupplementError("Dissect fixed-record result differs from validated fixups")
        record.update(fixed_record_sha256=sha(fixed), usa_tag_hex=tag.hex(), fixup_mapping=mapping,
                      header_observation="structurally_validated; Dissect MftRecord fixed-byte cross-check")
    except Exception as exc:
        record["parse_state"] = "corrupt_record"
        error("record_validation", type(exc).__name__ + ": " + str(exc))
        return record, attrs, times, errors

    offset, ordinal, seen = first, 0, set()
    ended = False
    while offset < used:
        try:
            span(offset, 4, first, used, "Attribute type")
            kind = struct.unpack_from("<I", fixed, offset)[0]
            if kind == 0xFFFFFFFF:
                record["attribute_end_offset"] = offset
                ended = True
                break
            span(offset, 16, first, used, "Common attribute header")
            length, form, name_len, name_off, attr_flags, instance = struct.unpack_from("<IBBHHH", fixed, offset + 4)
            if length == 0 or length % 8 or form not in (0, 1):
                raise SupplementError("Invalid attribute length/alignment/form")
            span(offset, length, first, used, "Attribute record")
            minimum = 24 if form == 0 else 72 if attr_flags & 0x8001 else 64
            if length < minimum:
                raise SupplementError("Short resident/nonresident attribute header")
            common = {**base, "record_sequence": sequence, "attribute_ordinal": ordinal,
                      "attribute_offset": offset, "attribute_length": length, "attribute_type": kind,
                      "attribute_instance": instance, "physical_attribute_id": f"{slot}-{kind}-{instance}",
                      "resident": form == 0, "attribute_flags": attr_flags,
                      "duplicate_instance_id": instance in seen, "parse_state": "header_only"}
            seen.add(instance)
            name_span = span(name_off, name_len * 2, minimum, length, "Attribute name") if name_len else (0, 0)
            common["attribute_name"] = utf16(bytes(fixed[offset + name_span[0]:offset + name_span[1]]))
            if form == 0:
                value_len, value_off = struct.unpack_from("<IH", fixed, offset + 16)
                value_span = span(value_off, value_len, minimum, length, "Resident value")
                if not disjoint(name_span, value_span):
                    raise SupplementError("Attribute name overlaps resident value")
                common.update(value_offset=value_off, value_length=value_len)
            else:
                low, high, mapping_off = struct.unpack_from("<QQH", fixed, offset + 16)
                # Data runs are never decoded or followed. Their start must still be bounded.
                span(mapping_off, 1, minimum, length, "Nonresident mapping-pairs start")
                if name_len and name_span[1] > mapping_off:
                    raise SupplementError("Nonresident name overlaps mapping-pairs area")
                common.update(lowest_vcn_decimal=str(low), highest_vcn_decimal=str(high),
                              mapping_pairs_offset=mapping_off, external_data_access="not_attempted")
            attrs.append(common)
            if kind in (16, 48):
                if form != 0:
                    raise SupplementError("Nonresident SI/FN is unsupported; no external access")
                value = bytes(fixed[offset + value_off:offset + value_off + value_len])
                if kind == 16 and not (value_len == 48 or value_len >= 72):
                    raise SupplementError("SI value must be exactly 48 or at least 72 bytes")
                if kind == 48:
                    if value_len < 66 or 66 + 2 * value[64] > value_len:
                        raise SupplementError("FN value/name is truncated")
                    common.update(parent_reference=reference(struct.unpack_from("<Q", value)[0]),
                                  filename_namespace=value[65], filename_length_code_units=value[64],
                                  filename=utf16(value[66:66 + 2 * value[64]]))
                if kind == 16:
                    common["si_layout"] = "legacy_48" if value_len == 48 else "modern_72_or_longer"
                    common["si_file_attributes"] = struct.unpack_from("<I", value, 32)[0]
                    if value_len >= 72:
                        common["si_internal_owner_id"] = struct.unpack_from("<I", value, 48)[0]
                        common["si_security_id"] = struct.unpack_from("<I", value, 52)[0]
                start = 0 if kind == 16 else 8
                values = struct.unpack_from("<QQQQ", value, start)
                parser_status = "matched_unsigned_bit_patterns"
                signed_values = None
                try:
                    parsed = (StandardInformation if kind == 16 else FileName)(io.BytesIO(value), dissect_record)
                    signed_values = [int(getattr(parsed.attr, field)) for field in DISSECT_FIELDS]
                    if any((signed & ((1 << 64) - 1)) != unsigned for signed, unsigned in zip(signed_values, values)):
                        raise SupplementError("Dissect signed timestamp bit pattern differs")
                except Exception as exc:
                    parser_status = "parser_error_raw_structural_observation_retained"
                    error("si_fn_dissect", type(exc).__name__ + ": " + str(exc), attribute_ordinal=ordinal)
                common.update(parse_state="timestamps_observed", dissect_timestamp_crosscheck=parser_status)
                for index, (field, value64) in enumerate(zip(TIME_FIELDS, values)):
                    position = offset + value_off + start + index * 8
                    restored = [m for m in mapping if not disjoint((position, position + 8), (m["fixed_offset"], m["fixed_offset"] + 2))]
                    times.append({**base, "record_sequence": sequence, "attribute_ordinal": ordinal,
                                  "attribute_offset": offset, "attribute_type": kind, "attribute_instance": instance,
                                  "physical_attribute_id": common["physical_attribute_id"],
                                  "timestamp_class": "SI" if kind == 16 else "FN", "field": field,
                                  "fixed_record_field_offset": position, "fixup_replacements_intersecting_field": restored,
                                  "dissect_timestamp_crosscheck": parser_status,
                                  "dissect_signed_decimal": str(signed_values[index]) if signed_values else None,
                                  **timestamp(value64, reference_ns)})
        except Exception as exc:
            header_valid = bool(attrs and attrs[-1]["attribute_offset"] == offset)
            if header_valid:
                attrs[-1]["parse_state"] = "malformed_or_unsupported"
            error("attribute_validation", type(exc).__name__ + ": " + str(exc),
                  attribute_offset=offset, attribute_ordinal=ordinal,
                  fixed_header_prefix_hex=bytes(fixed[offset:min(offset + 16, used)]).hex())
            if header_valid:
                # The complete common/name/value header was already validated, so
                # its next boundary is safe even when this SI/FN payload is bad.
                offset += length
                ordinal += 1
                continue
            break
        offset += length
        ordinal += 1
    if not ended:
        error("missing_attribute_end", "Attribute walk did not reach an explicit bounded END marker", attribute_offset=offset)
    record.update(parse_state="parsed_with_errors" if errors else "parsed", attribute_count=len(attrs),
                  timestamp_count=len(times), error_count=len(errors), attribute_walk_complete=ended)
    return record, attrs, times, errors


def json_lines(stream):
    stream.seek(0)
    line = 0
    while raw := stream.readline(MAX_LINE + 1):
        line += 1
        if len(raw) > MAX_LINE:
            raise SupplementError("JSONL input line exceeds one MiB")
        value = strict_json(raw)
        if not isinstance(value, dict):
            raise SupplementError("JSONL input must contain objects")
        yield line, raw, value
    stream.seek(0)


def bind_inputs(args, gate, stack):
    streams, records, objects = {}, {}, {}
    paths = {name: args.recovery_state / name for name in (
        "inputs.json", "status.json", "recovery-manifest.jsonl", "export-attempts.jsonl", "source-references.jsonl")}
    paths.update(catalog=args.catalog, exit_marker=args.recovery_exit_code)
    for name, path in paths.items():
        gate.require_unaliased(path)
        stream = stack.enter_context(gate.protected_file(path))
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SupplementError("Provenance inputs must be regular files with one hard link")
        if name in ("inputs.json", "status.json", "exit_marker") and info.st_size > MAX_LINE:
            raise SupplementError("Control input exceeds one MiB")
        streams[name] = stream
        records[name] = {"path": str(path), "metadata": gate.metadata(info), **digest(stream)}
        if name in ("inputs.json", "status.json"):
            objects[name] = strict_json(stream.read())
            if not isinstance(objects[name], dict):
                raise SupplementError("Recovery control input is not an object")
        if name == "exit_marker" and stream.read().strip() != b"0":
            raise SupplementError("Recovery invocation exit marker must be exactly zero")
        stream.seek(0)
    inputs, status = objects["inputs.json"], objects["status.json"]
    if (type(inputs.get("schema_version")) is not int or inputs["schema_version"] != 1 or
            type(status.get("schema_version")) is not int or status["schema_version"] != 1 or
            status.get("phase") != "complete" or status.get("recovered_all_selected") is not True or
            not status.get("completed_utc") or inputs.get("recovery_script_sha256") != args.recovery_sha256 or
            inputs.get("gate_sha256") != args.gate_sha256 or inputs.get("filesystem") != "ntfs" or
            type(inputs.get("sector_size")) is not int or inputs["sector_size"] != SECTOR_SIZE or
            inputs.get("mode") not in ("all", "selected")):
        raise SupplementError("Recovery is not a complete approved allocated-stream invocation")
    if records["exit_marker"]["metadata"]["mtime_ns"] < records["status.json"]["metadata"]["mtime_ns"]:
        raise SupplementError("Recovery exit marker predates the completed status")
    if (not isinstance(inputs.get("state_dir"), str) or not gate.same_path(inputs["state_dir"], args.recovery_state) or
            not isinstance(inputs.get("output_dir"), str) or not os.path.isabs(inputs["output_dir"])):
        raise SupplementError("Recovery root identity mismatch")
    # Fresh export/root is explicitly selected; sidecars are never an instruction to open another path.
    recovered_root = absolute(inputs["output_dir"])
    gate.require_unaliased(recovered_root)
    if args.mft_export.parent != recovered_root:
        raise SupplementError("Explicit export is outside the recorded recovery root")
    catalog_record = inputs.get("catalog", {})
    binding = inputs.get("inventory_binding", {})
    bound_catalog = binding.get("catalog_record", {})
    if (not isinstance(catalog_record.get("path"), str) or not gate.same_path(catalog_record["path"], args.catalog) or
            catalog_record.get("sha256") != records["catalog"]["sha256"] or
            catalog_record.get("metadata") != records["catalog"]["metadata"] or
            not isinstance(bound_catalog.get("path"), str) or not gate.same_path(bound_catalog["path"], args.catalog) or
            bound_catalog.get("sha256") != records["catalog"]["sha256"] or
            bound_catalog.get("bytes") != records["catalog"]["bytes"] or
            binding.get("producer_script_sha256") != args.gate_sha256):
        raise SupplementError("Explicit catalog does not match recovery/inventory binding")
    if inputs["mode"] == "selected":
        selection = inputs.get("selection", {})
        if (selection.get("schema_version") != 1 or selection.get("catalog_sha256") != records["catalog"]["sha256"] or
                not isinstance(selection.get("stream_ids"), list) or args.inode_attribute not in selection["stream_ids"]):
            raise SupplementError("Selected MFT is absent from recorded explicit recovery selection")
    inherited = inputs.get("image_gate", {})
    if (not isinstance(inherited.get("image"), str) or not os.path.isabs(inherited["image"]) or
            not re.fullmatch(r"[0-9a-f]{64}", str(inherited.get("sha256", ""))) or
            type(inherited.get("size")) is not int or inherited["size"] <= 0 or
            type(inputs.get("partition_offset_sectors")) is not int or inputs["partition_offset_sectors"] < 0):
        raise SupplementError("Malformed inherited image/geometry identity")
    # Compare the image path lexically only: do not resolve, stat or open it.
    for root in (args.output_dir, args.state_dir):
        if overlap(root, absolute(inherited["image"])) or overlap(root, recovered_root):
            raise SupplementError("New roots overlap inherited image or recovery outputs")
    selected = []
    for line, raw, item in json_lines(streams["recovery-manifest.jsonl"]):
        if item.get("inode") == args.inode_attribute:
            selected.append((line, sha(raw), item))
            if len(selected) > 1:
                raise SupplementError("Ambiguous selected recovery manifest stream")
    if len(selected) != 1:
        raise SupplementError("Selected MFT stream missing from recovery manifest")
    manifest_line, manifest_hash, manifest = selected[0]
    stream_id = manifest.get("id")
    if (type(stream_id) is not int or stream_id < 1 or manifest.get("state") != "complete" or
            manifest.get("deleted") not in (False, 0) or manifest.get("reallocated") not in (False, 0) or
            manifest.get("first_path") != "/$MFT" or
            type(manifest.get("expected_size")) is not int or manifest["expected_size"] < RECORD_SIZE):
        raise SupplementError("Selected manifest stream is not a complete allocated MFT export")
    found_attempts = []
    for line, raw, item in json_lines(streams["export-attempts.jsonl"]):
        if item.get("stream_id") == stream_id and item.get("state") == "complete":
            found_attempts.append((line, sha(raw), item))
            if len(found_attempts) > 1:
                raise SupplementError("Ambiguous completed attempts for selected MFT")
    if len(found_attempts) != 1:
        raise SupplementError("A single complete selected MFT export attempt is required")
    attempt_line, attempt_hash, attempt = found_attempts[0]
    details = attempt.get("details", {})
    output_record = details.get("output_record", {})
    relative = attempt.get("relative_path")
    if (attempt.get("attempt") != args.attempt or not isinstance(relative, str) or
            Path(relative).name != relative or relative in ("", ".", "..") or
            args.mft_export != recovered_root / relative or
            not isinstance(output_record.get("path"), str) or not gate.same_path(output_record["path"], args.mft_export) or
            details.get("state") != "complete" or type(details.get("exit_code")) is not int or details["exit_code"] != 0 or
            details.get("inode_attribute") != args.inode_attribute or details.get("deleted") is not False or
            details.get("original_path") != "/$MFT" or
            details.get("reallocated") is not False or details.get("expected_size") != manifest["expected_size"] or
            details.get("actual_size") != manifest["expected_size"] or
            details.get("stdout_bytes_seen") != manifest["expected_size"] or
            output_record.get("sha256") != details.get("stream_sha256")):
        raise SupplementError("Selected export attempt identity/size/state mismatch")
    prefix = inputs.get("tool_prefix")
    expected_command = (prefix + ["-i", "raw", "-f", "ntfs", "-b", str(SECTOR_SIZE), "-o",
                                  str(inputs["partition_offset_sectors"]), inherited["image"], args.inode_attribute]
                        if isinstance(prefix, list) and all(isinstance(v, str) for v in prefix) else None)
    if details.get("command") != expected_command:
        raise SupplementError("Allocated icat command provenance mismatch")
    # Authenticate each selected reference against exact original catalog line and decoded row.
    refs = []
    for line, raw, item in json_lines(streams["source-references.jsonl"]):
        if item.get("stream_id") == stream_id:
            if len(refs) >= 16:
                raise SupplementError("Selected MFT references exceed bounded limit")
            row = item.get("raw_json")
            if (item.get("problem") is not None or type(item.get("catalog_line")) is not int or item["catalog_line"] < 1 or
                    not isinstance(row, dict) or row.get("inode_attribute") != args.inode_attribute or
                    row.get("full_path") != "/$MFT" or row.get("deleted") is not False or
                    row.get("reallocated") is not False or row.get("deletion_corroborated") is not True or
                    row.get("size") != manifest["expected_size"]):
                raise SupplementError("Selected source row is not corroborated allocated unnamed /$MFT DATA")
            refs.append({"source_references_line": line, "source_references_row_sha256": sha(raw),
                         "catalog_line": item["catalog_line"], "row": row})
            if len(encode(refs)) > 128 * 1024:
                raise SupplementError("Selected MFT source-reference metadata exceeds 128 KiB")
    if not refs or manifest.get("alias_count") != len(refs) or len({r["catalog_line"] for r in refs}) != len(refs):
        raise SupplementError("Selected source-reference count/identity mismatch")
    wanted = {r["catalog_line"]: r for r in refs}
    catalog_lines = 0
    for line, raw, item in json_lines(streams["catalog"]):
        catalog_lines = line
        if line in wanted:
            if item != wanted[line]["row"]:
                raise SupplementError("Copied source reference differs from the original catalog row")
            wanted[line]["catalog_json_row_sha256"] = sha(raw)
    if catalog_lines != bound_catalog.get("lines") or any("catalog_json_row_sha256" not in r for r in refs):
        raise SupplementError("Catalog row count/selected line is inconsistent")
    stream = stack.enter_context(gate.protected_file(args.mft_export))
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SupplementError("Export must be a regular single-link file")
    actual = {"path": str(args.mft_export), "metadata": gate.metadata(info), **digest(stream)}
    if (actual["metadata"] != output_record.get("metadata") or actual["sha256"] != output_record.get("sha256") or
            actual["bytes"] != manifest["expected_size"]):
        raise SupplementError("Independently hashed export differs from the complete attempt")
    streams["mft_export"], records["mft_export"] = stream, actual
    return streams, records, {"inherited_image_gate": inherited, "inventory_binding": binding,
                             "partition_offset_sectors": inputs["partition_offset_sectors"],
                             "recovery_manifest_line": manifest_line, "recovery_manifest_row_sha256": manifest_hash,
                             "attempt_line": attempt_line, "attempt_row_sha256": attempt_hash,
                             "stream_id": stream_id, "inode_attribute": args.inode_attribute,
                             "source_references": refs}


class Budget:
    def __init__(self, args, gate):
        self.args, self.gate = args, gate
        self.written = 0
        self.last_check = 0

    def used(self):
        total = 0
        for root in (self.args.output_dir, self.args.state_dir):
            self.gate.require_unaliased(root)
            for path in root.iterdir():
                self.gate.safe_mutable_file(path)
                total += path.stat().st_size
        return total

    def check(self, additional=0, control=False):
        self.written = self.used()
        cap = self.args.max_output_bytes - (0 if control else CONTROL_RESERVE)
        if self.written + additional > cap:
            raise SupplementError("Explicit total output budget would be crossed")
        for root in (self.args.output_dir, self.args.state_dir):
            if shutil.disk_usage(root).free < self.args.reserve_bytes + additional:
                raise SupplementError("Free-space reserve would be crossed")
        self.last_check = time.monotonic()

    def write(self, stream, value):
        self.write_data(stream, encode(value))

    def write_data(self, stream, data):
        if time.monotonic() - self.last_check >= 1:
            self.check(len(data))
        if self.written + len(data) > self.args.max_output_bytes - CONTROL_RESERVE:
            raise SupplementError("Explicit total output budget would be crossed")
        # Unbuffered files: the tracked count corresponds to actual completed writes.
        if stream.write(data) != len(data):
            raise SupplementError("Short output write")
        self.written += len(data)

    def control(self, path, value):
        data = encode(value)
        if len(data) > CONTROL_RESERVE // 4:
            raise SupplementError("Control object exceeds bounded allowance")
        temporary = path.with_name(path.name + ".tmp")
        self.gate.safe_mutable_file(path)
        self.check(len(data), control=True)
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        self.written = self.used()


def parser_identity():
    import dissect.ntfs.mft
    import dissect.ntfs.attr
    import dissect.ntfs.c_ntfs
    import dissect.ntfs.util
    modules = (dissect.ntfs.mft, dissect.ntfs.attr, dissect.ntfs.c_ntfs, dissect.ntfs.util)
    return {"python": sys.version, "executable": sys.executable,
            "packages": {name: importlib.metadata.version(name) for name in ("dissect.ntfs", "dissect.cstruct", "dissect.util")},
            "modules": [{"name": mod.__name__, "path": mod.__file__, "sha256": sha(Path(mod.__file__).read_bytes())} for mod in modules]}


def run(args):
    if args.sector_size != SECTOR_SIZE or args.record_size != RECORD_SIZE:
        raise SupplementError("Only explicit 512-byte sector / 1024-byte record geometry is supported")
    gate = load_gate(args.gate_module, args.gate_sha256)
    paths = (args.mft_export, args.catalog, args.recovery_state, args.recovery_exit_code, args.gate_module)
    for path in (*paths, args.output_dir, args.state_dir):
        gate.require_unaliased(path)
    for root in (args.output_dir, args.state_dir):
        if os.path.lexists(root) or not root.parent.is_dir():
            raise SupplementError("Fresh output/state roots with existing parents required")
        if any(overlap(root, other) for other in paths):
            raise SupplementError("New root overlaps an input")
    if overlap(args.output_dir, args.state_dir):
        raise SupplementError("Fresh output/state roots must be separate")
    with ExitStack() as stack:
        streams, records, provenance = bind_inputs(args, gate, stack)
        identity = parser_identity()
        args.output_dir.mkdir()
        args.state_dir.mkdir()
        budget = Budget(args, gate)
        progress = {"schema_version": VERSION, "phase": "running", "scan_complete": False,
                    "started_utc": utc_now(), "bytes_visited": 0, "records_visited": 0, "parsed_records": 0,
                    "empty_slots": 0, "corrupt_or_error_records": 0, "truncated_tails": 0,
                    "attributes": 0, "timestamps": 0, "errors": 0,
                    "max_output_bytes": args.max_output_bytes, "reserve_bytes": args.reserve_bytes}
        outputs = {}
        try:
            budget.check()
            budget.control(args.state_dir / "inputs.json", {"schema_version": VERSION,
                "script_sha256": sha(Path(__file__).read_bytes()), "gate_sha256": args.gate_sha256,
                "recovery_sha256": args.recovery_sha256, "inputs": records, "provenance": provenance,
                "parser": identity, "geometry": {"sector_size": SECTOR_SIZE, "record_size": RECORD_SIZE},
                "output_dir": str(args.output_dir), "state_dir": str(args.state_dir), "limitations": LIMITATIONS})
            budget.control(args.state_dir / "status.json", progress)
            reference_ns = time.time_ns()
            progress["future_reference_unix_ns_decimal"] = str(reference_ns)
            with ExitStack() as out_stack:
                output_streams = {name: out_stack.enter_context((args.output_dir / name).open("xb", buffering=0))
                                  for name in ("mft-records.jsonl", "mft-attributes.jsonl", "mft-timestamps.jsonl", "mft-errors.jsonl")}
                stream = streams["mft_export"]
                stream.seek(0)
                last_status = time.monotonic()
                slot = 0
                while raw := stream.read(RECORD_SIZE):
                    record, attrs, times, errors = parse_record(raw, slot, records["mft_export"]["sha256"], reference_ns)
                    for name, items in zip(output_streams, ([record], attrs, times, errors)):
                        for item in items:
                            budget.write(output_streams[name], item)
                    progress["records_visited"] += 1
                    progress["bytes_visited"] += len(raw)
                    progress["parsed_records"] += record["parse_state"] == "parsed"
                    progress["empty_slots"] += record["parse_state"] == "empty_or_uninitialized_slot"
                    progress["corrupt_or_error_records"] += bool(errors)
                    progress["truncated_tails"] += record["parse_state"] == "truncated_tail"
                    progress["attributes"] += len(attrs)
                    progress["timestamps"] += len(times)
                    progress["errors"] += len(errors)
                    slot += 1
                    if time.monotonic() - last_status >= 5:
                        progress["updated_utc"] = utc_now()
                        budget.control(args.state_dir / "status.json", progress)
                        last_status = time.monotonic()
                for stream in output_streams.values():
                    os.fsync(stream.fileno())
            if progress["bytes_visited"] != records["mft_export"]["bytes"]:
                raise SupplementError("Full export coverage byte count mismatch")
            for name, stream in streams.items():
                if gate.metadata(os.fstat(stream.fileno())) != records[name]["metadata"] or digest(stream) != {k: records[name][k] for k in ("sha256", "bytes")}:
                    raise SupplementError("Locked input metadata/hash changed during processing")
            summary = ("# Physical MFT metadata observations\n\n"
                       f"Visited {progress['records_visited']} physical slots / {progress['bytes_visited']} export bytes. "
                       f"Parsed cleanly: {progress['parsed_records']}; empty slots: {progress['empty_slots']}; "
                       f"slots with errors: {progress['corrupt_or_error_records']}; short tails: {progress['truncated_tails']}.\n\n"
                       f"Retained {progress['attributes']} attribute headers and {progress['timestamps']} SI/FN timestamp observations. "
                       f"Explicit errors: {progress['errors']}.\n\n"
                       "The JSONL files retain exact record/attribute references, raw hashes, timestamp decimal strings and "
                       "UTF-16 names. Record order is physical export order. No image was read. "
                       "Base/parent references were not resolved; logical files and full paths were not reconstructed. "
                       "Filesystem dates are not human actions, deletion dates or communications.\n")
            with (args.output_dir / "summary.md").open("xb", buffering=0) as stream:
                budget.write_data(stream, summary.encode("utf-8"))
                os.fsync(stream.fileno())
            for path in args.output_dir.iterdir():
                gate.safe_mutable_file(path)
                with path.open("rb") as stream:
                    outputs[path.name] = {"path": str(path), **digest(stream)}
            budget.control(args.state_dir / "output-manifest.json", {"schema_version": VERSION, "outputs": outputs,
                "inputs_manifest_sha256": sha((args.state_dir / "inputs.json").read_bytes())})
            progress.update(scan_complete=True, phase="complete_with_errors" if progress["errors"] else "complete",
                            completed_utc=utc_now(), output_manifest_sha256=sha((args.state_dir / "output-manifest.json").read_bytes()))
            budget.control(args.state_dir / "status.json", progress)
            return progress
        except BaseException as exc:
            progress.update(phase="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", scan_complete=False,
                            error=type(exc).__name__ + ": " + str(exc), updated_utc=utc_now())
            try:
                budget.control(args.state_dir / "status.json", progress)
            except Exception:
                pass
            raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("mft-export", "catalog", "recovery-state", "recovery-exit-code", "gate-module", "output-dir", "state-dir"):
        parser.add_argument("--" + flag, type=absolute, required=True)
    for flag in ("gate-sha256", "recovery-sha256"):
        parser.add_argument("--" + flag, type=str.lower, required=True)
    parser.add_argument("--inode-attribute", required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--sector-size", type=int, choices=(SECTOR_SIZE,), required=True)
    parser.add_argument("--record-size", type=int, choices=(RECORD_SIZE,), required=True)
    parser.add_argument("--max-output-bytes", type=int, required=True)
    parser.add_argument("--reserve-bytes", type=int, required=True)
    args = parser.parse_args(argv)
    if (not all(re.fullmatch(r"[0-9a-f]{64}", getattr(args, name)) for name in ("gate_sha256", "recovery_sha256")) or
            not re.fullmatch(r"0-128-(0|[1-9][0-9]{0,19})", args.inode_attribute) or
            int(args.inode_attribute.rsplit("-", 1)[-1]) >= 2**64 or args.attempt < 1 or
            args.max_output_bytes <= CONTROL_RESERVE or args.reserve_bytes < 0):
        parser.error("Invalid hashes, full record-0 DATA identifier, attempt or capacity")
    return args


def main(argv=None):
    try:
        result = run(parse_args(argv))
        print(json.dumps(result, ensure_ascii=True, allow_nan=False))
        return 0 if result["phase"] == "complete" else 3
    except KeyboardInterrupt:
        print(json.dumps({"phase": "interrupted"}), file=sys.stderr)
        return 130
    except Exception as exc:
        print(json.dumps({"phase": "failed", "error": type(exc).__name__ + ": " + str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
