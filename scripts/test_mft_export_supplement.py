import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mft_tested", HERE / "mft_export_supplement.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
GATE = HERE / "collect_image_inventory.py"
GATE_HASH = "5b8089929c4586c68403b5d0c37b6b88d6b632b1097e1e7a7f68d1d99e348a5e"
TIMES = [113288544000000000, 128915178111234567, 138534624000000000, 189025920000000000]


class CountingRaw(io.RawIOBase):
    def __init__(self, payload):
        super().__init__()
        self.payload, self.requests = io.BytesIO(payload), []

    def readable(self):
        return True

    def seekable(self):
        return True

    def readinto(self, target):
        self.requests.append(len(target))
        return self.payload.readinto(target)

    def seek(self, *args):
        return self.payload.seek(*args)

    def tell(self):
        return self.payload.tell()


class BufferedJSONLTests(unittest.TestCase):
    def test_exact_lines_block_reads_eof_rewind_and_repeated_pass(self):
        lines = [json.dumps({'line': n, 'name': '€\udcff'}).encode() + b'\r\n' for n in range(3000)]
        lines[-1] = lines[-1][:-2]
        payload = b''.join(lines)
        raw = CountingRaw(payload)
        for _ in range(2):
            before = len(raw.requests)
            actual = list(m.json_lines(raw))
            self.assertEqual(actual, [(n, line, json.loads(line)) for n, line in enumerate(lines, 1)])
            self.assertEqual(raw.tell(), 0)
            self.assertFalse(raw.closed)
            self.assertLessEqual(len(raw.requests) - before, len(payload) // m.JSONL_BUFFER_BYTES + 3)
        self.assertEqual(set(raw.requests), {m.JSONL_BUFFER_BYTES})

    def test_limits_invalid_utf8_and_failure_position(self):
        exact = b'{"padding":"' + b' ' * (m.MAX_LINE - 14) + b'"}'
        self.assertEqual(len(exact), m.MAX_LINE)
        self.assertEqual(list(m.json_lines(CountingRaw(exact)))[0][1], exact)
        bad = b' ' * (m.JSONL_BUFFER_BYTES - 1) + b'\xc3\xff\r\n'
        for payload, consumed in [(exact + b'\ntrailing', m.MAX_LINE + 1), (bad + b'{}\n', len(bad))]:
            raw = CountingRaw(payload)
            with self.assertRaises((m.SupplementError, UnicodeDecodeError)):
                list(m.json_lines(raw))
            self.assertFalse(raw.closed)
            self.assertEqual(raw.tell(), consumed)

    def test_generator_close_detaches_and_preserves_consumed_position(self):
        first = b'{"first":1}\r\n'
        raw = CountingRaw(first + b'{"second":2}\n')
        lines = m.json_lines(raw)
        self.assertEqual(next(lines), (1, first, {'first': 1}))
        lines.close()
        self.assertFalse(raw.closed)
        self.assertEqual(raw.tell(), len(first))
        self.assertEqual(raw.read(), b'{"second":2}\n')


def attribute(kind, value, instance=1, name=b""):
    value_off = (24 + len(name) + 7) // 8 * 8
    length = (value_off + len(value) + 7) // 8 * 8
    data = bytearray(length)
    struct.pack_into("<IIBBHHHIHBB", data, 0, kind, length, 0, len(name) // 2, 24 if name else 0,
                     0, instance, len(value), value_off, 0, 0)
    data[24:24 + len(name)] = name
    data[value_off:value_off + len(value)] = value
    return data


def si(values=TIMES, length=72):
    value = bytearray(length)
    if length >= 32:
        struct.pack_into("<QQQQ", value, 0, *values)
    return value


def fn(name="name", values=TIMES, namespace=1):
    raw_name = name.encode("utf-16le", "surrogatepass")
    value = bytearray(66 + len(raw_name))
    struct.pack_into("<QQQQQ", value, 0, (7 << 48) | 5, *values)
    value[64:66] = bytes((len(raw_name) // 2, namespace))
    value[66:] = raw_name
    return value


def record(attrs=None, base_ref=0, end=True):
    data = bytearray(1024)
    data[:4] = b"FILE"
    struct.pack_into("<HH", data, 4, 48, 3)
    offset = 56
    for item in attrs if attrs is not None else [attribute(16, si()), attribute(48, fn(), 2)]:
        data[offset:offset + len(item)] = item
        offset += len(item)
    if end:
        struct.pack_into("<I", data, offset, 0xFFFFFFFF)
        offset += 4
    struct.pack_into("<HHHHIIQH", data, 16, 3, 1, 56, 1, offset, 1024, base_ref, 4)
    data[48:50] = b"\xab\xcd"
    for index, trailer in enumerate((510, 1022), 1):
        data[48 + index * 2:50 + index * 2] = data[trailer:trailer + 2]
        data[trailer:trailer + 2] = b"\xab\xcd"
    return bytes(data)


class ParserTests(unittest.TestCase):
    def parse(self, data):
        return m.parse_record(data, 0, "a" * 64, 0)

    def test_exact_times_and_fn_multiplicity(self):
        result, attrs, times, errors = self.parse(record([attribute(16, si()), attribute(48, fn("x|%20"), 2),
                                                       attribute(48, fn("x|%20", namespace=2), 3)]))
        self.assertEqual(result["parse_state"], "parsed")
        self.assertEqual(errors, [])
        self.assertEqual(len(times), 12)
        self.assertEqual([a["attribute_instance"] for a in attrs], [1, 2, 3])
        self.assertEqual([t["filetime_uint64_decimal"] for t in times[:4]], list(map(str, TIMES)))
        self.assertEqual([int(t["unix_ns_decimal"]) for t in times[:4]], [v * 100 - m.EPOCH_DELTA_NS for v in TIMES])
        self.assertIn("1234567Z", times[1]["utc"])
        self.assertEqual(attrs[1]["filename"]["text"], "x|%20")

    def test_high_bit_and_sentinels(self):
        values = [0, (1 << 64) - 1, 1 << 63, 1]
        _, _, times, errors = self.parse(record([attribute(16, si(values))]))
        self.assertFalse(errors)
        self.assertEqual([t["filetime_uint64_decimal"] for t in times], list(map(str, values)))
        self.assertEqual(times[0]["sentinel_candidate"], "zero")
        self.assertEqual(times[1]["sentinel_candidate"], "all_ones")
        self.assertEqual(times[2]["dissect_signed_decimal"], str(-(1 << 63)))
        self.assertEqual(times[2]["conversion"], "outside_datetime_range")

    def test_fixup_inside_timestamp(self):
        prefix = attribute(0x999, bytes(392))
        result, _, times, errors = self.parse(record([prefix, attribute(16, si())]))
        self.assertFalse(errors)
        self.assertEqual(result["fixup_mapping"][0]["fixed_offset"], 510)
        self.assertEqual(times[1]["fixed_record_field_offset"], 504)
        self.assertEqual(times[1]["fixup_replacements_intersecting_field"][0]["raw_replacement_offset"], 50)
        self.assertEqual(times[1]["filetime_uint64_decimal"], str(TIMES[1]))

    def test_unpaired_surrogate_preserved(self):
        _, attrs, times, errors = self.parse(record([attribute(48, fn("x\udcff|%20"))]))
        self.assertEqual(attrs[0]["filename"]["text"], "x\udcff|%20")
        self.assertTrue(attrs[0]["filename"]["unpaired_surrogate"])
        self.assertEqual(len(times), 4)
        self.assertIn(b"\\udcff", m.encode(attrs[0]))

    def test_reference_is_unresolved(self):
        result, attrs, _, _ = self.parse(record(base_ref=(12 << 48) | 42))
        self.assertEqual(result["base_reference"]["segment"], 42)
        self.assertEqual(result["base_reference"]["sequence"], 12)
        self.assertEqual(attrs[1]["parent_reference"]["resolution"], "not_attempted")

    def test_zero_and_tail_separate(self):
        result, _, _, errors = self.parse(bytes(1024))
        self.assertEqual(result["parse_state"], "empty_or_uninitialized_slot")
        self.assertFalse(errors)
        result, _, _, errors = self.parse(bytes(51))
        self.assertEqual(result["parse_state"], "truncated_tail")
        self.assertTrue(errors)

    def test_invalid_record_headers(self):
        for offset, data in ((0, b"BAAD"), (6, b"\x02\0"), (4, b"\xff\x01"), (510, b"zz"), (20, b"\x30\0")):
            with self.subTest(offset=offset):
                raw = bytearray(record())
                raw[offset:offset + len(data)] = data
                result, _, _, errors = self.parse(bytes(raw))
                self.assertEqual(result["parse_state"], "corrupt_record")
                self.assertTrue(errors)

    def test_si_lengths_and_missing_end(self):
        for length, valid in ((31, False), (48, True), (49, False), (71, False), (72, True), (80, True)):
            with self.subTest(length=length):
                _, _, times, errors = self.parse(record([attribute(16, si(length=length))]))
                self.assertEqual(not bool(errors), valid)
                self.assertEqual(len(times), 4 if valid else 0)
        result, _, _, errors = self.parse(record(end=False))
        self.assertFalse(result["attribute_walk_complete"])
        self.assertIn("missing_attribute_end", [e["error_code"] for e in errors])

    def test_bad_attribute_and_fn_spans(self):
        for kind in ("length", "value", "name", "fn"):
            attr = attribute(48, fn())
            if kind == "length":
                struct.pack_into("<I", attr, 4, 0)
            elif kind == "value":
                struct.pack_into("<H", attr, 20, 16)
            elif kind == "name":
                attr[9] = 4
                struct.pack_into("<H", attr, 10, 24)
            else:
                attr[24 + 64] = 255
            result, _, _, errors = self.parse(record([attr]))
            self.assertTrue(errors, kind)
            self.assertEqual(result["parse_state"], "parsed_with_errors")

    def test_no_reference_resolution(self):
        from dissect.ntfs.mft import MftRecord
        def poison(*args, **kwargs):
            raise AssertionError("External traversal attempted")
        with patch.object(MftRecord, "get", poison), patch.object(MftRecord, "open", poison), patch.object(MftRecord, "filename", poison):
            result, attrs, _, errors = self.parse(record([attribute(32, bytes(40)), attribute(48, fn())], base_ref=5))
        self.assertFalse(errors)
        self.assertEqual(len(attrs), 2)

    def test_malformed_value_does_not_hide_next_valid_fn(self):
        result, attrs, times, errors = self.parse(record([attribute(16, si(length=49)), attribute(48, fn("next"), 2)]))
        self.assertTrue(errors)
        self.assertTrue(result["attribute_walk_complete"])
        self.assertEqual(len(attrs), 2)
        self.assertEqual(len(times), 4)
        self.assertEqual(attrs[1]["filename"]["text"], "next")

    def test_duplicate_instance_retained(self):
        _, attrs, times, errors = self.parse(record([attribute(48, fn("same"), 2), attribute(48, fn("same"), 2)]))
        self.assertFalse(errors)
        self.assertTrue(attrs[1]["duplicate_instance_id"])
        self.assertEqual(len(times), 8)
        self.assertNotEqual(times[0]["attribute_ordinal"], times[4]["attribute_ordinal"])

    def test_nonresident_si_no_external_read(self):
        attr = bytearray(72)
        struct.pack_into("<IIBBHHH", attr, 0, 16, 72, 1, 0, 0, 0, 1)
        struct.pack_into("<QQH", attr, 16, 0, 0, 64)
        result, attrs, times, errors = self.parse(record([attr, attribute(48, fn("after"), 2)]))
        self.assertTrue(errors)
        self.assertTrue(result["attribute_walk_complete"])
        self.assertEqual(len(times), 4)
        self.assertEqual(attrs[0]["external_data_access"], "not_attempted")


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / "recovery-state"
        self.exports = self.root / "exports"
        self.state.mkdir()
        self.exports.mkdir()
        self.export = self.exports / "000000000001_0001_MFT"
        self.export.write_bytes(record())
        self.catalog = self.root / "catalog.jsonl"
        self.row = {"schema_version": 1, "source_line": 2, "full_path": "/$MFT", "inode_attribute": "0-128-1",
                    "size": 1024, "deleted": False, "reallocated": False, "deletion_corroborated": True}
        self.catalog.write_bytes(m.encode(self.row))
        self.marker = self.root / "recovery-exit.txt"
        self.marker.write_bytes(b"0\n")
        self.gate = m.load_gate(GATE, GATE_HASH)
        self.args = types.SimpleNamespace(mft_export=self.export, catalog=self.catalog, recovery_state=self.state,
            recovery_exit_code=self.marker, gate_module=GATE, gate_sha256=GATE_HASH, recovery_sha256="e" * 64,
            inode_attribute="0-128-1", attempt=1, sector_size=512, record_size=1024,
            output_dir=self.root / "out", state_dir=self.root / "state", max_output_bytes=16 * 1024 * 1024, reserve_bytes=0)
        cat_record = {"path": str(self.catalog), "sha256": m.sha(self.catalog.read_bytes()),
                      "metadata": self.gate.metadata(self.catalog.stat())}
        self.inputs = {"schema_version": 1, "state_dir": str(self.state), "output_dir": str(self.exports),
            "recovery_script_sha256": "e" * 64, "gate_sha256": GATE_HASH, "filesystem": "ntfs", "sector_size": 512,
            "partition_offset_sectors": 63, "mode": "all", "catalog": cat_record,
            "inventory_binding": {"producer_script_sha256": GATE_HASH,
                "catalog_record": {"path": str(self.catalog), "sha256": cat_record["sha256"], "bytes": self.catalog.stat().st_size, "lines": 1}},
            "image_gate": {"image": str(self.root / "NEVER_READ.raw"), "size": 102400, "sha256": "a" * 64},
            "tool_prefix": [str(self.root / "NEVER_EXECUTE.exe")]}
        self.status = {"schema_version": 1, "phase": "complete", "recovered_all_selected": True, "completed_utc": "2026-01-01T00:00:00Z"}
        self.manifest = {"id": 1, "inode": "0-128-1", "expected_size": 1024, "deleted": 0, "reallocated": 0,
                         "state": "complete", "alias_count": 1, "first_path": "/$MFT"}
        self.attempt = {"id": 1, "stream_id": 1, "attempt": 1, "relative_path": self.export.name, "state": "complete",
            "details": {"state": "complete", "exit_code": 0, "inode_attribute": "0-128-1", "deleted": False,
                "reallocated": False, "expected_size": 1024, "actual_size": 1024, "stdout_bytes_seen": 1024,
                "original_path": "/$MFT",
                "stream_sha256": m.sha(self.export.read_bytes()), "output_record": {"path": str(self.export),
                "sha256": m.sha(self.export.read_bytes()), "metadata": self.gate.metadata(self.export.stat())},
                "command": self.inputs["tool_prefix"] + ["-i", "raw", "-f", "ntfs", "-b", "512", "-o", "63",
                                                       self.inputs["image_gate"]["image"], "0-128-1"]}}
        self.refs = {"catalog_line": 1, "stream_id": 1, "raw_json": self.row, "problem": None}
        self.flush()

    def tearDown(self):
        self.temp.cleanup()

    def flush(self):
        for name, value in (("inputs.json", self.inputs), ("status.json", self.status),
                ("recovery-manifest.jsonl", self.manifest), ("export-attempts.jsonl", self.attempt),
                ("source-references.jsonl", self.refs)):
            (self.state / name).write_bytes(m.encode(value))
        self.marker.write_bytes(b"0\n")

    def bind(self):
        with m.ExitStack() as stack:
            return m.bind_inputs(self.args, self.gate, stack)[2]

    def test_fresh_full_run(self):
        result = m.run(self.args)
        self.assertEqual(result["phase"], "complete")
        self.assertEqual(result["timestamps"], 8)
        self.assertTrue(result["scan_complete"])
        self.assertFalse((self.root / "NEVER_READ.raw").exists())
        self.assertEqual(m.sha(self.export.read_bytes()), self.attempt["details"]["stream_sha256"])

    def test_source_copy_mismatch(self):
        self.refs = copy.deepcopy(self.refs)
        self.refs["raw_json"]["source_line"] = 99
        self.flush()
        with self.assertRaisesRegex(m.SupplementError, "original catalog"):
            self.bind()

    def test_wrong_catalog_hash(self):
        self.catalog.write_bytes(self.catalog.read_bytes() + b" ")
        with self.assertRaisesRegex(m.SupplementError, "catalog"):
            self.bind()

    def test_corrupt_export(self):
        self.export.write_bytes(bytes(1024))
        with self.assertRaisesRegex(m.SupplementError, "export differs"):
            self.bind()

    def test_incomplete_recovery(self):
        for phase in ("running", "complete_with_errors", "deferred"):
            self.status["phase"] = phase
            self.flush()
            with self.assertRaises(m.SupplementError):
                self.bind()

    def test_bad_marker(self):
        for value in (b"1", b"", b"0\n1", b"00"):
            self.marker.write_bytes(value)
            with self.assertRaises(m.SupplementError):
                self.bind()

    def test_incorrect_allocation_or_id(self):
        for field, value in (("full_path", "/$MFT:ADS"), ("deleted", True), ("deletion_corroborated", False), ("inode_attribute", "1-128-1")):
            self.refs = copy.deepcopy(self.refs)
            self.refs["raw_json"][field] = value
            self.flush()
            with self.assertRaises(m.SupplementError):
                self.bind()
            self.refs["raw_json"] = dict(self.row)

    def test_attempt_mismatch(self):
        self.args.attempt = 2
        with self.assertRaises(m.SupplementError):
            self.bind()

    def test_budget_reports_failed(self):
        self.args.max_output_bytes = m.CONTROL_RESERVE + 5000
        with self.assertRaises(m.SupplementError):
            m.run(self.args)
        status = json.loads((self.args.state_dir / "status.json").read_bytes())
        self.assertEqual(status["phase"], "failed")
        self.assertFalse(status["scan_complete"])

    def test_existing_output_refused(self):
        self.args.output_dir.mkdir()
        with self.assertRaises(m.SupplementError):
            m.run(self.args)

    def test_gate_pin_refused(self):
        self.args.gate_sha256 = "0" * 64
        with self.assertRaises(m.SupplementError):
            m.run(self.args)

    def test_export_hardlink_refused(self):
        os.link(self.export, self.exports / "alias")
        with self.assertRaises(m.SupplementError):
            self.bind()

    def test_stale_marker_refused(self):
        os.utime(self.marker, ns=(1, 1))
        with self.assertRaisesRegex(m.SupplementError, "predates"):
            self.bind()

    def test_single_completed_attempt_required(self):
        with (self.state / "export-attempts.jsonl").open("ab") as stream:
            stream.write(m.encode(self.attempt))
        self.marker.write_bytes(b"0")
        with self.assertRaisesRegex(m.SupplementError, "Ambiguous completed"):
            self.bind()

    def test_free_space_reserve(self):
        with patch.object(m.shutil, "disk_usage", return_value=types.SimpleNamespace(free=0)):
            with self.assertRaisesRegex(m.SupplementError, "reserve"):
                m.run(self.args)

    def test_geometry_refused(self):
        self.args.record_size = 4096
        with self.assertRaisesRegex(m.SupplementError, "geometry"):
            m.run(self.args)

    def test_zero_and_corrupt_full_run_are_honest(self):
        self.export.write_bytes(bytes(1024) + b"BAAD" + bytes(1020) + bytes(3))
        length = self.export.stat().st_size
        self.row["size"] = length
        self.catalog.write_bytes(m.encode(self.row))
        self.inputs["catalog"].update(sha256=m.sha(self.catalog.read_bytes()), metadata=self.gate.metadata(self.catalog.stat()))
        self.inputs["inventory_binding"]["catalog_record"].update(sha256=m.sha(self.catalog.read_bytes()), bytes=self.catalog.stat().st_size)
        self.manifest["expected_size"] = length
        details = self.attempt["details"]
        details.update(expected_size=length, actual_size=length, stdout_bytes_seen=length, stream_sha256=m.sha(self.export.read_bytes()))
        details["output_record"].update(sha256=m.sha(self.export.read_bytes()), metadata=self.gate.metadata(self.export.stat()))
        self.flush()
        result = m.run(self.args)
        self.assertEqual(result["phase"], "complete_with_errors")
        self.assertTrue(result["scan_complete"])
        self.assertEqual((result["records_visited"], result["empty_slots"], result["corrupt_or_error_records"], result["truncated_tails"]), (3, 1, 2, 1))

    @unittest.skipUnless(os.name == "nt", "Mandatory share denial is Windows-specific")
    def test_export_read_lock_denies_writer(self):
        with m.ExitStack() as stack:
            m.bind_inputs(self.args, self.gate, stack)
            with self.assertRaises(OSError):
                with self.export.open("r+b"):
                    pass

    def test_source_sidecar_hardlink_refused(self):
        os.link(self.state / "source-references.jsonl", self.root / "ref-alias")
        with self.assertRaisesRegex(m.SupplementError, "one hard link"):
            self.bind()


if __name__ == "__main__":
    unittest.main()
