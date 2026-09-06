#!/usr/bin/env python3
"""Synthetic fake-tool fixtures only; no evidence or installed forensic tool use."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import preserve_image
import recover_catalog as recovery


FAKE_TOOL = r'''
import os, sys, time
from pathlib import Path
if '-V' in sys.argv:
    print('Synthetic icat fixture 1')
    raise SystemExit(0)
identifier = sys.argv[-1]
image = Path(sys.argv[-2])
with open(Path(__file__).with_name('calls.log'), 'a') as log:
    log.write(identifier + '\n')
if os.name == 'nt':
    try:
        writable = open(image, 'r+b')
    except OSError:
        pass
    else:
        writable.close()
        sys.stderr.write('image not write protected')
        raise SystemExit(99)
if '-h' in sys.argv:
    raise SystemExit(98)
if identifier == '11-128-1':
    sys.stdout.buffer.write(image.read_bytes())
elif identifier == '12-128-2':
    sys.stdout.buffer.write(b'partial')
    sys.stderr.write('synthetic extraction failure')
    raise SystemExit(7)
elif identifier == '13-128-1':
    sys.stdout.buffer.write(b'OVERSIZE')
elif identifier == '14-128-1':
    pass
elif identifier == '15-128-1':
    sys.stdout.buffer.write(image.read_bytes())
elif identifier == '16-128-1':
    time.sleep(3)
else:
    sys.stderr.write('unknown synthetic inode')
    raise SystemExit(6)
'''


def catalog_row(identifier="11-128-1", path="/photos/sample.jpg", deleted=True, size=7, source_line=1):
    return {"schema_version": 1, "source_line": source_line, "full_path": path,
            "inode_attribute": identifier, "mode": "r/rrwxrwxrwx", "uid": 0, "gid": 0,
            "size": size, "atime_epoch": 0, "mtime_epoch": 1, "ctime_epoch": 2,
            "crtime_epoch": 3, "deleted": deleted, "reallocated": False,
            "deletion_corroborated": True,
            "raw_line_sha256": "0" * 64}


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="catalog-recovery-fixture-")
        self.root = Path(self.temp.name).resolve()
        self.data = b"A\x00\x00B\r\n\xff"
        self.source = self.root / "synthetic-original.bin"
        self.source.write_bytes(self.data)
        self.image = self.root / "verified-working.bin"
        self.preservation = self.root / "preservation"
        preserve_image.preserve(preserve_image.Config(self.source, self.image, self.preservation,
                                                     reserve_bytes=0, chunk_bytes=4))
        self.exit_marker = self.root / "preservation.exit"
        self.exit_marker.write_text("0\n")
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.fake = self.tools / "fake_icat.py"
        self.fake.write_text(FAKE_TOOL)
        self.inventory = self.root / "inventory"
        self.inventory.mkdir()
        self.catalog = self.inventory / "bodyfile-catalog.jsonl"
        self.output = self.root / "exports"
        self.state = self.root / "recovery-state"
        gate = Path(__file__).with_name("collect_image_inventory.py").resolve()
        self.config = recovery.Config(self.image, self.preservation, self.exit_marker, self.tools,
                                      self.catalog, self.output, self.state, gate,
                                      hashlib.sha256(gate.read_bytes()).hexdigest(),
                                      partition_offset=0, sector_size=512, max_output_bytes=1024,
                                      reserve_bytes=0, stream_timeout=5, progress_seconds=0.01,
                                      tool_prefix=(str(Path(sys.executable).resolve()), str(self.fake)))
        self.write_catalog([catalog_row()])

    def tearDown(self):
        self.temp.cleanup()

    def write_catalog(self, rows):
        self.catalog.write_text("".join(json.dumps(row) + "\n" for row in rows))
        self.write_inventory_binding()

    def write_inventory_binding(self):
        # Synthetic provenance fixture only: no production inventory is fabricated.
        gate = recovery.load_gate(self.config)
        image_identity = gate.read_preservation_gate(self.config)
        configuration = {
            "schema_version": 1, "image": str(self.image), "output_dir": str(self.inventory),
            "preservation_state": str(self.preservation), "preservation_exit_code": str(self.exit_marker),
            "tsk_bin": str(self.tools), "partition_offset_sectors": self.config.partition_offset,
            "sector_size": self.config.sector_size, "catalog_bodyfile": True,
            "script_sha256": self.config.gate_sha256.lower(),
        }
        manifest = {"configuration": configuration, "image_identity": image_identity}
        status = {"schema_version": 1, "phase": "complete", "image_identity": image_identity,
                  "bodyfile_catalog": {"path": str(self.catalog), "bytes": self.catalog.stat().st_size,
                                       "sha256": hashlib.sha256(self.catalog.read_bytes()).hexdigest()}}
        (self.inventory / "manifest.json").write_text(json.dumps(manifest))
        (self.inventory / "status.json").write_text(json.dumps(status))

    def alter_inventory(self, filename, alter):
        path = self.inventory / filename
        value = json.loads(path.read_text())
        alter(value)
        path.write_text(json.dumps(value))

    def results(self):
        return [json.loads(line) for line in (self.state / "export-attempts.jsonl").read_text().splitlines()]

    def calls(self):
        path = self.tools / "calls.log"
        return path.read_text().splitlines() if path.exists() else []

    def select(self, identifiers):
        self.config.selection_manifest = self.root / "selection.json"
        value = {"schema_version": 1, "catalog_sha256": hashlib.sha256(self.catalog.read_bytes()).hexdigest(),
                 "stream_ids": identifiers}
        self.config.selection_manifest.write_text(json.dumps(value), encoding="utf-8")
        return value

    def test_selection_allocated_deleted_ads_and_aliases_preserve_all_refs(self):
        self.write_catalog([catalog_row(deleted=False),
                            catalog_row(identifier="15-128-1", path="/sample.txt:ADS", source_line=2),
                            catalog_row(identifier="15-128-1", path="/alias.txt:ADS", source_line=3),
                            catalog_row(identifier="12-128-2", source_line=4),
                            catalog_row(identifier="99-48-1", source_line=5),
                            catalog_row(identifier="100", source_line=6),
                            catalog_row(identifier="101-128-1", path="/../invalid", source_line=7)])
        self.select(["15-128-1", "11-128-1"])
        status = recovery.run(self.config)
        self.assertEqual(status["phase"], "complete")
        self.assertTrue(status["recovered_all_selected"])
        self.assertEqual(status["selected_counts"], {"complete": 2})
        self.assertEqual(status["invalid_catalog_rows"], 1)
        self.assertEqual(status["counts"]["unsupported"], 1)
        self.assertEqual(self.calls(), ["11-128-1", "15-128-1"])
        attempts = self.results()
        self.assertNotIn("-r", attempts[0]["details"]["command"])
        self.assertIn("-r", attempts[1]["details"]["command"])
        self.assertEqual(attempts[1]["details"]["alias_count"], 2)
        self.assertEqual(len((self.state / "source-references.jsonl").read_text().splitlines()), 7)
        inputs = json.loads((self.state / "inputs.json").read_text())
        self.assertEqual(inputs["mode"], "selected")
        self.assertEqual(inputs["selection"]["stream_ids"], ["11-128-1", "15-128-1"])
        self.assertEqual(inputs["selection"]["manifest"]["sha256"],
                         hashlib.sha256(self.config.selection_manifest.read_bytes()).hexdigest())
        self.config.resume = True
        self.assertEqual(recovery.run(self.config)["phase"], "complete")
        self.assertEqual(len(self.results()), 2)
        self.assertEqual(self.calls(), ["11-128-1", "15-128-1"])

    def test_selection_missing_unsupported_ambiguous_conflicting_and_invalid_fail_before_image(self):
        cases = [([catalog_row()], ["15-128-1"], "missing"),
                 ([catalog_row(identifier="11-48-1")], ["11-48-1"], "unsupported"),
                 ([dict(catalog_row(), deletion_corroborated=False)], ["11-128-1"], "ambiguous"),
                 ([catalog_row(), catalog_row(size=6)], ["11-128-1"], "conflict"),
                 ([catalog_row(), catalog_row(deleted=False)], ["11-128-1"], "conflict"),
                 ([catalog_row(), dict(catalog_row(), reallocated=True)], ["11-128-1"], "conflict"),
                 ([catalog_row(), dict(catalog_row(), deletion_corroborated=False)], ["11-128-1"], "ambiguous"),
                 ([catalog_row(), catalog_row(path="/../bad")], ["11-128-1"], "invalid"),
                 ([catalog_row(), catalog_row(identifier="011-128-1")], ["11-128-1"], "noncanonical")]
        for component in range(3):
            parts = ["11", "128", "1"]
            parts[component] = "0" * 5000 + parts[component]
            cases.append(([catalog_row(), catalog_row(identifier="-".join(parts), size=6)],
                          ["11-128-1"], "noncanonical"))
        for rows, identifiers, error in cases:
            with self.subTest(error=error, rows=rows):
                self.write_catalog(rows)
                self.select(identifiers)
                gate = recovery.load_gate(self.config)
                original = gate.protected_file
                def no_image(path, *args, **kwargs):
                    self.assertNotEqual(Path(path), self.image)
                    return original(path, *args, **kwargs)
                with patch.object(recovery, "load_gate", return_value=gate), \
                        patch.object(gate, "protected_file", side_effect=no_image), \
                        self.assertRaisesRegex(recovery.RecoveryError, error):
                    recovery.run(self.config)
                self.assertEqual(self.calls(), [])
                self.assertFalse(self.state.exists())
                self.assertFalse(self.output.exists())

    def test_selection_manifest_strict_schema_and_ids(self):
        value = self.select(["11-128-1"])
        cases = [(dict(value, stream_ids=["11-128-1", "11-128-1"]), "Duplicate selected"),
                 (dict(value, stream_ids=[]), "between one"),
                 (dict(value, stream_ids=["11"]), "canonical full"),
                 (dict(value, stream_ids=["011-128-1"]), "canonical full"),
                 (dict(value, stream_ids=["11-128-18446744073709551616"]), "canonical full"),
                 (dict(value, stream_ids=["11-128-1;cmd"]), "canonical full"),
                 (dict(value, stream_ids=[None]), "canonical full"),
                 (dict(value, paths=["/photos/*"]), "requires only"),
                 (dict(value, schema_version=True), "Unsupported"),
                 (dict(value, catalog_sha256="0" * 64), "catalog SHA256"),
                 (dict(value, stream_ids=["11-128-1"] * 10001), "10000")]
        for invalid, error in cases:
            with self.subTest(error=error):
                self.config.selection_manifest.write_text(json.dumps(invalid), encoding="utf-8")
                with self.assertRaisesRegex(recovery.RecoveryError, error):
                    recovery.run(self.config)
        for payload, error in [(b'\xff', "UTF-8"), (b'\xef\xbb\xbf{}', "UTF-8"),
                               (b'{"schema_version":1,"schema_version":1}', "Duplicate selection"),
                               (b' ' * (1024 * 1024 + 1), "exceeds one MiB")]:
            self.config.selection_manifest.write_bytes(payload)
            with self.assertRaisesRegex(recovery.RecoveryError, error):
                recovery.run(self.config)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.state.exists())

    def test_selection_dry_run_streams_catalog_without_sqlite_image_or_outputs(self):
        self.write_catalog([catalog_row(identifier=str(n) + "-128-1") for n in range(1000, 2000)] +
                           [catalog_row()])
        self.select(["11-128-1"])
        self.config.dry_run = True
        with patch.object(recovery.sqlite3, "connect", side_effect=AssertionError("No dry-run database")):
            status = recovery.run(self.config)
        self.assertEqual(status["phase"], "dry_run")
        self.assertFalse(status["image_opened"])
        self.assertFalse(self.state.exists())
        self.assertFalse(self.output.exists())
        self.assertEqual(self.calls(), [])
        self.select(["15-128-1"])
        with self.assertRaisesRegex(recovery.RecoveryError, "missing"):
            recovery.run(self.config)

    def test_selection_changed_list_refuses_resume_and_invalidates_success(self):
        self.write_catalog([catalog_row(), catalog_row(identifier="15-128-1")])
        self.select(["11-128-1"])
        self.assertEqual(recovery.run(self.config)["phase"], "complete")
        self.select(["15-128-1"])
        self.config.resume = True
        with self.assertRaisesRegex(recovery.RecoveryError, "identities differ"):
            recovery.run(self.config)
        self.assertEqual(self.calls(), ["11-128-1"])
        status = json.loads((self.state / "status.json").read_text())
        self.assertEqual(status["phase"], "failed")
        self.assertFalse(status["recovered_all_selected"])

    def test_selection_whitespace_change_refuses_resume(self):
        self.select(["11-128-1"])
        recovery.run(self.config)
        with self.config.selection_manifest.open("a", encoding="utf-8") as stream:
            stream.write("\n")
        self.config.resume = True
        with self.assertRaisesRegex(recovery.RecoveryError, "identities differ"):
            recovery.run(self.config)
        self.assertEqual(self.calls(), ["11-128-1"])

    def test_selection_missing_on_resume_invalidates_success(self):
        self.select(["11-128-1"])
        recovery.run(self.config)
        self.select(["99-128-1"])
        self.config.resume = True
        with self.assertRaisesRegex(recovery.RecoveryError, "missing"):
            recovery.run(self.config)
        self.assertEqual(json.loads((self.state / "status.json").read_text())["phase"], "failed")

    def test_selection_exclusive_all_and_protected_output_boundary(self):
        self.select(["11-128-1"])
        self.config.all_files = True
        with self.assertRaisesRegex(recovery.RecoveryError, "mutually exclusive"):
            recovery.run(self.config)
        self.config.all_files = False
        self.config.selection_manifest = self.output / "selection.json"
        with self.assertRaisesRegex(recovery.RecoveryError, "disjoint"):
            recovery.run(self.config)

    def test_selection_parent_alias_is_refused(self):
        self.select(["11-128-1"])
        alias = self.root / "selection-alias"
        self.make_directory_alias(alias, self.root)
        self.config.selection_manifest = alias / "selection.json"
        self.assert_provenance_rejected_before_tool("aliases are not accepted")

    def test_selection_moved_identical_file_refuses_resume(self):
        self.select(["11-128-1"])
        recovery.run(self.config)
        destination = self.root / "other-selection.json"
        self.config.selection_manifest.rename(destination)
        self.config.selection_manifest = destination
        self.config.resume = True
        with self.assertRaisesRegex(recovery.RecoveryError, "identities differ"):
            recovery.run(self.config)
        self.assertEqual(self.calls(), ["11-128-1"])

    @unittest.skipUnless(os.name == "nt", "Windows deny-write handle validation")
    def test_selection_manifest_held_readonly_through_export(self):
        self.select(["11-128-1"])
        export = recovery.export_one
        def inspect_lock(*args, **kwargs):
            with self.assertRaises(OSError):
                with self.config.selection_manifest.open("r+b"):
                    self.fail("Selection manifest was writable during export")
            return export(*args, **kwargs)
        with patch.object(recovery, "export_one", side_effect=inspect_lock):
            self.assertEqual(recovery.run(self.config)["phase"], "complete")

    def test_binary_fidelity_zero_holes_hashes_and_locked_image(self):
        status = recovery.run(self.config)
        self.assertEqual(status["phase"], "complete")
        result = self.results()[0]["details"]
        self.assertEqual((self.output / self.results()[0]["relative_path"]).read_bytes(), self.data)
        self.assertEqual(result["output_record"]["sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(result["stream_sha256"], result["output_record"]["sha256"])
        self.assertIn("-r", result["command"])
        self.assertNotIn("-h", result["command"])
        self.assertEqual(result["command"][-1], "11-128-1")
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_aliases_and_duplicate_source_refs_export_once(self):
        self.write_catalog([catalog_row(), catalog_row(path="/backup/sample.jpg"), catalog_row()])
        recovery.run(self.config)
        self.assertEqual(self.calls(), ["11-128-1"])
        refs = [json.loads(line) for line in (self.state / "source-references.jsonl").read_text().splitlines()]
        self.assertEqual(len(refs), 3)
        self.assertEqual({row["stream_id"] for row in refs}, {1})
        self.assertEqual(self.results()[0]["details"]["alias_count"], 3)

    def test_surrogate_filename_retains_exact_reference_and_recovers_on_resume(self):
        undecodable = catalog_row(path="/bad\udcff.txt (deleted)")
        undecodable["raw_line_sha256"] = hashlib.sha256(b"synthetic bad\xff.txt bodyfile row").hexdigest()
        ordinary = catalog_row(identifier="15-128-1", path="/photos/caf\u00e9.jpg", source_line=2)
        self.write_catalog([undecodable, ordinary])
        catalog_bytes = self.catalog.read_bytes()
        result = recovery.run(self.config)
        self.assertEqual(result["phase"], "complete")
        self.assertEqual(self.calls(), ["11-128-1", "15-128-1"])
        refs = [json.loads(line) for line in (self.state / "source-references.jsonl").read_text().splitlines()]
        self.assertEqual([row["raw_json"] for row in refs], [undecodable, ordinary])
        streams = [json.loads(line) for line in (self.state / "recovery-manifest.jsonl").read_text().splitlines()]
        self.assertEqual(streams[0]["first_path"], "/bad<U+DCFF>.txt (deleted)")
        self.assertEqual(streams[1]["first_path"], ordinary["full_path"])
        first = self.results()[0]
        self.assertEqual(first["details"]["original_path"], streams[0]["first_path"])
        self.assertTrue(first["relative_path"].endswith("_bad_U_DCFF_.txt"))
        output_records = []
        for row in self.results():
            path = self.output / row["relative_path"]
            self.assertEqual(path.read_bytes(), self.data)
            info = path.stat()
            output_records.append((path.name, info.st_ino, info.st_mtime_ns))
        self.config.resume = True
        self.assertEqual(recovery.run(self.config)["phase"], "complete")
        self.assertEqual(self.calls(), ["11-128-1", "15-128-1"])
        self.assertEqual(len(self.results()), 2)
        self.assertEqual([(path.name, path.stat().st_ino, path.stat().st_mtime_ns)
                          for path in sorted(self.output.iterdir())], sorted(output_records))
        self.assertEqual(self.catalog.read_bytes(), catalog_bytes)

    def test_display_path_escapes_only_surrogates_without_directory_separators(self):
        self.assertEqual(recovery.display_path("/caf\u00e9/\U0001f642.txt"), "/caf\u00e9/\U0001f642.txt")
        display = recovery.display_path("/bad\ud800\udcff\udfff.txt")
        self.assertEqual(display, "/bad<U+D800><U+DCFF><U+DFFF>.txt")
        self.assertEqual(display.encode("utf-8").decode("utf-8"), display)
        self.assertEqual(recovery.safe_basename(display), "bad_U_D800__U_DCFF__U_DFFF_.txt")

    def test_unsafe_identifiers_and_path_escape_are_inventory_only(self):
        self.write_catalog([catalog_row(identifier="--help"), catalog_row(path="/safe/../../escape")])
        result = recovery.run(self.config)
        self.assertEqual(result["phase"], "complete_with_errors")
        self.assertEqual(result["invalid_catalog_rows"], 2)
        self.assertEqual(self.calls(), [])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_ntfs_metadata_attributes_not_exported(self):
        self.write_catalog([catalog_row(identifier="11-48-2"), catalog_row(identifier="11-144-1")])
        result = recovery.run(self.config)
        self.assertEqual(result["counts"]["inventory_only"], 2)
        self.assertEqual(self.calls(), [])

    def test_tsk_virtual_orphan_directory_is_inventory_only(self):
        row = catalog_row(identifier="39", path="/$OrphanFiles", size=0, deleted=False)
        row["mode"] = "V/V---------"
        self.write_catalog([row])
        result = recovery.run(self.config)
        self.assertEqual(result["phase"], "complete")
        self.assertEqual(result["counts"]["inventory_only"], 1)
        self.assertEqual(self.calls(), [])

    def test_deleted_default_and_explicit_all_allocated_streams(self):
        self.write_catalog([catalog_row(deleted=False)])
        result = recovery.run(self.config)
        self.assertEqual(result["counts"]["not_selected"], 1)
        self.assertEqual(self.calls(), [])
        self.config.output_dir = self.root / "all-exports"
        self.config.state_dir = self.root / "all-state"
        self.config.all_files = True
        self.assertEqual(recovery.run(self.config)["phase"], "complete")
        self.assertNotIn("-r", json.loads((self.config.state_dir / "export-attempts.jsonl").read_text())["details"]["command"])

    def test_nonzero_exit_preserves_hashed_partial(self):
        self.write_catalog([catalog_row(identifier="12-128-2", size=20)])
        result = recovery.run(self.config)
        record = self.results()[0]
        self.assertEqual(result["phase"], "complete_with_errors")
        self.assertEqual(record["state"], "partial")
        self.assertEqual(record["details"]["exit_code"], 7)
        self.assertEqual(record["details"]["actual_size"], 7)
        self.assertEqual(record["details"]["output_record"]["sha256"], hashlib.sha256(b"partial").hexdigest())

    def test_oversize_output_stopped_before_overflow_write(self):
        self.write_catalog([catalog_row(identifier="13-128-1", size=2)])
        result = recovery.run(self.config)
        self.assertEqual(result["phase"], "complete_with_errors")
        record = self.results()[0]["details"]
        self.assertLessEqual(record["actual_size"], 2)
        self.assertGreater(record["stdout_bytes_seen"], 2)
        self.assertIn("exceeds", record["error"])

    def test_budget_stops_then_resume_can_raise_budget(self):
        self.write_catalog([catalog_row(), catalog_row(identifier="15-128-1", source_line=2)])
        self.config.max_output_bytes = 7
        result = recovery.run(self.config)
        self.assertEqual(result["phase"], "deferred")
        self.assertEqual(self.calls(), ["11-128-1"])
        self.config.max_output_bytes = 14
        self.config.resume = True
        self.assertEqual(recovery.run(self.config)["phase"], "complete")
        self.assertEqual(self.calls(), ["11-128-1", "15-128-1"])

    def test_free_space_guard_defers_without_tool_export(self):
        with patch.object(recovery.shutil, "disk_usage", return_value=type("Usage", (), {"free": 1})()):
            result = recovery.run(self.config)
        self.assertEqual(result["phase"], "deferred")
        self.assertEqual(self.calls(), [])

    def test_completed_resume_checks_hash_and_metadata_before_skip(self):
        recovery.run(self.config)
        self.config.resume = True
        recovery.run(self.config)
        self.assertEqual(self.calls(), ["11-128-1"])
        output = next(self.output.iterdir())
        info = output.stat()
        output.write_bytes(b"X" + self.data[1:])
        os.utime(output, ns=(info.st_atime_ns, info.st_mtime_ns))
        recovery.run(self.config)
        self.assertEqual(self.calls(), ["11-128-1", "11-128-1"])
        self.assertEqual(len(list(self.output.iterdir())), 2)

    def test_changed_catalog_or_tool_refuses_resume(self):
        recovery.run(self.config)
        self.config.resume = True
        self.write_catalog([catalog_row(path="/changed-name.jpg")])
        with self.assertRaisesRegex(recovery.RecoveryError, "identities differ"):
            recovery.run(self.config)
        self.assertEqual(self.calls(), ["11-128-1"])
        status = json.loads((self.state / "status.json").read_text())
        self.assertEqual(status["phase"], "failed")
        self.assertFalse(status["recovered_all_selected"])

    def test_unconfirmed_deletion_suffix_is_not_selected_as_deleted(self):
        row = catalog_row(path="/literal-name (deleted)")
        row["deletion_corroborated"] = False
        self.write_catalog([row])
        status = recovery.run(self.config)
        self.assertEqual(status["counts"]["ambiguous_allocation"], 1)
        self.assertEqual(self.calls(), [])

    def test_disagreeing_alias_sizes_are_not_exported(self):
        self.write_catalog([catalog_row(), catalog_row(path="/other", size=8)])
        status = recovery.run(self.config)
        self.assertEqual(status["counts"]["conflict"], 1)
        self.assertEqual(self.calls(), [])

    def test_zero_byte_stream_is_hash_verified(self):
        self.write_catalog([catalog_row(identifier="14-128-1", size=0)])
        self.assertEqual(recovery.run(self.config)["phase"], "complete")
        details = self.results()[0]["details"]
        self.assertEqual(details["actual_size"], 0)
        self.assertEqual(details["output_record"]["sha256"], hashlib.sha256(b"").hexdigest())

    def test_unrelated_resume_output_pair_leaves_original_state_unchanged(self):
        recovery.run(self.config)
        before = (self.state / "status.json").read_bytes()
        self.config.resume = True
        self.config.output_dir = self.root / "unrelated-output"
        with self.assertRaisesRegex(recovery.RecoveryError, "state/output pair"):
            recovery.run(self.config)
        self.assertEqual((self.state / "status.json").read_bytes(), before)

    def test_interrupted_partial_is_retained_and_retried(self):
        def interrupt(config, command, path, *args):
            path.write_bytes(b"\x00partial")
            raise KeyboardInterrupt()

        with patch.object(recovery, "copy_tool_output", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                recovery.run(self.config)
        self.assertEqual(self.results()[0]["state"], "interrupted")
        self.config.resume = True
        self.assertEqual(recovery.run(self.config)["phase"], "complete")
        records = self.results()
        self.assertEqual(len(records), 2)
        self.assertEqual((self.output / records[0]["relative_path"]).read_bytes(), b"\x00partial")
        self.assertEqual(records[1]["state"], "complete")

    def test_hung_tool_times_out_and_is_stopped(self):
        self.write_catalog([catalog_row(identifier="16-128-1", size=7)])
        self.config.stream_timeout = 0.05
        result = recovery.run(self.config)
        self.assertEqual(result["phase"], "complete_with_errors")
        self.assertIn("timed out", self.results()[0]["details"]["error"])

    def test_missing_exit_gate_prevents_any_image_or_tool_use(self):
        self.exit_marker.unlink()
        with self.assertRaisesRegex(recovery.RecoveryError, "exit marker is absent"):
            recovery.run(self.config)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.calls(), [])

    def test_numbered_segment_image_rejected_before_tool_invocation(self):
        self.config.image = self.root / "explicit-image.001"
        with patch.object(recovery, "tool_records") as tools:
            with self.assertRaisesRegex(recovery.RecoveryError, "Numbered-segment"):
                recovery.run(self.config)
        tools.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_partition_offset_outside_image_rejected_before_tool_invocation(self):
        self.config.partition_offset = 1
        with patch.object(recovery, "tool_records") as tools:
            with self.assertRaisesRegex(recovery.RecoveryError, "offset is outside"):
                recovery.run(self.config)
        tools.assert_not_called()
        self.assertFalse(self.output.exists())

    def make_directory_alias(self, alias, target):
        if os.name == "nt":
            result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(target)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                self.skipTest("Cannot create synthetic directory junction")
        else:
            alias.symlink_to(target, target_is_directory=True)

    def test_output_parent_junction_alias_rejected_without_external_writes(self):
        target = self.root / "unrelated-directory"
        target.mkdir()
        alias = self.root / "directory-alias"
        self.make_directory_alias(alias, target)
        self.config.output_dir = alias / "exports"
        with self.assertRaisesRegex(RuntimeError, "aliases are not accepted"):
            recovery.run(self.config)
        self.assertEqual(list(target.iterdir()), [])

    def test_catalog_parent_junction_alias_rejected(self):
        alias = self.root / "catalog-alias"
        self.make_directory_alias(alias, self.inventory)
        self.config.catalog = alias / self.catalog.name
        with self.assertRaisesRegex(RuntimeError, "aliases are not accepted"):
            recovery.run(self.config)
        self.assertFalse(self.output.exists())

    def assert_provenance_rejected_before_tool(self, pattern):
        with patch.object(recovery, "tool_records") as tools:
            with self.assertRaisesRegex(RuntimeError, pattern):
                recovery.run(self.config)
        tools.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.state.exists())

    def test_wrong_inventory_image_refused_before_export(self):
        for filename in ("manifest.json", "status.json"):
            self.alter_inventory(filename, lambda row: row["image_identity"].update(sha256="f" * 64))
        self.assert_provenance_rejected_before_tool("image identity differs")

    def test_wrong_inventory_offset_refused_before_export(self):
        self.alter_inventory("manifest.json", lambda row: row["configuration"].update(partition_offset_sectors=1))
        self.assert_provenance_rejected_before_tool("geometry mismatch")

    def test_noninteger_inventory_geometry_refused_before_export(self):
        self.alter_inventory("manifest.json", lambda row: row["configuration"].update(partition_offset_sectors=False))
        self.assert_provenance_rejected_before_tool("geometry mismatch")

    def test_wrong_inventory_catalog_hash_refused_before_export(self):
        self.catalog.write_text(json.dumps(catalog_row(path="/different-source.jpg")) + "\n")
        self.assert_provenance_rejected_before_tool("catalog hash/byte count differs")

    def test_wrong_inventory_catalog_path_refused_before_export(self):
        self.alter_inventory("status.json", lambda row: row["bodyfile_catalog"].update(path=str(self.root / "other.jsonl")))
        self.assert_provenance_rejected_before_tool("catalog path differs")

    def test_incomplete_inventory_refused_before_export(self):
        self.alter_inventory("status.json", lambda row: row.update(phase="running"))
        self.assert_provenance_rejected_before_tool("inventory is not complete")

    def test_wrong_inventory_output_root_refused_before_export(self):
        self.alter_inventory("manifest.json", lambda row: row["configuration"].update(output_dir=str(self.root)))
        self.assert_provenance_rejected_before_tool("configuration path mismatch: output_dir")

    def test_unapproved_inventory_producer_refused_before_export(self):
        self.alter_inventory("manifest.json", lambda row: row["configuration"].update(script_sha256="f" * 64))
        self.assert_provenance_rejected_before_tool("producer does not match")

    def test_inventory_without_catalog_mode_refused_before_export(self):
        self.alter_inventory("manifest.json", lambda row: row["configuration"].update(catalog_bodyfile=False))
        self.assert_provenance_rejected_before_tool("not configured")

    def test_recovery_outputs_cannot_be_inside_inventory_root(self):
        self.config.output_dir = self.inventory / "exports"
        self.assert_provenance_rejected_before_tool("must be disjoint")

    def test_inventory_sidecar_drift_refuses_resume(self):
        recovery.run(self.config)
        self.config.resume = True
        self.alter_inventory("status.json", lambda row: row.update(extra="changed provenance"))
        with self.assertRaisesRegex(recovery.RecoveryError, "identities differ"):
            recovery.run(self.config)
        self.assertEqual(self.calls(), ["11-128-1"])
        status = json.loads((self.state / "status.json").read_text())
        self.assertFalse(status["recovered_all_selected"])

    def test_tool_leaf_symlink_rejected_before_version_invocation(self):
        alias = self.tools / "linked_icat.py"
        try:
            alias.symlink_to(self.fake)
        except OSError:
            self.skipTest("File symlinks unavailable on this fixture host")
        self.config.tool_prefix = (str(Path(sys.executable).resolve()), str(alias))
        with patch.object(recovery.subprocess, "run") as subprocess_run:
            with self.assertRaisesRegex(RuntimeError, "aliases are not accepted"):
                recovery.run(self.config)
        subprocess_run.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_hardlinked_mutable_state_and_sidecars_rejected(self):
        recovery.run(self.config)
        self.config.resume = True
        for index, name in enumerate(("events.jsonl", "recovery.sqlite3", "recovery.sqlite3-journal",
                                      "recovery.sqlite3-wal", "recovery.sqlite3-shm",
                                      "recovery-manifest.jsonl.tmp", "status.json")):
            with self.subTest(state_file=name):
                path = self.state / name
                original = path.read_bytes() if path.exists() else None
                external = self.root / f"unrelated-state-{index}.bin"
                external.write_bytes(original if original is not None else b"unrelated sentinel")
                expected = external.read_bytes()
                if path.exists():
                    path.unlink()
                os.link(external, path)
                try:
                    with self.assertRaisesRegex(RuntimeError, "one link"):
                        recovery.run(self.config)
                    self.assertEqual(external.read_bytes(), expected)
                finally:
                    path.unlink()
                    if original is not None:
                        path.write_bytes(original)

    def test_hardlinked_completed_output_is_refused(self):
        recovery.run(self.config)
        original = next(self.output.iterdir())
        external = self.root / "unrelated-output-link.bin"
        os.link(original, external)
        self.config.resume = True
        with self.assertRaisesRegex(RuntimeError, "one link"):
            recovery.run(self.config)
        self.assertEqual(external.read_bytes(), self.data)

    def test_gate_hash_mismatch_prevents_dependency_execution(self):
        self.config.gate_sha256 = "f" * 64
        with self.assertRaisesRegex(recovery.RecoveryError, "module SHA256 mismatch"):
            recovery.run(self.config)
        self.assertFalse(self.output.exists())

    def test_dry_run_no_image_open_or_outputs(self):
        self.config.dry_run = True
        result = recovery.run(self.config)
        self.assertFalse(result["image_opened"])
        self.assertFalse(result["writes_performed"])
        self.assertFalse(self.output.exists())
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
