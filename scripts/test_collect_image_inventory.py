#!/usr/bin/env python3
"""Synthetic fixtures only; no user image, original drive, or installed TSK needed."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import collect_image_inventory as inventory


FAKE_TOOL = r'''
import pathlib, sys, time
name, mode = sys.argv[1:3]
args = sys.argv[3:]
if '-V' in args:
    sys.stdout.buffer.write(b'The Sleuth Kit ver synthetic\n')
    sys.exit(0)
if mode == 'timeout':
    time.sleep(30)
if mode == 'failure':
    sys.stdout.buffer.write(b'partial\x00output\n')
    sys.stderr.buffer.write(b'synthetic error\xff\x00\n')
    sys.exit(7)
# Opening only the synthetic working image proves child read sharing works.
assert pathlib.Path(args[-1]).read_bytes().startswith(b'SYNTHETIC')
sys.stderr.buffer.write(b'synthetic diagnostic\xff\x00\n')
if name == 'mmls':
    sys.stdout.buffer.write(b'DOS Partition Table\nSlot Start End Length Description\n')
elif name == 'fsstat':
    sys.stdout.buffer.write(b'FILE SYSTEM INFORMATION\nFile System Type: NTFS\n')
elif name == 'fls' and '-m' in args:
    sys.stdout.buffer.write(b'0|/folder/a|b.txt:stream (deleted-realloc)|42-128-3|r/rrwxrwxrwx|0|0|9|1|2|3|4\n')
    sys.stdout.buffer.write(b'0|/folder/a|b.txt ($FILE_NAME)|42-48-2|r/rrwxrwxrwx|0|0|99|10|20|30|40\n')
elif name == 'fls':
    sys.stdout.buffer.write(b'r/r * 42-128-3(realloc):\tfolder/a|b.txt:stream\t0\xff\n')
elif name == 'ils':
    sys.stdout.buffer.write(b'class|host|device|start_time\nils|synthetic||0\nst_ino|st_alloc|st_uid|st_gid|st_mtime|st_atime|st_ctime|st_crtime|st_mode|st_nlink|st_size\n')
    if '-e' in args:
        sys.stdout.buffer.write(b'42|f|0|0|2|1|3|4|0|0|9\n')
'''


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="inventory-fixture-")
        self.root = Path(self.temporary.name)
        self.image = self.root / "synthetic working image.raw"
        self.image.write_bytes(b"SYNTHETIC" + bytes(range(256)) * 32)
        self.state = self.root / "preservation"
        self.state.mkdir()
        self.exit_file = self.root / "copy-exit.txt"
        self.exit_file.write_text("0\n", encoding="utf-8")
        self.tools = self.root / "tools"
        self.tools.mkdir()
        for name in ("mmls", "fsstat", "fls", "ils"):
            (self.tools / (name + (".exe" if os.name == "nt" else ""))).write_bytes(b"synthetic tool")
        self.fake = self.root / "fake_tool.py"
        self.fake.write_text(FAKE_TOOL, encoding="utf-8")
        self.config = inventory.Config(self.image, self.state, self.exit_file, self.tools,
                                       self.root / "inventory", 512, 0,
                                       reserve_bytes=0, poll_seconds=0.01, catalog_bodyfile=True)
        self.fake_mode = "ok"
        self.commands = []
        self.real_popen = subprocess.Popen
        self.write_gate()

    def tearDown(self):
        self.temporary.cleanup()

    def write_gate(self, final=True):
        actual = inventory.metadata(self.image.stat())
        source = {**actual, "inode": actual["inode"] + 1}
        digest = hashlib.sha256(self.image.read_bytes()).hexdigest()
        completed = inventory.utc_now()
        self.manifest = {"schema_version": 1, "source": str(self.root / "original-is-not-present.raw"),
                         "destination": str(self.image), "state_dir": str(self.state),
                         "source_metadata": source,
                         "destination_identity": {key: actual[key] for key in ("device", "inode")}}
        self.status = {"schema_version": 1, "phase": "complete", "verified": True,
                       "destination": str(self.image), "state_dir": str(self.state),
                       "source_size": actual["size"], "copied_bytes": actual["size"],
                       "checkpoint_bytes": actual["size"], "destination_verified_bytes": actual["size"],
                       "source_stream_sha256": digest, "destination_sha256": digest,
                       "completed_utc": completed}
        if final:
            self.manifest.update(final_destination_metadata=actual, last_verified_utc=completed,
                                 last_verified_sha256=digest)
            self.status["destination_metadata"] = actual
        self.save_gate()

    def save_gate(self):
        (self.state / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")
        (self.state / "status.json").write_text(json.dumps(self.status), encoding="utf-8")

    def fake_popen(self, command, **kwargs):
        self.commands.append(command)
        self.assertFalse(kwargs["shell"])
        self.assertIsInstance(command, list)
        name = Path(command[0]).stem
        return self.real_popen([sys.executable, str(self.fake), name, self.fake_mode, *command[1:]], **kwargs)

    def run_inventory(self, config=None):
        with patch.object(inventory.subprocess, "Popen", side_effect=self.fake_popen):
            return inventory.inventory(config or self.config)

    def test_end_to_end_binary_safe_catalog_and_unchanged_image(self):
        before = self.image.read_bytes()
        result = self.run_inventory()
        self.assertEqual(result["phase"], "complete")
        self.assertEqual(self.image.read_bytes(), before)
        self.assertEqual(len(self.commands), 11)
        self.assertEqual(result["stages"]["ils_orphan"]["state"], "complete")
        self.assertIn(b"\xff\x00", Path(result["stages"]["fls_root"]["stderr"]["path"]).read_bytes())
        catalog = [json.loads(line) for line in (self.config.output_dir / "bodyfile-catalog.jsonl").read_text().splitlines()]
        self.assertEqual(catalog[0]["source_line"], 1)
        self.assertEqual(catalog[0]["full_path"], "/folder/a|b.txt:stream (deleted-realloc)")
        self.assertEqual(catalog[0]["inode_attribute"], "42-128-3")
        self.assertTrue(catalog[0]["deleted"])
        self.assertTrue(catalog[0]["reallocated"])
        self.assertEqual(catalog[1]["inode_attribute"], "42-48-2")
        self.assertEqual(catalog[0]["crtime_epoch"], 4)

    def test_command_semantics_whole_disk_mmls_and_ils_no_timezone(self):
        config = replace(self.config, partition_offset=7)
        commands = dict(inventory.stage_commands(config, {name: name for name in ("mmls", "fsstat", "fls", "ils")}))
        self.assertNotIn("-o", commands["mmls"])
        for name, command in commands.items():
            if name != "mmls":
                self.assertEqual(command[command.index("-o")+1], "7")
            if name.startswith("ils_"):
                self.assertNotIn("-z", command)
                self.assertNotIn("UTC", command)
        self.assertIn("-e", commands["ils_all"])
        self.assertIn("-p", commands["ils_orphan"])
        self.assertIn("-r", commands["fls_bodyfile"])

    def test_missing_marker_never_opens_or_stats_image(self):
        self.exit_file.unlink()
        self.image.unlink()
        self.assertIsNone(inventory.read_preservation_gate(self.config))
        with patch.object(inventory, "check_image_handle") as checked:
            with self.assertRaisesRegex(inventory.InventoryError, "exit marker is absent"):
                self.run_inventory()
            checked.assert_not_called()
        self.assertEqual(self.commands, [])

    def test_finite_wait_expires_without_touching_image(self):
        self.exit_file.unlink()
        self.image.unlink()
        config = replace(self.config, wait=True, max_wait_hours=0.000003)
        with self.assertRaisesRegex(inventory.InventoryError, "wait expired"):
            self.run_inventory(config)
        self.assertEqual(self.commands, [])

    def test_nonzero_exit_marker_blocks(self):
        self.exit_file.write_text("1\n")
        with self.assertRaisesRegex(inventory.InventoryError, "unsuccessfully"):
            self.run_inventory()
        self.assertEqual(self.commands, [])

    def test_completed_but_unverified_blocks(self):
        self.status["verified"] = False
        self.save_gate()
        with self.assertRaisesRegex(inventory.InventoryError, "verified preservation"):
            inventory.read_preservation_gate(self.config)

    def test_incomplete_phase_with_success_marker_blocks(self):
        self.status["phase"] = "verifying_destination"
        self.save_gate()
        with self.assertRaisesRegex(inventory.InventoryError, "verified preservation"):
            inventory.read_preservation_gate(self.config)

    def test_all_byte_counts_are_required_and_exact(self):
        for key in ("source_size", "copied_bytes", "checkpoint_bytes", "destination_verified_bytes"):
            with self.subTest(key=key):
                self.write_gate()
                self.status[key] -= 1
                self.save_gate()
                with self.assertRaisesRegex(inventory.InventoryError, "byte count mismatch"):
                    inventory.read_preservation_gate(self.config)

    def test_hash_mismatch_blocks(self):
        self.status["destination_sha256"] = "0" * 64
        self.save_gate()
        with self.assertRaisesRegex(inventory.InventoryError, "SHA256 mismatch"):
            inventory.read_preservation_gate(self.config)

    def test_wrong_destination_and_state_bindings_block(self):
        for key in ("destination", "state_dir"):
            with self.subTest(key=key):
                self.write_gate()
                self.manifest[key] += "-other"
                self.save_gate()
                with self.assertRaises(inventory.InventoryError):
                    inventory.read_preservation_gate(self.config)

    def test_original_destination_same_identity_blocks(self):
        self.manifest["source_metadata"].update(self.manifest["destination_identity"])
        self.save_gate()
        with self.assertRaisesRegex(inventory.InventoryError, "identity must differ"):
            inventory.read_preservation_gate(self.config)

    def test_gate_never_needs_original_file(self):
        self.assertFalse(Path(self.manifest["source"]).exists())
        with inventory.held_verified_image(self.config) as gate:
            self.assertEqual(gate["size"], self.image.stat().st_size)

    def test_changed_image_identity_blocks(self):
        gate = inventory.read_preservation_gate(self.config)
        gate["destination_identity"]["inode"] += 1
        with inventory.protected_file(self.image) as stream:
            with self.assertRaisesRegex(inventory.InventoryError, "identity differs"):
                inventory.check_image_handle(self.config, gate, stream)

    def test_changed_final_mtime_blocks(self):
        gate = inventory.read_preservation_gate(self.config)
        changed = self.image.stat().st_mtime_ns + 10_000_000
        os.utime(self.image, ns=(changed, changed))
        with inventory.protected_file(self.image) as stream:
            with self.assertRaisesRegex(inventory.InventoryError, "final verified metadata"):
                inventory.check_image_handle(self.config, gate, stream)

    def test_legacy_gate_checks_mtime_and_documents_limitation(self):
        self.write_gate(final=False)
        del self.manifest["state_dir"]
        self.save_gate()
        gate = inventory.read_preservation_gate(self.config)
        self.assertEqual(gate["metadata_gate"], "legacy_v1_completion_time_bound")
        self.assertTrue(gate["legacy_manifest_state_binding"])
        with inventory.held_verified_image(self.config):
            pass
        changed = gate["completion_ns"] + 1_000_000_000
        os.utime(self.image, ns=(changed, changed))
        with self.assertRaisesRegex(inventory.InventoryError, "mtime is newer"):
            with inventory.held_verified_image(self.config):
                pass

    def test_final_marker_disagreement_blocks(self):
        self.manifest["last_verified_sha256"] = "0" * 64
        self.save_gate()
        with self.assertRaisesRegex(inventory.InventoryError, "markers disagree"):
            inventory.read_preservation_gate(self.config)

    def test_future_completion_blocks(self):
        self.status["completed_utc"] = (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
        self.save_gate()
        with self.assertRaisesRegex(inventory.InventoryError, "in the future"):
            inventory.read_preservation_gate(self.config)

    def test_existing_unrelated_output_refused_untouched(self):
        self.config.output_dir.mkdir()
        sentinel = self.config.output_dir / "unrelated.txt"
        sentinel.write_text("keep")
        with self.assertRaises(FileExistsError):
            self.run_inventory()
        self.assertEqual(sentinel.read_text(), "keep")
        self.assertEqual(list(self.config.output_dir.iterdir()), [sentinel])

    def test_resume_reuses_hashed_completed_stages(self):
        self.run_inventory()
        self.commands.clear()
        self.assertEqual(self.run_inventory(replace(self.config, resume=True))["phase"], "complete")
        self.assertEqual(self.commands, [])

    def test_resume_detects_modified_stage_output(self):
        result = self.run_inventory()
        Path(result["stages"]["fls_root"]["stdout"]["path"]).write_bytes(b"tampered")
        with self.assertRaisesRegex(inventory.InventoryError, "output changed"):
            self.run_inventory(replace(self.config, resume=True))

    def test_resume_rejects_redirected_stage_output(self):
        result = self.run_inventory()
        result["stages"]["fls_root"]["stdout"]["path"] = str(self.fake)
        inventory.atomic_json(self.config.output_dir / "status.json", result)
        with self.assertRaisesRegex(inventory.InventoryError, "outside expected stage"):
            self.run_inventory(replace(self.config, resume=True))

    def test_resume_rejects_hardlinked_mutable_catalog_without_writing_target(self):
        self.run_inventory()
        catalog = self.config.output_dir / "bodyfile-catalog.jsonl"
        original = self.root / "must-stay-unchanged.txt"
        original.write_bytes(b"synthetic unrelated file")
        catalog.unlink()
        os.link(original, catalog)
        with self.assertRaisesRegex(inventory.InventoryError, "one link"):
            self.run_inventory(replace(self.config, resume=True))
        self.assertEqual(original.read_bytes(), b"synthetic unrelated file")

    def test_output_alias_parent_rejected_without_touching_image(self):
        real = self.root / "real-parent"
        real.mkdir()
        alias = self.root / "alias-parent"
        try:
            alias.symlink_to(real, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"Symlink creation unavailable: {error}")
        config = replace(self.config, output_dir=alias / "inventory")
        self.image.unlink()
        with self.assertRaisesRegex(inventory.InventoryError, "path aliases"):
            inventory.validate_config(config)

    def test_numbered_image_name_refused_to_avoid_implicit_siblings(self):
        with self.assertRaisesRegex(inventory.InventoryError, "implicit sibling"):
            inventory.validate_config(replace(self.config, image=self.root / "image.001"))

    def corroborated_row(self, name, fls_bytes):
        raw = self.root / "fls-long.bin"
        raw.write_bytes(fls_bytes)
        row = {"full_path": name, "inode_attribute": "42-128-3", "deleted": True,
               "reallocated": False, "deletion_basis": "suffix candidate"}
        with inventory.long_fls_flags(raw, self.root) as flags:
            return inventory.corroborate_name_flags(row, flags)

    def test_literal_deleted_filename_corrected_from_long_fls(self):
        row = self.corroborated_row("/file (deleted)", b"r/r 42-128-3:\tfile (deleted)\t0\n")
        self.assertTrue(row["deletion_corroborated"])
        self.assertFalse(row["deleted"])

    def test_conflicting_long_fls_flags_remain_uncorroborated(self):
        row = self.corroborated_row("/file (deleted)", b"r/r 42-128-3:\tfile\t0\nr/r * 42-128-3:\tfile\t0\n")
        self.assertFalse(row["deletion_corroborated"])

    def test_file_name_combined_suffix_retained(self):
        raw = self.root / "bodyfile.bin"
        raw.write_bytes(b"0|/pipe|name ($FILE_NAME) (deleted-realloc)|42-48-2|r/rrwxrwxrwx|0|0|3|1|2|3|4\n")
        row = list(inventory.bodyfile_rows(raw))[0]
        self.assertEqual(row["full_path"], "/pipe|name ($FILE_NAME) (deleted-realloc)")
        self.assertEqual(row["inode_attribute"], "42-48-2")
        self.assertTrue(row["deleted"])
        self.assertTrue(row["reallocated"])

    def test_failure_preserves_raw_bytes_and_resumes_new_attempt(self):
        self.fake_mode = "failure"
        with self.assertRaisesRegex(inventory.InventoryError, "exited 7"):
            self.run_inventory()
        status = inventory.read_json(self.config.output_dir / "status.json")
        stage = status["stages"]["mmls"]
        self.assertEqual(stage["exit_code"], 7)
        self.assertEqual(stage["state"], "failed")
        self.assertEqual(Path(stage["stdout"]["path"]).read_bytes(), b"partial\x00output\n")
        self.fake_mode = "ok"
        result = self.run_inventory(replace(self.config, resume=True))
        self.assertEqual(result["stages"]["mmls"]["attempt"], 2)
        self.assertTrue(Path(stage["stdout"]["path"]).is_file())

    def test_timeout_kills_child_and_records_failure(self):
        self.fake_mode = "timeout"
        with self.assertRaisesRegex(inventory.InventoryError, "time limit"):
            self.run_inventory(replace(self.config, max_stage_hours=0.00003))
        result = inventory.read_json(self.config.output_dir / "status.json")
        self.assertEqual(result["stages"]["mmls"]["state"], "failed")
        self.assertIsNotNone(result["stages"]["mmls"]["exit_code"])

    def test_bodyfile_parse_counts_all_errors_and_preserves_ids(self):
        path = self.root / "bodyfile.bin"
        path.write_bytes(b'bad\n0|/x|8-128-2|r/rrwxrwxrwx|0|0|3|1|2|3|4\nwrong\n')
        with self.assertRaises(inventory.BodyfileParseError) as caught:
            inventory.validate_output("fls_bodyfile", path)
        self.assertEqual(caught.exception.parse_error_count, 2)
        self.assertEqual([row["source_line"] for row in caught.exception.error_examples], [1, 3])

    def test_bodyfile_non_utf8_is_losslessly_json_escaped(self):
        path = self.root / "bodyfile.bin"
        path.write_bytes(b'0|/x\xff|8-128-2|r/rrwxrwxrwx|0|0|3|1|2|3|4\n')
        row = list(inventory.bodyfile_rows(path))[0]
        restored = json.loads(json.dumps(row, ensure_ascii=True))
        self.assertEqual(restored["full_path"].encode("utf-8", errors="surrogateescape"), b"/x\xff")

    def test_empty_bodyfile_valid_but_bad_headers_fail(self):
        path = self.root / "empty"
        path.write_bytes(b"")
        self.assertEqual(inventory.validate_output("fls_bodyfile", path)["rows"], 0)
        for name in ("mmls", "fsstat", "ils_all", "version_mmls"):
            with self.subTest(name=name), self.assertRaises(inventory.InventoryError):
                inventory.validate_output(name, path)

    def test_unbounded_or_invalid_config_rejected(self):
        for key, value in (("max_wait_hours", float("nan")), ("max_stage_hours", float("inf")),
                           ("poll_seconds", 61), ("sector_size", 0), ("partition_offset", -1)):
            with self.subTest(key=key), self.assertRaises(inventory.InventoryError):
                inventory.validate_config(replace(self.config, **{key: value}))

    @unittest.skipUnless(os.name == "nt", "Windows deny-write sharing contract")
    def test_windows_lock_blocks_writers_and_allows_readers(self):
        with inventory.protected_file(self.image):
            with self.assertRaises(PermissionError):
                with open(self.image, "r+b"):
                    pass
            with open(self.image, "rb") as stream:
                self.assertEqual(stream.read(9), b"SYNTHETIC")


if __name__ == "__main__":
    unittest.main()
