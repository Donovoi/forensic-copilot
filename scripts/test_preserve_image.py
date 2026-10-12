#!/usr/bin/env python3
"""Synthetic fixtures only. Run: python -m unittest discover -s scripts -p test_preserve_image.py -v"""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import preserve_image as copy


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="preservation-fixture-")
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "synthetic-source.bin"
        # Includes zeroes, non-ASCII bytes, and a tail shorter than a transfer block.
        self.data = bytes(range(256)) * 31 + bytes(9216) + b"tail"
        self.source.write_bytes(self.data)
        self.destination = self.root / "working-copy.bin"
        self.state_dir = self.root / "copy-state"
        self.config = copy.Config(self.source, self.destination, self.state_dir,
                                  chunk_bytes=4096, reserve_bytes=0, progress_seconds=0.001)
        self.original_metadata = copy.source_metadata(self.source.stat())

    def tearDown(self):
        self.temp.cleanup()

    def status(self):
        return json.loads((self.state_dir / "status.json").read_text())

    def interrupt_after_partial_write(self):
        actual = copy.write_all
        calls = 0

        def interrupted(stream, data):
            nonlocal calls
            calls += 1
            if calls == 2:
                actual(stream, data[:137])
                raise OSError("synthetic interrupted write")
            return actual(stream, data)

        with patch.object(copy, "write_all", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "synthetic interrupted"):
                copy.preserve(self.config)
        self.assertEqual(self.destination.read_bytes(), self.data[:4096+137])
        self.assertFalse(self.status()["verified"])

    def test_complete_and_source_unchanged(self):
        result = copy.preserve(self.config)
        expected = hashlib.sha256(self.data).hexdigest()
        self.assertEqual(result["phase"], "complete")
        self.assertTrue(result["verified"])
        self.assertEqual(result["source_stream_sha256"], expected)
        self.assertEqual(result["destination_sha256"], expected)
        self.assertEqual(self.destination.read_bytes(), self.data)
        self.assertEqual(self.source.read_bytes(), self.data)
        self.assertEqual(copy.source_metadata(self.source.stat()), self.original_metadata)
        expected_metadata = copy.source_metadata(self.destination.stat())
        self.assertEqual(result["destination_metadata"], expected_metadata)
        manifest = json.loads((self.state_dir / "manifest.json").read_text())
        self.assertEqual(manifest["final_destination_metadata"], expected_metadata)

    def test_empty_image_has_verified_empty_hash(self):
        self.source.write_bytes(b"")
        result = copy.preserve(self.config)
        self.assertTrue(result["verified"])
        self.assertEqual(result["destination_sha256"], hashlib.sha256(b"").hexdigest())

    def test_dry_run_does_not_create_outputs(self):
        self.config.dry_run = True
        result = copy.preserve(self.config)
        self.assertFalse(result["writes_performed"])
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.state_dir.exists())

    def test_refuses_existing_output(self):
        self.destination.write_bytes(b"unrelated bytes")
        with self.assertRaisesRegex(copy.PreservationError, "absent destination"):
            copy.preserve(self.config)
        self.assertEqual(self.destination.read_bytes(), b"unrelated bytes")

    def test_refuses_source_as_destination(self):
        self.config.destination = self.source
        with self.assertRaisesRegex(copy.PreservationError, "must differ"):
            copy.preserve(self.config)
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_refuses_source_hardlink_destination_on_resume(self):
        copy.preserve(self.config)
        self.destination.unlink()
        try:
            os.link(self.source, self.destination)
        except OSError as error:
            self.skipTest(str(error))
        self.config.resume = True
        with self.assertRaisesRegex(copy.PreservationError, "same file"):
            copy.preserve(self.config)
        self.assertFalse(self.status()["verified"])

    def test_capacity_guard_leaves_no_outputs(self):
        self.config.reserve_bytes = 100
        with patch.object(copy.shutil, "disk_usage", return_value=type("Usage", (), {"free": 99})()):
            with self.assertRaisesRegex(copy.PreservationError, "Insufficient free"):
                copy.preserve(self.config)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.state_dir.exists())

    def test_resume_verifies_uncheckpointed_partial_block(self):
        self.interrupt_after_partial_write()
        self.config.resume = True
        result = copy.preserve(self.config)
        self.assertTrue(result["verified"])
        self.assertEqual(result["prefix_verified_bytes"], 4096+137)
        self.assertEqual(self.destination.read_bytes(), self.data)
        self.assertEqual(result["source_stream_sha256"], hashlib.sha256(self.data).hexdigest())
        expected_metadata = copy.source_metadata(self.destination.stat())
        self.assertEqual(result["destination_metadata"], expected_metadata)
        manifest = json.loads((self.state_dir / "manifest.json").read_text())
        self.assertEqual(manifest["final_destination_metadata"], expected_metadata)

    def test_completed_copy_resume_refreshes_destination_metadata(self):
        copy.preserve(self.config)
        self.config.resume = True
        result = copy.preserve(self.config)
        self.assertTrue(result["verified"])
        self.assertEqual(result["prefix_verified_bytes"], len(self.data))
        self.assertEqual(result["destination_metadata"], copy.source_metadata(self.destination.stat()))

    def test_legacy_manifest_can_resume(self):
        self.interrupt_after_partial_write()
        manifest_path = self.state_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest.pop("state_dir")
        manifest_path.write_text(json.dumps(manifest))
        self.config.resume = True
        self.assertTrue(copy.preserve(self.config)["verified"])

    def test_completed_resume_changed_source_invalidates_stale_success(self):
        copy.preserve(self.config)
        with open(self.source, "ab") as stream:
            stream.write(b"changed")
        self.config.resume = True
        with self.assertRaisesRegex(copy.PreservationError, "metadata mismatch"):
            copy.preserve(self.config)
        self.assertEqual(self.status()["phase"], "failed")
        self.assertFalse(self.status()["verified"])
        self.assertNotIn("completed_utc", self.status())
        events = [json.loads(line) for line in (self.state_dir / "events.jsonl").read_text().splitlines()]
        self.assertEqual(events[-1]["event"], "failed")

    def test_completed_resume_missing_source_invalidates_stale_success(self):
        copy.preserve(self.config)
        self.source.unlink()
        self.config.resume = True
        with self.assertRaises(FileNotFoundError):
            copy.preserve(self.config)
        self.assertEqual(self.status()["phase"], "failed")
        self.assertFalse(self.status()["verified"])

    def test_completed_resume_wrong_source_argument_invalidates_this_copy(self):
        copy.preserve(self.config)
        alternate = self.root / "alternate-synthetic-source.bin"
        alternate.write_bytes(self.data)
        self.config.source = alternate
        self.config.resume = True
        with self.assertRaisesRegex(copy.PreservationError, "metadata mismatch"):
            copy.preserve(self.config)
        self.assertFalse(self.status()["verified"])

    def test_completed_resume_manifest_schema_failure_invalidates_success(self):
        copy.preserve(self.config)
        manifest_path = self.state_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["schema_version"] = -1
        manifest_path.write_text(json.dumps(manifest))
        self.config.resume = True
        with self.assertRaisesRegex(copy.PreservationError, "metadata mismatch"):
            copy.preserve(self.config)
        self.assertFalse(self.status()["verified"])

    def test_completed_resume_capacity_failure_invalidates_success(self):
        copy.preserve(self.config)
        self.config.resume = True
        self.config.reserve_bytes = 1
        with patch.object(copy.shutil, "disk_usage", return_value=type("Usage", (), {"free": 0})()):
            with self.assertRaisesRegex(copy.PreservationError, "Insufficient free"):
                copy.preserve(self.config)
        self.assertFalse(self.status()["verified"])

    def test_wrong_destination_does_not_modify_unrelated_state(self):
        copy.preserve(self.config)
        before = {path.name: path.read_bytes() for path in self.state_dir.iterdir()}
        self.config.resume = True
        self.config.destination = self.root / "unrelated-destination.bin"
        with self.assertRaisesRegex(copy.PreservationError, "state/destination pair"):
            copy.preserve(self.config)
        after = {path.name: path.read_bytes() for path in self.state_dir.iterdir()}
        self.assertEqual(before, after)
        self.assertFalse(self.config.destination.exists())

    def test_resume_lock_failure_does_not_overwrite_active_run_status(self):
        copy.preserve(self.config)
        before = (self.state_dir / "status.json").read_bytes()
        self.config.resume = True
        with copy.state_lock(self.state_dir / "run.lock"):
            with self.assertRaises(OSError):
                copy.preserve(self.config)
        self.assertEqual((self.state_dir / "status.json").read_bytes(), before)

    def test_dry_run_resume_does_not_invalidate_previous_success(self):
        copy.preserve(self.config)
        before = {path.name: path.read_bytes() for path in self.state_dir.iterdir()}
        self.config.resume = True
        self.config.dry_run = True
        result = copy.preserve(self.config)
        self.assertEqual(result["phase"], "dry_run")
        after = {path.name: path.read_bytes() for path in self.state_dir.iterdir()}
        self.assertEqual(before, after)

    def test_metadata_gate_detects_destination_changed_after_completion(self):
        result = copy.preserve(self.config)
        original_metadata = result["destination_metadata"]
        with open(self.destination, "ab") as stream:
            stream.write(b"changed")
        self.assertNotEqual(original_metadata, copy.source_metadata(self.destination.stat()))

    def test_resume_refuses_corrupt_prefix_without_appending(self):
        self.interrupt_after_partial_write()
        corrupted = b"x" + self.destination.read_bytes()[1:]
        with open(self.destination, "r+b") as stream:
            stream.write(corrupted)
        self.config.resume = True
        with self.assertRaisesRegex(copy.PreservationError, "prefix mismatch"):
            copy.preserve(self.config)
        self.assertEqual(self.destination.read_bytes(), corrupted)
        self.assertFalse(self.status()["verified"])

    def test_resume_refuses_changed_source(self):
        self.interrupt_after_partial_write()
        old_dest = self.destination.read_bytes()
        with open(self.source, "ab") as stream:
            stream.write(b"changed")
        self.config.resume = True
        with self.assertRaisesRegex(copy.PreservationError, "metadata mismatch"):
            copy.preserve(self.config)
        self.assertEqual(self.destination.read_bytes(), old_dest)

    def test_destination_corruption_fails_independent_hash(self):
        actual = copy.verify_destination

        def corrupt_then_verify(destination, length, config, recorder):
            destination.seek(0)
            destination.write(b"x")
            destination.flush()
            os.fsync(destination.fileno())
            return actual(destination, length, config, recorder)

        with patch.object(copy, "verify_destination", side_effect=corrupt_then_verify):
            with self.assertRaisesRegex(copy.PreservationError, "SHA256 differs"):
                copy.preserve(self.config)
        self.assertFalse(self.status()["verified"])
        self.assertEqual(self.source.read_bytes(), self.data)

    def test_destination_short_write_is_completed(self):
        class ShortWriter:
            def __init__(self):
                self.data = bytearray()

            def write(self, data):
                self.data.extend(data[:3])
                return min(3, len(data))

        writer = ShortWriter()
        copy.write_all(writer, b"0123456789")
        self.assertEqual(writer.data, b"0123456789")

    @unittest.skipUnless(os.name == "nt", "Windows sharing guarantee")
    def test_windows_source_denies_writers_and_delete(self):
        with copy.open_file(self.source, "rb"):
            with self.assertRaises(OSError):
                with open(self.source, "r+b"):
                    pass
            with self.assertRaises(OSError):
                self.source.unlink()

    @unittest.skipUnless(os.name == "nt", "Windows sharing guarantee")
    def test_windows_existing_writer_prevents_source_open(self):
        with open(self.source, "r+b"):
            with self.assertRaises(OSError):
                with copy.open_file(self.source, "rb"):
                    pass

    def test_state_lock_denies_second_writer(self):
        self.state_dir.mkdir()
        with copy.state_lock(self.state_dir / "run.lock"):
            with self.assertRaises(OSError):
                with copy.state_lock(self.state_dir / "run.lock"):
                    pass


if __name__ == "__main__":
    unittest.main()
