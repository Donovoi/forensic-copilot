"""Synthetic tests only: never target supplied evidence."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from intake_gzip import (CHUNK, IntakeError, Item, Limits, open_locked,
                         process_item, validate_manifest, write_chunk)


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-intake-")
        self.root = Path(self.temp.name)
        self.limits = Limits(max_output_bytes=32 * 1024**2, reserve_bytes=0,
                             progress_seconds=0.01)

    def tearDown(self):
        self.temp.cleanup()

    def item(self, data=b"synthetic content" * 1000, compressed=None, expected=None):
        compressed = gzip.compress(data) if compressed is None else compressed
        source = self.root / "source.gz"
        source.write_bytes(compressed)
        return Item(source, expected or hashlib.sha256(compressed).hexdigest(),
                    self.root / "output.raw")

    def assert_failed(self, item, limits=None):
        with self.assertRaises((IntakeError, OSError, EOFError)):
            process_item(item, limits or self.limits)
        self.assertFalse(item.destination.exists())
        self.assertEqual(json.loads(item.status.read_text())["stage"], "failed")

    def test_valid(self):
        data = b"synthetic content" * 1000
        item = self.item(data)
        before = item.source.read_bytes()
        state = process_item(item, self.limits)
        self.assertEqual(item.destination.read_bytes(), data)
        self.assertEqual(item.source.read_bytes(), before)
        self.assertFalse(item.partial.exists())
        self.assertTrue(state["compressed_hash_complete"])
        self.assertTrue(state["gzip_validated"])
        self.assertTrue(state["source_stat_unchanged"])
        self.assertTrue(state["independent_output_hash_verified"])
        self.assertEqual(state["independent_output_sha256"], hashlib.sha256(data).hexdigest())

    def test_truncated(self):
        self.assert_failed(self.item(compressed=gzip.compress(b"data")[:-4]))

    def test_crc_corrupt(self):
        compressed = bytearray(gzip.compress(b"data"))
        compressed[-8] ^= 1
        self.assert_failed(self.item(compressed=bytes(compressed)))

    def test_wrong_hash(self):
        self.assert_failed(self.item(expected="0" * 64))

    def test_empty_source_rejected(self):
        self.assert_failed(self.item(compressed=b""))

    def test_independent_rehash_detects_wrong_output(self):
        item = self.item()
        def corrupt_write(stream, chunk, sparse):
            return write_chunk(stream, bytes([chunk[0] ^ 1]) + chunk[1:], sparse)
        with patch("intake_gzip.write_chunk", side_effect=corrupt_write):
            self.assert_failed(item)
        state = json.loads(item.status.read_text())
        self.assertIn("Independent output hash or size mismatch", state["error"])

    def test_size_limit(self):
        item = self.item(b"x" * (CHUNK + 1))
        self.assert_failed(item, Limits(max_output_bytes=CHUNK, reserve_bytes=0))
        self.assertLessEqual(item.partial.stat().st_size, CHUNK)

    def test_existing_destination(self):
        item = self.item()
        item.destination.write_bytes(b"preserve")
        with self.assertRaises(IntakeError):
            process_item(item, self.limits)
        self.assertEqual(item.destination.read_bytes(), b"preserve")
        self.assertFalse(item.partial.exists())

    def test_sparse_zeros(self):
        data = b"signature" + bytes(20 * 1024**2)
        item = self.item(data)
        state = process_item(item, self.limits)
        self.assertEqual(item.destination.stat().st_size, len(data))
        self.assertEqual(hashlib.sha256(item.destination.read_bytes()).hexdigest(), hashlib.sha256(data).hexdigest())
        self.assertGreater(state["zero_bytes_skipped"], 18 * 1024**2)
        if os.name == "nt":
            self.assertTrue(item.destination.stat().st_file_attributes & 0x200)
        else:
            self.assertLess(item.destination.stat().st_blocks * 512, len(data))

    def test_concatenated_members_and_zero_padding(self):
        blob = gzip.compress(b"one") + gzip.compress(b"two") + bytes(100)
        item = self.item(compressed=blob)
        state = process_item(item, self.limits)
        self.assertEqual(item.destination.read_bytes(), b"onetwo")
        self.assertEqual(state["compressed_bytes_read"], len(blob))
        self.assertEqual(state["compressed_sha256"], hashlib.sha256(blob).hexdigest())

    def test_invalid_trailing_data(self):
        self.assert_failed(self.item(compressed=gzip.compress(b"one") + b"garbage"))

    def test_existing_partial(self):
        item = self.item()
        item.partial.write_bytes(b"preserve")
        with self.assertRaises(IntakeError):
            process_item(item, self.limits)
        self.assertEqual(item.partial.read_bytes(), b"preserve")

    def test_capacity_failure(self):
        item = self.item()
        with patch("intake_gzip.shutil.disk_usage", return_value=type("Usage", (), {"free": 5})()):
            with self.assertRaises(IntakeError):
                process_item(item, Limits(max_output_bytes=32 * 1024**2, reserve_bytes=10))
        self.assertFalse(item.partial.exists())

    def test_manifest_overlap(self):
        item = self.item()
        with self.assertRaises(IntakeError):
            validate_manifest({"items": [{"source": str(item.source),
                "destination": str(item.source), "expected_sha256": item.expected_sha256}]})

    @unittest.skipUnless(os.name == "nt", "Windows sharing flags")
    def test_windows_source_write_delete_denied(self):
        item = self.item()
        with open_locked(item.source):
            with self.assertRaises(OSError):
                item.source.open("r+b")
            with self.assertRaises(OSError):
                item.source.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
