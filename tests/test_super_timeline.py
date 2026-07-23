from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "build_super_timeline.py"
)
SPEC = importlib.util.spec_from_file_location("build_super_timeline", SCRIPT_PATH)
assert SPEC and SPEC.loader
build_super_timeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_super_timeline)


class SuperTimelineTests(unittest.TestCase):
    def test_normalize_datetime_preserves_submicrosecond_sort_precision(self) -> None:
        earlier_ns, earlier = build_super_timeline.normalize_datetime(
            "2026-01-02T03:04:05.123456700+00:00"
        )
        later_ns, later = build_super_timeline.normalize_datetime(
            "2026-01-02T04:04:05.123456800+01:00"
        )
        self.assertLess(earlier_ns, later_ns)
        self.assertEqual(earlier, "2026-01-02T03:04:05.1234567+00:00")
        self.assertEqual(later, "2026-01-02T03:04:05.1234568+00:00")

    def test_semantically_invalid_iso_datetime_is_a_bounded_rejection(self) -> None:
        for value in (
            "2026-13-02T03:04:05+00:00",
            "2026-01-02T03:04:05+99:99",
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(build_super_timeline.TimelineError),
            ):
                build_super_timeline.normalize_datetime(value)

    def test_external_sort_combines_exports_without_merging_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = root / "inputs"
            output = root / "output"
            inputs.mkdir()
            plaso = inputs / "disk.jsonl"
            plaso.write_text(
                json.dumps(
                    {
                        "date_time": {
                            "__class_name__": "PosixTime",
                            "__type__": "DateTimeValues",
                        },
                        "timestamp": 1767323046000000,
                        "timestamp_desc": "Modified",
                        "message": "later disk event",
                        "parser": "filestat",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            volatility = inputs / "memory.jsonl"
            volatility.write_text(
                json.dumps(
                    {
                        "datetime": "2026-01-02T04:04:05+01:00",
                        "timestamp_desc": "Created",
                        "message": "earlier memory event",
                        "plugin": "windows.timeliner",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = inputs / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "title": "Fixture timeline",
                        "inputs": [
                            {
                                "path": str(plaso),
                                "format": "plaso-jsonl",
                                "evidence_label": "HOST-A-DISK",
                                "source_label": "disk",
                            },
                            {
                                "path": str(volatility),
                                "format": "volatility-timeliner-jsonl",
                                "evidence_label": "HOST-A-MEMORY",
                                "source_label": "memory",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            args = Namespace(
                manifest=str(manifest),
                allow_read_root=[str(inputs)],
                output_dir=str(output),
                chunk_events=1,
                max_input_line_bytes=1024 * 1024,
                max_recorded_errors=10,
                summary_limit=2,
                summary_regex=[],
                force=False,
            )

            self.assertEqual(build_super_timeline.build_timeline(args), 0)
            events = [
                json.loads(line)
                for line in (output / "super-timeline.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(
                [event["message"] for event in events],
                ["earlier memory event", "later disk event"],
            )
            self.assertEqual(events[0]["forensic_evidence"], "HOST-A-MEMORY")
            self.assertIn("datetime", events[0])
            self.assertIn("timestamp_desc", events[0])
            provenance = json.loads(
                (output / "super-timeline.provenance.json").read_text(encoding="utf-8")
            )
            self.assertEqual(provenance["event_count"], 2)
            self.assertEqual(provenance["summary"]["matching_event_count"], 2)
            self.assertFalse(provenance["summary"]["truncated"])
            self.assertFalse(provenance["normalization"]["plaso_storages_merged"])
            self.assertEqual(len(provenance["outputs"]), 4)
            self.assertEqual(len(list(output.glob("*.partial"))), 0)

    def test_rejected_event_is_recorded_and_returns_limited_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = root / "inputs"
            output = root / "output"
            inputs.mkdir()
            source = inputs / "events.jsonl"
            source.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "date_time": {
                                    "__class_name__": "PosixTime",
                                    "__type__": "DateTimeValues",
                                },
                                "timestamp": 1767323045000000,
                                "timestamp_desc": "Created",
                                "message": "valid",
                            }
                        ),
                        json.dumps(
                            {
                                "date_time": {
                                    "__class_name__": "NotSet",
                                    "__type__": "DateTimeValues",
                                    "string": "Not set",
                                },
                                "timestamp": 0,
                                "timestamp_desc": "Not a time",
                                "message": "invalid timestamp",
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = inputs / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "inputs": [
                            {
                                "path": str(source),
                                "format": "plaso-jsonl",
                                "evidence_label": "HOST-A",
                                "source_label": "disk",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            args = Namespace(
                manifest=str(manifest),
                allow_read_root=[str(inputs)],
                output_dir=str(output),
                chunk_events=10,
                max_input_line_bytes=1024 * 1024,
                max_recorded_errors=10,
                summary_limit=10,
                summary_regex=[],
                force=False,
            )

            self.assertEqual(build_super_timeline.build_timeline(args), 2)
            provenance = json.loads(
                (output / "super-timeline.provenance.json").read_text(encoding="utf-8")
            )
            self.assertEqual(provenance["rejected_event_count"], 1)
            self.assertIn(
                "no usable timestamp", provenance["recorded_errors"][0]["error"]
            )

    def test_real_plaso_webkit_epoch_timestamp_is_normalized(self) -> None:
        row = {
            "date_time": {
                "__class_name__": "WebKitTime",
                "__type__": "DateTimeValues",
                "timestamp": 0,
            },
            "timestamp": -11644473600000000,
            "timestamp_desc": "Expiration Time",
            "message": "cookie",
        }
        input_record = {
            "format": "plaso-jsonl",
            "evidence_label": "HOST-A-DISK",
            "source_label": "disk",
        }
        _, event = build_super_timeline.normalize_event(row, input_record, 0, 1)
        self.assertEqual(event["datetime"], "1601-01-01T00:00:00+00:00")
        self.assertEqual(event["timestamp"], -11644473600000000)


if __name__ == "__main__":
    unittest.main()
