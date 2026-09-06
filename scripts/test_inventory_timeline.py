import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
GATE = HERE / "collect_image_inventory.py"
GATE_SHA = "5b8089929c4586c68403b5d0c37b6b88d6b632b1097e1e7a7f68d1d99e348a5e"
spec = importlib.util.spec_from_file_location("inventory_timeline", HERE / "inventory_timeline.py")
timeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timeline)


def write_json(path, value):
    path.write_bytes(timeline.encode(value))


def base_row(number, **overrides):
    value = {"schema_version": 1, "source_line": number, "full_path": f"/root/file{number}.txt",
             "inode_attribute": f"{100 + number}-128-1", "mode": "r/rr--r--r--", "uid": 1, "gid": 2,
             "size": 10, "raw_line_sha256": hashlib.sha256(str(number).encode()).hexdigest(),
             "atime_epoch": 1, "mtime_epoch": 2, "ctime_epoch": 3, "crtime_epoch": 4,
             "deleted": False, "reallocated": False, "deleted_suffix_candidate": False,
             "deletion_corroborated": True, "deletion_basis": "synthetic exact flags"}
    value.update(overrides)
    return value


class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.inventory = self.root / "inventory"
        self.inventory.mkdir()
        self.output = self.root / "output"
        self.state = self.root / "state"
        self.rows = [base_row(1), base_row(2)]
        self.bind()

    def tearDown(self):
        self.temp.cleanup()

    def bind(self):
        catalog = self.inventory / "bodyfile-catalog.jsonl"
        catalog.write_bytes(b"".join(map(timeline.encode, self.rows)))
        with catalog.open("rb") as stream:
            record = {"path": str(catalog), **timeline.digest(stream)}
        identity = {"image": str(self.root / "DO-NOT-OPEN.raw"), "size": 100000,
                    "sha256": "a" * 64}
        config = {"schema_version": 1, "image": identity["image"], "output_dir": str(self.inventory),
                  "preservation_state": str(self.root / "DO-NOT-READ-preservation"),
                  "preservation_exit_code": str(self.root / "DO-NOT-READ-exit.txt"),
                  "tsk_bin": str(self.root / "DO-NOT-RUN-tsk"), "script_sha256": GATE_SHA,
                  "sector_size": 512, "partition_offset_sectors": 63, "catalog_bodyfile": True}
        stages = {name: {"state": "complete", "exit_code": 0} for name in timeline.STAGES}
        stages["fls_bodyfile"].update(validation={"rows": len(self.rows), "parse_errors": 0},
                                     stdout={"path": str(self.inventory / "fls_bodyfile/001.stdout.bin"), "sha256": "b" * 64})
        self.manifest = {"configuration": config, "image_identity": identity, "limitations": ["synthetic"]}
        self.status = {"schema_version": 1, "phase": "complete", "current_stage": None,
                       "completed_utc": "2026-01-01T00:00:00Z", "image_identity": copy.deepcopy(identity),
                       "bodyfile_catalog": record, "stages": stages}
        self.save_sidecars()

    def save_sidecars(self):
        write_json(self.inventory / "manifest.json", self.manifest)
        write_json(self.inventory / "status.json", self.status)

    def args(self, *extra):
        return timeline.parse_args(["--inventory-dir", str(self.inventory), "--inventory-module", str(GATE),
                                    "--inventory-sha256", GATE_SHA, "--output-dir", str(self.output),
                                    "--state-dir", str(self.state), "--max-output-bytes", str(32 * 1024**2),
                                    "--reserve-bytes", "0", "--reference-utc", "2026-01-01T00:00:00Z", *extra])

    def read_lines(self, filename):
        return [json.loads(raw) for raw in (self.output / filename).read_bytes().splitlines()]

    def test_happy_path_four_events_each_and_hashes(self):
        before = {p.name: p.read_bytes() for p in self.inventory.iterdir()}
        self.assertEqual(timeline.run(self.args()), 0)
        events = self.read_lines("filesystem-timestamps.jsonl")
        self.assertEqual(len(events), 8)
        self.assertEqual([e["original_epoch"] for e in events], [1, 1, 2, 2, 3, 3, 4, 4])
        status = json.loads((self.state / "status.json").read_bytes())
        self.assertEqual(status["phase"], "complete")
        self.assertEqual(status["summary"]["unique_data_stream_ids"], 2)
        manifest = json.loads((self.state / "output-manifest.json").read_bytes())
        for artifact in manifest["artifacts"]:
            self.assertEqual(hashlib.sha256(Path(artifact["path"]).read_bytes()).hexdigest(), artifact["sha256"])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.inventory.iterdir()})

    def test_never_reads_or_stats_recorded_image(self):
        original_open, original_stat = Path.open, Path.stat
        def guarded_open(path, *a, **kw):
            self.assertNotIn("DO-NOT-", str(path))
            return original_open(path, *a, **kw)
        def guarded_stat(path, *a, **kw):
            self.assertNotIn("DO-NOT-", str(path))
            return original_stat(path, *a, **kw)
        with patch.object(Path, "open", guarded_open), patch.object(Path, "stat", guarded_stat):
            self.assertEqual(timeline.run(self.args()), 0)

    def test_names_surrogates_aliases_and_size_conflicts_are_lossless(self):
        name = '/root/literal|percent%41-quote"-comma,-invalid\udcff.txt:stream (deleted)'
        self.rows = [base_row(1, full_path=name, size=10, deleted=True),
                     base_row(2, full_path=name, inode_attribute="101-128-1", size=20, deleted=True),
                     base_row(3, full_path=name, inode_attribute="102-128-1", size=30)]
        self.bind()
        self.assertEqual(timeline.run(self.args()), 0)
        refs = self.read_lines("catalog-rows.jsonl")
        self.assertEqual([x["catalog_row"]["full_path"] for x in refs], [name] * 3)
        self.assertEqual(len(self.read_lines("filesystem-timestamps.jsonl")), 12)
        streams = {s["inode_attribute"]: s for s in self.read_lines("streams.jsonl")}
        self.assertEqual(streams["101-128-1"]["alias_rows"], 2)
        self.assertTrue(streams["101-128-1"]["size_conflict"])
        self.assertEqual(streams["102-128-1"]["minimum_observed_size"], 30)
        db = sqlite3.connect(self.state / "index.sqlite")
        try:
            for row_id, raw, path_json in db.execute("SELECT row_id,raw,path_json FROM rows ORDER BY row_id"):
                self.assertEqual(raw, timeline.encode(self.rows[row_id - 1]))
                self.assertEqual(json.loads(path_json), name)
        finally:
            db.close()

    def test_zero_negative_huge_future_and_complete_yearspan(self):
        self.rows = [base_row(1, atime_epoch=0, mtime_epoch=-1, ctime_epoch=10**90, crtime_epoch=-10**90),
                     base_row(2, atime_epoch=1780000000, mtime_epoch=253402300799, ctime_epoch=-62135596800, crtime_epoch=0)]
        self.bind()
        self.assertEqual(timeline.run(self.args()), 0)
        events = self.read_lines("filesystem-timestamps.jsonl")
        self.assertEqual(len(events), 8)
        self.assertEqual([e["original_epoch"] for e in events], sorted([row[field] for row in self.rows for field in timeline.FIELDS]))
        zero = [e for e in events if e["original_epoch"] == 0]
        self.assertTrue(all(e["utc"] is None and e["timestamp_status"] == "zero_unknown" for e in zero))
        huge = [e for e in events if abs(e["original_epoch"]) == 10**90]
        self.assertTrue(all(e["timestamp_status"] == "outside_datetime_range" for e in huge))
        self.assertEqual(next(e for e in events if e["original_epoch"] == -1)["utc"], "1969-12-31T23:59:59Z")
        status = json.loads((self.state / "status.json").read_bytes())
        self.assertEqual(status["summary"]["earliest_valid_year"], 1)
        self.assertEqual(status["summary"]["latest_valid_year"], 9999)
        self.assertEqual(sum(e["future_after_reference"] for e in events), 3)

    def test_invalid_epoch_type_retained_but_incomplete(self):
        self.rows = [base_row(1, atime_epoch="unparsed", mtime_epoch=True, ctime_epoch=None, crtime_epoch=2)]
        self.bind()
        self.assertEqual(timeline.run(self.args()), 2)
        events = self.read_lines("filesystem-timestamps.jsonl")
        self.assertEqual(len(events), 4)
        self.assertEqual(sum(e["timestamp_status"] == "invalid_type" for e in events), 3)
        self.assertEqual(json.loads((self.state / "status.json").read_bytes())["phase"], "incomplete")

    def test_uncorroborated_deletion_never_becomes_deleted_stream_claim(self):
        self.rows = [base_row(1, full_path="/literal (deleted)", deleted=True, deletion_corroborated=False)]
        self.bind()
        self.assertEqual(timeline.run(self.args()), 0)
        self.assertEqual(self.read_lines("streams.jsonl")[0]["name_state_mask"], 8)

    def test_source_line_gaps_retained(self):
        self.rows = [base_row(2), base_row(5)]
        self.bind()
        self.assertEqual(timeline.run(self.args()), 0)
        self.assertEqual([row["reference"]["bodyfile_source_line"] for row in self.read_lines("catalog-rows.jsonl")], [2, 5])

    def test_markdown_label_cap_keeps_full_machine_records(self):
        root = "long-name-" + "x" * 3000
        extension = "extension" + "y" * 3000
        path = "/" + root + "/file." + extension
        self.rows = [base_row(1, full_path=path)]
        self.bind()
        self.assertEqual(timeline.run(self.args()), 0)
        markdown = (self.output / "summary.md").read_text(encoding="utf-8")
        self.assertIn("display truncated; full name in groups.jsonl and catalog records", markdown)
        self.assertNotIn(root, markdown)
        self.assertLess(len(markdown), 20000)
        for label in re.findall(r"^- `([^`]+)`:", markdown, re.MULTILINE):
            self.assertLessEqual(len(label), 240)
        self.assertEqual(self.read_lines("catalog-rows.jsonl")[0]["catalog_row"]["full_path"], path)
        groups = self.read_lines("groups.jsonl")
        self.assertTrue(any(row["kind"] == "data_root_path_rows" and row["name"] == root for row in groups))
        self.assertTrue(any(row["kind"] == "data_extension_candidate_rows" and row["name"] == extension for row in groups))

    def test_indexed_output_queries_need_no_temp_sort(self):
        db = timeline.open_database(self.root / "query-plans.sqlite")
        try:
            for query in ("SELECT * FROM rows ORDER BY row_id", "SELECT * FROM streams ORDER BY stream_id",
                          "SELECT * FROM groups ORDER BY kind,name_json",
                          "SELECT * FROM events ORDER BY bucket,digits,sort_text,row_id,field_order"):
                plan = db.execute("EXPLAIN QUERY PLAN " + query).fetchall()
                self.assertFalse(any("TEMP B-TREE" in row[-1].upper() for row in plan), plan)
        finally:
            db.close()

    def test_failed_upstream_and_mismatched_sidecars_refused(self):
        for change in ("phase", "identity", "producer", "hash", "stage", "rows", "output", "bodypath"):
            with self.subTest(change=change):
                self.bind()
                if change == "phase": self.status["phase"] = "indexing"
                elif change == "identity": self.status["image_identity"]["size"] += 1
                elif change == "producer": self.manifest["configuration"]["script_sha256"] = "0" * 64
                elif change == "hash": self.status["bodyfile_catalog"]["sha256"] = "0" * 64
                elif change == "stage": self.status["stages"]["ils_all"]["exit_code"] = 1
                elif change == "rows": self.status["bodyfile_catalog"]["lines"] = 4
                elif change == "output": self.manifest["configuration"]["output_dir"] = str(self.root / "unrelated")
                elif change == "bodypath": self.status["stages"]["fls_bodyfile"]["stdout"]["path"] = self.manifest["configuration"]["image"]
                self.save_sidecars()
                with self.assertRaises(timeline.TimelineError): timeline.run(self.args())
                self.assertFalse(self.output.exists())

    def test_wrong_module_hash_and_existing_outputs_refused(self):
        args = self.args()
        args.inventory_sha256 = "0" * 64
        with self.assertRaises(timeline.TimelineError): timeline.run(args)
        self.output.mkdir()
        marker = self.output / "unrelated.txt"
        marker.write_text("untouched")
        with self.assertRaises(timeline.TimelineError): timeline.run(self.args())
        self.assertEqual(marker.read_text(), "untouched")

    def test_overlapping_output_refused(self):
        args = self.args()
        args.output_dir = self.inventory / "nested"
        with self.assertRaises(timeline.TimelineError): timeline.run(args)

    def test_hardlinked_catalog_refused(self):
        alias = self.root / "catalog-alias"
        try:
            os.link(self.inventory / "bodyfile-catalog.jsonl", alias)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaises(timeline.TimelineError): timeline.run(self.args())

    def test_symlink_inventory_refused(self):
        alias = self.root / "inventory-alias"
        try:
            alias.symlink_to(self.inventory, target_is_directory=True)
        except OSError as exc:
            self.skipTest(str(exc))
        args = self.args()
        args.inventory_dir = alias
        with self.assertRaises(Exception): timeline.run(args)

    def test_output_budget_failure_has_honest_state(self):
        self.rows = [base_row(i, full_path="/" + "x" * 30000 + f"{i}.txt") for i in range(1, 22)]
        self.bind()
        args = self.args("--max-output-bytes", str(8 * 1024**2))
        with self.assertRaises((timeline.TimelineError, sqlite3.DatabaseError)):
            timeline.run(args)
        self.assertEqual(json.loads((self.state / "status.json").read_bytes())["phase"], "failed")
        self.assertLessEqual(sum(p.stat().st_size for root in (self.output, self.state) for p in root.iterdir()), args.max_output_bytes)

    def test_reserve_failure_never_claims_complete(self):
        args = self.args()
        args.reserve_bytes = 10**30
        with self.assertRaises(timeline.TimelineError): timeline.run(args)
        self.assertFalse((self.state / "output-manifest.json").exists())

    def test_duplicate_json_key_refused(self):
        path = self.inventory / "manifest.json"
        path.write_bytes(b'{"configuration":{},"configuration":{}}')
        with self.assertRaises(timeline.TimelineError): timeline.run(self.args())

    def test_timestamp_sort_key_is_arbitrary_integer_numeric_order(self):
        values = [-10**100, -100, -11, -10, -9, -1, 0, 1, 9, 10, 11, 100, 10**100]
        keyed = [(timeline.timestamp(v, 0)[:3], v) for v in reversed(values)]
        self.assertEqual([v for _, v in sorted(keyed)], values)


if __name__ == "__main__":
    unittest.main()
