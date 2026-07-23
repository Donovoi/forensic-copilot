from __future__ import annotations

import gzip
import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from hashlib import sha256
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "paired_vm_case.py"
SPEC = importlib.util.spec_from_file_location("paired_vm_case", SCRIPT_PATH)
assert SPEC and SPEC.loader
paired_vm_case = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(paired_vm_case)


class PairedVmCaseTests(unittest.TestCase):
    def make_evidence(self, root: Path, name: str = "HOST-A") -> tuple[Path, Path]:
        source = root / name
        source.mkdir(parents=True)
        disk = source / "host_backup.img.gz"
        with gzip.open(disk, "wb") as stream:
            stream.write(b"disk-content" * 1024)
        memory = source / "host.dump"
        memory.write_bytes(b"memory-content" * 1024)
        manifest = source / "hashes.txt"
        manifest.write_text(
            f"{disk.name}\nsha256: {sha256(disk.read_bytes()).hexdigest()}\n\n"
            f"{memory.name}\n{sha256(memory.read_bytes()).hexdigest()}\n",
            encoding="utf-8",
        )
        return disk, memory

    def initialize_fixture(self, root: Path) -> tuple[Path, Path, dict]:
        evidence = root / "evidence"
        case = root / "case"
        self.make_evidence(evidence)
        paired_vm_case.initialize_case(
            Namespace(
                evidence_root=str(evidence),
                case_root=str(case),
                case_id="CASE-001",
                force=False,
            )
        )
        state = json.loads((case / "case.json").read_text(encoding="utf-8"))
        integrity_sources = []
        for source in state["sources"]:
            manifests = []
            for record in source["hash_manifests"]:
                path = evidence / record["relative_path"]
                manifests.append(
                    {
                        "relative_path": record["relative_path"],
                        "sha256": sha256(path.read_bytes()).hexdigest(),
                    }
                )
            items = []
            for role in ("disk_gzip", "memory_dump"):
                record = source[role]
                path = evidence / record["relative_path"]
                items.append(
                    {
                        "role": role,
                        "relative_path": record["relative_path"],
                        "sha256": sha256(path.read_bytes()).hexdigest(),
                    }
                )
            integrity_sources.append(
                {
                    "source_name": source["source_name"],
                    "manifests": manifests,
                    "items": items,
                }
            )
        (case / "integrity.json").write_text(
            json.dumps({"status": "verified", "sources": integrity_sources}),
            encoding="utf-8",
        )
        for source in state["sources"]:
            working_root = case / "sources" / source["case_key"] / "disk" / "working"
            working_root.mkdir(parents=True, exist_ok=True)
            source_gzip = evidence / source["disk_gzip"]["relative_path"]
            working_path = working_root / "disk.raw"
            with gzip.open(source_gzip, "rb") as compressed:
                working_path.write_bytes(compressed.read())
            (working_root / "disk.raw.json").write_text(
                json.dumps(
                    {
                        "working_path": str(working_path.resolve()),
                        "source_relative_path": source["disk_gzip"]["relative_path"],
                        "size_bytes": working_path.stat().st_size,
                        "sha256": sha256(working_path.read_bytes()).hexdigest(),
                        "atomic_completion": True,
                    }
                ),
                encoding="utf-8",
            )
        return evidence, case, state

    def write_complete_report(
        self,
        evidence: Path,
        case: Path,
        state: dict,
        omit_evidence_id: str | None = None,
    ) -> Path:
        report = Path(state["report"]["working_path"])
        links = []
        for item in state["evidence_items"]:
            if item["evidence_item_id"] == omit_evidence_id:
                continue
            links.append(
                "- "
                + paired_vm_case.markdown_evidence_link(
                    report,
                    evidence / item["relative_path"],
                    f"{item['source_name']} / {item['name']}",
                )
            )
        report.write_text(
            "# CASE-001 forensic examination\n\n"
            "## Executive summary\n\nThe evidence supports the stated findings with documented limits.\n\n"
            "## Findings\n\nAll inventoried evidence items were examined.\n\n"
            "## Conclusions and confidence\n\nThe conclusion has moderate confidence.\n\n"
            "## Scope and boundaries\n\nOriginal evidence remained read-only.\n\n"
            "## Evidence inventory and links\n\n"
            + "\n".join(links)
            + "\n\n## Evidence handling and verification\n\nIntegrity records were reviewed.\n\n"
            "## Examination environment and tools\n\nTool versions are retained in case outputs.\n\n"
            "## File carving\n\nSignature carving was completed and validated.\n\n"
            "## Repair attempts\n\nDamage was assessed and repair-copy results were retained.\n\n"
            "## User and owner attribution\n\nLocal users and attribution limits were documented.\n\n"
            "## Timeline and correlations\n\nDisk and memory results were correlated.\n\n"
            "## Limitations and unresolved questions\n\nNo unresolved examination task remains.\n",
            encoding="utf-8",
        )
        return report

    def complete_all_work(self, case: Path, state: dict) -> Path:
        artifact = case / "artifacts" / "completed.txt"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("fixture result\n", encoding="utf-8")
        for work_item in state["work_items"]:
            if work_item["lane"] == "damage_repair_assessment":
                status = "not_applicable"
                artifacts = None
                note = "No damage indicator was present in this fixture."
            elif work_item["lane"] in {
                "allocated_file_examination",
                "deleted_unallocated_assessment",
                "signature_carving",
            }:
                result_root = case / "artifacts" / "trees" / work_item["work_item_id"]
                result_root.mkdir(parents=True)
                result_file = result_root / "result.txt"
                result_file.write_text("manifested fixture result\n", encoding="utf-8")
                digest = paired_vm_case.file_sha256(result_file)
                manifest = case / "artifacts" / f"{work_item['work_item_id']}.sha256"
                manifest.write_text(
                    f"{digest}  {result_file.stat().st_size}  result.txt\n",
                    encoding="utf-8",
                )
                metadata = case / "artifacts" / f"{work_item['work_item_id']}.json"
                root_field = (
                    "output_path"
                    if work_item["lane"] == "signature_carving"
                    else "recovered_path"
                )
                metadata.write_text(
                    json.dumps({root_field: str(result_root.resolve())}),
                    encoding="utf-8",
                )
                status = "completed"
                artifacts = [str(metadata), str(manifest)]
                note = None
            else:
                status = "completed"
                artifacts = [str(artifact)]
                note = None
            paired_vm_case.record_work_result(
                Namespace(
                    case_root=str(case),
                    work_item=work_item["work_item_id"],
                    status=status,
                    artifact=artifacts,
                    note=note,
                )
            )
        return artifact

    def test_overlapping_roots_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "evidence"
            evidence.mkdir()
            with self.assertRaises(paired_vm_case.CaseError):
                paired_vm_case.validate_boundaries(evidence, evidence / "analysis")

    def test_discovery_and_manifest_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "evidence"
            disk, memory = self.make_evidence(evidence)
            pairs = paired_vm_case.discover_pairs(evidence)
            self.assertEqual(len(pairs), 1)
            self.assertEqual(pairs[0]["source_name"], "HOST-A")
            parsed = paired_vm_case.parse_hash_manifest(
                evidence / "HOST-A" / "hashes.txt"
            )
            self.assertEqual(parsed[disk.name], sha256(disk.read_bytes()).hexdigest())
            self.assertEqual(
                parsed[memory.name], sha256(memory.read_bytes()).hexdigest()
            )
            gzip_result = paired_vm_case.hash_and_test_gzip_stream(disk)
            self.assertTrue(gzip_result["ok"])
            self.assertEqual(
                gzip_result["sha256"], sha256(disk.read_bytes()).hexdigest()
            )

    def test_init_verify_and_prepare(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            case = root / "case"
            self.make_evidence(evidence)
            init_args = Namespace(
                evidence_root=str(evidence),
                case_root=str(case),
                case_id="CASE-001",
                force=False,
            )
            self.assertEqual(paired_vm_case.initialize_case(init_args), 0)
            state = json.loads((case / "case.json").read_text(encoding="utf-8"))
            self.assertFalse(state["boundaries"]["evidence_writes_allowed"])

            verify_args = Namespace(
                case_root=str(case), source=None, skip_gzip_test=False
            )
            self.assertEqual(paired_vm_case.verify_case(verify_args), 0)
            integrity = json.loads(
                (case / "integrity.json").read_text(encoding="utf-8")
            )
            self.assertEqual(integrity["status"], "verified")
            self.assertFalse((case / "integrity.progress.json").exists())

            prepare_args = Namespace(
                case_root=str(case),
                source=None,
                minimum_free_gib=0.0,
                restart=False,
                force=False,
            )
            self.assertEqual(paired_vm_case.prepare_disks(prepare_args), 0)
            raw_path = case / "sources" / "HOST-A" / "disk" / "working" / "disk.raw"
            self.assertEqual(raw_path.read_bytes(), b"disk-content" * 1024)
            self.assertFalse(raw_path.with_name("disk.raw.partial").exists())

    def test_integrity_gate_blocks_preparation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            case = root / "case"
            self.make_evidence(evidence)
            paired_vm_case.initialize_case(
                Namespace(
                    evidence_root=str(evidence),
                    case_root=str(case),
                    case_id="CASE-001",
                    force=False,
                )
            )
            with self.assertRaises(paired_vm_case.CaseError):
                paired_vm_case.prepare_disks(
                    Namespace(
                        case_root=str(case),
                        source=None,
                        minimum_free_gib=0.0,
                        restart=False,
                        force=False,
                    )
                )

    def test_verify_can_prepare_atomic_working_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            case = root / "case"
            self.make_evidence(evidence)
            paired_vm_case.initialize_case(
                Namespace(
                    evidence_root=str(evidence),
                    case_root=str(case),
                    case_id="CASE-001",
                    force=False,
                )
            )
            verify_args = Namespace(
                case_root=str(case),
                source=None,
                skip_gzip_test=False,
                prepare_working_disks=True,
                minimum_free_gib=0.0,
                restart_partials=False,
            )
            self.assertEqual(paired_vm_case.verify_case(verify_args), 0)
            raw_path = case / "sources" / "HOST-A" / "disk" / "working" / "disk.raw"
            self.assertEqual(raw_path.read_bytes(), b"disk-content" * 1024)
            integrity = json.loads(
                (case / "integrity.json").read_text(encoding="utf-8")
            )
            disk_item = integrity["sources"][0]["items"][0]
            self.assertEqual(disk_item["working_copy"]["status"], "created")

    def test_failed_gzip_records_whole_file_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            case = root / "case"
            disk, _ = self.make_evidence(evidence)
            disk.write_bytes(b"not-a-gzip-stream")
            memory = evidence / "HOST-A" / "host.dump"
            (evidence / "HOST-A" / "hashes.txt").write_text(
                f"{disk.name}\nsha256: {sha256(disk.read_bytes()).hexdigest()}\n\n"
                f"{memory.name}\n{sha256(memory.read_bytes()).hexdigest()}\n",
                encoding="utf-8",
            )
            paired_vm_case.initialize_case(
                Namespace(
                    evidence_root=str(evidence),
                    case_root=str(case),
                    case_id="CASE-001",
                    force=False,
                )
            )
            verify_args = Namespace(
                case_root=str(case), source=None, skip_gzip_test=False
            )
            self.assertEqual(paired_vm_case.verify_case(verify_args), 2)
            integrity = json.loads(
                (case / "integrity.json").read_text(encoding="utf-8")
            )
            disk_item = integrity["sources"][0]["items"][0]
            expected = sha256(disk.read_bytes()).hexdigest()
            self.assertEqual(disk_item["sha256"], expected)
            self.assertEqual(
                disk_item["gzip_test"]["whole_file_sha256_fallback"], expected
            )
            self.assertFalse(disk_item["gzip_test"]["sha256_complete"])

    def test_existing_working_disk_requires_matching_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            case = root / "case"
            self.make_evidence(evidence)
            paired_vm_case.initialize_case(
                Namespace(
                    evidence_root=str(evidence),
                    case_root=str(case),
                    case_id="CASE-001",
                    force=False,
                )
            )
            self.assertEqual(
                paired_vm_case.verify_case(
                    Namespace(case_root=str(case), source=None, skip_gzip_test=False)
                ),
                0,
            )
            prepare_args = Namespace(
                case_root=str(case),
                source=None,
                minimum_free_gib=0.0,
                restart=False,
                force=False,
            )
            self.assertEqual(paired_vm_case.prepare_disks(prepare_args), 0)
            raw_path = case / "sources" / "HOST-A" / "disk" / "working" / "disk.raw"
            with raw_path.open("ab") as stream:
                stream.write(b"tamper")
            with self.assertRaises(paired_vm_case.CaseError):
                paired_vm_case.prepare_disks(prepare_args)

    def test_offline_volatility_command_constrains_evidence(self) -> None:
        command = paired_vm_case.volatility_command(
            "example/volatility:test",
            Path("/evidence/HOST-A"),
            "memory.dump",
            Path("/cases/CASE-001/memory"),
            Path("/cases/CASE-001/cache"),
            Path("/cases/CASE-001/symbols"),
            "windows.info",
            False,
            "processes",
        )
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--offline", command)
        self.assertIn(f"{Path('/cases/CASE-001/symbols')}:/symbols:rw", command)
        self.assertIn("/symbols", command)
        self.assertIn(f"{Path('/evidence/HOST-A')}:/evidence:ro", command)
        self.assertEqual(command[-1], "windows.info")

    def test_plaso_command_is_unattended_and_read_only(self) -> None:
        command = paired_vm_case.plaso_command(
            "example/plaso@sha256:digest",
            Path("/cases/CASE-001/disk"),
            Path("/cases/CASE-001/timeline"),
            "timeline.plaso.partial",
            "all",
            "none",
        )
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--unattended", command)
        self.assertIn("/output/timeline.plaso.partial.log.gz", command)
        self.assertIn(f"{Path('/cases/CASE-001/disk')}:/evidence:ro", command)
        self.assertIn("/output/timeline.plaso.partial", command)
        self.assertEqual(command[-1], "/evidence/disk.raw")

    def test_psort_slice_command_is_offline_and_separates_input_from_output(
        self,
    ) -> None:
        command = paired_vm_case.psort_slice_command(
            "example/plaso@sha256:digest",
            Path("/cases/CASE-001/timeline"),
            "timeline.plaso",
            Path("/cases/CASE-001/reports/timeline-slices"),
            "capture.csv.partial",
            "2026-05-21T16:08:42+00:00",
            10,
            "UTC",
        )
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--unattended", command)
        self.assertIn("dynamic", command)
        self.assertIn("--dynamic_time", command)
        self.assertIn("/output/capture.csv.partial.psort.log.gz", command)
        self.assertIn(f"{Path('/cases/CASE-001/timeline')}:/timeline:ro", command)
        self.assertIn(
            f"{Path('/cases/CASE-001/reports/timeline-slices')}:/output:rw", command
        )
        self.assertIn("/output/capture.csv.partial", command)
        self.assertEqual(command[-1], "/timeline/timeline.plaso")

    def test_psort_query_command_is_offline_logged_and_preserves_filter_argument(
        self,
    ) -> None:
        event_filter = 'filename contains "server.ps1"'
        command = paired_vm_case.psort_query_command(
            "example/plaso@sha256:digest",
            Path("/cases/CASE-001/timeline"),
            "timeline.plaso",
            Path("/cases/CASE-001/reports/timeline-queries"),
            "server-ps1.csv.partial",
            event_filter,
            "UTC",
        )
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--include_all", command)
        self.assertIn("/output/server-ps1.csv.partial.psort.log.gz", command)
        self.assertIn(f"{Path('/cases/CASE-001/timeline')}:/timeline:ro", command)
        self.assertIn(
            f"{Path('/cases/CASE-001/reports/timeline-queries')}:/output:rw", command
        )
        self.assertEqual(command[-2], "/timeline/timeline.plaso")
        self.assertEqual(command[-1], event_filter)

    def test_tsk_recover_command_is_allocated_only_and_read_only(self) -> None:
        command = paired_vm_case.tsk_recover_command(
            "example/tsk:test",
            Path("/cases/CASE-001/disk"),
            Path("/cases/CASE-001/recovered"),
            "offset-2048.partial",
            2048,
            3898,
        )
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("--read-only", command)
        self.assertIn(f"{Path('/cases/CASE-001/disk')}:/evidence:ro", command)
        self.assertIn(f"{Path('/cases/CASE-001/recovered')}:/output:rw", command)
        self.assertIn("-a", command)
        self.assertEqual(command[command.index("-d") + 1], "3898")
        self.assertEqual(
            command[-2:], ["/evidence/disk.raw", "/output/offset-2048.partial"]
        )
        self.assertEqual(paired_vm_case.recovery_basename(2048), "offset-2048")
        self.assertEqual(
            paired_vm_case.recovery_basename(2048, 3898), "offset-2048-dir-3898"
        )

    def test_tsk_recover_command_supports_unallocated_and_all_scopes(self) -> None:
        common = (
            "example/tsk:test",
            Path("/cases/CASE-001/disk"),
            Path("/cases/CASE-001/recovered"),
            "offset-2048-unallocated.partial",
            2048,
        )
        unallocated = paired_vm_case.tsk_recover_command(
            *common, recovery_scope="unallocated"
        )
        self.assertNotIn("-a", unallocated)
        self.assertNotIn("-e", unallocated)
        all_files = paired_vm_case.tsk_recover_command(*common, recovery_scope="all")
        self.assertIn("-e", all_files)
        self.assertNotIn("-a", all_files)
        self.assertEqual(
            paired_vm_case.recovery_basename(2048, recovery_scope="unallocated"),
            "offset-2048-unallocated",
        )

    def test_manifest_completed_recovery_binds_tree_and_records_lane(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, case, state = self.initialize_fixture(root)
            source = state["sources"][0]
            recovery_root = case / "sources" / source["case_key"] / "disk" / "recovered"
            destination = recovery_root / "offset-2048"
            destination.mkdir(parents=True)
            (destination / "one.txt").write_text("one\n", encoding="utf-8")
            nested = destination / "nested"
            nested.mkdir()
            (nested / "two.bin").write_bytes(b"two")
            metadata_path = recovery_root / "offset-2048.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "offset_sector": 2048,
                        "directory_inum": None,
                        "recovered_path": str(destination.resolve()),
                        "recovery_scope": "allocated",
                        "file_count": 2,
                        "logical_size_bytes": sum(
                            path.stat().st_size
                            for path in destination.rglob("*")
                            if path.is_file()
                        ),
                        "atomic_completion": True,
                        "run": {"exit_code": 0},
                    }
                ),
                encoding="utf-8",
            )

            result = paired_vm_case.manifest_completed_recovery(
                Namespace(
                    case_root=str(case),
                    source=[source["source_name"]],
                    offset=2048,
                    directory_inum=None,
                    recovery_scope="allocated",
                )
            )

            self.assertEqual(result, 0)
            manifest_path = recovery_root / "offset-2048.sha256"
            self.assertTrue(manifest_path.is_file())
            self.assertEqual(
                paired_vm_case.validate_sha256_tree_manifest(
                    manifest_path, destination
                ),
                [],
            )
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["manifest_path"], str(manifest_path))
            self.assertEqual(
                metadata["manifest_sha256"],
                paired_vm_case.file_sha256(manifest_path),
            )
            refreshed = json.loads((case / "case.json").read_text(encoding="utf-8"))
            disk_evidence_id = next(
                item["evidence_item_id"]
                for item in refreshed["evidence_items"]
                if item["case_key"] == source["case_key"]
                and item["role"] == "disk_gzip"
            )
            lane = next(
                item
                for item in refreshed["work_items"]
                if item["evidence_item_id"] == disk_evidence_id
                and item["lane"] == "allocated_file_examination"
            )
            self.assertEqual(lane["status"], "completed")
            self.assertEqual(len(lane["artifacts"]), 2)

    def test_photorec_command_carves_read_only_evidence_to_separate_output(
        self,
    ) -> None:
        disk = Path("/cases/CASE-001/disk/working")
        output = Path("/cases/CASE-001/disk/carving/photorec.partial")
        command = paired_vm_case.photorec_command("example/testdisk:7.2", disk, output)
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("--read-only", command)
        self.assertIn(f"{disk}:/evidence:ro", command)
        self.assertIn(f"{output}:/output:rw", command)
        self.assertIn("partition_none", command[-1])
        self.assertIn("wholespace", command[-1])
        self.assertIn("fileopt,everything,enable", command[-1])

    def test_testdisk_repair_command_writes_only_the_derivative(self) -> None:
        repair_root = Path("/cases/CASE-001/disk/repair/copy-01")
        command = paired_vm_case.testdisk_repair_command(
            "example/testdisk:7.2", repair_root
        )
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn(f"{repair_root}:/repair:rw", command)
        self.assertNotIn("/evidence", " ".join(command))
        self.assertEqual(command[-2], "/repair/partition.raw")
        self.assertIn("repairmft", command[-1])

    def test_partition_copy_and_delta_map_preserve_the_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "disk.raw"
            original.write_bytes(b"A" * 512 + b"B" * 512 + b"C" * 512)
            derivative = root / "partition.raw"
            result = paired_vm_case.copy_partition_range(
                original, derivative, 512, 1024
            )
            self.assertEqual(
                original.read_bytes(), b"A" * 512 + b"B" * 512 + b"C" * 512
            )
            self.assertEqual(derivative.read_bytes(), b"B" * 512 + b"C" * 512)
            self.assertEqual(result["size_bytes"], 1024)
            with derivative.open("r+b") as stream:
                stream.seek(512)
                stream.write(b"D" * 512)
            ranges, changed = paired_vm_case.changed_sector_ranges(
                original, 512, derivative
            )
            self.assertEqual(changed, 1)
            self.assertEqual(ranges, [{"start_sector": 1, "end_sector": 1}])

    def test_partition_delta_map_rejects_invalid_derivative_lengths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "disk.raw"
            original.write_bytes(b"A" * 1024)
            derivative = root / "partition.raw"
            derivative.write_bytes(b"")
            with self.assertRaisesRegex(paired_vm_case.CaseError, "empty"):
                paired_vm_case.changed_sector_ranges(original, 0, derivative)
            derivative.write_bytes(b"A")
            with self.assertRaisesRegex(paired_vm_case.CaseError, "sector aligned"):
                paired_vm_case.changed_sector_ranges(original, 0, derivative)

    def test_partition_delta_map_handles_multiple_changed_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "disk.raw"
            derivative = root / "partition.raw"
            original.write_bytes(b"A" * (6 * 512))
            derivative.write_bytes(
                b"B" * 512 + b"A" * 512 + b"C" * 1024 + b"A" * 512 + b"D" * 512
            )
            ranges, changed = paired_vm_case.changed_sector_ranges(
                original, 0, derivative
            )
            self.assertEqual(changed, 4)
            self.assertEqual(
                ranges,
                [
                    {"start_sector": 0, "end_sector": 0},
                    {"start_sector": 2, "end_sector": 3},
                    {"start_sector": 5, "end_sector": 5},
                ],
            )

    def test_recovered_plaso_command_separates_read_only_input(self) -> None:
        file_filter = Path("/cases/CASE-001/config/triage.filter")
        command = paired_vm_case.plaso_recovered_command(
            "example/plaso@sha256:digest",
            Path("/cases/CASE-001/recovered/offset-2048"),
            Path("/cases/CASE-001/timeline"),
            "recovered.plaso.partial",
            file_filter,
        )
        self.assertIn(
            f"{Path('/cases/CASE-001/recovered/offset-2048')}:/evidence:ro", command
        )
        self.assertIn(f"{Path('/cases/CASE-001/timeline')}:/output:rw", command)
        self.assertIn(f"{file_filter}:/config/file-filter.txt:ro", command)
        self.assertIn("--filter-file", command)
        self.assertIn("/config/file-filter.txt", command)
        self.assertEqual(command[-1], "/evidence")

    def test_plaso_completion_errors_detects_partial_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stdout = root / "stdout.log"
            internal = root / "internal.log.gz"
            stdout.write_text(
                "Processing completed with errors.\n"
                "Path specifications that could not be processed:\n",
                encoding="utf-8",
            )
            with gzip.open(internal, "wt", encoding="utf-8") as stream:
                stream.write("2026-01-01 [ERROR] unable to open file system\n")
            self.assertEqual(
                paired_vm_case.plaso_completion_errors(stdout, internal),
                [
                    "processing_completed_with_errors",
                    "unprocessed_path_specifications",
                    "internal_log_error",
                ],
            )

    def test_mmls_partition_parser_ignores_metadata_and_unallocated_rows(self) -> None:
        text = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Size    Description
000:  Meta      0000000000   0000000000   0000000001   0512B   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   1024K   Unallocated
002:  000:000   0000002048   0000206847   0000204800   0100M   NTFS / exFAT (0x07)
003:  000:001   0000206848   0166299647   0166092800   0079G   NTFS / exFAT (0x07)
"""
        partitions = paired_vm_case.parse_mmls_partitions(text)
        self.assertEqual([item["start_sector"] for item in partitions], [2048, 206848])
        self.assertEqual(partitions[1]["length_sectors"], 166092800)

    def test_elf2dmp_command_reads_original_and_writes_only_conversion_root(
        self,
    ) -> None:
        command = paired_vm_case.elf2dmp_command(
            "example/elf2dmp:test",
            Path("/evidence/HOST-A/memory.dump"),
            Path("/cases/CASE-001/memory/converted"),
            "windows.dmp.partial",
        )
        self.assertIn("--read-only", command)
        self.assertIn(f"{Path('/evidence/HOST-A')}:/evidence:ro", command)
        self.assertIn(f"{Path('/cases/CASE-001/memory/converted')}:/output:rw", command)
        self.assertNotIn("--network", command)
        self.assertEqual(
            command[-2:], ["/evidence/memory.dump", "/output/windows.dmp.partial"]
        )

    def test_extended_memory_plugins_cover_cross_view_console_and_persistence(
        self,
    ) -> None:
        plugins = paired_vm_case.EXTENDED_MEMORY_PLUGINS
        self.assertIn("windows.malware.psxview", plugins)
        self.assertIn("windows.consoles", plugins)
        self.assertIn("windows.malware.suspicious_threads", plugins)
        self.assertIn("windows.registry.scheduled_tasks", plugins)

    def test_memory_run_kind_separates_repeated_invocation_summaries(self) -> None:
        baseline = Namespace(plugin=None, info_only=False, extended=False)
        extended = Namespace(plugin=None, info_only=False, extended=True)
        custom = Namespace(plugin=["windows.consoles"], info_only=False, extended=False)
        self.assertEqual(paired_vm_case.memory_run_kind(baseline), "baseline")
        self.assertEqual(paired_vm_case.memory_run_kind(extended), "extended")
        self.assertRegex(
            paired_vm_case.memory_run_kind(custom), r"^custom-1-[0-9a-f]{12}$"
        )

    def test_init_creates_only_a_linked_working_draft_and_complete_inventory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            self.make_evidence(evidence)
            extra = evidence / "HOST-A" / "examiner-note.bin"
            extra.write_bytes(b"supplemental evidence")
            case = root / "case"
            paired_vm_case.initialize_case(
                Namespace(
                    evidence_root=str(evidence),
                    case_root=str(case),
                    case_id="CASE-001",
                    force=False,
                )
            )
            state = json.loads((case / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(state["schema_version"], 2)
            self.assertEqual(len(state["evidence_items"]), 4)
            self.assertTrue(Path(state["report"]["working_path"]).is_file())
            self.assertFalse(Path(state["report"]["final_path"]).exists())
            draft = Path(state["report"]["working_path"]).read_text(encoding="utf-8")
            self.assertIn("DRAFT — EXAMINATION INCOMPLETE", draft)
            self.assertEqual(len(paired_vm_case.markdown_link_targets(draft)), 4)

    def test_schema_one_case_is_upgraded_in_memory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence, case, state = self.initialize_fixture(Path(temporary))
            for key in ("evidence_items", "work_items", "report", "lifecycle"):
                state.pop(key)
            state["schema_version"] = 1
            legacy = case / "reports" / "CASE-001.md"
            legacy.write_text("legacy working report\n", encoding="utf-8")
            (case / "case.json").write_text(json.dumps(state), encoding="utf-8")
            _, loaded_evidence, upgraded = paired_vm_case.load_case(str(case))
            self.assertEqual(loaded_evidence, evidence.resolve())
            self.assertEqual(upgraded["schema_version"], 2)
            self.assertTrue(upgraded["work_items"])
            self.assertEqual(Path(upgraded["report"]["working_path"]), legacy)

    def test_prepare_review_rejects_placeholder_and_pending_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence, case, state = self.initialize_fixture(Path(temporary))
            report = Path(state["report"]["working_path"])
            errors = paired_vm_case.readiness_errors(report, case, evidence, state)
            self.assertTrue(any("not complete" in error for error in errors))
            self.assertTrue(any("placeholder" in error for error in errors))
            with self.assertRaises(paired_vm_case.CaseError):
                paired_vm_case.prepare_review(
                    Namespace(case_root=str(case), report=None)
                )

    def test_completion_rejects_a_missing_required_lane(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, state = self.initialize_fixture(Path(temporary))
            removed = state["work_items"].pop()

            errors = paired_vm_case.validate_work_completion(state)

            self.assertIn(
                f"Required work item is missing: {removed['work_item_id']}", errors
            )

    def test_derived_tree_metadata_cannot_expand_outside_case_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = root / "case"
            outside = root / "outside"
            case.mkdir()
            outside.mkdir()
            metadata = case / "recovery.json"
            manifest = case / "recovery.sha256"
            metadata.write_text(
                json.dumps({"output_path": str(outside.resolve())}),
                encoding="utf-8",
            )
            manifest.write_text("", encoding="utf-8")
            state = {
                "work_items": [
                    {
                        "work_item_id": "item.signature_carving",
                        "lane": "signature_carving",
                        "status": "completed",
                        "artifacts": [
                            {"path": str(metadata.resolve())},
                            {"path": str(manifest.resolve())},
                        ],
                    }
                ]
            }

            errors = paired_vm_case.validate_derived_tree_artifacts(
                state, case.resolve(), rehash=False
            )

            self.assertTrue(any("outside the case root" in error for error in errors))

    def test_completion_rejects_a_duplicate_required_lane(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, state = self.initialize_fixture(Path(temporary))
            state["work_items"].append(dict(state["work_items"][0]))

            errors = paired_vm_case.validate_work_completion(state)

            self.assertTrue(any("duplicated" in error for error in errors))

    def test_not_applicable_is_restricted_to_repair_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, case, state = self.initialize_fixture(Path(temporary))
            work_item = next(
                item
                for item in state["work_items"]
                if item["lane"] == "signature_carving"
            )

            with self.assertRaisesRegex(
                paired_vm_case.CaseError, "not_applicable is not permitted"
            ):
                paired_vm_case.record_work_result(
                    Namespace(
                        case_root=str(case),
                        work_item=work_item["work_item_id"],
                        status="not_applicable",
                        artifact=None,
                        note="Incorrectly skipped in fixture.",
                    )
                )

    def test_evidence_inventory_drift_blocks_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence, case, state = self.initialize_fixture(Path(temporary))
            (evidence / "HOST-A" / "late.bin").write_bytes(b"late evidence")

            errors = paired_vm_case.validate_current_evidence(
                case, evidence, state, rehash=False
            )

            self.assertTrue(any("un-inventoried" in error for error in errors))

    def test_prepare_review_rejects_missing_evidence_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence, case, state = self.initialize_fixture(Path(temporary))
            self.complete_all_work(case, state)
            omitted = state["evidence_items"][0]["evidence_item_id"]
            report = self.write_complete_report(
                evidence, case, state, omit_evidence_id=omitted
            )
            errors = paired_vm_case.validate_report(report, case, evidence, state)
            self.assertTrue(any(omitted in error for error in errors))
            with self.assertRaises(paired_vm_case.CaseError):
                paired_vm_case.prepare_review(
                    Namespace(case_root=str(case), report=None)
                )

    def test_hash_bound_review_is_required_before_final_report_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence, case, state = self.initialize_fixture(Path(temporary))
            self.complete_all_work(case, state)
            report = self.write_complete_report(evidence, case, state)
            self.assertEqual(
                paired_vm_case.prepare_review(
                    Namespace(case_root=str(case), report=None)
                ),
                0,
            )
            bundle = json.loads(
                (case / "reviews" / "review-bundle.json").read_text(encoding="utf-8")
            )
            peer_review = case / "reviews" / "peer-review.json"
            peer_review.write_text(
                json.dumps(
                    {
                        "recommendation": "ready",
                        "report_sha256": bundle["report_sha256"],
                        "coverage_sha256": bundle["coverage_sha256"],
                        "reviewed_utc": "2026-07-23T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            self.assertFalse((case / "reports" / "CASE-001.final.md").exists())
            self.assertEqual(
                paired_vm_case.finalize_report(
                    Namespace(
                        case_root=str(case), report=None, peer_review=str(peer_review)
                    )
                ),
                0,
            )
            final_report = case / "reports" / "CASE-001.final.md"
            self.assertEqual(
                final_report.read_text(encoding="utf-8"),
                report.read_text(encoding="utf-8"),
            )
            completion = json.loads(
                (case / "completion.json").read_text(encoding="utf-8")
            )
            self.assertEqual(completion["status"], "finalized")
            self.assertEqual(
                completion["report_sha256"], paired_vm_case.file_sha256(final_report)
            )

    def test_forced_reinitialization_refuses_existing_analysis_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, case, _ = self.initialize_fixture(root)

            with self.assertRaisesRegex(
                paired_vm_case.CaseError, "analysis or provenance files"
            ):
                paired_vm_case.initialize_case(
                    Namespace(
                        evidence_root=str(evidence),
                        case_root=str(case),
                        case_id="CASE-001",
                        force=True,
                    )
                )

    def test_report_change_after_review_blocks_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence, case, state = self.initialize_fixture(Path(temporary))
            self.complete_all_work(case, state)
            report = self.write_complete_report(evidence, case, state)
            paired_vm_case.prepare_review(Namespace(case_root=str(case), report=None))
            bundle = json.loads(
                (case / "reviews" / "review-bundle.json").read_text(encoding="utf-8")
            )
            peer_review = case / "reviews" / "peer-review.json"
            peer_review.write_text(
                json.dumps(
                    {
                        "recommendation": "ready",
                        "report_sha256": bundle["report_sha256"],
                        "coverage_sha256": bundle["coverage_sha256"],
                    }
                ),
                encoding="utf-8",
            )
            report.write_text(
                report.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(paired_vm_case.CaseError, "changed after"):
                paired_vm_case.finalize_report(
                    Namespace(
                        case_root=str(case), report=None, peer_review=str(peer_review)
                    )
                )

    def test_ready_with_caveats_is_not_exact_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence, case, state = self.initialize_fixture(Path(temporary))
            self.complete_all_work(case, state)
            self.write_complete_report(evidence, case, state)
            paired_vm_case.prepare_review(Namespace(case_root=str(case), report=None))
            bundle = json.loads(
                (case / "reviews" / "review-bundle.json").read_text(encoding="utf-8")
            )
            peer_review = case / "reviews" / "peer-review.json"
            peer_review.write_text(
                json.dumps(
                    {
                        "recommendation": "ready with caveats",
                        "report_sha256": bundle["report_sha256"],
                        "coverage_sha256": bundle["coverage_sha256"],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(paired_vm_case.CaseError, "exactly 'ready'"):
                paired_vm_case.finalize_report(
                    Namespace(
                        case_root=str(case), report=None, peer_review=str(peer_review)
                    )
                )


if __name__ == "__main__":
    unittest.main()
