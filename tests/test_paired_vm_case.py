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
            parsed = paired_vm_case.parse_hash_manifest(evidence / "HOST-A" / "hashes.txt")
            self.assertEqual(parsed[disk.name], sha256(disk.read_bytes()).hexdigest())
            self.assertEqual(parsed[memory.name], sha256(memory.read_bytes()).hexdigest())
            gzip_result = paired_vm_case.hash_and_test_gzip_stream(disk)
            self.assertTrue(gzip_result["ok"])
            self.assertEqual(gzip_result["sha256"], sha256(disk.read_bytes()).hexdigest())

    def test_init_verify_and_prepare(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            case = root / "case"
            self.make_evidence(evidence)
            init_args = Namespace(
                evidence_root=str(evidence), case_root=str(case), case_id="CASE-001", force=False
            )
            self.assertEqual(paired_vm_case.initialize_case(init_args), 0)
            state = json.loads((case / "case.json").read_text(encoding="utf-8"))
            self.assertFalse(state["boundaries"]["evidence_writes_allowed"])

            verify_args = Namespace(case_root=str(case), source=None, skip_gzip_test=False)
            self.assertEqual(paired_vm_case.verify_case(verify_args), 0)
            integrity = json.loads((case / "integrity.json").read_text(encoding="utf-8"))
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
            integrity = json.loads((case / "integrity.json").read_text(encoding="utf-8"))
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
            verify_args = Namespace(case_root=str(case), source=None, skip_gzip_test=False)
            self.assertEqual(paired_vm_case.verify_case(verify_args), 2)
            integrity = json.loads((case / "integrity.json").read_text(encoding="utf-8"))
            disk_item = integrity["sources"][0]["items"][0]
            expected = sha256(disk.read_bytes()).hexdigest()
            self.assertEqual(disk_item["sha256"], expected)
            self.assertEqual(disk_item["gzip_test"]["whole_file_sha256_fallback"], expected)
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

    def test_psort_slice_command_is_offline_and_separates_input_from_output(self) -> None:
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

    def test_psort_query_command_is_offline_logged_and_preserves_filter_argument(self) -> None:
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
        self.assertIn(
            f"{Path('/cases/CASE-001/timeline')}:/timeline:ro", command
        )
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
        self.assertEqual(command[-2:], ["/evidence/disk.raw", "/output/offset-2048.partial"])
        self.assertEqual(paired_vm_case.recovery_basename(2048), "offset-2048")
        self.assertEqual(
            paired_vm_case.recovery_basename(2048, 3898), "offset-2048-dir-3898"
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
        self.assertIn(f"{Path('/cases/CASE-001/recovered/offset-2048')}:/evidence:ro", command)
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

    def test_elf2dmp_command_reads_original_and_writes_only_conversion_root(self) -> None:
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
        self.assertEqual(command[-2:], ["/evidence/memory.dump", "/output/windows.dmp.partial"])

    def test_extended_memory_plugins_cover_cross_view_console_and_persistence(self) -> None:
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
        self.assertRegex(paired_vm_case.memory_run_kind(custom), r"^custom-1-[0-9a-f]{12}$")


if __name__ == "__main__":
    unittest.main()
