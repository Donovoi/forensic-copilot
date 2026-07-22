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
            self.assertEqual(disk_item["gzip_test"]["full_file_sha256_after_failure"], expected)
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
            "windows.info",
            False,
            "processes",
        )
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--offline", command)
        self.assertIn(f"{Path('/evidence/HOST-A')}:/evidence:ro", command)
        self.assertEqual(command[-1], "windows.info")


if __name__ == "__main__":
    unittest.main()
