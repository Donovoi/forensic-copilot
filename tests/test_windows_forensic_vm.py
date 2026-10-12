from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tooling"
    / "paired-vm"
    / "windows-forensic-vm"
    / "forensic_vm.py"
)
SPEC = importlib.util.spec_from_file_location("forensic_vm", MODULE_PATH)
assert SPEC and SPEC.loader
forensic_vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(forensic_vm)


class WindowsForensicVmTests(unittest.TestCase):
    def test_fat_volume_labels_fit_the_eleven_character_limit(self) -> None:
        self.assertLessEqual(len(forensic_vm.RESULTS_LABEL), 11)
        self.assertLessEqual(len(forensic_vm.AUXILIARY_LABEL), 11)

    def test_prepare_derivative_hashes_copy_and_writes_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "verified-working.raw"
            source.write_bytes(b"evidence-block" * 100)
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            derivative = root / "repair-derivative.raw"

            descriptor_path = forensic_vm.copy_derivative(source, derivative, expected)
            descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))

            self.assertEqual(source.read_bytes(), derivative.read_bytes())
            self.assertEqual(descriptor["source_sha256"], expected)
            self.assertEqual(descriptor["derivative_sha256"], expected)
            self.assertFalse(descriptor["original_evidence_writable"])

    def test_prepare_derivative_refuses_source_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.raw"
            source.write_bytes(b"x")
            digest = hashlib.sha256(b"x").hexdigest()
            with self.assertRaises(forensic_vm.SafetyError):
                forensic_vm.copy_derivative(source, source, digest)

    def test_prepare_derivative_refuses_symlink_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.raw"
            source.write_bytes(b"source")
            source_link = root / "source-link.raw"
            try:
                source_link.symlink_to(source)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")

            with self.assertRaisesRegex(forensic_vm.SafetyError, "path is a symlink"):
                forensic_vm.copy_derivative(
                    source_link,
                    root / "derivative.raw",
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                )

    def test_validate_derivative_refuses_hard_link_to_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.raw"
            source.write_bytes(b"same-filesystem-object")
            derivative = root / "derivative.raw"
            try:
                os.link(source, derivative)
            except OSError as exc:  # pragma: no cover - unusual filesystem policy
                self.skipTest(f"hard links unavailable: {exc}")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            descriptor = root / "derivative.json"
            descriptor.write_text(
                json.dumps(
                    {
                        "kind": "windows-filesystem-repair-derivative",
                        "source_path": str(source),
                        "derivative_path": str(derivative),
                        "derivative_size": derivative.stat().st_size,
                        "derivative_sha256": digest,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(forensic_vm.SafetyError):
                forensic_vm.validate_derivative(derivative, descriptor)

    def test_prepare_derivative_retains_partial_on_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.raw"
            source.write_bytes(b"not-the-expected-content")
            derivative = root / "derivative.raw"
            with self.assertRaises(forensic_vm.SafetyError):
                forensic_vm.copy_derivative(source, derivative, "0" * 64)
            self.assertFalse(derivative.exists())
            self.assertTrue((root / "derivative.raw.partial").is_file())

    def test_changed_extents_coalesces_adjacent_blocks(self) -> None:
        before = [
            {"sha256": value, "length": 4} for value in ("a", "b", "c", "d", "e", "f")
        ]
        after = [dict(value) for value in before]
        after[1]["sha256"] = "changed-1"
        after[2]["sha256"] = "changed-2"
        after[5]["sha256"] = "changed-5"

        self.assertEqual(
            forensic_vm.changed_extents(before, after, 4),
            [
                {"first_block": 1, "last_block": 2, "offset": 4, "length": 8},
                {"first_block": 5, "last_block": 5, "offset": 20, "length": 4},
            ],
        )

    def test_changed_extents_uses_partial_final_block_length(self) -> None:
        before = [
            {"sha256": "a", "length": 4, "offset": 0},
            {"sha256": "b", "length": 2, "offset": 4},
        ]
        after = [dict(value) for value in before]
        after[1]["sha256"] = "changed"

        self.assertEqual(
            forensic_vm.changed_extents(before, after, 4),
            [
                {
                    "first_block": 1,
                    "last_block": 1,
                    "offset": 4,
                    "length": 2,
                }
            ],
        )

    def test_volume_serial_requires_exact_windows_format(self) -> None:
        self.assertEqual(forensic_vm.normalize_volume_serial("abcd-0123"), "ABCD-0123")
        for unsafe in ("", "Volume", "ABCD0123", "ABCD-0123&chkdsk C: /f"):
            with (
                self.subTest(unsafe=unsafe),
                self.assertRaises(forensic_vm.SafetyError),
            ):
                forensic_vm.normalize_volume_serial(unsafe)

    def test_auxiliary_media_record_binds_path_and_hash_to_official_iso(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            auxiliary = root / "auxiliary.img"
            auxiliary.write_bytes(b"autounattend-media")
            auxiliary_sha256 = hashlib.sha256(auxiliary.read_bytes()).hexdigest()
            record = root / "auxiliary-media.json"
            payload = MODULE_PATH.parent / "payload"
            record.write_text(
                json.dumps(
                    {
                        "kind": "windows-forensic-autounattend-auxiliary-media",
                        "required_official_iso_sha256": forensic_vm.EXPECTED_BASE_ISO_SHA256,
                        "auxiliary_image_path": str(auxiliary),
                        "auxiliary_image_sha256": auxiliary_sha256,
                        "auxiliary_image_size": auxiliary.stat().st_size,
                        "filesystem_label": forensic_vm.AUXILIARY_LABEL,
                        "autounattend_sha256": forensic_vm.sha256_file(
                            payload / "Autounattend.xml"
                        ),
                        "repair_script_source_sha256": forensic_vm.sha256_file(
                            payload / "forensic-repair" / "run.cmd"
                        ),
                    }
                ),
                encoding="utf-8",
            )

            _, actual = forensic_vm.validate_auxiliary_media(auxiliary, record)
            self.assertEqual(actual, auxiliary_sha256)
            auxiliary.write_bytes(b"mutated")
            with self.assertRaises(forensic_vm.SafetyError):
                forensic_vm.validate_auxiliary_media(auxiliary, record)

    def test_autounattend_only_runs_the_forensic_windows_pe_command(self) -> None:
        answer_path = MODULE_PATH.parent / "payload" / "Autounattend.xml"
        root = ET.parse(answer_path).getroot()
        namespace = {"u": "urn:schemas-microsoft-com:unattend"}
        settings = root.findall("u:settings", namespace)
        self.assertEqual([item.attrib.get("pass") for item in settings], ["windowsPE"])
        paths = root.findall(".//u:RunSynchronousCommand/u:Path", namespace)
        self.assertEqual(len(paths), 1)
        self.assertIn("FORENSIC_AUX.TAG", paths[0].text or "")
        text = answer_path.read_text(encoding="utf-8")
        for dangerous_setup_setting in (
            "DiskConfiguration",
            "ImageInstall",
            "ProductKey",
            "InstallTo",
        ):
            self.assertNotIn(dangerous_setup_setting, text)

    def test_scan_qemu_command_has_two_read_only_guards_and_no_network(self) -> None:
        command = forensic_vm.qemu_docker_command(
            image="local/image:test",
            container_name="scan-test",
            official_iso=Path("/case/official.iso"),
            auxiliary_image=Path("/case/auxiliary.img"),
            derivative=Path("/case/derivative.raw"),
            results_image=Path("/case/results.img"),
            mode="scan",
            memory_mib=4096,
            cpus=2,
        )
        joined = " ".join(command)
        self.assertIn("--network none", joined)
        self.assertIn("-nic none", joined)
        self.assertIn("dst=/media/windows-official.iso,readonly", joined)
        self.assertIn("dst=/auxiliary/auxiliary.img,readonly", joined)
        self.assertIn("dst=/evidence/derivative.raw,readonly", joined)
        self.assertIn("readonly=on,cache=none", joined)
        self.assertIn("usb-storage,drive=auxiliary,removable=on", joined)
        self.assertIn("usb-storage,drive=derivative,removable=on", joined)
        self.assertNotIn("if=ide,index=1", joined)

    def test_repair_qemu_command_writes_only_derivative_and_results(self) -> None:
        command = forensic_vm.qemu_docker_command(
            image="local/image:test",
            container_name="repair-test",
            official_iso=Path("/case/official.iso"),
            auxiliary_image=Path("/case/auxiliary.img"),
            derivative=Path("/case/derivative.raw"),
            results_image=Path("/case/results.img"),
            mode="repair",
            memory_mib=4096,
            cpus=2,
        )
        joined = " ".join(command)
        self.assertIn("dst=/media/windows-official.iso,readonly", joined)
        self.assertIn("dst=/auxiliary/auxiliary.img,readonly", joined)
        self.assertIn("dst=/evidence/derivative.raw", joined)
        self.assertNotIn("dst=/evidence/derivative.raw,readonly", joined)
        self.assertIn("readonly=off,cache=none", joined)
        self.assertIn("usb-storage,drive=derivative,removable=on", joined)
        self.assertNotIn("if=ide,index=1", joined)

    def test_scan_proof_requires_guest_artifacts_and_unchanged_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            guest = root / "guest"
            guest.mkdir()
            digest = "a" * 64
            (root / "run.json").write_text(
                json.dumps(
                    {
                        "status": "complete",
                        "mode": "scan",
                        "derivative_sha256_before": digest,
                        "derivative_sha256_after": digest,
                        "changed_extents": [],
                        "official_iso_sha256": "official",
                        "auxiliary_image_sha256": "auxiliary",
                        "runtime_image_id": "runtime",
                        "expected_volume_serial": "1234-ABCD",
                        "derivative_disk_number": 0,
                        "derivative_partition_number": 0,
                    }
                ),
                encoding="utf-8",
            )
            (guest / "run-status.txt").write_text("STATUS=complete\n", encoding="utf-8")
            (guest / "chkdsk-scan.txt").write_text("scan output\n", encoding="utf-8")

            proof_args = {
                "official_iso_sha256": "official",
                "auxiliary_image_sha256": "auxiliary",
                "runtime_image_id": "runtime",
                "volume_serial": "1234-ABCD",
                "disk_number": 0,
                "partition_number": 0,
            }
            forensic_vm.validate_scan_proof(root, digest, **proof_args)
            with self.assertRaises(forensic_vm.SafetyError):
                forensic_vm.validate_scan_proof(root, "b" * 64, **proof_args)


if __name__ == "__main__":
    unittest.main()
