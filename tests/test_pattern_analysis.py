from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "run_pattern_analysis.py"
)
SPEC = importlib.util.spec_from_file_location("run_pattern_analysis", SCRIPT_PATH)
assert SPEC and SPEC.loader
run_pattern_analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_pattern_analysis)


class PatternAnalysisTests(unittest.TestCase):
    def make_pe(self, path: Path) -> None:
        content = bytearray(512)
        content[0:2] = b"MZ"
        content[0x3C:0x40] = (0x80).to_bytes(4, "little")
        content[0x80:0x84] = b"PE\x00\x00"
        path.write_bytes(content)

    def test_build_commands_are_static_and_do_not_launch_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "sample.exe"
            self.make_pe(target)
            patterns = Path(temporary) / "patterns.txt"
            floss = run_pattern_analysis.build_command(
                {"tool": "floss", "mode": "decoded"},
                Path("/tools/floss"),
                target,
                None,
            )
            executable = floss[0]
            self.assertEqual(Path(executable), Path("/tools/floss"))
            self.assertIn("--only", floss)
            self.assertEqual(floss[-1], str(target))
            self.assertNotEqual(executable, str(target))

            bstrings = run_pattern_analysis.build_command(
                {"tool": "bstrings", "mode": "baseline"},
                Path("/tools/bstrings"),
                target,
                None,
            )
            self.assertIn("-a", bstrings)
            self.assertIn("-u", bstrings)
            self.assertIn("--off", bstrings)
            self.assertNotIn("true", bstrings)

            rg_target = Path(temporary) / "tree"
            rg = run_pattern_analysis.build_command(
                {
                    "tool": "rg",
                    "mode": "fixed",
                    "target_kind": "tree",
                    "maximum_columns": 1024,
                },
                Path("/tools/rg"),
                rg_target,
                patterns,
            )
            self.assertIn("--no-config", rg)
            self.assertIn("--fixed-strings", rg)
            self.assertIn("--binary", rg)
            self.assertEqual(rg[-1], str(rg_target))

    def test_bounded_runner_records_global_output_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stdout = root / "stdout.txt"
            stderr = root / "stderr.txt"
            command = [
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('line\\n' * 10000)",
            ]
            result = run_pattern_analysis.run_bounded(
                command,
                stdout,
                stderr,
                root,
                timeout_seconds=30,
                maximum_bytes=1024,
                maximum_lines=10,
            )
            self.assertTrue(result["truncated"])
            self.assertEqual(result["limit_reason"], "maximum_output_lines")
            self.assertLessEqual(len(stdout.read_bytes()), 1024)
            self.assertLessEqual(
                len(stdout.read_text(encoding="utf-8").splitlines()), 10
            )

    def test_intentional_output_cap_is_limited_not_failed(self) -> None:
        status, limitations = run_pattern_analysis.classify_execution(
            "bstrings",
            {
                "exit_code": -15,
                "timed_out": False,
                "truncated": True,
                "limit_reason": "maximum_output_bytes",
            },
        )

        self.assertEqual(status, "completed_with_limit")
        self.assertIn("results are incomplete", limitations[0])

    @unittest.skipIf(os.name == "nt", "POSIX pseudo-terminal behavior")
    def test_bounded_runner_can_supply_nonredirected_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stdout = root / "stdout.txt"
            stderr = root / "stderr.txt"
            result = run_pattern_analysis.run_bounded(
                [sys.executable, "-c", "import sys; print(sys.stdin.isatty())"],
                stdout,
                stderr,
                root,
                timeout_seconds=30,
                maximum_bytes=1024,
                maximum_lines=10,
                tty_stdin=True,
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(stdout.read_text(encoding="utf-8").strip(), "True")

    def test_dry_run_validates_allowlisted_jobs_without_resolving_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = root / "inputs"
            output = root / "output"
            inputs.mkdir()
            pe = inputs / "sample.exe"
            self.make_pe(pe)
            strings_file = inputs / "strings.txt"
            strings_file.write_text("example.invalid\n", encoding="utf-8")
            tree = inputs / "tree"
            tree.mkdir()
            (tree / "note.txt").write_text("fixture\n", encoding="utf-8")
            manifest = inputs / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "jobs": [
                            {
                                "id": "decoded-pe",
                                "tool": "floss",
                                "mode": "decoded",
                                "target": str(pe),
                            },
                            {
                                "id": "baseline-strings",
                                "tool": "bstrings",
                                "mode": "baseline",
                                "target": str(strings_file),
                            },
                            {
                                "id": "tree-iocs",
                                "tool": "rg",
                                "mode": "fixed",
                                "target_kind": "tree",
                                "target": str(tree),
                                "patterns": ["example.invalid"],
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
                floss="missing-floss",
                bstrings="missing-bstrings",
                rg="missing-rg",
                maximum_output_bytes=1024 * 1024,
                maximum_output_lines=1000,
                timeout_seconds=30,
                dry_run=True,
                force=False,
            )

            self.assertEqual(run_pattern_analysis.analyze(args), 0)
            result = json.loads(
                (output / "pattern-analysis.provenance.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(result["safety"]["static_tooling_only"])
            self.assertFalse(result["safety"]["shell_used"])
            self.assertFalse(result["safety"]["evidence_executed"])
            self.assertEqual(
                [job["status"] for job in result["jobs"]],
                ["planned", "planned", "planned"],
            )
            self.assertEqual(
                result["jobs"][0]["target"]["sha256"],
                run_pattern_analysis.file_sha256(pe),
            )


if __name__ == "__main__":
    unittest.main()
