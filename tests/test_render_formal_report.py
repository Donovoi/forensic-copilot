from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "render_formal_report.py"
)
SPEC = importlib.util.spec_from_file_location("render_formal_report", SCRIPT_PATH)
assert SPEC and SPEC.loader
render_formal_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(render_formal_report)


class RenderFormalReportTests(unittest.TestCase):
    def make_bound_files(self, root: Path) -> tuple[Path, Path, Path]:
        report = root / "CASE-001.final.md"
        report.write_text("# Final report\n", encoding="utf-8")
        peer_review = root / "peer-review.json"
        peer_review.write_text(
            json.dumps({"recommendation": "ready"}), encoding="utf-8"
        )
        completion = root / "completion.json"
        completion.write_text(
            json.dumps(
                {
                    "status": "finalized",
                    "report_path": str(report.resolve()),
                    "report_sha256": render_formal_report.file_sha256(report),
                    "peer_review_path": str(peer_review.resolve()),
                    "peer_review_sha256": render_formal_report.file_sha256(peer_review),
                    "peer_review_recommendation": "ready",
                }
            ),
            encoding="utf-8",
        )
        return report.resolve(), peer_review.resolve(), completion.resolve()

    def test_exact_json_recommendation_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            review = Path(temporary) / "peer-review.json"
            review.write_text(
                json.dumps({"recommendation": "ready with caveats"}), encoding="utf-8"
            )
            self.assertEqual(
                render_formal_report.read_release_recommendation(review),
                "ready with caveats",
            )

    def test_completion_manifest_binds_report_and_peer_review_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, peer_review, completion = self.make_bound_files(Path(temporary))
            value = render_formal_report.validate_completion_binding(
                report, peer_review, completion
            )
            self.assertEqual(value["status"], "finalized")

    def test_report_edit_after_completion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, peer_review, completion = self.make_bound_files(Path(temporary))
            report.write_text("# Changed report\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Report hash"):
                render_formal_report.validate_completion_binding(
                    report, peer_review, completion
                )

    def test_peer_review_edit_after_completion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, peer_review, completion = self.make_bound_files(Path(temporary))
            peer_review.write_text(
                json.dumps({"recommendation": "not ready"}), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "Peer-review hash"):
                render_formal_report.validate_completion_binding(
                    report, peer_review, completion
                )


if __name__ == "__main__":
    unittest.main()
