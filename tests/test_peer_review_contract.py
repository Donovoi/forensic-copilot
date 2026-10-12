from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PeerReviewContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.agent_prompt = (
            ROOT / ".github" / "agents" / "forensic-peer-reviewer.agent.md"
        ).read_text(encoding="utf-8")
        cls.process_doc = (ROOT / "docs" / "peer-review-process.md").read_text(
            encoding="utf-8"
        )
        cls.open_code_prompt = (
            ROOT / "docs" / "opencode-agents" / "forensic-peer-reviewer.md"
        ).read_text(encoding="utf-8")
        cls.formal_doc = (ROOT / "docs" / "formal-report-output.md").read_text(
            encoding="utf-8"
        )

    def test_reviewer_and_process_require_hash_bound_json(self) -> None:
        for text in (self.agent_prompt, self.process_doc, self.open_code_prompt):
            with self.subTest(document=text[:40]):
                self.assertIn('"recommendation": "ready"', text)
                self.assertIn('"report_sha256"', text)
                self.assertIn('"coverage_sha256"', text)
                self.assertIn('"supported_findings"', text)
                self.assertIn('"challenged_findings"', text)
                self.assertIn('"missing_corroboration"', text)
                self.assertIn('"alternative_explanations"', text)
                self.assertIn('"required_wording_changes"', text)
                self.assertIn("peer-review.json", text)

    def test_formal_export_example_uses_finalized_contract(self) -> None:
        self.assertIn("--peer-review /analysis/peer-review.json", self.formal_doc)
        self.assertIn("--completion /analysis/completion.json", self.formal_doc)


if __name__ == "__main__":
    unittest.main()
