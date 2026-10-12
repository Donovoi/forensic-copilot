from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AttributionAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = json.loads((ROOT / "opencode.json").read_text(encoding="utf-8"))
        cls.open_code_prompt = (
            ROOT / "docs" / "opencode-agents" / "forensic-attribution-analyst.md"
        ).read_text(encoding="utf-8")
        cls.copilot_prompt = (
            ROOT / ".github" / "agents" / "forensic-attribution-analyst.agent.md"
        ).read_text(encoding="utf-8")

    def test_opencode_agent_is_internal_and_constrained(self) -> None:
        agent = self.config["agent"]["forensic-attribution-analyst"]
        permission = agent["permission"]

        self.assertEqual(agent["mode"], "subagent")
        self.assertEqual(permission["bash"]["*"], "deny")
        self.assertEqual(
            permission["bash"]["python scripts/robin_research.py run *"], "ask"
        )
        self.assertEqual(permission["task"], "deny")
        self.assertEqual(permission["websearch"], "deny")
        self.assertEqual(permission["webfetch"], "deny")
        self.assertEqual(permission["write"], "allow")
        self.assertEqual(permission["edit"], "allow")

    def test_examiner_can_delegate_to_attribution_agent(self) -> None:
        task_permission = self.config["agent"]["forensic-examiner"]["permission"][
            "task"
        ]
        self.assertEqual(task_permission["forensic-attribution-analyst"], "allow")

    def test_prompts_require_fragment_schema_and_privacy_controls(self) -> None:
        for prompt in (self.open_code_prompt, self.copilot_prompt):
            with self.subTest(prompt=prompt[:30]):
                self.assertIn("local_accounts", prompt)
                self.assertIn("observed_users", prompt)
                self.assertIn("owner_or_custodian_candidates", prompt)
                self.assertIn("contradictions_and_alternatives", prompt)
                self.assertIn("online_sources", prompt)
                self.assertIn("confidence_assessment", prompt)
                self.assertIn("query-log", prompt)
                self.assertIn("Never", prompt)
                self.assertIn("final", prompt)

    def test_copilot_agent_is_internal(self) -> None:
        self.assertIn("user-invocable: false", self.copilot_prompt)
        examiner = (
            ROOT / ".github" / "agents" / "forensic-examiner.agent.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Forensic Attribution Analyst", examiner)


if __name__ == "__main__":
    unittest.main()
