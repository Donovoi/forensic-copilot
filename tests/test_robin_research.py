from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "robin_research.py"
SPEC = importlib.util.spec_from_file_location("robin_research", SCRIPT_PATH)
assert SPEC and SPEC.loader
robin_research = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(robin_research)


class RobinResearchTests(unittest.TestCase):
    def test_config_locks_research_agent_to_webfetch(self) -> None:
        config = robin_research.build_opencode_config()
        agent = config["agent"][robin_research.ROBIN_AGENT]
        permission = agent["permission"]

        self.assertEqual(config["default_agent"], robin_research.ROBIN_AGENT)
        self.assertEqual(permission["*"], "deny")
        self.assertEqual(permission["webfetch"], "allow")
        self.assertEqual(permission["websearch"], "deny")
        self.assertEqual(permission["bash"], "deny")
        self.assertEqual(permission["write"], "deny")
        self.assertEqual(agent["steps"], 10)

    def test_response_limit_is_enforced(self) -> None:
        accepted = robin_research.validate_response("one\n\ntwo")
        self.assertEqual(accepted, "one\ntwo")

        too_many = "\n".join(str(index) for index in range(8))
        with self.assertRaises(robin_research.RobinResearchError):
            robin_research.validate_response(too_many)

        with self.assertRaises(robin_research.RobinResearchError):
            robin_research.validate_response("CRITICAL - MAXIMUM STEPS REACHED")
        with self.assertRaises(robin_research.RobinResearchError):
            robin_research.validate_response(
                "Maximum steps for this agent have been reached."
            )

    def test_repository_url_normalization_accepts_ssh(self) -> None:
        https = robin_research.normalized_repository_url(
            robin_research.ROBIN_REPOSITORY
        )
        ssh = robin_research.normalized_repository_url(
            "git@github.com:Donovoi/robin.git"
        )
        self.assertEqual(https, ssh)

    def test_checkout_verification_requires_origin_and_exact_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "robin-checkout"
            (root / "robin").mkdir(parents=True)
            (root / "robin" / "opencode_llm.py").write_text(
                "VALUE = 1\n", encoding="utf-8"
            )
            subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "config",
                    "user.email",
                    "tests@example.invalid",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Tests"], check=True
            )
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "-m", "fixture"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "remote",
                    "add",
                    "origin",
                    robin_research.ROBIN_REPOSITORY,
                ],
                check=True,
            )
            revision = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            details = robin_research.verify_robin_checkout(
                root, expected_revision=revision
            )

            self.assertEqual(details["revision"], revision)
            self.assertEqual(details["repository"], robin_research.ROBIN_REPOSITORY)

    def test_standalone_loader_does_not_import_robin_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module_dir = root / "robin"
            module_dir.mkdir()
            (module_dir / "__init__.py").write_text(
                "raise RuntimeError('package import forbidden')\n", encoding="utf-8"
            )
            (module_dir / "opencode_llm.py").write_text("VALUE = 7\n", encoding="utf-8")

            module = robin_research.load_robin_module(root)

            self.assertEqual(module.VALUE, 7)

    def test_generated_config_is_json_serializable(self) -> None:
        encoded = json.dumps(robin_research.build_opencode_config())
        self.assertIn(robin_research.ROBIN_AGENT, encoded)

    def test_attribution_mode_retains_web_only_privacy_constraints(self) -> None:
        config = robin_research.build_opencode_config("attribution")
        agent = config["agent"][robin_research.ROBIN_AGENT]
        self.assertEqual(agent["permission"]["webfetch"], "allow")
        self.assertEqual(agent["permission"]["bash"], "deny")
        self.assertIn("hosting subscriber", agent["prompt"])
        self.assertIn("Do not use breach data", agent["prompt"])


if __name__ == "__main__":
    unittest.main()
