from __future__ import annotations

import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qsl, urlsplit


def load_script(name: str):
    path = Path(__file__).resolve().parents[1] / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


firefox = load_script("extract_firefox_attribution.py")
chromium = load_script("extract_chromium_attribution.py")
chromium_profile = load_script("extract_chromium_profile_attribution.py")
public_ip = load_script("research_public_ip_attribution.py")
carving_formats = load_script("summarize_carving_formats.py")
memory_summary = load_script("summarize_memory_analysis.py")
sqlite_summary = load_script("inspect_sqlite_summary.py")


class FirefoxAttributionTests(unittest.TestCase):
    def test_source_provenance_includes_rollback_journal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            places = Path(temporary) / "places.sqlite"
            places.write_bytes(b"database")
            places.with_name("places.sqlite-journal").write_bytes(b"journal")

            names = {
                Path(item["path"]).name for item in firefox.sqlite_source_files(places)
            }

            self.assertEqual(names, {"places.sqlite", "places.sqlite-journal"})

    def test_redact_url_retains_search_but_removes_credentials_and_tokens(self) -> None:
        redacted, searches = firefox.redact_url(
            "https://alice:password@example.test/find?q=owner&exchange_token=secret&code=abc#fragment"
        )
        parsed = urlsplit(redacted)
        self.assertEqual(parsed.netloc, "REDACTED@example.test")
        self.assertEqual(parsed.fragment, "")
        self.assertEqual(searches, ["owner"])
        self.assertEqual(
            dict(parse_qsl(parsed.query)),
            {"q": "owner", "exchange_token": "[REDACTED]", "code": "[REDACTED]"},
        )

    def test_extract_records_database_and_companion_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            places = Path(temporary) / "places.sqlite"
            connection = sqlite3.connect(places)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE moz_places (url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER)"
            )
            connection.execute(
                "INSERT INTO moz_places VALUES (?, ?, ?, ?)",
                (
                    "https://example.test/?token=secret",
                    "Example",
                    2,
                    1_700_000_000_000_000,
                ),
            )
            connection.commit()
            source_companions_before = {
                path.name: path.read_bytes()
                for path in places.parent.glob(places.name + "-*")
            }

            result = firefox.extract(places)
            source_companions_after = {
                path.name: path.read_bytes()
                for path in places.parent.glob(places.name + "-*")
            }
            connection.close()

            self.assertEqual(result["row_count"], 1)
            self.assertIn(
                "places.sqlite-wal",
                [Path(item["path"]).name for item in result["source_files"]],
            )
            self.assertEqual(source_companions_before, source_companions_after)
            self.assertIn("token=%5BREDACTED%5D", result["visits"][0]["url"])


class PublicIpAttributionTests(unittest.TestCase):
    def test_collect_ip_logs_response_hashes_and_interpretation_limits(self) -> None:
        response = json.dumps({"name": "TEST-NET"}).encode()
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(
                public_ip, "fetch", return_value=(200, "application/json", response)
            ),
            mock.patch.object(
                public_ip.socket,
                "gethostbyaddr",
                return_value=("host.example.test", [], ["192.0.2.1"]),
            ),
        ):
            result = public_ip.collect_ip("192.0.2.1", Path(temporary), timeout=1.0)

            self.assertEqual(result["current_ptr"], "host.example.test")
            self.assertEqual(len(result["public_queries"]), len(public_ip.ENDPOINTS))
            for item in result["public_queries"]:
                self.assertEqual(item["status"], "completed")
                self.assertEqual(
                    item["response_sha256"], public_ip.sha256_bytes(response)
                )
                self.assertTrue(Path(item["response_path"]).is_file())
            self.assertTrue(result["interpretation_limits"])


class CarvingFormatSummaryTests(unittest.TestCase):
    def test_deterministic_samples_count_every_file_and_bound_each_extension(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(6):
                (root / f"file-{index}.txt").write_text(str(index), encoding="utf-8")
            (root / "sample.bin").write_bytes(b"sample")

            counts, first = carving_formats.deterministic_samples(root, 2)
            _, second = carving_formats.deterministic_samples(root, 2)

            self.assertEqual(counts, {".bin": 1, ".txt": 6})
            self.assertEqual(len(first[".txt"]), 2)
            self.assertEqual(first, second)


class MemorySummaryTests(unittest.TestCase):
    def test_json_shape_distinguishes_rows_from_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = root / "rows.json"
            rows.write_text("[{}, {}]\n", encoding="utf-8")
            mapping = root / "mapping.json"
            mapping.write_text('{"a": 1}\n', encoding="utf-8")

            self.assertEqual(memory_summary.json_shape(rows)["row_count"], 2)
            self.assertEqual(memory_summary.json_shape(mapping)["key_count"], 1)

    def test_unrun_memory_lanes_are_incomplete(self) -> None:
        lanes = memory_summary.summarize_lanes({}, {})

        self.assertTrue(lanes)
        self.assertTrue(all(item["status"] == "incomplete" for item in lanes.values()))

    def test_alternate_plugin_failure_is_terminal_but_limited(self) -> None:
        outputs = {"windows.info": {"plugin": "windows.info", "json_status": "valid"}}
        runs = {
            "host-windows.info": {
                "label": "host-windows.info",
                "exit_code": 0,
            }
        }

        lanes = memory_summary.summarize_lanes(outputs, runs)

        self.assertEqual(lanes["compatibility_and_os"]["status"], "completed")
        self.assertEqual(lanes["processes"]["status"], "incomplete")

    def test_successful_plugin_with_parser_warning_is_limited(self) -> None:
        outputs = {
            "windows.info": {
                "plugin": "windows.info",
                "json_status": "valid",
                "parser_warnings": ["WARNING plugin: incomplete layer"],
            }
        }
        runs = {
            "host-windows.info": {
                "label": "host-windows.info",
                "exit_code": 0,
            }
        }

        lanes = memory_summary.summarize_lanes(outputs, runs)

        self.assertEqual(
            lanes["compatibility_and_os"]["status"], "completed_with_limit"
        )
        self.assertEqual(
            lanes["compatibility_and_os"]["limited_groups"], [["windows.info"]]
        )

    def test_parser_warnings_ignore_framework_banner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stderr = Path(temporary) / "plugin.stderr.log"
            stderr.write_text(
                "Volatility 3 Framework 2.28.0\nWARNING plugin: Failed to get key\n",
                encoding="utf-8",
            )

            self.assertEqual(
                memory_summary.parser_warnings(stderr),
                ["WARNING plugin: Failed to get key"],
            )


class SqliteSummaryTests(unittest.TestCase):
    def test_inspection_validates_schema_without_exporting_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.sqlite"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE items (value TEXT)")
            connection.execute("INSERT INTO items VALUES ('private-content')")
            connection.commit()
            connection.close()

            result = sqlite_summary.inspect(path)

            self.assertTrue(result["integrity_ok"])
            table = next(
                item for item in result["schema_objects"] if item["name"] == "items"
            )
            self.assertEqual(table["row_count"], 1)
            self.assertNotIn("private-content", json.dumps(result))

    def test_malformed_sqlite_still_produces_a_limited_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "carved.sqlite"
            path.write_bytes(b"SQLite format 3\0" + b"\0" * 4096)

            result = sqlite_summary.inspect(path)

            self.assertFalse(result["integrity_ok"])
            self.assertTrue(result["integrity_error"] or result["schema_error"])
            self.assertFalse(path.with_name(path.name + "-wal").exists())
            self.assertFalse(path.with_name(path.name + "-shm").exists())


class ChromiumAttributionTests(unittest.TestCase):
    def test_extract_redacts_history_and_download_urls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            history = Path(temporary) / "History"
            connection = sqlite3.connect(history)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, "
                "typed_count INTEGER, last_visit_time INTEGER)"
            )
            connection.execute(
                "INSERT INTO urls VALUES (?, ?, ?, ?, ?)",
                (
                    "https://example.test/?q=device+owner&token=secret",
                    "Search",
                    3,
                    1,
                    13_000_000_000_000_000,
                ),
            )
            connection.execute(
                "CREATE TABLE downloads (target_path TEXT, tab_url TEXT, "
                "start_time INTEGER, total_bytes INTEGER)"
            )
            connection.execute(
                "INSERT INTO downloads VALUES (?, ?, ?, ?)",
                (
                    r"C:\\Users\\USER-A\\Downloads\\tool.zip",
                    "https://example.test/download?code=secret",
                    13_000_000_000_000_000,
                    42,
                ),
            )
            connection.commit()
            source_companions_before = {
                path.name: path.read_bytes()
                for path in history.parent.glob(history.name + "-*")
            }

            result = chromium.extract(history)
            source_companions_after = {
                path.name: path.read_bytes()
                for path in history.parent.glob(history.name + "-*")
            }
            connection.close()

            self.assertEqual(result["row_count"], 1)
            self.assertEqual(result["download_count"], 1)
            self.assertIn("token=%5BREDACTED%5D", result["visits"][0]["url"])
            self.assertIn("code=%5BREDACTED%5D", result["downloads"][0]["tab_url"])
            self.assertEqual(result["search_queries"], ["device owner"])
            self.assertEqual(source_companions_before, source_companions_after)

    def test_profile_extract_keeps_identity_fields_but_not_capability_blob(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            preferences = Path(temporary) / "Preferences"
            preferences.write_text(
                json.dumps(
                    {
                        "account_info": [
                            {
                                "email": "user@example.test",
                                "edge_account_first_name": "USER",
                                "edge_account_last_name": "A",
                                "accountcapabilities": {"unbounded": "blob"},
                            }
                        ],
                        "profile": {"name": "Profile 1", "avatar_index": 20},
                    }
                ),
                encoding="utf-8",
            )

            result = chromium_profile.extract(preferences)

            self.assertEqual(result["accounts"][0]["email"], "user@example.test")
            self.assertNotIn("accountcapabilities", result["accounts"][0])
            self.assertEqual(result["profile"]["name"], "Profile 1")
            self.assertEqual(len(result["source_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
