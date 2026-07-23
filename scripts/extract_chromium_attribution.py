#!/usr/bin/env python3
"""Extract bounded, redacted attribution leads from Chromium History SQLite."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import re
import shutil
import sqlite3
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_QUERY_NAMES = {
    "access_token",
    "apikey",
    "api_key",
    "auth",
    "challenge",
    "code",
    "consent_verifier",
    "credential",
    "key",
    "password",
    "passwd",
    "secret",
    "session",
    "state",
    "token",
    "usg",
    "uuid",
    "ved",
}
SEARCH_QUERY_NAMES = {"q", "query", "search", "search_query", "text"}
EMAIL_RE = re.compile(
    r"(?i)(?<![\w.+-])([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})(?![\w.-])"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(16 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def sqlite_source_files(history: Path) -> list[dict[str, object]]:
    artifacts = []
    for candidate in (
        history,
        history.with_name(history.name + "-wal"),
        history.with_name(history.name + "-shm"),
        history.with_name(history.name + "-journal"),
    ):
        if candidate.is_file():
            artifacts.append(
                {
                    "path": str(candidate.resolve()),
                    "size_bytes": candidate.stat().st_size,
                    "sha256": sha256(candidate),
                }
            )
    return artifacts


@contextmanager
def sqlite_query_copy(source: Path):
    """Query an isolated DB/WAL bundle so SQLite cannot write beside the source."""
    with tempfile.TemporaryDirectory(prefix="forensic-chromium-") as temporary:
        query_root = Path(temporary)
        query_database = query_root / source.name
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = source.with_name(source.name + suffix)
            if candidate.is_file():
                shutil.copyfile(candidate, query_root / (source.name + suffix))
        yield query_database


def redact_url(url: str) -> tuple[str, list[str]]:
    parsed = urlsplit(url)
    searches: list[str] = []
    redacted = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = name.casefold()
        if lowered in SEARCH_QUERY_NAMES and value:
            searches.append(value[:500])
        if lowered in SENSITIVE_QUERY_NAMES or any(
            marker in lowered
            for marker in ("token", "secret", "password", "challenge", "verifier")
        ):
            value = "[REDACTED]"
        redacted.append((name, value))
    hostname = parsed.hostname or ""
    if parsed.username or parsed.password:
        try:
            parsed_port = parsed.port
        except ValueError:
            parsed_port = None
        port = f":{parsed_port}" if parsed_port else ""
        host_for_netloc = f"[{hostname}]" if ":" in hostname else hostname
        netloc = f"REDACTED@{host_for_netloc}{port}"
    else:
        netloc = parsed.netloc
    return urlunsplit(
        (parsed.scheme, netloc, parsed.path, urlencode(redacted), "")
    ), searches


def chromium_time(value: int | None) -> str | None:
    if not value:
        return None
    timestamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
        microseconds=value
    )
    return timestamp.isoformat().replace("+00:00", "Z")


def redacted_url_record(url: str) -> tuple[str, str, list[str], set[str]]:
    redacted, searches = redact_url(url)
    hostname = (urlsplit(url).hostname or "").casefold()
    emails = {match.group(1) for match in EMAIL_RE.finditer(url)}
    return redacted, hostname, searches, emails


def extract(history: Path) -> dict[str, object]:
    source_files = sqlite_source_files(history)
    with sqlite_query_copy(history) as query_database:
        connection = sqlite3.connect(query_database)
        try:
            url_rows = connection.execute(
                "SELECT url, title, visit_count, typed_count, last_visit_time "
                "FROM urls ORDER BY last_visit_time"
            ).fetchall()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            download_rows = []
            if "downloads" in tables:
                columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(downloads)")
                }
                wanted = [
                    name
                    for name in (
                        "current_path",
                        "target_path",
                        "tab_url",
                        "tab_referrer_url",
                        "start_time",
                        "end_time",
                        "mime_type",
                        "total_bytes",
                        "state",
                        "danger_type",
                    )
                    if name in columns
                ]
                if wanted:
                    order = " ORDER BY start_time" if "start_time" in columns else ""
                    download_rows = connection.execute(
                        f"SELECT {', '.join(wanted)} FROM downloads{order}"
                    ).fetchall()
                    download_columns = wanted
                else:
                    download_columns = []
            else:
                download_columns = []
        finally:
            connection.close()

    domain_counts: Counter[str] = Counter()
    email_candidates: set[str] = set()
    search_queries: set[str] = set()
    visits = []
    for url, title, visit_count, typed_count, last_visit_time in url_rows:
        url = str(url or "")
        title = str(title or "")
        redacted_url, hostname, searches, emails = redacted_url_record(url)
        if hostname:
            domain_counts[hostname] += int(visit_count or 0)
        search_queries.update(searches)
        email_candidates.update(emails)
        email_candidates.update(match.group(1) for match in EMAIL_RE.finditer(title))
        visits.append(
            {
                "url": redacted_url,
                "title": title[:1000],
                "hostname": hostname,
                "visit_count": int(visit_count or 0),
                "typed_count": int(typed_count or 0),
                "last_visit_utc": chromium_time(last_visit_time),
            }
        )

    downloads = []
    for values in download_rows:
        row = dict(zip(download_columns, values, strict=True))
        for field in ("tab_url", "tab_referrer_url"):
            value = str(row.get(field) or "")
            if value:
                redacted, _, searches, emails = redacted_url_record(value)
                row[field] = redacted
                search_queries.update(searches)
                email_candidates.update(emails)
        for field in ("start_time", "end_time"):
            if field in row:
                row[field.replace("_time", "_utc")] = chromium_time(row.pop(field))
        downloads.append(row)

    return {
        "schema_version": 1,
        "source_path": str(history.resolve()),
        "source_sha256": sha256(history),
        "source_files": source_files,
        "query_method": "temporary byte-for-byte copy of SQLite DB/WAL bundle",
        "row_count": len(visits),
        "download_count": len(downloads),
        "domain_visit_counts": dict(domain_counts.most_common()),
        "candidate_emails": sorted(email_candidates),
        "search_queries": sorted(search_queries),
        "visits": visits,
        "downloads": downloads,
        "limitations": [
            "History entries identify use of this browser profile, not a real-world owner by themselves.",
            "Sensitive URL query values and URL credentials are redacted from this export.",
            "One row per URL is exported; last-visit time does not preserve every visit event.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    history = Path(args.history).resolve(strict=True)
    output = Path(args.output).resolve(strict=False)
    result = extract(history)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)
    print(
        f"Prepared {output} ({result['row_count']} history rows, "
        f"{result['download_count']} downloads)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
