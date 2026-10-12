#!/usr/bin/env python3
"""Extract bounded, redacted attribution leads from a Firefox places database."""

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
from datetime import datetime, timezone
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


def sqlite_source_files(places: Path) -> list[dict[str, object]]:
    """Record the database and any companion files that can affect query results."""
    artifacts = []
    for candidate in (
        places,
        places.with_name(places.name + "-wal"),
        places.with_name(places.name + "-shm"),
        places.with_name(places.name + "-journal"),
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
    with tempfile.TemporaryDirectory(prefix="forensic-firefox-") as temporary:
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


def firefox_time(value: int | None) -> str | None:
    if not value:
        return None
    return (
        datetime.fromtimestamp(value / 1_000_000, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def extract(places: Path) -> dict[str, object]:
    source_files = sqlite_source_files(places)
    with sqlite_query_copy(places) as query_database:
        connection = sqlite3.connect(query_database)
        try:
            rows = connection.execute(
                "SELECT url, title, visit_count, last_visit_date "
                "FROM moz_places ORDER BY last_visit_date"
            ).fetchall()
        finally:
            connection.close()

    domain_counts: Counter[str] = Counter()
    email_candidates: set[str] = set()
    search_queries: set[str] = set()
    visits = []
    for url, title, visit_count, last_visit_date in rows:
        url = str(url or "")
        title = str(title or "")
        redacted_url, searches = redact_url(url)
        hostname = (urlsplit(url).hostname or "").casefold()
        if hostname:
            domain_counts[hostname] += int(visit_count or 0)
        search_queries.update(searches)
        email_candidates.update(match.group(1) for match in EMAIL_RE.finditer(url))
        email_candidates.update(match.group(1) for match in EMAIL_RE.finditer(title))
        visits.append(
            {
                "url": redacted_url,
                "title": title[:1000],
                "hostname": hostname,
                "visit_count": int(visit_count or 0),
                "last_visit_utc": firefox_time(last_visit_date),
            }
        )
    return {
        "schema_version": 1,
        "source_path": str(places.resolve()),
        "source_sha256": sha256(places),
        "source_files": source_files,
        "query_method": "temporary byte-for-byte copy of SQLite DB/WAL bundle",
        "row_count": len(visits),
        "domain_visit_counts": dict(domain_counts.most_common()),
        "candidate_emails": sorted(email_candidates),
        "search_queries": sorted(search_queries),
        "visits": visits,
        "limitations": [
            "History entries identify use of this browser profile, not a real-world owner by themselves.",
            "Sensitive URL query values and URL credentials are redacted from this export.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--places", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    places = Path(args.places).resolve(strict=True)
    output = Path(args.output).resolve(strict=False)
    result = extract(places)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)
    print(f"Prepared {output} ({result['row_count']} history rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
