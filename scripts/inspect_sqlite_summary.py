#!/usr/bin/env python3
"""Validate and summarize a SQLite artifact without exporting table content."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(16 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def inspect(path: Path) -> dict[str, object]:
    # immutable=1 prevents SQLite from creating WAL/SHM companions beside a
    # carved or otherwise preservation-sensitive artifact.
    connection = sqlite3.connect(
        f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True
    )
    integrity_error = None
    schema_error = None
    try:
        try:
            integrity_rows = [
                row[0] for row in connection.execute("PRAGMA integrity_check")
            ]
        except sqlite3.DatabaseError as exc:
            integrity_rows = []
            integrity_error = f"{type(exc).__name__}: {exc}"
        try:
            schema_rows = connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "ORDER BY type, name"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            schema_rows = []
            schema_error = f"{type(exc).__name__}: {exc}"
        tables = []
        for object_type, name, table_name, sql in schema_rows:
            record = {
                "type": object_type,
                "name": name,
                "table_name": table_name,
                "sql": sql,
            }
            if object_type == "table" and not name.startswith("sqlite_"):
                try:
                    record["row_count"] = connection.execute(
                        f"SELECT count(*) FROM {quote_identifier(name)}"
                    ).fetchone()[0]
                except sqlite3.DatabaseError as exc:
                    record["row_count_error"] = f"{type(exc).__name__}: {exc}"
            tables.append(record)
    finally:
        connection.close()
    return {
        "schema_version": 1,
        "created_utc": utc_now(),
        "source_path": str(path.resolve()),
        "source_size_bytes": path.stat().st_size,
        "source_sha256": sha256(path),
        "integrity_check": integrity_rows,
        "integrity_ok": integrity_rows == ["ok"],
        "integrity_error": integrity_error,
        "schema_error": schema_error,
        "schema_objects": tables,
        "content_exported": False,
        "limitations": [
            "Schema and row counts do not establish the meaning, provenance, or completeness of the underlying records.",
            "No table content is exported by this validation helper.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sqlite", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    path = Path(args.sqlite).resolve(strict=True)
    output = Path(args.output).resolve(strict=False)
    result = inspect(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)
    print(
        f"Prepared {output} ({len(result['schema_objects'])} schema objects, "
        f"integrity_ok={result['integrity_ok']})"
    )
    return 0 if result["integrity_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
