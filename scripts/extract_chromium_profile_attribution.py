#!/usr/bin/env python3
"""Extract bounded identity fields from a Chromium Preferences file."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ACCOUNT_FIELDS = (
    "account_id",
    "edge_account_cid",
    "edge_account_first_name",
    "edge_account_last_name",
    "edge_account_location",
    "edge_account_oid",
    "edge_account_puid",
    "edge_account_tenant_id",
    "edge_account_type",
    "email",
    "full_name",
    "gaia",
    "given_name",
    "hd",
    "locale",
)
PROFILE_FIELDS = ("name", "avatar_index", "using_default_name")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(16 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def selected(source: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {
        field: source[field] for field in fields if source.get(field) not in (None, "")
    }


def extract(preferences: Path) -> dict[str, object]:
    data = json.loads(preferences.read_text(encoding="utf-8"))
    accounts = [
        selected(account, ACCOUNT_FIELDS)
        for account in data.get("account_info", [])
        if isinstance(account, dict)
    ]
    accounts = [account for account in accounts if account]
    profile = data.get("profile", {})
    google_username = (
        data.get("google", {}).get("services", {}).get("username")
        if isinstance(data.get("google"), dict)
        else None
    )
    return {
        "schema_version": 1,
        "source_path": str(preferences.resolve()),
        "source_size_bytes": preferences.stat().st_size,
        "source_sha256": sha256(preferences),
        "profile": selected(profile, PROFILE_FIELDS)
        if isinstance(profile, dict)
        else {},
        "accounts": accounts,
        "google_services_username": google_username or None,
        "limitations": [
            "Profile identity fields show an account configured in this browser profile; they do not independently prove legal ownership of the device or activity by that person.",
            "Fields can be stale, user-entered, pseudonymous, shared, or associated with a compromised account.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preferences", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    preferences = Path(args.preferences).resolve(strict=True)
    output = Path(args.output).resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    result = extract(preferences)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)
    print(f"Prepared {output} ({len(result['accounts'])} account record(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
