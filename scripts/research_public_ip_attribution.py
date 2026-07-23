#!/usr/bin/env python3
"""Collect reproducible public-registration leads for evidence-observed IPs.

Only the IP addresses supplied on the command line are sent to the listed public
registration services.  No evidence file, hash, credential, or private artifact
is uploaded.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


USER_AGENT = "forensic-copilot-public-attribution/1.0 (+https://github.com/Donovoi/forensic-copilot)"
ENDPOINTS = {
    "ripe-rdap": "https://rdap.db.ripe.net/ip/{ip}",
    "ripe-network-info": "https://stat.ripe.net/data/network-info/data.json?resource={ip}",
    "ripe-whois": "https://stat.ripe.net/data/whois/data.json?resource={ip}",
    "ripe-reverse-dns": "https://stat.ripe.net/data/reverse-dns/data.json?resource={ip}",
    "ripe-routing-history": "https://stat.ripe.net/data/routing-history/data.json?resource={ip}&min_peers_seeing=0",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_bytes_atomic(path: Path, value: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(value)
    temporary.replace(path)


def write_json_atomic(path: Path, value: object) -> None:
    write_bytes_atomic(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def fetch(url: str, timeout: float) -> tuple[int, str, bytes]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.headers.get_content_type(), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get_content_type(), exc.read()


def collect_ip(ip_text: str, output_root: Path, timeout: float) -> dict[str, Any]:
    ip = str(ipaddress.ip_address(ip_text))
    ip_root = output_root / ip
    ip_root.mkdir(parents=True, exist_ok=True)
    requests = []
    for name, template in ENDPOINTS.items():
        url = template.format(ip=ip)
        retrieved_utc = utc_now()
        try:
            status, content_type, body = fetch(url, timeout)
            body_path = ip_root / f"{name}.json"
            write_bytes_atomic(body_path, body)
            requests.append(
                {
                    "name": name,
                    "url": url,
                    "retrieved_utc": retrieved_utc,
                    "http_status": status,
                    "content_type": content_type,
                    "response_path": str(body_path.resolve()),
                    "response_size_bytes": len(body),
                    "response_sha256": sha256_bytes(body),
                    "status": "completed"
                    if 200 <= status < 300
                    else "completed_with_limit",
                }
            )
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            requests.append(
                {
                    "name": name,
                    "url": url,
                    "retrieved_utc": retrieved_utc,
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    try:
        ptr = socket.gethostbyaddr(ip)[0]
        ptr_status = "completed"
        ptr_error = None
    except (OSError, socket.herror, socket.gaierror) as exc:
        ptr = None
        ptr_status = "completed_with_limit"
        ptr_error = f"{type(exc).__name__}: {exc}"
    return {
        "ip": ip,
        "public_queries": requests,
        "current_ptr": ptr,
        "ptr_status": ptr_status,
        "ptr_error": ptr_error,
        "interpretation_limits": [
            "Registration and routing records identify network resources and providers, not necessarily a device owner, hosting subscriber, or human operator.",
            "PTR and routing data are current at collection time and may differ from conditions when the evidence was captured.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", action="append", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    output_root = Path(args.output_root).resolve(strict=False)
    output_root.mkdir(parents=True, exist_ok=True)
    result = {
        "schema_version": 1,
        "collected_utc": utc_now(),
        "collector": Path(__file__).name,
        "privacy_scope": "Only command-line IP addresses were submitted to public services.",
        "sources": [
            {"name": name, "url_template": url} for name, url in ENDPOINTS.items()
        ],
        "results": [collect_ip(ip, output_root, args.timeout) for ip in args.ip],
    }
    output_path = output_root / "query-log.json"
    write_json_atomic(output_path, result)
    print(f"Prepared {output_path} for {len(result['results'])} IP address(es)")
    return (
        0
        if all(
            any(query.get("status") == "completed" for query in item["public_queries"])
            for item in result["results"]
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
