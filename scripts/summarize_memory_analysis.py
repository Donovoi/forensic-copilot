#!/usr/bin/env python3
"""Hash and summarize completed Volatility outputs for coverage review."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LANE_REQUIREMENTS = {
    "compatibility_and_os": (("windows.info",),),
    "processes": (
        ("windows.pslist",),
        ("windows.psscan",),
        ("windows.pstree",),
        ("windows.cmdline",),
    ),
    "network": (("windows.netscan",),),
    "persistence": (
        ("windows.svcscan",),
        ("windows.modules",),
        ("windows.registry.scheduled_tasks",),
        ("windows.shimcachemem",),
    ),
    "user_sessions": (
        ("windows.sessions",),
        ("windows.getsids",),
        ("windows.envars",),
        ("windows.cmdscan", "windows.consoles"),
        ("windows.registry.userassist",),
    ),
    "extended_analysis": (
        ("windows.malfind",),
        ("windows.malware.psxview", "windows.psxview"),
        ("windows.malware.hollowprocesses", "windows.hollowprocesses"),
        ("windows.malware.processghosting", "windows.processghosting"),
        ("windows.malware.suspicious_threads", "windows.suspicious_threads"),
        ("windows.driverscan",),
        ("windows.filescan",),
        ("windows.handles",),
        ("windows.privileges",),
    ),
}


def parser_warnings(path: Path) -> list[str]:
    """Return material Volatility warning/error lines from a plugin stderr log."""
    if not path.is_file():
        return []
    warnings: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        normalized = line.strip()
        if normalized.startswith(("WARNING ", "ERROR ", "CRITICAL ")):
            warnings.append(normalized)
    return warnings


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(16 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path) -> dict[str, Any]:
    return {
        "path": str(path.resolve()),
        "size_bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def json_shape(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"json_status": "invalid", "json_error": f"{type(exc).__name__}: {exc}"}
    if isinstance(value, list):
        return {"json_status": "valid", "json_type": "list", "row_count": len(value)}
    if isinstance(value, dict):
        return {"json_status": "valid", "json_type": "object", "key_count": len(value)}
    return {"json_status": "valid", "json_type": type(value).__name__}


def plugin_from_path(path: Path) -> str:
    return path.name.removesuffix(".json")


def matching_runs(
    runs_by_label: dict[str, dict[str, Any]], plugin: str
) -> list[dict[str, Any]]:
    return [
        run
        for run in runs_by_label.values()
        if str(run.get("label", "")).endswith(plugin)
    ]


def summarize_lanes(
    output_by_plugin: dict[str, dict[str, Any]],
    runs_by_label: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    lanes: dict[str, dict[str, Any]] = {}
    for lane, groups in LANE_REQUIREMENTS.items():
        selected: list[dict[str, Any]] = []
        failed_runs: list[dict[str, Any]] = []
        missing_groups: list[list[str]] = []
        limited_groups: list[list[str]] = []
        for group in groups:
            group_runs = [
                run for plugin in group for run in matching_runs(runs_by_label, plugin)
            ]
            group_successes = [
                plugin
                for plugin in group
                if plugin in output_by_plugin
                and output_by_plugin[plugin].get("json_status") == "valid"
                and any(
                    run.get("exit_code") == 0
                    for run in matching_runs(runs_by_label, plugin)
                )
            ]
            for plugin in group_successes:
                selected.append(output_by_plugin[plugin])
            failed_runs.extend(run for run in group_runs if run.get("exit_code") != 0)
            if group_successes:
                if any(
                    output_by_plugin[plugin].get("parser_warnings")
                    for plugin in group_successes
                ):
                    limited_groups.append(list(group))
                continue
            if group_runs:
                limited_groups.append(list(group))
            else:
                missing_groups.append(list(group))

        if missing_groups:
            status = "incomplete"
            limitation = "One or more mandatory plugin groups were never run."
        elif limited_groups or failed_runs:
            status = "completed_with_limit"
            limitation = (
                "One or more mandatory plugin groups failed, were unsupported, or "
                "emitted material parser warnings; the attempts and warnings are retained."
            )
        else:
            status = "completed"
            limitation = None
        lanes[lane] = {
            "status": status,
            "requirements": [list(group) for group in groups],
            "plugin_outputs": selected,
            "failed_runs": failed_runs,
            "missing_groups": missing_groups,
            "limited_groups": limited_groups,
            "limitations": limitation,
        }
    return lanes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-root", required=True)
    parser.add_argument("--conversion-metadata", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    analysis_root = Path(args.analysis_root).resolve(strict=True)
    conversion_metadata = Path(args.conversion_metadata).resolve(strict=True)
    output = Path(args.output).resolve(strict=False)
    if not analysis_root.is_dir():
        parser.error("--analysis-root must be a directory")

    summary_files = sorted(analysis_root.glob("run-summary*.json"))
    if not summary_files:
        parser.error("no run-summary JSON files found")
    summaries = []
    runs_by_label: dict[str, dict[str, Any]] = {}
    for path in summary_files:
        data = json.loads(path.read_text(encoding="utf-8"))
        summaries.append(
            {**artifact(path), "run_kind": data.get("run_kind", path.stem)}
        )
        for run in data.get("runs", []):
            runs_by_label[run.get("label", f"unlabelled-{len(runs_by_label)}")] = run

    plugin_outputs = []
    for path in sorted(analysis_root.glob("*.json")):
        if path.name.startswith("run-summary"):
            continue
        plugin = plugin_from_path(path)
        plugin_outputs.append(
            {
                "plugin": plugin,
                **artifact(path),
                **json_shape(path),
                "parser_warnings": parser_warnings(
                    analysis_root / f"{plugin}.stderr.log"
                ),
            }
        )
    output_by_plugin = {item["plugin"]: item for item in plugin_outputs}

    lanes = summarize_lanes(output_by_plugin, runs_by_label)

    stderr_outputs = []
    for path in sorted(analysis_root.glob("*.stderr.log")):
        record = artifact(path)
        record["nonempty"] = path.stat().st_size > 0
        stderr_outputs.append(record)

    result = {
        "schema_version": 2,
        "created_utc": utc_now(),
        "analysis_root": str(analysis_root),
        "conversion_metadata": artifact(conversion_metadata),
        "run_summaries": summaries,
        "run_count": len(runs_by_label),
        "successful_run_count": sum(
            run.get("exit_code") == 0 for run in runs_by_label.values()
        ),
        "failed_run_count": sum(
            run.get("exit_code") != 0 for run in runs_by_label.values()
        ),
        "lanes": lanes,
        "all_plugin_outputs": plugin_outputs,
        "stderr_outputs": stderr_outputs,
        "limitations": [
            "A zero-row plugin output is negative output for that parser, not proof that an artifact or behavior never existed.",
            "The analyzed Windows dump is derived from a retained QEMU ELF source; conversion provenance remains material.",
            "Scanner-heavy outputs can contain stale or duplicate physical candidates and require corroboration.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)
    print(
        f"Prepared {output} ({result['successful_run_count']} successful, "
        f"{result['failed_run_count']} failed runs)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
