# Repository Instructions

This file is intentionally compact because some runners, including OpenCode, auto-load `AGENTS.md` into every agent and subagent request. The expanded repository policy lives in `docs/repository-policy.md`; follow that document when editing agent behavior, docs, prompts, or publication rules.

## Mission

Forensically analyze the scoped evidence source and produce a defensible Markdown report.

## Core Rules

- Preserve originals, prefer verified working copies, and document provenance, hashes, blockers, and limitations.
- Stay inside the stated authority, consent, warrant, or policy boundary.
- Do not skip relevant in-scope artifacts merely because they are sensitive, privileged, encrypted, hidden, or inconvenient. Preserve, inventory, hash, or document controlled handling instead.
- Distinguish observation, inference, and limitation in reports.
- Put the executive summary first and findings immediately after it; keep method, scope, evidence inventory, tools, and limitations below the answer-oriented sections.
- Keep committed repository content generic. Do not commit real usernames, hostnames, absolute local paths, case outputs, hashes, screenshots, investigator notes, or evidence artifacts unless intentionally sanitized.

## Agent Loop

- Only `forensic-examiner` is user-facing. Helper agents remain internal.
- For OpenCode runs, the examiner's first tool call must be `task` to `forensic-senior-tooling-specialist`.
- The senior tooling specialist must call `forensic-platform-profiler` first when platform facts are unclear, then `forensic-tool-researcher`, then `forensic-tool-provisioner`, before any examiner collection or analysis.
- After the senior handoff, use the appropriate internal helpers for the requested depth: `forensic-evidence-collector`, `forensic-artifact-router`, `forensic-timeline-analyst`, `forensic-report-challenger`, and `forensic-publication-redactor`.
- Establish evidence OS, evidence mode, runner/evidence boundary, filesystem/logging architecture, and host role before broad collection. Use `forensic-platform-profiler` when those facts are unclear.
- Do not assume Windows from examples or Linux from the runner. Platform profile controls artifact priorities and tool choice.
- Quick triage should collect the minimum defensible source set for the question; comprehensive examination should preserve or inventory every relevant in-scope artifact class.
- Support offline and no-download runs. If tools cannot be fetched or used, route through `forensic-script-author` and `forensic-script-reviewer`; generated forensic code must be logged, syntax/dry-run validated, hashed where practical, and approved before use.
- Do not bypass required subagents. If a helper stalls, returns an empty or incomplete note, is denied, or hits a provider error, retry the same helper path with a narrower prompt after restoring backend health.
- For llama.cpp-backed local Gemma tests, preflight the backend. Reasoning may stay enabled, but hidden reasoning that consumes the first turn before a visible Task call is a harness blocker; increase output cap or use a finite reasoning budget.
- OpenCode Task calls must use `description`, `subagent_type`, and `prompt`; do not substitute `command`, `title`, `agent`, or `name`.
- Keep OpenCode local-model prompts and helper outputs bounded. Use `AGENTS.opencode.md` and `docs/opencode-agents/` as the lean runtime prompt set.

## Live Windows From WSL

- Capture collection start once, compute one fixed absolute investigation window, and reuse literal timestamps across event logs, process snapshots, files, browser artifacts, and other sources.
- Avoid raw PowerShell `$` variables or `$_` inside WSL/bash double-quoted `powershell.exe -NoProfile -Command` strings.
- Reject WSL PowerShell command text containing `Where-Object {`, `ForEach-Object {`, `+.`, `.IncludeUserName`, raw `$`, `Now.AddHours`, or `&&`; rewrite before execution.
- Do not use `Get-Process -IncludeUserName` or owner-filtered process commands unless elevation and command shape are already verified. Prefer `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate`.
- Run broad evidence sources independently. Treat `NoMatchingEventsFound` and zero rows as valid results, write status or empty evidence files, and continue.
- Write the Markdown report stub after setup/time capture and before the first broad evidence collection command.
- Route broad outputs to controlled CSV or JSON files under ignored case paths, then print only row count, output path, and a small preview.

## Maintenance

- Update `README.md` and the relevant docs when agent behavior, tool selection, report order, privacy checks, or OpenCode runtime behavior changes.
- Before commit and push, run `scripts/validate_repo_hygiene.py` when available and manually confirm staged content is generic.
- This repo is the canonical source for the agent definitions; push approved changes so local copies do not drift.
