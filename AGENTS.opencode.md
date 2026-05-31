# OpenCode runtime instructions

These instructions are the lean OpenCode runtime layer for Forensic Copilot. `AGENTS.md` is also intentionally compact because OpenCode auto-loads it; the expanded repository policy is in `docs/repository-policy.md`.

## Mission

Forensically analyze the scoped evidence source and maintain a defensible Markdown report. Preserve originals, stay inside the stated authority and scope, separate observation from inference, and record limitations and blockers precisely.

## Mandatory OpenCode loop

- Only `forensic-examiner` is user-facing.
- The examiner's first OpenCode tool call in each run must be `task` to `forensic-senior-tooling-specialist`.
- The examiner must not call `todowrite`, `bash`, `read`, `grep`, or host collection before the opening senior Task.
- Every Task call must use `description`, `subagent_type`, and `prompt`.
- Do not use `command`, `title`, `agent`, or `name` instead of `description`.
- Keep the first Task prompt under 30 words. It only needs short case facts and the required platform/research/provision sequence; use one semicolon-separated line and never paste the full user request or a newline. For local Gemma-style runs, the opening Task must be emitted immediately, keep `description`, `subagent_type`, and `prompt` in that order, and never end the argument object with a period.
- The opening Task may include short data-boundary facts such as `io known` or `io unknown` when they fit under 30 words; do not paste long paths or expand the first Task to explain them.
- The senior tooling specialist must call `forensic-platform-profiler` first when platform facts are unclear, then `forensic-tool-researcher`, then `forensic-tool-provisioner` before handing work back to the examiner.
- If evidence OS, evidence mode, runner/evidence boundary, filesystem/logging architecture, or host role is unclear, route through `forensic-platform-profiler` before broad collection or OS-specific tool choice.
- Do not assume Windows from examples or Linux from the runner. Platform profile controls artifact priorities and tool choice.
- Establish data-location boundaries before broad collection: input/read roots, compute/staging roots, and output/report/export roots. If the user gave only a path, default to that path as input scope, ignored analyst-controlled case/tool/artifact paths for compute, and the requested or safe ignored report path for output.
- Ask after the mandatory senior handoff when missing data-location boundaries could materially affect legality, policy, contamination risk, remote/cloud compute, or the ability to proceed. Do not read outside input roots, stage or cache outside compute roots, use remote/cloud compute, or write outside output roots without approval.
- BitLocker is a strong Windows-evidence signal and E01 is a strong dead-box disk-image signal. Use those facts to avoid unnecessary platform-profiler turns on slow local models unless another fact contradicts them.
- After the senior handoff, use `forensic-evidence-collector` for scoped collection, `forensic-artifact-router` for parser or specialist-lane selection, `forensic-timeline-analyst` for timeline correlation, `forensic-report-challenger` for adversarial report review, and `forensic-publication-redactor` before publication or push.
- Match requested depth: quick triage collects the minimum defensible source set; comprehensive examination preserves or inventories every relevant in-scope artifact class.
- Offline and no-download runs must continue through the helper loop. If selected tools cannot be fetched or used, call `forensic-script-author` and then `forensic-script-reviewer`; generated code cannot run until review returns `SCRIPT_REVIEW: approved-for-controlled-use`.
- In OpenCode, the senior tooling specialist is a task-only coordinator; it should not read files, run shell commands, search the web directly, or keep its own todo list.
- If any required helper stalls, is denied, returns an empty or incomplete note, or hits a provider error, stop at that helper blocker and retry the same helper path with a narrower prompt. Do not collect evidence by bypassing mandatory subagents.
- If the provisioner returns no visible content, lacks `FLOW:`, or gives fewer than 3 concrete execution lines, the senior must retry `forensic-tool-provisioner` with a narrower visible-output prompt before handing work back to the examiner.
- Treat local provider failures such as `ECONNRESET`, `ConnectionRefused`, timeout, or failed `/health` or `/v1/models` checks as blocked helper-loop failures until the backend is restored.
- For llama.cpp-backed local Gemma runs, reasoning may stay enabled, but the backend must be preflighted with `scripts/check_opencode_llamacpp_backend.py --smoke-tool-call`. If hidden reasoning consumes the whole first turn and no visible senior Task appears, treat it as a harness failure; increase output cap or use a finite reasoning budget, then retry the same helper path.
- Run peer review before final handoff on substantial reports.

## Local-model bounds

- Keep helper prompts narrow and specific.
- Keep `forensic-platform-profiler` text-only in OpenCode. It should infer from the prompt or return `discovery_needed`, not load shell or broad file tool schemas.
- Require platform-profiler notes of 10 lines or fewer, researcher notes of 8 lines or fewer, provisioner notes of 10 lines or fewer, and senior handoffs of 12 lines or fewer.
- Require collector notes of 12 lines or fewer, router notes of 10 lines or fewer, timeline notes of 12 lines or fewer, challenger notes of 12 lines or fewer, and redactor notes of 10 lines or fewer.
- Require script-author notes of 12 lines or fewer and script-reviewer notes of 12 lines or fewer.
- Require provisioner notes to begin with visible `FLOW:` text. A successful empty provisioner result is still a failed helper loop.
- Use local SearXNG with 3 or fewer results for research when available.
- OpenCode `websearch` is denied for the researcher in this repo; use narrow `webfetch` only for known official upstream pages, or use local docs and label `OFFLINE-SOURCE-BASIS` when web access is unavailable.
- Durable case state belongs in report, artifact, and acquisition files, not in model context.

## Live Windows collection from WSL

- Treat WSL as the runner and Windows as the evidence source unless the prompt says otherwise.
- Use low-impact, read-only `powershell.exe -NoProfile -Command` calls for Windows collection.
- Capture collection start and timezone once, compute one fixed absolute investigation window, and reuse that literal window across all artifact sources.
- When capturing time, do not append `Z` to local `Get-Date` output. Record local ISO time, Windows timezone, and UTC ISO separately if needed; use local literal timestamps without `Z` for Windows event-log filters unless the command explicitly converts to UTC.
- Do not put raw PowerShell `$` variables or `$_` inside WSL/bash double-quoted command strings.
- Do not run WSL-to-Windows PowerShell commands that contain scriptblock filters such as `Where-Object { ... }` or `ForEach-Object { ... }`. Use property-form filters such as `Where-Object StartTime -GE [datetime]'YYYY-MM-DDTHH:MM:SS'`, or collect the bounded source without inline filtering and analyze the saved CSV/JSON.
- Before executing a WSL PowerShell command, inspect the literal command text. If it contains `Where-Object {`, `ForEach-Object {`, `+.`, `.IncludeUserName`, raw `$` variables, `Now.AddHours`, or `&&`, rewrite it first.
- Do not use `Get-Process -IncludeUserName`, `.IncludeUserName`, or owner-filtered process commands in WSL live triage unless the session is already confirmed elevated and the exact command has been tested. Collect a process snapshot with `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate` and use event logs or session artifacts for user attribution.
- Do not join independent evidence sources with `&&` or other short-circuit chains. Run each source as its own tool call, or ensure a per-source error is written and later sources still run.
- Treat `NoMatchingEventsFound`, empty process lists, and empty network lists as evidence results. Write an empty CSV/JSON or status file with the source, fixed window, row count `0`, and error or empty-result reason, then continue collecting other sources.
- After a broad source returns `NoMatchingEventsFound`, a non-zero event-log exit, or zero rows, do not start the next evidence source until a status file exists under the case artifact directory. Use OpenCode write/edit tools for status files when shell-safe status creation would require PowerShell variables.
- After the senior handoff, the examiner may create directories and capture current time/timezone, but must write the Markdown report stub before the first broad evidence collection command.
- Broad queries must write full results to controlled CSV or JSON files under `artifacts/` or `acquisitions/` and print only path, row count, and a small preview.
- Preserve or inventory sensitive in-scope artifacts such as cookies, tokens, credential stores, browser login databases, password-manager data, keys, and `.env` files without printing plaintext secrets unless the case specifically requires disclosure.
- Write Markdown reports with OpenCode edit/write tools, not shell redirection.

## Report order

Start or update the Markdown report early. Put `## Executive summary` first, `## Findings` immediately after it, and detailed scope, method, tool versions, limitations, and evidence inventory below the answer-oriented sections.

## Publication hygiene

Keep committed repository content generic. Do not commit real usernames, hostnames, absolute local paths, live case outputs, evidence artifacts, screenshots, hashes, or investigator notes unless they are intentionally sanitized placeholders.
