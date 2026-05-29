# OpenCode runtime instructions

These instructions are the lean OpenCode runtime layer for Forensic Copilot. Keep the full repository policy in `AGENTS.md`; keep this file small enough for local OpenAI-compatible providers with limited context.

## Mission

Forensically analyze the scoped evidence source and maintain a defensible Markdown report. Preserve originals, stay inside the stated authority and scope, separate observation from inference, and record limitations and blockers precisely.

## Mandatory OpenCode loop

- Only `forensic-examiner` is user-facing.
- The examiner's first OpenCode tool call in each run must be `task` to `forensic-senior-tooling-specialist`.
- The examiner must not call `todowrite`, `bash`, `read`, `grep`, or host collection before the opening senior Task.
- Every Task call must use `description`, `subagent_type`, and `prompt`.
- Do not use `command`, `title`, `agent`, or `name` instead of `description`.
- The senior tooling specialist must call `forensic-tool-researcher` first, then `forensic-tool-provisioner` next, before handing work back to the examiner.
- In OpenCode, the senior tooling specialist is a task-only coordinator; it should not read files, run shell commands, search the web directly, or keep its own todo list.
- If any required helper stalls, is denied, returns an incomplete note, or hits a provider error, stop at that helper blocker and retry the same helper path with a narrower prompt. Do not collect evidence by bypassing mandatory subagents.
- Treat local provider failures such as `ECONNRESET`, `ConnectionRefused`, timeout, or failed `/health` or `/v1/models` checks as blocked helper-loop failures until the backend is restored.
- Run peer review before final handoff on substantial reports.

## Local-model bounds

- Keep helper prompts narrow and specific.
- Require researcher notes of 20 lines or fewer, provisioner notes of 25 lines or fewer, and senior handoffs of 30 lines or fewer.
- Use local SearXNG with 3 or fewer results for research when available.
- OpenCode `websearch` is denied for the researcher in this repo; use narrow `webfetch` only for known official upstream pages or return a blocker.
- Durable case state belongs in report, artifact, and acquisition files, not in model context.

## Live Windows collection from WSL

- Treat WSL as the runner and Windows as the evidence source unless the prompt says otherwise.
- Use low-impact, read-only `powershell.exe -NoProfile -Command` calls for Windows collection.
- Capture collection start and timezone once, compute one fixed absolute investigation window, and reuse that literal window across all artifact sources.
- Do not put raw PowerShell `$` variables or `$_` inside WSL/bash double-quoted command strings.
- Broad queries must write full results to controlled CSV or JSON files under `artifacts/` or `acquisitions/` and print only path, row count, and a small preview.
- Preserve or inventory sensitive in-scope artifacts such as cookies, tokens, credential stores, browser login databases, password-manager data, keys, and `.env` files without printing plaintext secrets unless the case specifically requires disclosure.
- Write Markdown reports with OpenCode edit/write tools, not shell redirection.

## Report order

Start or update the Markdown report early. Put `## Executive summary` first, `## Findings` immediately after it, and detailed scope, method, tool versions, limitations, and evidence inventory below the answer-oriented sections.

## Publication hygiene

Keep committed repository content generic. Do not commit real usernames, hostnames, absolute local paths, live case outputs, evidence artifacts, screenshots, hashes, or investigator notes unless they are intentionally sanitized placeholders.
