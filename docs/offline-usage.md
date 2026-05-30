# Offline and No-Download Usage

Forensic Copilot is designed to keep working when the environment cannot reach GitHub, Copilot, package managers, or the public web.

## Operating Modes

- **Online:** the tooling researcher may check current upstream docs and the provisioner may stage approved tools.
- **Restricted:** web access exists but downloads, package installs, or external clones are blocked.
- **Offline:** no web or package access is available; the workflow relies on local docs, installed tools, native OS capabilities, and generated scripts.

## Offline Source Order

1. Case scope, legal authority, and local SOPs.
2. Local repo guidance: `AGENTS.md`, `docs/repository-policy.md`, `docs/tooling-matrix.md`, and `docs/sources.md`.
3. Installed forensic tools and their local `--version` or help output.
4. Native OS commands and APIs.
5. Generated standard-library scripts, but only after review.

## Generated Script Fallback

Use the fallback when a case needs repeatable collection or parsing and selected tools cannot be downloaded, installed, cloned, licensed, or run.

The required path is:

1. `Forensic Tool Researcher` labels local-only basis as `OFFLINE-SOURCE-BASIS`.
2. `Forensic Tool Provisioner` returns `SCRIPT_FALLBACK_REQUIRED` with runtime, input, output, logging, and validation needs.
3. `Forensic Script Author` writes the smallest read-only script under an ignored case or tool-cache path.
4. `Forensic Script Reviewer` performs static review, syntax validation, dry-run or fixture validation, log checks, and hashes where practical.
5. The examiner may run the script only after `SCRIPT_REVIEW: approved-for-controlled-use`.

## Script Safety Requirements

Generated scripts must:

- take explicit input, output, and time-window arguments
- write structured outputs and status files
- log command line, runtime, start/end times, row counts, warnings, and errors
- record zero-row and blocked-source results
- avoid writes to evidence or unrelated system state
- avoid package installation, downloads, network calls, service changes, and log clearing
- avoid printing plaintext secrets unless the case explicitly requires disclosure

If any check fails, revise the script and review again before operational use.
