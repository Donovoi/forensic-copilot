# 2026-05-30 - Offline script fallback and interface docs

## Trigger

The workflow needed first-class support for enterprise/offline environments where Copilot, web research, package managers, GitHub, GitLab, or tool downloads are unavailable.

It also needed clearer instructions for common AI interfaces rather than a long README centered mainly on one runner.

## Accepted changes

- Added `Forensic Script Author` and `Forensic Script Reviewer` as internal helpers for no-download fallback code.
- Required generated forensic scripts to be read-only toward evidence, logged, syntax/dry-run validated, hashed where practical, and approved before use.
- Updated the senior tooling loop so blocked downloads route to script authoring and review instead of silently shrinking the examination.
- Let OpenCode's tool researcher read local repo guidance so offline research can use local docs and label `OFFLINE-SOURCE-BASIS`.
- Stopped disabling Ollama in `opencode.json` so local offline providers can be configured by the operator.
- Added bridge files for Copilot, Claude Code, and Gemini CLI.
- Split interface and offline details into focused docs and rewrote the README into a shorter human-facing landing page.
- Tightened script fallback prompts after fixture testing showed the author could otherwise overclaim unsupported raw EVTX parsing or suggest system-mutating fixture setup.

## Validation expectation

Before publishing this change, verify JSON validity, repo hygiene, staged privacy, and that the OpenCode config exposes the script-author and script-reviewer agents as subagent targets. Fixture tests should confirm that the author does not fake complex parsers and that the reviewer blocks missing or unvalidated scripts.
