# OpenCode live-host rerun hardening

## Reason

The advanced tooling rerun showed that the subagent loop could complete, but several OpenCode-specific issues made noninteractive live-host testing brittle.

## Issues observed

- Report creation under `reports/` was rejected when `edit` and `write` were configured with path globs. OpenCode 1.15.11 evaluated the fallback ask rule for report paths, so noninteractive runs stalled.
- Some full prompts passed as long command-line arguments left an `opencode` process running before normal logging. Passing the detailed test brief as an attached file avoided the startup hang.
- The examiner used avoidable live-host command shapes: `cmd /c ver`, `Get-Process -IncludeUserName` without elevation, full-process `StartTime` sorting, DMTF timestamp conversion, and broad directory listings.
- Browser profile directory enumeration surfaced credential-store filenames even though the prompt at that time treated credential stores as outside the narrow metadata pass. The later sensitive-artifact collection update supersedes that default exclusion.

## Decision

- Set the OpenCode examiner `edit` and `write` permissions to `allow` so ignored Markdown report generation works in noninteractive runs. The examiner prompt still limits writes to requested reports or explicitly scoped ignored notes, and repo hygiene validation protects commits.
- Keep helper subagents mandatory. The successful rerun invoked the senior tooling specialist, researcher, provisioner, and peer reviewer.
- Tighten live-host command guidance to prefer native PowerShell, create the report stub before collection, avoid shell-based report writes, avoid broad scriptblocks, filter file listings to the investigation window, and use explicit browser-artifact paths instead of whole-profile enumeration.

## Verification

- `opencode run` health check completed with the configured GPT-5.5 model path.
- A report-write smoke test completed after changing examiner `edit` and `write` to `allow`.
- The full attached-prompt run completed and wrote a generic ignored report under `reports/`; peer review returned `ready with caveats`.
- A final attached-prompt rerun completed and wrote a second generic ignored report under `reports/`.
- Peer review ran twice on the final rerun: first `ready with caveats`, then `ready` after wording and repeatability revisions.

## Follow-up

Future OpenCode tests should prefer `--file` for long live-host prompts and should treat permission rejections or large noisy command outputs as workflow bugs to fix in prompts or project permissions.
