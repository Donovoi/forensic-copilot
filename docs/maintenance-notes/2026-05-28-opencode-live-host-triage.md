# Forensic Agent Maintenance Note

## Trigger for review

OpenCode testing showed that the custom examiner could load with `openai/gpt-5.5`, but a live-host triage run stalled after the examiner delegated immediately to the toolsmith helper. The helper attempted a compound Windows command probe before the examiner collected artifacts or wrote the requested report.

## Files reviewed

- `README.md`
- `AGENTS.md`
- `.github/agents/forensic-examiner.agent.md`
- `.github/agents/forensic-toolsmith.agent.md`
- `docs/tooling-matrix.md`
- `docs/privacy-and-redaction.md`
- `scripts/validate_repo_hygiene.py`
- `opencode.json`

## Reusable issue identified

- OpenCode does not automatically treat GitHub Copilot `.agent.md` files as runnable project agents without project configuration.
- Helper-subagent delegation must be configured explicitly for OpenCode so it remains part of every loop.
- The examiner needed explicit blocker handling for helper stalls: narrow and retry the helper rather than bypassing it.
- Windows live-host triage needed stronger instruction to use small, bounded, read-only commands instead of compound shell probes.
- The hygiene validator scanned ignored local case-output directories, which made a successful ignored `reports/` run conflict with pre-push validation.

## Lessons learned or new guidance

- The portable workflow should keep helper-agent instructions available as OpenCode subagent prompts, not only passive context.
- OpenCode project configuration should point directly at the examiner prompt, set the intended OpenAI model, and keep helper prompts loaded.
- For live Windows host triage, no-install built-in commands are the right first-pass path unless scope justifies a broader collection method.

## Changes applied or proposed

- Added `opencode.json` with `forensic-examiner` as the default project agent and `openai/gpt-5.5` as the model.
- Added OpenCode setup and run guidance to the README.
- Required OpenCode helper use through the Task tool and added instructions to stop, narrow, and retry if a helper stalls.
- Added Windows live-host triage command constraints to the examiner and toolsmith guidance.
- Updated the tooling matrix with a live Windows host caution.
- Ignored `.env` and `.env.*` files so local OpenAI credentials stay out of published content.
- Updated the hygiene validator to skip ignored evidence, report, and tool-cache directories.
- Documented the validator skip behavior in the privacy checklist.

## Guardrail checks

- preservation-first handling preserved
- scope discipline preserved
- Markdown reporting preserved
- loop compatibility preserved through mandatory helper subagents
- public content remained generic and non-identifying

## Privacy check

- No live case paths, hostnames, user names, browser history, logs, or generated reports were added.
- The OpenCode examples use placeholders and generic authorized-host wording.

## What to watch on the next run

- whether OpenCode completes the live-host report after successful toolsmith and peer-review subagent calls
- whether the helper notes are specific enough for defensibility
- whether command permissions need additional safe read-only patterns after more Windows runs
