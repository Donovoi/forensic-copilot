# Maintenance notes

These notes capture why reusable workflow changes were accepted.

They complement `docs/self-update-loop.md` by leaving a short, reviewable rationale for prompt, tooling, export, and policy updates that affect future runs.

## Index

- `2026-05-29-opencode-local-model-context.md` — keep OpenCode global instructions, role prompts, context, and helper turns lean enough for local Gemma-style providers and allow WSL Windows collection bridge commands
- `2026-05-31-local-gemma-reasoning-preflight.md` — fail fast when local llama.cpp hidden reasoning consumes the visible first Task budget
- `2026-05-30-os-aware-platform-routing.md` — add platform profiling so evidence OS and runner OS are separated before collection and tool selection
- `2026-05-30-offline-script-fallback-and-interface-docs.md` — support offline/no-download environments with generated-script review and clearer interface setup docs
- `2026-05-30-expanded-subagent-loop.md` — add collection, artifact-routing, timeline-analysis, report-challenge, and publication-redaction helpers while preserving quick-triage depth
- `2026-05-29-sensitive-artifact-collection.md` — treat sensitive artifacts as controlled evidence rather than default exclusions
- `2026-05-28-advanced-tooling-specialist.md` — add a senior tooling specialist with mandatory research and provisioning subagents for advanced DFIR tool selection
- `2026-05-28-reader-first-report-order.md` — move executive summary and findings to the top of forensic reports
- `2026-05-28-opencode-live-host-rerun-hardening.md` — harden noninteractive OpenCode report writing and live Windows command shapes after rerun testing
- `2026-05-28-opencode-live-host-triage.md` — add OpenCode project configuration, GPT-5.5 setup guidance, and inline helper-mode for live Windows triage
- `2026-05-19-blocked-access-recovery-and-carving-clarity.md` — require a blocked-access recovery branch and explicit attempted-versus-impossible deleted/unallocated/carving reporting
- `2026-05-18-repo-hygiene-and-export-portability.md` — remove local residue, add validation automation, and harden formal export portability
- `2026-05-18-portable-agent-setup.md` — keep setup and usage guidance portable across agent runners
- `2026-05-18-prepush-privacy-sweep-and-git-metadata.md` — strengthen publication-time privacy checks and metadata warnings
- `2026-05-18-auto-tooling-and-default-intake.md` — infer safe intake defaults and auto-stage Linux image tooling when feasible
- `2026-05-15-style-and-formal-output.md` — tighten writing style and formal-output guidance
- `2026-05-15-scope-boundaries-and-blocker-escalation.md` — reinforce scope limits and blocker handling
- `2026-05-15-peer-review-and-server-routing.md` — refine peer review and server-analysis routing

Some older entries predate the current maintenance-note template, but they still record the reason a reusable workflow change was made.
