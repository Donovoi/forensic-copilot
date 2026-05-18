# Forensic Agent Maintenance Note

## Trigger for review

User feedback on a path-only `E01` intake showed two reusable gaps:

- the workflow still pushed Linux image-toolchain setup back to the user instead of treating it as an internal opening action
- the examiner still depended too much on the user restating baseline handling that should already be implied by a forensic image request

## Files reviewed

- `README.md`
- `.github/agents/forensic-examiner.agent.md`
- `.github/agents/forensic-toolsmith.agent.md`
- `docs/tooling-matrix.md`
- `docs/example-investigation.md`
- `docs/sources.md`

## Reusable issue identified

- path-only image requests were treated as incomplete instructions instead of enough context to begin conservatively
- Linux `E01` readiness was described like a user step rather than a toolsmith responsibility
- public examples still implied the user needed to ask explicitly for preservation-first handling, scope discipline, Markdown case recording, and triage-first behavior

## Lessons learned or new guidance

- a forensic image path alone is enough to infer preservation-first, scope-limited triage and a Markdown case record
- when the evidence type clearly implies a minimal Linux baseline stack, the helper tooling path should attempt that setup automatically before surfacing a blocker
- `libewf` belongs in the tracked Linux-friendly baseline for `E01` / EWF handling

## Changes applied or proposed

- updated the examiner to infer default intake posture from path-only image requests and to start the Markdown case record automatically
- updated the examiner to treat minimal Linux image-toolchain setup as part of the opening workflow
- updated the toolsmith to auto-stage the minimal supported baseline when feasible instead of handing setup back by default
- added `libewf` to the tooling matrix and source basis
- simplified README and example prompts so the defaults are implied rather than manually restated

## Guardrail checks

- preservation-first handling strengthened
- scope discipline preserved
- Markdown reporting preserved
- loop compatibility preserved
- Linux-first tool selection clarified without pretending Windows-first tools are native on Linux

## Privacy check

- examples remain placeholder-based
- no real case outputs or identifying details were added to public docs
- no workstation-specific paths were added to the published guidance

## What to watch on the next run

- whether path-only image requests now proceed without redundant clarification
- whether the toolsmith attempts the minimal Linux baseline before surfacing setup as a blocker
- whether examples stay aligned with the inferred-default behavior
