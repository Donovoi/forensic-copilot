# Expanded Subagent Loop

## Why this changed

Testing showed that the tooling loop could select and prepare forensic commands, but the examiner still had too much operational load after the senior handoff. Collection, artifact routing, timeline analysis, adversarial challenge, and publication redaction are different jobs with different failure modes.

## Accepted changes

- Added `Forensic Evidence Collector` for scoped collection, status files, row counts, hashes, and collection handoff without analysis.
- Added `Forensic Artifact Router` for parser and specialist-lane prioritization without collecting or concluding.
- Added `Forensic Timeline Analyst` for normalized user and system activity timelines.
- Added `Forensic Report Challenger` for adversarial review of attribution, causality, alternative explanations, and release-blocking report claims.
- Added `Forensic Publication Redactor` for pre-publication, pre-export, pre-commit, and pre-push leakage review.
- Added lean OpenCode versions of each new helper and registered them in `opencode.json`.
- Preserved the existing rule that the examiner's first helper is the senior tooling specialist, and the senior must call researcher then provisioner before collection.
- Added local-model output caps for the new helpers so the full chain can reach the publication redactor without context bloat.

## Triage boundary

The collector and router now distinguish `triage`, `targeted`, and `comprehensive` depth. Quick triage should collect the minimum defensible source set needed to answer or prioritize the question. Comprehensive examination should preserve or inventory every relevant in-scope artifact class. Sensitive artifacts remain controlled evidence when in scope; they are not printed or published casually.

## Validation expectations

Future tests should cover each new helper in isolation and then the combined flow:

- collector returns collection depth, outputs, status files, hashes, blockers, and next analysis inputs
- router returns priority lanes, tools, controlled sensitive stores, blocked lanes, and timeline inputs
- timeline analyst returns key events, attribution assessment, gaps, confidence, and inputs
- report challenger returns must-fix claims, attribution risks, alternatives, safer wording, and residual risk
- publication redactor returns a release decision and the checks it ran

## Test notes

OpenCode isolated registration tests first exposed a provider issue: the local setup listed `github-copilot/gpt-5.5`, but Copilot rejected that model at request time with `model_not_supported`; later Copilot GPT-family probes hit quota. The new helper behavior was therefore tested with a supported non-Gemma OpenCode model override.

Isolation tests confirmed output markers for:

- `COLLECTION`
- `ROUTE`
- `TIMELINE`
- `CHALLENGE`
- `REDACTION`

The first combined run invoked every helper but allowed the challenge output to grow too large, and the final redactor call hit an upstream provider error. After adding output caps, a combined fixture-only run invoked the senior tooling specialist, researcher, provisioner, evidence collector, artifact router, timeline analyst, report challenger, and publication redactor in order and exited cleanly without live commands or file writes.
