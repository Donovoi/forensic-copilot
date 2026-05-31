# Secret-Led Evidence Expansion

## Trigger

Controlled secret extraction was allowed, but the workflow still needed to say what happens next. In real examinations, recovered credentials, cookies, tokens, keys, recovery material, and account secrets may unlock local evidence or point to further victims and systems that need review.

## Change

- Required extracted secrets to become classified evidence leads rather than dead-end outputs.
- Added a lead index concept with source artifact, secret type, likely program/site/service, account or owner when known, local or remote use, confidence, controlled output path, and next allowed action.
- Directed local in-scope unlock or follow-on collection attempts to proceed through the normal helper loop when authority and data-location boundaries allow it.
- Required remote, cloud, third-party, or otherwise scope-expanding use to be reported to the user in redacted form and approved before login or collection unless already explicitly authorized.
- Updated collection, routing, provisioning, analysis, script review, peer review, and report challenge prompts to check for this loop.

## Guardrails preserved

- legal and policy scope discipline
- input, compute, and output boundaries
- controlled secret-output storage
- no plaintext secret leakage into public repository content
- mandatory subagent loop
- report disclosure of secret-led provenance and blockers
