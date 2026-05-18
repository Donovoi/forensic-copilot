# Forensic Agent Maintenance Note

## Trigger for review

User feedback asked for a stronger guarantee that published changes stay generic and non-identifying on every future update, not just when a maintainer happens to remember.

## Files reviewed

- `AGENTS.md`
- `docs/privacy-and-redaction.md`
- `docs/sources.md`
- `docs/maintenance-notes/2026-05-15-peer-review-and-server-routing.md`

## Reusable issue identified

- the repo already required a privacy sweep before pushing, but the rule did not explicitly cover every commit and staged diff review
- the public privacy checklist did not clearly call out Git author identity and remote ownership as separate exposure paths
- one source-basis note still mentioned a named individual where a generic practitioner-literature reference was sufficient

## Lessons learned or new guidance

- a clean repository tree is necessary but not sufficient for anonymous publication
- commit author identity, remote ownership, and hosting metadata can still identify the publisher even when the content is fully sanitized
- public workflow docs should prefer generic references when a named individual is not necessary to preserve the method

## Changes applied or proposed

- strengthened the repo rule from a push-only privacy sweep to a repo-wide sweep before every commit and push
- required staged-diff review as part of the published privacy checklist
- documented Git author identity and remote ownership as explicit metadata exposures
- replaced one named-individual practitioner reference with a generic literature reference

## Guardrail checks

- preservation-first handling preserved
- scope discipline preserved
- Markdown reporting preserved
- loop compatibility preserved
- published content made more generic and non-identifying

## Privacy check

- reviewed tracked repository content for real names, usernames, emails, local paths, and evidence identifiers
- found identifying details only in local Git metadata, not in tracked repository content
- updated public docs to warn that Git metadata remains a separate exposure path

## What to watch on the next run

- whether every future change gets a repo-wide privacy sweep before commit and push
- whether staged diffs are reviewed for identifying content instead of only relying on whole-repo searches
- whether public docs remain generic when a named source or example is not actually required
