# Forensic Agent Maintenance Note

## Trigger for review

User feedback on a BitLocker-protected `E01` run showed that the workflow stopped too close to first encryption confirmation and left deleted, unallocated, slack, snapshot, and carving coverage ambiguous.

## Files reviewed

- `.github/agents/forensic-examiner.agent.md`
- `.github/agents/forensic-toolsmith.agent.md`
- `.github/agents/forensic-peer-reviewer.agent.md`
- `README.md`
- `docs/limitations.md`
- `docs/tooling-matrix.md`
- `docs/peer-review-process.md`
- `docs/example-investigation.md`

## Reusable issue identified

- blocked-access cases needed a required access-recovery branch before blocker-only handoff
- reports needed a clearer distinction between `attempted and unsuccessful`, `not attempted in this run`, and `not possible without additional access material`
- peer review needed an explicit trigger to catch wording that implied all deleted, unallocated, slack, snapshot, or carving avenues were exhausted when only a locked volume was blocked

## Lessons learned or new guidance

- encryption confirmation is not the end of the loop
- the examiner should decide separately what was possible at the whole-disk layer versus inside the locked volume
- the toolsmith should document recovery paths as attempted, blocked, deferred, or out of scope instead of stopping at the first access barrier

## Changes applied or proposed

- updated the examiner to require an access-recovery branch and layer-specific deleted, unallocated, slack, snapshot, and carving decisions
- updated the toolsmith to stage the smallest supported recovery branch and record why recovery paths were attempted, skipped, or blocked
- updated peer-review guidance so blocked-access reports must distinguish impossible work from unattempted work
- updated supporting docs and examples to reflect the same distinctions

## Guardrail checks

- preservation-first handling strengthened
- scope discipline preserved
- Markdown reporting preserved
- loop compatibility preserved

## Privacy check

- examples remain generic and placeholder-based
- no case-specific outputs or identifying details were added to published repo content

## What to watch on the next run

- whether blocked-access reports now separate locked-volume limits from whole-disk free-space or carving decisions
- whether the toolsmith documents supported recovery attempts before blocker-only handoff
- whether peer review rejects wording that treats `not attempted` as `not possible`
