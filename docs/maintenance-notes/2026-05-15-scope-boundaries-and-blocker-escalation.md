# Forensic Agent Maintenance Note

## Trigger for review

A case report on a split EWF set relied on derived artifacts outside the supplied evidence path and described the blocker too vaguely to justify the fallback.

## Files reviewed

- `AGENTS.md`
- `README.md`
- `docs/peer-review-process.md`
- `docs/limitations.md`
- `docs/example-investigation.md`
- `.github/agents/forensic-examiner.agent.md`
- `.github/agents/forensic-peer-reviewer.agent.md`
- `.github/agents/forensic-maintainer.agent.md`

## Reusable issue identified

- the workflow needed a harder scope-boundary rule around neighboring outputs and prior exports
- blocker language needed to force the examiner to say what failed and what decision was required next
- peer review needed to treat scope leaks and vague blocker statements as first-class review targets

## Lessons learned or new guidance

- provenance alone is not enough to make an out-of-scope artifact fair game
- when a direct step is blocked, the user should hear the concrete blocker before the workflow shifts to a weaker or broader evidence base
- reports are easier to trust when scope errors are called out plainly instead of softened into generic limitations

## Changes applied or proposed

- added repo-level scope-boundary and blocker-escalation rules
- updated the examiner to stop on out-of-scope fallbacks and ask for direction
- updated peer review and maintainer review to catch scope leaks and vague blocker language
- updated the README, limitations doc, and example intake questions to reflect the stricter scope model

## Guardrail checks

- preservation-first handling preserved
- scope discipline strengthened
- Markdown reporting preserved
- loop compatibility preserved

## Privacy check

- maintenance note kept generic
- no case-specific paths outside placeholders were added to public-facing guidance

## What to watch on the next run

- whether the examiner asks before using prior exports outside the supplied case path
- whether blocker sections explain the actual decision point instead of hiding behind generic environment language
- whether peer review catches scope drift before release
