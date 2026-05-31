# Data Location Boundaries

## Trigger

Forensic runs may happen in labs, enterprises, or offline environments where the examiner is allowed to read evidence from one place, process or stage tools in another place, and write reports or exports somewhere else. Earlier prompts emphasized case scope but did not name those input, compute, and output locations as first-class boundaries.

## Change

- Added input/read, compute/staging, and output/report/export boundary intake to the README, repository policy, and examiner prompts.
- Preserved the bare-path default: a supplied evidence path is enough to begin conservative triage.
- Required the agent to ask before reading outside input scope, staging or caching on unapproved storage, using remote/cloud compute, or writing outside approved outputs.
- Updated OpenCode guidance so the first mandatory senior Task can stay compact while still carrying short `io known` or `io unknown` markers when useful.

## Guardrails preserved

- preservation-first handling
- scope discipline
- mandatory subagent loop
- offline and no-download fallback
- reader-first Markdown reports
- generic public repository content
