# Forensic Agent Maintenance Note

## Trigger for review

User feedback on the public docs highlighted two issues:

- the prose still leaned on repetitive contrast sentences that made the writing sound machine-generated
- the workflow stopped at Markdown even when a peer-reviewed formal report package would be useful

## Files reviewed

- `README.md`
- `AGENTS.md`
- `.github/agents/forensic-examiner.agent.md`
- `.github/agents/forensic-toolsmith.agent.md`
- `.github/agents/forensic-maintainer.agent.md`
- `.github/agents/forensic-peer-reviewer.agent.md`
- `docs/peer-review-process.md`
- `docs/self-update-loop.md`
- `docs/tooling-matrix.md`
- `docs/limitations.md`
- `docs/sources.md`

## Reusable issue identified

- some key docs still used polished contrast phrasing often enough to undermine credibility
- the workflow needed a clear rule for when a formal report package may be generated
- the tooling split for local report export needed to be explicit so the repo would not drift into browser-specific or WASM-specific complexity without a strong reason

## Lessons learned or new guidance

- direct technical prose reads as more credible than rhetorical contrast when the subject is forensic method
- `uv` is a good fit for local Python-side orchestration and Python CLI helpers, but it is not the install path for non-Python binaries such as `pandoc`
- formal export belongs after peer review, with Markdown kept as the canonical record

## Changes applied or proposed

- added repo-level writing-style guidance that discourages formulaic "not X but Y" prose
- tightened the README language and added formal export documentation
- updated the examiner, toolsmith, peer reviewer, and maintainer prompts to reflect the new prose and export rules
- added a Linux-first formal export path using a local Python helper, `pandoc`, and a PDF backend when available
- updated the hero illustration badge to reflect formal output support

## Guardrail checks

- preservation-first handling preserved
- scope discipline preserved
- Markdown remains the canonical report format
- peer review still gates release
- loop compatibility preserved

## Privacy check

- new examples use placeholders only
- no case-specific outputs or workstation paths were added to public docs
- generated formal outputs are ignored by `.gitignore`

## What to watch on the next run

- whether the docs continue to slide back into repetitive contrast phrasing
- whether the export script needs an additional PDF backend for common Linux setups
- whether examiners try to use formal export before peer review closes as `ready`
