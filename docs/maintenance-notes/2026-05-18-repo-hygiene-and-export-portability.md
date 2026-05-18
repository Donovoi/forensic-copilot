# Forensic Agent Maintenance Note

## Trigger for review

A repo-wide audit surfaced a few reusable cleanup problems:

- workstation-specific residue had been committed into the canonical repo
- the formal export helper still depended on a local CSS path when generating HTML
- privacy and hygiene checks were documented, but not backed by a lightweight automated validator
- the public setup guidance repeated itself and left one portability detail about `.agent.md` frontmatter too implicit

## Files reviewed

- `.gitignore`
- `README.md`
- `AGENTS.md`
- `scripts/render_formal_report.py`
- `docs/formal-report-output.md`
- `docs/privacy-and-redaction.md`
- `docs/maintenance-notes/`

## Reusable issue identified

- scratch probes and editor-local tasks can slip into the repo if the ignore rules and validation path are both too loose
- a formal HTML export should not reference a workstation-specific stylesheet path
- privacy guidance is easier to follow consistently when it includes a small automated sweep as well as manual review
- portable agent instructions need to say what to do with `.agent.md` frontmatter when the runner does not understand agent metadata

## Lessons learned or new guidance

- editor-local state and scratch probes should be ignored or removed rather than curated in the public repo by default
- formal HTML output should carry its own styling instead of pointing at a local repo path
- a lightweight validator is enough to catch obvious local-path leaks and scratch files before commit and push
- maintenance notes become easier to review over time when the directory has an index

## Changes applied or proposed

- removed committed scratch and workstation-local files from the canonical repo
- hardened `.gitignore` for `.vscode/` state and root-level `.tmp_*` scratch files
- updated the formal export helper to support `--check-deps`, `--skip-pdf`, and inline CSS for portable HTML output
- added `scripts/validate_repo_hygiene.py` and a GitHub Actions workflow to run it in CI
- updated README portability guidance to explain how to use `.agent.md` files when a runner cannot parse YAML frontmatter
- added a maintenance-note index and refreshed the relevant docs to match the new validation and export behavior

## Guardrail checks

- preservation-first handling preserved
- scope discipline preserved
- Markdown reporting preserved as the canonical source
- public-repo privacy rules strengthened
- portability improved without making the workflow depend more heavily on any one editor or vendor format

## Privacy check

- removed workstation-specific task paths from tracked repo content
- no real case artifacts, names, or identifying details were added
- the new validation helper is aimed at obvious local-path leaks and scratch files, not live case data collection

## What to watch on the next run

- whether the validator catches future local residue before commit
- whether inline-styled HTML exports travel cleanly without leaking local CSS paths
- whether the shorter README flow stays clear without the duplicated quick-start section
