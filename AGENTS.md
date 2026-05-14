# Repository instructions

All agents, prompts, instructions, and supporting documents in this repository must contribute to the same outcome:

> forensically analyze the evidence item and produce a defensible Markdown report.

## Non-negotiable priorities

1. **Preservation first** — preserve originals, prefer verified working copies, and document chain of custody and hashes.
2. **Defensibility over convenience** — prefer repeatable, well-documented workflows over clever shortcuts.
3. **Scope discipline** — stay within the stated authority, warrant, consent, or policy boundary.
4. **Markdown deliverable** — all analysis must ultimately support a Markdown report that a human can read and defend.
5. **Current guidance wins** — when authoritative guidance changes, update the workflow and cite the source.
6. **Self-improvement must stay bounded** — any optimization or self-modification must preserve the forensic-analysis loop, not replace or weaken it.

## Tooling rules

- Prefer Linux-friendly, open, reproducible tooling where possible.
- Do not install every forensic utility by default; select only what advances the current evidence analysis.
- Do not pretend Windows-only or proprietary tools are natively available on Linux.
- If a tool requires Windows, a license, a container, or manual download, document that clearly.
- Record selected tools, versions, install paths, and blockers in Markdown.

## Required documentation updates

When changing agent behavior or tool choices, also update the relevant docs:

- `docs/self-update-loop.md` when the improvement process or loop guardrails change
- `docs/tooling-matrix.md` for tool-selection changes
- `docs/sources.md` for new guidance or upstream references
- `README.md` when the repo purpose or workflow changes materially

## Agent design rules

- Keep agents single-purpose and explicit.
- Minimize tools to what the role actually needs.
- Make descriptions rich in trigger terms so delegation works.
- Require the examiner agent to distinguish observation, inference, and limitation.
- Require the toolsmith agent to justify why each tool is selected, skipped, or deferred.
- Require the maintainer path to justify every self-update with either observed workflow friction, validated lessons learned, or newer authoritative guidance.
- Require any self-modifying behavior to preserve preservation-first handling, scope discipline, Markdown reporting, and loop compatibility.

## Self-update policy

After a significant investigation, tooling-preparation cycle, or best-practice update, the relevant agent flow should perform a self-update review.

That review must:

1. capture what worked, what failed, and what caused avoidable friction
2. compare the current instructions against the latest authoritative guidance and the actual work performed
3. make only minimal, justified edits that improve future investigations
4. verify that the changes still preserve the end goal of forensic analysis and Markdown reporting
5. preserve a looping structure so future runs can continue to improve instead of converging on a brittle one-shot procedure

Self-update never authorizes unsafe evidence handling, scope creep, unsupported claims, or report shortcuts.

## Reporting expectations

The final or interim report must remain in Markdown and should include, when applicable:

- case metadata and scope
- evidence inventory and acquisition or preservation summary
- hashes and verification details
- examination environment and tool versions
- findings and timeline correlations
- limitations, deviations, and contamination risks
- conclusions and answers to tasking

## Sync policy

This repo is the canonical source for these agent definitions.

After future edits, push the changes to the public GitHub repo rather than letting local copies drift.
