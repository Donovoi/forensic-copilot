# Forensic Copilot

<p align="center">
  <img src="docs/assets/forensic-copilot-hero.svg" alt="Forensic Copilot hero illustration" width="100%" />
</p>

<p align="center">
  <strong>A self-improving forensic examiner agent for investigator-facing, evidence-safe analysis and Markdown reporting.</strong>
</p>

<p align="center">
  Inspired by the feel of systems like <strong>OpenEvolve</strong> and <strong>Andrej Karpathy's autoresearch</strong>—but adapted for digital forensics, where preservation, scope discipline, and defensibility matter as much as iteration speed.
</p>

## What this repo is

`Forensic Copilot` is a repository of custom agents, instructions, and supporting docs for a **digital forensic examiner agent** that:

- supports a **non-technical investigator**
- narrows and clarifies investigative scope
- examines mounted file systems and disk images defensibly
- explains findings in plain language
- produces a **Markdown forensic report**
- improves itself through a guarded, evidence-safe review loop

This is not a generic autonomous coding agent with a forensic sticker on it.

It is a forensic workflow system designed to behave more like a real digital forensic examiner working alongside an investigator, incident responder, or case officer.

## What the agent actually is

At the top level, the system exposes **one user-facing agent**:

- `Forensic Examiner`

Behind the scenes, the examiner orchestrates two internal helper subagents:

- `Forensic Toolsmith` — validates tooling, readiness, install strategy, and platform caveats
- `Forensic Maintainer` — critiques the workflow, captures lessons learned, and updates the system safely

So from the user's perspective, this feels like **one examiner**.

From the system's perspective, it is a **looped forensic research-and-analysis pipeline** with internal specialization.

## Why it feels like OpenEvolve / autoresearch

The inspiration is structural, not literal.

The system borrows the *shape* of self-improving research loops:

- clarify the objective
- run a focused attempt
- inspect the results
- critique what happened
- keep the good changes
- repeat when needed

But the optimization target is very different.

Instead of optimizing for novelty, benchmark wins, or open-ended exploration, `Forensic Copilot` optimizes for:

- evidence preservation
- scope correctness
- investigator usefulness
- report quality
- reproducibility
- defensibility

In short:

| Self-improving research systems | Forensic Copilot adaptation |
| --- | --- |
| Iterate aggressively | Iterate defensibly |
| Improve based on outcomes | Improve based on outcomes **and** forensic guardrails |
| Seek better experiments | Seek better examinations and clearer reports |
| Keep what works | Keep only what preserves evidence, scope, and rigor |

## The loop ✨

<p align="center">
  <img src="docs/assets/forensic-copilot-loop.svg" alt="Forensic Copilot loop diagram" width="100%" />
</p>

The examiner does not simply run once and stop.

It works in a controlled loop:

1. **Receive the case request**
2. **Ask high-value clarification questions** when context would materially improve scope or interpretation
3. **Validate tools and environment** through the internal toolsmith
4. **Examine the evidence** using preservation-first handling
5. **Analyze and interpret findings** in relation to the case
6. **Write or update the Markdown report**
7. **Review and improve the workflow** through the internal maintainer
8. **Loop again** if meaningful questions remain

Crucially, clarification is helpful—but not a permanent blocker.

If the user cannot answer every question, the examiner should proceed with conservative assumptions, state them clearly, and continue useful work.

## The user experience

The agent is meant to feel like a capable forensic examiner assisting an investigator.

That means it should:

- help translate a vague request into a workable forensic objective
- ask smart questions about scope, timeframe, accounts, hosts, and authority limits
- explain technical evidence in ordinary language
- point out limitations and uncertainty
- keep the report useful for decision-making, not just artifact dumping

Example interactions:

- “Investigate `/evidence/drive.E01` for evidence of data theft.”
- “Review `/mnt/image` and tell me whether there is evidence of persistence or lateral movement.”
- “Examine this image for user activity during the last 72 hours and write a Markdown report.”

## Design principles

The repo is built around a few non-negotiables:

- **Preservation first** — originals stay preserved, working copies get analyzed
- **Scope discipline** — stay within the stated authority and case boundaries
- **Plain-language usefulness** — findings must help a non-technical stakeholder
- **Markdown output** — reports should be readable, diffable, and portable
- **Guarded self-improvement** — the system may evolve, but never by weakening forensic rigor

## One visible agent, hidden helpers

| Role | Visibility | Responsibility |
| --- | --- | --- |
| `Forensic Examiner` | User-facing | investigator support, scope clarification, examination, analysis, reporting |
| `Forensic Toolsmith` | Internal | tool selection, staging, readiness, install and platform logic |
| `Forensic Maintainer` | Internal | self-update, workflow critique, architecture review, safe optimization |

Only `Forensic Examiner` should be selected directly by the user.

## The architecture is allowed to evolve

The current design is intentional, but it is not sacred.

Through the self-update process, the system may:

- add agents
- remove agents
- merge or split roles
- change internal boundaries
- revise the main examiner role itself

That flexibility is allowed **only** when it improves the forensic-analysis and reporting outcome without violating the core guardrails.

## Repository layout

| Path | Purpose |
| --- | --- |
| `.github/agents/` | custom agent definitions |
| `docs/self-update-loop.md` | self-improvement process and hard guardrails |
| `docs/tooling-matrix.md` | opinionated tool-selection guidance |
| `docs/privacy-and-redaction.md` | public-repo sanitization checklist |
| `docs/sources.md` | authoritative references and upstream anchors |
| `AGENTS.md` | repository-wide rules for future modifications |

## Quick start in VS Code

1. Add the agent files into your workspace `.github/agents/` directory.
2. Reload VS Code if the agent picker does not update immediately.
3. Select **`Forensic Examiner`** in Copilot Chat.
4. Give it an evidence path, image path, or investigative question.

Example prompt:

> Investigate `/evidence/image.E01` for suspicious user activity and produce a Markdown report. If important context is missing, ask the minimum high-value clarification questions first.

## Privacy note

This repository is intended to stay generic when published.

Do not commit:

- real names
- usernames
- hostnames
- employer or client names
- raw evidence outputs
- screenshots from live investigations
- absolute local paths tied to a real environment

Use placeholders such as:

- `CASE-001`
- `ANALYST`
- `HOST-A`
- `/evidence/image.E01`

See `docs/privacy-and-redaction.md` for the full checklist.

## In one sentence

`Forensic Copilot` is a self-improving forensic examiner agent that behaves like a real investigator-facing digital forensic examiner: it clarifies scope, preserves rigor, examines evidence, explains findings, writes Markdown reports, and improves its own workflow without compromising defensibility.
