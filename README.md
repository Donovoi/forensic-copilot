# Forensic Analysis Agents

Git-tracked custom agents, instructions, and supporting documentation for **forensically analyzing evidence items** and producing **defensible Markdown reports**.

## Purpose

This repository is the canonical home for:

- forensic examiner agent definitions
- tooling-selection and environment-preparation subagents
- report and methodology instructions
- research notes that justify workflow or toolchain choices

Every change in this repo must support the same end goal:

> examine a mounted file system or forensic image in a defensible way and produce a clear Markdown report.

## Included agents

- `Forensic Examiner` — the only user-facing agent; it leads collection, examination, analysis, reporting, and the orchestration of internal helper subagents.
- `Forensic Toolsmith` — internal subagent called by the examiner to validate tooling, environment readiness, and installation strategy.
- `Forensic Maintainer` — internal subagent called by the examiner during the loop to review lessons learned, instruction quality, and safe self-improvement.

Only `Forensic Examiner` should be selected directly by the user. The other two agents are support roles inside the examiner's workflow.

## Operating principles

- Preserve originals; analyze verified working copies.
- Prefer read-only workflows and document any deviation.
- Treat mounted file-system views as partial evidence views, not full-image truth.
- Prefer current authoritative guidance such as NIST, SWGDE, NIJ, and tool-specific official docs.
- Prefer reproducible, Linux-friendly, open tooling when possible.
- Document platform-specific constraints for tools that are Windows-first, proprietary, or both.
- Separate observed artifacts from interpretation.
- Keep the report in Markdown and update it as the analysis progresses.
- Close the loop after significant work by reviewing what succeeded, what failed, and what authoritative guidance changed, then applying only minimal justified improvements.

## Repository layout

- `.github/agents/` — custom agent definitions
- `docs/privacy-and-redaction.md` — what must be sanitized before anything is published
- `docs/self-update-loop.md` — self-improvement process and guardrails
- `docs/tooling-matrix.md` — current tool-selection guidance and platform notes
- `docs/sources.md` — authoritative references and upstream projects
- `AGENTS.md` — repository-level instructions for future changes

## Privacy and genericity rules

This repository is intended to stay **generic** when published.

Do not commit content that can identify:

- a real person
- a specific workstation or host
- an employer, client, or agency
- a live case, evidence item, or internal environment

Use neutral placeholders instead, for example:

- `CASE-001`
- `/evidence/image.E01`
- `ANALYST`
- `HOST-A`
- `ORG-NAME`

Before pushing, run a privacy sweep and sanitize any names, usernames, emails, hostnames, absolute local paths, employer references, ticket IDs, or case-derived artifacts.

## Update policy

This repository is intended to be the **canonical source** for the forensic agents and instructions.

When we make future changes to these agents or decisions:

1. update the relevant agent or doc in this repo
2. run the self-update review when the change was driven by performance feedback, tooling drift, or new authoritative guidance
3. update supporting docs if the workflow or toolchain changed
4. push the change to the public GitHub repository so the canonical copy stays current

## Notes on tool downloads

This repository stores **definitions, instructions, and documentation**.

Downloaded tools, virtual environments, containers, and large evidence-derived outputs should usually be kept **outside git history** or under ignored directories, with their versions and locations recorded in the Markdown report or provisioning notes.

Evidence files, case outputs, screenshots, exported artifacts, and investigator notes should also remain outside git unless they have been deliberately sanitized for public release.

## Next steps

- keep the canonical repo in sync with accepted workflow and tooling changes
- optionally mirror selected agents into a workspace-level `.github/agents/` folder when you want them active in another workspace
- use the self-update loop after significant investigations, tool failures, or new best-practice findings
