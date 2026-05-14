# Forensic Copilot

<p align="center">
	<img src="docs/assets/forensic-copilot-hero.svg" alt="Forensic Copilot hero illustration" width="100%" />
</p>

`Forensic Copilot` defines a Copilot custom agent for investigator-facing host and disk examinations. The current emphasis is Linux-based review of mounted file systems and common disk-image formats where the analyst needs a traceable workflow, explicit limitations, and a Markdown report.

The repo is meant to help a human examiner, incident responder, or non-technical investigator work through a case more systematically. It is not presented as a replacement for evidentiary judgment, lab SOPs, or formal tool validation.

## Current scope

| Evidence or task type | Current status | Notes |
| --- | --- | --- |
| Mounted file-system paths | Primary | Useful for scoped review and artifact extraction. Not equivalent to full-image analysis. |
| `raw/dd`, `E01`, `AFF4`, `VMDK/VHD` | Primary | Intended inputs for filesystem, artifact, and timeline work. |
| Live-host decision support | Limited | Used to frame preservation and acquisition decisions, not to replace live-response SOPs. |
| Firmware or opaque blobs | Secondary | Supported when the evidence requires it, usually through tool selection by the internal toolsmith. |
| Memory, mobile, cloud-native, or packet-only work | Outside primary scope | May require separate workflows, additional agents, or external SOPs. |

## What the examiner does

The user interacts with a single visible agent: `Forensic Examiner`.

On each run the examiner is expected to:

- translate a broad request into concrete forensic questions
- ask only the clarification questions that are likely to change scope, interpretation, or priority
- invoke internal helper paths for tool readiness and workflow review
- keep evidence handling preservation-first and read-only where possible
- separate observation, inference, and limitation
- maintain a Markdown report as the work progresses

The helper roles are internal:

- `Forensic Toolsmith` handles tool selection, readiness, and platform caveats
- `Forensic Maintainer` reviews lessons learned and bounded updates to the workflow

Only `Forensic Examiner` should be selected directly by the user.

## What to provide

At minimum, the examiner works best when given:

- an evidence path or image path
- the question to answer, even if it is still broad
- known scope or authority limits
- timezone or locale assumptions if they matter
- whether the source is live, mounted, or a preserved image
- the desired report path if one is already chosen

If some of this is missing, the examiner should ask concise follow-up questions and then proceed with conservative assumptions when the answers are unavailable.

## What you get back

The expected output is a Markdown report that records:

- the request and scope assumptions
- evidence handling and verification notes
- the examination method and tool versions
- findings and timeline correlations
- explicit limitations and unresolved questions
- conclusions stated in language a non-technical stakeholder can follow

## Operational flow

<p align="center">
	<img src="docs/assets/forensic-copilot-loop.svg" alt="Forensic Copilot loop diagram" width="100%" />
</p>

The current workflow is iterative rather than one-pass:

1. receive the case request
2. narrow the task with high-value clarification questions
3. check tool readiness and platform constraints
4. examine the evidence with preservation-first handling
5. analyze and correlate the resulting artifacts
6. write or update the Markdown report
7. review what should change before the next loop

This is where the project borrows from systems such as OpenEvolve and autoresearch: not in the details of their implementation, but in the idea that a run can critique itself and improve the next run. The difference is the optimization target. Here the goal is not novelty or benchmark performance; it is defensible examination and a better report.

## Known limits

The most important limits are easy to miss if they are not stated plainly:

- mounted file-system views do not answer every question that a full image can answer
- deleted, unallocated, slack-space, and some filesystem-internal questions may require full-image access
- encryption, cloud placeholders, remote mounts, and hybrid storage layers can change what is observable
- some commonly used forensic tools remain Windows-first or license-constrained
- this repo documents a workflow, not a formal validation package

See `docs/limitations.md` for the fuller list.

## Quick start in VS Code

1. Clone this repo or copy the `.github/agents/` directory into the target workspace.
2. Ensure all three agent files are present in the workspace `.github/agents/` directory, even though only `Forensic Examiner` is user-facing.
3. Keep the repo docs available if you want the maintainer path to update the same canonical source rather than a drifting local copy.
4. Reload the VS Code window if the agent picker does not refresh automatically.
5. Select **`Forensic Examiner`** in Copilot Chat.

Example first prompt:

> Investigate `/evidence/image.E01` for suspicious user activity and produce a Markdown report. If context is missing, ask only the clarification questions that materially affect scope or interpretation.

For a worked example, see `docs/example-investigation.md`.

## Documentation set

| Path | Purpose |
| --- | --- |
| `.github/agents/` | custom agent definitions |
| `docs/limitations.md` | current scope limits, cautions, and validation boundaries |
| `docs/example-investigation.md` | example prompt, clarification exchange, and report excerpt |
| `docs/self-update-loop.md` | rules for post-run workflow improvement |
| `docs/tooling-matrix.md` | current tool-selection starting point |
| `docs/sources.md` | source basis and review anchors |
| `docs/privacy-and-redaction.md` | public-repo sanitization checklist |
| `AGENTS.md` | repository-wide rules for future changes |

## Source basis

The repo is intentionally tied to current process guidance rather than to a single person's preferences. The current source basis is summarized in `docs/sources.md`, including what each source is used for and when it was last reviewed.

## Privacy note

This repository is meant to stay generic when published. Do not commit real names, user names, hostnames, employer names, client names, live case outputs, or machine-specific paths. Use placeholders such as `CASE-001`, `ANALYST`, `HOST-A`, and `/evidence/image.E01`.

The practical checklist is in `docs/privacy-and-redaction.md`.
