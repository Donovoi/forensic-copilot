# Current limitations and cautions

This repository is easier to trust if its limits are stated plainly. The agent is meant to help structure examinations, not to pretend every evidence type or workflow is equally well supported.

## Evidence access limits

- A mounted file-system view is a partial representation of the evidence. It may be enough for scoped artifact review, but it does not answer every question that a full image can answer.
- Deleted entries, unallocated space, slack space, some filesystem-internal artifacts, prior volume states, and certain metadata questions may require full-image access.
- Encryption, detached key material, and credential-protected containers may block examination until live context or valid keys are available.
- Cloud-backed placeholders, remote mounts, and synchronized folders can make it unclear whether the visible files represent the full logical evidence set.

## Platform and tooling limits

- The current workflow is Linux-first. That is a design choice, not a claim that all useful forensic tools run natively on Linux.
- Windows-first tools such as `FTK Imager`, `KAPE`, and many `Zimmerman` utilities may require a separate workstation, VM, or manual setup path.
- Timeline tooling can be worth the cost in the right case, but tools such as `Plaso` and `Timesketch` can add packaging, service, or deployment friction.
- Proprietary or licensed tools are not redistributed by this repo. If they are needed, the licensing and execution path should be documented explicitly.

## Investigation and reporting limits

- The agent can help narrow scope, but it cannot determine legal authority, warrant scope, or policy boundaries on its own.
- Findings still require examiner review. AI-generated phrasing is not evidence and should not replace direct artifact verification.
- Attribution is rarely a one-artifact question. The report should preserve uncertainty when the available evidence does not support a stronger conclusion.
- A well-structured Markdown report is useful, but it is not a substitute for tool validation records, chain-of-custody documentation, or testimony preparation.

## Self-update limits

- The self-update path may refine prompts, docs, or agent boundaries, but it must not relax preservation, scope, reporting, or privacy controls.
- Public changes should leave a reviewable note explaining what changed and why.
- The method may evolve, but it should not drift silently during evidentiary work.

## Current validation status

This repo reflects current guidance, operational heuristics, and workflow design choices. It is **not** a formal validation package and should be used alongside:

- local lab SOPs
- tool validation records
- case-specific legal review
- human examiner judgment
