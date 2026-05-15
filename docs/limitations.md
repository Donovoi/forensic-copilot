# Current limitations and cautions

This repository is easier to trust if its limits are stated plainly. The agent is meant to help structure examinations, not to pretend every evidence type or workflow is equally well supported.

## Evidence access limits

- A mounted file-system view is a partial representation of the evidence. It may be enough for scoped artifact review, but it does not answer every question that a full image can answer.
- A neighboring output directory, cached export, or prior analyst product is not automatically part of the case scope, even when it appears to reference the same image.
- Deleted entries, unallocated space, slack space, some filesystem-internal artifacts, prior volume states, and certain metadata questions may require full-image access.
- Encryption, detached key material, and credential-protected containers may block examination until live context or valid keys are available.
- Cloud-backed placeholders, remote mounts, and synchronized folders can make it unclear whether the visible files represent the full logical evidence set.

## Derived-artifact limits

- If direct image access is blocked and the examination depends on previously generated outputs, the report should declare that explicitly.
- Derived artifacts can still be useful, but they require a provenance ledger: source image, source hash, derived artifact path, tool, version, and command path.
- Derived artifacts narrow the questions that can be answered confidently. They are especially weak for claims about absent artifacts, complete host state, or subtle timestamp interpretation.

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
- A polished PDF or DOCX can improve presentation. It does not strengthen weak findings, close corroboration gaps, or replace the Markdown case record.
- Formal export depends on local rendering tools. If `pandoc` or a PDF backend is missing, document the blocker instead of faking a finished package.

## Server interpretation limits

- On servers, recovered URLs, domains, admin endpoints, crawler strings, and server IP references may reflect hosted content, preserved logs, brute-force noise, or automation rather than a user's local browsing history.
- `.bashrc`, `.bash_profile`, or similar shell files suggest account context, not necessarily recent shell use.
- Backup or staging paths under `root` or service-owned directories may be manual administration, scheduled automation, or deployment tooling; they should not be presented as interactive user activity without corroboration.
- Stronger human-activity claims on servers usually need corroboration from auth/session logs, shell history, sudo/su records, direct file modification context, service logs, cron/systemd evidence, or similar host artifacts.

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
