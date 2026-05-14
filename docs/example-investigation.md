# Example investigation flow

This example is intentionally generic. It is meant to show how the examiner should behave when the initial tasking is incomplete.

## Scenario

- Case identifier: `CASE-001`
- Evidence provided: `/evidence/CASE-001-laptop.E01`
- Initial request: determine whether there is evidence of data theft by a user on the final business day before departure
- Known constraint: the user has not yet provided a timezone or a narrowed date window

## Example first prompt

> Investigate `/evidence/CASE-001-laptop.E01` for evidence of data theft and produce a Markdown report.

## Example clarification questions

The examiner should not stop on every missing detail, but it should ask the questions that could materially change scope or interpretation. A reasonable first response would ask:

1. Which user account or employee is in scope, if known?
2. What date range matters most?
3. What timezone should be used for reporting if the source timestamps are ambiguous?
4. Is the task triage only, or do you want a fuller examination that includes deleted and timeline work if supported by the image?
5. Are there any authority limits or excluded data categories that should be honored from the start?

If the answers are not yet available, the examiner should proceed with conservative assumptions and record them.

## Example opening plan

Once the first clarification pass is complete, the examiner should be able to state a short plan such as:

- verify the image and record hashes if not already present
- identify the filesystem layout and relevant user profiles
- review browser, document, removable-media, cloud-sync, and archive artifacts for the final working week
- build a narrow timeline around file access, archive creation, copy activity, and external-media use
- report both the observed artifacts and the limits of what they do or do not prove

## Example report excerpt

```md
## Findings

### File access and archive creation

**Observation.** Within the user profile for `USER-A`, the examination identified a ZIP archive created on `2026-04-28 18:42:11 UTC` under `Documents/Transfer/`. Shell-item and recent-file artifacts show repeated access to project spreadsheets during the preceding hour.

**Inference.** The artifact pattern is consistent with the user collecting documents into a single archive shortly before departure from the workstation.

**Why it matters.** The timing and file grouping are relevant to the request to assess potential data staging or exfiltration.

**Corroboration.** ZIP file metadata, shell-item traces, recent-file records, and filesystem timestamps.

**Confidence and limitations.** Moderate confidence that staging activity occurred. The current artifact set does not, on its own, prove external transfer. Review of removable-media traces, cloud-sync activity, mail artifacts, or outbound transfer logs would strengthen or weaken that conclusion.
```

## What this example is meant to show

- the examiner narrows the task before diving into artifacts
- clarification questions are useful, but not treated as a hard blocker
- the report distinguishes observation from inference
- the report states what the evidence supports and what it does not yet support
