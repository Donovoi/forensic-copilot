# Example investigation flow

This example is intentionally generic. It is meant to show how the examiner should behave when the initial tasking is incomplete.

## Scenario

- Case identifier: `CASE-001`
- Evidence provided: `/evidence/CASE-001-laptop.E01`
- Initial request: determine whether there is evidence of data theft by a user on the final business day before departure
- Known constraint: the user has not yet provided a timezone or a narrowed date window

## Example first prompt

> Investigate `/evidence/CASE-001-laptop.E01` for evidence of data theft.

From that prompt alone, the examiner should infer preservation-first handling, keep the scope limited to the supplied image, start the Markdown case record immediately, and assume triage unless the user asks for deeper work or the evidence justifies escalation.

## Example clarification questions

The examiner should keep moving when context is incomplete. The first questions should focus on the details that could materially change scope or interpretation. A reasonable first response would ask:

1. Which user account or employee is in scope, if known?
2. What date range matters most?
3. What timezone should be used for reporting if the source timestamps are ambiguous?
4. Are there any authority limits or excluded data categories that should be honored from the start?
5. If pre-existing exports, timelines, or other derived outputs already exist outside `/evidence/CASE-001-laptop.E01`, should they be treated as in scope or ignored unless I come back for approval?

If the answers are not yet available, the examiner should proceed with conservative assumptions and record them.

## Example opening plan

Once the first clarification pass is complete, the examiner should be able to state a short plan such as:

- confirm or stage the minimal Linux-friendly image-access toolchain and verify that the E01 is readable before deeper examination
- if the primary volume is encrypted or otherwise blocked, branch into supported access-recovery work before blocker-only handoff: confirm the barrier, test read-only metadata and unlock paths within scope, and decide whether any whole-disk free-space or carving pass remains possible and worth doing
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

## Example blocked-access wording

```md
## Limitations, deviations, and contamination risks

- The primary Windows data volume remained locked in this run, so no volume-internal deleted-entry, filesystem-unallocated, slack-space, snapshot, or plaintext-carving review of that volume was possible without a supported unlock path.
- A separate whole-disk free-space or carving pass outside the locked volume was not completed in this run, so those avenues are not treated as exhausted.
- Recovery work in this run was limited to confirming the access barrier, testing supported read-only metadata or unlock paths with in-scope material, and documenting the remaining decision point.
```

## Example peer review note

```md
# Forensic Peer Review Note

## Supported findings

- The archive creation event is well supported by multiple artifacts.

## Challenged findings

- Do not state that exfiltration occurred unless a transfer artifact, outbound log, removable-media trace, or equivalent corroboration exists.
- Require the report to distinguish blocked encrypted-volume work from unattempted disk-level free-space or carving work.

## Missing corroboration

- network transfer evidence
- removable-media activity
- mail or cloud-sync confirmation

## Alternative explanations

- temporary staging for backup or handoff that did not lead to external transfer

## Release recommendation

- Ready with caveats after wording is limited to staging activity rather than confirmed exfiltration.
```

## What this example is meant to show

- the examiner narrows the task before diving into artifacts
- clarification questions are useful, but not treated as a hard blocker
- the report distinguishes observation from inference
- the report states what the evidence supports and what it does not yet support
- blocked-access wording should distinguish impossible work from unattempted work
- peer review challenges overstatement before the report is released
- on server cases, recovered URLs and admin endpoints should not be equated with local browsing or successful authentication without corroboration
