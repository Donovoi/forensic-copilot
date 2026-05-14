# Self-update loop

This document governs how the repository changes after real investigative use. It exists to keep the workflow improvable without allowing silent drift in evidence-handling practice.

The goal does not change:

> forensically analyze the evidence item and produce a defensible Markdown report.

## Two kinds of adaptation

The repo distinguishes between runtime adaptation and repository maintenance.

### Runtime adaptation

During a case, the examiner may adapt:

- clarification questions
- investigative priorities
- tool choice and order of operations
- report emphasis
- the next loop based on what the evidence actually shows

That kind of adaptation is normal casework.

### Repository maintenance

Edits to agent files, instructions, docs, or agent boundaries are maintenance actions. They should be justified, recorded, and pushed to the canonical repository so the method remains reviewable.

In short: the examiner may adapt the plan during a case, but the public method should not drift silently.

## Core invariants

Any accepted maintenance change must preserve all of the following:

1. preservation-first evidence handling
2. scope discipline and legal or policy boundaries
3. explicit limitations and defensible reporting
4. Markdown as the deliverable format
5. iterative looping so the workflow can improve over time
6. the end goal of forensic analysis and reporting

If a proposed change weakens any invariant, reject it or revise it.

## Review triggers

Run a self-update review when any of the following occurs:

- a significant investigative loop is completed
- a major report is delivered
- tooling installation or verification fails repeatedly
- a new authoritative source changes the preferred method
- an instruction proves ambiguous, misleading, or incomplete
- repeated manual work suggests the workflow can be simplified safely

## Inputs worth checking

Use as many of these as are available:

- the latest Markdown report
- tooling preparation notes
- task lists or execution notes
- observed blockers, delays, or validation failures
- newly identified NIST, SWGDE, NIJ, CFTT, or official upstream guidance
- feedback about report clarity, omissions, or weak sections

## Maintenance workflow

1. **Capture the trigger**
   - record what happened and why a review is being opened

2. **Separate case-specific friction from reusable workflow issues**
   - not every awkward case justifies a prompt rewrite

3. **Compare the current instructions with the work that was actually performed**
   - identify where the current docs helped, failed, or stayed silent

4. **Compare with current guidance**
   - check whether authoritative recommendations or upstream install paths changed

5. **Design the smallest justified edit**
   - prefer a narrow correction over a wholesale rewrite
   - agent boundaries may change, but only if the change is easier to explain and easier to defend than the current split

6. **Validate the guardrails**
   - confirm that preservation, scope, reporting, privacy, and loop compatibility remain intact

7. **Record the maintenance note**
   - leave a concise trace of why the change was made and what it is expected to improve

8. **Push the canonical update**
   - publish accepted changes to the maintained public repository so local copies do not drift

## Good maintenance changes

Typical safe updates include:

- clarifying intake questions that repeatedly matter
- adding missing evidence-handling warnings
- tightening report section requirements
- refining tool-selection logic after repeated setup friction
- pinning a new source or upstream reference
- merging or splitting agent responsibilities when the current design adds avoidable confusion

## Changes to reject

Reject changes that:

- reduce hashing, chain-of-custody, or read-only requirements
- remove limitation reporting to make reports look cleaner
- hide uncertainty or make attribution easier without corroboration
- broaden tool installation behavior without a case-driven need
- collapse iterative review into a one-pass workflow
- rewrite public instructions without leaving a reviewable justification

## Minimum maintenance note

Every accepted change should leave behind a short note that states:

- what triggered the review
- what changed
- what source or lesson justified it
- which guardrails were checked
- what should improve on the next run

If the change is intended for public publication, also record what privacy and redaction checks were performed.
