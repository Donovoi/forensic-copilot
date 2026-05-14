# Self-update loop

This document defines how the forensic agent system improves itself without losing the plot.

The goal never changes:

> forensically analyze the evidence item and produce a defensible Markdown report.

## Core invariants

Any self-update, optimization, or instruction rewrite must preserve all of the following:

1. preservation-first evidence handling
2. scope discipline and legal or policy boundaries
3. explicit limitations and defensible reporting
4. Markdown as the deliverable format
5. iterative looping so the workflow can improve over time
6. the end goal of forensic analysis and reporting

If a proposed change would weaken any invariant, reject or revise it.

## When to run the self-update stage

Run a self-update review when any of the following occurs:

- a significant investigation loop is completed
- a major report is delivered
- tooling installation or verification repeatedly fails
- a new authoritative best practice changes how work should be done
- an agent instruction proves ambiguous, misleading, or incomplete
- repeated manual work suggests the workflow can be simplified safely

## Inputs to review

The self-update stage should consider as many of these as are available:

- the latest Markdown report
- tooling preparation notes
- task lists and execution notes
- observed blockers, delays, or validation failures
- newly identified NIST, SWGDE, NIJ, CFTT, or official upstream guidance
- feedback about report clarity or missing sections

## Loop process

1. **Capture lessons learned**
   - record what worked, what failed, what was slow, and what was risky

2. **Compare with current instructions**
   - identify where the existing agents or docs did not guide the work well enough

3. **Compare with current guidance**
   - check whether authoritative recommendations or upstream install paths changed

4. **Design minimal edits**
   - prefer small, justified changes over sweeping rewrites

5. **Validate guardrails**
   - ensure the changes still preserve the core invariants listed above

6. **Apply and document**
   - update the relevant agents or docs
   - summarize why the change was made and what future improvement is expected

7. **Push the canonical update**
   - publish accepted changes to the canonical GitHub repository so the maintained version stays current

## Safe optimization patterns

Good self-updates usually look like:

- clarifying intake questions
- adding missing evidence-handling warnings
- improving report section requirements
- tightening tool-selection logic after repeated setup pain
- adding a missing best-practice citation or upstream source
- splitting a vague responsibility into a dedicated subagent

## Unsafe optimization patterns

Reject changes that:

- reduce hashing, chain-of-custody, or read-only requirements
- remove limitation reporting to make reports look cleaner
- collapse iterative review into a one-pass workflow with no reflection stage
- add broad tool-installation behavior unrelated to the case
- make attribution claims easier without requiring corroboration

## Minimum maintenance note

Every accepted self-update should leave behind a concise note of:

- what triggered the review
- what changed
- what source or lesson justified it
- which guardrails were checked
- how the next run should be better
