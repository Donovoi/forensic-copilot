# Peer review process

This document defines the case-review step that happens before a substantial report is handed off.

Peer review is not the same as self-update.

- **Peer review** challenges the current case findings.
- **Maintenance review** changes the reusable workflow only when a repeatable issue has been identified.

## Why this exists

Some forensic reports are most at risk when the artifacts are real but the interpretation is fragile. That happens often when:

- only derived artifacts are available
- server-side web artifacts dominate the evidence
- the report is tempted to overstate successful authentication or interactive use
- malware naming or case naming could bias the conclusion
- confidence is moderate or low but the findings are operationally important

The peer-review step exists to challenge those conclusions before release.

## When to run it

Run peer review before final handoff on any substantial report, and especially when one or more of these conditions are present:

- direct raw-image access was blocked or incomplete
- server-side web artifacts dominate the analysis
- user attribution depends on the absence of direct auth/session artifacts
- malware execution or successful-login inference is being considered
- the draft report contains medium-confidence conclusions that could drive decisions

## Reviewer responsibilities

The peer reviewer should:

- read the draft report and the artifacts it cites
- identify which findings are well supported
- identify where the report is leaning too hard on inference
- suggest alternative explanations that fit the same artifacts
- identify missing corroboration that should be named before release
- recommend wording downgrades where the evidence does not support the stronger claim

The peer reviewer is not responsible for editing prompts, docs, or repo architecture.

## Minimum output

Return or create a Markdown note containing:

# Forensic Peer Review Note
## Report reviewed
## Supported findings
## Challenged findings
## Missing corroboration
## Alternative explanations
## Required wording changes
## Release recommendation

Release recommendations should be one of:

- **ready**
- **ready with caveats**
- **not ready**

## Relationship to maintenance review

If peer review reveals a reusable workflow problem, the maintainer path should use that note as an input to a later workflow update. If the issue is specific to the current case, it should stay in the case record and not automatically change the repo.
