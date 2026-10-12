# Hash-bound peer-review contract

## Trigger

The live paired-VM workflow exposed a reusable interface mismatch:
`paired_vm_case.py finalize-report` requires structured JSON bound to the frozen
report and coverage hashes, while the peer-reviewer prompts and formal-export
examples still requested a Markdown note.

## Change

- Require both Copilot and OpenCode peer reviewers to return the same structured
  `peer-review.json` shape when a review bundle is supplied.
- Keep supported findings, challenged findings, missing corroboration,
  alternatives, required wording changes, and residual caveats in that record.
- State that only exact `ready` passes finalization and that both review-bundle
  hashes must be copied without alteration.
- Correct formal-export examples to include the peer-review JSON and finalized
  completion manifest.
- Add a regression test covering the cross-interface contract.

## Preserved boundaries

- The canonical forensic report remains Markdown.
- Independent review must still be substantive; the JSON gate is not permission
  to invent a `ready` recommendation.
- Supplemental narrative notes remain allowed, but they cannot replace the
  hash-bound lifecycle record.
