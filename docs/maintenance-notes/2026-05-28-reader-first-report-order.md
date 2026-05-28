# Reader-first report order

## Reason

Recent live-host reports were technically defensible, but the highest-value answer was too far down the document. Investigators need the practical answer first, then the supporting forensic detail.

## Decision

The canonical Markdown report order now starts with:

1. executive summary
2. findings
3. analysis and timeline correlation
4. conclusions and answers to tasking
5. limitations, deviations, and contamination risks
6. scope, metadata, evidence handling, tooling, methodology, and appendices

This keeps the report defensible while making it easier to read under time pressure.

## Guardrails

- The executive summary must not overstate the evidence.
- Findings still need artifact references, timestamps, corroboration, confidence, and limitations.
- Chain of custody, evidence handling, hashes, tools, methodology, and blockers still remain in the report; they are just moved below the answer-oriented sections.
- Peer review should flag reports that bury the answer beneath metadata or method sections.
