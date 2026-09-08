# Tool selection and validation

Select the best-supported method for the current question, evidence features, and authorized environment. No product, bundled helper, native command, open-source package, commercial suite, or generated script is the default answer to every job. The tooling matrix is a candidate index. An installed tool or a previous successful run does not settle the next choice.

This document defines project policy informed by the sources below. It is not a claim of NIST certification, accreditation, or complete compliance with a standard.

## Source basis

Reviewed 2026-09-08. Check for newer final guidance and relevant tool reports at the next substantive selection; retain the review date and any offline limitation.

| Source | What it supports | Limit of that basis |
| --- | --- | --- |
| [NIST CFTT program](https://www.nist.gov/itl/csd/secure-systems-and-applications/computer-forensics-tool-testing-program-cftt) and [methodology](https://www.nist.gov/itl/csd/secure-systems-and-applications/computer-forensics-tool-testing-program-cftt/cftt-general-0) | Evaluate a defined forensic function using requirements, relevant tests, documentation and reported results. | A report concerns tested features and conditions; inspect its version and anomalies before applying it elsewhere. |
| [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final), August 2006 | A process basis for collection, examination, analysis and reporting, with documented data handling. | This is IT incident-response guidance, not an exhaustive investigation procedure or legal authority. Its age requires current artifact and tool documentation alongside it. |
| [NIST IR 8354](https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8354.pdf), November 2022, sections 4.8-4.10 | Distinguish method suitability from implementation correctness; account for version, environment and technology changes when evaluating tests. | A scientific foundation review does not certify this harness or establish a universal tool ranking. |
| [NIST tools and techniques catalog](https://toolcatalog.nist.gov/) | Discover candidates by forensic function and technical needs. | Entries contain developer-provided information; inclusion does not imply testing or endorsement. |

Use other applicable primary guidance, such as current published SWGDE documents and laboratory procedures, after checking its scope and revision. Distinguish final guidance, drafts, public comments, test reports, and vendor claims. Record exact document sections supporting a decision. Our candidate-comparison and corroboration gates below are project rules; do not attribute them to a universal NIST two-tool requirement.

## Decide by capability

Before each substantive stage, the senior tooling specialist must obtain a current research note and a provisioner validation plan. Reuse a previous decision only after confirming that its inputs, requirements, tool/build, dependencies, rules, settings, runtime and known limitations still apply.

1. Define the question and required output before naming tools: for example, preserve logical image bytes, enumerate deleted named streams, interpret an application timestamp, decode all video frames, or make a viewing derivative. These are different jobs.
2. Record evidence features and constraints: format and version, filesystem or application, allocated/deleted scope, corruption or fragmentation, timestamp semantics, approved locations, preservation controls, runtime, licensing, time, storage and live-system impact.
3. Compare at least two credible candidates when available, including tools outside this repository. A candidate may be a documented native method or independently reviewed script. If only one is feasible, explain the alternatives considered and the resulting validation gap; do not invent a second choice or stop unrelated work.
4. Evaluate supported coverage, applicable CFTT or other test results, known defects, local fixture results, reproducibility, output provenance, data handling and operational cost. Treat popularity and active releases as research signals. The newest release is not automatically the best validated release. Prefer open and reproducible options when suitability is otherwise comparable; do not let platform or vendor preference override demonstrated correctness.
5. Select a primary method and an independent check for material results. State why rejected and deferred candidates were not selected, what the chosen method cannot establish, and what would trigger a new selection.

Use the [selection-record template](templates/tool-selection-record.md) in a controlled case directory. Keep the public template generic. Research and senior handoffs remain within their existing line limits: carry concise decision fields and a record reference, then let the examiner persist details. The task-only OpenCode senior must not acquire file or shell responsibilities to write the record.

## Validate before evidence use

The provisioner must bind the selected build, dependencies and configuration to the plan and record the relevant validation evidence. Distinguish integrity checks (download signatures/hashes), method suitability, implementation tests and validation of the actual result. A hash match or a successful process exit does not establish correct forensic interpretation.

Use known-answer public or synthetic inputs for the features that matter. Include representative positive cases, known absence, malformed/truncated input, unsupported features and boundary cases. Define expected results before running the test. For example, a deleted-stream export test should address allocation and named streams if those features are in scope; a timeline test should address precision, timezone and missing values. Record mismatches and the limits of fixtures. A fixture pass does not prove every result on the case image.

Check relevant NIST CFTT reports and documented reference datasets when available. Record the tested function, tool/version, configuration, test identifiers, anomalies and the difference from the intended use. A missing CFTT report does not automatically disqualify a tool; it leaves that source of validation unavailable and requires another documented basis. Do not call a catalog entry or test result a blanket NIST approval.

Changes to a binary, parser library, signature database, rules, settings, operating environment or relevant evidence format require reassessment and targeted revalidation before reuse. Pin the accepted setup for the run. Do not auto-update a running job or silently replace an executable beneath a reviewed tool-specific adapter.

## Independent checks and disagreements

For material findings, recovery-completeness claims, uncertain parsing, tool failures, unexpected empty output or a changed implementation, seek a check that can expose a different class of error. Independence must be described:

- Two interfaces that call the same parser or codec library are not independent implementations of that function. Record shared engines, libraries, rules and input derivation; unknown lineage is unknown independence.
- A separate parser of the same source bytes can check interpretation. A documented byte-level examination against the format can provide a different check. Another artifact can corroborate an event, but it must have a meaning and origin that support that claim.
- Filesystem recovery and carving cover different cases. Neither is automatically a validator of the other's deletion dates, filenames or completeness. Metadata recognition, full decoding, visual examination and enhancement are also distinct levels of evidence.
- A second hash of a recovered file checks stability. It does not show that missing bytes were reconstructed correctly. Repeating the same command is a repeatability check, not independent corroboration.

Compare results at source-record, byte-range, stream or timestamp-field level as appropriate. Preserve raw outputs, commands, hashes, units, offsets, timezone assumptions and errors from every attempt. A disagreement starts a review of source identity, parser coverage, settings, transforms, timestamps and known bugs. Resolve it with an independent method or direct source inspection when feasible; never settle it by majority vote, attractiveness, or silently discarding the inconvenient result.

Unresolved disagreements remain explicit. Limit or withhold the affected claim and retain the next test needed. If an independent check is unavailable, report that limitation and adjust confidence; do not label the finding independently validated. Avoid repeated whole-image reads solely to increase the tool count. Prefer the verified working copy and bounded relevant exports within the established scope.

## Handoff and review gates

- Researcher: capability, credible candidates, dated sources, applicable validation evidence, known limits and possible shared dependencies.
- Senior: selected method, rejected/deferred alternatives, independent-check plan, validation gaps and reassessment triggers.
- Provisioner: exact build/configuration, known-answer test plan and results or explicit pending status, resource limits and safe commands. Pending validation is not clearance for evidence execution.
- Examiner: persist the selection record, verify the handoff is complete, perform the approved checks, and connect result-level validation to the findings. Continue unrelated supported stages when one capability remains blocked.
- Challenger and peer reviewer: require these records for material claims; check independence, unresolved discrepancies, unsupported absence/completeness claims and overstated standards language before release.

## Existing providers

The preservation, inventory, catalog-recovery, timeline, MFT, PhotoRec and media-probe helpers are optional implementations with specific validated input contracts. Their tool/version pins and strict provenance checks remain binding whenever they are selected. This policy does not make them interchangeable by renaming a binary, relaxing an allowlist or relabeling an output manifest. Select another provider when it is better supported, then validate its adapter and result mapping through the existing script-review loop before evidence use. Failure of one provider is a limitation of that attempt, not proof that the evidence cannot be recovered.
