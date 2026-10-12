# Offline image workflow integration

The paired disk/memory runner and image preservation/recovery work developed on
separate branches. Integration retains both sets of tools, agents and tests.
The combined CI configuration runs the paired standard-library suite and the
image-workflow Windows/Linux matrix with the pinned optional MFT dependencies.
The research prompts retain the pinned Robin adapter while incorporating
capability-specific validation, shared-dependency checks and source limitations.

An adversarial fixture reproduced a stale integrity gate: after successful
verification, a retry that failed reading its manifest left the old `verified`
record available to downstream consumers. Verification now writes `in_progress`
before reading manifests or evidence. The regression proves that both preparation
and final-review hash consumers reject that interrupted retry.

A separate bounded gzip intake helper addresses limits in the paired runner's
legacy preparation: explicit expansion and reserve budgets, Windows source
sharing protection, concatenated-member/CRC validation, compressed hash matching,
an independent raw-output reread, and exclusive publication. Synthetic tests
exercise corrupt/truncated streams, trailing data, output corruption, expansion
limits, capacity exhaustion, sparse zero blocks, existing targets and Windows
write/delete denial. Its status includes tool/runtime provenance and remains
private. It does not populate the paired ledger or establish acquisition origin.

The legacy paths remain available with their weaker output and capacity
guarantees clearly documented. Integration does not certify any parser, prove
case completeness, or authorize network access. Runtime evidence containers use
the existing offline controls; any optional online symbol or research path still
requires the applicable scope decision.
