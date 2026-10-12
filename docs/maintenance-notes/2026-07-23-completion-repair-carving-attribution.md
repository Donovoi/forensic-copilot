# 2026-07-23 - Completion-gated forensic reruns

## Trigger

A substantial paired disk-and-memory report was written while full recovery and
timeline work were still running. It also described a damaged NTFS `$MFT`
without attempting a repair on a copy, omitted file carving, and did not separate
observed device users from real-world owner or operator attribution.

## Accepted changes

- inventory every regular evidence file and create required per-item work lanes
- create only a working report at intake and block finalization on non-terminal work
- bind peer review to exact report and coverage hashes and require exact `ready`
- add whole-disk PhotoRec carving with per-file hashes and atomic promotion
- add metadata-aware allocated, unallocated, and all-file TSK recovery scopes
- add hashed partition-copy and TestDisk MFT-repair experiments with sector deltas
- add a constrained attribution helper and bounded Firefox/public-IP collectors
- require summary-first reporting, evidence links, repair, carving, attribution,
  timeline, limitations, and handling sections before review
- regenerate and validate the complete required lane matrix at every gate
- serialize state/review/finalization writes and lock each repair derivative
- require manifests for recovered/carved trees and rehash evidence, raw working
  disks, and manifested trees before review and finalization
- make unrun memory plugin groups incomplete and isolate SQLite DB/WAL queries in
  disposable scratch copies
- restrict `not_applicable` to the damage-assessment lane and refuse forced
  reinitialization over finalized artifacts

## Validation expectation

Future case reruns must leave incomplete work visible in `case-status`. A final
Markdown/PDF may be produced only after every evidence item has terminal work,
all retained artifacts still validate, and the hash-bound peer review is ready.
Repair and Windows-VM experiments operate only on derivatives; public attribution
research never uploads evidence or credentials.
