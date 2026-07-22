# Paired VM case runner

## Trigger

A real case supplied two source directories, each containing a compressed raw
disk image, a QEMU ELF memory dump, and a SHA-256 manifest. The repository could
describe the right preservation and analysis principles but had no deterministic
way to enforce boundaries, resume stages, or record paired tool runs.

## Change

- added `scripts/paired_vm_case.py` for discovery, boundary checks, integrity
  verification, atomic working-image creation, container builds, Volatility
  baselines, Sleuth Kit partition/filesystem discovery, and atomic Plaso timelines
- added fixture-based standard-library tests
- documented paired-source provenance, direct ELF compatibility testing,
  `elf2dmp` fallback, container limits, and disk/memory correlation
- added minimal Volatility and Sleuth Kit container definitions
- added a checksum-verified QEMU 11.0.2 `elf2dmp` build and atomic conversion adapter
- added offline, provenance-linked Plaso time-slice CSV exports for focused correlation
- added an explicit-offset, allocated-file-only TSK recovery and recovered-directory
  Plaso fallback for volumes that TSK can traverse but Plaso's NTFS backend cannot
- added an opt-in extended memory pass after real evidence exposed the need for console,
  cross-view, persistence, and process-tampering checks beyond the initial baseline
- preserved per-invocation memory summaries so a focused follow-up cannot erase the
  baseline run record
- corrected the timeline export adapter after live Plaso 20260512 probes rejected
  the historical output identifier and exposed an internal-log write outside the
  read-only container; exports now use dynamic CSV and an explicit writable log path
- applied the same explicit log-path guard to extraction after an NTFS error showed
  that Plaso's lazy logger otherwise masks the original filesystem exception
- rejected Plaso's exit-zero partial success after a damaged/unsupported NTFS MFT
  caused the main partition to be skipped while only the boot partition was stored
- added a hashed, single-file read-only Plaso include filter after live recovery
  exposed a multi-million-file corpus that would make an initial full parse wasteful
- added directory-inode-scoped TSK recovery with distinct artifact names so critical
  logs can be triaged without presenting a partial directory recovery as a full volume
- updated renamed Volatility malware plugin identifiers after 2.28.0 emitted removal
  warnings for the legacy aliases during live analysis
- added atomic, offline Plaso event-filter exports after the case required a
  filename query across millions of stored events; the adapter preserves all
  matches, passes the filter as one non-shell argument, and gives Plaso an
  explicit writable logfile inside the case output

## Basis

The change follows the current Volatility 3 ELF and Windows guidance, QEMU memory
dump and `elf2dmp` documentation, The Sleuth Kit `mmls` manual, and Plaso's
documented Docker workflow. Real fixture testing also exposed and removed an
unnecessary dependency on the external GNU `gzip` executable.
The first real large-file run also showed that separate hashing and gzip testing
doubled evidence I/O, so they were combined into one compressed-byte pass.
The review also found that downstream commands did not enforce the integrity
result and that known raw images were left to format autodetection. Downstream
evidence commands now require a verified gate, and `mmls` receives `-i raw`.
The first builds also showed moving base tags and an implicit Sleuth Kit package;
the public definitions now pin both base digests and the observed package version,
while recording the remaining transitive Python dependency set and limitation.
The multi-hour shape of real paired-image verification also justified an atomic
per-item progress ledger. It preserves interruption context but is deliberately
not accepted as the completed integrity gate.
The first converted crash-dump probe also showed that Volatility process
parallelism could lose a valid DTB hit; the safe default is now `off`, with
parallel modes retained as recorded, compatibility-tested opt-ins.

## Guardrails checked

The runner refuses overlapping roots and evidence symlinks, writes no evidence
paths, keeps partial outputs explicit, uses read-only evidence mounts, records
network exceptions, retains independent tool failures, and writes case-specific
state only below ignored case roots.

## Expected improvement

Future paired VM cases should reach a verified, reproducible first-pass result
without rebuilding shell command chains or losing provenance between disk and
memory lanes.

## Publication checks

All committed examples use generic case, host, and path placeholders. No case
hashes, filenames, addresses, absolute analyst paths, or evidence outputs are
included.
