# Paired VM case runner

## Trigger

A real case supplied two source directories, each containing a compressed raw
disk image, a QEMU ELF memory dump, and a SHA-256 manifest. The repository could
describe the right preservation and analysis principles but had no deterministic
way to enforce boundaries, resume stages, or record paired tool runs.

## Change

- added `scripts/paired_vm_case.py` for discovery, boundary checks, integrity
  verification, atomic working-image creation, container builds, Volatility
  baselines, and Sleuth Kit partition discovery
- added fixture-based standard-library tests
- documented paired-source provenance, direct ELF compatibility testing,
  `elf2dmp` fallback, container limits, and disk/memory correlation
- added minimal Volatility and Sleuth Kit container definitions

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
