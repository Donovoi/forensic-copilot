# Paired VM disk and memory workflow

Use this workflow when one source is represented by both a disk image and a
volatile-memory capture. The pair belongs to one analytical source, while each
file retains its own provenance, hash, format, parser, and limitations.

## Boundaries and preservation

Declare three roots before collection or analysis:

- input/read root containing the original evidence
- compute/staging root for working images, caches, and tool state
- output/report/export root for logs, derived artifacts, and the Markdown report

The current runner requires the case root to be completely separate from the
evidence root. It refuses evidence symlinks, never writes beside an evidence
file, writes state atomically, and keeps interrupted decompression output under a
distinct `.partial` name for explicit review.

Initialize the case before running a parser:

```bash
python scripts/paired_vm_case.py init \
  --case-id CASE-001 \
  --evidence-root /evidence/paired-vms \
  --case-root /cases/CASE-001
```

This creates a report stub early, `case.json`, independent per-source working
directories, and a JSON Lines command ledger.

## Integrity gate

Run `verify` before creating working images. It calculates SHA-256 for each disk
and memory file, parses common two-line and `sha256:` manifest layouts, and fully
decompresses each gzip stream to a discard sink so CRC and truncation errors are
detected. The disk SHA-256 and gzip validation share one compressed-byte pass to
avoid doubling I/O on large evidence.

Add `--prepare-working-disks` to write the separately hashed raw working image
during that same pass. The `.partial` file is promoted atomically only after the
gzip stream succeeds and the compressed hash does not mismatch the supplied
manifest. This avoids a second full decompression without weakening the gate.

An unlisted hash is reported as `unlisted`; a supplied hash mismatch or invalid
gzip stream fails the gate. Do not reinterpret a mismatch as a filename-format
problem without preserving the mismatch result and checking the manifest.

## Tool preparation

`build-tools` creates two minimal images and records their resolved Docker image
metadata in the case root:

- Volatility 3 2.28.0 with its published `full` extra from PyPI on Python 3.12
- the Ubuntu 24.04 packaged Sleuth Kit

The definitions remain small so their behavior is inspectable. The resolved
image ID, package/tool version output, build logs, and command ledger belong in
the case record. Rebuild deliberately when upstream inputs change.

The Dockerfiles pin their base-image digests, Volatility release, and Sleuth Kit
package version. They do not yet hash-pin every transitive Python wheel or snapshot
the Ubuntu package repository. Treat the recorded resolved image IDs and Python
package inventory as required provenance, and do not claim that a fresh future
build is byte-identical.

## Memory first pass

Start with a network-disabled compatibility test:

```bash
python scripts/paired_vm_case.py memory \
  --case-root /cases/CASE-001 \
  --info-only
```

Network-disabled runs pass Volatility's explicit `--offline` flag as well as
Docker `--network none`. The default `processes` parallelism is recorded in the
command ledger and can be reduced with `--parallelism threads` or `off` when an
environment or plugin behaves poorly.

Volatility 3 has an ELF64 segmented layer, so a QEMU ELF physical-memory dump may
work directly. A successful `windows.info` result establishes that the layer and
Windows symbols were resolved; the ELF file signature alone does not.

If symbols are absent, rerun only the compatibility test with `--allow-network`.
This permits automatic Microsoft PDB/symbol resolution while the evidence mount
remains read-only. Do not enable networking for later plugins once the cache is
ready. If the ELF layer still cannot construct the guest address space, convert
a working copy with QEMU `elf2dmp`, hash the conversion, and retain the original
failure and conversion provenance.

Without `--info-only`, the runner executes independent baseline plugins and
continues after a plugin-specific failure. Each plugin receives a separate JSON
result, stderr log, exit code, and timing record. Failure of one plugin must not
silently suppress the others.

## Disk first pass

`prepare-disks` streams each already-verified gzip file into a separately hashed raw working image,
fsyncs it, and renames it atomically only after successful completion. It refuses
to overwrite completed or partial outputs unless the examiner supplies the
specific restart/force flag. The command refuses to run until `integrity.json`
reports a verified result. Prefer `verify --prepare-working-disks` when avoiding a
second decompression is operationally important.

`disk-layout` runs `mmls -B -i raw` with the working-image directory bind-mounted
read-only into a read-only, network-disabled container. Review the resulting
partition table before selecting filesystem offsets, BitLocker handling, volume
shadow copies, deleted-entry work, or timeline parsers.

## Timeline and correlation

Use the upstream `log2timeline/plaso` container for a timeline when the case
question justifies the I/O and parser breadth. Record its resolved digest and run
full-image timelines serially on rotational storage. Plaso documents direct
storage-image input and Docker volume mapping; do not replace its parser with an
unreviewed homegrown implementation.

Correlate disk and memory without collapsing provenance:

- process name, PID, parent, command line, executable path, and disk hash
- loaded DLL/module path and its disk counterpart
- socket endpoint, owning process, service, firewall/log evidence, and timestamp
- memory-resident registry/service state and on-disk registry/event-log state
- acquisition time, guest clock, filesystem timestamps, and timezone/clock skew

Every conclusion should point to the source artifact and tool output that supports
it. Record alternative explanations and missing corroboration in the Markdown
report before peer review.

## Current manual basis

- Volatility 3 Windows tutorial and ELF64 layer documentation
- QEMU `dump-guest-memory` and `contrib/elf2dmp`
- The Sleuth Kit `mmls` manual
- Plaso Docker and `log2timeline` user documentation

Links and review context are maintained in `docs/sources.md`.
