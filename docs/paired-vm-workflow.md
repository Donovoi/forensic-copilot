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

Long runs update `integrity.progress.json` atomically after every completed
evidence item. That checkpoint is an interruption ledger only: downstream
commands accept only a completed, verified `integrity.json`. The progress file is
removed after the final result is written.

An unlisted hash is reported as `unlisted`; a supplied hash mismatch or invalid
gzip stream fails the gate. Do not reinterpret a mismatch as a filename-format
problem without preserving the mismatch result and checking the manifest.

## Tool preparation

`build-tools` creates three minimal images, pulls one upstream image, and records
their resolved Docker metadata in the case root:

- Volatility 3 2.28.0 with its published `full` extra from PyPI on Python 3.12
- the Ubuntu 24.04 packaged Sleuth Kit
- QEMU 11.0.2 `elf2dmp`, built from a checksum-verified official source tarball
- the upstream Plaso `20260512` image pinned to its published linux/amd64 digest

The definitions remain small so their behavior is inspectable. The resolved
image ID, package/tool version output, build logs, and command ledger belong in
the case record. Rebuild deliberately when upstream inputs change.
Analysis commands require the selected image to exist locally and never perform
an implicit, unrecorded pull.

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
Docker `--network none`. Parallelism defaults to `off` because the first real
QEMU-derived crash dump lost its automagic DTB hit under process parallelism.
Any explicit `threads` or `processes` override is recorded in the command ledger
and should be compatibility-tested with `windows.info` first.

Volatility 3 has an ELF64 segmented layer, so a QEMU ELF physical-memory dump may
work directly. A successful `windows.info` result establishes that the layer and
Windows symbols were resolved; the ELF file signature alone does not.

If symbols are absent, rerun only the compatibility test with `--allow-network`.
This permits automatic Microsoft PDB/symbol resolution while the evidence mount
remains read-only. Do not enable networking for later plugins once the cache is
ready. If the ELF layer still cannot construct the guest address space, convert
a derived working copy with `memory-convert --allow-network`. The adapter mounts
the verified ELF evidence read-only, allows QEMU to request only the required
Microsoft PDB, hashes and atomically promotes the resulting Windows dump, and
retains the original failures and conversion provenance. Analyze it with
`memory --input converted`; never replace the original evidence.

Without `--info-only`, the runner executes independent baseline plugins and
continues after a plugin-specific failure. Each plugin receives a separate JSON
result, stderr log, exit code, and timing record. Failure of one plugin must not
silently suppress the others.

Add `--extended` after the baseline when the evidence warrants a deeper pass.
It adds process cross-view, recovered console history, environment and privilege
context, suspicious-thread/process-tampering checks, scheduled tasks, UserAssist,
and in-memory shim-cache evidence. These plugins remain independent so an
unsupported artifact does not suppress the other results.
Baseline, extended, information-only, and custom invocations retain distinct
`run-summary-KIND.json` files; `run-summary.json` is only the latest summary.

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

`disk-filesystems` parses only allocated `mmls` rows and records `fsstat -i raw
-o SECTOR` output for each offset under the source metadata directory. A
partition-table type such as `0x07` is only a hint; use the filesystem result to
distinguish NTFS, exFAT, encrypted content, or a parser failure.

## Timeline and correlation

Use `timeline` when the case question justifies Plaso's I/O and parser breadth.
It runs the digest-pinned upstream image unattended, defaults to all partitions
and no Volume Shadow Copies, and promotes the separately hashed `.partial`
storage file only after success. Select one source at a time on rotational
storage; later include VSS deliberately with `--vss-stores all` when its added
time and duplicate volume are justified. Plaso documents direct storage-image
input and Docker volume mapping; do not replace its parser with an unreviewed
homegrown implementation.

Plaso can return exit status zero after skipping a path specification. The
adapter therefore also rejects `Processing completed with errors`, unprocessed
path specifications, and internal error-level log records. It retains the store
as incomplete with metadata instead of promoting a deceptively successful
timeline.

If Plaso's NTFS backend cannot open a volume but Sleuth Kit can traverse it,
`disk-recover` provides a controlled fallback: allocated files are recovered
from an explicit sector offset into an atomic derived directory, and
`timeline-recovered` parses that directory read-only. This preserves file
content and artifact parsers but cannot reproduce every original filesystem
metadata event. In particular, do not treat host timestamps on TSK's recovered
copies as original NTFS times; use embedded artifact timestamps, recorded TSK
metadata, or direct filesystem output instead. Retain that limitation and the
direct-image failure in the report.
When a full allocated-file pass is too large for initial triage, resolve a
directory with TSK `ifind` and pass its record as `--directory-inum` to both
commands. The directory number is included in artifact names and provenance so
the scoped result cannot be confused with a complete-volume recovery.
For very high-file-count recoveries, pass a Plaso include list with
`--file-filter`. The adapter validates and hashes the filter, mounts only that
single file read-only, and records its path and digest beside the timeline.
This enables a fast event-log, registry, and user-activity triage pass without
discarding the complete recovered tree or representing the result as exhaustive.

Use `timeline-slice` to export a small, atomic dynamic CSV window around a
memory-derived timestamp. The completed Plaso storage file is mounted read-only,
the export runs without network access, and its metadata links the CSV back to
the timeline SHA-256. This makes focused disk/memory correlation practical
without flattening the entire event store for every question.
Use `--storage-name recovered-offset-SECTOR.plaso` to slice a completed fallback
timeline instead of the default direct-image store.

Use `timeline-query` for a focused Plaso event-filter export without flattening
the entire storage file. It retains all matching events, writes Plaso's own log
inside the case output, atomically promotes the CSV, and records the filter and
source timeline digest in metadata. For example:

```bash
python scripts/paired_vm_case.py timeline-query \
  --case-root /cases/CASE-001 --source HOST-A \
  --filter 'filename contains "server.ps1"' --name server-ps1
```

Use stored event attributes such as `filename`, `data_type`, `source_name`, or
`event_identifier`. Current Plaso releases treat formatted fields such as
`message`, `source`, and `parser` as output-only fields and do not expand them in
event filters. Keep secrets out of a filter when the query metadata will be
shared; the exact expression is deliberately retained in the case record.

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
