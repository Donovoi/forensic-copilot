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

This creates a visibly non-final `CASE-001.working.md`, `case.json`, independent
per-source working directories, a complete regular-file evidence inventory,
required per-item examination lanes, and a JSON Lines command ledger. It does
not create a final report.

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

`build-tools` creates four minimal images, pulls one upstream image, and records
their resolved Docker metadata in the case root:

- Volatility 3 2.28.0 with its published `full` extra from PyPI on Python 3.12
- the Ubuntu 24.04 packaged Sleuth Kit
- QEMU 11.0.2 `elf2dmp`, built from a checksum-verified official source tarball
- TestDisk and PhotoRec 7.2 from the checksum-verified official static archive
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
Use `--recovery-scope unallocated` for metadata-aware recovery of deleted or
unallocated files. The default remains `allocated`; `--recovery-scope all` maps
to TSK's explicit all-files mode. Each scope has a distinct output name and
metadata record so a partial or allocated-only recovery cannot be mistaken for
deleted-file coverage.
If a recovery tree was produced by an older harness version before tree
manifests were mandatory, run `disk-recover-manifest` only after recovery has
finished. It checks the recorded successful run and working-disk hash, hashes
every recovered file, binds the manifest to the recovery metadata, and only
then records the corresponding coverage lane.
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

### Full cross-source super timeline

Keep every Plaso storage file independent. Export each completed storage with
Plaso's `json_line` output module and retain the storage digest and export
metadata. Normalize Volatility Timeliner output to JSONL objects containing at
least `datetime`, `timestamp_desc`, and `message`. Do not merge Plaso storage
files merely to obtain a combined view.

Create a schema-1 manifest whose `inputs` records contain `path`, `format`,
`evidence_label`, `source_label`, and preferably `sha256`. Supported formats are
`plaso-jsonl`, `plaso-dynamic-csv`, and `volatility-timeliner-jsonl`. Then run:

```bash
python scripts/build_super_timeline.py \
  --manifest /cases/CASE-001/timeline-inputs.json \
  --allow-read-root /cases/CASE-001/timeline-exports \
  --output-dir /cases/CASE-001/reports/super-timeline \
  --summary-regex 'rdp|powershell|vpn|scheduled task'
```

The script validates input hashes, normalizes timestamps to UTC, rejects Plaso
`NotSet`/`Not a time` records explicitly, and uses disk-backed external sorting.
Its full JSONL and CSV contain Timesketch's required `datetime`,
`timestamp_desc`, and `message` fields plus source/evidence labels. The bounded
HTML and CSV summaries are reader views, not substitutes for the full export.
The provenance file records every accepted and rejected input event. Deploying
a Timesketch service is optional; use it when collaborative tagging, analyzers,
or stories justify the additional persistent service, and otherwise retain the
portable import-compatible exports.

### Bounded static string and pattern analysis

Use `run_pattern_analysis.py` for manifest-driven FLOSS, bstrings, and ripgrep
jobs. The manifest identifies the tool, mode, target, patterns, and optional
target manifest. The runner requires non-overlapping approved read and output
roots, validates PE targets before FLOSS, never invokes a shell, and records
tool versions, commands, target hashes, limits, output hashes, timeouts, and
truncation.

FLOSS is limited to stack, tight, and decoded static strings; it does not
execute the PE. bstrings extracts bounded ASCII/Unicode strings. Current
bstrings builds incorrectly switch to standard-input mode whenever stdin is
redirected, so the runner supplies a pseudo-terminal on POSIX and requires an
interactive console on Windows. ripgrep runs without user config, ignores no
in-scope files, follows no symlinks, and applies byte/line caps. Treat every
string or regex hit as a triage lead: library strings indicate capability, not
execution, and shared reports must not reproduce credentials or secrets.

Correlate disk and memory without collapsing provenance:

- process name, PID, parent, command line, executable path, and disk hash
- loaded DLL/module path and its disk counterpart
- socket endpoint, owning process, service, firewall/log evidence, and timestamp
- memory-resident registry/service state and on-disk registry/event-log state
- acquisition time, guest clock, filesystem timestamps, and timezone/clock skew

Every conclusion should point to the source artifact and tool output that supports
it. Record alternative explanations and missing corroboration in the Markdown
report before peer review.

## Signature carving and damaged-filesystem repair

`disk-carve` runs PhotoRec 7.2 over the whole verified raw disk, with the evidence
mount read-only and the result under a separate atomic output directory. It
enables signature families explicitly, selects whole-space scanning, retains
PhotoRec's paranoid validation setting, and hashes every carved file into a
manifest before promotion. Treat the extension as a recovery hint: validate
important artifacts by format and record false-positive or partial-file limits.
PhotoRec complements TSK's metadata-aware unallocated recovery; it does not
replace it.

If one parser reports damaged NTFS metadata, preserve that exact failure. Run
`disk-repair-copy` with the partition's start and length sectors to create and
hash an exact derivative slice. `disk-repair-testdisk` mounts only that
derivative read-write, invokes TestDisk's MFT repair path without networking,
then hashes the result, records changed sector ranges, and checks the result with
independent TSK `fsstat`, recursive `fls`, and any supplied exact failing MFT
records (`--validation-inum`). A per-copy lock and an atomic `running` state
prevent concurrent repair attempts. The original disk is never passed to the
repair container. TestDisk may legitimately make no change because NTFS
`$MFTMirr` normally covers only early metadata records; retain that as a tested
limitation, not as success.

When a Windows-native `chkdsk` cross-check is justified, use current Microsoft
evaluation/WinPE media, verify the ISO against Microsoft's published SHA-256,
and customize a clean, snapshotted VM only as needed for repeatable logging.
Attach no original evidence or verified working disk to Windows: expose yet
another hashed derivative only. Keep the VM offline and record the base ISO,
custom-media hash, VM command, Windows and tool builds, commands, before/after
hashes, filesystem output, and changed extents. Windows-native repair is a
derived-evidence experiment, not a reason to replace or conceal the original
damaged item.

## Attribution and public-source corroboration

Device user, custodian/owner, hosting subscriber, network provider, and operator
are separate claims. Start with local accounts, profiles, sessions, registry
identity, browser/app history, and disk-memory correlation. Public research is
allowed only with recorded case authority, approved identifier classes and
output paths, a query budget, and minimum-necessary disclosure. Never upload an
evidence file, hash, secret, credential, cookie, or bulk personal data.

`extract_firefox_attribution.py` and `extract_chromium_attribution.py` hash the
SQLite database and present WAL, SHM, or rollback-journal companions, copy the
bundle into temporary scratch, and query only that copy so SQLite cannot create
or update companions beside the examined artifact. They redact URL credentials
and sensitive query values. `research_public_ip_attribution.py` records IP-only
RIPE RDAP/RIPEstat lookups and current PTR results with response hashes. Network
registration can support provider attribution, but it does not identify a VPS
subscriber or human operator. The examiner must preserve counter-evidence and
use calibrated confidence when no real-world owner can be defensibly named.

## Completion and final-report gate

Use `case-status` throughout the examination. Every evidence file receives
required work items appropriate to its role. Record durable outputs with
`record-result`; limited work must state the exact limitation and still link its
retained artifacts. The gate regenerates the required lane matrix rather than
trusting mutable ledger entries, rejects missing/duplicate lanes, and permits
`not_applicable` only for damage assessment. Recovery and carving lanes require
tree manifests. Memory coverage requires an explicit successful or retained
failed attempt for every mandatory plugin group; an unrun lane is incomplete.

`prepare-review` refuses pending work, evidence-root inventory drift, missing
evidence links, report placeholders, and incomplete required sections. It then
rehashes all original evidence, verified raw working disks, and manifested
recovered/carved trees before freezing the working report and coverage hashes in
`reviews/review-bundle.json`.

The peer reviewer returns structured JSON bound to those exact hashes.
`finalize-report` holds the case-state lock across its readiness transaction,
accepts only the exact recommendation `ready`, re-runs the deep validation, and
verifies that neither report nor coverage changed. It then creates
`CASE-001.final.md` and `completion.json` atomically. Formal rendering also
requires `--completion` and rechecks the bound hashes. Never rename a draft or
interim narrative to “final” to bypass this lifecycle.

## Current manual basis

- Volatility 3 Windows tutorial and ELF64 layer documentation
- QEMU `dump-guest-memory` and `contrib/elf2dmp`
- The Sleuth Kit `mmls` manual
- TestDisk and PhotoRec documentation
- Plaso Docker and `log2timeline` user documentation

Links and review context are maintained in `docs/sources.md`.
