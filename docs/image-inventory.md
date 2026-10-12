# Verified-image metadata inventory runner

`scripts/collect_image_inventory.py` orchestrates installed TSK tools with bounded
waits, durable stage status, provenance, and a preservation gate. It does not
mount images, read the original, extract content, or carve. Independent script
review is required before evidence execution. Author tests use synthetic inputs;
reviewers should also exercise a public NTFS fixture with real installed tools.

Example (replace every placeholder with an approved case path and reviewed offset):

```text
python scripts/collect_image_inventory.py --image /case/working.raw --preservation-state /case/copy-state --preservation-exit-code /case/copy-exit.txt --tsk-bin /tools/tsk/bin --output-dir /case/inventory --sector-size 512 --partition-offset 63 --wait --max-wait-hours 24 --max-stage-hours 24 --reserve-gib 64 --catalog-bodyfile
```

The output parent must exist; the output directory itself must be absent. A
UTF-8/ASCII preservation exit file must contain exactly `0` after whitespace
trimming. The optional `--wait` checks preservation documents, with no image
stat/open until success. Its default maximum is 24 hours, with a hard configurable
ceiling of 168 hours. Each child has an independent finite stage limit. Polling is
five seconds by default; interruption, timeout, nonzero exit and output-capacity
stops produce failed status and retained partial outputs.

## Preservation and path checks

The gate requires preservation schema 1, `phase=complete`, `verified=true`, matching
full source/destination SHA-256, and exact source/copy/checkpoint/destination-read
byte counts. Both status and manifest must identify the selected destination;
status must identify the selected canonical state directory. Source and destination
identities must differ. The source pathname is recorded but never opened or
statted. Numbered image filenames are rejected because TSK may otherwise discover
additional numbered segments outside the explicit input.

Updated preservation manifests also supply final destination metadata, verified
hash and completion UTC. The runner checks all markers agree and compares the
opened image's file identity, size and nanosecond modification time with that final
metadata. Frozen legacy v1 manifests without final metadata use the recorded
destination identity/size and require modification time no later than completion.
Legacy manifests may lack `state_dir`; the canonical selected directory plus its
bound status and destination provide the fallback binding. Both legacy limitations
are recorded in the inventory manifest. No new full image hash is performed.

A read-only Windows handle denies write and delete sharing throughout all child
tools. Incompatible child access fails; the script never weakens sharing. POSIX
uses a cooperative advisory lock and requires external write protection. Image
identity is checked before/after stages. Paths with symbolic-link or junction
aliases are rejected, as are overlapping input/state/tool/output roots. Mutable
resumed state and catalog files must have exactly one hard link.

## Stages, outputs, and resume

The sequence captures each executable's SHA-256 and `-V` output, then runs `mmls`
from whole-image origin, explicit-offset NTFS `fsstat`, shallow long `fls`, recursive
long `fls`, a separate recursive bodyfile, `ils -e` and `ils -p`. NTFS long listings
render times with `-z UTC`. **`ils -z` means unused inodes; it is never passed `UTC`.**

Commands are argument arrays with `shell=False`; child stdout/stderr go directly
to binary files. `manifest.json`, `status.json` and append-only `events.jsonl`
record arguments, input identity, UTC, tool hashes/version, stage PID/progress,
output paths, byte/line counts, output SHA-256, exit status and validation. Empty
results and stderr are retained. Expected headings and all bodyfile rows are
checked; invalid bodyfile rows are counted, with bounded error examples, and block
successful completion. Raw long-fls text is retained without a completeness claim.

Use the identical arguments plus `--resume` only for this runner's output. The
runner binds resume to its own script SHA-256, paths, partition selection, catalog
setting and preservation identity. It verifies previously completed outputs and
tool hashes before reuse. Failed stages receive new numbered attempts, preserving
earlier bytes. Changed scripts need a fresh output directory and new review;
altering the manifest to defeat the binding is not a supported recovery method.

Free space is checked before collection stages and while children run, preserving
the explicit reserve. This is a polling guard: an unusually fast writer can
consume space between polls. SQLite directory-name corroboration uses a 16 MiB
page-cache target and controlled disk scratch, with capacity checks during
indexing. File/line hashes and catalogs stream their inputs; no full image is read
into memory. This is an inventory budget, not approval for unrestricted exports.

## Bodyfile catalog contract

`--catalog-bodyfile` emits `bodyfile-catalog.jsonl`; `bodyfile-statistics.json` is
always produced. Each schema-1 row has:

| Field | Meaning |
| --- | --- |
| `schema_version`, `source_line` | Catalog version and one-based raw bodyfile line |
| `full_path` | Entire TSK-rendered name, including embedded pipes, ADS and all suffix annotations |
| `inode_attribute` | Complete inode or NTFS inode-type-id string; never truncated |
| `mode`, `uid`, `gid`, `size` | Bodyfile values; size is logical row size |
| `atime_epoch`, `mtime_epoch`, `ctime_epoch`, `crtime_epoch` | Original integer bodyfile epoch values |
| `raw_line_sha256` | SHA-256 of raw row with only its line ending removed |
| `deleted_suffix_candidate` | Whether the raw name has TSK's deleted/deleted-realloc suffix |
| `deleted`, `reallocated` | Corroborated long-fls flags when available; otherwise suffix candidates |
| `deletion_corroborated`, `deletion_basis` | Whether exact name/full-ID long-fls corroboration succeeded and its basis |

Parsing splits the first field from the left and the final nine fields from the
right, preserving pipes inside names. Invalid UTF-8 bytes round-trip through JSON
ASCII escapes and Python `surrogateescape`; consumers must preserve them. TSK
itself sanitizes control characters when printing names; this catalog cannot
restore characters absent from its source output.

An allocated file can literally end in `(deleted)`. Exact name and full stream ID
are checked against long-fls record-leading deletion/reallocation flags, and
conflicting matches remain uncorroborated. Downstream recovery must inspect
`deletion_corroborated` and preserve that uncertainty; `deleted` alone is not
sufficient proof. Directory-entry deletion and inode allocation are separate
facts. `ils` remains a separate raw allocation/orphan inventory. Bodyfile-only
`$FILE_NAME` metadata rows may have no exact long-fls stream match.

For NTFS, type 128 (`$DATA`) streams are possible content-export candidates;
type 48 (`$FILE_NAME`) is metadata with a different timestamp source. Preserve all
rows and aliases. Summed row sizes include metadata, directory rows, names and
streams and must not be presented as unique recoverable bytes. File validation,
deduplication and storage planning belong to a separately reviewed recovery lane.

`fls -r` does not descend deleted directories. Neither its successful exit nor a
completed metadata inventory establishes that all deleted files were enumerated
or recovered. Orphans, unallocated blocks, slack, disk gaps, snapshots and nested
containers require their own documented coverage stages. Rendering NTFS times in
UTC does not establish the evidence computer's timezone or a human activity time.

## Validation and manual basis

```text
python -m py_compile scripts/collect_image_inventory.py scripts/test_collect_image_inventory.py
python -m unittest discover -s scripts -p test_collect_image_inventory.py -v
```

Use workspace-controlled `TMP`/`TEMP` for fixtures. The suite uses small invented
images and fake TSK subprocesses; it never examines user evidence. It covers gate
failures, legacy/final metadata, binary output, finite waits/timeouts, unchanged
images, Windows sharing, output isolation, resume, malformed bodyfile rows, and
name/stream/deletion edge cases. Actual-tool fixture validation remains a distinct
review record with the reviewed script's exact hash.

Manuals checked 2026-09-06: [mmls](https://www.sleuthkit.org/sleuthkit/man/mmls.html),
[fsstat](https://www.sleuthkit.org/sleuthkit/man/fsstat.html),
[fls](https://www.sleuthkit.org/sleuthkit/man/fls.html), and
[ils](https://www.sleuthkit.org/sleuthkit/man/ils.html). Installed TSK 4.14.0 help
corroborated the flags. Upstream [file-name rendering source](https://github.com/sleuthkit/sleuthkit/blob/sleuthkit-4.14.0/tsk/fs/fs_name.c)
documents the bodyfile suffix and stream-ID format.
