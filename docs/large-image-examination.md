# Large-image recovery and historical activity examination

Use this workflow for broad recovery, deleted media, historical timelines, or contact analysis from a disk image. It supplements the senior tooling and review loop. A lengthy copy or scan is a running stage, not a completed examination.

## Preservation and storage

1. Record logical size, compression/sparse attributes, hosting device, source metadata, destination device, free space, and output boundaries. Hosting-file timestamps are container metadata, not evidence of activity inside the image.
2. Budget the full logical image size unless the selected tool has validated sparse handling. Source compression can make physical USB reads and logical copy throughput differ substantially.
3. Reserve system free space explicitly. Separately budget the working image, exports, indexes, temporary decompression, and carving duplicates. Enough space for the image does not imply enough space for every recoverable output.
4. Prefer one sequential source read that copies and hashes the bytes, followed by an independent destination read/hash. Record both hashes, byte counts, source identity and stability checks, UTC timing, tool version or script hash, and errors.
5. Use checkpoints, exclusive job ownership, and a documented resume procedure. A partial copy remains unverified until retained bytes have been checked and the complete destination passes verification. Refuse unrelated existing outputs and stale success markers.
6. Keep the source read-only. Never boot an acquired OS or execute recovered programs. Prefer image parsers without writable mounts. Record any justified deviation from verified-copy analysis.

When ordinary copy tools cannot supply the required single-pass hashing, progress, identity checks, and resumability together, the senior specialist may select a reviewed preservation helper. Synthetic fixture review is a prerequisite to real evidence use.

## Durable stages and completion

Write machine-readable status and an append-only event log under the case staging root. Each stage needs a state (`pending`, `running`, `complete`, `failed`, `deferred`, or `unavailable`), input identity, command/tool version, UTC timing, output paths, byte/row counts, exit status, validation result, and limitations. Keep the Markdown report current.

Stages: preservation; partition/filesystem/encryption/OS identification; allocated/deleted/orphan metadata inventory and size planning; filesystem-aware recovery; artifact parsing and timeline; unallocated/slack/disk-gap carving; media validation; contact correlation and independent review.

For long-running local jobs, save enough state for another examiner turn to continue without restarting the source read. Do not leave a partial image exposed as an approved input. Any automatic follow-on process must validate the completed preservation record, process exit, byte counts, matching hashes and working-file identity before reading it. State files can become stale after a crash; a previous success marker must not survive a failed resumed attempt as if it described the new attempt.

Do not infer successful extraction from exit status alone: verify expected files, counts and parseability. Preserve errors and empty results. A disk-space stop must be explicit and resumable and must not produce a completeness claim.

## Recovery layers

Keep separate coverage entries for allocated files, deleted filesystem records, orphan records, volume unallocated blocks, whole-disk gaps, slack, snapshots, and nested containers. Record attempted ranges and exceptions. Inventory relevant classes even when recovery is blocked.

Prefer filesystem-aware recovery because it may preserve names, paths, timestamps, streams and fragmented extents. Preserve metadata even for unreadable/overwritten deleted content. In The Sleuth Kit, `fls -r` does not descend deleted directories; use the official `ils` allocation/orphan inventory and appropriate recovery path before making a broad deleted-entry claim. Check current help for flags and filesystem support.

Treat that manual warning as a completeness limit, not a prediction that every deleted child will be absent. Current versions can expose reconstructed paths or virtual orphan entries in particular images. Validate representative deleted-directory, fragmented-file and alternate-stream cases against known test data, and keep the supplementary inventory regardless of which names appear in one listing.

Do not reuse flags across TSK commands without checking help: `ils -z` selects likely-unused inodes, whereas `fls -z` takes a timezone.

`tsk_recover` defaults to unallocated files; `-e` includes allocated and unallocated files. Do not run an unrestricted export before budgeting sizes. Signature carving complements filesystem recovery and may return fragments, embedded thumbnails, duplicates and false positives. A carved file generally lacks a reliable original name, deletion date, owner or path.

For every export retain image identity, partition offset and unit, filesystem identifier, record/inode and stream, original path if available, allocation state, reported/exported sizes, command/tool, output hash, errors and validation status. Hash deduplication must preserve all source references.

On NTFS retain full TSK attribute identifiers and enumerate alternate data streams. Exporting a bare inode can recover only the default stream. Use `istat`/`ffind` as needed to inspect attributes and names. With `icat`, do not use `-h` for a faithful logical-file export: that option removes sparse holes. Record recovery options and compare exported and expected sizes.

For media distinguish signature recognition, metadata parsing, decoder validation and visual review. Record original metadata timestamps and timezone status. A recognizable extension or header alone does not establish successful recovery.

## Timeline and contact evidence

Retain original timestamps and semantics alongside normalized UTC when conversion is supported. Every event needs source artifact, record ID or byte offset, timestamp field, clock/timezone basis, account association, observation, interpretation, confidence and limitations. Separate filesystem metadata events from application-recorded actions. A copied-file timestamp need not be a local edit; access times need not be human opens; deletion flags rarely establish deletion dates.

Verify timestamp precision and range at the parser boundary. TSK 4.14.0 public-fixture checks reproduced zero/unknown exports for raw NTFS dates in 1960 and 2200, whole-second bodyfile output for a fractional 2009 timestamp, and a preserved 2040 date. These test points do not define every supported boundary. An exact bodyfile timeline cannot restore information lost during native export; retain raw SI/FN FILETIME values for significant chronology and investigate exported zero values. Its type-48 rows use a selected FILE_NAME timestamp set; they do not enumerate every filename attribute. See the versioned [bodyfile implementation](https://github.com/sleuthkit/sleuthkit/blob/sleuthkit-4.14.0/tsk/fs/fs_name.c#L650) and [filename selection](https://github.com/sleuthkit/sleuthkit/blob/sleuthkit-4.14.0/tsk/fs/fls_lib.c#L159).

Establish the evidence timezone from configuration artifacts. Do not impose the analyst host timezone. Distinguish account identifiers, device ownership and the human performing an action.

| Evidence | Supports | Does not establish alone |
| --- | --- | --- |
| Dated message with account, participants and message ID | A recorded communication event | Physical user identity, delivery or reading |
| Conversation database with sender/recipient roles | A locally recorded exchange | Authenticity of an imported database or human control |
| Address book/contact card | A stored contact association | Communication or date of contact |
| Browser visit to profile/webmail | Recorded navigation in a profile | A sent message, login or relationship |
| Bare address/name/string, cache, resource or quotation | A lead requiring context | Contact, conversation, ownership or identity |

Separate drafts, sent/received records, address-book entries, cached pages, automated notifications, spam and unvalidated carved fragments. Preserve message IDs, participant roles, account context, direction, original dates/timezones and delivery limitations. Keep full private artifacts in controlled outputs and use only necessary excerpts in reports.

Test alternatives including shared accounts, imported backups, forwarded messages, software samples, copied media and prior owners. Do not access remote accounts with recovered credentials without separate authority.

## Report and review

Answer the tasking first with sourced findings, confidence, concrete dated examples and limitations. Include recovery manifests, coverage matrix, unresolved identity/timezone issues and remaining work. Report counts by category and validation level; never promise overwritten-byte recovery or assume all deleted history survives.

The challenger must test alternatives for drive purpose, ownership and contact attribution. The peer reviewer checks that each conclusion follows from source records and that completed work is distinct from planned/running stages. Published repository changes contain only generic code, synthetic fixtures and sanitized guidance.

Official command references: [fls](https://www.sleuthkit.org/sleuthkit/man/fls.html), [ils](https://www.sleuthkit.org/sleuthkit/man/ils.html), [tsk_recover](https://www.sleuthkit.org/sleuthkit/man/tsk_recover.html). Consult current documentation before selecting a command.
