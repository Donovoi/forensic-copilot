# Controlled NTFS free-space carving

`scripts/supervise_photorec.py` supervises one fresh Windows PhotoRec 7.2 scan of an explicitly preserved raw image's primary MBR NTFS partition. Python 3.10+ and the exact reviewed Windows PhotoRec/TSK packages are required. Independent script/tool review is required before evidence use. No mounts, repairs, image writes, recovered-program execution or automatic resume are implemented.

The helper pins the inventory preservation gate and the executable/DLL set in `scripts/photorec-7.2-tools.json`. Obtain tools through the senior tooling loop; do not substitute a version or edit the allowlist merely to bypass a mismatch. A different tool package requires a reviewed adaptation and fresh validation.

All paths and geometry are explicit: `--image`, `--preservation-state`, `--preservation-exit-code`, `--gate-module`, `--approved-tools`, `--photorec-dir`, `--tsk-bin`, fresh `--state-dir` and `--output-dir`, `--partition-number`, `--partition-offset`, `--partition-length`, and `--sector-size 512`. Use the completed inventory's geometry. Required `--max-output-gib` and optional runtime/file/log limits need a deliberate storage plan. The minimum reserve is 64 GiB plus a write cushion of at least 1 GiB; the default cushion is 2 GiB.

No image read/stat occurs before the preservation gate. Read-only Windows handles protect evidence and tools during native use. A kill-on-close Windows job contains each child. Fresh child home, temporary and working directories isolate PhotoRec preferences and sessions.

MBR, NTFS boot and TSK geometry must agree. The conservative partition-length check prevents a reproduced PhotoRec fallback that scanned the whole partition despite a requested free-space scan when NTFS recognition failed. The helper discovers the unique unnamed DATA attribute of allocated MFT record 6, exports the complete initialized `$Bitmap`, and checks its exact size. Failed geometry is refused without repairing evidence or widening the scan.

The scan enables carving families except Dovecot. Native fixture tests found its weak zero signature could create false positives and truncate a valid WAV; the omission remains an explicit coverage gap. Other false positives, embedded files and fragments remain possible.

Completion requires native exit zero, empty stderr, normal completion/count markers, an NTFS bitmap-filter trace and closed bounded XML reports. Source identity, partition bounds, structure and every reported physical extent are checked against currently unallocated clusters, including padding. Ordinary exports need unique report mappings, matching sizes and stable SHA256s. Six known report-only metadata families remain distinct from files. Exact `t` plus at least seven digits plus `.jpg` thumbnails may lack XML mappings; these are hashed but their parentage and allocation provenance remain unverified.

Runtime, bytes, file count, logs and free space are **polled stop thresholds**, with possible overshoot. They are not hard quotas. A slow directory traversal stops the scan. Stops retain partial files and explicitly incomplete state; unfinished hashes or partial inventories may be deferred or truncated. Preserve the attempt before planning any continuation because PhotoRec can overwrite an existing report during resume.

State includes inputs, commands, stream logs, bitmap information, status/events, output hashes and supervisor exit records. Completion requires the actual invocation exit as well as current status. Hashes and allocation checks establish retained bytes and reported source extents; they do not establish historical authenticity, successful decoding, original names or exhaustive deleted-file recovery. Slack, disk gaps, allocated files, other partitions and snapshots remain separate layers.

Run synthetic tests with approved staging for temporary files:

```text
python -m unittest discover -s scripts -p test_supervise_photorec.py -v
```

Tests cover binary bitmap handling, geometry, XML/provenance failures, path aliases, space/runtime stops, native-child cleanup and allocation controls. Separate native public-fixture checks recovered an exact free-cluster sentinel and excluded an allocated sentinel. A positive extraction alone is insufficient to validate free-space scope.

Official sources: [PhotoRec usage](https://www.cgsecurity.org/testdisk_doc/photorec.html), [scripted syntax](https://www.cgsecurity.org/testdisk_doc/scripted_run.html), [7.2 source](https://www.cgsecurity.org/testdisk-7.2.tar.bz2), [TSK icat](https://www.sleuthkit.org/sleuthkit/man/icat.html), [istat](https://www.sleuthkit.org/sleuthkit/man/istat.html) and [fsstat](https://www.sleuthkit.org/sleuthkit/man/fsstat.html).
