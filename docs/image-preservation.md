# Verified image preservation

`scripts/preserve_image.py` is a standard-library fallback for copying an existing regular image file to analyst-controlled storage. It supplies a repeatable preservation record when a short native copy command does not provide stream hashing, resumable prefix verification, and durable progress together. It does not acquire a physical disk, repair unreadable sectors, parse evidence, or recover deleted files. Route proposed evidence use through the script reviewer first.

Python 3.10 or newer is required. Source, destination, and state directory are explicit arguments. Keep the image and the state directory under approved ignored case paths. The state directory contains case-specific absolute paths, file identities, hashes, and operational errors and must remain private. Destination and state parent directories must already exist; a fresh run requires both destination and state directory to be absent.

Example using placeholder paths:

```powershell
python scripts/preserve_image.py 'E:\evidence\image.raw' 'C:\cases\CASE-001\image.raw' --state-dir 'C:\cases\CASE-001\preservation' --dry-run
python scripts/preserve_image.py 'E:\evidence\image.raw' 'C:\cases\CASE-001\image.raw' --state-dir 'C:\cases\CASE-001\preservation'
```

A fresh run reads the source sequentially once while calculating SHA256. After copying it flushes and calls `fsync`, then re-reads the complete destination with an independent SHA256 object. The destination handle stays protected throughout verification to avoid a close/reopen replacement race. This verifies logical file bytes returned by the OS; it is not a cache-bypassing media read test. Compression, sparse allocation, ACLs, alternate data streams, and source filesystem metadata are not copied. A compressed source may need its entire logical size on the destination volume.

The default capacity guard reserves 64 GiB beyond the expected remaining copy; `--reserve-gib` can adjust this for a planned recovery workload. Capacity is checked before copying and before each write. Disk capacity can still change between a check and write; an I/O failure leaves an incomplete output. The script never skips read errors or fills unreadable bytes with zeroes.

On Windows, the source is opened read-only with `FILE_SHARE_READ` only, which denies simultaneous writers and deletion and refuses an existing incompatible writable handle. The destination also denies other writers and deletion. The state lock prevents simultaneous script attempts. On POSIX, file locks are advisory, so external write protection remains necessary. The script never sets source timestamps or attributes; filesystem access-time updates caused by reads remain possible. A hardware write blocker or read-only source volume is stronger protection than file sharing.

An interrupted run may be resumed with the same paths and `--resume`. Resume requires the original manifest, matching source identity/size/modification time and destination identity. It compares every retained destination byte against the corresponding source byte, including any tail written after the last durable checkpoint, and reconstructs the source SHA256 state. It appends only after this comparison succeeds. A mismatch stops without truncation or append. Resuming therefore re-reads the source prefix and can take substantial time. There is no trust-prefix or overwrite mode.

An actual resume attempt first binds the selected state directory to the manifest's recorded absolute destination path, obtains its exclusive state lock, and atomically replaces any previous success status with `validating_resume` and `verified: false`. Source/path/metadata, capacity, and prefix checks follow that invalidation. A subsequent failure records `failed`, including failures before the source can be opened. Use the recorded canonical destination path when resuming. Arguments pointing to a different destination/state pair, unusable or untrusted manifests, and failure to acquire a running attempt's lock are rejected without changing that state. This avoids damaging another case's record. Dry runs remain read-only and do not invalidate earlier results.

`manifest.json` records provenance, tool/runtime details, script hash, initial arguments, and source metadata. `events.jsonl` records starts, resume-prefix verification, completion, or failure. `status.json` is replaced atomically about every five seconds, subject to I/O latency. Copy checkpoints follow a destination flush/fsync. The phases are `validating_resume`, `copying`, `verifying_resume_prefix`, `verifying_destination`, `failed`, and `complete`. Reading the progress file is safe while the copy runs. If a process is killed or the volume becomes unavailable, its last status may remain stale; check process state and timestamps. If initial setup fails before the manifest is written, no resume is possible without examiner review of the newly created empty output/state directory.

Only `phase: complete` with `verified: true`, the expected byte count, and matching source-stream/destination hashes is preservation completion. Successful status also records `destination_metadata` containing device/file identity, size, and modification time in nanoseconds from the protected verified file handle. The manifest stores this as `final_destination_metadata` with its last successful verification time/hash; those manifest fields are historical and cannot replace the current status check. Before downstream examination, compare the current destination identity, size, and modification time against this successful metadata. A difference requires renewed verification. This metadata comparison is a conservative unchanged-file gate, not proof against deliberate same-size/mtime-preserving modification; rehash when stronger assurance is required. Older manifests without completion metadata need a new verification or another reviewed gate.

The destination name exists during copying; downstream examination must check the status first. A successful copy does not establish how or when the original image was acquired and does not guarantee the underlying image was complete or error free.

Synthetic verification (no evidence paths):

```powershell
python -m py_compile scripts/preserve_image.py scripts/test_preserve_image.py
python -m unittest discover -s scripts -p test_preserve_image.py -v
python scripts/preserve_image.py --help
```

Official API basis, reviewed 2026-09-06: [Python os and fsync](https://docs.python.org/3/library/os.html#os.fsync), [Python hashlib](https://docs.python.org/3/library/hashlib.html), [Microsoft CreateFileW sharing and access semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), and [Python msvcrt.open_osfhandle](https://docs.python.org/3/library/msvcrt.html#msvcrt.open_osfhandle).
