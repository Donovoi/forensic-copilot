# Verified gzip intake

`scripts/intake_gzip.py` creates raw working files from compressed evidence using
Python's standard library. It makes no network requests and starts no VM or
container. It is a logical transformation, not an acquisition tool or filesystem
parser. It does not populate the paired-case completion ledger.

Before use, approve the input and output roots, confirm capacity, and record the
reviewed script hash and supplied compressed-file hashes in the private case
record. A hash provided alongside an image establishes a comparison target;
agreement does not independently prove the image's origin or completeness.

The private JSON manifest contains one or more items with absolute paths:

```json
{
  "items": [
    {
      "source": "/evidence/HOST-A.img.gz",
      "expected_sha256": "<64 hexadecimal characters from the source manifest>",
      "destination": "/cases/CASE-001/working/HOST-A.raw"
    }
  ]
}
```

Destination parents must already exist. Existing final files, partial files,
status files, overlapping targets, symlinks and Windows reparse points are
refused. All capacity choices are explicit; the following values are examples
and must be replaced with the approved per-image limit and storage reserve:

```bash
python scripts/intake_gzip.py /cases/CASE-001/intake.json \
  --max-output-gib 100 --reserve-gib 20 --validate-only
python scripts/intake_gzip.py /cases/CASE-001/intake.json \
  --max-output-gib 100 --reserve-gib 20
```

Validation-only reads the manifest and source metadata, not source contents, and
creates no outputs. Processing checks free space before every decompressed
chunk and during the independent output reread. The expansion limit applies to
logical bytes even when zero blocks are stored sparsely. Free-space checks are
conservative and cannot reserve capacity against other running programs.

Each compressed stream is hashed as read, and Python gzip validates CRCs,
truncation and concatenated members. The raw bytes are hashed while written to a
new `.partial` file, flushed, then independently read and hashed. The final file
appears only after the expected compressed hash, complete byte counts, raw hash
comparison and source identity checks succeed. Failures retain the partial and
failure status; there is no resume or overwrite option.

The `.status.json` record includes script/runtime provenance, progress, source
identity, both raw hashes and the first 512 decompressed bytes in hexadecimal.
Keep it private. Accept only `stage: complete` with the hash, byte-count and
source-invariance checks true. Recheck the final file's hash before later use if
it may have changed. A killed process may leave stale progress; status alone
cannot establish that a process is still active. A publication/status failure
can leave a final file needing explicit review.

Windows handles deny other writers and deletion while open. POSIX does not have
the equivalent sharing lock here; externally protect the input against writes.
Neither mode is a hardware write blocker, and reads may update access metadata.
The analyst-controlled output directory must not be concurrently modified.

Synthetic validation runs in the normal image-workflow test matrix:

```bash
python -m unittest discover -s scripts -p test_intake_gzip.py -v
```

Official API basis: [Python gzip](https://docs.python.org/3/library/gzip.html),
[Python file operations](https://docs.python.org/3/library/os.html), and
[Windows CreateFileW sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
