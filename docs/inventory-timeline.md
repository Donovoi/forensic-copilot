# Timeline from a completed inventory

`scripts/inventory_timeline.py` creates a source-referenced overview from the reviewed inventory helper's completed catalog. It reads the inventory manifest, status, catalog and explicitly pinned helper module. It never opens the image or recorded preservation paths and invokes no native tools. Independent script review remains required before evidence use.

Pass explicit `--inventory-dir`, `--inventory-module`, `--inventory-sha256`, fresh `--output-dir` and `--state-dir`, `--max-output-bytes`, and `--reserve-bytes`. Parent directories must exist and all roots must be separate. Optional `--reference-utc` controls future-date labels; it is never a date filter. There is no resume or overwrite mode.

The helper requires completed stages, exit zero, matching producer and sidecar identities, and the catalog's exact hash, byte count, row count and zero parse errors. Windows read-only handles deny other writers/deletion throughout processing; POSIX locks are cooperative. Final input checks and output hashes are required for completion. This inherits image provenance from the inventory rather than independently verifying the image again.

Outputs include every catalog row, four timestamp-field observations per row, exact source-line byte positions and hashes, full stream identifiers and aliases, size conflicts, name-state flags, extension/root/year groupings, and a bounded Markdown overview. A SQLite index preserves raw row bytes and escaped JSON names. Literal pipes, percent sequences, duplicate paths and undecodable filename bytes are retained; names never determine output paths or SQL identifiers.

Epochs sort numerically, including values outside signed 64-bit range. Zero remains `zero_unknown`; negative, future and unconvertible integers retain their original values and labels. Invalid timestamp types are retained but force an incomplete outcome. Malformed catalog records stop explicitly. The helper cannot restore raw NTFS precision or date ranges already lost by TSK; use the raw-metadata checks in [large-image examination](large-image-examination.md).

The byte budget includes SQLite, output and state, with control-record headroom. Minimum budget is 8 MiB. Free-space checks are periodic and other writers can consume space between checks. A crash or budget stop leaves partial output and must not be called complete. The derived SQLite index is disposable and is never resumed after failure.

Run synthetic tests with temporary files under approved staging:

```text
python -m unittest discover -s scripts -p test_inventory_timeline.py -v
```

The tests cover exact row references, aliases and unusual names, timestamp boundaries, catalog drift, provenance mismatches, path isolation, budgets and indexed numeric ordering. A public NTFS catalog has also been checked for complete row and four-field preservation. Filesystem observations do not establish ownership, communication, human activity or deletion dates.
