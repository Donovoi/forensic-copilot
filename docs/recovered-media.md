# Bounded recovered-media metadata checks

`scripts/probe_recovered_media.py` is a Windows/Python 3.10+ standard-library supervisor for explicit, hash-bound recovered files. It reads selected exports and their producer records; it never opens, hashes, mounts or stats an image named in that provenance. Independent review of the applicable script, tool packages and input scope remains required before evidence use. The source retains its original pre-review header to preserve the independently reviewed bytes; approval records are maintained separately.

## Select a closed producer result

Supply a strict UTF-8 batch JSON and its SHA256. Its fields are exactly:

| Field | Value |
| --- | --- |
| `schema_version` | Integer `1` |
| `producer_kind` | `recovery` or `photorec` |
| `producer_sha256` | Approved producer script SHA256 |
| `source_state` | Canonical producer state directory |
| `source_files` | Mapping from `inputs.json`, `status.json`, and the producer manifest filename to their SHA256 values |
| `source_exit`, `source_exit_sha256` | Explicit producer invocation exit marker and its SHA256 |
| `export_root` | Canonical controlled export directory from producer provenance |
| `artifacts` | List of objects containing exactly one-based `source_line` and expected output `sha256` |

The recovery manifest is `export-attempts.jsonl`; the PhotoRec manifest is `output-manifest.jsonl`. The batch is limited to one MiB and 10,000 unique selected lines, with one MiB per source row and 16 MiB of selected provenance. Use smaller explicit batches when necessary. Paths or extensions do not select evidence. Each output path must belong to the producer's flat numeric export layout or immediate `recup.N` directory, and its full hash, size and file identity must match.

Recovery can supply closed complete, partial, failed or interrupted attempts when full output hashes and metadata exist and producer exit/status agree. PhotoRec requires its completed state, successful invocation, matching configuration and status-bound output manifest. Metadata-only partial carve records are deferred. Reallocated clusters, partial exports and unmapped thumbnail parents retain their original caveats; metadata parsing does not upgrade them.

Inputs must be canonical regular single-link files on fixed local volumes. UNC/device/alternate-stream paths, symbolic links, junctions/reparse points and redirects outside the export root are refused. Read-only Windows handles deny write/delete sharing on input records, selected files and tool dependencies. Containing directories must remain under exclusive analyst control; these checks do not defend against arbitrary hostile directory replacement.

## Provision the approved tools separately

The tool manifest has exactly `schema_version: 1` and `tools`, with `ffprobe` and `exiftool` groups. Each group has its canonical `root`, relative `executable` name, verified `version`, and `files` mapping relative dependency paths to SHA256. Use lowercase hexadecimal digests in manifests. The complete ExifTool package and selected ffprobe executable/DLL set must match. The CLI binds this manifest's SHA256. The worker neither installs tools nor updates this manifest.

Native validation used ExifTool 13.59 and ffprobe 8.1.1. Renew validation for a different build or dependency set. Supply the pinned repository inventory helper only for its path, locking and atomic-file functions; the media worker does not call its image-gate APIs.

Inspect `python scripts/probe_recovered_media.py --help`. Required arguments are `--batch`, `--batch-sha256`, `--tools-manifest`, `--tools-sha256`, `--gate-module` and `--state-dir`. All paths and approval values are explicit. `--dry-run` validates the selected provenance and tool set without probing recovered file contents. Start with a fresh owned state directory; `--resume` requires the same bound inputs and policy.

## Parser and resource limits

Binary headers select only PNG, JPEG, RIFF/WAVE and recognized `ftyp` MP4/MOV brands. Other signatures remain hashed deferred records. ffprobe receives one forced `png_pipe`, `jpeg_pipe`, `wav` or `mov` demuxer, the matching format whitelist and a file-only protocol whitelist. There is no automatic fallback, image sequence expansion, script/playlist demuxing, network protocol or hardware decoding. MOV external references and absolute paths are explicitly disabled. Native external-track fixtures still exit zero when media is skipped; warning-level diagnostics therefore make that result incomplete.

ExifTool receives `-config` and a genuine empty argument first, followed by fixed read-only options and tags. Implicit analyst configurations, writing options, formulas, alternate source files and embedded extraction are disabled. `-fast2` intentionally omits some metadata. Device, GPS and identifying metadata remain controlled private outputs.

Each child starts suspended, joins a kill-on-close Windows job with process/aggregate memory limits, then runs with a controlled cwd/temp/home and minimal environment. Defaults allow four related processes, 512 MiB committed memory, 60 seconds per child, one MiB stdout and 64 KiB stderr. ffprobe also limits probing, analysis, streams, threads and individual allocations. The worker fully hashes each file before and after probing, with default 16 GiB and 1,800-second bounds per hash.

State storage defaults to 512 MiB with a 64 GiB free-space reserve. Storage checks are polled stop thresholds with write allowances, not filesystem quotas. The six-hour batch threshold is checked between bounded files. Timeouts, memory limits and storage stops remain resource outcomes, not proof of damaged media. These controls are not an OS security sandbox for native parser vulnerabilities.

## Results and verified resume

Numbered per-file records preserve source references, full hashes, processing UTC times, exact commands, parsed metadata, raw bounded captures, exits and errors. `records-index.json` binds finalized record hashes and identities. Resume independently checks that index, the exact child commands, retained capture paths/hashes/metadata and parsed JSON before reuse. Missing or changed records/captures create another numbered attempt and retain earlier data. Failed, unknown and incomplete results are retried; they cannot count as previously successful analysis.

`probe_ok` requires both tools to return usable expected JSON, exit zero and no diagnostics, capture errors or resource stops. It establishes bounded metadata/header checks only. It does not prove full decode, media authenticity, complete recovery, historical timezone, drive ownership or contact. The batch is `complete` only when all selected files qualify; otherwise it retains explicit gaps. CLI exits are `0` for complete/dry-run, `2` for a returned incomplete batch, `1` for an operational exception and `130` for interruption.

Windows synthetic tests run explicitly with `python -m unittest discover -s tests/windows -p 'test_*.py' -v`; CI runs them on Windows with Python 3.10 and 3.12. Native cross-format, disabled-config and external-reference fixtures require separately provisioned approved tools and independent local review. Synthetic CI does not claim that native tool validation occurred on each CI host.

Primary basis: [ffprobe options](https://ffmpeg.org/ffprobe.html), [FFmpeg demuxer options](https://ffmpeg.org/ffmpeg-formats.html), and [ExifTool maintained command documentation](https://github.com/exiftool/exiftool/blob/master/exiftool). See [catalog recovery](catalog-recovery.md) and [supervised carving](supervised-carving.md) for the producer provenance.
