# Paired VM tool containers

These definitions provide the minimal first-pass tools used by
`scripts/paired_vm_case.py`:

- Volatility 3 `2.28.0` with its published `full` extra for memory triage,
  YARA, disassembly, and cryptographic helpers
- the Ubuntu 24.04 packaged Sleuth Kit for partition and filesystem discovery
- QEMU 11.0.2 `elf2dmp` for the controlled QEMU ELF-to-Windows-dump fallback

The runner records the resolved image metadata and tool output inside the ignored
case root. Evidence is bind-mounted read-only. Containers are read-only and
network-disabled except when the examiner explicitly enables Volatility network
access for Microsoft symbol resolution.

The base images are digest-pinned and the Sleuth Kit package version is explicit.
`build-tools` also records the resolved image metadata and complete Python package
set. PyPI transitive wheels and the Ubuntu repository remain external build
inputs, so keep the resolved image ID as part of the case provenance.

The `elf2dmp` image verifies the official QEMU source tarball SHA-256 before
building only the required tool. Runtime conversion needs Microsoft symbol
access, writes only below the case conversion directory, and leaves the original
ELF evidence read-only.

Plaso remains an optional second-stage tool. `build-tools` pulls the upstream
`20260512` image by its linux/amd64 digest and records the resolved metadata;
`timeline` runs it serially without copying Plaso into these images. Focused
`timeline-slice` and `timeline-query` exports mount completed storage read-only
and write their CSV, metadata, and Plaso logfile only inside the case output.
