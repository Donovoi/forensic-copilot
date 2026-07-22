# Paired VM tool containers

These definitions provide the minimal first-pass tools used by
`scripts/paired_vm_case.py`:

- Volatility 3 `2.28.0` with its published `full` extra for memory triage,
  YARA, disassembly, and cryptographic helpers
- the Ubuntu 24.04 packaged Sleuth Kit for partition and filesystem discovery

The runner records the resolved image metadata and tool output inside the ignored
case root. Evidence is bind-mounted read-only. Containers are read-only and
network-disabled except when the examiner explicitly enables Volatility network
access for Microsoft symbol resolution.

The base images are digest-pinned and the Sleuth Kit package version is explicit.
`build-tools` also records the resolved image metadata and complete Python package
set. PyPI transitive wheels and the Ubuntu repository remain external build
inputs, so keep the resolved image ID as part of the case provenance.

Plaso remains an optional second-stage tool. Prefer the upstream
`log2timeline/plaso` container and record its resolved digest rather than copying
Plaso into these images.
