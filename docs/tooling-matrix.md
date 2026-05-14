# Tooling matrix

This matrix is the starting point for the `Forensic Toolsmith` agent. It is intentionally opinionated toward **defensible, Linux-friendly, evidence-driven** workflows.

## Selection heuristics

1. choose the smallest toolchain that answers the case questions
2. prefer tools with strong upstream reputation and reproducible setup paths
3. avoid platform drama unless the evidence actually requires it
4. record why each tool was selected, skipped, or deferred

## Current matrix

| Tool | Primary role | Linux readiness | When to prefer it | Notes |
| --- | --- | --- | --- | --- |
| `bulk_extractor` | content scanning, feature extraction, carving support | High | broad content extraction from images or mounted evidence | Good companion tool, not a full filesystem examiner. |
| `The Sleuth Kit` | partition, volume, filesystem, deleted-file, and metadata analysis | High | raw/E01/AFF4/disk-image workflows and filesystem-level validation | Official upstream: `sleuthkit/sleuthkit`. Foundational for disk and filesystem analysis. |
| `Plaso` | supertimeline generation from multiple artifacts | Medium | timeline-heavy cases where cross-artifact ordering matters | Use when timeline correlation is central; packaging can be dependency-sensitive. |
| `Timesketch` | collaborative timeline analysis and enrichment | Medium | cases with large timelines, team review, tagging, or analysis at scale | Official docs currently point to deploy script and service-oriented setup. Heavier than local CLI-only tooling. |
| `Binwalk` | firmware and opaque binary blob analysis | High | firmware images, embedded artifacts, archives, or nonstandard blobs | Official upstream: `ReFirmLabs/binwalk`. Not a general substitute for filesystem forensics. |
| `FTK Imager` | acquisition, preview, and export in ecosystems that require it | Low on Linux | workflows that explicitly require FTK output or verification in a Windows-capable environment | Treat as proprietary and platform-constrained; do not assume native Linux installation. |
| `KAPE` | targeted Windows artifact collection and parsing orchestration | Low on Linux | Windows triage and targeted acquisition workflows | Treat as Windows-first. Prefer a Windows host or VM and document the path clearly. |
| `Zimmerman tools` | Windows artifact parsing and enrichment | Low on Linux | detailed Windows artifact parsing when native Linux tools are insufficient | Windows-first tool family; use with compatible runtime or Windows environment. |
| `OSDFIR` / artifact repositories | structured artifact definitions and repeatable parsing workflows | Medium | when artifact-definition reuse improves repeatability and coverage | Useful as supporting infrastructure rather than as a single do-everything examiner tool. |
| hashing utilities | evidence verification and handoff integrity | High | every case | Mandatory rather than optional. Capture algorithms and results in the report. |
| SQLite inspection tools | browser, app, and artifact database review | High | app and user-activity artifacts stored in SQLite | Treat as supporting tooling for artifact review and corroboration. |

## Practical defaults on Linux

For a typical Linux-based disk-image examination, the first-pass stack should usually be:

1. hashing utilities
2. The Sleuth Kit
3. `bulk_extractor`
4. SQLite inspection tools and filesystem-specific helpers
5. `Plaso` if timeline depth is needed
6. `Timesketch` only if collaborative or large-scale timeline review is justified

## Platform-specific cautions

- Windows-first tools should be documented, not magically normalized into a Linux host.
- Proprietary tools may require manual download, licensing, or separate analyst workstations.
- Container or VM-based execution can be acceptable when documented and reproducible.

## Maintenance notes

Refresh this matrix when:

- upstream install guidance changes
- a tool becomes unsupported or archived
- a better-supported tool meaningfully replaces a current recommendation
- a new evidence type requires a different default stack
- repeated setup friction or case outcomes show that the current default stack is no longer the best fit

When these triggers occur, run the self-update process described in `docs/self-update-loop.md` and document why the recommendation changed.
