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
| `bulk_extractor` | content scanning, feature extraction, carving support | High | broad content extraction from images or mounted evidence | Good companion tool, not a full filesystem examiner; on Linux server user-activity cases it is usually corroborative rather than primary proof of logon or browsing. |
| `The Sleuth Kit` | partition, volume, filesystem, deleted-file, and metadata analysis | High | raw/E01/AFF4/disk-image workflows and filesystem-level validation | Official upstream: `sleuthkit/sleuthkit`. Foundational for disk and filesystem analysis. |
| `Plaso` | supertimeline generation from multiple artifacts | Medium | timeline-heavy cases where cross-artifact ordering matters | Use when timeline correlation is central; packaging can be dependency-sensitive. |
| `Timesketch` | collaborative timeline analysis and enrichment | Medium | cases with large timelines, team review, tagging, or analysis at scale | Official docs currently point to deploy script and service-oriented setup. Heavier than local CLI-only tooling. |
| `Binwalk` | firmware and opaque binary blob analysis | High | firmware images, embedded artifacts, archives, or nonstandard blobs | Official upstream: `ReFirmLabs/binwalk`. Not a general substitute for filesystem forensics. |
| `FTK Imager` | acquisition, preview, and export in ecosystems that require it | Low on Linux | workflows that explicitly require FTK output or verification in a Windows-capable environment | Treat as proprietary and platform-constrained; do not assume native Linux installation. |
| `KAPE` | targeted Windows artifact collection and parsing orchestration | Low on Linux | Windows triage and targeted acquisition workflows | Treat as Windows-first. Prefer a Windows host or VM and document the path clearly. |
| `Zimmerman tools` | Windows artifact parsing and enrichment | Low on Linux | detailed Windows artifact parsing when native Linux tools are insufficient | Windows-first tool family; use with compatible runtime or Windows environment. |
| `OSDFIR` / artifact repositories | structured artifact definitions and repeatable parsing workflows | Medium | when artifact-definition reuse improves repeatability and coverage | Useful as supporting infrastructure rather than as a single do-everything examiner tool. |
| `ForensicArtifacts` / `artifacts-kb` | artifact-family coverage and checklist support | High | when you need a structured reminder of which artifact families should exist on a host role or platform | Useful for coverage and terminology; not a standalone proof engine. |
| hashing utilities | evidence verification and handoff integrity | High | every case | Mandatory rather than optional. Capture algorithms and results in the report. |
| SQLite inspection tools | browser, app, and artifact database review | High | app and user-activity artifacts stored in SQLite | Treat as supporting tooling for artifact review and corroboration. |
| `uv` | run local Python helper scripts and Python-based CLI tools | High | when the workflow includes local automation such as report packaging | Good wrapper for repo scripts and Python CLIs; do not treat it as the installer for non-Python binaries such as `pandoc`. |
| `Pandoc` | render reviewed Markdown into formal HTML, DOCX, or PDF-ready outputs | Medium | when peer review has cleared the report and a formal package is needed | Keep Markdown as the source of truth. PDF output still depends on an available renderer or PDF backend. |

## Practical defaults on Linux

For a typical Linux-based disk-image examination, the first-pass stack should usually be:

1. hashing utilities
2. The Sleuth Kit
3. `bulk_extractor`
4. SQLite inspection tools and filesystem-specific helpers
5. `Plaso` if timeline depth is needed
6. `Timesketch` only if collaborative or large-scale timeline review is justified

## Report-production defaults

For formal report output:

1. keep the working report in Markdown
2. wait for peer review to return `ready`
3. use `uv run` to invoke local export scripts when the repo ships them
4. use `Pandoc` to render standalone HTML or DOCX from the reviewed Markdown
5. render PDF with a supported local backend such as `weasyprint` or `wkhtmltopdf` when available

`uvx` or `uv tool run` is a good fit for Python-based CLI helpers. It is not a substitute for installing system binaries such as `pandoc`.

## Linux server user-activity bias

For Linux server user-activity cases, first-pass collection should lean toward:

1. authentication and session artifacts (`auth.log`, `secure`, `wtmp`, `btmp`, `lastlog`)
2. shell history, shell-profile, and sudo/su context
3. web-server, application, and service logs
4. cron, systemd, rc scripts, and startup persistence
5. SSH configs, keys, temp paths, upload paths, and host identity/timezone artifacts
6. broad scanning tools such as `bulk_extractor` only as supporting discovery or corroboration unless direct extraction is impossible

## Derived-artifact mode

When direct image access is blocked and only derived outputs are available:

- declare that mode explicitly
- record the source image path and hash
- record the derived artifact path, tool, version, and command used
- state which questions the derived artifacts can and cannot answer

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
