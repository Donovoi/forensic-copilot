# Sources and review basis

This file records the external material that currently informs the repo. It is not meant to be exhaustive. It is meant to show what was actually checked, why it matters, and where that guidance enters the workflow.

Last reviewed: `2026-05-15`

## Process guidance checked directly

| Source | Used for | Why it matters here | Link |
| --- | --- | --- | --- |
| `NISTIR 8387` — *Digital Evidence Preservation: Considerations for Evidence Handlers* | evidence handling, preservation language, contamination concerns | Sets the preservation-first tone for how the examiner should approach evidence before analysis begins. | <https://www.nist.gov/publications/digital-evidence-preservation-considerations-evidence-handlers> |
| `NIST SP 800-86` — *Guide to Integrating Forensic Techniques into Incident Response* | overall forensic process, incident-response context, documentation discipline | Still useful for process framing even though some tooling examples are dated. | <https://csrc.nist.gov/pubs/sp/800/86/final> |
| `SWGDE` — *Model Standard Operation Procedures for Computer Forensics* | workflow structure, documentation expectations, defensibility language | Useful when deciding what should be explicit in the examiner's process and report. | <https://www.swgde.org/documents/published-complete-listing/12-f-001-swgde-model-standard-operation-procedures-for-computer-forensics/> |
| `SWGDE` — *Linux Tech Notes* | Linux-specific examiner cautions and environment awareness | Relevant because the current repo emphasis is Linux-based examination. | <https://www.swgde.org/documents/published-complete-listing/16-f-001-linux-tech-notes/> |
| `SWGDE` — *Best Practices Apple macOS Forensic Acquisition* | acquisition caveats, platform-specific preservation concerns | Useful mainly as a reminder that host-specific acquisition guidance varies and should not be hand-waved. | <https://www.swgde.org/documents/published-complete-listing/23-f-005-swgde-best-practices-apple-macos-forensic-acquisition/> |

## Tracked source families

These are part of the repo's reference baseline, but this file only pins them at the family level unless a directly reviewed document has been added:

- `SWGDE` report-writing guidance
- `NIJ` digital evidence guidance
- `NIST CFTT` tool-testing materials

That is deliberate. This file should not imply a document was checked if it was only remembered or mentioned indirectly.

## Tool upstreams checked directly

| Tool or project | Why it is tracked | Current repo position | Link |
| --- | --- | --- | --- |
| `The Sleuth Kit` | core filesystem and image analysis tooling | still a primary Linux-friendly examiner tool | <https://github.com/sleuthkit/sleuthkit> |
| `bulk_extractor` | feature extraction, scanning, and supporting carving workflows | useful companion tool, not a substitute for filesystem analysis | <https://github.com/simsong/bulk_extractor> |
| `Plaso` | timeline generation from multiple artifacts | useful when timeline depth justifies the setup cost | <https://github.com/log2timeline/plaso> |
| `Timesketch` | collaborative timeline review and enrichment | heavier than local CLI workflows; justified mainly for larger or team-based timeline work | <https://github.com/google/timesketch> |
| `Binwalk` | firmware and blob analysis | appropriate for firmware and opaque binary work, not general host forensics | <https://github.com/ReFirmLabs/binwalk> |
| `uv` | local automation for repo scripts and Python-based CLI helpers | useful for running report-packaging helpers and ephemeral Python tools without adding more bespoke environment glue | <https://docs.astral.sh/uv/> |

## Secondary workflow references

| Project or reference | How it informs the repo | Note |
| --- | --- | --- |
| `ForensicArtifacts/artifacts` | artifact-family coverage and structured thinking about supported operating systems and source types | Used as a checklist and coverage reference, not as a standalone proof engine. |
| `ForensicArtifacts/artifacts-kb` | supporting context for artifact families and collection terminology | Useful for coverage and naming consistency. |
| Bruce Nikkel, *Practical Linux Forensics* | high-level Linux-forensics themes such as service-aware interpretation, auth/session priority, timezone discipline, and conservative attribution | Used only at the level of practitioner themes in this environment; no copyrighted text is quoted or treated as direct authority here. |

## Current working observations

- `Timesketch` remains more service-oriented than lightweight local tooling.
- `The Sleuth Kit` remains a sensible default for Linux-based image and filesystem work.
- `Binwalk` is treated as a specialist tool, not a general-purpose substitute for host forensics.
- `uv run` fits local script orchestration well, and `uvx` / `uv tool run` fits Python-based CLI helpers. Non-Python binaries such as `pandoc` still need their own install path.
- Windows-first tools such as `FTK Imager`, `KAPE`, and many `Zimmerman` utilities are tracked as platform-specific dependencies rather than presumed native on Linux.
- Artifact-definition ecosystems can improve coverage and gap detection even when they are not the primary extraction mechanism.
- High-level Linux-forensics practitioner guidance reinforces role-aware interpretation: a Linux web server should not be read as if every recovered URL or admin endpoint represents local browsing by a human user.

## How to use this file

When new guidance materially changes the recommended workflow:

1. update the relevant agent or doc
2. run the review described in `docs/self-update-loop.md`
3. update `docs/tooling-matrix.md` if the tool recommendation changed
4. update this file if the source basis changed materially
5. cite the source in the resulting maintenance note or report
