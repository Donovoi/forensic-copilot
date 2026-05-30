# Sources and review basis

This file records the external material that currently informs the repo. It is not meant to be exhaustive. It is meant to show what was actually checked, why it matters, and where that guidance enters the workflow.

Last reviewed: `2026-05-30`

## Process guidance checked directly

| Source                                                                                | Used for                                                                      | Why it matters here                                                                                      | Link                                                                                                                                    |
| ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `NISTIR 8387` — _Digital Evidence Preservation: Considerations for Evidence Handlers_ | evidence handling, preservation language, contamination concerns              | Sets the preservation-first tone for how the examiner should approach evidence before analysis begins.   | <https://www.nist.gov/publications/digital-evidence-preservation-considerations-evidence-handlers>                                      |
| `NIST SP 800-86` — _Guide to Integrating Forensic Techniques into Incident Response_  | overall forensic process, incident-response context, documentation discipline | Still useful for process framing even though some tooling examples are dated.                            | <https://csrc.nist.gov/pubs/sp/800/86/final>                                                                                            |
| `SWGDE` — _Model Standard Operation Procedures for Computer Forensics_                | workflow structure, documentation expectations, defensibility language        | Useful when deciding what should be explicit in the examiner's process and report.                       | <https://www.swgde.org/documents/published-complete-listing/12-f-001-swgde-model-standard-operation-procedures-for-computer-forensics/> |
| `SWGDE` — _Linux Tech Notes_                                                          | Linux-specific examiner cautions and environment awareness                    | Relevant because the current repo emphasis is Linux-based examination.                                   | <https://www.swgde.org/documents/published-complete-listing/16-f-001-linux-tech-notes/>                                                 |
| `SWGDE` — _Best Practices Apple macOS Forensic Acquisition_                           | acquisition caveats, platform-specific preservation concerns                  | Useful mainly as a reminder that host-specific acquisition guidance varies and should not be hand-waved. | <https://www.swgde.org/documents/published-complete-listing/23-f-005-swgde-best-practices-apple-macos-forensic-acquisition/>            |

## Tracked source families

These are part of the repo's reference baseline, but this file only pins them at the family level unless a directly reviewed document has been added:

- `SWGDE` report-writing guidance
- `NIJ` digital evidence guidance
- `NIST CFTT` tool-testing materials

That is deliberate. This file should not imply a document was checked if it was only remembered or mentioned indirectly.

## Tool upstreams checked directly

| Tool or project          | Why it is tracked                                                | Current repo position                                                                                               | Link                                               |
| ------------------------ | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `The Sleuth Kit`         | core filesystem and image analysis tooling                       | still a primary Linux-friendly examiner tool                                                                        | <https://github.com/sleuthkit/sleuthkit>           |
| `libewf`                 | EWF/E01 verification, metadata inspection, and Linux-side access | tracked as the baseline Linux-friendly access layer for E01 handling before filesystem analysis                     | <https://github.com/libyal/libewf>                 |
| `bulk_extractor`         | feature extraction, scanning, and supporting carving workflows   | useful companion tool, not a substitute for filesystem analysis                                                     | <https://github.com/simsong/bulk_extractor>        |
| `Velociraptor`           | endpoint collection, VQL artifacts, and offline collectors       | candidate for authorized live/offline endpoint collection when native commands are insufficient                      | <https://docs.velociraptor.app/>                   |
| `Velociraptor Artifacts` | reusable endpoint collection logic and tool wrapping             | tracked for artifact-based collection, dead-disk remapping possibilities, and external-tool management              | <https://docs.velociraptor.app/docs/artifacts/>    |
| `Hayabusa`               | Windows event-log timelines and Sigma-oriented threat hunting    | strong candidate for Windows last-hours user-activity and incident timelines                                        | <https://github.com/Yamato-Security/hayabusa>      |
| `Chainsaw`               | rapid Windows forensic artifact search and Sigma hunting         | strong candidate for fast EVTX and selected Windows artifact triage                                                 | <https://github.com/WithSecureLabs/chainsaw>       |
| `SigmaHQ`                | detection-rule corpus and format ecosystem                       | supporting rule source for compatible event-log hunting tools                                                       | <https://github.com/SigmaHQ/sigma>                 |
| `KAPE` docs              | targeted Windows collection and processing model                 | Windows-first candidate when authorized triage collection or parser orchestration is appropriate                    | <https://ericzimmerman.github.io/KapeDocs/>        |
| `KapeFiles`              | community targets and modules for KAPE                           | tracked as the versioned target/module source when KAPE is selected                                                 | <https://github.com/EricZimmerman/KapeFiles>       |
| `Zimmerman tools`        | Windows artifact parsing and timeline-friendly outputs           | Windows-first parser family to select by artifact type, not as a blanket dependency                                 | <https://ericzimmerman.github.io/>                 |
| `DFIR-ORC`               | configurable Windows forensic artifact collection                | candidate when its collection model, configuration, and operational requirements fit the case                       | <https://github.com/DFIR-ORC/dfir-orc>             |
| `Plaso`                  | timeline generation from multiple artifacts                      | useful when timeline depth justifies the setup cost                                                                 | <https://github.com/log2timeline/plaso>            |
| `Plaso` docs             | current install, support, and timeline guidance                  | used to verify that Plaso remains a timeline engine rather than a lightweight one-off parser                        | <https://plaso.readthedocs.io/en/latest/index.html> |
| `Timesketch`             | collaborative timeline review and enrichment                     | heavier than local CLI workflows; justified mainly for larger or team-based timeline work                           | <https://github.com/google/timesketch>             |
| `Dissect`                | unified framework for containers, filesystems, and artifacts     | candidate when a single Python framework reduces extraction friction across image and artifact formats              | <https://github.com/fox-it/dissect>                |
| `Binwalk`                | firmware and blob analysis                                       | appropriate for firmware and opaque binary work, not general host forensics                                         | <https://github.com/ReFirmLabs/binwalk>            |
| `uv`                     | local automation for repo scripts and Python-based CLI helpers   | useful for running report-packaging helpers and ephemeral Python tools without adding more bespoke environment glue | <https://docs.astral.sh/uv/>                       |

## Secondary workflow references

| Project or reference                    | How it informs the repo                                                                                                                          | Note                                                                                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `ForensicArtifacts/artifacts`           | artifact-family coverage and structured thinking about supported operating systems and source types                                              | Used as a checklist and coverage reference, not as a standalone proof engine. <https://github.com/ForensicArtifacts/artifacts>        |
| `ForensicArtifacts/artifacts-kb`        | supporting context for artifact families and collection terminology                                                                              | Useful for coverage and naming consistency. <https://github.com/ForensicArtifacts/artifacts-kb>                                       |
| Linux-forensics practitioner literature | high-level Linux-forensics themes such as service-aware interpretation, auth/session priority, timezone discipline, and conservative attribution | Used only at the level of practitioner themes in this environment; no copyrighted text is quoted or treated as direct authority here. |

## AI interface and README references

| Source | Used for | Link |
| --- | --- | --- |
| GitHub README guidance | Keep the README focused on what the project does, why it helps, how to start, where to get help, and who maintains it. | <https://docs.github.com/articles/about-readmes/> |
| GitHub Copilot custom agents | Repository-level `.github/agents/*.agent.md` guidance and custom-agent positioning. | <https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-custom-agents> |
| VS Code custom instructions | `.github/copilot-instructions.md`, `AGENTS.md`, and workspace instruction behavior. | <https://code.visualstudio.com/docs/copilot/customization/custom-instructions> |
| OpenAI Codex CLI getting started | Codex local execution and `AGENTS.md` project-instruction expectations. | <https://help.openai.com/en/articles/11096431> |
| OpenAI Codex `AGENTS.md` docs | Codex project instruction file behavior and compatibility notes. | <https://github.com/openai/codex/blob/main/docs/agents_md.md> |
| Claude Code memory docs | `CLAUDE.md` project memory guidance. | <https://code.claude.com/docs/en/memory> |
| Claude Code subagents | `.claude/agents/` project subagent guidance. | <https://code.claude.com/docs/en/sub-agents> |
| Gemini CLI context docs | `GEMINI.md` project context guidance. | <https://google-gemini.github.io/gemini-cli/docs/cli/gemini-md.html> |
| Open WebUI prompts | Reusable prompt setup for local or enterprise web UI usage. | <https://docs.openwebui.com/features/workspace/prompts/> |
| Open WebUI knowledge | Knowledge-base setup for loading repository guidance into Open WebUI. | <https://docs.openwebui.com/features/workspace/knowledge/> |
| Open WebUI models | Model preset setup for custom system prompts, tools, and knowledge. | <https://docs.openwebui.com/features/workspace/models/> |
| OpenCode agents | `opencode.json` agent and subagent configuration shape. | <https://dev.opencode.ai/docs/agents/> |

## Current working observations

- `libewf` remains the baseline Linux-friendly access and verification layer for `E01` / EWF inputs and pairs naturally with The Sleuth Kit for filesystem work.
- For Windows last-hours user-activity questions, `Hayabusa`, `Chainsaw`, KAPE/KapeFiles, Zimmerman tools, and Velociraptor are now tracked as first-class candidates, but the workflow must still choose the smallest safe subset for the case.
- `Velociraptor` is powerful for endpoint artifacts and offline collectors, but its operational model should be documented before use.
- `DFIR-ORC` is tracked as a Windows collection framework, not a general parser or default live-host first step.
- `Dissect` is tracked as a broad forensic framework that may reduce extraction friction in mixed image/container cases.
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
