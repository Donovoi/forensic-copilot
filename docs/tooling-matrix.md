# Tooling matrix

This matrix is the starting point for the `Forensic Senior Tooling Specialist` agent and its research and provisioning subagents. It is intentionally opinionated toward **defensible, evidence-driven** workflows that can choose either expert-used external tools or native live-off-the-land commands.

## Selection heuristics

1. choose the smallest toolchain that answers the case questions
2. when Linux image work clearly implies a baseline stack, stage or verify that minimal stack first instead of pushing setup back to the user
3. consult the newest official manual, vendor documentation, maintained upstream docs, or approved local docs/cache before deciding a program's command syntax, API, automation, update, parallelization, or fallback behavior
4. prefer tools with strong upstream reputation and reproducible setup paths
5. avoid platform drama unless the evidence actually requires it
6. record why each tool was selected, skipped, or deferred
7. when direct access is blocked, verify the smallest supported recovery branch before blocker-only handoff and make a separate layer-specific decision about any remaining disk-level scanning or carving
8. for substantive tool decisions, run the specialist loop: current tool research first, provisioning and execution-flow design second
9. treat sensitivity as a handling issue, not a collection veto; in-scope credential, cookie, token, key, browser, and environment-file artifacts should be preserved, inventoried, parsed, or extracted when they may answer the case question
10. treat offline and no-download environments as normal operating modes; use local docs, installed tools, native commands, and generated-script fallback rather than assuming web access
11. identify the evidence OS and evidence mode before OS-specific collection; the runner OS is not automatically the evidence OS

## Advanced tooling specialist flow

The senior tooling specialist should not act as a one-person installer. For every substantive case loop it should:

1. map the case question to artifact classes and platform constraints
2. invoke `Forensic Platform Profiler` when OS, evidence mode, host role, filesystem/logging, or runner boundary is unclear
3. invoke `Forensic Tool Researcher` to check current upstream or official sources for the profiled platform
4. select the smallest justified toolchain
5. invoke `Forensic Tool Provisioner` to stage, update, verify, or document the execution flow under ignored local paths such as `toolcache/`, `tooling/downloads/`, or `tooling/cache/`
6. when downloads or selected tools are blocked, invoke the script-author and script-reviewer fallback before any generated code is used
7. hand the examiner exact command templates, expected outputs, versions or commits, script review status, caveats, and blockers

If a live-host case is still in its bounded first-response phase, the specialist may choose native commands first and defer downloads until scope and authority justify them. The deferral must be documented.

If the environment is offline or cannot fetch tools, the fallback order is: installed trusted tools, native read-only commands, then generated standard-library scripts. Generated scripts must be logged, syntax-checked, dry-run or fixture-tested, hashed where practical, and approved by `Forensic Script Reviewer` before operational use.

## OS-first routing

Before selecting tools, classify the evidence platform:

| Evidence platform | First forensic priorities | Avoid |
| --- | --- | --- |
| Windows endpoint/server | EVTX, registry, Prefetch/Amcache/ShimCache/SRUM where present, LNK/Jump Lists/ShellBags, scheduled tasks, services, PowerShell, RDP/SMB, NTFS metadata, browser/app artifacts | assuming endpoint artifacts exist on servers, using Linux runner facts as Windows evidence |
| Linux endpoint/server | auth logs, journal/syslog/messages, auditd when configured, shell history, sudo/su, SSH, cron, systemd units/timers, package logs, service/web/app logs, user dotfiles, filesystem metadata | assuming all distros use the same log paths, treating absent auditd as proof of no activity |
| macOS | APFS/HFS+ structure, FileVault/APFS state, unified logs, FSEvents, quarantine/Gatekeeper/XProtect, TCC, LaunchAgents/Daemons, login items, Spotlight metadata, snapshots, extended attributes | treating APFS like a simple mounted folder, ignoring extended attributes or unified logs |
| Container/VM/cloud/appliance | host/guest boundary, image/layer format, mounted volumes, service logs, orchestrator/cloud logs, exported metadata, time source | mixing host and guest evidence or treating SaaS exports like full host images |

## Current matrix

| Tool                                 | Primary role                                                             | Linux readiness | When to prefer it                                                                                                                            | Notes                                                                                                                                                                                |
| ------------------------------------ | ------------------------------------------------------------------------ | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `libewf` / EWF tools                 | EWF/E01 verification, metadata review, and read-only access              | High            | `E01` and segmented EWF inputs that need verification or a Linux-side access path                                                            | Foundational for Linux E01 readiness. Pair it with hashing and The Sleuth Kit rather than treating it as a full examiner on its own.                                                 |
| `libbde` / `libbde-python`           | BitLocker metadata characterization and supported read-only access paths | Medium          | Windows volumes that appear BitLocker-protected and need protection confirmation, metadata inspection, or testing with valid unlock material | Signature confirmation alone is not equivalent to successful metadata access or decryption. Use it to characterize the barrier and a supported unlock path, not to overstate access. |
| `bulk_extractor`                     | content scanning, feature extraction, carving support                    | High            | broad content extraction from images or mounted evidence                                                                                     | Good companion tool, not a full filesystem examiner; on Linux server user-activity cases it is usually corroborative rather than primary proof of logon or browsing.                 |
| `The Sleuth Kit`                     | partition, volume, filesystem, deleted-file, and metadata analysis       | High            | raw/E01/AFF4/disk-image workflows and filesystem-level validation                                                                            | Official upstream: `sleuthkit/sleuthkit`. Foundational for disk and filesystem analysis.                                                                                             |
| `Velociraptor`                       | endpoint collection, artifact-based DFIR, offline collectors             | Medium          | authorized endpoint collection, reusable artifact logic, enterprise-scale or offline Windows/Linux/macOS triage                               | Powerful but operationally heavier than simple commands. Use targeted artifacts and document collector configuration, output container handling, and live-host impact.               |
| `Hayabusa`                           | Windows event-log timelines and Sigma-oriented threat hunting            | High            | Windows user-activity and incident timelines where EVTX artifacts are central                                                                | Strong fit for last-hours Windows activity questions. Prefer release binaries or documented builds and record rule source/update state.                                               |
| `Chainsaw`                           | rapid Windows forensic artifact search and hunt                          | High            | EVTX, MFT, Shimcache, Amcache, SRUM, and Sigma-driven triage where fast local output is useful                                                | Good complement or cross-check to Hayabusa. Watch for rule mapping, EDR warnings, and output format consistency.                                                                      |
| `SigmaHQ` rules                      | detection-rule corpus for log hunting                                    | High            | detection-oriented review with Hayabusa, Chainsaw, SIEM, or compatible tooling                                                               | Rules support hunting logic, not evidence extraction by themselves. Record release or commit and any local filtering.                                                                 |
| `Plaso`                              | supertimeline generation from multiple artifacts                         | Medium          | timeline-heavy cases where cross-artifact ordering matters                                                                                   | Use when timeline correlation is central; packaging can be dependency-sensitive.                                                                                                     |
| `Timesketch`                         | collaborative timeline analysis and enrichment                           | Medium          | cases with large timelines, team review, tagging, or analysis at scale                                                                       | Official docs currently point to deploy script and service-oriented setup. Heavier than local CLI-only tooling.                                                                      |
| `Dissect`                            | unified access to forensic containers, filesystems, and artifacts        | Medium          | mixed image formats, hypervisor containers, and artifact access where a single framework reduces extraction friction                          | Python-based and broad. Check license and version compatibility before adopting it as the primary parser.                                                                            |
| `Binwalk`                            | firmware and opaque binary blob analysis                                 | High            | firmware images, embedded artifacts, archives, or nonstandard blobs                                                                          | Official upstream: `ReFirmLabs/binwalk`. Not a general substitute for filesystem forensics.                                                                                          |
| `FTK Imager`                         | acquisition, preview, and export in ecosystems that require it           | Low on Linux    | workflows that explicitly require FTK output or verification in a Windows-capable environment                                                | Treat as proprietary and platform-constrained; do not assume native Linux installation.                                                                                              |
| `KAPE` / `KapeFiles`                 | targeted Windows artifact collection and parsing orchestration           | Low on Linux    | authorized Windows triage and targeted acquisition workflows                                                                                 | Treat as Windows-first. Record target/module files and whether KAPE collected data, parsed data, or both.                                                                            |
| `Zimmerman tools`                    | Windows artifact parsing and enrichment                                  | Low on Linux    | detailed Windows artifact parsing for EVTX, MFT, Amcache, SRUM, ShellBags, LNK, Jump Lists, and related artifacts                            | Windows-first tool family; use with a compatible Windows environment or documented runtime path.                                                                                     |
| `DFIR-ORC`                           | configurable Windows forensic artifact collection                        | Low on Linux    | managed Windows collection where its configuration, deployment, and build model fit the operation                                             | Useful for collection, not a magic analysis layer. Document configuration, embedded tools, output packages, and administrative requirements.                                          |
| `OSDFIR` / artifact repositories     | structured artifact definitions and repeatable parsing workflows         | Medium          | when artifact-definition reuse improves repeatability and coverage                                                                           | Useful as supporting infrastructure rather than as a single do-everything examiner tool.                                                                                             |
| `ForensicArtifacts` / `artifacts-kb` | artifact-family coverage and checklist support                           | High            | when you need a structured reminder of which artifact families should exist on a host role or platform                                       | Useful for coverage and terminology; not a standalone proof engine.                                                                                                                  |
| hashing utilities                    | evidence verification and handoff integrity                              | High            | every case                                                                                                                                   | Mandatory rather than optional. Capture algorithms and results in the report.                                                                                                        |
| SQLite inspection tools              | browser, app, and artifact database review                               | High            | app and user-activity artifacts stored in SQLite                                                                                             | Treat as supporting tooling for artifact review and corroboration.                                                                                                                   |
| `uv`                                 | run local Python helper scripts and Python-based CLI tools               | High            | when the workflow includes local automation such as report packaging                                                                         | Good wrapper for repo scripts and Python CLIs; do not treat it as the installer for non-Python binaries such as `pandoc`.                                                            |
| `Pandoc`                             | render reviewed Markdown into formal HTML, DOCX, or PDF-ready outputs    | Medium          | when peer review has cleared the report and a formal package is needed                                                                       | Keep Markdown as the source of truth. PDF output still depends on an available renderer or PDF backend.                                                                              |

## Practical defaults on Linux

For `E01`, `AFF4`, and other directly inspectable image work on Linux, the senior tooling specialist should try to verify or stage this baseline automatically before declaring the case blocked.

For a typical Linux-based disk-image examination, the first-pass stack should usually be:

1. hashing utilities
2. `libewf` / EWF tools when the image format requires them
3. The Sleuth Kit
4. SQLite inspection tools and filesystem-specific helpers
5. `bulk_extractor`
6. `Plaso` if timeline depth is needed
7. `Timesketch` only if collaborative or large-scale timeline review is justified

If BitLocker or another encrypted Windows volume is detected, extend the baseline with a read-only recovery branch: characterize the protection, test supported unlock or mount paths with in-scope material, and then decide separately whether any remaining whole-disk free-space review or carving of accessible plaintext regions is still useful.

## Windows endpoint and live-host user-activity bias

For authorized Windows endpoint or live-host user-activity questions, especially narrow windows such as "what happened in the last two hours", first-pass collection should usually start with:

1. native read-only host state and time context (`Get-Date`, `Get-TimeZone`, `whoami`, `quser`, `Get-Process`, targeted `Get-WinEvent`)
2. targeted EVTX review for logon, process creation, PowerShell, service, scheduled-task, RDP, and session artifacts
3. `Hayabusa` for fast EVTX timelines and detection-context enrichment when event logs are accessible
4. `Chainsaw` as a fast independent cross-check for EVTX, Shimcache, Amcache, SRUM, MFT, and Sigma-style hunting where the artifact set supports it
5. `KAPE` / `KapeFiles`, `Velociraptor` offline collection, or `DFIR-ORC` only when authorized collection depth, operational model, and output handling are clear
6. selected Zimmerman parsers for deep parsing of specific Windows artifacts after collection
7. controlled acquisition or parsing of browser profiles, cookies, login databases, tokens, keys, password-manager stores, environment files, and other secret-bearing artifacts when those artifacts are in scope and could corroborate user activity

The specialist should decide whether to stage external tools only after the research subagent confirms current upstream choices and the provisioner can prepare a bounded execution flow.

Secret-bearing artifacts should be copied, hashed, parsed, and, when justified, dumped through controlled case outputs. Plaintext secret values belong in approved secret-evidence files, not public repository content, ordinary prompts, or report prose. The report should normally cite their existence, path, hash, timestamp, parser result, and relevance while redacting the actual value unless disclosure is essential to the case.

If the active AI interface, provider policy, system instruction, or enterprise rule does not allow plaintext secret handling, keep that model out of the plaintext lane. Use approved local tools, an offline workflow, or a local model for extraction and analysis of the secret values, then give cloud or restricted agents only redacted summaries, paths, hashes, counts, and handling notes.

Every secret extraction pass should produce a lead index for the next loop. At minimum, record source artifact, secret type, likely program/site/service, account or owner when known, local-versus-remote use, confidence, controlled output path, and next allowed action. Local in-scope uses can include unlocking an encrypted file, mounted volume, local mail store, browser profile, password vault, archive, database, or application account already inside the evidence boundary. Remote services and cloud accounts require explicit authority and user direction unless the case scope already authorizes that access.

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
- On live Windows hosts, especially through OpenCode or another single-agent runner, the opening pass should use native read-only commands and short bounded queries before considering extra tooling. Avoid install steps, broad recursive sweeps, and long compound shell probes unless the scope and urgency justify them.

## Maintenance notes

Refresh this matrix when:

- upstream install guidance changes
- a tool becomes unsupported or archived
- a better-supported tool meaningfully replaces a current recommendation
- a new evidence type requires a different default stack
- repeated setup friction or case outcomes show that the current default stack is no longer the best fit

When these triggers occur, run the self-update process described in `docs/self-update-loop.md` and document why the recommendation changed.
