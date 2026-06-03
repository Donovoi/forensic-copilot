# Specialized Tool Adapters

Specialized tool adapters let Forensic Copilot use expert tooling without making the whole workflow depend on one product, vendor, operating system, or agent runtime.

The examiner remains the investigator-facing coordinator. The senior tooling specialist selects an adapter only when the case question, evidence type, authority, platform, manual guidance, and local environment justify it. If the adapter is unavailable, unsupported, or less suitable than another method, the workflow can still proceed through native commands, open tooling, generated reviewed scripts, or another approved adapter.

## Adapter Pattern

A specialized tool adapter should provide a narrow forensic boundary around one tool family or execution environment. Good adapters:

- consult the current official manual, vendor documentation, maintained upstream docs, or approved local docs/cache before recommending commands, automation, APIs, parallelization, or fallback behavior
- accept local file paths, manifests, or scoped configuration files rather than raw evidence facts in prompt text
- enforce input/read, compute/staging, and output/report/export boundaries
- prefer read-only, headless, documented, and repeatable operations over GUI automation
- record who, what, why, when, how, tool versions, command lines, hashes where practical, SOP basis, deviations, and limitations
- return sanitized status, structured outputs, report paths, hashes, and local alias-map paths rather than raw usernames, hostnames, evidence names, recovered filenames, secrets, or case-sensitive paths
- keep raw exports inside approved forensic containers or controlled case outputs when export is necessary
- remain optional and replaceable

Adapters are not separate investigative lanes. They are provider implementations selected by the tooling loop. A case may use no adapters, one adapter, or several adapters when that is more defensible than a single monolithic toolchain.

## Loose Coupling Contract

Forensic Copilot may hand an adapter a local case-run manifest or equivalent local configuration containing:

- case objective and requested depth
- evidence input roots and explicit exclusions
- approved compute, staging, cache, and temporary roots
- approved report, log, export, and redacted-deliverable roots
- privacy policy, alias-map policy, and no-internet or local-only requirements
- manual/source basis required before action
- allowed tool profile, including headless, GUI fallback, parallelism, GPU, container, or remote-compute limits
- SOP or best-practice set to cite in contemporaneous notes

An adapter should return:

- selected action and reason
- manual or local-doc basis used
- command, script, API, X-Tension, or GUI fallback used
- sanitized status and progress
- structured machine-readable output for downstream analysis
- report path, status-file path, and hashes where practical
- local-only alias-map path without revealing the map contents
- limitations, failed unlocks, skipped sources, and validation state

The manifest is a contract shape, not ownership. Forensic Copilot can consume adapter outputs, and adapters can be used independently by an examiner or another harness.

## Privacy And Prompt Hygiene

Adapter calls should minimize raw case facts in prompts and logs. Prefer file-in/file-out operations with local paths and sanitized return values. Keep sensitive maps and raw findings in ignored case workspaces, normally with names such as `.local.json`, `.sensitive.json`, or another locally documented convention.

Do not send case identifiers, evidence names, recovered filenames, usernames, hostnames, client names, BitLocker keys, credentials, secrets, screenshots, or case-specific hashes to public repositories, remote models, or web searches unless the case authority and data-handling policy explicitly allow that disclosure.

## Manual-First Gate

Before using a specialized program, the tooling specialist or adapter should check the newest available official manual, vendor docs, maintained upstream docs, or approved local docs/cache for:

- command-line and headless operation
- automation flags, APIs, plug-ins, or extension points
- distributed, batch, parallel, GPU, or worker execution
- forensic container/export behavior
- logging, audit, and report output behavior
- read-only modes and actions that may modify evidence or case databases
- limitations, licensing, and version-specific caveats

If current docs are unreachable, record the local/offline source basis and the review-date limitation before continuing.

## First Example: X-Ways-MCP

X-Ways-MCP is an optional specialized adapter for workflows where X-Ways Forensics is already licensed, installed, authorized, and suitable for the evidence. It may be a good fit for E01 handling, X-Ways case metadata, BitLocker-aware workflows, file carving, X-Tensions, and X-Ways-specific reporting.

Use it only when the senior tooling specialist selects it after manual-first review. It should remain an example provider, not a required dependency and not a product-specific default lane. If X-Ways is unavailable, the license is unclear, the current manual does not support the desired operation, or another toolchain is more defensible, the examiner should use the normal tooling loop.

When X-Ways-MCP is selected, prefer:

- documented headless commands, saved configuration, scripts, APIs, X-Tensions, or native distributed processing before UI automation
- read-only case metadata queries before exporting files
- local sanitized reports and structured JSON over raw file dumps
- forensic containers or controlled case outputs when export is necessary
- parallel processing only where the manual, case state, and evidence handling support it
- contemporaneous notes for every action, including SOP basis and deviations

### X-Ways PowerShell Workflow Surface

When the X-Ways MCP PowerShell module is available, the preferred handoff is a local plan/status workflow, not raw case material in prompts:

1. `New-XwfForensicRun` creates the local run workspace, contemporaneous notes, plans, containers, derived output, reports, manual-cache pointer, safety policy, and initial best-practice note.
2. `New-XwfQueryFirstUsagePatternPlan` is the first choice for per-machine/per-user usage questions because it plans X-Ways query surfaces before materializing file contents.
3. `New-XwfContainerExportPlan` is used only when query output is insufficient and export is justified; exported file content must go to an approved forensic container or controlled case output.
4. `New-XwfUsagePatternPlan` plans derived analysis from an approved container path.
5. `Add-XwfContemporaneousNote`, `Select-XwfBestPractice`, `Test-XwfManualGate`, and `Test-XwfForensicAction` keep every decision tied to manual/source basis, SOP or best-practice basis, and soundness gates.

For direct local-model regressions, feed Gemma only sanitized plan, status, and summary outputs from these functions. Keep raw case names, user names, recovered filenames, evidence names, keys, and alias maps local and outside prompts.

The same pattern should apply to future adapters for other products. Add the adapter as a documented provider with a manifest-compatible interface, privacy boundary, manual-first gate, tests, and failure-mode notes rather than embedding product-specific behavior into the examiner prompt.
