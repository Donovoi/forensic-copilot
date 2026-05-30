# Forensic Copilot

![Forensic Copilot hero illustration](docs/assets/forensic-copilot-hero.svg)

`Forensic Copilot` provides a GitHub Copilot custom agent plus a portable Markdown instruction set for investigator-facing host and disk examinations. The current emphasis is preservation-first review of mounted file systems, common disk-image formats, and authorized host triage where the analyst needs a traceable workflow, comprehensive in-scope collection, explicit limitations, current tool selection, and a Markdown report.

The repo gives a human examiner, incident responder, or non-technical investigator a structured way to work through a case. Use it alongside evidentiary judgment, lab SOPs, and formal tool validation.

## Setup and use

This repo is designed to work in two modes:

1. as a native custom-agent bundle in tools that understand `.github/agents/`
2. as a portable Markdown instruction pack in other repo-aware coding agents and local model wrappers

### Core files to keep available

For the best results, keep these files in the active workspace or prompt context:

- `AGENTS.md` for compact repository-wide rules that auto-loaded tools can safely ingest
- `docs/repository-policy.md` for the expanded repository policy and guardrails
- `AGENTS.opencode.md` for lean OpenCode runtime instructions on local or smaller-context models
- `docs/opencode-agents/` for lean OpenCode-specific agent prompts
- `.github/agents/forensic-examiner.agent.md` as the main user-facing workflow
- `.github/agents/forensic-senior-tooling-specialist.agent.md` for advanced tool strategy and subagent orchestration
- `.github/agents/forensic-tool-researcher.agent.md` for current upstream and expert-tool research
- `.github/agents/forensic-tool-provisioner.agent.md` for tool staging, update, verification, and execution-flow handoff
- `.github/agents/forensic-evidence-collector.agent.md` for scoped acquisition, status files, hashes, and collection handoff
- `.github/agents/forensic-artifact-router.agent.md` for parser and specialist-lane routing
- `.github/agents/forensic-timeline-analyst.agent.md` for user and system timeline correlation
- `.github/agents/forensic-report-challenger.agent.md` for adversarial report review
- `.github/agents/forensic-publication-redactor.agent.md` for pre-publication and pre-push leakage checks
- `.github/agents/forensic-toolsmith.agent.md` as a legacy compatibility helper that delegates to the senior tooling specialist
- `.github/agents/forensic-peer-reviewer.agent.md` for case-review logic
- `.github/agents/forensic-maintainer.agent.md` for workflow-maintenance logic
- `docs/limitations.md`, `docs/tooling-matrix.md`, and `docs/peer-review-process.md` for supporting policy and execution detail

### GitHub Copilot in VS Code

1. Clone this repo or copy the `.github/agents/` directory into the target workspace.
2. Ensure all agent files are present in the workspace `.github/agents/` directory, even though only `Forensic Examiner` is user-facing.
3. Keep the repo docs available if you want the maintainer path to update the same canonical source instead of a drifting local copy.
4. Reload the VS Code window if the agent picker does not refresh automatically.
5. Select **`Forensic Examiner`** in Copilot Chat.

### OpenCode with GPT-5.5

This repo includes `opencode.json` so OpenCode can load the forensic examiner directly instead of relying on Copilot-specific `.agent.md` discovery.

1. Install or update OpenCode. Version `1.15.11` or newer is recommended for the `github-copilot/gpt-5.5` model entry when your OpenCode/Copilot account supports that model:

   ```powershell
   opencode upgrade -m npm
   opencode --version
   opencode models
   ```

2. Configure OpenCode authentication for the provider that exposes GPT-5.5, such as a Copilot login or provider-specific API key. Keep local credential files out of git; `.env` and `.env.*` are ignored by default.
3. Start the examiner with the project agent and GPT-5.5 model:

   ```powershell
   opencode run --agent forensic-examiner --model github-copilot/gpt-5.5 "Investigate /evidence/image.E01 for suspicious user activity."
   ```

4. For authorized live Windows host triage, keep the first run narrow and explicit:

   ```powershell
   opencode run --agent forensic-examiner --model github-copilot/gpt-5.5 "Analyze this authorized live Windows host for user activity during the last two hours. Use low-impact read-only commands only and write the Markdown report under reports/."
   ```

The OpenCode configuration sets `forensic-examiner` as the default project agent and uses `github-copilot/gpt-5.5`, which is the desired GPT-5.5 model path when exposed by OpenCode. It also pins OpenCode's `small_model` to `github-copilot/gpt-5.5` so lightweight sidecar calls, such as session title generation, do not inherit stale global provider settings. It registers the helper agents as OpenCode subagents so the examiner can invoke the senior tooling specialist, evidence collector, artifact router, timeline analyst, report challenger, publication redactor, peer reviewer, and maintainer through the Task tool as part of the standard loop. The examiner's first OpenCode tool call should be the senior tooling Task, and the senior tooling specialist then invokes `forensic-tool-researcher` and `forensic-tool-provisioner` for substantive tool decisions, so research, staging, and execution-flow design remain part of the loop instead of optional side work.

Model discovery and runtime support can differ by account. In one validation run, `opencode models` listed `github-copilot/gpt-5.5`, but the provider rejected it at request time with `model_not_supported`; later Copilot GPT-family probes also hit quota. Treat that as a provider/account blocker, not an agent-loop failure. For harness-only tests, override `--model` and `OPENCODE_CONFIG_CONTENT` to a currently supported non-Gemma model, then return to GPT-5.5 when the account supports it.

After the senior handoff, the examiner selects the next helper by requested depth and case question. Quick triage should use the minimum defensible source set needed to answer or prioritize the question. Comprehensive examination should preserve or inventory every relevant in-scope artifact class. Collection work can route through `forensic-evidence-collector`; parser prioritization through `forensic-artifact-router`; user/system timeline correlation through `forensic-timeline-analyst`; adversarial report challenge through `forensic-report-challenger`; and publication or pre-push checks through `forensic-publication-redactor`.

The project keeps OpenCode's prompt footprint intentionally small by loading `AGENTS.opencode.md` plus lean role prompts under `docs/opencode-agents/`. OpenCode may still auto-load the top-level `AGENTS.md`, so that file is intentionally compact; the expanded repository guardrail document lives in `docs/repository-policy.md`, and the Copilot-compatible prompts remain in `.github/agents/`. That keeps local providers with smaller context windows usable while preserving the same subagent loop. To test a configured local provider, override the model at runtime:

```bash
cd /mnt/c/path/to/forensic-copilot
OPENCODE_CONFIG_CONTENT='{"small_model":"llamacpp-local/gemma-heretic-bf16"}' \
  opencode run --title "local forensic test" \
  --agent forensic-examiner \
  --model llamacpp-local/gemma-heretic-bf16 \
  "Analyze this authorized live Windows host for user and system activity during the last two hours. Write the Markdown report under reports/."
```

The `OPENCODE_CONFIG_CONTENT` override keeps lightweight OpenCode calls on the same local provider as the main run. Passing `--title` is also recommended for noninteractive local-model regression tests because it avoids spending a slow single-slot local model request on automatic title generation before the examiner reaches the first mandatory Task call.

For llama.cpp-backed local Gemma tests, prefer a single-slot server with prompt cache and context checkpoints disabled when stability matters more than speed. A stable baseline shape is `-np 1 -ctxcp 0 --no-cache-idle-slots -sps 0.0 --reasoning off --reasoning-budget 0 --timeout 7200`, with batch and GPU-layer values sized for the host. If CUDA/cuBLAS errors recur even with conservative batch and low GPU-layer settings, restart the backend CPU-only with `-ngl 0` or use a verified quantized/non-BF16 local model before retrying. If the backend returns `ECONNRESET`, `ConnectionRefused`, or CUDA errors during a helper turn, stop at the helper blocker, restore `/health` and `/v1/models`, and rerun the same subagent path rather than collecting evidence directly.

When launching OpenCode from Windows into WSL for a background regression, call the WSL-native binary explicitly, for example `$HOME/.local/bin/opencode`, or wrap the command with `wsl.exe -e bash -lc "..."`. A Windows npm shim on `PATH` can bootstrap OpenCode through Windows paths and stall before the local WSL provider is reached.

When prompting local models, keep the first helper call schema explicit. The OpenCode Task tool requires `description`, `subagent_type`, and `prompt`; using `command` instead of `description` causes the helper call to fail before the subagent starts.
Keep the examiner's first Task prompt compact, preferably under 30 words. On very slow BF16 local providers, an oversized first tool call can exceed the provider's first streamed chunk window before OpenCode receives the mandatory subagent call.

Keep local-model web research bounded. The committed OpenCode config denies OpenCode `websearch` to the tooling researcher, so it should prefer local SearXNG with 3 or fewer results and use `webfetch` only for the smallest number of known official upstream pages needed to confirm the recommendation. If SearXNG is unavailable, the researcher should return a blocker instead of opening a broad second search lane. This keeps expert-tool research usable on providers with smaller context windows.

Keep local-model helper output bounded too. A focused researcher note should fit in 8 lines, a provisioning note in 10 lines, and the senior handoff in 12 lines. In the OpenCode config the senior specialist is a task-only coordinator: it can call the researcher and provisioner, but it cannot run shell commands, search directly, or keep a todo list. The senior specialist's first assistant turn should be only the researcher Task call, and its next turn after the researcher returns should be only the provisioner Task call. Provisioner notes must begin with visible `FLOW:` text; an empty provisioner result is a failed helper loop that must be retried, not a valid handoff. This keeps the mandatory subagent loop moving on slower local models without bypassing it.

Keep the examiner's first Task prompt compact and JSON-safe for local Gemma runs: one semicolon-separated line under 30 words, no pasted full user request, no newline inside the `prompt` value, and no period after the final tool-argument field. The committed Gemma test-model output limit is 512 tokens so OpenCode has room to receive the complete Task tool-call JSON before helper output caps take over. The local Gemma model entry also sets low-verbosity, zero-temperature, and no-reasoning options because OpenCode passes model and agent options through to providers that support them.

The project also sets conservative OpenCode tool-output and compaction limits, and gives the inherited `llamacpp-local` provider a one-hour request and stream-chunk timeout so very slow first-token latency does not cancel the mandatory subagent loop. Tool output is truncated into OpenCode's backing storage after a bounded preview, and automatic compaction is delayed enough that small evidence steps can complete before summarization. These settings reduce local-model context pressure; they are not a substitute for writing forensic evidence and report state to files.

If a local OpenAI-compatible provider returns `ECONNRESET`, `ConnectionRefused`, or repeated timeout errors during a helper turn, treat that as a blocked subagent loop. Restore the backend so `/health` and `/v1/models` answer again, then rerun the same helper path; do not continue evidence collection without the required subagent.

When OpenCode runs in WSL against the Windows host, the examiner should collect Windows artifacts through bounded `powershell.exe -NoProfile -Command` calls.
For noninteractive `opencode run` jobs, prepare output paths with idempotent single commands such as `mkdir -p reports artifacts acquisitions`; avoid `ls ... || mkdir ...` setup chains because a safe probe can still be evaluated as an ask permission and auto-rejected.
Do not place raw PowerShell `$` variables or `$_` scriptblock references inside WSL double-quoted commands, because bash may expand them before PowerShell starts. Reject and rewrite command text containing `Where-Object {`, `ForEach-Object {`, shell-mangled `+.`, `.IncludeUserName`, raw `$`, moving `Now.AddHours` windows, or `&&` source chains before execution. Prefer fixed literal local timestamps, property-form filters such as `Where-Object StartTime -GE [datetime]'YYYY-MM-DDTHH:MM:SS'` only when the property is known to exist, and CSV or JSON evidence files under `artifacts/` or `acquisitions/` with only small previews printed to the console. Do not append `Z` to local `Get-Date` output; record Windows timezone separately or call `.ToUniversalTime().ToString('o')` when a UTC value is required.
For process collection from WSL, avoid `Get-Process -IncludeUserName`, `.IncludeUserName`, and owner-filtered process commands unless elevation and command behavior have already been verified. Use a current process snapshot such as `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate`, then establish user attribution from session state and event logs.
For last-N-hours work, capture collection start once, compute the absolute start and end of the investigation window, and reuse that fixed window across every artifact source rather than letting each command use a new moving `Get-Date` boundary.
Run independent evidence sources separately. Do not chain event-log, process, network, filesystem, and browser collection with `&&`; an empty Security log result or `NoMatchingEventsFound` must be written as a zero-row evidence/status result and must not prevent later sources from running.
For local-model runs, the examiner may create directories and capture current time/timezone after the senior handoff, but the Markdown report stub should be written before the first broad evidence source. If an event-log command exits with `NoMatchingEventsFound`, write a case artifact status JSON or Markdown note with source, command, fixed window, collection time, row count `0`, and reason before running the next source.

### Other agentic tools and local model setups

If your tool does not support named custom agents, use the same workflow in a portable way:

1. Open the repository so the tool can read `AGENTS.md` and the files under `.github/agents/`.
2. Treat `AGENTS.md` as the compact repository-wide policy layer and `docs/repository-policy.md` as the expanded policy reference.
3. Load or paste `.github/agents/forensic-examiner.agent.md` as the main system, developer, or role prompt for the active coding agent.
4. If the runner does not understand the YAML frontmatter in `.agent.md` files, strip the frontmatter and use the Markdown body as the portable instruction text.
5. Keep the helper-agent files in context as internal reference material, even if the tool cannot route true subagents.
6. Keep the supporting docs available so the agent can apply the same limits, tool-selection rules, and peer-review gating.

### Compatibility note

This structure is intended to stay usable across GitHub Copilot, OpenCode, Codex, Claude Code, GitHub CLI-based workflows, and Ollama-backed local agent shells, provided the runner can do the basics:

- read repository files or accept pasted Markdown instructions
- keep a reasonably long system or developer prompt
- maintain or edit a Markdown report in the workspace
- optionally run commands or tools when the environment allows it

For Ollama specifically, the compatibility lives in the instruction files and the repo-aware wrapper or coding agent that sits in front of the model. Ollama by itself is the serving layer, not the workflow layer. For OpenCode, prefer the committed `opencode.json` and OpenAI model path when the goal is to run this workflow with GPT rather than a local Gemma-family model.

### First prompt

Start with a prompt like:

> Investigate `/evidence/image.E01` for suspicious user activity.

From that prompt alone, the examiner should infer preservation-first handling, keep the scope limited to that image, start a Markdown case record, assume triage unless deeper work is justified, and use the internal senior tooling specialist to research, select, and prepare the minimal image-analysis stack automatically when needed.

For a worked example, see `docs/example-investigation.md`. If you need a formal package after peer review, see `docs/formal-report-output.md`.

## Current scope

| Evidence or task type                             | Current status        | Notes                                                                                              |
| ------------------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------- |
| Mounted file-system paths                         | Primary               | Useful for scoped review and artifact extraction. Not equivalent to full-image analysis.           |
| `raw/dd`, `E01`, `AFF4`, `VMDK/VHD`               | Primary               | Intended inputs for filesystem, artifact, and timeline work.                                       |
| Live-host decision support                        | Limited               | Used to frame preservation and acquisition decisions, not to replace live-response SOPs.           |
| Firmware or opaque blobs                          | Secondary             | Supported when the evidence requires it, usually through tool selection by the internal senior tooling specialist. |
| Memory, mobile, cloud-native, or packet-only work | Outside primary scope | May require separate workflows, additional agents, or external SOPs.                               |

## What the examiner does

The user interacts with a single visible agent: `Forensic Examiner`.

On each run the examiner is expected to:

- translate a broad request into concrete forensic questions
- ask only the clarification questions that are likely to change scope, interpretation, or priority
- infer preservation-first, scope-limited triage from a bare evidence path instead of asking the user to restate those defaults
- classify the host role early enough to avoid treating servers like desktop endpoints
- invoke internal helper paths for advanced tool strategy, current tool research, provisioning, case peer review, and workflow review
- have the internal senior tooling specialist verify or stage the minimal toolchain automatically when the evidence type or case question already implies it
- if direct access is blocked, pursue supported recovery and narrower corroborative paths before a blocker-only handoff, and state whether deleted-entry, unallocated-space, slack, snapshot, and carving work was attempted, deferred, or impossible
- keep evidence handling preservation-first and read-only where possible
- preserve or inventory sensitive in-scope artifacts such as credentials, cookies, tokens, browser login databases, keys, password-manager stores, and `.env` files when they may answer the case question
- separate evidence preservation from disclosure, so secret values are not printed into prompts, terminal output, reports, or public repository content unless the case specifically requires that value
- separate observation, inference, and limitation
- maintain a Markdown report as the work progresses

The helper roles are internal:

- `Forensic Senior Tooling Specialist` maps the case question to expert-used tools, live-off-the-land options, and a safe execution flow
- `Forensic Tool Researcher` checks current upstream repositories, official docs, releases, and adoption signals for the specialist
- `Forensic Tool Provisioner` downloads, clones, updates, organizes, verifies, or documents selected tools and command flow under ignored staging paths
- `Forensic Toolsmith` remains only as a compatibility alias for older prompts and delegates substantive work to the senior tooling specialist
- `Forensic Peer Reviewer` challenges case findings, missing corroboration, and overconfident wording before release
- `Forensic Maintainer` reviews lessons learned and bounded updates to the workflow

Only `Forensic Examiner` should be selected directly by the user.

## What to provide

An evidence path alone is enough to begin. When the rest is missing, the examiner should still start with preservation-first, scope-limited triage and a Markdown case record.

At minimum, the examiner works best when given:

- an evidence path or image path
- the question to answer, even if it is still broad
- known scope, authority limits, and any categories that require special handling
- whether adjacent derived outputs or prior exports outside the evidence path are in scope
- timezone or locale assumptions if they matter
- whether the source is live, mounted, or a preserved image
- the desired report path if one is already chosen

If some of this is missing, the examiner should ask concise follow-up questions only where the answers materially change scope or interpretation, proceed with conservative inferred defaults when the answers are unavailable, and create a sensible default Markdown case record when no report path has been supplied.

## What you get back

The canonical output is a Markdown report that records:

- an executive summary that answers the tasking in plain language
- findings and timeline correlations
- conclusions stated in language a non-technical stakeholder can follow
- explicit limitations and unresolved questions
- the request and scope assumptions
- evidence handling and verification notes
- the examination method and tool versions

When peer review closes as `ready`, the same Markdown source can be rendered into a formal export package for circulation or filing. The current export path is documented in `docs/formal-report-output.md`.

## Operational flow

![Forensic Copilot loop diagram](docs/assets/forensic-copilot-loop.svg)

The workflow starts with the case request and then loops back through clarification as needed:

1. receive the case request
2. narrow the task with high-value clarification questions
3. run the senior tooling specialist, including research and provisioning subagents, to check tool readiness and platform constraints
4. examine the evidence with preservation-first handling
5. analyze and correlate the resulting artifacts
6. write or update the Markdown report
7. run case peer review before release
8. review what should change before the next loop

The loop stays tied to casework: preserve the evidence, answer the case questions, challenge the draft, and revise the reusable method only when a repeatable issue shows up.

The original investigator brief is a one-time intake step. If peer review, new questions, or maintenance review send the case around again, the next pass resumes at clarification rather than waiting for a new brief.

Peer review is case-specific. Maintenance review is where reusable method changes are considered.

## Known limits

The most important limits are easy to miss if they are not stated plainly:

- mounted file-system views do not answer every question that a full image can answer
- deleted, unallocated, slack-space, and some filesystem-internal questions may require full-image access
- encryption, cloud placeholders, remote mounts, and hybrid storage layers can change what is observable
- some commonly used forensic tools remain Windows-first or license-constrained
- on servers, recovered URLs, domains, admin endpoints, and crawler strings may reflect hosted-service activity rather than local user browsing or successful authentication
- nearby case folders, cached outputs, or prior exports are not automatically in scope just because they reference the same image
- this repo documents a workflow, not a formal validation package

See `docs/limitations.md` for the fuller list.

## Documentation set

- `.github/agents/` — custom agent definitions
- `docs/opencode-agents/` — lean OpenCode runtime agent prompts
- `docs/maintenance-notes/` — reviewable notes for workflow changes and cleanup rationale
- `docs/limitations.md` — current scope limits, cautions, and validation boundaries
- `docs/example-investigation.md` — example prompt, clarification exchange, and report excerpt
- `docs/formal-report-output.md` — formal report export rules, tooling, and release gating
- `docs/peer-review-process.md` — case peer-review rules and release criteria
- `docs/self-update-loop.md` — rules for post-run workflow improvement
- `docs/tooling-matrix.md` — current tool-selection starting point
- `docs/sources.md` — source basis and review anchors
- `docs/privacy-and-redaction.md` — public-repo sanitization checklist
- `scripts/` — formal export and repo-hygiene validation helpers
- `AGENTS.md` — compact auto-loaded repository rules
- `docs/repository-policy.md` — expanded repository policy for future changes
- `AGENTS.opencode.md` — lean runtime rules loaded by OpenCode

## Source basis

The repo follows current process guidance and keeps its source basis in `docs/sources.md`, including what each source is used for and when it was last reviewed.

## Privacy note

This repository is meant to stay generic when published. Do not commit real names, user names, hostnames, employer names, client names, live case outputs, or machine-specific paths. Use placeholders such as `CASE-001`, `ANALYST`, `HOST-A`, and `/evidence/image.E01`.

The practical checklist is in `docs/privacy-and-redaction.md`.
