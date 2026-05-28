# Forensic Copilot

![Forensic Copilot hero illustration](docs/assets/forensic-copilot-hero.svg)

`Forensic Copilot` provides a GitHub Copilot custom agent plus a portable Markdown instruction set for investigator-facing host and disk examinations. The current emphasis is preservation-first review of mounted file systems, common disk-image formats, and authorized host triage where the analyst needs a traceable workflow, explicit limitations, current tool selection, and a Markdown report.

The repo gives a human examiner, incident responder, or non-technical investigator a structured way to work through a case. Use it alongside evidentiary judgment, lab SOPs, and formal tool validation.

## Setup and use

This repo is designed to work in two modes:

1. as a native custom-agent bundle in tools that understand `.github/agents/`
2. as a portable Markdown instruction pack in other repo-aware coding agents and local model wrappers

### Core files to keep available

For the best results, keep these files in the active workspace or prompt context:

- `AGENTS.md` for repository-wide rules and guardrails
- `.github/agents/forensic-examiner.agent.md` as the main user-facing workflow
- `.github/agents/forensic-senior-tooling-specialist.agent.md` for advanced tool strategy and subagent orchestration
- `.github/agents/forensic-tool-researcher.agent.md` for current upstream and expert-tool research
- `.github/agents/forensic-tool-provisioner.agent.md` for tool staging, update, verification, and execution-flow handoff
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

### OpenCode with OpenAI

This repo includes `opencode.json` so OpenCode can load the forensic examiner directly instead of relying on Copilot-specific `.agent.md` discovery.

1. Install or update OpenCode. Version `1.15.11` or newer is recommended for the `openai/gpt-5.5` model entry:

   ```powershell
   opencode upgrade -m npm
   opencode --version
   opencode models openai
   ```

2. Configure an OpenAI API key through OpenCode or an environment variable. Keep local credential files out of git; `.env` and `.env.*` are ignored by default.
3. Start the examiner with the project agent and OpenAI model:

   ```powershell
   opencode run --agent forensic-examiner --model openai/gpt-5.5 "Investigate /evidence/image.E01 for suspicious user activity."
   ```

4. For authorized live Windows host triage, keep the first run narrow and explicit:

   ```powershell
   opencode run --agent forensic-examiner --model openai/gpt-5.5 "Analyze this authorized live Windows host for user activity during the last two hours. Use low-impact read-only commands only and write the Markdown report under reports/."
   ```

The OpenCode configuration sets `forensic-examiner` as the default project agent and uses `openai/gpt-5.5`. It also registers the helper agents as OpenCode subagents so the examiner can invoke `forensic-senior-tooling-specialist`, `forensic-peer-reviewer`, and `forensic-maintainer` through the Task tool as part of the standard loop. The senior tooling specialist then invokes `forensic-tool-researcher` and `forensic-tool-provisioner` for substantive tool decisions, so research, staging, and execution-flow design remain part of the loop instead of optional side work.

### Other agentic tools and local model setups

If your tool does not support named custom agents, use the same workflow in a portable way:

1. Open the repository so the tool can read `AGENTS.md` and the files under `.github/agents/`.
2. Treat `AGENTS.md` as the repository-wide policy layer.
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
- known scope or authority limits
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
- `AGENTS.md` — repository-wide rules for future changes

## Source basis

The repo follows current process guidance and keeps its source basis in `docs/sources.md`, including what each source is used for and when it was last reviewed.

## Privacy note

This repository is meant to stay generic when published. Do not commit real names, user names, hostnames, employer names, client names, live case outputs, or machine-specific paths. Use placeholders such as `CASE-001`, `ANALYST`, `HOST-A`, and `/evidence/image.E01`.

The practical checklist is in `docs/privacy-and-redaction.md`.
