# Using Forensic Copilot in AI Tools

The repo is intentionally plain Markdown so it can run in many agent interfaces. Keep `AGENTS.md`, `docs/repository-policy.md`, and `.github/agents/` available to the model.

## GitHub Copilot and VS Code

Use the native custom-agent files.

1. Clone this repo or copy `.github/agents/` into the target workspace.
2. Keep `.github/copilot-instructions.md` and `AGENTS.md` in the workspace root.
3. Reload VS Code if the agent list does not refresh.
4. Select `Forensic Examiner`.

## OpenCode

Use the committed `opencode.json`.

```bash
opencode run --agent forensic-examiner --model PROVIDER/MODEL "Investigate /evidence/image.E01 for suspicious user activity."
```

For offline or local-model tests, preflight the backend and override both `model` and `small_model` without changing the repo:

```bash
python scripts/check_opencode_llamacpp_backend.py --base-url http://LOCAL-GPU-HOST:8080 --smoke-tool-call --smoke-max-tokens 2048

OPENCODE_CONFIG_CONTENT='{"model":"llamacpp-local/gemma-heretic-bf16","small_model":"llamacpp-local/gemma-heretic-bf16"}' \
  opencode run --agent forensic-examiner --model llamacpp-local/gemma-heretic-bf16 \
  "Analyze this authorized host for user activity during the last two hours."
```

For llama.cpp-backed Gemma runs, keep reasoning enabled when that is the desired local-model behavior, but ensure the first turn has enough output budget for both thinking and the visible Task call. A finite llama.cpp budget such as `--reasoning on --reasoning-budget 1024` prevents unrestricted hidden thinking from consuming the whole OpenCode turn.

OpenCode must still use the subagent loop. If tools cannot be downloaded, the senior tooling specialist must route through `forensic-script-author` and `forensic-script-reviewer`.

## Codex

Open the repo in Codex. Codex should load `AGENTS.md` as the compact project instruction file. Ask for the forensic task directly, for example:

```text
Use Forensic Examiner to analyze /evidence/image.E01 for suspicious user activity and write reports/CASE-001.md.
```

If Codex does not expose named subagents in your environment, keep `.github/agents/` open as reference material and ask it to follow the same internal helper sequence.

## Claude Code

Claude Code can use `CLAUDE.md` for project memory. For native subagents, copy the relevant `.github/agents/*.agent.md` prompt bodies into `.claude/agents/` or create them with `/agents`.

Use:

```text
Follow CLAUDE.md and use the Forensic Examiner workflow for /evidence/image.E01.
```

## Gemini CLI

Gemini CLI can load `GEMINI.md` from the project. Keep `.github/agents/` in context and use:

```text
Use GEMINI.md and the Forensic Examiner prompt to triage /evidence/image.E01.
```

If native subagents are unavailable, ask Gemini to perform the helper stages explicitly and record which stage produced each decision.

## Open WebUI

Open WebUI works best as a prompt or model preset.

1. Create a Workspace Model or Prompt named `Forensic Examiner`.
2. Paste the body of `.github/agents/forensic-examiner.agent.md` as the system prompt.
3. Upload `AGENTS.md`, `docs/repository-policy.md`, `docs/tooling-matrix.md`, and helper agent files into a Knowledge collection.
4. If web access is disabled, tell the model to use `docs/offline-usage.md` and the script fallback path.

Open WebUI does not automatically enforce repo file permissions or subagent routing. Treat its output as a guided examiner worksheet unless it is connected to a controlled execution environment.

## Other Local or Enterprise Wrappers

For Cursor, Windsurf, Continue, Cline, Ollama-backed shells, and similar tools:

1. Put `AGENTS.md` in the project root.
2. Load or paste `.github/agents/forensic-examiner.agent.md` as the main instruction.
3. Keep helper prompts available as reference.
4. Disable web tools when the environment requires it.
5. Require generated scripts to pass the script-reviewer checklist before use.
