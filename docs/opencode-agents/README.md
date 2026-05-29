# OpenCode agent prompts

These prompts are intentionally smaller than the GitHub Copilot `.github/agents/*.agent.md` prompts. OpenCode loads one active agent prompt per turn, so local providers can become fragile when every helper receives the full portable policy text plus the full helper prompt.

Use these files from `opencode.json` for OpenCode runs. Keep `AGENTS.md` and `.github/agents/` as the canonical full-policy and Copilot-compatible instruction set.
