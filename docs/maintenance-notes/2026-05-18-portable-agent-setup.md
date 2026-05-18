# Forensic Agent Maintenance Note

## Trigger for review

User feedback highlighted a documentation gap near the start of the public README: the repo described the GitHub Copilot path clearly, but it did not explain early enough how to use the same workflow in other agentic coding tools and local model-backed setups.

## Files reviewed

- `README.md`
- `AGENTS.md`

## Reusable issue identified

- the public docs still read as Copilot-first even though the workflow is mostly text-based and portable
- non-VS-Code users were not told clearly which files form the portable instruction bundle
- future edits could accidentally overfit the repo to one agent format if portability was not stated as a design rule

## Lessons learned or new guidance

- the most portable part of this repo is the Markdown instruction layer, not the vendor-specific agent wrapper
- users of OpenCode, Codex, Claude Code, GitHub CLI-based workflows, and Ollama-backed setups need a simple explanation of how to load the same workflow
- the helper-agent split should remain conceptually usable even in tools that do not expose true subagent routing

## Changes applied or proposed

- added a setup-and-use section near the start of `README.md`
- documented both the native `.github/agents/` path and the portable Markdown-instructions path
- clarified which files should stay available in other agentic tools
- added a repo rule requiring the workflow to remain portable across tools that can consume repository instructions or pasted prompts

## Guardrail checks

- preservation-first handling preserved
- scope discipline preserved
- Markdown reporting preserved
- loop compatibility preserved
- public content remained generic and non-identifying

## Privacy check

- examples stayed placeholder-based
- no personal, case-specific, or workstation-specific details were added

## What to watch on the next run

- whether the README stays clear for both Copilot and non-Copilot users
- whether future changes preserve the Markdown-based portable path instead of assuming `.github/agents/` support everywhere
- whether helper-agent guidance remains understandable in tools without first-class subagent features
