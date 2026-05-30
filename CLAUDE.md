# Forensic Copilot for Claude Code

Claude Code should treat `AGENTS.md` as the compact project policy and `docs/repository-policy.md` as the expanded reference.

The user-facing role is `Forensic Examiner` in `.github/agents/forensic-examiner.agent.md`. The other `.github/agents/*.agent.md` files are internal helper roles. If you want native Claude Code subagents, copy the relevant helper prompt bodies into `.claude/agents/` and keep their names aligned.

For offline or no-download cases, do not stop at missing web access. Use local docs, installed tools, native commands, and the generated-script fallback. Generated forensic scripts must be reviewed, syntax or dry-run validated, logged, and approved before they touch evidence.
