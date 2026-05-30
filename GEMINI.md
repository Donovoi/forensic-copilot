# Forensic Copilot for Gemini CLI

Gemini CLI should treat `AGENTS.md` as the compact project policy and `docs/repository-policy.md` as the expanded reference.

Use `.github/agents/forensic-examiner.agent.md` as the main role prompt. Keep helper agent files available as internal reference material if Gemini cannot route named subagents directly.

For offline or no-download cases, use local docs, installed tools, native commands, and the generated-script fallback. Generated forensic scripts must be reviewed, syntax or dry-run validated, logged, and approved before they touch evidence.
