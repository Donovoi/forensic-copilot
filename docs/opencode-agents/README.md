# OpenCode agent prompts

These prompts are intentionally smaller than the GitHub Copilot `.github/agents/*.agent.md` prompts. OpenCode loads one active agent prompt per turn and may also auto-load top-level repository instructions, so local providers can become fragile when every helper receives the full portable policy text plus the full helper prompt.

Use these files from `opencode.json` for OpenCode runs. Keep `AGENTS.md` compact for auto-loaded core rules, keep `docs/repository-policy.md` as the expanded repository policy, and keep `.github/agents/` as the Copilot-compatible instruction set.

The examiner's first helper remains the senior tooling specialist. After the senior handoff, the OpenCode prompt set also supports scoped evidence collection, artifact routing, timeline analysis, adversarial report challenge, and publication redaction. Keep quick-triage prompts narrow; comprehensive prompts may ask the collector and router to preserve or inventory every relevant in-scope artifact class.
