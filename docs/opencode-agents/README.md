# OpenCode agent prompts

These prompts are intentionally smaller than the GitHub Copilot `.github/agents/*.agent.md` prompts. OpenCode loads one active agent prompt per turn and may also auto-load top-level repository instructions, so local providers can become fragile when every helper receives the full portable policy text plus the full helper prompt.

Use these files from `opencode.json` for OpenCode runs. Keep `AGENTS.md` compact for auto-loaded core rules, keep `docs/repository-policy.md` as the expanded repository policy, and keep `.github/agents/` as the Copilot-compatible instruction set.

The examiner's first helper remains the senior tooling specialist. The prompt set now includes platform profiling so the workflow separates evidence OS from runner OS before collection or OS-specific tool choice. After the senior handoff, OpenCode also supports scoped evidence collection, artifact routing, timeline analysis, adversarial report challenge, publication redaction, and offline/no-download script fallback. Keep quick-triage prompts narrow; comprehensive prompts may ask the collector and router to preserve or inventory every relevant in-scope artifact class.

If tools cannot be downloaded, cloned, installed, or used, route through `forensic-script-author` and then `forensic-script-reviewer`. Generated code is not usable until it is logged, validated, and approved with `SCRIPT_REVIEW: approved-for-controlled-use`.
