# Advanced tooling specialist

## Reason

Live-host testing showed the workflow could complete a bounded report, but the tooling lane was too shallow for deeper DFIR work. The examiner needed a mandatory subagent path that can research current expert-used tools, stage or document the selected tools, and hand back a bounded execution flow before collection expands.

## Files changed

- `.github/agents/forensic-examiner.agent.md`
- `.github/agents/forensic-senior-tooling-specialist.agent.md`
- `.github/agents/forensic-tool-researcher.agent.md`
- `.github/agents/forensic-tool-provisioner.agent.md`
- `.github/agents/forensic-toolsmith.agent.md`
- `opencode.json`
- `README.md`
- `AGENTS.md`
- `docs/tooling-matrix.md`
- `docs/sources.md`

## Source refresh

The source refresh checked current upstream or official material for Velociraptor, Hayabusa, Chainsaw, KAPE/KapeFiles, Eric Zimmerman's tools, SigmaHQ, DFIR-ORC, Plaso, Timesketch, The Sleuth Kit, libewf, Dissect, and ForensicArtifacts.

## Decision

The old toolsmith role now remains as a compatibility helper. The substantive tool loop routes through `Forensic Senior Tooling Specialist`, which must call:

1. `Forensic Tool Researcher` for current upstream and expert-tool research
2. `Forensic Tool Provisioner` for staging, update, verification, and execution-flow handoff

The specialist can still choose native operating-system commands when that is the safest or most defensible path, especially during bounded live-host triage.

## Guardrails

- Select the smallest justified toolchain, not every plausible tool.
- Stage downloads, clones, rules, caches, and local modifications only under ignored analyst-controlled paths unless a case explicitly authorizes another location.
- Record source URL, version or commit, hash or signature status when practical, local staging path, license caveat, and exact command templates.
- Stop and retry a stalled helper instead of bypassing the subagent loop.
- Keep `Forensic Examiner` as the only user-facing agent.

## Verification focus

Future tests should confirm:

- OpenCode lists all new subagents from `opencode.json`
- `forensic-examiner` can invoke `forensic-senior-tooling-specialist`
- the senior specialist invokes the research and provisioning subagents in order
- the provisioner can prepare a bounded Windows event-log execution flow without reading secrets or writing to evidence
