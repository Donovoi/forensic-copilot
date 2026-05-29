# OpenCode local-model context budget

## Trigger

A WSL OpenCode test using `llamacpp-local/gemma-heretic-bf16` failed before collection. The initial request was 30,745 tokens, while the configured Gemma server exposed a 16,384-token context window.

## Cause

The project `opencode.json` loaded `AGENTS.md`, every `.github/agents/*.agent.md` file, and several support docs as global instructions. The selected examiner prompt was then loaded again as the active agent prompt, so helper-agent prompts and docs were duplicated in every main-agent request.

The agent definitions also hard-pinned each role to `openai/gpt-5.5`, which made one-off local-provider testing harder than it needed to be.

## Decision

Keep OpenCode's global instruction list lean and rely on per-agent prompts for helper roles. The top-level default model remains `openai/gpt-5.5`, but individual agent entries no longer pin the model, so `--model llamacpp-local/gemma-heretic-bf16` can test the full workflow on the local provider.

For WSL live-host collection against the Windows source host, allow bounded `powershell.exe -NoProfile -Command` bridge calls from the examiner instead of requiring unsafe global permission bypasses.

Safe WSL-local setup commands such as `date`, `pwd`, and `mkdir -p` for ignored report or artifact directories are allowed so noninteractive runs can record runner context and prepare output paths. Reports must still distinguish WSL runner metadata from Windows evidence.

A Gemma rerun confirmed that OpenCode can split a harmless setup chain into separate permission checks: `ls -d reports artifacts acquisitions 2>/dev/null || mkdir -p reports artifacts acquisitions` was rejected because the `ls` probe fell through to `ask`, even though the `mkdir` half was allowed. Noninteractive live-host runs should use one idempotent `mkdir -p reports artifacts acquisitions` command when setup is needed, and the config also allows the narrow directory probes seen in this failure mode.

The same test exposed a local-model schema drift issue: Gemma used `command` when calling the Task tool, but OpenCode requires `description`, `subagent_type`, and `prompt`. Keep the exact Task field names in the examiner and helper prompts so the mandatory subagent loop starts cleanly.

A later nested researcher run showed the next pressure point: multiple broad `websearch` calls expanded the request to 28,743 tokens and exceeded the same 16,384-token context window. Local-model research must stay targeted, use small result counts and `contextMaxCharacters`, and summarize after no more than two searches before continuing.

The next Gemma run proved that bounded search alone is not enough. The researcher subagent kept streaming a long note for more than 35 minutes after completing its bounded search, leaving the senior and examiner waiting. Local-model helper prompts now need explicit output caps and should avoid todo-list bookkeeping for single focused helper requests: researcher notes 20 lines or fewer, provisioner notes 25 lines or fewer, and senior handoffs 30 lines or fewer.

The same run also hit a slow automatic compaction pass immediately after the examiner created the report stub. OpenCode supports project-level compaction and tool-output limits, so this repo now sets bounded tool output and explicit automatic compaction with pruning, one preserved tail turn, a recent-token cap, and a reserved context buffer. The report and artifact files remain the durable state; the model context should not be the evidence store.

In a later run, the researcher correctly used local SearXNG but then followed it with OpenCode `websearch`. For Gemma-style local runs, that second source lane should be explicit, not habitual. After a successful SearXNG search, avoid OpenCode `websearch` unless SearXNG is unavailable or the senior specialist specifically needs another source lane.

The next retry showed that prompt guidance alone was too soft: the researcher still attempted OpenCode `websearch` after a successful local SearXNG result. The OpenCode config now denies `websearch` for the researcher and keeps `webfetch` available for narrowly targeted official upstream pages.

The same run returned a valid researcher result, then the parent generation stalled before the required provisioner call. The fix is to make the senior's post-research behavior deterministic: immediately call `forensic-tool-provisioner`, with no interim prose summary. The project config also advertises a smaller `llamacpp-local/gemma-heretic-bf16` output limit for this repo so helper turns are less likely to monopolize a single llama.cpp slot.

Another restart showed that BF16 first-token latency can still trip OpenCode or provider-side request cancellation before the first useful token arrives. The project sets a one-hour request timeout and one-hour chunk timeout for the inherited `llamacpp-local` provider, while leaving the actual provider URL in the analyst's local WSL config. Although OpenCode's generated schema says `false` can disable the provider timeout, live testing still showed five-minute cancellation behavior, so the project uses a large numeric value instead of `false`.

When cancelling a run against a single-slot local llama.cpp server, confirm the backend slot clears before starting the next run. A stale in-flight request can leave the new OpenCode process waiting quietly even though `/health` still answers. If the backend must be restarted, target the real process with an anchored command-line match such as `pgrep -f '^/path/to/llama-server-rpc'`; avoid broad `pkill -f` strings that can match and kill the restart shell itself. For very slow BF16 local runs, start llama-server with a long read/write timeout such as `--timeout 3600`; otherwise the backend may cancel a long first generation before the examiner reaches the first Task call.

A later live-host rerun reached evidence collection but failed in a more practical way. The examiner used PowerShell variables and `$_` inside WSL double-quoted `powershell.exe -NoProfile -Command` strings. Bash expanded `$startTime` to an empty value and `$_` to a shell path before PowerShell ran, causing parser errors and a large `Get-Process` error burst. The next model request then exceeded the 16,384-token local context window. WSL live-host triage should avoid raw PowerShell `$` tokens in double-quoted commands, prefer fixed literal timestamps and simplified `Where-Object Property -Operator Value` filters, and write broad evidence to files with only a small console preview.

That rerun also showed why moving windows are not precise enough for forensic reporting. After the first collection timestamp is captured, the agent should compute one absolute two-hour window and reuse it across event logs, process starts, filesystem metadata, browser artifacts, and any staged tool output. Each evidence file should record the fixed window, collection time, source command, and row count so later report updates are not dependent on fragile model memory.

Another Gemma run proved the mandatory subagent sequence but failed while the provisioner was being called: the llama.cpp OpenAI-compatible endpoint first returned `ECONNRESET` and then refused connections on `LOCAL-GPU-HOST:8080`. This is a backend health blocker, not permission to continue without subagents. The examiner should stop at the helper blocker, restore `/health` and `/v1/models`, then retry the same helper loop.

Automatic compaction was useful as an emergency recovery path, but it was slow and sometimes produced stale or truncated next-step text on this local model. The project now keeps compaction enabled but less aggressive, lowers retained tool output, and pushes broad result sets into controlled artifact files instead of the chat transcript.

A subsequent Gemma rerun proved the first mandatory Task call and successfully started the senior tooling specialist, but the senior subagent request still reached a 13,894-token prompt pass. A follow-up run with a lean global instruction file lowered the examiner's first request to 6,656 tokens, but the nested senior helper still reached 14,784 tokens because it loaded the full senior `.agent.md` prompt and accumulated parent context. OpenCode now loads `AGENTS.opencode.md` plus lean role prompts under `docs/opencode-agents/`, while `AGENTS.md` and `.github/agents/` remain the canonical full repository policy and Copilot-compatible prompt set.

Another retry lowered the examiner prompt to roughly 1,024 tokens and the senior prompt to roughly 10,190 tokens, proving the lean prompt split worked but still leaving a large helper request. The senior role now has task-only OpenCode permissions and no todo, read, shell, or direct web tools. It must coordinate the researcher and provisioner rather than carrying extra tool schemas into its own prompt.

## Validation expectations

Future local-model tests should confirm that:

- the first request fits the local provider context window
- nested helper requests leave enough local context margin for researcher and provisioner turns
- helper subagents still load through their own prompts
- CLI `--model` overrides apply to the active workflow
- Task calls use `description`, `subagent_type`, and `prompt`, not `command`
- web research stays bounded enough for the configured local context window
- the researcher cannot fall back to OpenCode `websearch` after a successful local SearXNG search
- helper outputs stay bounded enough that the subagent returns control to the parent loop
- the senior calls the provisioner immediately after the researcher returns
- provider `ECONNRESET`, `ConnectionRefused`, or timeout errors stop the helper loop until the backend is healthy, then the same helper path is retried
- OpenCode tool-output and compaction settings reduce context growth before evidence collection begins
- local-provider request timeouts do not cancel slow BF16 generations before a helper Task call is emitted
- WSL live-host collection can use bounded Windows PowerShell bridge commands without `--dangerously-skip-permissions`
- safe WSL-local setup commands do not trigger noninteractive permission rejections
- WSL PowerShell commands do not include raw `$` variables or `$_` scriptblock references inside double-quoted command strings
- last-N-hours investigations reuse a fixed absolute collection window after collection start is captured
- broad evidence sources are saved under controlled artifact paths with small previews instead of streamed wholesale into model context
