# OpenCode local-model context budget

## Trigger

A WSL OpenCode test using `llamacpp-local/gemma-heretic-bf16` failed before collection. The initial request was 30,745 tokens, while the configured Gemma server exposed a 16,384-token context window.

## Cause

The project `opencode.json` loaded `AGENTS.md`, every `.github/agents/*.agent.md` file, and several support docs as global instructions. The selected examiner prompt was then loaded again as the active agent prompt, so helper-agent prompts and docs were duplicated in every main-agent request.

The agent definitions also hard-pinned each role to a GPT-5.5 provider path, which made one-off local-provider testing harder than it needed to be.

## Decision

Keep OpenCode's global instruction list lean and rely on per-agent prompts for helper roles. The top-level default model remains GPT-5.5, but individual agent entries no longer pin the model, so `--model llamacpp-local/gemma-heretic-bf16` can test the full workflow on the local provider.

For WSL live-host collection against the Windows source host, allow bounded `powershell.exe -NoProfile -Command` bridge calls from the examiner instead of requiring unsafe global permission bypasses.

Safe WSL-local setup commands such as `date`, `pwd`, and `mkdir -p` for ignored report or artifact directories are allowed so noninteractive runs can record runner context and prepare output paths. Reports must still distinguish WSL runner metadata from Windows evidence.

A Gemma rerun confirmed that OpenCode can split a harmless setup chain into separate permission checks: `ls -d reports artifacts acquisitions 2>/dev/null || mkdir -p reports artifacts acquisitions` was rejected because the `ls` probe fell through to `ask`, even though the `mkdir` half was allowed. Noninteractive live-host runs should use one idempotent `mkdir -p reports artifacts acquisitions` command when setup is needed, and the config also allows the narrow directory probes seen in this failure mode.

The same test exposed a local-model schema drift issue: Gemma used `command` when calling the Task tool, but OpenCode requires `description`, `subagent_type`, and `prompt`. Keep the exact Task field names in the examiner and helper prompts so the mandatory subagent loop starts cleanly.

A later nested researcher run showed the next pressure point: multiple broad `websearch` calls expanded the request to 28,743 tokens and exceeded the same 16,384-token context window. Local-model research must stay targeted, use small result counts and `contextMaxCharacters`, and summarize after no more than two searches before continuing.

The next Gemma run proved that bounded search alone is not enough. The researcher subagent kept streaming a long note for more than 35 minutes after completing its bounded search, leaving the senior and examiner waiting. Local-model helper prompts now need explicit output caps and should avoid todo-list bookkeeping for single focused helper requests: researcher notes 8 lines or fewer, provisioner notes 10 lines or fewer, and senior handoffs 12 lines or fewer.

The same run also hit a slow automatic compaction pass immediately after the examiner created the report stub. OpenCode supports project-level compaction and tool-output limits, so this repo now sets bounded tool output and explicit automatic compaction with pruning, one preserved tail turn, a recent-token cap, and a reserved context buffer. The report and artifact files remain the durable state; the model context should not be the evidence store.

In a later run, the researcher correctly used local SearXNG but then followed it with OpenCode `websearch`. For Gemma-style local runs, that second source lane should be explicit, not habitual. After a successful SearXNG search, avoid OpenCode `websearch` unless SearXNG is unavailable or the senior specialist specifically needs another source lane.

The next retry showed that prompt guidance alone was too soft: the researcher still attempted OpenCode `websearch` after a successful local SearXNG result. The OpenCode config now denies `websearch` for the researcher and keeps `webfetch` available for narrowly targeted official upstream pages.

The same run returned a valid researcher result, then the parent generation stalled before the required provisioner call. The fix is to make the senior's post-research behavior deterministic: immediately call `forensic-tool-provisioner`, with no interim prose summary. The project config also advertises a smaller `llamacpp-local/gemma-heretic-bf16` output limit for this repo so helper turns are less likely to monopolize a single llama.cpp slot.

Another restart showed that BF16 first-token latency can still trip OpenCode or provider-side request cancellation before the first useful token arrives. The project sets a one-hour request timeout and one-hour chunk timeout for the inherited `llamacpp-local` provider, while leaving the actual provider URL in the analyst's local WSL config. Although OpenCode's generated schema says `false` can disable the provider timeout, live testing still showed five-minute cancellation behavior, so the project uses a large numeric value instead of `false`.

When cancelling a run against a single-slot local llama.cpp server, confirm the backend slot clears before starting the next run. A stale in-flight request can leave the new OpenCode process waiting quietly even though `/health` still answers. If the backend must be restarted, target the real process with an anchored command-line match such as `pgrep -f '^/path/to/llama-server-rpc'`; avoid broad `pkill -f` strings that can match and kill the restart shell itself. For very slow BF16 local runs, start llama-server with a long read/write timeout such as `--timeout 3600` or higher; otherwise the backend may cancel a long first generation before the examiner reaches the first Task call.

A later live-host rerun reached evidence collection but failed in a more practical way. The examiner used PowerShell variables and `$_` inside WSL double-quoted `powershell.exe -NoProfile -Command` strings. Bash expanded `$startTime` to an empty value and `$_` to a shell path before PowerShell ran, causing parser errors and a large `Get-Process` error burst. The next model request then exceeded the 16,384-token local context window. WSL live-host triage should avoid raw PowerShell `$` tokens in double-quoted commands, prefer fixed literal timestamps and simplified `Where-Object Property -Operator Value` filters, and write broad evidence to files with only a small console preview.

That rerun also showed why moving windows are not precise enough for forensic reporting. After the first collection timestamp is captured, the agent should compute one absolute two-hour window and reuse it across event logs, process starts, filesystem metadata, browser artifacts, and any staged tool output. Each evidence file should record the fixed window, collection time, source command, and row count so later report updates are not dependent on fragile model memory.

Another Gemma run proved the mandatory subagent sequence but failed while the provisioner was being called: the llama.cpp OpenAI-compatible endpoint first returned `ECONNRESET` and then refused connections on `LOCAL-GPU-HOST:8080`. This is a backend health blocker, not permission to continue without subagents. The examiner should stop at the helper blocker, restore `/health` and `/v1/models`, then retry the same helper loop.

Automatic compaction was useful as an emergency recovery path, but it was slow and sometimes produced stale or truncated next-step text on this local model. The project now keeps compaction enabled but less aggressive, lowers retained tool output, and pushes broad result sets into controlled artifact files instead of the chat transcript.

A subsequent Gemma rerun proved the first mandatory Task call and successfully started the senior tooling specialist, but the senior subagent request still reached a 13,894-token prompt pass. A follow-up run with a lean global instruction file lowered the examiner's first request to 6,656 tokens, but the nested senior helper still reached 14,784 tokens because it loaded the full senior `.agent.md` prompt and accumulated parent context. OpenCode now loads `AGENTS.opencode.md` plus lean role prompts under `docs/opencode-agents/`, while the expanded repository policy lives in `docs/repository-policy.md` and `.github/agents/` remains the Copilot-compatible prompt set.

Another retry lowered the examiner prompt to roughly 1,024 tokens and the senior prompt to roughly 10,190 tokens, proving the lean prompt split worked but still leaving a large helper request. The senior role now has task-only OpenCode permissions and no todo, read, shell, or direct web tools. It must coordinate the researcher and provisioner rather than carrying extra tool schemas into its own prompt.

A later local-provider rerun exposed a different pre-agent stall: OpenCode used the inherited global `small_model` for automatic session title generation before the examiner reached its first Task call. In that environment the inherited sidecar rejected the configured reasoning effort and left the run parked before forensic work began. OpenCode documents `small_model` as the model used for lightweight tasks such as title generation, so the project now pins the default `small_model` to GPT-5.5. Local Gemma regression tests should override it with `OPENCODE_CONFIG_CONTENT='{"small_model":"llamacpp-local/gemma-heretic-bf16"}'` and pass `--title` so title generation cannot delay the mandatory subagent loop.

The next one-hour live-host test proved the full subagent chain but exposed a collection-control bug. The senior handoff still suggested moving-window PowerShell and raw `$_` scriptblocks; the examiner then ran three independent evidence sources in one `&&` chain. When `Get-WinEvent` returned `NoMatchingEventsFound`, the process and network commands never ran and the agent tried to read output files that were not created. OpenCode live-host instructions now require fixed local timestamps, separate UTC values when needed, no raw `$_`, no `Now.AddHours`, and one evidence source per tool call. Empty event logs or zero-row artifacts must be written as explicit evidence/status results so later sources are not skipped.

A follow-up one-hour Gemma run reached the examiner -> senior -> researcher -> provisioner chain and wrote the report stub correctly, but collection still produced unsafe WSL PowerShell shapes. The examiner used `Where-Object { ... }` scriptblocks that were shell-mangled into `+.` property access, including a Security event user filter and a `Get-Process` `.IncludeUserName` owner filter. The run continued to a later network source, proving the no-`&&` fix worked, but the process and event commands were not defensible. The OpenCode prompt set now requires pre-execution command inspection, rejects WSL scriptblock filters, rejects shell-mangled `+.` and `.IncludeUserName`, uses `Get-WinEvent -FilterHashtable` or property-form filters, and collects process snapshots with `Get-CimInstance Win32_Process` while deriving user attribution from sessions and event logs.

The next retry showed that even a lean first request can fail if the first Task tool call itself is too verbose for a slow BF16 local backend. The remote llama.cpp server cancelled before OpenCode received a completed streamed tool call. The examiner's opening Task prompt and the senior's nested helper prompts are now deliberately compact: the first Task prompt should stay under 40 words, carry only short case facts plus the researcher-then-provisioner requirement, and leave detailed command families to the senior handoff after the subagent loop starts.

A later successful loop reached collection with safe command shapes, but the examiner still delayed the report stub until after broad collection and continued from `NoMatchingEventsFound` event-log errors without writing zero-row status files. The prompts now make the allowed pre-report sequence explicit: setup directories, capture time/timezone, write the report stub, then begin broad evidence collection. They also require a status file for every no-match or zero-row broad source before the next source runs.

The next one-hour Gemma regression exposed two launch and handoff issues. A Windows `Start-Process` call into WSL picked up the Windows npm OpenCode shim instead of the WSL-native binary, so background tests should call `$HOME/.local/bin/opencode` explicitly or use `wsl.exe -e bash -lc "..."`. After that was corrected, the examiner successfully called the senior specialist first, but the senior subagent stalled before emitting the required researcher Task. The lean OpenCode prompts now make the senior's first two assistant turns Task-only and lower local helper caps to 8/10/12 lines.

A follow-up one-hour test showed that a 256-token Gemma output cap was too tight for the examiner's first Task tool-call JSON. OpenCode recorded an invalid tool use because the JSON string was truncated before `subagent_type` and the closing fields arrived. The Gemma test output limit is now 512 tokens, while the first Task prompt must stay as one semicolon-separated line under 30 words with no pasted full user prompt and no newline. Helper response caps still apply after the Task call succeeds.

The next rerun proved that 512 tokens fixed the truncation length but not local Gemma's tendency to spend most of the turn before emitting the tool call, then punctuate the final JSON field with a period. The local Gemma model entry now sets `reasoningEffort` to `none`, `textVerbosity` to `low`, and `temperature` to `0`, and the prompt set tells the examiner to emit the opening Task immediately, preserve field order, and never add a period after the last tool-argument field.

A one-hour Gemma rerun proved the examiner -> senior -> researcher -> provisioner chain, including local SearXNG research, but exposed two new failure modes. OpenCode still auto-loaded top-level `AGENTS.md` despite the project `instructions` list, so the nested prompts again inherited the full repository policy. The run also completed the provisioner task with an empty result, leaving the senior without a usable execution flow. `AGENTS.md` is now a compact auto-loaded core-rules file, the expanded policy moved to `docs/repository-policy.md`, the provisioner must begin visible output with `FLOW:`, and the senior must retry provisioner if the result is empty, missing `FLOW:`, or too thin to hand off.

The same test also showed two backend-side llama.cpp crashes. The first followed a context-checkpoint or slot-cache restore error, and the second was a CUDA/cuBLAS failure during a long nested prompt. For local Gemma regression runs, prefer a single llama.cpp slot with prompt cache and context checkpoints disabled, such as `-np 1 -ctxcp 0 --no-cache-idle-slots -sps 0.0 --reasoning off --reasoning-budget 0 --timeout 7200`, and reduce batch or GPU-layer settings if CUDA errors recur. A later rerun reached the provisioner again with cache and checkpoints disabled but still died in CUDA/cuBLAS before the provisioner could emit `FLOW:`. If that repeats, use CPU-only `-ngl 0` or a verified quantized/non-BF16 local model, restore `/health` and `/v1/models`, then retry the same helper path. These backend failures remain blocked-helper-loop conditions; they are not permission to bypass subagents.

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
- Windows-to-WSL background tests use the WSL-native `opencode` binary rather than a Windows npm shim
- the senior's first local-model turn is a Task-only call to `forensic-tool-researcher`
- the examiner's first Task tool call is valid JSON, does not appear as `"tool":"invalid"`, and is not truncated by the local model output cap
- provider `ECONNRESET`, `ConnectionRefused`, or timeout errors stop the helper loop until the backend is healthy, then the same helper path is retried
- OpenCode tool-output and compaction settings reduce context growth before evidence collection begins
- local-provider request timeouts do not cancel slow BF16 generations before a helper Task call is emitted
- WSL live-host collection can use bounded Windows PowerShell bridge commands without `--dangerously-skip-permissions`
- safe WSL-local setup commands do not trigger noninteractive permission rejections
- WSL PowerShell commands do not include raw `$` variables or `$_` scriptblock references inside double-quoted command strings
- last-N-hours investigations reuse a fixed absolute collection window after collection start is captured
- broad evidence sources are saved under controlled artifact paths with small previews instead of streamed wholesale into model context
- global `small_model` settings do not route local-provider runs through an unrelated sidecar provider before the first Task call
- each broad evidence source runs independently, and empty or no-match results do not short-circuit later collection
- WSL PowerShell commands do not contain scriptblock filters, shell-mangled `+.` property access, or `Get-Process` owner-filtering through `.IncludeUserName`
- the examiner's first Task prompt is compact enough for slow local BF16 providers to emit before first streamed chunk cancellation
- the examiner's first Task prompt is one semicolon-separated line with no pasted full user request, no embedded newline, and no final-field punctuation outside JSON
- local Gemma test runs use low-verbosity, zero-temperature, no-reasoning model options when the OpenCode provider accepts them
- the report stub exists before broad evidence collection, and no-match event sources produce status files before later sources run
- top-level `AGENTS.md` stays compact enough for OpenCode auto-loading, with expanded policy in `docs/repository-policy.md`
- provisioner helper results begin with visible `FLOW:` content and empty provisioner results trigger a retry instead of examiner handoff
- local llama.cpp tests use cache and checkpoint settings that keep the single-slot backend stable through nested helper prompts
