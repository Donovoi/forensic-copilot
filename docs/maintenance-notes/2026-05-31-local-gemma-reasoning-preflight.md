# Local Gemma reasoning-budget preflight

## Trigger

An OpenCode regression using the local Gemma path reached the llama.cpp backend but produced no visible examiner output. The first request exited successfully after consuming the full output cap in hidden reasoning, so the mandatory first `forensic-senior-tooling-specialist` Task never appeared.

## Cause

The local model was doing useful hidden reasoning, but the configured first-turn output cap was too small for both thinking and the visible Task call. Server-side reasoning can make OpenCode receive streamed deltas while the visible transcript stays empty until the request ends.

The same run also confirmed that Copilot model discovery is not enough. A listed Copilot model can still be rejected at request time by the provider/account.

## Decision

Do not pin a top-level OpenCode model in the repo. Require users and regression jobs to choose the model explicitly, or let their own OpenCode user config provide the default.

Add a backend preflight script for llama.cpp local runs. It checks health, advertised model, context, idle slots, and stale reasoning slot state, with an optional tool-call smoke test.

For local Gemma regression runs, keep reasoning enabled when that is the desired local-model behavior, but use enough output budget and preferably a finite reasoning budget, such as `--reasoning on --reasoning-budget 1024`, so the first visible Task can still surface. A successful OpenCode exit with no visible first Task is a harness failure and must not be treated as a forensic result or permission to bypass subagents.

The follow-up reasoning-enabled test reached the examiner-to-senior Task and then the senior-to-platform-profiler Task, proving the mandatory loop. The profiler request then reset the local backend because OpenCode included broad shell and file tool schemas in a nested helper that only needed text inference. Keep the platform profiler text-only in OpenCode, and avoid calling it when strong case facts already identify the platform, such as BitLocker for Windows evidence and E01 for a disk image.

## Validation expectations

- `scripts/check_opencode_llamacpp_backend.py` fails before OpenCode when the backend is unreachable, busy, missing the requested model, or too small for the prompt.
- With `--smoke-tool-call`, the script fails if the backend returns only hidden reasoning and no visible content or tool call within the configured token budget.
- OpenCode local-model tests still pass `--title` and override both `model` and `small_model`.
- The examiner's first visible action remains a Task call to `forensic-senior-tooling-specialist`.
- The senior specialist should not route BitLocker E01 image work through a shell-capable platform profiler unless another fact makes the evidence platform genuinely ambiguous.
