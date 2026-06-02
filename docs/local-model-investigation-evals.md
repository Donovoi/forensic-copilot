# Local Model Investigation Evals

Use this workflow to test whether a local OpenCode + llama.cpp model can reach
the same high-level forensic conclusion as a stronger reference run without
leaking case facts.

## Gates

1. llama.cpp backend health and model advertisement
2. optional visible tool-call smoke test
3. OpenCode command availability, when `--runner opencode`
4. OpenCode forensic-examiner run or direct llama.cpp run
5. comparison against a local expected-result JSON

If any early gate fails, the eval records `blocked` and does not pretend a model
completed the investigation.

## Command

`opencode.json` defaults both `model` and `small_model` to local
`llamacpp-local/gemma-heretic-q4_k_m` so compaction and summaries do not fall
back to an external provider. Override this only in a private local config.

On a distributed setup, run the OpenAI-compatible llama.cpp HTTP server on the
OpenCode runner, then use Tailscale/RPC behind that server for GPU workers. For
example, `commando-1` can serve `http://127.0.0.1:8080/v1` while using
`ubuntu-gpu:50052` as an RPC worker. If the GPU host directly serves HTTP, set
`--base-url` and the private OpenCode provider `baseURL` to that Tailscale URL.

```powershell
python scripts\run_local_model_investigation_eval.py `
  --runner opencode `
  --base-url http://127.0.0.1:8080 `
  --model gemma-heretic-q4_k_m `
  --opencode-model llamacpp-local/gemma-heretic-q4_k_m `
  --prompt-file <local-redacted-prompt.txt> `
  --expected-json <local-expected-summary.json>
```

The prompt and expected JSON should live in ignored local case output folders.
Do not commit case prompts, expected case conclusions, raw model output, alias
maps, or reports.

The runner attaches a local prompt file to OpenCode instead of passing prompt
text as a command-line argument. Status JSON records command shape, paths, exit
codes, and comparison status, but not the raw prompt text.

If the full OpenCode helper loop is too slow for the local model, use the direct
runner to test Gemma's analytical conclusion from sanitized local artifacts:

```powershell
python scripts\run_local_model_investigation_eval.py `
  --runner direct `
  --base-url http://127.0.0.1:8080 `
  --model gemma-heretic-q4_k_m `
  --prompt-file <local-redacted-prompt.txt> `
  --context-file <sanitized-report.md> `
  --context-file <sanitized-structured.json> `
  --expected-json <local-expected-summary.json>
```

The direct runner is not a substitute for OpenCode orchestration. It is a local
regression fallback that answers whether the model can reach the same sanitized
conclusion once tool-loop overhead is removed.

## Expected JSON

The comparison file can stay simple:

```json
{
  "required_substrings": [
    "7 machine",
    "10",
    "M001",
    "M007"
  ],
  "forbidden_substrings": [
    "recovery key value",
    "raw evidence name"
  ]
}
```

This is a coarse regression gate. Human review still decides whether the model
used the right forensic reasoning, respected the adapter contract, and recorded
limitations honestly.
