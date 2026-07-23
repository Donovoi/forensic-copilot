# 2026-07-22 - Robin-backed tooling research

## Trigger

The online tooling-research helper used its own OpenCode and SearXNG path, so
the harness did not actually exercise the maintained Donovoi/robin fork.

## Decision

Online tooling research must run through the exact Donovoi/robin revision
pinned by `scripts/robin_research.py`. The adapter verifies the remote and
commit, loads Robin's dependency-light OpenCode client, and launches a separate
research-only agent from a temporary workspace.

The Robin agent may use at most a small SearXNG result set and narrow official
page fetching. Shell, local reads, writes, edits, task delegation, and generic
web search are denied. Its output is rejected if it exceeds seven non-empty
research lines or exhausts its bounded steps; the adapter adds an eighth
provenance line.

## Changes

- Added setup, pin verification, and bounded execution to
  `scripts/robin_research.py`.
- Made the OpenCode and Copilot-compatible tooling researchers invoke Robin
  first and preserve its backend revision line.
- Denied direct web tools to the outer OpenCode researcher so it cannot silently
  replace the required backend.
- Kept explicit offline runs on the documented local-source fallback path.
- Added fixture tests for pin checks, policy isolation, the standalone loader,
  and output bounds.

## Privacy

Research questions must contain only generic platform, evidence-mode, artifact,
and tooling needs. The adapter runs under a temporary directory and does not
write prompts or results into the repository. No case data, evidence names,
secrets, usernames, hostnames, hashes, absolute case paths, or screenshots were
added.
