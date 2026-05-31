# 2026-05-31 - Manual-first tooling decisions

## Trigger

Live X-Ways work showed that a planned workaround could be wrong if the current
manual already documents a native capability.

## Decision

Before making decisions about any program, tool, command family, API,
automation route, update path, or fallback, the workflow must check the newest
available official manual, vendor documentation, maintained upstream docs, or
approved local docs/cache.

If current documentation cannot be reached because the run is offline or
restricted, the helper must state the local/offline basis and review-date limit
instead of pretending the answer is current.

## Changes

- Added the rule to compact and expanded repository policy.
- Updated the senior tooling specialist, tool researcher, and tool provisioner
  prompts for both Copilot-compatible and OpenCode prompt sets.
- Updated the tooling matrix so manual-first checking precedes command, API,
  automation, update, parallelization, or fallback decisions.

## Privacy

No case data, evidence names, keys, recovered filenames, hashes, local case
paths, or screenshots were added.
