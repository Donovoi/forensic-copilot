# Sensitive artifact collection

## Trigger

Live-host testing showed that the workflow treated credential stores, cookies, tokens, browser login databases, password-manager data, and `.env` files as data to avoid during collection. That is too broad for forensic work: those artifacts may be the evidence that proves user activity, access, intent, or compromise.

## Decision

Sensitivity is now treated as a handling and disclosure issue, not a collection veto. When the authority and case question include an artifact class, the examiner should preserve or inventory it with hashes, provenance, and controlled outputs. Plaintext secret values should not be printed into prompts, terminal transcripts, Markdown reports, or public repository content unless the case specifically requires that value.

## Changes

- Added comprehensive in-scope collection as a repository priority.
- Updated the examiner, senior tooling specialist, and tool provisioner prompts to collect or preserve secret-bearing artifacts when in scope.
- Expanded OpenCode permissions so the examiner can create ignored acquisition and artifact paths, hash collected files, and copy or archive in-scope artifacts.
- Updated workflow docs to separate case evidence handling from public-repository redaction.

## Validation expectations

Future live-host tests should confirm that the agent:

- inventories sensitive artifact classes instead of excluding them by category
- preserves or hashes relevant stores under ignored case-output paths
- avoids exposing plaintext secret values in the report unless explicitly required
- keeps scope, authority, and publication controls visible in the Markdown report

