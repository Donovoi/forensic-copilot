# Privacy and redaction checklist

This repository is public-facing and should remain generic.

Redaction is a publication control, not an evidence-collection rule. During authorized casework, sensitive artifacts can still be preserved, hashed, parsed, dumped, and cited as evidence when they are in scope. Secret values should live in approved controlled case outputs, with provenance and handling notes. The restriction here is on what enters the public repository, ordinary prompts, terminal previews, and report prose without a specific case need.

When secret extraction produces leads, public-facing materials should describe the lead category, source artifact, likely program/site/service, confidence, and controlled output path without exposing the value. Plaintext values remain in the controlled case output unless the case specifically requires disclosure.

Before publishing changes, verify that the content does **not** reveal:

- your real name or another person's real name
- usernames or account names
- email addresses
- workstation or hostname details
- absolute local paths such as `/home/name/...` or `C:\Users\name\...`
- employer, client, agency, or team names
- internal ticket numbers or case references
- screenshots or exports from live investigations
- evidence-derived hashes, identifiers, serial numbers, or unique environment details unless deliberately sanitized

## Use placeholders instead

Preferred placeholder patterns:

- `CASE-001`
- `ANALYST`
- `HOST-A`
- `ORG-NAME`
- `/evidence/image.E01`
- `/analysis/report.md`

## Quick pre-commit and pre-push checklist

1. Search the repository for names, usernames, emails, hostnames, and absolute paths.
2. Search for employer, client, organization, or agency references.
3. Confirm no evidence files, screenshots, notes, or raw case outputs are being committed.
4. Confirm examples use placeholders rather than live values.
5. Run `scripts/validate_repo_hygiene.py` or an equivalent automated sweep to catch obvious local paths and scratch files.
6. Review the staged diff and confirm every changed file still passes this checklist.
7. Confirm the remaining content still supports the forensic-analysis and Markdown-report goal.

## Automation helper

The repo includes `scripts/validate_repo_hygiene.py` for a baseline automated sweep.

Use it to catch obvious workstation-specific paths and scratch files before you commit. It skips the same top-level case-output and evidence-staging directories that are ignored by git, such as `reports/`, `cases/`, `evidence/`, `artifacts/`, `exports/`, `acquisitions/`, and `toolcache/`, so local investigation outputs can remain present but untracked while the published repository is checked. It does not replace manual review for privacy, case scope, or publication risk.

## Important limitation

This checklist only covers repository **content**.

Public GitHub metadata can still identify you, including:

- the repository owner or organization name
- the commit author name and email from your Git configuration
- the remote URL or hosting account used for publication
- your public GitHub profile
- repository stars, followers, or activity patterns

If stronger anonymity is required, publish from a neutral organization or pseudonymous account and use a neutral Git author identity before committing.
