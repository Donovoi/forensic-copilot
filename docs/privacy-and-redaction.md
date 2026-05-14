# Privacy and redaction checklist

This repository is public-facing and should remain generic.

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

## Quick pre-push checklist

1. Search for names, usernames, emails, hostnames, and absolute paths.
2. Search for employer, client, organization, or agency references.
3. Confirm no evidence files, screenshots, notes, or raw case outputs are being committed.
4. Confirm examples use placeholders rather than live values.
5. Confirm the remaining content still supports the forensic-analysis and Markdown-report goal.

## Important limitation

This checklist only covers repository **content**.

Public GitHub metadata can still identify you, including:

- the repository owner or organization name
- your public GitHub profile
- repository stars, followers, or activity patterns

If stronger anonymity is required, publish from a neutral organization or pseudonymous account rather than a personally identifying GitHub identity.
