# Tooling workspace

Use this directory for local, non-versioned helper assets that support tool preparation.

Suggested subdirectories:

- `downloads/` — manually downloaded or fetched packages
- `cache/` — package caches, container metadata, or temporary build state
- `report/` — CSS, templates, or other local assets used by the formal report export pipeline

The repository `.gitignore` is set up so large or transient tool assets do not pollute git history.

When tools are staged here, record the following in a Markdown provisioning note:

- tool name and version
- source or upstream URL
- install or extract path
- readiness verification method
- licensing or platform caveats
