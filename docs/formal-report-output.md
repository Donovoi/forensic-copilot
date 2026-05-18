# Formal report output

The Markdown report is the canonical case record.

Formal output exists to give that same reviewed content a cleaner layout for circulation, filing, or briefing. It should never become a second source document that drifts away from the Markdown report.

## Release gate

Formal export is allowed only after peer review returns `ready`.

- `ready` — generate the formal package if the case requires it
- `ready with caveats` — hold the formal package until the caveats are resolved or formally accepted
- `not ready` — do not export

The peer-review note stays part of the case record either way.

## Current export path

The current Linux-first export path is:

1. keep the report in Markdown
2. use `uv run` to execute the local export helper script
3. use `pandoc` to render standalone HTML and DOCX from the reviewed Markdown
4. have the helper embed the bundled stylesheet into the generated HTML so the export does not depend on a workstation-specific CSS path
5. render PDF from the generated HTML when a supported local backend is available, or use `--skip-pdf` when only HTML and DOCX are required

The bundled helper script is `scripts/render_formal_report.py`.

Default outputs are written beside the source report:

- `report.formal.html`
- `report.formal.docx`
- `report.formal.pdf`

The HTML output is self-styled. It should not point at an absolute local path for `tooling/report/formal-report.css`.

## Tool split

Use each tool for the part it actually handles:

- `uv run` — run the local Python orchestration script
- `uvx` / `uv tool run` — optional path for Python-based CLI helpers
- `pandoc` — convert reviewed Markdown into standalone HTML or DOCX
- `weasyprint` or `wkhtmltopdf` — turn the generated HTML into PDF when available

`uv` should not be treated as the installer for non-Python binaries such as `pandoc`.

## Preflight and degraded mode

The helper script supports two practical modes that make export failures easier to explain:

- `--check-deps` — report whether `pandoc` and a supported PDF backend are available before case export time
- `--skip-pdf` — generate HTML and DOCX only when no PDF backend is installed or a PDF is not required for the handoff

## Why this is the baseline

This repo is Linux-first. A browser-embedded export stack, a WASM-only renderer, or a WebView2 path would add more runtime coupling than the current workflow needs.

Those ideas may be worth revisiting later if offline cross-platform packaging becomes a hard requirement. They are not the baseline today.

## Failure handling

If export fails:

- keep the Markdown report as the source of truth
- keep the peer-review note with the case record
- record which binary or backend was missing
- use `--check-deps` early when you need to confirm the local export toolchain
- use `--skip-pdf` rather than presenting an HTML or DOCX-only result as a full formal package
- do not claim that a formal package was produced when only an HTML draft exists

## Example

```text
uv run scripts/render_formal_report.py --check-deps

uv run scripts/render_formal_report.py \
  --report /analysis/forensic-report.md \
  --peer-review /analysis/forensic-peer-review.md \
  --skip-pdf

uv run scripts/render_formal_report.py \
  --report /analysis/forensic-report.md \
  --peer-review /analysis/forensic-peer-review.md
```

The script will refuse to export if the peer-review note does not contain a `ready` recommendation.
