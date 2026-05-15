#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


RELEASE_PATTERN = re.compile(r"(ready with caveats|not ready|ready)", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Render a reviewed Markdown forensic report into formal HTML, DOCX, and PDF outputs. "
            "Export is gated on a peer-review recommendation of 'ready'."
        )
    )
    parser.add_argument("--report", required=True, help="Path to the Markdown report")
    parser.add_argument("--peer-review", required=True, help="Path to the peer-review note")
    parser.add_argument(
        "--output-prefix",
        help="Optional output prefix. Defaults to <report-stem>.formal beside the report.",
    )
    parser.add_argument("--title", help="Optional document title for HTML and DOCX output")
    return parser.parse_args()


def read_release_recommendation(peer_review_path: Path) -> str:
    section = None
    for raw_line in peer_review_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            section = line[3:].strip().lower()
            continue
        if section == "release recommendation" and line:
            match = RELEASE_PATTERN.search(line)
            if match:
                return match.group(1).lower()
    raise ValueError(
        f"Could not find a release recommendation in peer-review note: {peer_review_path}"
    )


def ensure_binary(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise FileNotFoundError(f"Required binary not found in PATH: {name}")
    return resolved


def build_output_paths(report_path: Path, output_prefix: str | None) -> tuple[Path, Path, Path]:
    if output_prefix:
        prefix = Path(output_prefix)
    else:
        prefix = report_path.with_name(f"{report_path.stem}.formal")
    return (
        prefix.with_name(f"{prefix.name}.html"),
        prefix.with_name(f"{prefix.name}.docx"),
        prefix.with_name(f"{prefix.name}.pdf"),
    )


def run_command(command: list[str]) -> None:
    subprocess.run(command, check=True)


def render_html_and_docx(
    report_path: Path,
    html_path: Path,
    docx_path: Path,
    css_path: Path,
    title: str,
) -> None:
    pandoc = ensure_binary("pandoc")

    html_command = [
        pandoc,
        str(report_path),
        "--from",
        "gfm",
        "--to",
        "html5",
        "--standalone",
        "--css",
        str(css_path),
        "--metadata",
        f"title={title}",
        "--output",
        str(html_path),
    ]
    docx_command = [
        pandoc,
        str(report_path),
        "--from",
        "gfm",
        "--to",
        "docx",
        "--metadata",
        f"title={title}",
        "--output",
        str(docx_path),
    ]

    run_command(html_command)
    run_command(docx_command)


def render_pdf_from_html(html_path: Path, pdf_path: Path) -> str:
    if shutil.which("weasyprint"):
        run_command(["weasyprint", str(html_path), str(pdf_path)])
        return "weasyprint"
    if shutil.which("wkhtmltopdf"):
        run_command(["wkhtmltopdf", "--enable-local-file-access", str(html_path), str(pdf_path)])
        return "wkhtmltopdf"
    raise FileNotFoundError(
        "No supported PDF backend found. Install 'weasyprint' or 'wkhtmltopdf', then re-run the export."
    )


def main() -> int:
    args = parse_args()
    report_path = Path(args.report).expanduser().resolve()
    peer_review_path = Path(args.peer_review).expanduser().resolve()
    repo_root = Path(__file__).resolve().parent.parent
    css_path = repo_root / "tooling" / "report" / "formal-report.css"

    if not report_path.is_file():
        raise FileNotFoundError(f"Report not found: {report_path}")
    if not peer_review_path.is_file():
        raise FileNotFoundError(f"Peer-review note not found: {peer_review_path}")
    if not css_path.is_file():
        raise FileNotFoundError(f"CSS asset not found: {css_path}")

    recommendation = read_release_recommendation(peer_review_path)
    if recommendation != "ready":
        print(
            f"Peer review recommendation is '{recommendation}'. Formal export is blocked until the note is marked 'ready'.",
            file=sys.stderr,
        )
        return 2

    html_path, docx_path, pdf_path = build_output_paths(report_path, args.output_prefix)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    title = args.title or report_path.stem.replace("-", " ").replace("_", " ").title()

    render_html_and_docx(report_path, html_path, docx_path, css_path, title)
    pdf_backend = render_pdf_from_html(html_path, pdf_path)

    print(f"HTML written to: {html_path}")
    print(f"DOCX written to: {docx_path}")
    print(f"PDF written to:  {pdf_path}")
    print(f"PDF backend:     {pdf_backend}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"render_formal_report.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
