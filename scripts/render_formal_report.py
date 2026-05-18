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
    parser.add_argument("--report", help="Path to the Markdown report")
    parser.add_argument("--peer-review", help="Path to the peer-review note")
    parser.add_argument(
        "--output-prefix",
        help="Optional output prefix. Defaults to <report-stem>.formal beside the report.",
    )
    parser.add_argument("--title", help="Optional document title for HTML and DOCX output")
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Report whether pandoc and a supported PDF backend are available, then exit.",
    )
    parser.add_argument(
        "--skip-pdf",
        action="store_true",
        help="Render HTML and DOCX only. Useful when no PDF backend is installed.",
    )

    args = parser.parse_args()
    if not args.check_deps and (not args.report or not args.peer_review):
        parser.error("--report and --peer-review are required unless --check-deps is used")
    return args


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


def find_pdf_backend() -> tuple[str, str] | None:
    for name in ("weasyprint", "wkhtmltopdf"):
        resolved = shutil.which(name)
        if resolved:
            return name, resolved
    return None


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


def inline_css(html_path: Path, css_path: Path) -> None:
    html = html_path.read_text(encoding="utf-8")
    css = css_path.read_text(encoding="utf-8")
    marker = "</head>"
    if marker not in html:
        raise ValueError(f"Generated HTML does not contain a </head> element: {html_path}")

    style_block = f"<style>\n{css}\n</style>\n"
    html_path.write_text(html.replace(marker, f"{style_block}{marker}", 1), encoding="utf-8")


def print_dependency_status() -> int:
    pandoc = shutil.which("pandoc")
    pdf_backend = find_pdf_backend()

    print(f"pandoc:         {pandoc or 'missing'}")
    if pdf_backend:
        backend_name, backend_path = pdf_backend
        print(f"PDF backend:    {backend_name} ({backend_path})")
    else:
        print("PDF backend:    missing (install weasyprint or wkhtmltopdf, or use --skip-pdf)")

    return 0 if pandoc else 1


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
    inline_css(html_path, css_path)
    run_command(docx_command)


def render_pdf_from_html(html_path: Path, pdf_path: Path) -> str:
    pdf_backend = find_pdf_backend()
    if pdf_backend and pdf_backend[0] == "weasyprint":
        run_command([pdf_backend[1], str(html_path), str(pdf_path)])
        return pdf_backend[0]
    if pdf_backend and pdf_backend[0] == "wkhtmltopdf":
        run_command([pdf_backend[1], "--enable-local-file-access", str(html_path), str(pdf_path)])
        return pdf_backend[0]
    raise FileNotFoundError(
        "No supported PDF backend found. Install 'weasyprint' or 'wkhtmltopdf', then re-run the export."
    )


def main() -> int:
    args = parse_args()
    if args.check_deps:
        return print_dependency_status()

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
    if args.skip_pdf:
        print(f"HTML written to: {html_path}")
        print(f"DOCX written to: {docx_path}")
        print("PDF written to:  skipped (--skip-pdf)")
        return 0

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
        raise SystemExit(1) from exc
