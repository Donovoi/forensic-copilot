#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
IGNORED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "venv",
}
FORBIDDEN_PATHS = {
    ".tmp_test_probe.py": "scratch probe files should not be committed",
    ".vscode/tasks.json": "workstation-specific VS Code tasks should stay local",
}
FORBIDDEN_GLOBS = {
    ".tmp_*": "scratch files should not be committed",
}
LOCAL_PATH_PATTERNS = {
    "Linux home path": re.compile(r"/home/(?!(?:name|user|USER|ANALYST)/)([A-Za-z0-9._-]+)/"),
    "macOS home path": re.compile(r"/Users/(?!(?:name|user|USER|ANALYST)/)([A-Za-z0-9._-]+)/"),
    "WSL-mounted Windows user path": re.compile(
        r"/mnt/[a-z]/Users/(?!(?:name|user|USER|ANALYST)/)([A-Za-z0-9._-]+)/",
        re.IGNORECASE,
    ),
    "Windows user path": re.compile(
        r"[A-Za-z]:\\Users\\(?!(?:name|user|USER|ANALYST)\\)([A-Za-z0-9._-]+)\\"
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check the repository for obvious local-path leaks and scratch files."
    )
    parser.add_argument(
        "--root",
        default=str(REPO_ROOT),
        help="Repository root to scan. Defaults to the parent of this script.",
    )
    return parser.parse_args()


def iter_repo_files(root: Path):
    for current_dir, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name for name in dirnames if name not in IGNORED_DIRS and not name.startswith(".git")
        )
        for filename in sorted(filenames):
            yield Path(current_dir) / filename


def is_text_file(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:1024]
    except OSError:
        return False
    return b"\x00" not in sample


def find_forbidden_paths(root: Path) -> list[str]:
    violations: list[str] = []

    for relative_path, reason in FORBIDDEN_PATHS.items():
        if (root / relative_path).exists():
            violations.append(f"{relative_path}: {reason}")

    for pattern, reason in FORBIDDEN_GLOBS.items():
        for path in sorted(root.glob(pattern)):
            relative = path.relative_to(root)
            violations.append(f"{relative}: {reason}")

    return sorted(set(violations))


def find_local_path_leaks(root: Path) -> list[str]:
    violations: list[str] = []

    for path in iter_repo_files(root):
        if not is_text_file(path):
            continue

        relative = path.relative_to(root)
        text = path.read_text(encoding="utf-8", errors="ignore")
        for label, pattern in LOCAL_PATH_PATTERNS.items():
            for match in pattern.finditer(text):
                violations.append(f"{relative}: {label}: {match.group(0)}")

    return sorted(set(violations))


def main() -> int:
    args = parse_args()
    root = Path(args.root).expanduser().resolve()

    if not root.is_dir():
        print(f"validate_repo_hygiene.py: repository root not found: {root}", file=sys.stderr)
        return 1

    violations = [
        *find_forbidden_paths(root),
        *find_local_path_leaks(root),
    ]
    if violations:
        print("Repo hygiene violations found:")
        for violation in sorted(set(violations)):
            print(f"- {violation}")
        return 1

    print(f"Repo hygiene checks passed for {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
