#!/usr/bin/env python3
# Copyright (c) 2026 strhide developers
# SPDX-License-Identifier: Apache-2.0
"""Compile the trimmed-feature matrix that CI treats as a blocking gate.

`--all-features` and the default set do not prove that each domain still
compiles on its own: a `#[cfg(feature = "...")]` on a type definition but not
on its `impl` block only breaks the single-feature builds. This script runs
exactly the rows from `.github/workflows/ci.yml` ("Minimal feature builds"), in
order, and stops at the first failure.

Every command is run from the repository's `rust/` directory regardless of
where the script is invoked from.

Usage:
    python scripts/check_feature_matrix.py                 # all eleven rows
    python scripts/check_feature_matrix.py content-png     # one row
    python scripts/check_feature_matrix.py structure analysis
    python scripts/check_feature_matrix.py none            # no-default-features

A selector matches a row when it equals the row's feature name, one of its
comma-joined parts, or `none` for the bare `--no-default-features` build.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RUST_DIR = REPO_ROOT / "rust"

# Cargo may colour its diagnostics even when the output is captured (the CI and
# some local shells set `CARGO_TERM_COLOR=always`), so match on text without
# escape sequences.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Keep this list identical to the "Minimal feature builds" step in
# .github/workflows/ci.yml. An empty tuple is the bare, featureless build.
MATRIX: list[tuple[str, ...]] = [
    (),
    ("structure-base",),
    ("structure",),
    ("content-base",),
    ("content-png",),
    ("content-jpeg",),
    ("content-hevc",),
    ("content",),
    ("analysis",),
    ("core-io",),
    ("config",),
]


def command_for(features: tuple[str, ...]) -> list[str]:
    cmd = ["cargo", "build", "--no-default-features"]
    if features:
        cmd += ["--features", ",".join(features)]
    return cmd


def selector_for(features: tuple[str, ...]) -> str:
    return ",".join(features) if features else "none"


def describe(cmd: list[str]) -> str:
    return " ".join(cmd)


def key_error_lines(output: str) -> list[str]:
    """Keep only the lines a reader needs, not the whole cargo log."""
    kept: list[str] = []
    for line in ANSI_RE.sub("", output).splitlines():
        stripped = line.strip()
        if stripped.startswith("error") or stripped.startswith("-->"):
            kept.append(line.rstrip())
            if len(kept) >= 12:
                break
    return kept


def selection(args: list[str]) -> list[tuple[str, ...]]:
    if not args:
        return MATRIX

    rows: list[tuple[str, ...]] = []
    for wanted in args:
        matches = [
            row
            for row in MATRIX
            if wanted == selector_for(row) or wanted in row or wanted == "none" and not row
        ]
        if not matches:
            valid = ", ".join(selector_for(row) for row in MATRIX)
            raise SystemExit(f"unknown row '{wanted}'; valid rows: {valid}")
        rows.extend(matches)
    # Preserve matrix order and drop duplicates so repeated selectors stay cheap.
    return [row for row in MATRIX if row in rows]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Compile every trimmed feature combination CI requires."
    )
    parser.add_argument(
        "rows",
        nargs="*",
        metavar="ROW",
        help="only run the matching rows (feature name, or 'none'); default: all",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the rows without compiling anything",
    )
    args = parser.parse_args(argv)

    if args.list:
        for row in MATRIX:
            print(f"{selector_for(row):<16} {describe(command_for(row))}")
        return 0

    if not RUST_DIR.is_dir():
        print(f"Error: Rust directory not found at {RUST_DIR}", file=sys.stderr)
        return 1

    rows = selection(args.rows)
    for row in rows:
        cmd = command_for(row)
        line = describe(cmd)
        result = subprocess.run(
            cmd,
            cwd=RUST_DIR,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            print(f"[FAIL] {line}")
            for error_line in key_error_lines(result.stdout + result.stderr):
                print(f"       {error_line}")
            return result.returncode or 1
        print(f"[ok]   {line}")

    print(f"OK: {len(rows)} feature build(s) succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
