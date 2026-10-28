#!/usr/bin/env python3
# Copyright (c) 2026 strhide developers
# SPDX-License-Identifier: Apache-2.0
"""Architectural boundary linter for strhide.

Enforces three strict modularity invariants:
1. structure ↛ stego: The container layer cannot depend on the content stego engine.
2. stego ↛ structure: The content stego engine cannot depend on the container layer.
3. core ↛ {formats, structure, stego, cli}: Core foundations cannot depend on higher layers.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def strip_rust_comments_and_strings(source: str) -> str:
    """Remove line comments, block comments, and string literals from Rust source."""
    out = []
    i = 0
    n = len(source)
    in_block = 0
    in_line = False
    in_string = False
    escape = False

    while i < n:
        if in_line:
            if source[i] == "\n":
                in_line = False
                out.append("\n")
            i += 1
        elif in_block > 0:
            if i + 1 < n and source[i : i + 2] == "*/":
                in_block -= 1
                i += 2
            elif i + 1 < n and source[i : i + 2] == "/*":
                in_block += 1
                i += 2
            else:
                if source[i] == "\n":
                    out.append("\n")
                i += 1
        elif in_string:
            if escape:
                escape = False
            elif source[i] == "\\":
                escape = True
            elif source[i] == '"':
                in_string = False
            i += 1
        else:
            if i + 1 < n and source[i : i + 2] == "//":
                in_line = True
                i += 2
            elif i + 1 < n and source[i : i + 2] == "/*":
                in_block = 1
                i += 2
            elif source[i] == '"':
                in_string = True
                i += 1
            else:
                out.append(source[i])
                i += 1
    return "".join(out)


def check_directory(
    root: Path,
    forbidden_patterns: list[tuple[re.Pattern[str], str]],
) -> list[str]:
    violations = []
    if not root.is_dir():
        return violations

    for rs_file in sorted(root.rglob("*.rs")):
        content = rs_file.read_text(encoding="utf-8")
        clean_code = strip_rust_comments_and_strings(content)

        for line_no, line in enumerate(clean_code.splitlines(), start=1):
            for pattern, desc in forbidden_patterns:
                if pattern.search(line):
                    rel = rs_file.as_posix()
                    violations.append(
                        f"{rel}:{line_no}: violation of rule '{desc}':\n  {line.strip()}"
                    )
    return violations


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    rust_src = repo_root / "rust" / "src"

    if not rust_src.is_dir():
        print(f"Error: Rust src directory not found at {rust_src}", file=sys.stderr)
        return 1

    structure_dir = rust_src / "structure"
    stego_dir = rust_src / "stego"
    core_dir = rust_src / "core"

    # Rule 1: structure !-> stego
    rule1_patterns = [
        (
            re.compile(r"\b(?:crate|strhide)::stego\b"),
            "structure !-> stego",
        )
    ]

    # Rule 2: stego !-> structure
    rule2_patterns = [
        (
            re.compile(r"\b(?:crate|strhide)::structure\b"),
            "stego !-> structure",
        )
    ]

    # Rule 3: core !-> {formats, structure, stego, cli}
    rule3_patterns = [
        (
            re.compile(r"\b(?:crate|strhide)::(?:formats|structure|stego|cli)\b"),
            "core !-> {formats, structure, stego, cli}",
        )
    ]

    violations = []
    violations.extend(check_directory(structure_dir, rule1_patterns))
    violations.extend(check_directory(stego_dir, rule2_patterns))
    violations.extend(check_directory(core_dir, rule3_patterns))

    if violations:
        print(f"Found {len(violations)} architectural boundary violation(s):", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    print("OK: all architectural boundaries intact (structure !-> stego, stego !-> structure, core !-> {formats, structure, stego, cli})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
