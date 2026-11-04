#!/usr/bin/env python3
# Copyright (c) 2026 strhide developers
# SPDX-License-Identifier: Apache-2.0
"""Architectural boundary linter for strhide.

Enforces these modularity invariants:
1. structure ↛ stego.
2. stego ↛ structure.
3. core ↛ {formats, structure, stego, cli, analysis}.
4. formats ↛ {structure, stego, cli, analysis} (formats sits above core only).
5. analysis ↛ cli.

Absolute paths (`crate::x`, `strhide::x`) and cross-layer relative paths
(`super::x`) are both checked. Strings, raw strings, char literals and byte
literals are stripped before matching, so examples quoted in code or comments
cannot trigger a violation, and an odd quote inside a literal cannot hide real
imports.

Run `python scripts/import_lint.py --self-test` to exercise the lexer and the
relative-path resolution against synthetic fixtures.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


# `r"..."`, `r#"..."#`, `br#"..."#`, `cr#"..."#`.
RAW_STRING_RE = re.compile(r'[bc]?r(#*)"')
# `'x'`, `'\n'`, `'\''`; lifetimes (`'a`) and labels (`'outer`) do not match.
CHAR_LITERAL_RE = re.compile(r"'(?:\\.|[^\\'\n])'")
IDENT_CHAR_RE = re.compile(r"[A-Za-z0-9_]")
SUPER_REF_RE = re.compile(r"\bsuper::(?:super::)*([A-Za-z_][A-Za-z0-9_]*)")


def _blank(text: str) -> str:
    """Replace a removed span with its newlines so line numbers stay aligned."""
    return "\n" * text.count("\n")


def strip_rust_comments_and_strings(source: str) -> str:
    """Remove line comments, block comments, and literals from Rust source."""
    out: list[str] = []
    i = 0
    n = len(source)

    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i)
            if end < 0:
                break
            out.append("\n")
            i = end + 1
        elif source.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth > 0:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    if source[i] == "\n":
                        out.append("\n")
                    i += 1
        elif (raw := RAW_STRING_RE.match(source, i)) and (
            i == 0 or not IDENT_CHAR_RE.match(source[i - 1])
        ):
            # The prefix may be `r`, `br` or `cr`; the terminator repeats the
            # same number of `#`.
            terminator = '"' + raw.group(1)
            end = source.find(terminator, raw.end())
            if end < 0:
                out.append(_blank(source[i:]))
                break
            stop = end + len(terminator)
            out.append(_blank(source[i:stop]))
            i = stop
        elif source[i] == '"':
            i += 1
            while i < n:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == '"':
                    i += 1
                    break
                if source[i] == "\n":
                    out.append("\n")
                i += 1
        elif source[i] == "'":
            literal = CHAR_LITERAL_RE.match(source, i)
            if literal:
                out.append(_blank(literal.group(0)))
                i = literal.end()
            else:
                # Lifetime or label: keep the apostrophe as real code.
                out.append("'")
                i += 1
        else:
            out.append(source[i])
            i += 1

    return "".join(out)


def module_parts(rs_file: Path, src_root: Path) -> list[str]:
    """Module path components for a file, e.g. `core/mod.rs` -> `["core"]`."""
    parts = list(rs_file.relative_to(src_root).with_suffix("").parts)
    if parts and parts[-1] in {"mod", "lib", "main"}:
        parts.pop()
    return parts


def rust_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    return sorted(root.rglob("*.rs"))


def check_tree(
    src_root: Path,
    root: Path,
    forbidden_layers: set[str],
    rule_desc: str,
) -> list[str]:
    """Report absolute and cross-layer `super::` references under `root`."""
    violations: list[str] = []
    if not forbidden_layers:
        return violations

    layer_alternation = "|".join(sorted(forbidden_layers))
    absolute_re = re.compile(rf"\b(?:crate|strhide)::(?:{layer_alternation})\b")

    for rs_file in rust_files(root):
        content = rs_file.read_text(encoding="utf-8")
        clean_code = strip_rust_comments_and_strings(content)
        parts = module_parts(rs_file, src_root)

        for line_no, line in enumerate(clean_code.splitlines(), start=1):
            if absolute_re.search(line):
                violations.append(
                    f"{rs_file.as_posix()}:{line_no}: violation of rule '{rule_desc}':\n"
                    f"  {line.strip()}"
                )
                continue
            for match in SUPER_REF_RE.finditer(line):
                target = match.group(1)
                if target not in forbidden_layers:
                    continue
                # `super::` climbs one module each; reaching depth zero means
                # the name is a crate-root layer rather than a sibling module.
                hops = match.group(0).count("super::")
                if len(parts) - hops == 0:
                    violations.append(
                        f"{rs_file.as_posix()}:{line_no}: violation of rule '{rule_desc}':\n"
                        f"  {line.strip()}"
                    )
                    break

    return violations


def run_self_tests() -> int:
    """Exercise the lexer and relative-path resolution on synthetic fixtures."""
    import tempfile
    import unittest

    class ImportLintSelfTest(unittest.TestCase):
        def setUp(self) -> None:
            self._tmp = tempfile.TemporaryDirectory()
            self.src = Path(self._tmp.name) / "src"
            for layer in ("core", "structure", "stego", "formats"):
                (self.src / layer).mkdir(parents=True)

        def tearDown(self) -> None:
            self._tmp.cleanup()

        def write(self, rel: str, text: str) -> Path:
            path = self.src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            return path

        def test_raw_string_quotes_do_not_swallow_following_code(self) -> None:
            sample = 'let _ = r#"a "quoted" sample"#;\nuse crate::stego::Thing;\n'
            stripped = strip_rust_comments_and_strings(sample)
            self.assertNotIn("quoted", stripped)
            self.assertIn("crate::stego", stripped)

        def test_char_literal_quote_does_not_hide_a_real_import(self) -> None:
            sample = "let q = '\"';\nuse crate::stego::Thing;\n"
            stripped = strip_rust_comments_and_strings(sample)
            self.assertNotIn("'", stripped)
            self.assertNotIn('"', stripped)
            self.assertIn("crate::stego", stripped)

        def test_raw_string_keeps_line_numbers(self) -> None:
            sample = 'let _ = r#"line1\nline2\nline3"#;\nuse crate::stego::Thing;\n'
            stripped = strip_rust_comments_and_strings(sample)
            self.assertEqual(len(stripped.splitlines()), len(sample.splitlines()))

        def test_super_reference_at_layer_root_is_flagged(self) -> None:
            self.write("core/mod.rs", "use super::stego::Thing;\n")
            found = check_tree(self.src, self.src / "core", {"stego"}, "core !-> stego")
            self.assertEqual(len(found), 1)
            self.assertIn("core/mod.rs:1", found[0])

        def test_super_reference_inside_a_layer_is_allowed(self) -> None:
            # `src/core/commit.rs` is `crate::core::commit`, so `super::stego`
            # names a sibling inside `core`, not the crate-root `stego`.
            self.write("core/commit.rs", "use super::stego::Thing;\n")
            found = check_tree(self.src, self.src / "core", {"stego"}, "core !-> stego")
            self.assertEqual(found, [])

        def test_formats_cannot_reach_structure(self) -> None:
            self.write("formats/sniff.rs", "use crate::structure::Thing;\n")
            found = check_tree(
                self.src,
                self.src / "formats",
                {"structure", "stego", "cli", "analysis"},
                "formats !-> {structure, stego, cli, analysis}",
            )
            self.assertEqual(len(found), 1)

        def test_analysis_cannot_reach_cli(self) -> None:
            self.write("analysis.rs", "use crate::cli::args;\n")
            found = check_tree(self.src, self.src / "analysis.rs", {"cli"}, "analysis !-> cli")
            self.assertEqual(len(found), 1)

        def test_comments_and_strings_are_ignored(self) -> None:
            self.write(
                "core/mod.rs",
                "// use crate::stego::X;\nlet _ = \"crate::stego\";\n/* crate::stego */\n",
            )
            found = check_tree(self.src, self.src / "core", {"stego"}, "core !-> stego")
            self.assertEqual(found, [])

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ImportLintSelfTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return run_self_tests()

    repo_root = Path(__file__).resolve().parent.parent
    rust_src = repo_root / "rust" / "src"

    if not rust_src.is_dir():
        print(f"Error: Rust src directory not found at {rust_src}", file=sys.stderr)
        return 1

    rules = [
        (
            rust_src / "structure",
            {"stego"},
            "structure !-> stego",
        ),
        (
            rust_src / "stego",
            {"structure"},
            "stego !-> structure",
        ),
        (
            rust_src / "core",
            {"formats", "structure", "stego", "cli", "analysis"},
            "core !-> {formats, structure, stego, cli, analysis}",
        ),
        (
            rust_src / "formats",
            {"structure", "stego", "cli", "analysis"},
            "formats !-> {structure, stego, cli, analysis}",
        ),
        (
            rust_src / "analysis.rs",
            {"cli"},
            "analysis !-> cli",
        ),
    ]

    violations: list[str] = []
    for root, forbidden, desc in rules:
        violations.extend(check_tree(rust_src, root, forbidden, desc))

    if violations:
        print(f"Found {len(violations)} architectural boundary violation(s):", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1

    print(
        "OK: all architectural boundaries intact "
        "(structure !-> stego, stego !-> structure, "
        "core !-> {formats, structure, stego, cli, analysis}, "
        "formats !-> {structure, stego, cli, analysis}, analysis !-> cli)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
