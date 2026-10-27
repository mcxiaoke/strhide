#!/usr/bin/env python3
"""Stage-0 baseline harness for the strhide architecture refactor.

Why this exists
---------------
The refactor moves ISOBMFF parsing, format sniffing and payload metadata
between modules. Those changes must not alter what the tool *writes*: a carrier
that embeds today must still embed to the same size, extract to the same
payload, and restore bit-for-bit. Unit tests cover behaviour; this harness
freezes the observable numbers of every local corpus file so a silent byte
regression shows up as a diff.

What is recorded (all deterministic)
------------------------------------
Per case, for both domains:
  * original size + sha256
  * structure domain: chosen strategy, envelope size, stego size, extracted
    payload sha256, restored sha256 (must equal the original), per-strategy
    capacity numbers from `inspect --json`
  * content domain: capacity (max / recommended), stego size, extracted payload
    sha256

Every content-domain embed is driven with a fixed `--seed`, so its salt/nonce
come from the seed instead of fresh randomness: the stego bytes are
reproducible and ARE hashed. A parsing/encoding change that moves a single
coefficient then shows up as a hash diff, not just as a size diff.

The structure domain has no seed knob (the UBE envelope nonce is always
random), so there only the envelope size, the chosen strategy, the per-strategy
capacity numbers and bit-exact restoration are compared.

Usage
-----
    # freeze the current behaviour (run this before touching the code)
    python scripts/baseline_hash.py --write

    # after a refactor step: recompute and diff against the frozen file
    python scripts/baseline_hash.py --check

    # cheap smoke test on the first few cases
    python scripts/baseline_hash.py --only fixtures --limit 3

    # reproducibility check is on by default (fixed --seed); `--no-seed` falls
    # back to random salt and then only sizes/capacities are compared

HEVC content-domain embeds are opt-in (`--include-content-hevc`): a single
1080p60 clip costs ~100 s and ~12 GB of RSS, which is fine locally but not as a
default gate. The HEIF/MP4 *structure* paths always run — they are the ones the
ISOBMFF merge touches — and they are cheap.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "temp" / "baseline"

# Payloads are short and fixed. The content domain is capacity-bound, so a tiny
# payload keeps every carrier eligible; capacity itself is recorded separately.
PAYLOAD_STRUCTURE = "strhide-baseline-structure"
PAYLOAD_CONTENT = "sb1"

# Fixed content-domain seed: makes embed byte-reproducible (see `--seed` on
# `strhide embed`). Changing it changes every content hash in the baseline, so
# treat it as part of the baseline format, not a knob.
SEED_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

STRUCTURE_EXTS = {
    "png", "jpg", "jpeg", "webp", "wav", "heic", "heif", "avif",
    "mp4", "mov", "m4v", "mkv", "zip", "jar", "pdf", "exe", "dll",
    "h265", "hevc", "hevc10", "txt",
}
CONTENT_EXTS_DEFAULT = {"png", "jpg", "jpeg"}
CONTENT_EXTS_HEVC = {"heic", "heif", "avif", "mp4", "mov", "m4v", "h265", "hevc", "hevc10"}

CORPORA = [
    ("fixtures", REPO / "rust" / "tests" / "fixtures"),
    ("assets", REPO / "rust" / "tests" / "assets"),
    ("testhevc", REPO / "temp" / "testhevc"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_bin(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.exists():
            sys.exit(f"error: --bin not found: {p}")
        return p.resolve()
    names = ["strhide.exe" if os.name == "nt" else "strhide"]
    for profile in ("release", "debug"):
        for name in names:
            p = REPO / "rust" / "target" / profile / name
            if p.exists():
                return p.resolve()
    sys.exit("error: no strhide binary found; run `cargo build --release` in rust/")


def newest_source_mtime() -> float:
    newest = 0.0
    for root in (REPO / "rust" / "src",):
        for path in root.rglob("*.rs"):
            newest = max(newest, path.stat().st_mtime)
    return newest


def run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


def first_error(err: str) -> str:
    for line in reversed(err.strip().splitlines()):
        if line.strip():
            return line.strip()[:200]
    return ""


def is_unsupported(err: str) -> bool:
    low = err.lower()
    return "supported carrier format" in low or "not supported" in low or "unsupported" in low


def load_json_line(stdout: str) -> dict | None:
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def load_json_block(stdout: str) -> dict | None:
    """Parse a pretty-printed single JSON object (inspect --json)."""
    text = stdout.strip()
    start = text.find("{")
    if start < 0:
        return None
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        return None


def capacity_pairs(inspect: dict | None) -> list[list] | None:
    if not inspect:
        return None
    out = []
    for item in inspect.get("strategies") or []:
        if isinstance(item, dict):
            out.append([item.get("strategy"), item.get("capacity_bytes")])
    return out


def case_id(corpus: str, path: Path) -> str:
    rel = path.relative_to(REPO).as_posix()
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in rel)
    return f"{corpus}__{safe}"


def collect_cases(only: str | None) -> list[tuple[str, Path]]:
    cases = []
    for corpus, root in CORPORA:
        if only and only not in corpus:
            continue
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            ext = path.suffix.lower().lstrip(".")
            if ext not in STRUCTURE_EXTS:
                continue
            cases.append((corpus, path))
    return cases


def structure_pass(bin_path: Path, orig: Path, work: Path, timeout: int) -> dict:
    stego = work / f"stego{orig.suffix}"
    restored = work / f"restored{orig.suffix}"
    payload_out = work / "payload.bin"

    code, out, err = run(
        [str(bin_path), "write", str(orig), "-t", PAYLOAD_STRUCTURE,
         "-o", str(stego), "--no-backup", "--quiet"],
        timeout,
    )
    if code != 0:
        return {
            "status": "failed",
            "unsupported": is_unsupported(err),
            "note": first_error(err),
        }

    result: dict = {"status": "ok", "stego_size": stego.stat().st_size}

    code, out, err = run(
        [str(bin_path), "inspect", str(stego), "--json"], timeout
    )
    inspect = load_json_block(out) if code == 0 else None
    if inspect:
        result["format"] = inspect.get("format")
        result["strategy"] = inspect.get("strategy")
        result["ube_total_size"] = inspect.get("ube_total_size")
        result["strategy_capacities"] = capacity_pairs(inspect)

    code, out, err = run(
        [str(bin_path), "read", str(stego), "-o", str(payload_out),
         "--overwrite", "--quiet"],
        timeout,
    )
    if code != 0:
        result["status"] = "read_failed"
        result["note"] = first_error(err)
        return result
    result["payload_sha256"] = sha256_file(payload_out)

    code, out, err = run(
        [str(bin_path), "restore", str(stego), "-o", str(restored),
         "--no-backup", "--overwrite", "--quiet"],
        timeout,
    )
    if code != 0:
        result["status"] = "restore_failed"
        result["note"] = first_error(err)
        return result
    result["restored_sha256"] = sha256_file(restored)
    result["restored_equals_original"] = result["restored_sha256"] == sha256_file(orig)
    return result


def content_pass(
    bin_path: Path, orig: Path, work: Path, timeout: int, seed: str | None
) -> dict:
    stego = work / f"cstego{orig.suffix}"

    code, out, err = run([str(bin_path), "capacity", str(orig), "--json"], timeout)
    if code != 0:
        return {"status": "failed", "note": first_error(err)}
    cap = load_json_line(out)
    result: dict = {"status": "ok"}
    if cap:
        result["capacity_max_bytes"] = cap.get("max_raw_payload_bytes")
        result["capacity_recommended_bytes"] = cap.get("recommended_max_bytes")
        result["capacity_total_elements"] = cap.get("total_elements")
        max_bytes = cap.get("max_raw_payload_bytes") or 0
        if max_bytes < len(PAYLOAD_CONTENT):
            result["status"] = "insufficient_capacity"
            return result

    embed_cmd = [str(bin_path), "embed", str(orig), "-t", PAYLOAD_CONTENT,
                 "-o", str(stego), "--no-backup", "--quiet"]
    if seed:
        embed_cmd += ["--seed", seed]
    code, out, err = run(embed_cmd, timeout)
    if code != 0:
        return {"status": "embed_failed", "note": first_error(err), **result}
    result["stego_size"] = stego.stat().st_size
    if seed:
        result["stego_sha256"] = sha256_file(stego)

    code, out, err = run(
        [str(bin_path), "extract", str(stego), "--stdout", "--quiet"], timeout
    )
    if code != 0:
        result["status"] = "extract_failed"
        result["note"] = first_error(err)
        return result
    got = out.strip()
    result["payload_matches"] = got == PAYLOAD_CONTENT
    result["payload_sha256"] = hashlib.sha256(got.encode()).hexdigest()
    return result


def build_report(bin_path: Path, args) -> dict:
    cases = collect_cases(args.only)
    if args.limit:
        cases = cases[: args.limit]
    work_root = args.out / "work"
    if not args.keep_work and work_root.exists():
        shutil.rmtree(work_root, ignore_errors=True)
    work_root.mkdir(parents=True, exist_ok=True)

    report = {
        "schema": 2,
        "payload_structure": PAYLOAD_STRUCTURE,
        "payload_content": PAYLOAD_CONTENT,
        "seed": args.seed or None,
        "include_content_hevc": bool(args.include_content_hevc),
        "cases": [],
    }
    total = len(cases)
    for idx, (corpus, path) in enumerate(cases, 1):
        cid = case_id(corpus, path)
        work = work_root / cid
        work.mkdir(parents=True, exist_ok=True)
        orig = work / f"orig{path.suffix}"
        shutil.copyfile(path, orig)

        entry: dict = {
            "id": cid,
            "corpus": corpus,
            "file": path.relative_to(REPO).as_posix(),
            "ext": path.suffix.lower().lstrip("."),
            "orig_size": orig.stat().st_size,
            "orig_sha256": sha256_file(orig),
        }

        started = time.time()
        entry["structure"] = structure_pass(bin_path, orig, work, args.timeout)
        entry["structure"]["elapsed_ms"] = int((time.time() - started) * 1000)

        ext = entry["ext"]
        content_exts = set(CONTENT_EXTS_DEFAULT)
        if args.include_content_hevc:
            content_exts |= CONTENT_EXTS_HEVC
        if ext in content_exts and entry["orig_size"] <= args.content_max_mb * 1024 * 1024:
            started = time.time()
            entry["content"] = content_pass(bin_path, orig, work, args.timeout, args.seed)
            entry["content"]["elapsed_ms"] = int((time.time() - started) * 1000)

        report["cases"].append(entry)
        flag = entry["structure"]["status"]
        extra = entry.get("content", {}).get("status", "-")
        print(f"[{idx}/{total}] {cid}: structure={flag} content={extra}", flush=True)

    if not args.keep_work:
        shutil.rmtree(work_root, ignore_errors=True)
    return report


# Volatile or informational keys that must not fail a `--check`.
IGNORED_KEYS = {"elapsed_ms", "note", "unsupported"}
# Without a seed the content-domain salt is random, so its compressed length and
# its bytes legitimately differ between runs (measured 6702 vs 6664 bytes on the
# same JPEG). `check` drops these two keys only when the baseline itself was
# recorded with `--no-seed`; a seeded baseline compares them strictly.
UNSEEDED_VOLATILE = {"content.stego_size", "content.stego_sha256"}


def flatten(obj: dict, ignored_paths: set[str], prefix: str = "") -> dict:
    flat = {}
    for key, value in obj.items():
        path = f"{prefix}{key}"
        if key in IGNORED_KEYS or path in ignored_paths:
            continue
        if isinstance(value, dict):
            flat.update(flatten(value, ignored_paths, f"{path}."))
        else:
            flat[path] = value
    return flat


def check(report: dict, baseline: dict) -> int:
    if baseline.get("seed") != report.get("seed"):
        print(
            f"error: seed mismatch (baseline {baseline.get('seed')!r} vs current "
            f"{report.get('seed')!r}); the content hashes are not comparable, "
            "re-freeze with --write or pass the baseline's seed"
        )
        return 2

    ignored_paths = set() if baseline.get("seed") else set(UNSEEDED_VOLATILE)
    old = {c["id"]: flatten(c, ignored_paths) for c in baseline["cases"]}
    new = {c["id"]: flatten(c, ignored_paths) for c in report["cases"]}
    diffs = 0

    for cid in sorted(set(old) - set(new)):
        print(f"MISSING  {cid}")
        diffs += 1
    for cid in sorted(set(new) - set(old)):
        print(f"EXTRA    {cid}")
        diffs += 1
    for cid in sorted(set(old) & set(new)):
        keys = sorted(set(old[cid]) | set(new[cid]))
        for key in keys:
            if old[cid].get(key) != new[cid].get(key):
                print(f"DIFF     {cid} :: {key}: {old[cid].get(key)!r} -> {new[cid].get(key)!r}")
                diffs += 1

    if diffs:
        print(f"\ncheck FAILED: {diffs} difference(s) vs {baseline.get('generated_at', 'baseline')}")
        return 1
    print(f"\ncheck OK: {len(new)} cases identical to baseline")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="freeze the current behaviour into baseline.json")
    ap.add_argument("--check", action="store_true", help="recompute and diff against baseline.json")
    ap.add_argument("--bin", default=None, help="path to the strhide binary")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="baseline directory (default: temp/baseline)")
    ap.add_argument("--only", default=None, help="only corpora whose name contains this substring")
    ap.add_argument("--limit", type=int, default=0, help="only the first N cases (smoke test)")
    ap.add_argument("--include-content-hevc", action="store_true",
                    help="also run content-domain roundtrips on HEVC/HEIF/MP4 (slow, ~12 GB RSS)")
    ap.add_argument("--content-max-mb", type=int, default=64,
                    help="skip content roundtrips on files larger than this (MB)")
    ap.add_argument("--seed", default=SEED_HEX,
                    help="content-domain embed seed (64 hex digits); makes stego bytes comparable")
    ap.add_argument("--no-seed", action="store_true",
                    help="do not seed embeds; content size/bytes are then not compared")
    ap.add_argument("--timeout", type=int, default=900, help="per-command timeout in seconds")
    ap.add_argument("--keep-work", action="store_true", help="keep the per-case work directories")
    args = ap.parse_args()

    if not args.write and not args.check:
        ap.print_help()
        return 2

    if args.no_seed:
        args.seed = ""
    args.out = Path(args.out)
    args.out.mkdir(parents=True, exist_ok=True)
    bin_path = find_bin(args.bin)
    print(f"binary: {bin_path}")
    src_mtime = newest_source_mtime()
    if bin_path.stat().st_mtime < src_mtime:
        print("warning: binary is older than rust/src — rebuild before freezing a baseline")

    baseline = None
    if args.check:
        target = args.out / "baseline.json"
        if not target.exists():
            print(f"error: {target} not found; run --write first")
            return 2
        baseline = json.loads(target.read_text(encoding="utf-8"))
        # Fail before spending a minute on the corpus: content hashes recorded
        # under a different seed are not comparable at all.
        if baseline.get("seed") != (args.seed or None):
            print(
                f"error: seed mismatch (baseline {baseline.get('seed')!r} vs current "
                f"{args.seed!r}); re-freeze with --write or pass the baseline's seed"
            )
            return 2

    report = build_report(bin_path, args)

    if args.write:
        report["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        try:
            report["binary"] = bin_path.relative_to(REPO).as_posix()
        except ValueError:
            report["binary"] = str(bin_path)
        target = args.out / "baseline.json"
        target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nwrote {target} ({len(report['cases'])} cases)")
        return 0

    return check(report, baseline)


if __name__ == "__main__":
    sys.exit(main())
