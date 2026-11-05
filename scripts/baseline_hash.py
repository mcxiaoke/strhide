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
import re
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
    "mp4", "mov", "m4v", "mkv", "webm", "zip", "jar", "pdf", "exe", "dll",
}

# Content-domain algorithms matrix:
# PNG: HILL (default), S-UNIWARD, MiPOD
# JPEG: UERD (default), J-UNIWARD, J-MiPOD
# HEVC: CABAC in-place steganography
# Audio: PCM / residual steganography
CONTENT_ALGORITHMS: dict[str, list[str]] = {
    "png": ["hill", "suniward", "mipod"],
    "jpg": ["uerd", "juniward", "jmipod"],
    "jpeg": ["uerd", "juniward", "jmipod"],
    "hevc": ["cabac"],
    "h265": ["cabac"],
    "hevc10": ["cabac"],
    "heic": ["cabac"],
    "heif": ["cabac"],
    "mp4": ["cabac"],
    "mov": ["cabac"],
    "m4v": ["cabac"],
    "mkv": ["cabac"],
    "webm": ["cabac"],
    "wav": ["wav_pcm"],
    "flac": ["flac_residual"],
}

CONTENT_EXTS_HEVC = {"heic", "heif", "mp4", "mov", "m4v", "mkv", "webm", "h265", "hevc", "hevc10"}
CONTENT_EXTS = set(CONTENT_ALGORITHMS.keys())
ALL_EXTS = STRUCTURE_EXTS | CONTENT_EXTS

CORPORA = [
    ("baseline", REPO / "testdata" / "baseline"),
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


def get_binary_version(bin_path: Path) -> str:
    code, out, err = run([str(bin_path), "-V"], timeout=10)
    if code == 0 and out.strip():
        return out.strip()
    code, out, err = run([str(bin_path), "--version"], timeout=10)
    if code == 0 and out.strip():
        return out.strip()
    return "unknown"


def extract_version_hash(version_str: str) -> str | None:
    # Matches commit: <hash>, e.g. "sth 0.9.0 (commit: 4371dab, built: 2026-11-05T11:41:56Z)"
    m = re.search(r"commit:\s*([^\s,\)]+)", version_str)
    if m:
        val = m.group(1).strip()
        if val and val.lower() != "unknown":
            return val
    m = re.search(r"\b([0-9a-fA-F]{7,40})\b", version_str)
    if m:
        return m.group(1)
    return None


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


def strategy_name(value) -> str | None:
    """The strategy's registry name, whatever shape the CLI reports.

    Stage 4 turned `strategy` from a bare string into `{id, name}`; the baseline
    records the *name* either way, so a frozen baseline stays comparable.
    """
    if isinstance(value, dict):
        return value.get("name")
    return value


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
            if ext not in ALL_EXTS:
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
        result["strategy"] = strategy_name(inspect.get("strategy"))
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
    bin_path: Path,
    orig: Path,
    work: Path,
    timeout: int,
    seed: str | None,
    algos: list[str],
) -> dict:
    code, out, err = run([str(bin_path), "capacity", str(orig), "--json"], timeout)
    if code != 0:
        if is_unsupported(err):
            return {"status": "unsupported", "note": first_error(err)}
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

    algorithms: dict[str, dict] = {}
    for algo in algos:
        stego = work / f"cstego_{algo}{orig.suffix}"
        embed_cmd = [
            str(bin_path), "embed", str(orig),
            "-a", algo,
            "-t", PAYLOAD_CONTENT,
            "-o", str(stego),
            "--no-backup", "--quiet",
        ]
        if seed:
            embed_cmd += ["--seed", seed]

        code, out, err = run(embed_cmd, timeout)
        if code != 0:
            algorithms[algo] = {
                "status": "embed_failed",
                "note": first_error(err),
            }
            continue

        algo_res: dict = {
            "status": "ok",
            "stego_size": stego.stat().st_size,
        }
        if seed:
            algo_res["stego_sha256"] = sha256_file(stego)

        code, out, err = run(
            [str(bin_path), "extract", str(stego), "--stdout", "--quiet"],
            timeout,
        )
        if code != 0:
            algo_res["status"] = "extract_failed"
            algo_res["note"] = first_error(err)
            algorithms[algo] = algo_res
            continue

        got = out.strip()
        algo_res["payload_matches"] = (got == PAYLOAD_CONTENT)
        algo_res["payload_sha256"] = hashlib.sha256(got.encode()).hexdigest()
        algorithms[algo] = algo_res

    result["algorithms"] = algorithms

    default_algo = algos[0]
    if default_algo in algorithms and algorithms[default_algo].get("status") == "ok":
        result["stego_size"] = algorithms[default_algo]["stego_size"]
        if seed and "stego_sha256" in algorithms[default_algo]:
            result["stego_sha256"] = algorithms[default_algo]["stego_sha256"]
        result["payload_matches"] = algorithms[default_algo].get("payload_matches", True)
        result["payload_sha256"] = algorithms[default_algo].get("payload_sha256")
    elif any(a.get("status") == "ok" for a in algorithms.values()):
        result["status"] = "ok"
    else:
        result["status"] = "algorithms_failed"

    return result


def build_report(bin_path: Path, args) -> dict:
    cases = collect_cases(args.only)
    if args.limit:
        cases = cases[: args.limit]
    work_root = args.out / "work"
    if not args.keep_work and work_root.exists():
        shutil.rmtree(work_root, ignore_errors=True)
    work_root.mkdir(parents=True, exist_ok=True)

    include_hevc = not args.skip_content_hevc

    report = {
        "schema": 3,
        "payload_structure": PAYLOAD_STRUCTURE,
        "payload_content": PAYLOAD_CONTENT,
        "seed": args.seed or None,
        "include_content_hevc": bool(include_hevc),
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

        ext = entry["ext"]
        if ext in STRUCTURE_EXTS:
            started = time.time()
            entry["structure"] = structure_pass(bin_path, orig, work, args.timeout)
            entry["structure"]["elapsed_ms"] = int((time.time() - started) * 1000)
        else:
            entry["structure"] = {"status": "skipped", "reason": "format_has_no_structure_domain"}

        algos = CONTENT_ALGORITHMS.get(ext)
        is_hevc = ext in CONTENT_EXTS_HEVC
        skip_hevc = is_hevc and not include_hevc

        if algos and not skip_hevc and entry["orig_size"] <= args.content_max_mb * 1024 * 1024:
            started = time.time()
            entry["content"] = content_pass(bin_path, orig, work, args.timeout, args.seed, algos)
            entry["content"]["elapsed_ms"] = int((time.time() - started) * 1000)

        report["cases"].append(entry)
        flag = entry["structure"]["status"]
        extra = entry.get("content", {}).get("status", "-")
        algos_info = ""
        if "algorithms" in entry.get("content", {}):
            ok_cnt = sum(1 for a in entry["content"]["algorithms"].values() if a.get("status") == "ok")
            tot_cnt = len(entry["content"]["algorithms"])
            algos_info = f" ({ok_cnt}/{tot_cnt} algos)"
        print(f"[{idx}/{total}] {cid}: structure={flag} content={extra}{algos_info}", flush=True)

    if not args.keep_work:
        shutil.rmtree(work_root, ignore_errors=True)
    return report


# Volatile or informational keys that must not fail a `--check`.
IGNORED_KEYS = {"elapsed_ms", "note", "unsupported", "reason"}


def is_unseeded_volatile(path: str) -> bool:
    return path.endswith(".stego_size") or path.endswith(".stego_sha256") or path in {"stego_size", "stego_sha256"}


def flatten(obj: dict, is_seeded: bool, prefix: str = "") -> dict:
    flat = {}
    for key, value in obj.items():
        path = f"{prefix}{key}"
        if key in IGNORED_KEYS:
            continue
        if not is_seeded and is_unseeded_volatile(path):
            continue
        if isinstance(value, dict):
            flat.update(flatten(value, is_seeded, f"{path}."))
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

    is_seeded = bool(baseline.get("seed"))
    old = {c["id"]: flatten(c, is_seeded) for c in baseline["cases"]}
    new = {c["id"]: flatten(c, is_seeded) for c in report["cases"]}
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
    ap.add_argument("--write", action="store_true",
                    help="freeze the current behaviour into baseline.json (full corpus only)")
    ap.add_argument("--check", action="store_true", help="recompute and diff against baseline.json")
    ap.add_argument("--bin", default=None, help="path to the strhide binary")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="baseline directory (default: temp/baseline)")
    ap.add_argument("--only", default=None, help="only corpora whose name contains this substring")
    ap.add_argument("--limit", type=int, default=0, help="only the first N cases (smoke test)")
    ap.add_argument("--skip-content-hevc", action="store_true",
                    help="skip content-domain roundtrips on HEVC/HEIF/MP4")
    ap.add_argument("--include-content-hevc", action="store_true", default=True,
                    help="(default on) include HEVC/HEIF/MP4 content roundtrips")
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

    # A filtered run only knows a subset of the corpus; freezing it would
    # replace the full baseline and make every other case look "missing".
    if args.write and (args.only or args.limit):
        ap.error(
            "--write cannot be combined with --only/--limit: it would replace "
            "the full baseline with a filtered subset"
        )

    if args.no_seed:
        args.seed = ""
    args.out = Path(args.out)
    args.out.mkdir(parents=True, exist_ok=True)
    bin_path = find_bin(args.bin)
    bin_sha256 = sha256_file(bin_path)
    bin_version = get_binary_version(bin_path)
    version_hash = extract_version_hash(bin_version)

    print(f"binary:  {bin_path}")
    print(f"version: {bin_version}")
    print(f"sha256:  {bin_sha256}")

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
        base_bin = baseline.get("binary")
        base_path = baseline.get("binary_path") or (base_bin.get("path") if isinstance(base_bin, dict) else base_bin)
        base_sha = baseline.get("binary_sha256") or (base_bin.get("sha256") if isinstance(base_bin, dict) else None)
        base_ver = baseline.get("binary_version") or (base_bin.get("version") if isinstance(base_bin, dict) else None)
        base_copy = baseline.get("binary_copy") or (base_bin.get("copy") if isinstance(base_bin, dict) else None)
        if base_ver:
            print(f"baseline version: {base_ver}")
        if base_sha:
            print(f"baseline sha256:  {base_sha}")
        if base_copy:
            copy_path = args.out / base_copy
            exists_tag = "present" if copy_path.exists() else "not found"
            print(f"baseline copy:    {base_copy} ({exists_tag})")
        if base_sha and base_sha != bin_sha256:
            print("note: current binary differs from baseline binary (expected when testing refactors)")

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
            rel_path = bin_path.relative_to(REPO).as_posix()
        except ValueError:
            rel_path = str(bin_path)

        hash_tag = version_hash or bin_sha256[:8]
        ext = bin_path.suffix if bin_path.suffix else (".exe" if os.name == "nt" else "")
        copy_name = f"strhide-{hash_tag}{ext}"
        copy_dest = args.out / copy_name
        if bin_path.resolve() != copy_dest.resolve():
            shutil.copy2(bin_path, copy_dest)
            print(f"copied binary to {copy_dest}")
        else:
            print(f"binary already at {copy_dest}")

        report["binary_path"] = rel_path
        report["binary_sha256"] = bin_sha256
        report["binary_version"] = bin_version
        report["binary_copy"] = copy_name
        report["binary"] = {
            "copy": copy_name,
            "hash": hash_tag,
            "path": rel_path,
            "sha256": bin_sha256,
            "version": bin_version,
        }
        target = args.out / "baseline.json"
        target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nwrote {target} ({len(report['cases'])} cases)")
        return 0

    return check(report, baseline)


if __name__ == "__main__":
    sys.exit(main())
