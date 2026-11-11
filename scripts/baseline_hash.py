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

Schema 4 (Compact Git-friendly Baseline)
---------------------------------------
Schema 4 stores a clean, deterministic contract of assertions in `scripts/baseline.json`:
  * Carrier filename, original size, and 16-hex short SHA-256
  * Structure domain: chosen strategy, stego size, and UBE size (when applicable)
  * Content domain: max and recommended capacity, and per-algorithm stego size + 16-hex short hash
All machine-specific metadata (binary paths, compilation timestamps, elapsed time)
and redundant fields are omitted so the file stays small (~10 KB) and produces
clean, conflict-free git diffs.

Usage
-----
    # check against the committed compact baseline (default)
    python scripts/baseline_hash.py --check

    # freeze/update the compact baseline (writes to scripts/baseline.json)
    python scripts/baseline_hash.py --write

    # smoke test on the first few cases
    python scripts/baseline_hash.py --check --limit 3
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
DEFAULT_BASELINE = REPO / "scripts" / "baseline.json"
LEGACY_BASELINE = REPO / "temp" / "baseline" / "baseline.json"
DEFAULT_WORK_DIR = REPO / "temp" / "baseline" / "work"

PAYLOAD_STRUCTURE = "strhide-baseline-structure"
PAYLOAD_STRUCTURE_SHA256 = hashlib.sha256(PAYLOAD_STRUCTURE.encode("utf-8")).hexdigest()
PAYLOAD_CONTENT = "sb1"
PAYLOAD_CONTENT_SHA256 = hashlib.sha256(PAYLOAD_CONTENT.encode("utf-8")).hexdigest()

SEED_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

STRUCTURE_EXTS = {
    "png", "jpg", "jpeg", "webp", "wav", "heic", "heif", "avif",
    "mp4", "mov", "m4v", "mkv", "webm", "zip", "jar", "pdf", "exe", "dll",
}

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


def get_git_commit() -> str:
    code, out, _ = run(["git", "rev-parse", "--short", "HEAD"], timeout=5)
    if code == 0 and out.strip():
        return out.strip()
    return "unknown"


def extract_version_hash(version_str: str) -> str | None:
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


def load_json_block(stdout: str) -> dict | None:
    text = stdout.strip()
    start = text.find("{")
    if start < 0:
        return None
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        return None


def strategy_name(value) -> str | None:
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
    result["payload_matches"] = (result["payload_sha256"] == PAYLOAD_STRUCTURE_SHA256)

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

    cap = load_json_block(out)
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
    work_root = Path(args.work_dir)
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


def to_compact_schema4(report: dict, generated_at: str | None = None, git_commit: str | None = None) -> dict:
    """Convert full raw report into concise, Git-friendly Schema 4 dictionary."""
    compact = {
        "schema": 4,
        "generated_at": generated_at or report.get("generated_at"),
        "git_commit": git_commit or report.get("git_commit"),
        "seed": report.get("seed"),
        "cases": {},
    }
    for c in report["cases"]:
        fname = Path(c["file"]).name
        entry: dict = {
            "orig_size": c["orig_size"],
            "orig_sha256": c["orig_sha256"][:16],
        }
        st = c.get("structure", {})
        if st.get("status") == "ok":
            st_entry = {
                "strategy": st.get("strategy"),
                "stego_size": st.get("stego_size"),
            }
            if st.get("ube_total_size") is not None:
                st_entry["ube_size"] = st.get("ube_total_size")
            entry["struct"] = st_entry

        ct = c.get("content", {})
        if ct.get("status") == "ok":
            ct_entry = {
                "cap_max": ct.get("capacity_max_bytes"),
                "cap_rec": ct.get("capacity_recommended_bytes"),
            }
            algos = {}
            for aname, ares in sorted(ct.get("algorithms", {}).items()):
                if ares.get("status") == "ok":
                    algo_item: dict = {"size": ares.get("stego_size")}
                    if ares.get("stego_sha256"):
                        algo_item["hash"] = ares.get("stego_sha256")[:16]
                    algos[aname] = algo_item
            if algos:
                ct_entry["algos"] = algos
            entry["content"] = ct_entry

        compact["cases"][fname] = entry
    return compact


# Volatile or informational keys that must not fail a Schema-3 `--check`.
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


def check_schema3(report: dict, baseline: dict) -> int:
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


def check_schema4(report: dict, baseline: dict, is_filtered: bool = False) -> int:
    """Validate report against compact Schema 4 baseline."""
    if baseline.get("seed") != report.get("seed"):
        print(
            f"error: seed mismatch (baseline {baseline.get('seed')!r} vs current "
            f"{report.get('seed')!r}); the content hashes are not comparable"
        )
        return 2

    current = to_compact_schema4(report)
    base_cases = baseline.get("cases", {})
    curr_cases = current.get("cases", {})

    diffs = 0
    raw_by_fname = {Path(c["file"]).name: c for c in report.get("cases", [])}

    if not is_filtered:
        for fname in sorted(set(base_cases) - set(curr_cases)):
            print(f"MISSING  {fname}")
            diffs += 1
    for fname in sorted(set(curr_cases) - set(base_cases)):
        print(f"EXTRA    {fname}")
        diffs += 1

    for fname in sorted(set(base_cases) & set(curr_cases)):
        b_case = base_cases[fname]
        c_case = curr_cases[fname]
        raw_case = raw_by_fname.get(fname, {})

        # Carrier original properties
        if b_case.get("orig_size") != c_case.get("orig_size"):
            print(f"DIFF     {fname} :: orig_size: {b_case.get('orig_size')} -> {c_case.get('orig_size')}")
            diffs += 1
        if b_case.get("orig_sha256") != c_case.get("orig_sha256"):
            print(f"DIFF     {fname} :: orig_sha256: {b_case.get('orig_sha256')} -> {c_case.get('orig_sha256')}")
            diffs += 1

        # Structure domain assertions
        b_struct = b_case.get("struct")
        c_struct = c_case.get("struct")
        raw_st = raw_case.get("structure", {})

        if b_struct is not None:
            if c_struct is None:
                print(f"DIFF     {fname} :: struct status: expected ok, got {raw_st.get('status')}")
                diffs += 1
            else:
                if not raw_st.get("restored_equals_original", False):
                    print(f"FAIL     {fname} :: structure restoration mismatch (restored != original)")
                    diffs += 1
                if not raw_st.get("payload_matches", True):
                    print(f"FAIL     {fname} :: structure payload extraction mismatch")
                    diffs += 1
                if b_struct.get("strategy") != c_struct.get("strategy"):
                    print(f"DIFF     {fname} :: struct.strategy: {b_struct.get('strategy')} -> {c_struct.get('strategy')}")
                    diffs += 1
                if b_struct.get("stego_size") != c_struct.get("stego_size"):
                    print(f"DIFF     {fname} :: struct.stego_size: {b_struct.get('stego_size')} -> {c_struct.get('stego_size')}")
                    diffs += 1
                if b_struct.get("ube_size") != c_struct.get("ube_size"):
                    print(f"DIFF     {fname} :: struct.ube_size: {b_struct.get('ube_size')} -> {c_struct.get('ube_size')}")
                    diffs += 1
        elif c_struct is not None:
            print(f"DIFF     {fname} :: struct: unexpected structure domain result")
            diffs += 1

        # Content domain assertions
        b_content = b_case.get("content")
        c_content = c_case.get("content")
        raw_ct = raw_case.get("content", {})

        if b_content is not None:
            if c_content is None:
                print(f"DIFF     {fname} :: content status: expected ok, got {raw_ct.get('status')}")
                diffs += 1
            else:
                if b_content.get("cap_max") != c_content.get("cap_max"):
                    print(f"DIFF     {fname} :: content.cap_max: {b_content.get('cap_max')} -> {c_content.get('cap_max')}")
                    diffs += 1
                if b_content.get("cap_rec") != c_content.get("cap_rec"):
                    print(f"DIFF     {fname} :: content.cap_rec: {b_content.get('cap_rec')} -> {c_content.get('cap_rec')}")
                    diffs += 1

                b_algos = b_content.get("algos", {})
                c_algos = c_content.get("algos", {})
                raw_algos = raw_ct.get("algorithms", {})

                for aname in sorted(set(b_algos) | set(c_algos)):
                    if aname not in c_algos:
                        print(f"DIFF     {fname} :: missing content algo {aname}")
                        diffs += 1
                        continue
                    if aname not in b_algos:
                        print(f"DIFF     {fname} :: extra content algo {aname}")
                        diffs += 1
                        continue

                    ba = b_algos[aname]
                    ca = c_algos[aname]
                    raw_a = raw_algos.get(aname, {})
                    if not raw_a.get("payload_matches", True):
                        print(f"FAIL     {fname} :: content.{aname} payload extraction mismatch")
                        diffs += 1
                    if ba.get("size") != ca.get("size"):
                        print(f"DIFF     {fname} :: content.{aname}.size: {ba.get('size')} -> {ca.get('size')}")
                        diffs += 1
                    if ba.get("hash") != ca.get("hash"):
                        print(f"DIFF     {fname} :: content.{aname}.hash: {ba.get('hash')} -> {ca.get('hash')}")
                        diffs += 1
        elif c_content is not None:
            print(f"DIFF     {fname} :: content: unexpected content domain result")
            diffs += 1

    if diffs:
        print(f"\ncheck FAILED: {diffs} difference(s) vs baseline")
        return 1
    print(f"\ncheck OK: {len(curr_cases)} cases identical to baseline")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true",
                    help="freeze the current behaviour into baseline (compact by default)")
    ap.add_argument("--check", action="store_true", help="recompute and diff against baseline.json")
    ap.add_argument("--bin", default=None, help="path to the strhide binary")
    ap.add_argument("--baseline", "-f", default=None,
                    help="path to baseline.json (default: scripts/baseline.json)")
    ap.add_argument("--out", default=None,
                    help="legacy: baseline output directory (default: temp/baseline)")
    ap.add_argument("--legacy", action="store_true",
                    help="use legacy verbose Schema 3 format and copy binary to temp/baseline")
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
    ap.add_argument("--work-dir", default=str(DEFAULT_WORK_DIR), help="temp directory for carrier operations")
    ap.add_argument("--keep-work", action="store_true", help="keep the per-case work directories")
    args = ap.parse_args()

    if not args.write and not args.check:
        ap.print_help()
        return 2

    if args.write and (args.only or args.limit):
        ap.error(
            "--write cannot be combined with --only/--limit: it would replace "
            "the full baseline with a filtered subset"
        )

    if args.no_seed:
        args.seed = ""

    # Determine baseline path
    if args.baseline:
        baseline_path = Path(args.baseline)
    elif args.out:
        baseline_path = Path(args.out) / "baseline.json"
    else:
        # Default target
        if args.legacy:
            baseline_path = LEGACY_BASELINE
        else:
            baseline_path = DEFAULT_BASELINE

    bin_path = find_bin(args.bin)
    bin_sha256 = sha256_file(bin_path)
    bin_version = get_binary_version(bin_path)
    version_hash = extract_version_hash(bin_version)

    print(f"binary:   {bin_path}")
    print(f"version:  {bin_version}")
    print(f"sha256:   {bin_sha256}")
    print(f"baseline: {baseline_path}")

    src_mtime = newest_source_mtime()
    if bin_path.stat().st_mtime < src_mtime:
        print("warning: binary is older than rust/src — rebuild before freezing a baseline")

    baseline = None
    if args.check:
        target = baseline_path
        if not target.exists() and not args.baseline and not args.out:
            # Fallback to legacy if default not found
            if LEGACY_BASELINE.exists():
                print(f"note: {target} not found; falling back to legacy {LEGACY_BASELINE}")
                target = LEGACY_BASELINE

        if not target.exists():
            print(f"error: baseline not found at {target}; run --write first")
            return 2
        baseline = json.loads(target.read_text(encoding="utf-8"))

        if baseline.get("generated_at"):
            print(f"baseline time:    {baseline.get('generated_at')}")
        if baseline.get("git_commit"):
            print(f"baseline commit:  {baseline.get('git_commit')}")

        # Fail early on seed mismatch
        if baseline.get("seed") != (args.seed or None):
            print(
                f"error: seed mismatch (baseline {baseline.get('seed')!r} vs current "
                f"{args.seed!r}); re-freeze with --write or pass the baseline's seed"
            )
            return 2

    report = build_report(bin_path, args)

    if args.write:
        if args.legacy or baseline_path.parent == DEFAULT_OUT_DIR:
            # Legacy Schema 3 writer
            out_dir = baseline_path.parent
            out_dir.mkdir(parents=True, exist_ok=True)
            report["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            try:
                rel_path = bin_path.relative_to(REPO).as_posix()
            except ValueError:
                rel_path = str(bin_path)

            hash_tag = version_hash or bin_sha256[:8]
            ext = bin_path.suffix if bin_path.suffix else (".exe" if os.name == "nt" else "")
            copy_name = f"strhide-{hash_tag}{ext}"
            copy_dest = out_dir / copy_name
            if bin_path.resolve() != copy_dest.resolve():
                shutil.copy2(bin_path, copy_dest)
                print(f"copied binary to {copy_dest}")
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
            baseline_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"\nwrote legacy baseline to {baseline_path} ({len(report['cases'])} cases)")
            return 0
        else:
            # Compact Schema 4 writer
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            gen_time = time.strftime("%Y-%m-%dT%H:%M:%S")
            commit = version_hash or get_git_commit()
            compact = to_compact_schema4(report, generated_at=gen_time, git_commit=commit)
            content = json.dumps(compact, indent=2, sort_keys=True) + "\n"
            baseline_path.write_bytes(content.encode("utf-8"))
            print(f"\nwrote compact baseline to {baseline_path} ({len(compact['cases'])} cases, {len(content)} bytes)")
            return 0

    schema_ver = baseline.get("schema", 3) if isinstance(baseline, dict) else 3
    if schema_ver >= 4:
        return check_schema4(report, baseline, is_filtered=bool(args.only or args.limit))
    return check_schema3(report, baseline)


if __name__ == "__main__":
    sys.exit(main())
