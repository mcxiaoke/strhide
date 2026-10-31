#!/usr/bin/env python3
"""Real-executable algorithm matrix for `strhide` PNG/JPEG carriers.

Runs `strhide embed` / `strhide extract` for every image in the configured
directories against every cost model supported for that container, and checks
that the extracted payload is byte-identical to what was embedded.

This exercises the shipping executable end to end (argument parsing, engine
selection, carrier self-description, extraction) rather than the library API.

Examples
--------
    # everything, both default corpora, 2 parallel jobs
    python scripts/stego_algorithm_matrix.py

    # only the newly added models
    python scripts/stego_algorithm_matrix.py --only mipod,jmipod

    # one corpus, keep the stego files for inspection
    python scripts/stego_algorithm_matrix.py --dirs temp/testhighres --keep

Exit code is non-zero when any carrier/algorithms pair fails. Carriers that the
tool deliberately rejects (APNG, indexed PNG, progressive JPEG, interlaced PNG)
are reported as SKIP, not as failures.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

PNG_ALGORITHMS = ["hill", "suniward", "mipod"]
JPEG_ALGORITHMS = ["uerd", "juniward", "jmipod"]
PASSWORD = "AlgorithmMatrix#2026"
DEFAULT_DIRS = ["temp/teststego", "temp/testhighres"]
DEFAULT_JOBS = 2
DEFAULT_TIMEOUT = 900

# Error text the CLI prints for carriers the content engine intentionally refuses.
REJECTION_HINTS = (
    "unsupported",
    "not supported",
    "animated",
    "apng",
    "indexed",
    "palette",
    "colour type 3",
    "progressive",
    "interlaced",
    "adam7",
    "不支持的文件格式",
    "exceed",
    "too large",
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def image_algorithms(path: Path) -> list[str]:
    ext = path.suffix.lower()
    if ext == ".png":
        return PNG_ALGORITHMS
    if ext in (".jpg", ".jpeg"):
        return JPEG_ALGORITHMS
    return []


def collect_images(dirs: list[Path]) -> list[Path]:
    images: list[Path] = []
    for directory in dirs:
        if not directory.is_dir():
            print(f"[WARN] not a directory: {directory}", file=sys.stderr)
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_file() and image_algorithms(path):
                images.append(path)
    return images


def run(cmd: list[str], timeout: int) -> tuple[int, str, str, float]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr, time.monotonic() - started
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s", time.monotonic() - started


def payload_for(path: Path, algorithm: str) -> str:
    """Unique ASCII payload so a cross-file mix-up cannot pass by accident."""
    digest = hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:10]
    return f"matrix-{algorithm}-{digest}"


def run_one(
    exe: Path,
    source: Path,
    algorithm: str,
    out_dir: Path,
    timeout: int,
    keep: bool,
) -> dict:
    payload = payload_for(source, algorithm)
    output = out_dir / f"{source.stem}.{algorithm}{source.suffix.lower()}"
    embed_cmd = [
        str(exe),
        "embed",
        str(source),
        "-t",
        payload,
        "-a",
        algorithm,
        "-p",
        PASSWORD,
        "-o",
        str(output),
    ]
    rc, stdout, stderr, embed_s = run(embed_cmd, timeout)
    row = {
        "file": source.name,
        "path": str(source),
        "algorithm": algorithm,
        "embed_s": round(embed_s, 2),
        "extract_s": None,
        "status": "FAIL",
        "detail": "",
    }
    if rc != 0:
        message = (stderr or stdout).strip()
        lower = message.lower()
        if any(hint in lower for hint in REJECTION_HINTS):
            row["status"] = "SKIP"
            row["detail"] = message.splitlines()[-1] if message else "unsupported carrier"
        else:
            row["detail"] = f"embed rc={rc}: {message[-400:]}"
        return row

    extract_cmd = [str(exe), "extract", str(output), "-p", PASSWORD]
    rc2, stdout2, stderr2, extract_s = run(extract_cmd, timeout)
    row["extract_s"] = round(extract_s, 2)
    if rc2 != 0:
        row["detail"] = f"extract rc={rc2}: {(stderr2 or stdout2).strip()[-400:]}"
    elif stdout2.strip() != payload:
        row["detail"] = (
            f"payload mismatch: want {payload!r}, got {stdout2.strip()[:120]!r}"
        )
    else:
        row["status"] = "PASS"

    if row["status"] == "PASS" and not keep:
        output.unlink(missing_ok=True)
    return row


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run strhide.exe embed/extract for every algorithm × carrier."
    )
    parser.add_argument(
        "--exe",
        default=str(repo_root() / "rust" / "target" / "release" / "strhide.exe"),
        help="Path to the strhide executable (default: release build).",
    )
    parser.add_argument(
        "--dirs",
        nargs="*",
        default=DEFAULT_DIRS,
        help=f"Corpus directories relative to the repository root (default: {DEFAULT_DIRS}).",
    )
    parser.add_argument(
        "--only",
        default="",
        help="Comma-separated algorithm filter, e.g. mipod,jmipod.",
    )
    parser.add_argument(
        "--out-dir",
        default="temp/stego_algorithm_matrix",
        help="Directory for temporary stego files and the JSON report.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=DEFAULT_JOBS,
        help=f"Parallel exe invocations (default: {DEFAULT_JOBS}).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Per embed/extract timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument("--keep", action="store_true", help="Keep stego carriers.")
    parser.add_argument(
        "--limit", type=int, default=0, help="Only the first N images (0 = all)."
    )
    parser.add_argument(
        "--match",
        default="",
        help="Only carriers whose name contains this substring.",
    )
    args = parser.parse_args()

    exe = Path(args.exe)
    if not exe.is_file():
        print(
            f"[ERROR] executable not found: {exe}\n"
            "        build it with: cargo build --release --all-features (in rust/)",
            file=sys.stderr,
        )
        return 2

    root = repo_root()
    dirs = [root / d if not Path(d).is_absolute() else Path(d) for d in args.dirs]
    out_dir = root / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    only = {item.strip().lower() for item in args.only.split(",") if item.strip()}

    images = collect_images(dirs)
    if args.match:
        images = [p for p in images if args.match.lower() in p.name.lower()]
    if args.limit > 0:
        images = images[: args.limit]
    if not images:
        print("[ERROR] no PNG/JPEG carriers found", file=sys.stderr)
        return 2

    tasks = [
        (image, algorithm)
        for image in images
        for algorithm in image_algorithms(image)
        if not only or algorithm in only
    ]
    if not tasks:
        print("[ERROR] no (carrier, algorithm) pairs after filtering", file=sys.stderr)
        return 2

    print(
        f"strhide executable: {exe}\n"
        f"corpora: {', '.join(str(d) for d in dirs)}\n"
        f"images: {len(images)} | pairs: {len(tasks)} | jobs: {args.jobs} | "
        f"timeout: {args.timeout}s",
        flush=True,
    )

    lock = threading.Lock()
    rows: list[dict] = []
    started = time.monotonic()

    def worker(task: tuple[Path, str]) -> dict:
        source, algorithm = task
        row = run_one(exe, source, algorithm, out_dir, args.timeout, args.keep)
        with lock:
            rows.append(row)
            detail = f" ({row['detail']})" if row["detail"] else ""
            print(
                f"[{len(rows):>3}/{len(tasks)}] {row['status']:<4} "
                f"{source.name:<38} {algorithm:<9} "
                f"embed={row['embed_s']}s"
                + (f" extract={row['extract_s']}s" if row["extract_s"] else "")
                + detail,
                flush=True,
            )
        return row

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = [pool.submit(worker, task) for task in tasks]
        for future in concurrent.futures.as_completed(futures):
            future.result()

    rows.sort(key=lambda r: (r["file"], r["algorithm"]))
    passed = [r for r in rows if r["status"] == "PASS"]
    skipped = [r for r in rows if r["status"] == "SKIP"]
    failed = [r for r in rows if r["status"] == "FAIL"]
    elapsed = time.monotonic() - started

    report = {
        "exe": str(exe),
        "dirs": [str(d) for d in dirs],
        "only": sorted(only),
        "elapsed_s": round(elapsed, 2),
        "total": len(rows),
        "passed": len(passed),
        "skipped": len(skipped),
        "failed": len(failed),
        "rows": rows,
    }
    report_path = out_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), "utf-8")

    print("\n" + "=" * 100)
    print(
        f"TOTAL {len(rows)} | PASS {len(passed)} | SKIP {len(skipped)} | "
        f"FAIL {len(failed)} | elapsed {elapsed:.1f}s"
    )
    if skipped:
        print("\nSkipped (intentionally rejected carriers):")
        for row in skipped:
            print(f"  {row['file']} [{row['algorithm']}]: {row['detail']}")
    if failed:
        print("\nFailures:")
        for row in failed:
            print(f"  {row['file']} [{row['algorithm']}]: {row['detail']}")
    slowest = sorted(
        (r for r in rows if r["status"] == "PASS"),
        key=lambda r: (r["embed_s"] or 0) + (r["extract_s"] or 0),
        reverse=True,
    )[:5]
    if slowest:
        print("\nSlowest round trips:")
        for row in slowest:
            print(
                f"  {row['file']} [{row['algorithm']}]: "
                f"embed {row['embed_s']}s + extract {row['extract_s']}s"
            )
    print(f"\nJSON report: {report_path}")
    print("=" * 100)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
