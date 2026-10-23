#!/usr/bin/env python3
"""Blind-detection calibration harness for the spatial (PNG) channel.

Two jobs, both driven by the real `strhide` binary so the numbers describe what
ships:

  gen     build a labelled set: covers + stego variants at chosen payload sizes
  scan    run `strhide scan --json` over a set and dump per-detector numerics
  report  per-detector distributions, threshold candidates and a confusion
          matrix for `cover` vs `stego`

The detector values live in `detectors[].metric` as formatted strings
("rate: 0.052"), so they are parsed back to floats with a strict pattern; the
3-decimal resolution is enough because the thresholds are chosen at 0.01
granularity.

Examples
--------
    python scripts/png_blind_calib.py gen \
        --bin rust/target/release/strhide.exe \
        --covers temp/images/png --limit 40 \
        --payloads 64,4096,full --out temp/calib/set1

    python scripts/png_blind_calib.py scan --bin ... --set temp/calib/set1 \
        --out temp/calib/set1.json

    python scripts/png_blind_calib.py report --input temp/calib/set1.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

METRIC_RE = re.compile(r":\s*(-?\d+(?:\.\d+)?)")
CAPACITY_RE = re.compile(r"(?:Max raw payload|最大原始载荷)[^0-9]{0,4}(\d+)")


def iter_images(root: Path):
    if root.is_file():
        if root.suffix.lower() in (".png", ".jpg", ".jpeg"):
            yield root
        return
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() in (".png", ".jpg", ".jpeg"):
            yield p


def collect(paths):
    seen, out = set(), []
    for raw in paths:
        for p in iter_images(Path(raw)):
            key = os.path.normpath(str(p))
            if key not in seen:
                seen.add(key)
                out.append(p)
    return out


def noise(n: int) -> bytes:
    """Deterministic incompressible bytes (xorshift32)."""
    state = 0x1234_5678
    out = bytearray()
    for _ in range(n):
        state ^= (state << 13) & 0xFFFF_FFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFF_FFFF
        out.append(state & 0xFF)
    return bytes(out)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


# ---------------------------------------------------------------------------
# gen: covers + stego variants
# ---------------------------------------------------------------------------

def cmd_gen(a):
    if a.covers_list:
        covers = [Path(line.strip()) for line in Path(a.covers_list).read_text(encoding="utf-8").splitlines() if line.strip()]
        covers = [p for p in covers if p.is_file() and p.suffix.lower() == ".png"]
    else:
        covers = [p for p in iter_images(Path(a.covers)) if p.suffix.lower() == ".png"]
    if a.limit:
        covers = covers[: a.limit]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    specs = []
    for token in a.payloads.split(","):
        token = token.strip()
        if token:
            specs.append((token, None if token == "full" else int(token)))

    # A deterministic incompressible payload pool: the envelope deflates what it
    # is given, so a repeated byte pattern would silently shrink to nothing and
    # stop exercising capacity.
    blob_dir = out / "payloads"
    blob_dir.mkdir(exist_ok=True)
    biggest = max((n for _, n in specs if n), default=64)
    blob = bytearray(noise(biggest))
    payload_files = {}
    for label, size in specs:
        if size is None:
            continue  # "full" is sized per carrier, below
        n = size
        p = blob_dir / f"noise_{n}.bin"
        if not p.exists():
            p.write_bytes(bytes(blob[:n]) * (1 + n // len(blob)))
        payload_files[label] = p

    def capacity_of(cover: Path):
        r = run([a.bin, "embed", str(cover), "--capacity", "-p", a.password])
        m = CAPACITY_RE.search(r.stdout or "")
        return int(m.group(1)) if m else None

    manifest = []
    for src in covers:
        for label, size in specs:
            stego_dir = out / f"stego_{label}"
            stego_dir.mkdir(exist_ok=True)
            target = stego_dir / src.name
            if size is None:
                cap = capacity_of(src)
                if not cap:
                    print(f"[skip] {src.name}: capacity probe failed")
                    manifest.append({"cover": str(src), "stego": None, "payload": label, "ok": False,
                                     "error": "capacity probe failed"})
                    continue
                payload_path = blob_dir / "full" / f"{src.stem}.bin"
                payload_path.parent.mkdir(exist_ok=True)
                if not payload_path.exists():
                    payload_path.write_bytes(noise(cap))
            else:
                payload_path = payload_files[label]
            cmd = [
                a.bin, "embed", str(src),
                "-d", str(payload_path),
                "-o", str(target), "--overwrite",
                "-p", a.password,
            ]
            r = run(cmd)
            ok = r.returncode == 0 and target.exists()
            manifest.append(
                {
                    "cover": str(src),
                    "stego": str(target) if ok else None,
                    "payload": label,
                    "ok": ok,
                    "error": "" if ok else (r.stderr or r.stdout).strip().splitlines()[-1:],
                    "size_before": src.stat().st_size,
                    "size_after": target.stat().st_size if ok else None,
                }
            )
            if not ok:
                print(f"[skip] {src.name} payload={label}: {(r.stderr or r.stdout).strip()[:140]}")

    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    ok = sum(1 for m in manifest if m["ok"])
    print(f"generated {ok}/{len(manifest)} stego files from {len(covers)} covers -> {out}")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

def scan_batch(binary: str, files, chunk: int = 64):
    """Scan files in chunks; returns {path: report}."""
    out = {}
    files = [str(f) for f in files]
    for i in range(0, len(files), chunk):
        part = files[i : i + chunk]
        r = run([binary, "scan", *part, "--json"])
        if r.returncode not in (0, 1) or not r.stdout.strip():
            print(f"scan failed for chunk {i}: {r.stderr[-300:]}", file=sys.stderr)
            continue
        for rep in json.loads(r.stdout):
            # The report carries the carrier path under "carrier" (older builds
            # called it "file"); accept both so the harness survives the rename.
            key = rep.get("carrier") or rep.get("file")
            out[key] = rep
    return out


def cmd_scan(a):
    root = Path(a.set[0]) if a.set else Path(".").resolve()
    manifest_path = root / "manifest.json"
    labels = {}
    if manifest_path.exists():
        for m in json.loads(manifest_path.read_text(encoding="utf-8")):
            if not m["ok"]:
                continue
            labels[os.path.normpath(m["cover"])] = ("cover", "-")
            labels[os.path.normpath(m["stego"])] = ("stego", m["payload"])
        files = [Path(p) for p in labels]
    else:
        paths = list(a.set or [])
        for lst in a.file_list or []:
            paths.extend(
                line.strip() for line in Path(lst).read_text(encoding="utf-8").splitlines() if line.strip()
            )
        files = collect(paths)
        for p in files:
            labels[os.path.normpath(str(p))] = ("cover", "-")

    reports = scan_batch(a.bin, files)
    rows = []
    for path, rep in reports.items():
        key = os.path.normpath(path)
        label, payload = labels.get(key, ("unknown", "-"))
        row = {
            "file": path,
            "label": label,
            "payload": payload,
            "risk_score": rep.get("risk_score"),
            "verdict": rep.get("verdict"),
            "detectors": {},
            "findings": [f["detector"] for f in rep.get("findings", [])],
        }
        for m in rep.get("detectors", []):
            parsed = METRIC_RE.search(m.get("metric", ""))
            row["detectors"][m["name"]] = {
                "value": float(parsed.group(1)) if parsed else None,
                "status": m.get("status"),
            }
        rows.append(row)

    Path(a.out).write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"scanned {len(rows)} files -> {a.out}")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def quantile(values, q):
    if not values:
        return None
    v = sorted(values)
    idx = min(len(v) - 1, max(0, int(round(q * (len(v) - 1)))))
    return v[idx]


def cmd_report(a):
    rows = json.loads(Path(a.input).read_text(encoding="utf-8"))
    names = sorted({n for r in rows for n in r["detectors"]})
    covers = [r for r in rows if r["label"] == "cover"]
    stegos = [r for r in rows if r["label"] == "stego"]
    print(f"rows={len(rows)} covers={len(covers)} stegos={len(stegos)}")
    print()
    print(f"{'detector':<18}{'set':<7}{'n':>4}{'min':>8}{'p50':>8}{'p90':>8}{'p99':>8}{'max':>8}{'>0.05':>7}")
    for name in names:
        for label, group in (("cover", covers), ("stego", stegos)):
            vals = [r["detectors"][name]["value"] for r in group if r["detectors"].get(name, {}).get("value") is not None]
            if not vals:
                continue
            over = sum(1 for v in vals if v > 0.05)
            print(
                f"{name:<18}{label:<7}{len(vals):>4}{min(vals):>8.3f}{quantile(vals, 0.5):>8.3f}"
                f"{quantile(vals, 0.9):>8.3f}{quantile(vals, 0.99):>8.3f}{max(vals):>8.3f}{over:>7}"
            )
    print()

    # Threshold sweep over the two rate detectors: FP on covers, TPR on stego.
    for name in [n for n in names if n.startswith("spatial:") and n != "spatial:chi2"]:
        cover_vals = [r["detectors"][name]["value"] for r in covers if name in r["detectors"]]
        print(f"--- {name}")
        print(f"{'thr':>6}{'FP':>6}{'FP%':>7}{'TP_all':>8}{'TP%':>7}", end="")
        payloads = sorted({r["payload"] for r in stegos})
        for p in payloads:
            print(f"{'TP@' + str(p):>12}", end="")
        print()
        for thr in (0.05, 0.06, 0.07, 0.08, 0.09, 0.10, 0.12, 0.15):
            fp = sum(1 for v in cover_vals if v > thr)
            tp = sum(1 for r in stegos if r["detectors"].get(name, {}).get("value", 0) > thr)
            print(
                f"{thr:>6.2f}{fp:>6}{100.0 * fp / max(1, len(cover_vals)):>6.0f}%"
                f"{tp:>8}{100.0 * tp / max(1, len(stegos)):>6.0f}%",
                end="",
            )
            for p in payloads:
                g = [r for r in stegos if r["payload"] == p]
                hit = sum(1 for r in g if r["detectors"].get(name, {}).get("value", 0) > thr)
                print(f"{100.0 * hit / max(1, len(g)):>11.0f}%", end="")
            print()
        print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen")
    g.add_argument("--bin", required=True)
    g.add_argument("--covers")
    g.add_argument("--covers-list", help="text file with one cover per line (takes precedence)")
    g.add_argument("--limit", type=int, default=0)
    g.add_argument("--payloads", default="64,4096,full")
    g.add_argument("--password", default="CalibP@ss2026")
    g.add_argument("--out", required=True)
    g.set_defaults(func=cmd_gen)

    s = sub.add_parser("scan")
    s.add_argument("--bin", required=True)
    s.add_argument("--set", nargs="*", help="directories or files to scan")
    s.add_argument("--file-list", nargs="*", help="text files with one image path per line")
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report")
    r.add_argument("--input", required=True)
    r.set_defaults(func=cmd_report)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
