#!/usr/bin/env python3
"""Fetch and derive the local HEVC Annex-B test corpus.

The sniffing and CABAC engines are validated against real streams, not against
synthetic start codes: real encoders disagree about what the first NAL of a
file may be (VPS-first, IDR-first, a bare TRAIL_R frame, an open-GOP RASL
after a cut). This script builds `temp/testhevc/annexb/` (gitignored) from the
PhotoPrism public sample set plus two ffmpeg-derived streams.

Sources
-------
* `https://dl.photoprism.app/samples/Formats/Video/H.265-HEVC/` -- real-world
  encodes: 8-bit/10-bit, HDR10, 4:4:4, parameter-set-only, single frames, and a
  phone capture. Their licences belong to their publishers; they are used as
  local test material only.
* Derived with the local ffmpeg (no network): an Annex-B remux of the phone
  capture, an open-GOP re-encode (which is the only way to obtain RASL/RADL
  leading pictures), and single-NAL slices of that re-encode that start on a
  non-parameter-set NAL -- the shape a frame extractor or a crude splitter
  produces.

Usage
-----
    python scripts/fetch_hevc_samples.py            # download + derive
    python scripts/fetch_hevc_samples.py --list     # print the manifest
    python scripts/fetch_hevc_samples.py --verify   # sizes only, no download

Everything is idempotent: existing files with the expected size are kept.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

BASE_URL = "https://dl.photoprism.app/samples/Formats/Video/H.265-HEVC"

# name -> expected byte size (0 = accept whatever the server sends)
REMOTE: dict[str, int] = {
    "bear-sps-pps.hevc": 911,
    "bear-frame5.hevc": 1136,
    "blackwhite_yuv444p-frame.hevc": 2975,
    "bear-frame0.hevc": 3558,
    "bear-320x180-10bit-frame-0.hevc": 5918,
    "bear.hevc": 14428,
    "bbb.hevc": 20503,
    "test-25fps.hevc": 114405,
    "test-25fps.hevc10": 115179,
    "bear-1280x720-hevc-10bit-hdr10.hevc": 272747,
    "TSU_640x360.mp4": 1269711,
    "VID_20201221_214720.mp4": 6251446,
}

# NAL unit type -> short name (ITU-T H.265 Table 7-1, defined values only).
NAL_NAMES = {
    0: "trail_n",
    1: "trail_r",
    2: "tsa_n",
    3: "tsa_r",
    4: "stsa_n",
    5: "stsa_r",
    6: "radl_n",
    7: "radl_r",
    8: "rasl_n",
    9: "rasl_r",
    16: "bla_w_lp",
    17: "bla_w_radl",
    18: "bla_n_lp",
    19: "idr_w_radl",
    20: "idr_n_lp",
    21: "cra",
    32: "vps",
    33: "sps",
    34: "pps",
    35: "aud",
    36: "eos",
    37: "eob",
    38: "fd",
    39: "prefix_sei",
    40: "suffix_sei",
}


def corpus_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "temp" / "testhevc" / "annexb"


def download(name: str, expected: int, dest: Path) -> None:
    target = dest / name
    if target.exists() and (expected == 0 or target.stat().st_size == expected):
        print(f"  keep     {name} ({target.stat().st_size} B)")
        return
    url = f"{BASE_URL}/{name}"
    print(f"  fetch    {name}")
    tmp = target.with_suffix(target.suffix + ".part")
    with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    size = tmp.stat().st_size
    if expected and size != expected:
        tmp.unlink()
        raise SystemExit(f"{name}: got {size} bytes, expected {expected}")
    tmp.replace(target)


def run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"{' '.join(cmd)} failed:\n{proc.stderr.strip()}")


def nal_units(data: bytes) -> list[tuple[int, int]]:
    """(start-code offset, NAL header offset) for every Annex-B NAL."""
    out: list[tuple[int, int]] = []
    i, n = 0, len(data)
    while i + 3 < n:
        if data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 1:
            out.append((i, i + 3))
            i += 3
        elif i + 4 < n and data[i : i + 4] == b"\x00\x00\x00\x01":
            out.append((i, i + 4))
            i += 4
        else:
            i += 1
    return out


def first_nal_type(path: Path) -> int | None:
    units = nal_units(path.read_bytes())
    if not units:
        return None
    header = path.read_bytes()[units[0][1]]
    return (header >> 1) & 0x3F


def derive(dest: Path) -> None:
    if shutil.which("ffmpeg") is None:
        print("  skip     ffmpeg not on PATH: derived streams not rebuilt")
        return

    phone = dest / "VID_20201221_214720.mp4"
    remux = dest / "VID_20201221_214720_annexb.hevc"
    if phone.exists() and not remux.exists():
        print("  derive   VID_20201221_214720_annexb.hevc")
        run(["ffmpeg", "-v", "error", "-y", "-i", str(phone),
             "-c", "copy", "-bsf:v", "hevc_mp4toannexb", "-f", "hevc", str(remux)])

    bear = dest / "bear.hevc"
    opengop = dest / "bear-opengop.hevc"
    if bear.exists() and not opengop.exists():
        print("  derive   bear-opengop.hevc (open GOP, RASL/RADL leading pictures)")
        run(["ffmpeg", "-v", "error", "-y", "-i", str(bear), "-c:v", "libx265",
             "-x265-params",
             "open-gop=1:bframes=4:keyint=24:min-keyint=24:scenecut=0:log-level=error",
             "-f", "hevc", str(opengop)])

    if opengop.exists():
        data = opengop.read_bytes()
        units = nal_units(data)
        for group, label in (((6, 7), "radl"), ((8, 9), "rasl")):
            out = dest / f"bear-opengop-{label}-frame.hevc"
            if out.exists():
                continue
            for idx, (sc, ns) in enumerate(units):
                nal_type = (data[ns] >> 1) & 0x3F
                if nal_type in group:
                    end = units[idx + 1][0] if idx + 1 < len(units) else len(data)
                    out.write_bytes(data[sc:end])
                    print(f"  derive   {out.name} ({NAL_NAMES.get(nal_type, nal_type)})")
                    break


def manifest(dest: Path) -> None:
    rows = ["name\tsize\tsha256\tfirst_nal"]
    for path in sorted(p for p in dest.iterdir() if p.is_file() and not p.name.endswith(".part")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        nal = first_nal_type(path) if path.suffix in (".hevc", ".hevc10") else None
        rows.append(f"{path.name}\t{path.stat().st_size}\t{digest}\t{NAL_NAMES.get(nal, nal)}")
    (dest / "manifest.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"  wrote    manifest.txt ({len(rows) - 1} entries)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="print the manifest and exit")
    parser.add_argument("--verify", action="store_true", help="check sizes without downloading")
    args = parser.parse_args()

    dest = corpus_dir()
    dest.mkdir(parents=True, exist_ok=True)

    if args.list:
        path = dest / "manifest.txt"
        if not path.exists():
            raise SystemExit("manifest.txt missing: run the script without --list first")
        print(path.read_text(encoding="utf-8"), end="")
        return 0

    if not args.verify:
        print(f"corpus: {dest}")
        for name, expected in REMOTE.items():
            download(name, expected, dest)
        derive(dest)

    missing = [n for n in REMOTE if not (dest / n).exists()]
    if missing:
        print(f"missing: {', '.join(missing)}", file=sys.stderr)
        return 1
    manifest(dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
