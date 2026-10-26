#!/usr/bin/env python3
"""HEVC 隐写画质评测：同一载体的载荷-画质曲线。

对给定载体，按一组载荷大小依次 embed，再用 ffmpeg 计算三种口径的保真度：

* **PSNR**（像素误差，工程底线）：平均 / 最差帧 / 逐帧标准差
* **SSIM**（结构相似度，块级扰动比 PSNR 敏感）
* **VMAF**（Netflix 感知模型，最接近"人眼是否看得出来"）

同时输出逐帧 CSV，用来看误差是**均匀分摊**还是**集中在少数帧**（漂移的指纹）。

用法::

    python scripts/hevc_quality_sweep.py --carrier temp/testhevc/IMG_0033.MOV \\
        --payloads 1024,5120,15360,40600,102400,362800 --metrics psnr,ssim,vmaf

产物写到 ``temp/quality_sweep/<carrier>/``（默认 gitignored 目录）。
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STRHIDE = ROOT / "rust" / "target" / "release" / ("strhide.exe" if os.name == "nt" else "strhide")
PASSWORD = "sweep"

PSNR_RE = re.compile(r"average:([0-9.]+|inf)\s+min:([0-9.]+|inf)\s+max:([0-9.]+|inf)")
SSIM_RE = re.compile(r"SSIM.*?All:([0-9.]+)")


def run(cmd: list[str], cwd: Path | None = None) -> str:
    """Run a command and return its stderr (ffmpeg reports on stderr)."""
    proc = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if proc.returncode != 0:
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr[-2000:]}")
    return proc.stderr


def make_payload(path: Path, size: int) -> None:
    # Deterministic so a rerun reproduces the same numbers.
    rng = random.Random(0xC0FFEE + size)
    path.write_bytes(bytes(rng.getrandbits(8) for _ in range(size)))


def embed(carrier: Path, payload: Path, out: Path) -> str:
    return run([
        str(STRHIDE), "embed", str(carrier),
        "-d", str(payload), "-o", str(out),
        "-p", PASSWORD, "--overwrite",
    ])


def psnr(cover: Path, stego: Path, stats: Path | None, workdir: Path) -> dict[str, float]:
    # Filter options are `:`-separated, so an absolute Windows path (`C:...`)
    # cannot be passed as an option value. ffmpeg runs with `workdir` as its cwd
    # and the stats file is named relative to it instead.
    lavfi = "[0:v][1:v]psnr"
    if stats:
        lavfi += f"=stats_file={stats.name}"
    log = run(["ffmpeg", "-hide_banner", "-nostdin", "-i", str(cover), "-i", str(stego),
               "-lavfi", lavfi, "-f", "null", "-"], cwd=workdir)
    match = PSNR_RE.search(log)
    if not match:
        raise SystemExit(f"no PSNR summary:\n{log[-1000:]}")
    avg, worst, best = (float("inf") if v == "inf" else float(v) for v in match.groups())
    return {"psnr_avg": avg, "psnr_min": worst, "psnr_max": best}


def per_frame_psnr(stats: Path) -> list[float]:
    values = []
    for line in stats.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.search(r"psnr_avg:([0-9.]+|inf)", line)
        if match:
            values.append(float("inf") if match.group(1) == "inf" else float(match.group(1)))
    return values


def ssim(cover: Path, stego: Path) -> dict[str, float]:
    log = run(["ffmpeg", "-hide_banner", "-nostdin", "-i", str(cover), "-i", str(stego),
               "-lavfi", "[0:v][1:v]ssim", "-f", "null", "-"])
    match = SSIM_RE.search(log)
    if not match:
        raise SystemExit(f"no SSIM summary:\n{log[-1000:]}")
    return {"ssim": float(match.group(1))}


def vmaf(cover: Path, stego: Path, workdir: Path, model: Path) -> dict[str, float]:
    log_path = workdir / "vmaf.json"
    log_path.unlink(missing_ok=True)
    # Same reason as `psnr`: the model path travels inside a filter option, so it
    # is copied next to the log and referenced by file name.
    local_model = workdir / "vmaf_model.json"
    if not local_model.exists():
        local_model.write_bytes(model.read_bytes())
    log = run(["ffmpeg", "-hide_banner", "-nostdin", "-i", str(cover), "-i", str(stego),
               "-lavfi",
               "[0:v][1:v]libvmaf=log_fmt=json:log_path=vmaf.json:model=path=vmaf_model.json",
               "-f", "null", "-"], cwd=workdir)
    if not log_path.exists():
        raise SystemExit(f"VMAF produced no log:\n{log[-1000:]}")
    data = json.loads(log_path.read_text(encoding="utf-8"))
    pooled = data.get("pooled_metrics", {}).get("vmaf", {})
    return {"vmaf_mean": pooled.get("mean"), "vmaf_min": pooled.get("min")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--carrier", required=True)
    ap.add_argument("--payloads", required=True, help="逗号分隔的载荷字节数")
    ap.add_argument("--metrics", default="psnr,ssim,vmaf")
    ap.add_argument(
        "--vmaf-model",
        default=None,
        help="libvmaf 没有内置模型，需要模型 JSON；省略时按 VMAF_MODEL 环境变量、"
        "本地 vmaf 仓库、temp/vmaf/ 的顺序查找",
    )
    args = ap.parse_args()

    carrier = Path(args.carrier).resolve()
    if not STRHIDE.exists():
        raise SystemExit(f"missing binary: {STRHIDE} (run cargo build --release)")
    sizes = [int(s) for s in args.payloads.split(",") if s.strip()]
    metrics = {m.strip() for m in args.metrics.split(",") if m.strip()}
    model = None
    if "vmaf" in metrics:
        candidates = []
        if args.vmaf_model:
            candidates.append(Path(args.vmaf_model))
        if os.environ.get("VMAF_MODEL"):
            candidates.append(Path(os.environ["VMAF_MODEL"]))
        candidates += [
            Path("F:/Develop/github/vmaf/model/vmaf_v0.6.1.json"),
            ROOT / "temp/vmaf/vmaf_v0.6.1.json",
        ]
        model = next((c.resolve() for c in candidates if c.is_file()), None)
    if model is not None and not model.exists():
        raise SystemExit(
            f"VMAF model not found: {model}\n"
            "download: curl -sSL -o temp/vmaf/vmaf_v0.6.1.json "
            "https://raw.githubusercontent.com/Netflix/vmaf/master/model/vmaf_v0.6.1.json"
        )

    outdir = ROOT / "temp" / "quality_sweep" / carrier.stem
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"# {carrier.name}  ({carrier.stat().st_size} bytes)")
    header = f"{'payload':>10} {'flips~':>9} {'PSNR avg':>9} {'worst':>7} {'σ':>6} {'SSIM':>8} {'VMAF':>7} {'VMAF min':>9}"
    print(header)
    print("-" * len(header))

    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for size in sizes:
            payload = work / f"p{size}.bin"
            make_payload(payload, size)
            stego = outdir / f"stego_{size}.{carrier.suffix.lstrip('.')}"
            embed(carrier, payload, stego)

            stats = work / f"psnr_{size}.log"
            row: dict[str, float] = {"payload": size}
            row.update(psnr(carrier, stego, stats, work))
            frames = per_frame_psnr(stats)
            if frames:
                finite = [f for f in frames if f != float("inf")]
                mean = sum(finite) / len(finite) if finite else float("inf")
                var = sum((f - mean) ** 2 for f in finite) / len(finite) if finite else 0.0
                row["frames"] = len(frames)
                row["psnr_sigma"] = var ** 0.5
                (outdir / f"psnr_per_frame_{size}.csv").write_text(
                    "frame,psnr\n" + "\n".join(f"{i},{v}" for i, v in enumerate(frames)) + "\n",
                    encoding="utf-8",
                )
            if "ssim" in metrics:
                row.update(ssim(carrier, stego))
            if "vmaf" in metrics:
                row.update(vmaf(carrier, stego, work, model))

            rows.append(row)
            print(f"{size:>10} {int(size * 4):>9} {row['psnr_avg']:>9.2f} {row['psnr_min']:>7.2f} "
                  f"{row.get('psnr_sigma', 0):>6.3f} {row.get('ssim', float('nan')):>8.5f} "
                  f"{row.get('vmaf_mean') or float('nan'):>7.2f} {row.get('vmaf_min') or float('nan'):>9.2f}")

    summary = outdir / "sweep.json"
    summary.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\nwrote {summary.relative_to(ROOT)}")
    print("flips~ = 载荷比特 × 0.5（STC u=2、约 25% 槽位被翻转的估算）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
