#!/usr/bin/env python3
"""Generate the root-level BENCHMARK.md (short, two tables) from the raw
benchmark JSON produced by `rust/examples/perf_bench.rs`.

Usage:
    python scripts/bench/gen_summary.py

The detailed reports live in docs/BENCH_{STRUCTURE,CONTENT}_20261107.md.
This file deliberately contains only two tables plus the factor ranking.
"""

from __future__ import annotations

import json
import math
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "temp" / "bench" / "results"
OUT = ROOT / "BENCHMARK.md"

STRUCTURE_SIZES = [4, 64, 256, 1024, 4096]  # KiB
CONTENT_SIZES = [1, 8, 32, 128]  # KiB
SCENARIOS = [
    ("PNG / HILL", "12 MP RGB", "png_hill"),
    ("PNG / S-UNIWARD", "12 MP RGB", "png_suniward"),
    ("PNG / MiPOD", "12 MP RGB", "png_mipod"),
    ("JPEG / UERD", "5760×3840", "jpeg_uerd"),
    ("JPEG / J-UNIWARD", "5760×3840", "jpeg_juniward"),
    ("JPEG / J-MiPOD", "5760×3840", "jpeg_jmipod"),
    ("HEVC / MP4", "1080p60 · 3.3 s", "hevc_mp4"),
    ("HEVC / HEIC", "4032×3024", "heic"),
    ("WAV / PCM", "47 MiB · 240 s", "wav_pcm"),
    ("FLAC / residual", "21 MiB · 240 s", "flac_residual"),
]


def pearson(xs: list[float], ys: list[float]) -> float:
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy = math.sqrt(sum((y - my) ** 2 for y in ys))
    return num / (dx * dy) if dx and dy else float("nan")


def ranks(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            out[order[k]] = avg
        i = j + 1
    return out


def spearman(xs: list[float], ys: list[float]) -> float:
    return pearson(ranks(xs), ranks(ys))


def load() -> tuple[list[dict], list[dict]]:
    structure = json.loads((RESULTS / "structure.json").read_text(encoding="utf-8"))
    content = json.loads((RESULTS / "content.json").read_text(encoding="utf-8"))
    extra_path = RESULTS / "flac128.json"
    if extra_path.exists():
        extra = json.loads(extra_path.read_text(encoding="utf-8"))
        known = {c.get("id") for c in content["cells"]}
        content["cells"].extend(c for c in extra["cells"] if c.get("id") not in known)
    sc = [
        c for c in structure["cells"]
        if c["id"].startswith("structure/") and c.get("status") == "ok"
    ]
    cc = [
        c for c in content["cells"]
        if c["id"].startswith("content/") and c.get("status") == "ok"
    ]
    return sc, cc


def table_structure(sc: list[dict]) -> list[str]:
    lines = [
        "| 载荷 | 写入 (9 载体) | 读取 (9 载体) | 典型值 (中位数) | 相对 4 KiB |",
        "| :--- | :--- | :--- | ---: | ---: |",
    ]
    base = statistics.median(
        c["write"]["median_ms"] for c in sc if c["payload_bytes"] == 4 * 1024
    )
    for kib in STRUCTURE_SIZES:
        rows = [c for c in sc if c["payload_bytes"] == kib * 1024]
        w = [c["write"]["median_ms"] for c in rows]
        r = [c["read"]["median_ms"] for c in rows]
        typical = statistics.median(w)
        lines.append(
            f"| {kib if kib < 1024 else kib // 1024} "
            f"{'KiB' if kib < 1024 else 'MiB'} "
            f"| {min(w):.1f} – {max(w):.1f} ms "
            f"| {min(r):.1f} – {max(r):.1f} ms "
            f"| {typical:.1f} ms | {typical / base:.2f}× |"
        )
    return lines


def fmt_ms(v: float) -> str:
    return f"{v:.0f}"


def table_content(cc: list[dict]) -> list[str]:
    lines = [
        "| 载体 / 算法 | 载体规模 | 1 KiB (ms) | 8 KiB (ms) | 32 KiB (ms) | 128 KiB (ms) | 提取 @32 KiB (ms) |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for label, scale, sid in SCENARIOS:
        rows = {c["payload_bytes"]: c for c in cc if c["carrier_id"] == sid}
        cells = []
        for kib in CONTENT_SIZES:
            c = rows.get(kib * 1024)
            cells.append(fmt_ms(c["write"]["median_ms"]) if c else "—")
        ext = rows.get(32 * 1024)
        ext_txt = fmt_ms(ext["read"]["median_ms"]) if ext else "—"
        lines.append(
            f"| {label} | {scale} | " + " | ".join(cells) + f" | {ext_txt} |"
        )
    return lines


def factor_lines(sc: list[dict], cc: list[dict]) -> list[str]:
    # Structure: monotonic payload effect and within-tier carrier-size effect.
    payloads = [c["payload_bytes"] for c in sc]
    writes = [c["write"]["median_ms"] for c in sc]
    r_payload_spearman = spearman(payloads, writes)
    r_carrier = []
    for kib in STRUCTURE_SIZES:
        rows = [c for c in sc if c["payload_bytes"] == kib * 1024]
        r_carrier.append(
            pearson([c["carrier_bytes"] for c in rows],
                    [c["write"]["median_ms"] for c in rows])
        )

    # Content: cross-engine correlation at the fixed 32 KiB tier.
    r32 = [c for c in cc if c["payload_bytes"] == 32 * 1024]
    r_bytes = pearson(
        [c["carrier_bytes"] for c in r32],
        [c["write"]["median_ms"] for c in r32],
    )
    # Within-engine payload sensitivity (Spearman on log2 payload, 4 points each).
    payload_ratios: list[tuple[str, float]] = []
    for _, _, sid in SCENARIOS:
        rows = sorted(
            (c for c in cc if c["carrier_id"] == sid),
            key=lambda c: c["payload_bytes"],
        )
        if len(rows) >= 2:
            ratio = rows[-1]["write"]["median_ms"] / rows[0]["write"]["median_ms"]
            payload_ratios.append((sid, ratio))

    lines = [
        f"- **结构域**：{r_payload_spearman:.2f} 的 Spearman 相关来自载荷档位"
        f"（整体单调，1 MiB 台阶除外），但 4 KiB → 4 MiB 只从 21.5 ms 到 34.5 ms（**1.6×**）。"
        f"同一载荷档内载体大小的相关系数 r = {min(r_carrier):.2f}–{max(r_carrier):.2f}，"
        "不过绝对差只有 3–6 ms。"
        "**真正的主导项是固定的 PBKDF2 密钥派生（100 000 次，约 20 ms）**，"
        "它占 4 KiB 档的 ~95%；载荷每 +1 MiB 约 +3 ms，载体大小几乎不影响。",
        f"- **内容域**：跨引擎看，载体字节数与 32 KiB 档耗时"
        f" r = {r_bytes:+.2f}（**无相关**），分辨率同样无预测力"
        "（12 MP PNG ≈ 1.8 s，12 MP HEIC 仅 0.24 s，22 MP JPEG ≈ 1.7–2.4 s），"
        "时长也不单独预测（240 s WAV 0.39 s vs 3.3 s HEVC 2.0 s）。"
        "**决定数量级的是引擎/容器路径**：要不要重算代价图、要不要全量熵解码、"
        "要不要多次重算 CRC/MD5。",
        "- **内容域内部**：固定引擎后，载荷大小才是主要变量——1 KiB → 最大档"
        f"使耗时变化 {min(v for _, v in payload_ratios):.1f}×（FLAC，仅测到 32 KiB）到 "
        f"{max(v for _, v in payload_ratios):.0f}×（WAV，测到 128 KiB）；"
        "载体规模/时长在同引擎内明显正相关（固定 32 KiB：21 MiB FLAC 6.8 s → "
        "58 MiB FLAC 11.8 s）。",
    ]
    ratios = [
        c["read"]["median_ms"] / c["write"]["median_ms"]
        for c in r32 if c["write"]["median_ms"] > 0
    ]
    lines.append(
        "- **读取侧**：结构域读取与写入同量级（都要一次 KDF）；内容域提取只需嵌入的 "
        f"{min(ratios) * 100:.0f}–{max(ratios) * 100:.0f}%（不重算代价图）。"
    )
    return lines + [
    ]


def main() -> int:
    sc, cc = load()
    lines: list[str] = []
    add = lines.append
    add("# 性能基线 / Performance")
    add("")
    add("> 简明基线。**单位毫秒（ms），表中为 20 次采样的中位数**；"
        "详细方法、逐格方差与原始数据见 "
        "[结构域报告](docs/BENCH_STRUCTURE_20261107.md) 与 "
        "[内容域报告](docs/BENCH_CONTENT_20261107.md)。")
    add("")
    add("环境：Intel i7-11700（8C/16T）· 32 GiB · Windows 10 · Rust 1.99.1 · "
        "`strhide 0.9.2/0.9.3` · `--release`（LTO）。"
        "内存 API 计时：固定密码/固定 seed/固定随机载荷，**含 PBKDF2，不含磁盘 I/O**。"
        "每格 2 次预热 + 20 次采样，写入后逐字节校验读回。")
    add("")
    add("**一句话**：结构域 **20–46 ms**，几乎只由密钥派生决定；"
        "内容域 **0.06–14.6 s**，跨引擎差两个数量级，"
        "由「引擎/容器路径」决定数量级、由载荷大小决定同引擎内的斜率。")
    add("")
    add("## 结构域（容器信封）")
    add("")
    add("9 种载体（PNG / JPEG / WebP / WAV / MP4 / MKV / ZIP / PDF / PE）的取值范围；"
        "典型值为 9 个载体的中位数。")
    add("")
    lines.extend(table_structure(sc))
    add("")
    add("> 1 MiB 档比 4 MiB 还慢，是 `COMPRESSION_PROBE_MIN_BYTES = 1 MiB` "
        "的压缩探测边界，不是测量误差；详见结构域报告 §5.2。")
    add("")
    add("## 内容域（媒体隐写）")
    add("")
    add("**下表所有耗时列单位均为毫秒（ms）**：每格为嵌入耗时，"
        "最后一列是 32 KiB 档的提取耗时。算法维度全量覆盖"
        "（PNG 3 种、JPEG 3 种、HEVC、WAV、FLAC）。")
    add("")
    lines.extend(table_content(cc))
    add("")
    add("> FLAC 的 128 KiB 档在 21 MiB 载体上放不下：换 58 MiB Hi-Res 载体后"
        "嵌入 14 609 ms / 提取 5 271 ms，不与本表其它行做载荷维度比较。"
        "HEVC 短片的 128 KiB 档超出 High 安全档位，实测已降为 Balanced。")
    add("")
    add("## 主要与什么相关")
    add("")
    lines.extend(factor_lines(sc, cc))
    add("")
    add("**逐项判定**（跨引擎比较时）：")
    add("")
    add("- **载荷大小**：结构域弱（每 MiB 约 +3 ms）；内容域**同一引擎内**强（1.1×–23×）。")
    add("- **载体大小**：结构域极弱（3–6 ms）；内容域跨引擎无相关（r = -0.03），"
        "同一引擎内正相关（21 MiB → 58 MiB FLAC：6.8 s → 11.8 s）。")
    add("- **载体分辨率**：只在图像引擎内部影响固定成本，跨引擎无预测力"
        "（同为 12 MP：HEIC 0.24 s vs PNG 1.8 s）。")
    add("- **载体时长**：音频/视频引擎内部正相关，跨引擎无预测力"
        "（240 s WAV 0.39 s vs 3.3 s HEVC 2.0 s）。")
    add("- **真正的主因**：结构域 = 固定 PBKDF2；内容域 = 引擎/容器路径"
        "（代价图重算、全量熵解码、多次 CRC/MD5 复检）。")
    add("")
    add("## 复现")
    add("")
    add("```bash")
    add("cd rust")
    add("cargo build --release --all-features --example perf_bench")
    add("./target/release/examples/perf_bench --domain structure --reps 20 --warmup 2 --io \\")
    add("    --out ../temp/bench/results/structure.json")
    add("./target/release/examples/perf_bench --domain content --reps 20 --warmup 2 --io \\")
    add("    --out ../temp/bench/results/content.json")
    add("./target/release/examples/perf_bench --domain content --only flac128 --reps 20 \\")
    add("    --warmup 2 --out ../temp/bench/results/flac128.json 2>&1 | tee ../temp/bench/results/flac128.log")
    add("C:/Home/Develop/venv/Scripts/python.exe ../scripts/bench/gen_summary.py")
    add("C:/Home/Develop/venv/Scripts/python.exe ../scripts/bench/render_report.py")
    add("```")
    add("")
    OUT.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
