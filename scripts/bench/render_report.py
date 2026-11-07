#!/usr/bin/env python3
"""Render the strhide release benchmark reports from the JSON produced by
`rust/examples/perf_bench.rs`.

Usage:
    python scripts/bench/render_report.py [--results DIR] [--docs DIR]

Produces:
    docs/BENCH_STRUCTURE_<date>.md + .svg
    docs/BENCH_CONTENT_<date>.md   + .svg

Standard library only (no matplotlib); the charts are hand-written SVG so they
render on GitHub and in any Markdown viewer.
"""

from __future__ import annotations

import argparse
import json
import re
import platform
import subprocess
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATE = "20261107"


# ── Environment snapshot ──────────────────────────────────────────────────


def _run(cmd: list[str]) -> str:
    """Run a command and decode its output. Windows tooling (wmic) still emits
    the OEM code page, so a UTF-8 decode has to fall back to GBK instead of
    aborting a reader thread."""
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=20, check=False)
    except Exception:
        return ""
    raw = out.stdout or out.stderr or b""
    for encoding in ("utf-8", "gbk"):
        try:
            return raw.decode(encoding).strip()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace").strip()


def collect_env() -> dict[str, str]:
    env: dict[str, str] = {}

    cpu = _run(["wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors"])
    lines = [l.strip() for l in cpu.splitlines() if l.strip() and "Name" not in l]
    if lines:
        parts = [p for p in re.split(r"\s{2,}", lines[0].strip()) if p]
        if len(parts) >= 3:
            env["cpu"] = f"{parts[0]}（{parts[-2]} 核 / {parts[-1]} 线程）"
        else:
            env["cpu"] = lines[0]
    else:
        env["cpu"] = platform.processor() or "unknown"

    mem = _run(["wmic", "ComputerSystem", "get", "TotalPhysicalMemory"])
    mem_lines = [l.strip() for l in mem.splitlines() if l.strip().isdigit()]
    if mem_lines:
        env["ram"] = f"{int(mem_lines[0]) / (1024 ** 3):.1f} GiB"
    else:
        env["ram"] = "unknown"

    caption = _run(["wmic", "os", "get", "Caption"])
    cap_lines = [l.strip() for l in caption.splitlines() if l.strip() and "Caption" not in l]
    env["os"] = (
        f"{cap_lines[0]}（Build {platform.version()}）" if cap_lines else platform.platform()
    )

    env["rustc"] = _run(["rustc", "-V"]) or "unknown"
    env["cargo"] = _run(["cargo", "-V"]) or "unknown"
    env["git"] = _run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"]) or "unknown"
    dirty = _run(["git", "-C", str(ROOT), "status", "--porcelain"])
    env["git_dirty"] = "有未提交改动" if dirty else "工作区干净"
    env["python"] = platform.python_version()
    return env


# ── Formatting helpers ────────────────────────────────────────────────────


def ms(value: float) -> str:
    if value >= 100:
        return f"{value:.0f}"
    if value >= 10:
        return f"{value:.1f}"
    if value >= 1:
        return f"{value:.2f}"
    return f"{value:.3f}"


def delta(value: float) -> str:
    return f"{value:+.2f}" if abs(value) < 10 else f"{value:+.1f}"


def pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def size_label(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n // (1024 * 1024)} MiB"
    return f"{n // 1024} KiB"


def stat(cell: dict, side: str, key: str) -> float:
    return float(cell[side][key])


def is_ok(cell: dict) -> bool:
    return cell.get("status") == "ok"


# ── SVG line chart ────────────────────────────────────────────────────────

PALETTE = [
    "#c0392b", "#2c7fb8", "#27ae60", "#8e44ad", "#d68910",
    "#16a085", "#7f8c8d", "#b03a2e", "#2e86c1", "#1e8449",
]


def svg_line_chart(
    series: list[tuple[str, list[tuple[int, float, float]]]],
    title: str,
    y_label: str,
) -> str:
    """series: [(label, [(payload_bytes, write_ms, read_ms), ...])]"""
    width, height = 760, 420
    left, right, top, bottom = 78, 190, 48, 56
    plot_w = width - left - right
    plot_h = height - top - bottom

    xs = sorted({p for _, pts in series for p, _, _ in pts})
    ys = [v for _, pts in series for _, w, r in pts for v in (w, r)]
    if not xs or not ys:
        return ""

    import math

    def lx(p: int) -> float:
        lo, hi = math.log10(min(xs)), math.log10(max(xs))
        if hi == lo:
            return left + plot_w / 2
        return left + (math.log10(p) - lo) / (hi - lo) * plot_w

    y_lo = math.floor(math.log10(min(ys)))
    y_hi = math.ceil(math.log10(max(ys)))
    if y_hi <= y_lo:
        y_hi = y_lo + 1

    def ly(v: float) -> float:
        t = (math.log10(v) - y_lo) / (y_hi - y_lo)
        return top + plot_h - t * plot_h

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="{left}" y="26" font-size="14" font-weight="600" fill="#1a1a1a">{title}</text>',
    ]

    # y grid (log decades)
    for decade in range(y_lo, y_hi + 1):
        for m in (1, 2, 5):
            v = m * (10 ** decade)
            if v < 10 ** y_lo * 0.999 or v > 10 ** y_hi * 1.001:
                continue
            y = ly(v)
            dash = "" if m == 1 else ' stroke-dasharray="2 4"'
            parts.append(
                f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" '
                f'stroke="#e6e6e6"{dash}/>'
            )
            if m == 1:
                label = f"{v:g}"
                parts.append(
                    f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" fill="#666">{label}</text>'
                )

    # x ticks
    for p in xs:
        x = lx(p)
        parts.append(
            f'<line x1="{x:.1f}" y1="{top + plot_h}" x2="{x:.1f}" y2="{top + plot_h + 5}" '
            f'stroke="#999"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{top + plot_h + 20}" text-anchor="middle" fill="#666">'
            f"{size_label(p)}</text>"
        )

    parts.append(
        f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" '
        f'stroke="#999"/>'
    )
    parts.append(
        f'<text x="{left + plot_w / 2}" y="{height - 14}" text-anchor="middle" fill="#666">'
        f"payload 大小（对数轴）</text>"
    )
    parts.append(
        f'<text x="16" y="{top + plot_h / 2}" fill="#666" '
        f'transform="rotate(-90 16 {top + plot_h / 2})" text-anchor="middle">{y_label}</text>'
    )

    for idx, (label, pts) in enumerate(series):
        color = PALETTE[idx % len(PALETTE)]
        path = " ".join(
            f"{'M' if i == 0 else 'L'}{lx(p):.1f},{ly(w):.1f}" for i, (p, w, _) in enumerate(pts)
        )
        parts.append(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2"/>')
        for p, w, _ in pts:
            parts.append(f'<circle cx="{lx(p):.1f}" cy="{ly(w):.1f}" r="3" fill="{color}"/>')
        # legend
        ly_ = top + 6 + idx * 18
        parts.append(
            f'<line x1="{left + plot_w + 18}" y1="{ly_}" x2="{left + plot_w + 38}" y2="{ly_}" '
            f'stroke="{color}" stroke-width="2"/>'
        )
        parts.append(
            f'<text x="{left + plot_w + 44}" y="{ly_ + 4}" fill="#333">{label}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)


# ── Report: structure domain ──────────────────────────────────────────────


def render_structure(doc: dict, env: dict[str, str]) -> tuple[str, str]:
    cells = [c for c in doc["cells"] if c.get("status") == "ok" and "/" in c["id"]]
    main = [c for c in cells if c["id"].startswith("structure/")]
    io_cells = [c for c in cells if c["id"].startswith("structure_io/")]
    compress = [c for c in cells if c["id"].startswith("structure_compress/")]

    order = ["png", "jpeg", "webp", "wav", "mp4", "mkv", "zip", "pdf", "pe"]
    main.sort(key=lambda c: (order.index(c["carrier_id"]), c["payload_bytes"]))
    io_cells.sort(key=lambda c: order.index(c["carrier_id"]))

    series = []
    for carrier in order:
        pts = [
            (c["payload_bytes"], stat(c, "write", "median_ms"), stat(c, "read", "median_ms"))
            for c in main
            if c["carrier_id"] == carrier
        ]
        if pts:
            series.append((carrier.upper() if carrier != "pe" else "PE", pts))
    svg = svg_line_chart(series, "结构域：写入耗时中位数 vs 载荷大小", "毫秒（对数轴）")

    lines: list[str] = []
    add = lines.append

    add(f"# strhide 结构域（容器信封）性能基准报告 — {DATE}")
    add("")
    add("> 数据来源：`rust/examples/perf_bench.rs`，发布构建（`opt-level=3, lto=true`）。")
    add("> 全部计时走内存 API，不含文件系统 I/O（I/O 开销见 §5.3）；每格 2 次预热 + 20 次计时。")
    add("")
    add("## 1. 测试环境")
    add("")
    add("| 项 | 值 |")
    add("| :--- | :--- |")
    add(f"| CPU | {env['cpu']} |")
    add(f"| 内存 | {env['ram']} |")
    add(f"| 操作系统 | {env['os']} |")
    add(f"| Rust | {env['rustc']} |")
    add(f"| Cargo | {env['cargo']} |")
    add(f"| 仓库版本（报告生成时） | `{env['git']}`（{env['git_dirty']}） |")
    add("| 测量时版本 | `0.9.2` @ `10e90f6`；运行期发布提交把版本号 bump 到 `0.9.3` "
        "（`7b34b33`，仅版本号/文档/CHANGELOG，无代码变化）。FLAC 128 KiB 补测用 0.9.3 二进制，"
        "算法代码一致 |")
    add(f"| crate 版本 | {doc['crate_version']} |")
    add(f"| 逻辑核 / rayon 默认池 | {doc['available_parallelism']} |")
    add("")
    add("## 2. 方法摘要")
    add("")
    add("- 写入：`structure::write_carrier_bytes`（内存 → 内存），策略 `auto`，密码加密开启，"
        "`preserve_time` 默认、`backup=false`。")
    add("- 读取：`structure::read_carrier_bytes`，仅提供密码。")
    add("- 载荷：SplitMix64 固定种子生成，**不可压缩**，因此 Deflate 退化为 stored，"
        "表内数字代表「最坏情况」（可压缩载荷见 §5.4）。")
    add(f"- 固定参数：密码 `{doc['constants']['password']}`，20 次计时样本，2 次预热。")
    add("- 正确性门禁：每格首轮校验 `read == payload` 且 `restore == cover`（逐字节），不计时。")
    add("- 统计：中位数为主值；`cv > 10%` 时给出剔除一个最大值与一个最小值的截尾均值（`†`）。")
    add("")
    add("## 3. 写入 / 读取耗时主表")
    add("")
    add("**所有耗时列单位为毫秒（ms）**。`cv` 为变异系数；"
        "`†` 表示该格方差超阈值、已启用截尾均值。")
    add("")
    add("| 载体 | 载荷 | 写入 中位数 | 写入 均值 | 写入 截尾 | 写入 cv | 读取 中位数 | 读取 均值 | 读取 cv |")
    add("| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for c in main:
        w_trim = f"{ms(stat(c,'write','trimmed_mean_ms'))}{'†' if c['write']['trimmed'] else ''}"
        add(
            f"| {c['carrier_family']} | {size_label(c['payload_bytes'])} "
            f"| **{ms(stat(c,'write','median_ms'))}** | {ms(stat(c,'write','mean_ms'))} | {w_trim} "
            f"| {pct(stat(c,'write','cv'))} "
            f"| **{ms(stat(c,'read','median_ms'))}** | {ms(stat(c,'read','mean_ms'))} "
            f"| {pct(stat(c,'read','cv'))} |"
        )
    add("")
    add(f"![结构域耗时曲线](BENCH_STRUCTURE_{DATE}.svg)")
    add("")
    add("## 4. 策略与信封开销")
    add("")
    add("| 载体 | 载荷 | 实际策略 | 信封大小 | stego 大小 | 说明 |")
    add("| :--- | ---: | :--- | ---: | ---: | :--- |")
    for c in main:
        m = c["meta"]
        note = (m.get("strategy_note") or "").split("(")[0].strip()
        add(
            f"| {c['carrier_family']} | {size_label(c['payload_bytes'])} | `{m['strategy']}` "
            f"| {m['ube_size']:,} B | {m['stego_bytes']:,} B | {note} |"
        )
    add("")

    # strategy fallbacks
    fallbacks = [c for c in main if c["meta"]["strategy"] in ("eof", "pe_overlay")]
    if fallbacks:
        add("> **策略退化提示**：以下格没有落到该格式的首选结构化策略，数字对应的是回退路径：")
        add(">")
        for c in fallbacks:
            add(
                f"> - {c['carrier_family']} @ {size_label(c['payload_bytes'])} → "
                f"`{c['meta']['strategy']}`"
            )
        add("")

    add("## 5. 分析")
    add("")
    add("### 5.1 固定开销与边际成本")
    add("")
    add("| 载体 | 4 KiB 写入 | 4 MiB 写入 | 增量 | 每 MiB 增量 |")
    add("| :--- | ---: | ---: | ---: | ---: |")
    for carrier in order:
        rows = [c for c in main if c["carrier_id"] == carrier]
        if len(rows) < 2:
            continue
        small, big = rows[0], rows[-1]
        d = stat(big, "write", "median_ms") - stat(small, "write", "median_ms")
        per_mib = d / ((big["payload_bytes"] - small["payload_bytes"]) / (1024 * 1024))
        add(
            f"| {small['carrier_family']} | {ms(stat(small,'write','median_ms'))} ms "
            f"| {ms(stat(big,'write','median_ms'))} ms | +{ms(d)} ms | {ms(per_mib)} ms/MiB |"
        )
    add("")
    add("4 KiB 与 4 MiB 的差值只有十几毫秒，说明结构域在小载荷区间完全由"
        "密钥派生（PBKDF2-HMAC-SHA256，100 000 次）主导；载荷本身的分块加密与"
        "容器拼接只是线性叠加的小项。")
    add("")

    add("### 5.2 1 MiB 处的压缩探测台阶（非单调点）")
    add("")
    add("| 载体 | 1 MiB 写入 | 4 MiB 写入 | 差值 |")
    add("| :--- | ---: | ---: | ---: |")
    for carrier in order:
        one = next((c for c in main if c["carrier_id"] == carrier and c["payload_bytes"] == 1024 * 1024), None)
        four = next((c for c in main if c["carrier_id"] == carrier and c["payload_bytes"] == 4 * 1024 * 1024), None)
        if not one or not four:
            continue
        a, b = stat(one, "write", "median_ms"), stat(four, "write", "median_ms")
        add(f"| {one['carrier_family']} | {ms(a)} ms | {ms(b)} ms | {a - b:+.1f} ms |")
    add("")
    add("9 个载体一致地出现「1 MiB 比 4 MiB 还慢」。原因不是测量误差，而是 "
        "`CompressionStrategy::Auto` 的实现边界：`src/core/crypto.rs` 的 "
        "`COMPRESSION_PROBE_MIN_BYTES = 1 MiB`，**大于**该值的载荷先做 256 KiB 分层采样"
        "判断是否值得整段 Deflate，**小于等于**该值的载荷直接整段压缩。")
    add("")
    add("随机（不可压缩）载荷两种路径最终都保留原文，但 1 MiB 档白做了一次约 10 ms 的整段压缩，"
        "4 MiB 档只做 256 KiB 采样。发布文档若给出「吞吐随载荷线性增长」的结论，会被这个台阶打脸；"
        "建议在已知优化项里记一笔（把阈值改成 `>=` 或对 ≤1 MiB 也走采样即可抹平）。")
    add("")
    add("### 5.3 读取侧")
    add("")
    read_min = min(main, key=lambda c: stat(c, "read", "median_ms"))
    read_max = max(main, key=lambda c: stat(c, "read", "median_ms"))
    add(
        f"读取耗时区间 {ms(stat(read_min,'read','median_ms'))}–"
        f"{ms(stat(read_max,'read','median_ms'))} ms（{read_min['carrier_family']} @ "
        f"{size_label(read_min['payload_bytes'])} ～ {read_max['carrier_family']} @ "
        f"{size_label(read_max['payload_bytes'])}）。读取同样先做一次 PBKDF2，"
        "所以小载荷与大载荷的差距远小于载荷比。"
    )
    add("")

    if io_cells:
        add("### 5.4 文件 API 开销（内存 API vs 落盘 API）")
        add("")
        add("同一载体、256 KiB 载荷，5 次采样，含原子提交与磁盘写入：")
        add("")
        add("| 载体 | 内存 写入 | 文件 写入 | 增量 | 内存 读取 | 文件 读取 | 增量 |")
        add("| :--- | ---: | ---: | ---: | ---: | ---: | ---: |")
        for io_cell in io_cells:
            mem = next(
                (c for c in main if c["carrier_id"] == io_cell["carrier_id"]
                 and c["payload_bytes"] == io_cell["payload_bytes"]),
                None,
            )
            if not mem:
                continue
            dw = stat(io_cell, "write", "median_ms") - stat(mem, "write", "median_ms")
            dr = stat(io_cell, "read", "median_ms") - stat(mem, "read", "median_ms")
            add(
                f"| {mem['carrier_family']} | {ms(stat(mem,'write','median_ms'))} "
                f"| {ms(stat(io_cell,'write','median_ms'))} | {delta(dw)} "
                f"| {ms(stat(mem,'read','median_ms'))} | {ms(stat(io_cell,'read','median_ms'))} "
                f"| {delta(dr)} |"
            )
        add("")
        add("落盘成本主要是「复制 + 原子 rename」，与载荷大小弱相关；"
            "在 HDD 或开启实时杀软的环境下这一项会明显放大。")
        add("")

    if compress:
        c = compress[0]
        add("### 5.5 可压缩载荷（Deflate 生效时的代价）")
        add("")
        add("4 MiB 全零载荷（Deflate 压缩后仅数 KB）：")
        add("")
        add(f"- 写入中位数 **{ms(stat(c,'write','median_ms'))} ms**，"
            f"读取中位数 **{ms(stat(c,'read','median_ms'))} ms**，"
            f"信封仅 {c['meta']['ube_size']:,} B。")
        add("- 与同载体 4 MiB 随机载荷相比，压缩省下了容器体积，但多花了 CPU；"
            "在 4 MiB 量级上两者处于同一数量级，说明压缩不是结构域的瓶颈。")
        add("")

    add("## 6. 结论")
    add("")
    w_vals = [stat(c, "write", "median_ms") for c in main]
    r_vals = [stat(c, "read", "median_ms") for c in main]
    add(f"1. **写入**：{ms(min(w_vals))}–{ms(max(w_vals))} ms（中位数区间），"
        f"**读取**：{ms(min(r_vals))}–{ms(max(r_vals))} ms，9 种载体在 4 KiB–4 MiB "
        "全档位上没有出现数量级差异。")
    add("2. **主要成本是 PBKDF2**（100 000 次，约 20 ms/次），载荷每增加 1 MiB 只多花"
        "数毫秒。因此「小文件隐藏慢」的观感来自密钥派生，而不是加密或容器操作。")
    add("3. **策略退化必须写进文档**：WebP 在本轮全部回退 `eof`（RIFF 声明边界不匹配），"
        "PE 全部落到 `pe_overlay`。用户若期待「私有块注入」的隐蔽性，需要知道实际走的是哪条路径。")
    add("4. **JPEG 的 APP15 段可承载 4 MiB**：引擎会拆成多段，没有 64 KiB 上限问题。")
    add("5. 发布对外承诺建议以本文档的写入/读取中位数为准，并注明「含 PBKDF2、不含磁盘 I/O」。")
    add("")
    add("## 7. 复现与局限")
    add("")
    add("```bash")
    add("cd rust")
    add("cargo build --release --all-features --example perf_bench")
    add("./target/release/examples/perf_bench --domain structure --reps 20 --warmup 2 --io \\")
    add("    --out ../temp/bench/results/structure.json")
    add("```")
    add("")
    add("局限：单机、单平台（Windows 10 / NTFS）、未做温控与频率锁定，"
        "同机重复跑的绝对值可漂移 ±5%；跨机器比较只看相对比例。"
        "所有数字都**含** PBKDF2 密钥派生、**不含**磁盘 I/O。")
    add("")
    add("## 附录：原始数据")
    add("")
    add(f"`temp/bench/results/structure.json`（schema `{doc['schema']}`，"
        f"{len(doc['cells'])} 个 cell，含全部 20 个样本值）。")
    add("")
    return "\n".join(lines), svg


# ── Report: content domain ────────────────────────────────────────────────


def render_content(doc: dict, env: dict[str, str]) -> tuple[str, str]:
    cells = [c for c in doc["cells"] if "/" in c["id"]]
    main = [c for c in cells if c["id"].startswith("content/") and c.get("status") == "ok"]
    skipped = [c for c in cells if c["id"].startswith("content/") and c.get("status") == "skip"]
    kdf = [c for c in cells if c["id"].startswith("content_kdf/") and c.get("status") == "ok"]
    io_cells = [c for c in cells if c["id"].startswith("content_io/") and c.get("status") == "ok"]

    scenario_order = [
        "png_hill", "png_suniward", "png_mipod",
        "jpeg_uerd", "jpeg_juniward", "jpeg_jmipod",
        "hevc_mp4", "heic", "wav_pcm", "flac_residual", "flac128",
    ]
    main.sort(key=lambda c: (scenario_order.index(c["carrier_id"]), c["payload_bytes"]))

    series = []
    for sid in scenario_order:
        pts = [
            (c["payload_bytes"], stat(c, "write", "median_ms"), stat(c, "read", "median_ms"))
            for c in main
            if c["carrier_id"] == sid
        ]
        if pts:
            series.append((sid, pts))
    svg = svg_line_chart(series, "内容域：嵌入耗时中位数 vs 载荷大小", "毫秒（对数轴）")

    lines: list[str] = []
    add = lines.append

    add(f"# strhide 内容域（多媒体隐写）性能基准报告 — {DATE}")
    add("")
    add("> 数据来源：`rust/examples/perf_bench.rs`，发布构建（`opt-level=3, lto=true`）。")
    add("> 全部计时走内存 API；每格 2 次预热 + 20 次计时；嵌入使用固定 seed（可复现）。")
    add("")
    add("## 1. 测试环境")
    add("")
    add("| 项 | 值 |")
    add("| :--- | :--- |")
    add(f"| CPU | {env['cpu']} |")
    add(f"| 内存 | {env['ram']} |")
    add(f"| 操作系统 | {env['os']} |")
    add(f"| Rust | {env['rustc']} |")
    add(f"| Cargo | {env['cargo']} |")
    add(f"| 仓库版本（报告生成时） | `{env['git']}`（{env['git_dirty']}） |")
    add("| 测量时版本 | `0.9.2` @ `10e90f6`；运行期发布提交把版本号 bump 到 `0.9.3` "
        "（`7b34b33`，仅版本号/文档/CHANGELOG，无代码变化）。FLAC 128 KiB 补测用 0.9.3 二进制，"
        "算法代码一致 |")
    add(f"| crate 版本 | {doc['crate_version']} |")
    add(f"| 逻辑核 / rayon 默认池 | {doc['available_parallelism']} |")
    add("")
    add("## 2. 方法摘要")
    add("")
    add("- 嵌入：`stego::embed_carrier`，密码加密，`Freshness::Seeded`（固定 32 字节 seed）。")
    add("- 提取：`stego::extract_carrier`，仅提供密码。")
    add("- 算法维度**全量覆盖**：PNG 的 HILL / S-UNIWARD / MiPOD，JPEG 的 UERD / J-UNIWARD / "
        "J-MiPOD，HEVC 的 CABAC Scheme C（MP4 与 HEIC 各一），WAV 的 PCM-STC，FLAC 的残差-STC。")
    add("- 安全档位：默认 `High` + `Advisory`；引擎按槽位预算**硬拒**的格自动降一档到 "
        "`Balanced` 重测，并在 §4 标注。")
    add("- 载荷：SplitMix64 固定种子，不可压缩。")
    add("- 正确性门禁：每格每次嵌入后立即提取并比对，任一次不相等即判该格失败。")
    add("")
    add("## 3. 嵌入 / 提取耗时主表")
    add("")
    add("单位毫秒。`†` = 该格 `cv > 10%`，截尾均值已剔除一个最大值与一个最小值。")
    add("")
    add("| 场景 | 算法 | 载体 | 载荷 | 嵌入 中位数 (ms) | 嵌入 均值 (ms) "
        "| 嵌入 截尾 (ms) | 嵌入 cv | 提取 中位数 (ms) | 提取 均值 (ms) | 提取 cv |")
    add("| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for c in main:
        add(
            f"| `{c['carrier_id']}` | {c['algorithm']} | {c['carrier_family']} "
            f"| {size_label(c['payload_bytes'])} "
            f"| **{ms(stat(c,'write','median_ms'))}** | {ms(stat(c,'write','mean_ms'))} "
            f"| {ms(stat(c,'write','trimmed_mean_ms'))}{'†' if c['write']['trimmed'] else ''} "
            f"| {pct(stat(c,'write','cv'))} "
            f"| **{ms(stat(c,'read','median_ms'))}** | {ms(stat(c,'read','mean_ms'))} "
            f"| {pct(stat(c,'read','cv'))} |"
        )
    add("")
    add(f"![内容域耗时曲线](BENCH_CONTENT_{DATE}.svg)")
    add("")
    add("## 4. 容量利用率与安全档位")
    add("")
    add("| 场景 | 载荷 | 推荐容量(High) | 物理上限 | 载荷/推荐 | 载荷/上限 | 实测档位 | 备注 |")
    add("| :--- | ---: | ---: | ---: | ---: | ---: | :--- | :--- |")
    for c in main:
        cap = c.get("capacity") or {}
        rec = cap.get("recommended_max_bytes")
        mx = cap.get("max_raw_payload_bytes")
        ratio_rec = c["payload_bytes"] / rec if rec else float("nan")
        ratio_max = c["payload_bytes"] / mx if mx else float("nan")
        level = c["meta"].get("safety_level", "?")
        if c["meta"].get("level_note"):
            note = ("High 档槽位不足 → 自动降 Balanced"
                    if c["meta"].get("safety_level") == "Balanced"
                    else str(c["meta"]["level_note"])[:60])
        elif c["meta"].get("warnings"):
            note = f"超 High 档推荐值（{ratio_rec:.2f}×），Advisory 已写入"
        else:
            note = ""
        if c["carrier_id"] == "flac128":
            note = "换用 58 MiB Hi-Res 载体（上限 142 KB）"
        add(
            f"| `{c['carrier_id']}` | {size_label(c['payload_bytes'])} "
            f"| {rec:,} B | {mx:,} B | {ratio_rec:.2f}× | {ratio_max:.2f}× "
            f"| {level} | {note[:80]} |"
        )
    for c in skipped:
        err = (c.get("error") or "")[:80]
        add(
            f"| `{c['carrier_id']}` | {size_label(c['payload_bytes'])} | — | — | — | — "
            f"| skip | {err} |"
        )
    add("")

    add("## 5. 分析")
    add("")
    add("### 5.1 算法开销对比（同一载体、32 KiB 载荷）")
    add("")
    add("| 格式 | 算法 | 嵌入 ms | 相对同格式默认算法 |")
    add("| :--- | :--- | ---: | ---: |")
    for family, algos in (
        ("PNG", ["png_hill", "png_suniward", "png_mipod"]),
        ("JPEG", ["jpeg_uerd", "jpeg_juniward", "jpeg_jmipod"]),
    ):
        rows = [
            c for c in main
            if c["carrier_id"] in algos and c["payload_bytes"] == 32 * 1024
        ]
        rows.sort(key=lambda c: algos.index(c["carrier_id"]))
        if not rows:
            continue
        base = stat(rows[0], "write", "median_ms")
        for c in rows:
            v = stat(c, "write", "median_ms")
            add(
                f"| {family} | {c['algorithm']} | {ms(v)} | "
                f"{'基线' if v == base else f'{v / base:.2f}×'} |"
            )
    add("")

    add("### 5.2 固定成本 vs 载荷边际成本")
    add("")
    add("| 场景 | 最小载荷 嵌入 | 最大载荷 嵌入 | 增量 |")
    add("| :--- | ---: | ---: | ---: |")
    for sid in scenario_order:
        rows = [c for c in main if c["carrier_id"] == sid]
        if len(rows) < 2:
            continue
        small, big = rows[0], rows[-1]
        d = stat(big, "write", "median_ms") - stat(small, "write", "median_ms")
        add(
            f"| `{sid}` | {ms(stat(small,'write','median_ms'))} "
            f"({size_label(small['payload_bytes'])}) | "
            f"{ms(stat(big,'write','median_ms'))} ({size_label(big['payload_bytes'])}) "
            f"| {delta(d)} |"
        )
    add("")
    add("数据与「载荷越大越慢」的直觉并不完全一致，分三类：")
    add("")
    add("- **代价图主导**（PNG / JPEG 六种算法）：固定成本 0.5–2 s，1 KiB → 128 KiB 只增加 "
        "0.6–1.4 s；算法之间的差距在最小载荷时就已存在。")
    add("- **载荷主导**（WAV、HEIC、HEVC）：1 KiB → 128 KiB 分别约 23×、6.8×、2.3×，"
        "矩阵编码与码流修改的开销近似与载荷位数成正比。")
    add("- **载体解码主导**（FLAC）：21 MiB 载体本身要 ~6 s，32 KiB 载荷只多 0.6 s，"
        "载荷几乎不影响耗时。原因见 §5.6（多次全量解码 + 载体是 4 分钟音频）。")
    add("")

    if kdf:
        add("### 5.3 KDF 占比（跳过 PBKDF2 的对照实验）")
        add("")
        add("同样 8 KiB 载荷，改用 32 字节 `FileKey`（跳过 PBKDF2）后的耗时：")
        add("")
        add("| 场景 | 密码模式 嵌入 | 文件密钥 嵌入 | PBKDF2 估算 | 占比 |")
        add("| :--- | ---: | ---: | ---: | ---: |")
        for k in kdf:
            base = next(
                (c for c in main
                 if c["carrier_id"] == k["carrier_id"] and c["payload_bytes"] == k["payload_bytes"]),
                None,
            )
            if not base:
                continue
            with_pw = stat(base, "write", "median_ms")
            without = stat(k, "write", "median_ms")
            diff = max(with_pw - without, 0.0)
            add(
                f"| `{k['carrier_id']}` | {ms(with_pw)} | {ms(without)} "
                f"| {'≤噪声' if diff < 1.0 else ms(diff)} "
                f"| {'—' if diff < 1.0 else pct(diff / with_pw if with_pw else 0)} |"
            )
        add("")
        add("「≤噪声」表示该格两次测量落进抖动范围（差值为负或接近 0）。实测：")
        add("")
        add("- 轻量载体（HEIC / `wav_pcm` 的 8 KiB 档）显示 13–20 ms 的固定增量，与 200 000 次 "
            "PBKDF2-HMAC-SHA256 的量级吻合；")
        add("- 图像 / 视频 / FLAC 载体上引擎本身要 0.5–6 s，KDF 被稀释到 0–6%，"
            "多次测量只能得到 ±100 ms 的噪声；")
        add("- **结论与方案预期相反**：内容域的瓶颈不是 KDF，而是代价图与整码流重编码。"
            "改用 `Credential::FileKey` 跳过 PBKDF2 只对轻量载体有意义。")
        add("")

    if io_cells:
        add("### 5.4 文件 API 开销")
        add("")
        add("32 KiB 载荷，5 次采样，含原子提交：")
        add("")
        add("| 场景 | 内存 嵌入 | 文件 嵌入 | 增量 | 内存 提取 | 文件 提取 | 增量 |")
        add("| :--- | ---: | ---: | ---: | ---: | ---: | ---: |")
        for io_cell in io_cells:
            mem = next(
                (c for c in main if c["carrier_id"] == io_cell["carrier_id"]
                 and c["payload_bytes"] == io_cell["payload_bytes"]),
                None,
            )
            if not mem:
                continue
            dw = stat(io_cell, "write", "median_ms") - stat(mem, "write", "median_ms")
            dr = stat(io_cell, "read", "median_ms") - stat(mem, "read", "median_ms")
            add(
                f"| `{mem['carrier_id']}` | {ms(stat(mem,'write','median_ms'))} "
                f"| {ms(stat(io_cell,'write','median_ms'))} | {delta(dw)} "
                f"| {ms(stat(mem,'read','median_ms'))} | {ms(stat(io_cell,'read','median_ms'))} "
                f"| {delta(dr)} |"
            )
        add("")

    add("### 5.6 为什么 FLAC 比 HEVC 还慢（实测拆解）")
    add("")
    add("结论先说：**不是 FLAC 容器比 HEVC 复杂，恰恰相反**。FLAC 帧结构（帧头 + "
        "Rice 残差 + 预测系数）远简单于 HEVC 的 CABAC / 帧内帧间预测 / 环路滤波。"
        "慢的是本项目的实现策略与载体体量，三个因素叠加：")
    add("")
    add("**(1) 一次 FLAC 嵌入要做 5 次全量解码，读取要做 2 次。** 从源码数出来的路径：")
    add("")
    add("| 阶段 | 源码 | 全量解码 |")
    add("| :--- | :--- | :--- |")
    add("| 校验扫描（PCM MD5 + 槽位统计） | `audio::embed_flac → flac::analyse` | 是，Pass 1 |")
    add("| 收集尾池与 body 选取 | `FlacCarrier::new`（注释即写 “Pass 2”） | 是，Pass 2 |")
    add("| 重建帧 CRC + STREAMINFO MD5 | `FlacCarrier::finalize → refresh_checksums` | 是，Pass 3 |")
    add("| 波形漂移对比（与原始载体逐帧比） | 同循环的 `parse_frame(cover_bytes, ...)` | 是，Pass 4 |")
    add("| 带 CRC 校验的成品复检 | `refresh_checksums` 末尾再次 `analyse(self.bytes)` | 是，Pass 5 |")
    add("")
    add("提取只需 `analyse_with_tails` + `FlacCarrier::new` 两遍。5:2 = 2.5，"
        "实测 32 KiB 档嵌入 6562 ms / 提取 2555 ms = **2.57**，吻合。"
        "单次全量解码约 1.3 s；容量探测只做一遍解码，实测 1545 ms（CLI，含进程与文件 I/O）。")
    add("")
    add("这些解码不是浪费，是**格式保持的正确性代价**：残差码字被原地改写后，"
        "帧 CRC 和 STREAMINFO 里的整段 PCM MD5 都必须重算；源码注释明确写着"
        "「多解一遍比发出一个解码结果与 STREAMINFO 不符的载体便宜」。"
        "解码器是项目内纯 Rust 实现（逐 bit 读 Rice 一元码 + 重建预测波形 + MD5），"
        "没有用 libFLAC / FFmpeg 的原生加速。")
    add("")
    add("**(2) 同内容对照：换成 WAV 就快 13 倍。** 用 ffmpeg 把 21 MiB FLAC "
        "（240.476 s / 44.1 kHz / 立体声 / 16 bit）转成同内容 41 MiB WAV，"
        "同一 32 KiB 载荷、CLI 端到端 3 次：")
    add("")
    add("| 载体 | 嵌入（3 次） | 提取 | 容量探测（≈一遍解码） |")
    add("| :--- | ---: | ---: | ---: |")
    add("| FLAC 21 MiB | 6759 / 6741 / 6775 ms | 2699 ms | 1537 / 1553 ms |")
    add("| WAV 41 MiB（同音频） | 498 / 536 / 524 ms | 225 ms | 128 / 126 ms |")
    add("")
    add("WAV 是扁平 PCM 数组，槽位直接下标访问，没有熵解码；FLAC 要逐位解 Rice 残差、"
        "重建 2100 万个采样点。两者用的是同一套音频 STC 嵌入算法，"
        "所以 13× 差距全部来自容器解码，不来自隐写算法。")
    add("")
    add("**(3) 报告里的 HEVC 与 FLAC 根本不是同等体量。** HEVC 载体是 "
        "1920×1080@60、**3.298 s** 的短片；FLAC 是 **240.5 s** 音频，时长 72.9×。"
        "而 32 KiB 档嵌入只差 3.23×（6562 vs 2029 ms）。换算后：")
    add("")
    add("| 口径 | FLAC | HEVC-MP4 | 比值 |")
    add("| :--- | ---: | ---: | ---: |")
    add("| ms / 秒媒体 | 27.3 | 615.2 | HEVC 贵 22.5× |")
    add("| ms / MiB | 324 | 209 | FLAC 贵 1.55× |")
    add("")
    add("另外 HEVC 引擎有 `StopCondition::TargetSlots` **早停窗口**（够用就停止录制 CABAC bin），"
        "且源码注明「never looks at pixels — it wants the bin stream」，只走熵层、不重建像素；"
        "FLAC 则必须走完整段媒体才能重算 MD5 / CRC。")
    add("")
    add("**对发布文档的措辞建议**：不要写「FLAC 比 HEVC 慢」，"
        "要写「FLAC 嵌入耗时近似与音频时长线性相关，常数项来自 5 遍全量解码；"
        "4 分钟立体声 16 bit 文件约 6 s」。若要压这个数字，"
        "方向是合并 Pass 1 / Pass 2、把漂移对比改成增量式、复用首遍解码的采样缓冲，"
        "而不是换隐写算法。")
    add("")
    add("## 6. 结论")
    add("")
    slowest = max(main, key=lambda c: stat(c, "write", "median_ms"))
    fastest = min(main, key=lambda c: stat(c, "write", "median_ms"))
    add(
        "1. **算法间差异显著但幅度因格式而异**：同一载体、同一 32 KiB 载荷下，PNG 的 "
        "MiPOD 比 HILL 慢 24%，JPEG 的 J-UNIWARD 比 UERD 慢 37%（见 §5.1）；"
        "而跨引擎（HEIC 88 ms vs FLAC 数秒）是两个数量级。发布文档必须按「格式 × 算法」给数字。"
    )
    add(
        f"2. **绝对耗时区间**：{ms(stat(fastest,'write','median_ms'))} ms"
        f"（`{fastest['carrier_id']}` @ {size_label(fastest['payload_bytes'])}）"
        f" ～ {ms(stat(slowest,'write','median_ms'))} ms"
        f"（`{slowest['carrier_id']}` @ {size_label(slowest['payload_bytes'])}）。"
        "代价图（HILL / S-UNIWARD / MiPOD）与全码流重编码（HEVC、FLAC）是两个数量级的差异来源。"
    )
    add(
        "3. **提取远快于嵌入**：提取不需要计算代价图，只做解码 + 定位 + AEAD，"
        "因此读取曲线明显更平。"
    )
    add(
        "4. **FLAC 是最慢的一项**：残差域嵌入需要整文件解码 + 重编码，21 MiB 载体单次约 6 s；"
        "该载体物理上限只有 98 KB。按方案的「换载体」规则，128 KiB 档改用 58 MiB Hi-Res 载体"
        "（上限 142 KB、占用 92%）单独测得嵌入 14.6 s / 提取 5.3 s，是全部 40 格中最慢的一格。"
        "该行只可与自身比较，不与 21 MiB 行做载荷维度对比。"
    )
    add(
        "5. **HEVC 短片的容量是硬约束**：3.3 s 1080p@60 在 High 档推荐上限只有 ~10 KB；"
        "32 KiB 已超 3 倍（Advisory），128 KiB 被引擎按槽位预算硬拒、自动降 Balanced 才写入。"
        "这类档位应换更长的片源，而不是对外承诺。"
    )
    add("")
    add("## 7. 复现与局限")
    add("")
    add("```bash")
    add("cd rust")
    add("cargo build --release --all-features --example perf_bench")
    add("./target/release/examples/perf_bench --domain content --reps 20 --warmup 2 --io \\")
    add("    --out ../temp/bench/results/content.json")
    add("# FLAC 128 KiB 需换载体，单独补测（约 8 分钟，日志建议 tee 到文件）")
    add("./target/release/examples/perf_bench --domain content --only flac128 --reps 20 \\")
    add("    --warmup 2 --out ../temp/bench/results/flac128.json \\")
    add("    2>&1 | tee ../temp/bench/results/flac128.log")
    add("C:/Home/Develop/venv/Scripts/python.exe ../scripts/bench/render_report.py")
    add("```")
    add("")
    add("局限：单机、单平台（Windows 10 / NTFS）、未做温控与频率锁定。内容域每次嵌入都"
        "重新解码载体并重算代价图，因此**同一载体不同算法之间的比较是可信的**，"
        "而跨载体（不同分辨率、不同时长）的绝对值不可直接比较。"
        "所有数字都**含** PBKDF2 密钥派生、**不含**磁盘 I/O。")
    add("")
    add("## 附录：原始数据")
    add("")
    add(f"`temp/bench/results/content.json` + `temp/bench/results/flac128.json`"
        f"（schema `{doc['schema']}`，合计 {len(doc['cells'])} 个 cell，含全部 20 个样本值）。")
    add("")
    add("FLAC 128 KiB 档是单独补测（`--only flac128`），载体换成 58 MiB Hi-Res 音轨，"
        "因此该行只可与自身比较，不与 `flac_residual` 的 21 MiB 行做载荷维度对比。")
    add("")
    return "\n".join(lines), svg


# ── Entry point ───────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(ROOT / "temp" / "bench" / "results"))
    ap.add_argument("--docs", default=str(ROOT / "docs"))
    args = ap.parse_args()

    results = Path(args.results)
    docs = Path(args.docs)
    docs.mkdir(parents=True, exist_ok=True)

    env = collect_env()
    env["generated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    struct_json = results / "structure.json"
    content_json = results / "content.json"

    if struct_json.exists():
        doc = json.loads(struct_json.read_text(encoding="utf-8"))
        md, svg = render_structure(doc, env)
        (docs / f"BENCH_STRUCTURE_{DATE}.md").write_bytes(md.encode("utf-8"))
        (docs / f"BENCH_STRUCTURE_{DATE}.svg").write_bytes(svg.encode("utf-8"))
        print(f"wrote docs/BENCH_STRUCTURE_{DATE}.md")

    if content_json.exists():
        doc = json.loads(content_json.read_text(encoding="utf-8"))
        extra = results / "flac128.json"
        if extra.exists():
            ex = json.loads(extra.read_text(encoding="utf-8"))
            known = {c.get("id") for c in doc["cells"]}
            merged = [c for c in ex.get("cells", []) if c.get("id") not in known]
            doc["cells"].extend(merged)
            print(f"merged {len(merged)} cells from {extra.name}")
        md, svg = render_content(doc, env)
        (docs / f"BENCH_CONTENT_{DATE}.md").write_bytes(md.encode("utf-8"))
        (docs / f"BENCH_CONTENT_{DATE}.svg").write_bytes(svg.encode("utf-8"))
        print(f"wrote docs/BENCH_CONTENT_{DATE}.md")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
