# 性能基线 / Performance

> 简明基线。**单位毫秒（ms），表中为 20 次采样的中位数**；详细方法、逐格方差与原始数据见 [结构域报告](docs/BENCH_STRUCTURE_20261107.md) 与 [内容域报告](docs/BENCH_CONTENT_20261107.md)。

环境：Intel i7-11700（8C/16T）· 32 GiB · Windows 10 · Rust 1.99.1 · `strhide 0.9.2/0.9.3` · `--release`（LTO）。内存 API 计时：固定密码/固定 seed/固定随机载荷，**含 PBKDF2，不含磁盘 I/O**。每格 2 次预热 + 20 次采样，写入后逐字节校验读回。

**一句话**：结构域 **20–46 ms**，几乎只由密钥派生决定；内容域 **0.06–14.6 s**，跨引擎差两个数量级，由「引擎/容器路径」决定数量级、由载荷大小决定同引擎内的斜率。

## 结构域（容器信封）

9 种载体（PNG / JPEG / WebP / WAV / MP4 / MKV / ZIP / PDF / PE）的取值范围；典型值为 9 个载体的中位数。

| 载荷 | 写入 (9 载体) | 读取 (9 载体) | 典型值 (中位数) | 相对 4 KiB |
| :--- | :--- | :--- | ---: | ---: |
| 4 KiB | 20.2 – 26.2 ms | 20.7 – 22.3 ms | 21.5 ms | 1.00× |
| 64 KiB | 20.8 – 27.1 ms | 20.1 – 21.9 ms | 22.7 ms | 1.05× |
| 256 KiB | 24.8 – 30.1 ms | 20.6 – 21.6 ms | 26.7 ms | 1.24× |
| 1 MiB | 39.4 – 46.1 ms | 21.9 – 22.9 ms | 42.1 ms | 1.96× |
| 4 MiB | 31.2 – 38.5 ms | 26.2 – 28.0 ms | 34.5 ms | 1.60× |

> 1 MiB 档比 4 MiB 还慢，是 `COMPRESSION_PROBE_MIN_BYTES = 1 MiB` 的压缩探测边界，不是测量误差；详见结构域报告 §5.2。

## 内容域（媒体隐写）

**下表所有耗时列单位均为毫秒（ms）**：每格为嵌入耗时，最后一列是 32 KiB 档的提取耗时。算法维度全量覆盖（PNG 3 种、JPEG 3 种、HEVC、WAV、FLAC）。

| 载体 / 算法 | 载体规模 | 1 KiB (ms) | 8 KiB (ms) | 32 KiB (ms) | 128 KiB (ms) | 提取 @32 KiB (ms) |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| PNG / HILL | 12 MP RGB | 1556 | 1678 | 1784 | 2580 | 1170 |
| PNG / S-UNIWARD | 12 MP RGB | 1753 | 1770 | 1775 | 2340 | 1199 |
| PNG / MiPOD | 12 MP RGB | 1951 | 2023 | 2213 | 2728 | 1610 |
| JPEG / UERD | 5760×3840 | 552 | 1502 | 1731 | 1859 | 373 |
| JPEG / J-UNIWARD | 5760×3840 | 1085 | 2037 | 2373 | 2438 | 387 |
| JPEG / J-MiPOD | 5760×3840 | 1038 | 1961 | 2193 | 2332 | 359 |
| HEVC / MP4 | 1080p60 · 3.3 s | 1296 | 1448 | 2029 | 2947 | 649 |
| HEVC / HEIC | 4032×3024 | 88 | 111 | 240 | 601 | 47 |
| WAV / PCM | 47 MiB · 240 s | 60 | 129 | 387 | 1390 | 124 |
| FLAC / residual | 21 MiB · 240 s | 5943 | 6099 | 6562 | — | 2555 |

> FLAC 的 128 KiB 档在 21 MiB 载体上放不下：换 58 MiB Hi-Res 载体后嵌入 14 609 ms / 提取 5 271 ms，不与本表其它行做载荷维度比较。HEVC 短片的 128 KiB 档超出 High 安全档位，实测已降为 Balanced。

## 主要与什么相关

- **结构域**：0.83 的 Spearman 相关来自载荷档位（整体单调，1 MiB 台阶除外），但 4 KiB → 4 MiB 只从 21.5 ms 到 34.5 ms（**1.6×**）。同一载荷档内载体大小的相关系数 r = 0.65–0.74，不过绝对差只有 3–6 ms。**真正的主导项是固定的 PBKDF2 密钥派生（100 000 次，约 20 ms）**，它占 4 KiB 档的 ~95%；载荷每 +1 MiB 约 +3 ms，载体大小几乎不影响。
- **内容域**：跨引擎看，载体字节数与 32 KiB 档耗时 r = -0.03（**无相关**），分辨率同样无预测力（12 MP PNG ≈ 1.8 s，12 MP HEIC 仅 0.24 s，22 MP JPEG ≈ 1.7–2.4 s），时长也不单独预测（240 s WAV 0.39 s vs 3.3 s HEVC 2.0 s）。**决定数量级的是引擎/容器路径**：要不要重算代价图、要不要全量熵解码、要不要多次重算 CRC/MD5。
- **内容域内部**：固定引擎后，载荷大小才是主要变量——1 KiB → 最大档使耗时变化 1.1×（FLAC，仅测到 32 KiB）到 23×（WAV，测到 128 KiB）；载体规模/时长在同引擎内明显正相关（固定 32 KiB：21 MiB FLAC 6.8 s → 58 MiB FLAC 11.8 s）。
- **读取侧**：结构域读取与写入同量级（都要一次 KDF）；内容域提取只需嵌入的 16–73%（不重算代价图）。

**逐项判定**（跨引擎比较时）：

- **载荷大小**：结构域弱（每 MiB 约 +3 ms）；内容域**同一引擎内**强（1.1×–23×）。
- **载体大小**：结构域极弱（3–6 ms）；内容域跨引擎无相关（r = -0.03），同一引擎内正相关（21 MiB → 58 MiB FLAC：6.8 s → 11.8 s）。
- **载体分辨率**：只在图像引擎内部影响固定成本，跨引擎无预测力（同为 12 MP：HEIC 0.24 s vs PNG 1.8 s）。
- **载体时长**：音频/视频引擎内部正相关，跨引擎无预测力（240 s WAV 0.39 s vs 3.3 s HEVC 2.0 s）。
- **真正的主因**：结构域 = 固定 PBKDF2；内容域 = 引擎/容器路径（代价图重算、全量熵解码、多次 CRC/MD5 复检）。

## 复现

```bash
cd rust
cargo build --release --all-features --example perf_bench
./target/release/examples/perf_bench --domain structure --reps 20 --warmup 2 --io \
    --out ../temp/bench/results/structure.json
./target/release/examples/perf_bench --domain content --reps 20 --warmup 2 --io \
    --out ../temp/bench/results/content.json
./target/release/examples/perf_bench --domain content --only flac128 --reps 20 \
    --warmup 2 --out ../temp/bench/results/flac128.json 2>&1 | tee ../temp/bench/results/flac128.log
C:/Home/Develop/venv/Scripts/python.exe ../scripts/bench/gen_summary.py
C:/Home/Develop/venv/Scripts/python.exe ../scripts/bench/render_report.py
```

