# Stego 各步骤性能瓶颈评估与 Profile 分析报告

- **日期**：2026-10-24
- **测试环境**：Windows 10 x64, AMD64, Rust 1.86.0 (edition 2024), Profile `release` (opt-level = 3, lto = true)
- **分析工具**：`rust/examples/stego_profile.rs`（支持 `-s/--size`, `-a/--algo`, `-h/--help` 自定义载荷与载体）
- **测试载荷**：`64.00 KiB`（65,536 字节高熵测试载荷）
- **测试载体**：
  - **PNG 大图**：`temp/profile_test/test_large.png`（3106 × 4774，4 通道 RGBA，**14.83 MPixels**，未压缩像素 59.3 MB，文件 17.68 MB）
  - **JPEG 大图**：`temp/profile_test/test_large.jpg`（3072 × 4096，3 通道 YCbCr，**12.58 MPixels**，文件 16.73 MB）

---

## 1. 最终实测数据（优化后：方案 1 Rayon 并行 ≤ 8 线程 + 方案 2 SIMD `zlib-rs`）

> 载体：14.83 MPixels (3106×4774 RGBA)，载荷：64 KiB

| 步骤阶段 | HILL 耗时 | HILL 占比 | S-UNIWARD 耗时 | S-UNIWARD 占比 | 阶段优化效果与说明 |
|---|---|---|---|---|---|
| **Step 1: PNG 解码与反滤波** | 215.36 ms | 9.3% | 215.36 ms | 7.6% | 解析 chunks、zlib-rs 解压、还原 RGBA 扫描线 |
| **Step 2: 代价模型计算** | 328.04 ms | 14.2% | 953.11 ms | 33.7% | HILL 3 级卷积 vs S-UNIWARD 双向小波多带变换 |
| **Step 3: 方向代价计算** | 182.05 ms | 7.9% | 32.72 ms | 1.2% | HILL 局部 8 邻域加权 vs S-UNIWARD 对称模型快速通道 |
| **Step 4: 重新滤波与 Deflate 压缩** | **384.39 ms** | **16.6%** | **384.39 ms** | **13.6%** | **从原 4058 ms 降至 384 ms（提速 10.56 倍！）** |
| **Step 5: 排序与 STC 矩阵编码** | ~1.19 s | 51.9% | ~1.24 s | 43.9% | 1483 万像素全序排序与状态网格求解 |
| **嵌入端总计（Embed Total）** | **2.309 s** | 100% | **2.826 s** | 100% | **从原 5.81s/6.34s 降至 2.31s/2.83s（总耗时减少 3.5 秒）** |
| **提取端总计（Extract Total）** | **1.416 s** | — | **2.070 s** | — | **提取往返校验 100% 成功！** |

---

## 2. JPEG 频域算法对比（UERD vs J-UNIWARD）

> 载体：12.58 MPixels (3072×4096 YCbCr)，载荷：64 KiB

| 步骤阶段 | UERD 嵌入 | UERD 占比 | J-UNIWARD 嵌入 | J-UNIWARD 占比 | 阶段核心说明 |
|---|---|---|---|---|---|
| **Step 1: DCT 系数解析 (`dct_io`)** | 129.86 ms | 12.7% | 129.86 ms | 10.4% | JPEG marker 解析、Huffman 熵解码恢复 DCT 系数 |
| **Step 2: 几何结构分析** | 6.63 ms | 0.6% | 6.63 ms | 0.5% | MCU 块几何布局分析 |
| **Step 3: 代价模型计算** | **33.97 ms** | 3.3% | **267.96 ms** | 21.4% | UERD 频域能量平滑 (34ms) vs J-UNIWARD 多线程小波卷积 (268ms) |
| **Step 4: DCT 系数写回 (`dct_io`)** | 150.73 ms | 14.8% | 150.73 ms | 12.0% | Huffman 熵编码写回 JPEG 码流 |
| **Step 5: STC 动态规划 / KDF** | **705.17 ms** | **69.1%** | **704.18 ms** | **56.2%** | **64 KiB（52.4 万 bits）STC Trellis Viterbi 动态规划求解** |
| **嵌入端总计（Embed Total）** | **1.020 s** | 100% | **1.253 s** | 100% | 两者总耗时差距仅为代价模型本身的差值（~234ms） |
| **提取端总计（Extract Total）** | **272.65 ms** | — | **280.72 ms** | — | **两者完全一致！JPEG 提取端走固定几何网格，无需运行代价模型！** |

---

## 3. 落地实施总结

1. **方案 2（底层 SIMD 引擎 `zlib-rs`）**：
   - 在 `Cargo.toml` 中显式开启 `flate2 = { version = "1.1.10", default-features = false, features = ["zlib-rs"] }`。
   - 保持 100% 纯 Rust 静态编译，单核吞吐量提升近 3 倍。
2. **方案 1（Rayon 多线程分块 Deflate）**：
   - 限制最大工作线程为 8（`rayon::current_num_threads().clamp(1, 8)`）。
   - 按整行边界均匀分块，前 $k-1$ 块使用 `SyncFlush` 字节对齐，第 $k$ 块使用 `Finish` 产生终结块。
   - 组装标准 RFC 1950 zlib 头部与 Adler-32 校验和。小于 2 MB 时零开销直通单线程。
3. **效果综合**：
   - PNG Deflate 压缩耗时从 **4.06 秒压至 0.38 秒（提速 10.56 倍）**。
   - 原本占据 70% 的绝对瓶颈被彻底清除，PNG Embed 总耗时压缩逾 60%。
