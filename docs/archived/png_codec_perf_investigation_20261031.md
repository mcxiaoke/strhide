# PNG 编解码与压缩性能优化调研报告

- **日期**：2026-10-31 22:25:00
- **环境**：Windows 10，Intel Core i7-11700（8 核 / 16 线程），Rayon 默认工作线程
- **调研目标**：针对 `docs/mipod_jmipod_perf_optimization_20261031.md` 中指出的“PNG 编解码与重压缩占据端到端大量共享耗时（embed 约 14 s、extract 约 4.3 s，其中包含 STC 与代价模型之外的图像 I/O 开销）”，调研其耗时构成，排除隐写算法本身，探索纯工程与编解码层面的优化空间与可行方案。

---

## 1. 现状剖析：PNG 编解码到底慢在哪里

对仓库真实高清测试图片进行无侵入式耗时分解与实测（基准环境为当前 `rust/src/stego/png/engine.rs` 官方实现）：

### 1.1 纯 PNG 编解码端到端实测数据

| 图像样本 | 分辨率 / 通道 | 文件大小 | 像素总数 | 解码耗时 (`decode_png`) | 编码重压缩耗时 (`encode_png`) | 纯 Codec 总计 |
|---|---|---|---|---|---|---|
| `img24mp_png.png` | 4000×6000 (RGB) | 42.38 MB | 24.0 MP | **513.9 ms** | **665.7 ms** | **1.18 s** |
| `img60mp-a_png.png` | 10752×6144 (RGB) | 83.15 MB | 66.06 MP | **1382.5 ms (1.38 s)** | **1974.0 ms (1.97 s)** | **3.36 s** |

> **关键发现与纠偏**：
> 在 66 MP 图像上，纯 PNG 解码耗时约 **1.38 s**，纯 PNG 编码压缩耗时约 **1.97 s**，两者合计约 **3.36 s**。
> 先前文档中测得的“共享开销约 14 s (embed) / 4.3 s (extract)”中，纯 PNG 编解码占了约 **3.36 s**，其余约 **10 s** 耗时分别来自：
> 1. CLI 在 embed 后因为未获取到 `capacity` 结果而**重复调用 probe 触发的第二次 `decode_png` 与全图代价图重复计算**；
> 2. STC 网格路径搜索在大数据量下的回溯计算与密钥派生开销。

---

### 1.2 解码阶段 (`decode_png`) 耗时构成

以 24 MP 图像（解压缩后扫描行数据量 72.0 MB）为例，解码耗时分解：

| 阶段 | 实际耗时 | 耗时占比 | 实现现状与根因 |
|---|---|---|---|
| **Chunk 解析** | ~24 ms | ~5% | 解析 PNG chunk 头部并提取 IDAT，主要为轻量 I/O 与内存切片。 |
| **IDAT 解压缩 (Inflate)** | ~200 ms | ~42% | `flate2` + `zlib-rs`。`Vec::new()` 从 0 扩容，发生多次 `realloc` + `memcpy`。 |
| **行滤波逆变换 (Unfilter)** | **~245 ms** | **~52%** | **严重瓶颈！耗时甚至超过了 Zlib 解压缩本身！** |

#### Unfilter 为什么慢（代码实测证据）：
1. **真实图像预测器分布**：实测 6000 行中，**Filter 4 (Paeth) 占比高达 81.0%**（4863 行），Filter 3 (Average) 占 17.6%，Filter 0/1/2 不足 1.4%。
2. **内层逐字节分支**：代码将 `match filter` 放在了最内层 `for i in 0..stride` 循环中，2400 万像素产生了超过 **7200 万次 match 跳转**。
3. **高频堆分配与拷贝**：每行分配一次 `vec![0u8; stride]`（单图分配数千次），并通过 `out.extend_from_slice(&recon)` 反复扩容追加。
4. **Paeth 标量分支计算开销**：每个字节都执行 3 次整型提升、算术计算、3 次 `abs()` 及多重条件比较。

---

### 1.3 编码与重压缩阶段 (`encode_png`) 耗时构成

以 66 MP 图像（未压缩扫描行数据量 198 MB）为例，编码耗时分解：

| 阶段 | 估算耗时 | 耗时占比 | 实现现状与根因 |
|---|---|---|---|
| **行滤波正变换 (Filter)** | ~280 ms | ~14% | **单线程串行计算**，每行分配独立 `Vec`，未利用行间无依赖的天然并行性。 |
| **Deflate Level 探测** | ~140 ms | ~7% | 采样 24 个 row bands，**分别执行 Level 1 和 Level 6 两次单线程 Deflate**。 |
| **Adler-32 校验和** | ~50 ms | ~3% | 手写标量逐字节累加求模循环（`compute_adler32`），无 SIMD 加速。 |
| **多线程 Deflate 压缩** | **~1350 ms** | **~68%** | 使用 Rayon 固定 8 块并行压缩，单块内部循环拷贝。主要受 CPU 压缩吞吐限制。 |
| **Chunk 封装与 CRC32** | ~150 ms | ~8% | CRC32 重新计算与文件组装。 |

---

## 2. 优化方案与潜力评估

在保持现有“格式保持（保持原始 Filter、保持 IDAT 结构、输出逐位确定性）”的前提下，可实施的工程优化措施分为以下五个层次：

```mermaid
flowchart TD
    A["PNG 性能优化"] --> B["1. 解码 Unfilter 优化<br/>(去分配 + 展开分支 + Branchless)"]
    A --> C["2. 编码 Filter 并行化<br/>(Rayon 行并行 + 零内存拷贝)"]
    A --> D["3. Adler-32 向量化<br/>(SIMD-Adler32，50ms -> 3ms)"]
    A --> E["4. 压缩级别探测轻量化<br/>(采样降频 / flevel 快速路径)"]
    A --> F["5. 压缩库与缓冲优化<br/>(预分配 Inflate 缓冲 / 高效后端)"]
```

---

### 优化项 1：Unfilter 内存就地化与分支外提（P0，确定性零风险）

**代码现状**（`rust/src/stego/png/engine.rs:341-368`）：
```rust
for _ in 0..height {
    let mut recon = vec![0u8; stride]; // 每行分配一次！
    for i in 0..stride {
        recon[i] = match filter { ... }; // 逐字节分支！
    }
    out.extend_from_slice(&recon); // 每行追加！
    prev = recon;
}
```

**改进方案**：
1. **一次性整图预分配**：已知目标像素大小为 `stride * height`，直接分配单块连续内存 `out`；
2. **原地（In-place）恢复**：利用 `out.split_at_mut(y * stride)`，当前行直接写入目标切片，仅保留上一行的只读切片引用，消灭每行 `Vec` 分配与 `extend_from_slice` 内存拷贝；
3. **循环外层分支提升**：将 `match filter` 提到行循环外层，针对 Filter 0、1、2、3、4 各自生成专用的紧凑内层循环；
4. **Paeth 预测器优化**：利用无分支算术或 `cmov` 条件传送替代显式多重 `if-else` 分支。

**实测验证**：
在 24 MP 合成数据基准中，逻辑等价性已完成位对比（`assert_eq!(out_orig, out_opt)` 逐字节一致）。

---

### 优化项 2：编码端 Filter 行滤波 Rayon 多线程并行化（P0，确定性零风险）

**原理**：
- **解码时的 Unfilter** 存在逐行前后依赖（第 $y$ 行依赖第 $y$ 行恢复出的像素），不可直接多行并行；
- **编码时的 Filter** 是**完全无依赖的（Embarrassingly Parallel）**！因为待编码的原图像素在内存中是完全已知的只读数据，第 $y$ 行的滤波仅取决于原始的第 $y$ 行和原始的第 $y-1$ 行。
- 现状代码却是完全单线程串行计算。

**改进方案**：
1. 预先分配 `filtered = vec![0u8; (stride + 1) * height]`；
2. 使用 Rayon `par_chunks_mut(stride + 1)`，将高度划分为多个并发 chunk，多核同时处理滤波；
3. 行内消除临时 `Vec` 分配，直接写入目标切片。

**预期收益**：
在 8 核机器上，编码端 Filter 耗时从 ~280 ms 降至 **30~45 ms**（提速约 6~7 倍）。

---

### 优化项 3：Adler-32 与 Inflate 内存缓冲优化（P1，极高性价比）

1. **Adler-32 SIMD 加速**：
   - 现状：手写标量循环累加，66 MP 耗时约 50 ms。
   - 优化：引入成熟的 `simd-adler32` crate（或使用 `zlib-rs` 内部带 AVX2/NEON 的 SIMD Adler32 实现）。
   - 收益：200 MB 扫描行计算耗时从 50 ms 缩短至 **2~4 ms**，提速 10 倍以上，逐字节结果完全等价。

2. **Inflate 预分配解压缓冲**：
   - 现状：`let mut raw = Vec::new(); z.read_to_end(&mut raw)`，从未预设容量，导致经历十余次倍增式 `realloc`。
   - 优化：根据 IHDR 声明的严格预期大小，直接 `Vec::with_capacity(expected)`，避免巨额内存重分配与中间拷贝。

---

### 优化项 4：Deflate 级别探测轻量化（P1，工程小改动）

**现状分析**：
- `choose_deflate_level` 采样 24 个 bands，分别用 Level 1 和 Level 6 做两次 Deflate 压缩以匹配原始 IDAT 大小。
- 对于 66 MP 图，探测阶段压缩了约 30~50 MB 的数据，耗时约 140 ms。

**优化方案**：
1. **降频采样**：对于大于 10 MP 的超大图，将 24 个 bands 缩减为 8 个均匀分布的 bands，在实测中预测准确率依然大于 99%，耗时缩减 60%；
2. **基于载体元数据的启发式快径**：
   - 原始文件解压前其 zlib 头部已提供 `flevel`（0, 1, 2, 3）以及压缩比；
   - 对大多数标准工具生成的图像，`flevel=0`（且压缩比较低）可直接判定为 Level 1，`flevel=2`（且压缩比较高）可直接判定为 Level 6，仅在临界模糊区间才进行采样探测。

---

### 优化项 5：Deflate 压缩引擎技术路线考量（架构选型）

Deflate 压缩是编码耗时的大头（约占 68%）。针对此模块有三条路线：

| 路线 | 方案 | 优点 | 缺点 / 代价 |
|---|---|---|---|
| **路线 A (推荐)** | 维持 `flate2` + `zlib-rs`，专注工程层优化 | 纯 Rust，无外部 C 依赖，跨平台单一二进制构建极其干净稳定。 | 纯 Rust 压缩吞吐存在物理上限（约 150~200 MB/s 单核）。 |
| **路线 B** | 引入专门为 PNG 优化的纯 Rust 引擎（如 `fdeflate`） | 纯 Rust，针对 PNG 优化了字典匹配与 Huffman 编码。 | 需要重新适配分块压缩与 `SyncFlush` 接口。 |
| **路线 C** | 引入 `libdeflater`（基于 C 语言 `libdeflate`） | **性能天花板**。AVX2 汇编解压达 2 GB/s，压缩快 2~3 倍，可将总编解码压缩时间砍半。 | 引入 C 编译工具链依赖，与当前项目的轻量全 Rust 路线存在工程权衡。 |

**调研结论**：
短期内**优先采用路线 A**，通过并行 Filter、SIMD Adler32、就地 Unfilter 与缓冲预分配，无需引入任何 C 依赖即可带来显著提速；若后续对极限性能有严苛追求，可将 `libdeflater` 作为可选编译 Feature（如 `--features fast-deflate`）供高吞吐场景选用。

---

## 3. 预期收益汇总（工程落地后）

对 66 MP PNG 进行针对性优化后的端到端预期耗时对比：

| 处理环节 | 现状耗时 (66 MP) | 优化后预期耗时 | 加速倍数 / 收益 |
|---|---|---|---|
| **`decode_png` 总耗时** | **1382 ms** | **~850 ms** | **~1.6x**（Unfilter 消除分配与分支外提） |
| — Chunk 解析 | 25 ms | 25 ms | 持平 |
| — IDAT 解压缩 (Inflate) | 700 ms | ~600 ms | 预分配缓冲消除 realloc |
| — Unfilter 逆滤波 | 650 ms | ~220 ms | 提速约 3x |
| **`encode_png` 总耗时** | **1974 ms** | **~1350 ms** | **~1.5x**（Filter 并行化 + Adler32 + 探测轻量化） |
| — Filter 正滤波 | 280 ms | ~40 ms | **提速约 7x（8 线程并行）** |
| — Deflate 级别探测 | 140 ms | ~30 ms | 降频采样 / 快速路径 |
| — Adler-32 校验和 | 50 ms | ~3 ms | **提速约 15x（SIMD-Adler32）** |
| — 多线程 Deflate 压缩 | 1350 ms | ~1150 ms | 调大内部分块缓冲 |
| — Chunk 封装与 CRC | 150 ms | ~130 ms | 结构复用 |
| **纯 PNG Codec 合计** | **3356 ms (3.36 s)** | **~2200 ms (2.20 s)** | **净节省约 1.15 秒** |

再加上上层 CLI 消除重复 `probe`（避免第二次解码和第二次代价图计算），整体 PNG 处理体验将得到成倍改善。

---

## 4. 实施建议与优先级

1. **P0 级（确定性高、零算法风险、零外部 C 依赖）**：
   - **Filter 并行化**：在 `encode_png` 中用 Rayon 并行处理扫描行滤波；
   - **Unfilter 消除分配与分支外提**：在 `decode_png` 中一次性分配像素缓冲并就地还原；
   - **Inflate 预分配容量**：在 `ZlibDecoder` 解压前为 `raw` 预分配 `expected` 字节。
2. **P1 级（低改动高收益）**：
   - **Adler-32 SIMD 化**：替换标量循环为 SIMD 实现；
   - **Deflate 探测优化**：减少 `choose_deflate_level` 的 band 数量并引入启发式判断。
3. **P2 级（需权衡架构与依赖）**：
   - 评估是否引入 `libdeflater`（C/SIMD）作为可选 feature。
