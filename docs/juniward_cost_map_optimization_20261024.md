# J-UNIWARD 代价图：P0–P2 性能优化与对齐修正

- 日期：2026-10-24
- 范围：`stego/jpeg/cost/juniward.rs`、`stego/jpeg/cost/precover.rs`（反量化并行化）、
  `Cargo.toml`（rayon 提升为 `stego` feature 依赖）；不动线格式、不动 trait、不动提取路径
- 结论：**端到端 6.7×（24 MP）/ 11.2×（100 MP）**，对 UERD 的差距从 10× 缩到 **1.4–2.5×**；
  同时修正了一处使整张代价图偏移一个块的对齐缺陷

---

## 1. 问题

J-UNIWARD 作为第二套 JPEG 代价模型加入后，实测比 UERD 慢 10 倍以上。24 MP 载体、1 KiB 载荷：

| | UERD | J-UNIWARD | 倍数 |
| :--- | ---: | ---: | ---: |
| embed（CLI 端到端） | 1.02 s | 10.46 s | 10.3× |
| extract | 0.39 s | 0.45 s | — |

提取侧与算法完全无关（`extract_jpeg` 不接收 cost model），所以全部代价都在嵌入侧。

## 2. 诊断

### 2.1 耗时分解

用独立的复刻程序（24 MP / 375 000 个亮度块 / 单线程）逐阶段计时：

| 阶段 | 耗时 | 占比 |
| :--- | ---: | ---: |
| `separable_residual` + `recip`（3 band，f64 + 逐像素 clamp） | 0.90 s | 3.5 % |
| `gather_patch`（逐元素 clamp） | 0.32 s | 1.3 % |
| **内积主循环** | **24.5 s** | **95 %** |

### 2.2 根因

旧实现对每个块的 63 个 AC 系数**各重扫一遍同一个 23×23 窗口**：

```text
3 band × 375 000 块 × 63 系数 × 529 = 3.7e10 次乘加
```

这 63 次扫描读的是同一块内存，只是权重不同。而 `|ΔR| = |u_i| ⊗ |v_j|`（DCT 基与
Daubechies-8 滤波器都可分离），所以整个扫描是一个**双线性型**：

```text
S[i][j] = u_iᵀ · P · v_j  =  u_iᵀ · (P · V)      P = 权重窗，23×23
```

先算 `T = P·V`（23×8×23 = 4232 次乘加）再算 `Uᵀ·T`（8×8×23 = 1472），合计 **5704**，
而不是 `63×23×23 = 33327`：**5.8× 的削减，结果等价**。

### 2.3 顺带发现的对齐缺陷

旧 `footprint()` 用 `idx = ky + SUPPORT_START + a = ky + a - 7`，而
`separable_residual()` 的卷积中心是 `- HALF`，两者相差 8：

```text
patch 第 ky 行 = 绝对行 y₀ + SUPPORT_START + ky
ΔR 在绝对行 y 读 Δplane[y + a - HALF]，而 Δplane 只在块内 [0, N) 非零
⇒ 对应的基函数行 = (y₀ + SUPPORT_START + ky) + a - HALF - y₀
                 = ky + a - (2·HALF - 1) = ky + a - 15
```

旧代码少了 8，后果是 **`|u|` 的非零支撑落在 `ky ∈ [0,14]`（15 个 tap）而不是 `[0,22]`（23 个）**，
整张代价图用**偏移一个块（8 像素）的邻域**来定价。

用独立的二维残差数值对拍确认：旧公式相对误差 1.0（完全错位），修正后 5e-16（机器精度）。
原有的 `tests/jpeg_juniward.rs` 只断言了定性属性（平坦块更贵、DC 不变、与 UERD 不同），
没有与真实残差对拍，所以没能发现。

**注意**：单独修这个缺陷会让旧实现从 25.5 s 涨到 38 s（非零 tap 从 15 变 23）。
双线性重排不受影响，所以两者必须一起改——先修再优化会得到一个"正确但更慢"的中间态。

## 3. 实施

### P0：对齐修正 + 双线性重排

- `BASIS_SHIFT = 2·HALF - 1`，`footprint()` 改为 `idx = ky + a - BASIS_SHIFT`，并把推导写进常量文档。
- 内层改为 `T = P·V` → `S = Uᵀ·T` 两趟，`mid` 按 `mid[j][ky]` **转置**存储，让第二趟两个操作数都连续。

### P1：预 pad 去 clamp + 四路展开

- 新增 `reciprocal_plane()`：直接把 `1/(|R|+σ)` 写进一块**预填充边界**的 f32 平面
  （左/上 7 列行、右/下 8 列行，边界复制，与 `separable_residual` 的 clamp 语义一致）。
  内部只做一次除法，边界靠 `fill` / `copy_within` 复制。
- `gather()` 变成纯 `copy_from_slice`，没有任何 clamp；`PAD = 24`（`SUPPORT` 向上取整到 4 的倍数），
  超出 `SUPPORT` 的列与最后一行零填充，内积按 4 lane 展开。
- 权重平面跨 band 复用同一块缓冲，工作集不随 band 数增长。

数值差异只来自 f32 累加顺序：最坏相对误差 **3.08e-7**（与 f64 参考对拍），
远小于代价图排序所需的精度，且 J-UNIWARD 代价**只在嵌入端计算一次**（`engine.rs:573` 是唯一调用点），
不存在 embed/extract 跨端一致性约束。

### P1.5：AVX2/FMA 运行时派发

- `DotKernel` trait 两个实现：`ScalarKernel`（4 累加器，可移植）与 `Avx2Kernel`（8 宽 FMA）。
- **按类型单态化，不用函数指针**：每块要调用 `PAD*8 + 63 = 255` 次内积，
  间接调用 2.9e8 次的开销会吃掉全部收益。
- 派发在 `compute_cost` 入口做一次：`is_x86_feature_detected!("avx2") && ("fma")`，
  非 x86_64 平台直接走标量分支。不用 `-C target-cpu=native`，二进制保持可移植。
- 与 `stego/coding/stc.rs` 已有的 AVX2 内核同一套模式（那里是每列一次调用、摊得薄；
  这里必须内联，所以多了包装层）。

### P2：多线程

并行粒度**只能到块层，不能到 band 层**：band 层并行会让 3 份权重平面同时驻留
（100 MP 每份 404 MB）叠加 3 份 f64 残差（每份 805 MB），峰值突破 3 GB。
所以三个 band 仍然串行，band 内部（残差、倒数平面、块扫描）全部并行：

| 阶段 | 并行方式 |
| :--- | :--- |
| `separable_residual` | 两趟 1D 卷积都按行 `par_chunks_mut(pw)`；垂直趟只读邻行，按行切不改变任何浮点运算 |
| `reciprocal_plane` | 内部行按行并行（每行含自己的左右边界），上下边界行在其后串行复制 |
| 块扫描 | `par_chunks_mut(SWEEP*64)` 按 512 块一批；`for_each_init` 给每个任务自己的 `patch`/`mid` 暂存 |
| `decompress_luma` | 按 8 行带 `par_chunks_mut(pw*N)`；块序是 MCU 交错，先按块行分桶再分发 |

`decompress_luma` 在 `precover.rs`，被 UERD 的 cost polarization 共用。这里**只是并行化，
不改任何算术**（每块独立 IDCT、写入位置不变），所以对 UERD 的输出没有影响；
它默认 `polarize_weight = 1.0`（关闭），本来也不会走到这条路径。

AVX2 与 rayon 的组合要小心：rayon 的任务闭包是普通函数，进去会丢掉 `target_feature` 上下文。
所以整个扫描的 kernel 放进带 `#[target_feature(enable = "avx2,fma")]` 的 `sweep_avx2`，
每个任务调用它一次（512 块），而不是每个窗口一次——一次任务级调用可以摊薄，
且 `sweep_kernel` 泛型内联后 intrinsics 才能在正确上下文展开。

因为每个块独占 `costs[bi*64 .. bi*64+64]`、没有跨块归约，结果与线程数**逐位无关**；
`cost_map_is_deterministic_across_runs` 用 `to_bits()` 逐元素锁住这一点。

`rayon` 从 `dev-dependencies` 提升为 `stego` feature 下的可选依赖。

## 4. 实测

环境：Windows 10、16 逻辑核、`cargo build --release`（默认 target-cpu，未开 `-C target-cpu=native`）、
CLI 端到端（含解码、STC、编码、落盘）。单次测量，噪声约 ±5%，关键点用 5 次最小值复核过。

### 4.1 分辨率（载荷 1 KiB）

| 载体 | 像素 | UERD | 优化前 | P0+P1 | +AVX2 | +P2 | 累计 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| img24mp | 24.0 MP | 1.07 s | 10.20 s | 3.56 s | 2.49 s | **1.53 s** | 6.7× |
| img32mp | 32.7 MP | 0.67 s | 13.21 s | 4.08 s | 2.70 s | **1.38 s** | 9.6× |
| img48mp | 50.3 MP | 1.19 s | 20.45 s | 6.43 s | 4.47 s | **2.39 s** | 8.6× |
| img60mp-a | 66.1 MP | 1.52 s | 26.85 s | 8.36 s | 5.69 s | **3.32 s** | 8.1× |
| img100mp | 100.7 MP | 1.47 s | 40.85 s | 12.11 s | 8.34 s | **3.66 s** | 11.2× |

单位像素成本 0.41 → **0.036–0.064 s/MP**。
对 UERD 的倍数：24 MP 1.43×、32 MP 2.06×、48 MP 2.01×、66 MP 2.18×、100 MP 2.49×。

100 MP 的倍数最高，是因为它的 STC 与解码占比相对低——同样的代价图开销被摊在更大的图上，
而 UERD 那 1.47 s 里几乎全是 I/O。

### 4.2 载荷（24 MP）

| 载荷 | UERD | 前 | 后 | 对 UERD 倍数（前→后） |
| :--- | ---: | ---: | ---: | ---: |
| 512 B | 0.91 s | 10.37 s | **1.35 s** | 11.4× → 1.48× |
| 1 KiB | 0.99 s | 10.46 s | **1.43 s** | 10.6× → 1.44× |
| 4 KiB | 1.41 s | 10.94 s | **1.87 s** | 7.8× → 1.33× |
| 16 KiB | 2.48 s | 11.87 s | **2.89 s** | 4.8× → 1.17× |
| 64 KiB | 2.47 s | 11.98 s | **2.97 s** | 4.9× → 1.20× |
| 256 KiB | 2.75 s | 12.35 s | **3.21 s** | 4.5× → 1.17× |
| 512 KiB | 4.68 s | 14.28 s | **5.07 s** | 3.1× → 1.08× |
| 900 KiB | 7.43 s | 17.00 s | **8.60 s** | 2.3× → 1.16× |

载荷越大，STC 越主导，两者越接近。**满载荷下 J-UNIWARD 只比 UERD 慢 8–16%**，
已经不构成选择障碍。

### 4.3 代价图本身的耗时

扣掉共享部分（UERD 同载荷的耗时；UERD 的代价图只有 10 ms 量级，约等于共享开销）：

| 场景 | 前 | P0+P1 | +AVX2 | +P2 | 累计 |
| :--- | ---: | ---: | ---: | ---: | ---: |
| 24 MP + 1 KiB | 9.44 s | 2.44 s | 1.45 s | **0.44 s** | **21.5×** |

拆开看：内积 8.1 s → 0.29 s（单线程，28×），残差 0.90 s → 0.12 s，反量化 0.27 s → 0.05 s。

### 4.4 为什么 16 线程只有 3.3× 而不是 16×

P2 单独贡献：代价图 1.45 s → 0.44 s（3.3×）。低于核数，有三个结构性原因：

1. **band 串行**：内存约束决定了三个 band 不能同时展开，只有 1/3 的工作量能并起来。
2. **阶段间同步**：每个 band 内 residual → reciprocal → sweep 三道屏障，×3 band = 9 次 fork-join。
   24 MP 下单阶段只有 0.1–0.3 s，同步与调度占比被放大。
3. **内存带宽**：残差每 band 读 402 MB、写 805 MB，是纯带宽型代码。

按阿姆达尔定律，即使块扫描接近无限快，band 串行 + 屏障也把上限定在 3–4× 附近——
实测已经接近这个上限。继续压缩只能改算法（例如把三个 band 融合成一趟、只保留一份权重），
不再属于并行范畴。

## 5. 正确性

- 新增单测 `footprint_matches_the_real_residual`：对 3 个 band × 3 个系数，
  用真实的 `separable_residual` 二维残差与 `|u|⊗|v|` 逐点对拍，容差 1e-6。
  这是对齐缺陷的回归守卫。
- 新增单测 `textured_carrier_stays_inside_the_cap`：纹理载体上所有代价有限、为正、不超过 wet cap、
  DC 恒为 wet。
- 新增单测 `dot_kernels_agree`：同一组 24 维向量，标量与 AVX2 内核结果需在 1e-5 相对误差内，
  防"换台机器 build 出不同代价图"。
- 新增单测 `cost_map_is_deterministic_across_runs`：同一输入两次计算，`to_bits()` 逐元素相等，
  锁住并行不引入调度依赖。
- 新增单测 `decompress_places_every_block`：4:2:0 的 MCU 交错块序下，
  每个块必须落在自己的网格单元上（分桶漏块会留下 0 而不是 DC 电平）。
- 端到端：6 张高分辨率载体 × 8 种载荷，全部 `roundtrip=OK`。
- 质量抽查：24 MP 上用 1 KiB 载荷，嵌入后 `scan` 风险 0/100；900 KiB 满载荷同样是 0/100。
  **内置 DCT 检测器对该载荷下的 J-UNIWARD 不敏感**（`docs/stego_remediation_plan_20261023_1815.md`
  已记录这一检测器缺口），因此这不是"抗检改善"的证据，只是没有退化。
  修正前后的 stego 文件大小从 14 696 019 变为 14 838 507 字节（+1.0%）。
- `cargo test`：**567 passed / 0 failed**（19 个 test binary 全绿）；
  `batch_corpus` 12.5 s 通过；`batch_stego` 86.7 s 通过；
  `cargo fmt --check` 与 `cargo clippy --all-targets -D warnings` 干净。

顺带修了 CLI 帮助里两处算法名拼写错误（`-a juniwward` → `-a juniward`，
`src/i18n/messages.rs` 的中英文示例），照着原示例敲会直接报 `Unknown JPEG stego algorithm`。
同名的 4 个测试函数也一并改正。

## 6. 未做（P3）

| 项 | 改动 | 预期 | 风险 |
| :--- | :--- | :--- | :--- |
| **P3a residual** | `separable_residual` 预 pad 去 clamp + f32 化 | 0.12 s → 0.06 s | 中 |
| **P3b decompress** | `precover` 的 f64 8×8 IDCT 向量化 | 0.05 s → 0.02 s | 低（已并行，仅剩单块计算） |

P2 之后这两项的**绝对收益都已经很小**（合计约 0.1 s，占 24 MP 端到端的 7%）。
真正的剩余成本是引擎侧：JPEG 解码、STC 求解、熵编码、落盘，24 MP 下约 1.0 s，
与算法无关，UERD 付的是同一笔。

也就是说：**J-UNIWARD 的代价图已经从"比 UERD 慢 9.4 s"降到"慢 0.44 s"，
继续压这块的边际收益接近零。** 如果还要再快，方向是引擎侧（例如 STC 的多线程化），
不再是代价模型。

## 7. P3 的风险（若仍要做）

### P3a（residual）——中风险，边界语义是唯一的雷

去 clamp 必须严格保持 edge-replicate。现有 `footprint_matches_the_real_residual`
只在块 (16,16) 取值，**没有覆盖最外圈块**，改之前应先补一条边界用例，
否则边界一圈的代价会静默变化，而这类变化不会让任何往返测试失败。
f32 化本身影响很小：残差是像素域差分，f32 相对误差 1e-7，`σ = 1/64` 时低幅值位置由 σ 主导。

### P3b（decompress）——低风险，但仍有跨模型耦合

`decompress_luma` 同时服务 J-UNIWARD 的 `compute_cost` 和 UERD 的 `direction_bias`
（cost polarization）。它现在已经是纯并行、数值不变。若进一步改 f32 或换 AAN 快速 DCT，
就会改变数值路径：

- f32 化会同时改变 UERD 在开启 polarization 时的方向偏好；
- AAN 的乘法数从 1024 降到约 200，但舍入位置全变，需要与当前实现逐点对拍。

只做 SIMD 化（保持 f64 与现有算式）则安全得多。

## 8. 复现

```bash
cd rust
cargo fmt && cargo clippy --all-targets -D warnings
cargo test
cargo test --test batch_corpus -- --ignored
cargo test --test batch_stego -- --ignored
```

基准脚本：`temp/bench_jw_cli.py`（分辨率/payload/复现性三阶段），
原始数据在 `temp/benchout/bench-{res,pay}-before.json`（优化前）、
`bench-{res,pay}-p1.json`（P0+P1）与 `bench-{res,pay}.json`（当前）。
微基准与数值对拍：`temp/jwbench2.rs`、`temp/jwverify.rs`、`temp/verify_juniward_align.py`。
