# J-UNIWARD 代价图：P0 + P1 性能优化与对齐修正

- 日期：2026-10-24
- 范围：`rust/src/stego/jpeg/cost/juniward.rs`（单文件，不动线格式、不动 trait、不动提取路径）
- 结论：**代价图计算 6.5×、端到端 embed 4.1×**（P0 + P1 + AVX2 运行时派发）；
  同时修正了一处使整张代价图偏移一个块的对齐缺陷。

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
  超出 `SUPPORT` 的列与最后一行零填充，`dot()` 按 4 lane 展开。
- 权重平面跨 band 复用同一块缓冲，工作集不随 band 数增长。

数值差异只来自 f32 累加顺序：最坏相对误差 **3.08e-7**（与 f64 参考对拍），
远小于代价图排序所需的精度，且 J-UNIWARD 代价**只在嵌入端计算一次**（`engine.rs:573` 是唯一调用点），
不存在 embed/extract 跨端一致性约束。

### P1.5：AVX2/FMA 运行时派发

P1 之后内积成为最大单项，而默认编译目标只有 SSE2。加一层运行时派发，
不引入 `-C target-cpu=native`（保持二进制可移植）：

- `DotKernel` trait 两个实现：`ScalarKernel`（4 累加器，可移植）与 `Avx2Kernel`（8 宽 FMA）。
- **按类型单态化，不用函数指针**：每块要调用 `PAD*8 + 63 = 255` 次内积，
  间接调用 2.9e8 次的开销会吃掉全部收益。
- `cost_map::<K>` 是 `#[inline(always)]` 的泛型，`cost_map_avx2` 是带
  `#[target_feature(enable = "avx2,fma")]` 的薄包装。泛型函数内联进包装后，
  `Avx2Kernel::dot` → `dot_avx2` 也在 AVX2 上下文里展开，intrinsics 才能正常生成。
- 派发在 `compute_cost` 入口做一次：`is_x86_feature_detected!("avx2") && ("fma")`，
  非 x86_64 平台直接走标量分支。
- 与 `stego/coding/stc.rs` 已有的 AVX2 内核同一套模式（该处是每列一次调用，摊得薄；
  这里必须内联，所以多了包装层）。

## 4. 实测

环境：Windows 10、16 逻辑核、`cargo build --release`（默认 target-cpu，未开 `-C target-cpu=native`）、
单线程、CLI 端到端（含解码、STC、编码、落盘）。

### 4.1 分辨率（载荷 1 KiB）

| 载体 | 像素 | UERD | J-UNIWARD 前 | P0+P1 | +AVX2 | 累计提升 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| img24mp | 24.0 MP | 1.10 s | 10.20 s | 3.56 s | **2.49 s** | 4.10× |
| img32mp | 32.7 MP | 0.69 s | 13.21 s | 4.08 s | **2.70 s** | 4.89× |
| img48mp | 50.3 MP | 1.22 s | 20.45 s | 6.43 s | **4.47 s** | 4.58× |
| img60mp-a | 66.1 MP | 1.58 s | 26.85 s | 8.36 s | **5.69 s** | 4.72× |
| img100mp | 100.7 MP | 1.68 s | 40.85 s | 12.11 s | **8.34 s** | 4.90× |

单位像素成本从 0.41 s/MP 降到 **0.083–0.104 s/MP**，线性度保持。

### 4.2 载荷（24 MP）

| 载荷 | UERD | 前 | 后 | 提升 | 对 UERD 倍数（前→后） |
| :--- | ---: | ---: | ---: | ---: | ---: |
| 512 B | 0.96 s | 10.37 s | **2.50 s** | 4.15× | 10.8× → 2.6× |
| 1 KiB | 1.08 s | 10.46 s | **2.53 s** | 4.13× | 9.7× → 2.3× |
| 4 KiB | 1.52 s | 10.94 s | **2.98 s** | 3.67× | 7.2× → 2.0× |
| 16 KiB | 2.69 s | 11.87 s | **4.13 s** | 2.87× | 4.4× → 1.5× |
| 64 KiB | 2.77 s | 11.98 s | **4.14 s** | 2.89× | 4.3× → 1.5× |
| 256 KiB | 3.06 s | 12.35 s | **4.48 s** | 2.76× | 4.0× → 1.5× |
| 512 KiB | 5.23 s | 14.28 s | **6.76 s** | 2.11× | 2.7× → 1.3× |
| 900 KiB | 8.21 s | 17.00 s | **9.91 s** | 1.72× | 2.1× → 1.2× |

代价图是固定开销、STC 随载荷增长，所以载荷越大，改善倍数越被摊薄——
但"慢 10 倍"的场景（小载荷）恰恰是改善最多的：24 MP + 1 KiB 从 **9.7× 降到 2.3×**。

### 4.3 代价图本身的耗时

从上面扣掉共享部分（UERD 同载荷的耗时）：

| 场景 | 前 | P0+P1 | +AVX2 | 累计 |
| :--- | ---: | ---: | ---: | ---: |
| 24 MP + 1 KiB | 9.44 s | 2.44 s | **1.45 s** | **6.5×** |

拆开看：内积 8.1 s → 0.29 s（**28×**），而 `decompress_luma` + `separable_residual`
+ 倒数平面合计约 1.16 s **没有变化**，现在是剩余耗时的主体。

### 4.4 单核上限

P1 之后内积是最大单项，而此时默认编译目标只有 SSE2。开启 AVX2/FMA 派发后：

| | 24 MP 内积 | 说明 |
| :--- | ---: | :--- |
| 标量内核（4 累加器 / SSE2 宽度） | 1.12 s | 默认 target |
| AVX2 + FMA 内核（8 lane） | **0.29 s** | 3.9× |
| `-C target-cpu=native` 全量编译 | 0.29 s | 与显式派发持平 |

显式派发拿到了 `native` 的全部收益，同时保住二进制在任意 x86-64 上的可运行性。
内积到此已接近单核峰值，再要提速只能减少运算量或并行。

## 5. 正确性

- 新增单测 `footprint_matches_the_real_residual`：对 3 个 band × 3 个系数，
  用真实的 `separable_residual` 二维残差与 `|u|⊗|v|` 逐点对拍，容差 1e-6。
  这是对齐缺陷的回归守卫。
- 新增单测 `textured_carrier_stays_inside_the_cap`：纹理载体上所有代价有限、为正、不超过 wet cap、
  DC 恒为 wet。
- 原有 `footprint_reflects_frequency_content`、`flat_plane_produces_finite_costs` 保持通过。
- 质量抽查：24 MP 上用 1 KiB 载荷，嵌入后 `scan` 风险 0/100；900 KiB 满载荷同样是 0/100。
  **内置 DCT 检测器对该载荷下的 J-UNIWARD 不敏感**（`docs/stego_remediation_plan_20261023_1815.md`
  已记录这一检测器缺口），因此这不是"抗检改善"的证据，只是没有退化。
  修正前后的 stego 文件大小从 14 696 019 变为 14 838 507 字节（+1.0%），
  代价图更集中在真实纹理处，修改分布随之变化。
- 新增单测 `dot_kernels_agree`：同一组 24 维向量，标量内核与 AVX2 内核结果需在 1e-5 相对误差内。
  AVX2 是运行时选中的，这里防的是"换台机器 build 出不同代价图"。
- `cargo test`：200 lib + 全部集成/文档测试 **0 失败**；
  `cargo test --test batch_corpus -- --ignored` 通过；
  `cargo test --test batch_stego -- --ignored` 通过；
  `cargo fmt --check` 与 `cargo clippy --all-targets -D warnings` 干净。

顺带修了 CLI 帮助里两处算法名拼写错误（`-a juniwward` → `-a juniward`，
`src/i18n/messages.rs` 的中英文示例），照着原示例敲会直接报 `Unknown JPEG stego algorithm`。
同名的 4 个测试函数也一并改正。

## 6. 未做（后续）

| 项 | 改动 | 预期 | 风险 |
| :--- | :--- | :--- | :--- |
| **P2 多线程** | 块层按行 `par_chunks_mut(64)`；rayon 从 `dev-dependencies` 提升为 `stego` feature 下的可选依赖 | 代价图 1.45 s → 约 0.25 s | 低 |
| **P3a residual** | `separable_residual` 预 pad 去 clamp + f32 化 | 0.90 s → 0.24 s | 中 |
| **P3b decompress** | `precover::decompress_luma` 的 f64 8×8 IDCT 向量化/f32 化 | 0.53 s → 0.2 s | **高**（见下） |

P2 + P3 全部完成后，24 MP / 1 KiB 的端到端预计 1.2 s 左右，与 UERD 同量级。

## 7. 后续项的风险

### P2（多线程）——低风险，但有两个必须避开的坑

1. **并行粒度只能放在块层，不能放 band 层。** band 层并行会让 3 份权重平面同时驻留
   （100 MP 每份 404 MB）叠加 3 份 f64 残差（每份 805 MB），峰值冲破 3 GB。
   块层并行时每线程只多一个 2.3 KB 的 `patch` 和 768 B 的 `mid`。
2. **扩展性受内存带宽限制，不是 CPU。** `separable_residual` 是纯带宽型（读 402 MB、写 805 MB，
   ×3 band）。微基准里 16 线程相对单线程只有 5.8×（0.29 s → 0.05 s），不是 16×。
   所以 P2 的真实收益应按 5–6× 估，不要按核数估。

其余都是安全的：每块独占 `costs[bi*64..bi*64+64]`，`par_chunks_mut` 无数据竞争；
块内 f32 累加顺序不变，结果与单线程**逐位一致**（这里没有跨块归约）。
依赖侧：rayon 已在 `dev-dependencies`（测试在用），CI 只有 ubuntu/windows，
仓库没有 wasm 目标，提升为可选依赖的风险主要是 `--no-default-features` 组合要补测。

### P3a（residual）——中风险，边界语义是唯一的雷

去 clamp 必须严格保持 edge-replicate。现有 `footprint_matches_the_real_residual`
只在块 (16,16) 取值，**没有覆盖最外圈块**，改之前应先补一条边界用例，
否则边界一圈的代价会静默变化，而这类变化不会让任何往返测试失败。
f32 化本身影响很小：残差是像素域差分，f32 相对误差 1e-7，`σ = 1/64` 时低幅值位置由 σ 主导。

### P3b（decompress）——高风险，因为它被 UERD 共用

`precover::decompress_luma` 同时服务两条路径：

- J-UNIWARD 的 `compute_cost`；
- **UERD 的 `direction_bias`（cost polarization）** → `precover::estimate` → `decompress_luma`。

改它等于改 UERD 的代价图（polish 后的方向偏好），而 UERD 是 JPEG 的**默认**模型。
后果是 `batch_stego` 的检测率基线要整体重跑，且"UERD 输出变了"这件事本身需要一次评估说明。

建议顺序：P3b 要么给 J-UNIWARD 单独开一个 f32 版反量化路径（不碰共用函数），
要么接受 UERD 一起变、并按新基线重跑 `batch_stego`。**不要**在没跑检测率对比的情况下直接改共用实现。

另外 IDCT 若改成 AAN 快速算法，乘法数从 1024 降到约 200，但数值路径完全不同（舍入位置变了），
需要与当前实现逐点对拍；只做 SIMD 化则安全得多。

## 8. 复现

```bash
cd rust
cargo fmt && cargo clippy --all-targets -D warnings
cargo test
cargo test --test batch_corpus -- --ignored
cargo test --test batch_stego -- --ignored
```

基准脚本：`temp/bench_jw_cli.py`（分辨率/payload/复现性三阶段），
原始数据在 `temp/benchout/bench-{res,pay}-before.json` 与 `bench-{res,pay}.json`。
微基准与数值对拍：`temp/jwbench2.rs`、`temp/jwverify.rs`、`temp/verify_juniward_align.py`。
