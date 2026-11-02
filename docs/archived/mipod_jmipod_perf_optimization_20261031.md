# MiPOD / J-MiPOD 性能优化方案

- 日期：2026-10-31 21:56:20
- 分支：`mipod-jmipod-dev`（commit `4475ee7`）
- 环境：Windows 10，i7-11700（8 核 / 16 线程），Rayon 线程数 8（CLI 默认 `(cores/2).max(4)`）
- 验证工程：`temp/mipod_bench/`（独立 crate，`strhide` 以 path 依赖、`content-png,content-jpeg` 特性编译；未改动主项目任何代码）
- 结论：**代价模型本身可提速 MiPOD 约 11.5–11.9 倍、J-MiPOD 约 20–29 倍**，且输出代价图的误差在 1e-7 量级以内、逐位可复现，PNG 类内改动的代价图不变性保持不变。

---

## 1. 性能剖析：慢在哪里

对真实语料逐阶段计时（`temp/mipod_bench`，与库内 `compute_cost` 同输入同算法，最终代价图逐位一致的对照已验证）。

### MiPOD（PNG）

| 载体 | 总耗时 | 空格掩码 | Wiener | 补空间投影 | σ²→FI | 7×7 平滑 | 载荷标定 |
|---|---|---|---|---|---|---|---|
| 24 MP (4000×6000) | 10.16 s | 54 ms | 131 ms | 464 ms | 22 ms | 55 ms | **8.35 s (82%)** |
| 66 MP (10752×6144) | 31.03 s | 151 ms | 367 ms | 1551 ms | 59 ms | 157 ms | **25.37 s (82%)** |

### J-MiPOD（JPEG）

| 载体 | 总耗时 | 亮度解压 | 空域方差 (p=3) | BᵀSB + FI | 载荷标定 |
|---|---|---|---|---|---|
| 24 MP / 375k blocks | 8.90 s | 24 ms | 281 ms | 21 ms | **8.53 s (96%)** |
| 100 MP / 6.29M blocks | 49.52 s | 226 ms | 1008 ms | 90 ms | 约 **35–38 s（~72–76%）** |

根因：

1. **载荷标定把 `solve_rho` 嵌套进了每一次熵求值**。Illinois 求根要 10–14 次 `ΣH3` 求值，每次遍历 2400 万–1 亿个元素，且每个元素都做一次 `ln + 3~6 次 exp` 牛顿迭代。复杂度 `O(iters × n × Newton)`，与分辨率线性增长。
2. **MiPOD 的 9×9 补空间投影有 4 倍冗余访存**。水平方向每个像素调用 81 次 `reflect_index`（`rem_euclid` 整数除法）；垂直方向每个像素的 36 个内积重复读取同一批 9 个值，实际产生约 324 次标量加载 / 像素。
3. 次要项：Wiener 2×2 逐像素四邻域求和带边界分支；7×7 平滑每个 tap 都走 `reflect_index`。

---

## 2. 优化项与实测

### A. 载荷标定：直方图化 + 单调插值表（最大收益）

**思路**（`cost_calibration.rs`，不改数学）：

- `log(FI)` 的取值范围与分布只影响 `ΣH3` 的值，不要求逐元素精确：
  1. 一次并行扫描得到 `active / min_log / max_log`（现有代码是 3 次串行全图扫描）；
  2. 把 `log(FI)` 分桶到固定 32768 桶的等宽直方图（桶计数为整数，归约与线程数无关）；
  3. 每次 `ΣH3(t)` 只遍历 32768 个非空桶（桶中点求值），成本从 `O(n)` 降为 `O(32768)`；
  4. 最终代价图用同一网格上的 `ρ(t+u)` 单调表做线性插值（表 256 KB，L2 常驻），不再逐元素求解。

**为什么安全**：

- `ρ` 是 `I` 的严格单调函数，直方图只影响标定出的标量 `t`（参考载荷），不改变“`ρ` 随 `I` 单调”的性质；插值表单调 ⇒ 槽位排序与现有实现一致。
- 桶计数是整数、桶和按桶序串行累加 ⇒ 跨线程数逐位一致（实测 8 线程与 1 线程 hash 完全相同）。
- 实测误差：真实 66 MP 图 `max|Δρ| = 3.3e-9`（相对 2.8e-9），达到的参考载荷误差 3.6e-10；24 MP 图 `max|Δρ| = 4.5e-8`；仓库单测中的 2048 元素用例相对误差 2.7e-7（阈值 1e-6）。

**收益**（仅标定阶段）：

| 数据规模 | 原实现 | 直方图 + 精确末图 | 直方图 + 插值末图 |
|---|---|---|---|
| 24M 元素 | 7.77 s | 0.65 s（12x） | 0.10–0.15 s（约 50x） |
| 66M 元素（真实 PNG） | 25.37 s | 1.82 s | 0.25 s |
| 100M 元素（真实 JPEG） | ~35–38 s | — | 0.38 s |

建议采用“插值末图”版本：误差比精确末图仅大 ~1e-9，速度再快 4–5 倍。

### B. 9×9 补空间投影：去整数除法 + 复用垂直加载（逐位等价）

**现状问题**：

- 水平 pass：`for x { for kv { for a { reflect_index(x+a-half,w) } } }`，内点也做 81 次 `rem_euclid`。
- 垂直 pass：`for kv { for ku { for a { horiz[...] } } }`，同一 `(li+x+kv)` 列的 9 个值被 4 个 `ku` 重复加载。

**改法**（`spatial_variance.rs::complement_energy`）：

1. 水平方向按区间拆分：`x ∈ [half, w-half)` 直接用连续切片 `src[x-half..x-half+p]`，仅两端 `half` 个像素走镜像索引；
2. 垂直方向把 `a` 提到 `ku` 外层：每个 `(x, kv)` 先取一次 9 个值到寄存器/栈数组，再对 `ku ∈ [l-kv, p)` 做内积；
3. `p` 用 const generics 特化（3/5/7/9/11/17），保留原有 `Vec<Vec<f64>>` 通用回退路径；
4. 保持原求和顺序（`kv` 外层、`ku`、`a` 递增）⇒ **结果逐位一致**。

**验证**：对 `p=3/5/7/9` 与 `l=p`、`l=p-2`、`l<p` 组合，在 6 组尺寸（含 `w<p`、`h<p`、2×2）上与原实现比对，能量图全部 `bit-identical`（`temp/mipod_bench cmp`）。

**收益**：24 MP 由 1557 ms → 455 ms（3.4x）；66 MP 由 5015 ms → 1551 ms（3.2x）。`BAND_BYTES` 保持 16 MB（实测 32 MB 反而慢约 17%，因垂直 pass 工作集变大）。

### C. 7×7 平滑：内点去 `reflect_index`（逐位等价）

- 水平/垂直都按 `[half, w-half)` 拆分，内点连续读；边缘保持原镜像逻辑与求和顺序。
- 结果与原函数逐位一致（已比对 6 组尺寸）。
- 24 MP 122 ms → 55 ms；66 MP 350 ms → 157 ms。

### D. Wiener 2×2：可分离两遍求和（已实测，不采纳）

- 方案：先算竖直双行和（`sum` 与 `sum²`），再算水平双列和；边界仍零填充。
- 实测**更慢**：24 MP 87 ms → 131 ms，66 MP 255 ms → 367 ms。原因是多出两张全图级中间平面（读写量翻倍），而原实现是单遍融合的 4 邻域求和。
- 结论：**保留原实现**。本方案中其他优化后的端到端数字包含这个实验性的 Wiener 改动，实际落地时去掉 D 还会再快约 50–120 ms（24 MP / 66 MP）。

### E. 规模参数（p / l）——质量换速度，需产品决策

同一 24 MP 图上优化后投影耗时：

| p / l | 3/3 | 5/5 | 7/7 | 9/9（当前） | 11/11 | 17/12 |
|---|---|---|---|---|---|---|
| 补空间投影 | 69 ms | 136 ms | 256 ms | 456 ms | 807 ms | 5204 ms |

- `p/l` 不写入 FeatureWord：若做成可调参数，必须扩展空间域特征字段（项目未发布，可做），否则仅能作为固定默认值。
- 论文把 p=9/l=9 定为“medium”；改成 7/7 可再省约 44% 投影时间，但会改变代价形状/安全性，建议只作为显式“fast profile”，不默认。
- J-MiPOD 已按官方发布版用 p=3/l=3，无需调整。

### F. CLI 每次 embed 会算两遍代价图（额外 1 倍，建议修）

`stego::io::embed_carrier_file` 在 `embed_carrier_with_dialect_info` 返回后，发现 `EmbedOutput.capacity == None`（PNG 引擎只返回 `stats`），会再调一次 `probe_carrier_capacity_with_dialect` 来打印容量行；`probe_png_capacity` 又会执行一次 `cost_model.compute_cost`。

66 MP PNG 实测（CLI，solo，同一短载荷）：

| 算法 | cost_model | embed | embed − 2×cost | extract | extract − cost |
|---|---|---|---|---|---|
| HILL | 1.63 s | 17.19 s | 13.93 s | 6.03 s | 4.40 s |
| S-UNIWARD | 9.03 s | 31.50 s | 13.44 s | 13.70 s | 4.67 s |
| MiPOD | 31.41 s | 77.41 s | 14.59 s | 35.67 s | 4.26 s |

结论：PNG 解码 + 重压缩 + STC 的共享开销只有约 **14 s（embed）/ 4.3 s（extract）**；其余差异全部来自代价模型。MiPOD 的 77 s 里，代价模型被算了 **两遍**（62.8 s）。

可选修法（与本次优化独立、收益同样显著）：

- 让 `embed_png_with_stats`/`EmbedStats` 返回嵌入时已有的槽位数与推荐容量，`EmbedOutput` 直接带 `capacity`，CLI 不再探测；或 CLI 仅在 `--safety` 需要告警时才探测，并复用 embed 的 pool 结果。
- 收益：MiPOD embed 再省一遍代价图（优化前 31.4 s，优化后 2.6 s）；HILL/S-UNIWARD 各省 1.6 s / 9.0 s。
- 风险：容量行与警告逻辑需要逐字段核对，避免“显示的容量”和实际 embed 使用的 pool 不一致（这正是 `SlotPlan` 与 probe 共用代码路径的原因）。

### H. AVX2 SIMD：可用，但不是第一优先级（有逐位一致实测）

项目已有三处先例：

- `jpeg/cost/juniward.rs`：`sweep_avx2`（AVX2+FMA）+ 标量回退，`PngParams::deterministic` 在 seeded 运行里强制标量（FMA 与标量末位不同）。
- `coding/stc.rs`：`accumulate_xor_avx2`，运行时 `is_x86_feature_detected!` 门控。
- vendor `rusty_h265-accel`：标量是 oracle，AVX2/SSE2/NEON 是 twins，测试用 `assert_eq!` 逐位比对（不是容差）。

对 MiPOD/J-MiPOD 的可用性结论：

- **最值得向量化的是空域方差投影**（投影占优化后 MiPOD 66 MP 的约 60%）。用“向量 lanes = 相邻 x 的独立输出像素、每 lane 仍按 `a` 递增累加、用 `mul+add` 而不用 FMA”的方式，结果与标量**逐位一致**（不引入 `deterministic` 开关，也不会让 PNG 嵌入端/提取端因 CPU 特性不同而漂移）。
- 实测（`temp/mipod_bench avx2`，8 线程，AVX2 可用）：

| 载体 | p/l | 标量投影 | AVX2 投影 | 加速 | 逐位一致 |
|---|---|---|---|---|---|
| 24 MP | 3/3 | 71.6 ms | 53.0 ms | 1.35x | 是 |
| 24 MP | 5/5 | 127.9 ms | 74.9 ms | 1.71x | 是 |
| 24 MP | 7/7 | 291.0 ms | 165.2 ms | 1.76x | 是 |
| 24 MP | 9/9 | 485.7 ms | 336.4 ms | 1.44x | 是 |
| 66 MP | 3/3 | 206.6 ms | 166.7 ms | 1.24x | 是 |
| 66 MP | 5/5 | 403.5 ms | 277.8 ms | 1.45x | 是 |
| 66 MP | 7/7 | 779.1 ms | 507.9 ms | 1.53x | 是 |
| 66 MP | 9/9 | 1484.6 ms | 985.8 ms | 1.51x | 是 |

- **达不到 4x**：投影已经是访存为主（9 行 × 9 tap 的窗口复用受 L2/L3 限制），且 p=9 的窗口比 p=3/7 更大；AVX2 主要省的是指令数，不是内存字节。p=3（J-MiPOD）只有 1.24–1.35x。
- 可顺带向量化：7×7 平滑（约 1.5–2x）、Wiener 2×2（约 1.5x）、类掩码亮度（约 2x）；这些在 66 MP 上合计约 0.5 s，能再省 0.2–0.3 s。
- **不适合向量化**：直方图标定（scatter 累加 + 逐桶 `exp/牛顿`）、末图查表（随机 gather）、`compress`/PNG 重压缩。这些恰好是优化后剩余时间里较“硬”的部分。

预期（在 A+B+C 之后再做 AVX2）：

- MiPOD 66 MP 代价模型 2.60 s → 约 1.9–2.0 s（再快 1.3–1.4x）；
- J-MiPOD 100 MP 代价模型 1.71 s → 约 1.4–1.5 s（再快 1.1–1.2x，因为 p=3 投影占比小，Wiener/标定更大）。
- 如果直接给**未做 A/B/C 的现状代码**加 AVX2，只会把 66 MP 的 31.4 s 降到约 27 s（1.15x），因为 25 s 的标定几乎不受益——**AVX2 不能替代算法级优化**。

实现建议：

- `#[cfg(target_arch = "x86_64")]` + `is_x86_feature_detected!("avx2")` 运行时门控，`#[target_feature(enable = "avx2")]` 的非泛型内核（宏展开 p=3/5/7/9 特化），其余走现有标量路径。
- J-MiPOD 的代价图只在 embed 使用，可仿照 J-UNIWARD 用 AVX2+FMA；MiPOD 因提取要复算，建议只用 mul+add 保持逐位一致。
- 测试：向量/标量 kernel 逐位 `assert_eq!`；覆盖 `w < 2p`、尾部不足 4 像素、镜像边缘；跨线程与类内不变性沿用现有测试。

#### H.1 `-C target-cpu=x86-64-v3` 会不会让普通代码自动提速？

配置确认：`.github/workflows/release.yml` 只在 `x86_64-avx2` 这个**可选** matrix 项里设置 `rustflags: "-C target-cpu=x86-64-v3"`；默认 `x86_64` artifact 的 rustflags 为空（Windows 与 Linux 都是如此）。也就是说普通用户拿到的默认二进制仍是 SSE2 基线。

实测（同一 temp 工程分别用默认 flags 与 `-C target-cpu=x86-64-v3` 构建）：

| 指标 | 默认构建 | v3 构建 | 变化 |
|---|---|---|---|
| 标量投影 p=9，66 MP | 1484.6 ms | 1496.4 ms | 0% |
| 标量投影 p=3，66 MP | 206.6 ms | 197.5 ms | ~4% |
| 优化后 MiPOD 管线，24 MP | 884.1 ms | 834.6 ms | ~5%（含噪声） |
| 优化后 J-MiPOD 管线，24 MP | 434.7 ms | 402.7 ms | ~7%（Wiener/平滑少量自动向量化） |
| 原库 `compute_cost`，24 MP | 10.16 s | 10.09 s | ~1% |

结论：

- **v3 不会给这两条代价模型带来明显自动提速**。热点是浮点归约（逐 tap 累加）+ 分支边界 + 访存；在不允许改变浮点运算顺序（未开 fast-math）的前提下，LLVM 无法把归约循环自动向量化。
- 因此仍需要显式 AVX2 内核（§2-H 的 1.48–1.55x），不能靠 `target-cpu` 替代。
- 可移植性：v3 artifact 要求 Haswell 及以后（AVX2/FMA），更老的 CPU 会直接非法指令；CI 同时保留 baseline artifact 正是为此。
- 跨 artifact 一致性：本次实测两套构建的 `selftest` 哈希与代价图数值完全一致（未观察到 FMA 收缩差异）；但如果以后引入依赖全局 FMA 的路径，`--seed` 可复现产物需要像 J-UNIWARD 那样强制标量。

### I. 其他可选方向（不建议在本轮做）

- 代价图/中间图改 `f32`：可把投影访存减半，但引入精度变化和额外验证成本；当前投影已从 82% 的标定手里让位后不再是唯一瓶颈，收益边际。
- `fisher_to_costs` 末图改精确解：仅比插值多 0.5–1.5 s（24–66 MP），若追求“与旧实现数值最接近”可保留精确末图，仍比现状快 12 倍。
- STC / PNG 重压缩 / 容量探测重复计算是端到端剩余时间的大头，不属于代价模型优化范围（见 §2-F、§3）。

---

## 3. 端到端预期（CLI solo 实测 + §2 优化后代价）

66 MP PNG 同载体、同短载荷的实测对照（HILL / S-UNIWARD / MiPOD 三种空域算法）：

| 场景（66 MP PNG） | 代价模型 | 现状 embed | 现状 extract | 优化后 embed | 优化后 extract |
|---|---|---|---|---|---|
| HILL | 1.63 s | 17.19 s | 6.03 s | 17.2 s（探测修复后 ~15.6 s） | 6.0 s |
| S-UNIWARD | 9.03 s | 31.50 s | 13.70 s | 31.5 s（探测修复后 ~22.5 s） | 13.7 s |
| MiPOD | 31.41 s | 77.41 s | 35.67 s | ~19.8 s（2×2.6+14.6；探测修复后 ~17.2 s） | ~6.9 s |

其它载体：

| 场景 | 现状 embed | 现状 extract | 优化后 embed | 优化后 extract |
|---|---|---|---|---|
| MiPOD 24 MP PNG | 30.34 s* | 13.92 s* | ~11.9 s* | ~4.6 s* |
| J-MiPOD 24 MP JPEG | 11.09 s* | 0.49 s* | ~2.6 s | 不变（0.49 s） |
| J-MiPOD 100 MP JPEG | 55.17 s* | 0.80 s* | ~7.4 s | 不变（0.80 s） |

`*` 来自 `temp/stego_algorithm_matrix/report.json`（两个进程并发执行，单进程会略快）。

说明：

- **修正**：PNG embed 的共享开销（解码 + 重压缩 + STC）只有约 14 s，不是此前按并发数据推算的 47 s。MiPOD embed 慢的真实原因是 **CLI 每次 embed 会把代价图算两遍**：embed 一遍 + 容量探测一遍（见 §2-F）。
- 三种算法共享同一份 PNG 开销；HILL 快是因为代价模型只需 1.6 s；S-UNIWARD 的 9 s 已经让 embed 达到 31.5 s；MiPOD 原来 31.4 s 且付两遍，因此显得格外慢。
- 优化后 MiPOD 的 embed/extract 与 HILL 基本同一量级（差距主要剩一遍容量探测）。
- JPEG 提取本就不算代价，J-MiPOD 的收益全部落在 embed。
- 若还想让 PNG embed 再快，下一步应优化 zlib 重压缩档位/表达式，或消除重复探测；可另开任务。

---

## 4. 落地实施步骤（建议）

### 第 1 步：`rust/src/stego/cost_calibration.rs`

- 新增私有 `Histogram { u_min, du, inv_du, counts: Vec<u32> }`：
  - `Grid::build(log_fi, u_min, u_max)`：`par_chunks(1<<18).fold(|| vec![0u32; 32768], ...).reduce(...)`；计数为整数，归约顺序无关。
  - `total_entropy_nats(t)`：按桶序串行累加，桶中点 `u = u_min + (i+0.5)·du`。
  - `rho_table(t)`：桶边界上的 `solve_rho(exp(t+u))`；末图线性插值，越界 clamp。
- `fisher_to_costs` 流程改为：一次并行统计 `(active,min,max)` → 直方图 → 原 Illinois 循环（换成直方图求值）→ 插值末图。
- 保留 `solve_rho` / `ternary_entropy_nats` 原样，现有单测不动。
- 新增/调整单测：
  - 直方图 `ΣH3(t)` 与逐元素精确求和在 4096 元素、3 档载荷下相对误差 < 1e-6；
  - 现有 `calibration_meets_the_target_entropy` 仍 < 1e-6（实测 2.7e-7）；
  - `fisher_to_costs` 同一输入在 1 线程与默认线程池下逐位一致（可用 `ThreadPoolBuilder::install`）；
  - 排序不随参考载荷变化（现有测试已覆盖，保留）。

### 第 2 步：`rust/src/stego/spatial_variance.rs`

- `complement_energy`：新增 `fn complement_energy_p<const P: usize>`；`p ∈ {3,5,7,9,11,17}` 走特化，其他奇数 p 保留现通用实现。
  - 水平内点切片；垂直“载入一次、复用 ku”。
  - 保持 `kv → ku → a` 求和顺序，确保逐位一致。
- `box_smooth`：内点切片；边缘保留镜像；顺序不变。
- 可选：`wiener_residual` 保持原样（可分离版本实测更慢，见 D）。
- 新增单测：
  - 对 6 组尺寸（含小于 p 的宽高）× 3 组 `(p,l)` 断言特化路径与通用路径逐位一致；
  - 现有显式投影矩阵对照测试保持通过（p=3/5/9、degree<p）。

### 第 3 步：模型层

- `png/cost/mipod.rs`、`jpeg/cost/jmipod.rs` **无需改动**（只调用共享函数）。
- **P1（可选，收益大）**：消除 CLI embed 后的重复容量探测（§2-F）。让 PNG embed 返回已算出的 `capacity`（`SlotPlan` 建好后 pool/推荐容量都已在手），或让 `embed_carrier_file` 只在需要安全告警时探测；注意与 `probe_png_capacity` 的字段逐项对齐。
- 若采纳 p/l 可调：需要给空间域 FeatureWord 增加 `p`/`l` 字段（wire 变更，项目未发布可直接做），并在线 id、CLI/GUI 选项中写明；不建议和本轮纯性能改动混在一起。

### 第 4 步：验证

```bash
cd rust
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --all-targets
cargo test local_ --all-features -- --ignored
cargo build --release --all-features
python scripts/baseline_hash.py --check          # MiPOD/J-MiPOD 不在基线内，确认无结构回归
python scripts/stego_algorithm_matrix.py --only mipod,jmipod --jobs 2
```

- 预期：`local_algorithm_matrix` 的 PNG/JPEG 全组合仍 PASS；35 张真实语料矩阵耗时从 357.6 s 降到约 220–260 s（其中 JPEG 侧提升最大，PNG 侧受重压缩限制）。
- 补充冒烟：24 MP PNG 与 100 MP JPEG 的 embed/extract 计时应与 §3 接近。
- 若改动 GUI 以外代码，GUI 测试可不动；若同时扩展了 wire 选项，再跑 `pnpm test:cross` 等。

### 第 5 步：文档

- 按仓库规则在 `docs/CHANGES-YYYYMMDD.md` 顶部追加变更摘要（含时间戳）；本方案文档可并入或作为附件。

---

## 5. 风险与回归点

1. **代价数值变化**：直方图标定使 `ρ` 有 ≤1e-7 的相对变化，槽位排序不变，但 STC 在近似并列代价处的最优解可能改选不同槽位 ⇒ 同一载荷生成的 stego 字节可能和旧实现不同。项目未发布，无需兼容；回归以“提取成功 + 代价图不变性”为准。
2. **PNG 提取一致性**：代价图只依赖 `pixel & 0xF8` 后的平面；新实现同输入同输出（已用 24 MP 与两张小图做类内 ±1 全图搬移验证，逐位一致）。
3. **跨线程确定性**：直方图计数为整数、熵和按桶序、末图逐元素插值 ⇒ 8 线程与 1 线程 hash 一致（已验证）。
4. **极端输入**：全平坦图（`min=max`）走单桶；NaN/Inf/0/负值仍置 0；`target_bits≤0` 仍全 0；空/单元素图不 panic。已用 `selftest` 覆盖。
5. **内存**：直方图每线程 128 KB、插值表 256 KB；不新增全图级缓冲，峰值内存不变。
6. **误差口径**：参考载荷 `alpha` 本来只是代价形状参数，不参与提取；允许 1e-6 级误差，但建议在注释中明确“直方图/插值是有意的数值近似”。

---

## 6. 复现实验（temp 工程）

```bash
cd temp/mipod_bench
cargo build --release --offline

# 分阶段剖析 + 与库内结果逐位比对（会先跑一遍原库 compute_cost）
target/release/mipod_bench.exe png  ../testhighres/img24mp_png.png
target/release/mipod_bench.exe jpeg ../testhighres/img24mp.jpg

# 仅优化后管线 + 误差/加速比
target/release/mipod_bench.exe png-opt  ../testhighres/img60mp-a_png.png
target/release/mipod_bench.exe jpeg-opt ../testhighres/img100mp.jpg

# 投影/平滑等价性与不同 p/l 组合的耗时
target/release/mipod_bench.exe cmp
target/release/mipod_bench.exe energy-p ../testhighres/img24mp_png.png

# 标定边界用例、排序、跨线程确定性、PNG 类内不变性
target/release/mipod_bench.exe selftest
RAYON_NUM_THREADS=1 target/release/mipod_bench.exe selftest
target/release/mipod_bench.exe invar ../testhighres/img24mp_png.png
```

关键实测汇总：

| 指标 | MiPOD 24 MP | MiPOD 66 MP | J-MiPOD 24 MP | J-MiPOD 100 MP |
|---|---|---|---|---|
| 原 `compute_cost` | 10.16 s | 31.03 s | 8.90 s | 49.52 s |
| 优化后管线 | **0.88 s（11.5x）** | **2.60 s（11.9x）** | **0.43 s（20.5x）** | **1.71 s（29.0x）** |
| `max|Δρ|` | 4.5e-8 | 3.3e-9 | 3.9e-8 | 5.4e-8 |
| 参考载荷相对误差 | 2.9e-8 | 3.6e-10 | 1.5e-8 | 3.0e-8 |
| 补空间投影等价性 | 逐位一致 | 逐位一致 | 逐位一致（p=3） | 逐位一致（p=3） |
| 平滑等价性 | 逐位一致 | 逐位一致 | — | — |
| 跨线程确定性 | 一致 | 一致 | 一致 | 一致 |
| PNG 类内不变性 | 一致 | — | — | — |

---

## 7. 建议的优先级

1. **P0**：A（直方图标定 + 插值末图）——单点收益最大，约 12–45 倍标定加速，代码集中在一个文件。
2. **P0**：B（补空间投影内点/复用加载）——逐位等价，MiPOD 再快 3 倍投影。
3. **P1**：C（7×7 平滑内点）——逐位等价，低风险小收益。
4. **P1**：F（消除 CLI 重复容量探测）——MiPOD embed 再省一遍代价图；HILL/S-UNIWARD 也受益。
5. **P2**：H（AVX2 投影/平滑/Wiener）——在 A+B+C 之后再做，MiPOD 66 MP 再快 1.3–1.4x；单独加在现状代码上只有 1.15x。
6. **P2**：E（p/l 快速档、f32）——按质量/兼容性需求再决定；D（Wiener 可分离）已实测更慢，放弃。
