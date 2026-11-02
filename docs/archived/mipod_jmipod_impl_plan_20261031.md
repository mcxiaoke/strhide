# MiPOD / J-MiPOD 实现分析与实施计划

- 日期：2026-10-31 20:12:54
- 分支：`mipod-jmipod-dev`
- 参考：`docs/mipod_jmipod_implementation_guide_20261031.md`（旧指南）、`temp/code/mipod_jmipod_impl/`（纯 NumPy 参考实现）、`temp/github/conseal`、`temp/github/vazswk-MiPOD`、`temp/github/capsule-7800700-code-jmipod`、`temp/github/capsule-9148499-code`、两篇论文原文。

## 1. 目标与边界

先把两个代价模型做成**正确、稳定、可用**的 Rust 实现，再接入注册表/CLI/GUI。

- MiPOD（空域 PNG）：`PngCostModel`，输出对称 STC 代价，提取端可在 stego 上复算出完全相同的槽位排序。
- J-MiPOD（DCT 域 JPEG）：`JpegCostModel`，输出 AC 系数代价，DC 永远 wet；JPEG 提取不需要代价模型。
- 不追求逐像素复刻官方实现；以论文推导 + 官方实现的关键结构为准，对不确定参数显式记录。

## 2. 已完成的核对结论（决定实现方式）

### 2.1 数学核心可用

- 可分离补空间投影与显式 `P_G^⊥` 等价：p=9/l=9 误差 `4.97e-14`，p=3/l=3 误差 `7.1e-15`（随机窗口，双精度量级）。
- DCT 方差传播 `V = Bᵀ S B`（`B = C⊙C`）与官方 64×64 `MatDCT.^2 / q²` 等价：误差 `8.9e-16`。
- 旧指南的两个单元测试逻辑可通过；其方差估计与 conseal 显式投影的最大相对误差 `2.16e-15`。

### 2.2 旧指南必须修的问题

1. `solve_beta` 在 `x≈1` 的分支切换点崩溃（`x=1.0` 返回 β=6.4e-5，真值 0.298），且 `x>1e11` 硬钳位造成 ρ 平台（27.63）。
2. Wiener 用 3×3 对称填充；论文固定 `w=2`，官方与 conseal 均为 `[2,2]`（Matlab 语义为零填充、左上对齐）。
3. J-MiPOD 复用 MiPOD 的 `p=9/l=9`；官方发布版用 `(3,3)`。论文文字引用 MiPOD `Sec. V`，两者都可自圆其说，本实现选官方 `(3,3)`（速度与代码一致性），并记录差异。
4. 官方 J-MiPOD 有 3×3 FI 后置滤波；论文 Algorithm 1 没有。本实现**不做**（省 200MB 级中间图、更贴论文；记录差异）。
5. 方差下界与负载口径不统一：本实现 J-MiPOD 采用官方的 DCT 域 `1e-5` 下界、`bpnzAC` 参考负载。
6. 中间图 `horiz` 为 72 B/px（24MP≈1.7GB）；改为行带分块（目标 <32MB）。
7. 载荷标定串行且每像素 6 步牛顿 × 28 次二分；改为 ρ 形式单调牛顿 + Illinois 求根 + 固定分块的确定性并行归约。
8. `content-jpeg` 单独编译时静默退化为均匀代价；共享估计器移到 `content-base`，单一代码路径。

### 2.3 数值核心（采用 NumPy 参考实现的思路）

令 `ρ = ln((1-2β)/β) = ln(1/β - 2)`，拉格朗日条件等价于

```
h(ρ) = ρ · (e^ρ + 2) = x,   x = scale · I
```

`h` 在 `ρ ≥ 0` 上凸且严格递增，`ρ0 = ln(1+x)` 必在根右侧，从右侧做牛顿迭代单调收敛，`x ∈ [0, 1e300]` 全程有效，**不对 β/ρ 钳位**。于是：

- 无代价平台，ρ 严格随 I 单调，排序与载荷标定值无关（PNG 嵌入/提取各自用不同 α 也不会错位）。
- `β = 1/(e^ρ+2)`；三元熵用数值稳定形式 `H = 2βL + p0·Lm`（`L=ρ+Lm`，`Lm=ln(1+2e^-ρ)`，`p0=e^-Lm`）。
- 标定 `scale`：对 `t=ln(scale)` 求 `ΣH=R`，总熵严格递减；先夹逼再用 Illinois 法，确定性。

## 3. 设计决策

| 项 | MiPOD (PNG) | J-MiPOD (JPEG) | 说明 |
|---|---|---|---|
| 块大小 p / 阶 l | 9 / 9 | 3 / 3 | PNG 用论文 medium；JPEG 用官方发布值 |
| Wiener | 2×2，零填充，左上对齐 | 同左 | 论文固定 w=2，官方 `wiener2(X,[2 2])` 语义 |
| 方差下界 | 0.01（论文 Eq.27） | 空域 1e-6；DCT 方差 1e-5 | J-MiPOD 按官方/DCT 域取样 |
| Fisher | `2/σ⁴` | `2/σ⁴` | 常数被 λ 吸收，保持论文写法 |
| Fisher 平滑 | 7×7 箱式（对称填充） | 不做 | 论文 VI-F 支持 7×7；J-MiPOD 官方滤波记录但不实现 |
| 载荷参考 | α bpp，默认 0.20 | α bpnzAC，默认 0.20 | 仅用于代价形状标定，不是真实载荷 |
| 代价 | ρ（对称） | ρ；DC=wet | 方向选择交给引擎默认（对称） |
| 线上标识 | PNG FeatureWord `algorithm_id=3` | 无（V3 提取不看代价） | |
| 确定性 | 固定分块并行归约 + 无钳位 | 同左 | 同输入跨线程数逐位一致 |

### 3.1 提取端一致性（PNG）

- 与 HILL/S-UNIWARD 相同，先对像素做 `pixel & 0xF8` 再算代价；类内 ±1 不改变掩码值，因此 stego 上重算与 cover 逐位一致。
- α 不写入 FeatureWord：由 2.3 的单调性，α 只改变代价的单调变换，不改变排序；默认路径与极端 α 均不会因排序错位导致提取失败。

### 3.2 内存与性能

- 方差估计按行带处理：仅保留 `(band + 2·half)` 行的一维投影，目标峰值 <32MB，不随图像高度线性膨胀。
- 载荷标定：`ΣH(t)` 用固定 4096 元素分块的并行归约（块内串行、块和按序累加），跨线程数逐位一致；Illinois 迭代 ~10 次；最终 ρ 并行逐像素求解。
- 24MP 估算：方差估计 ~10 GFLOP（Rayon）；标定 ~1.5e9 exp（Rayon，秒级）；峰值内存 <1GB（含引擎既有缓冲）。

## 4. 分步实施

### 第 1 步：共享空域方差估计器

新增 `rust/src/stego/spatial_variance.rs`（`content-base` 下编译）：

- `wiener_residual(plane, w, h, window)`：支持 2/3 窗口；Matlab 语义（偶窗口左上对齐、零填充）；噪声功率为局部方差全图均值。
- `estimate_variance(plane, w, h, p, degree, floor)`：可分离 DCT-II 补空间能量；行带处理；镜像（symmetric）填充。
- `box_smooth(plane, w, h, window)`：对称填充的可分离箱式平滑。
- 单元测试：p=3/5/9 与显式 `P_G^⊥` 对照；维纳残差对照；下界生效。

### 第 2 步：MiPOD 代价模型

新增 `rust/src/stego/png/cost/mipod.rs`：

- 类掩码亮度 → 方差 → `2/σ⁴` → 7×7 平滑 → `fisher_to_rho(fisher, alpha)`。
- ρ 求解器 + 熵标定（Illinois、固定分块归约）。
- 测试：`solve_rho` 残差（含 x=1、1e-12、1e300）、α 不影响排序、平坦/纹理排序、类内改动后代价图逐位不变。

### 第 3 步：J-MiPOD 代价模型

新增 `rust/src/stego/jpeg/cost/jmipod.rs`：

- `decompress_luma` → 复用第 1 步（p=3、w=2、空域下界 1e-6）→ `Bᵀ S B / q²` → DCT 方差下界 1e-5 → FI → 标定 → ρ；DC=wet。
- 参考负载 `bpnzAC`（非零 AC 计数；为 0 时退回 AC 总数）。
- 测试：方差传播对照显式 64×64；DC wet；平坦/纹理排序；忙碌块内低频 < 高频。

### 第 4 步：注册表与枚举接线

- `png/registry.rs`：`SPATIAL_ALGORITHM_MIPOD = 3`，名称/wire id/list。
- `jpeg/registry.rs`：`jmipod` 名称与 list。
- `options.rs`：`SpatialAlgorithm::Mipod`、`JpegAlgorithm::Jmipod` 及其 `from_name/model/id/PartialEq`。
- `stego/mod.rs`：新增 `spatial_variance` 模块声明。

### 第 5 步：CLI 与 GUI

- `cli/helpers.rs` 未知算法提示；`core/i18n/messages.rs` 帮助文案（中/英）。
- GUI：`gui/src/lib/stego.ts` 的 `ALGORITHMS`、`StegoEmbedView.tsx` 标签。

### 第 6 步：集成测试

- `rust/tests/test_lifecycle/png_mipod.rs`：纹理 PNG 用 `SpatialAlgorithm::Mipod` 嵌入→默认选项提取；FeatureWord 声明 `mipod`；平坦像素材质代价显著更高。
- `rust/tests/test_lifecycle/jpeg_jmipod.rs`：`small.jpg` 用 `JpegAlgorithm::Jmipod` 嵌入→无需算法提取；DC 不变；平坦块代价更高；与 UERD 的最便宜 10% 不完全重合。
- 在 `tests/test_lifecycle.rs` 注册两个模块。

### 第 7 步：验收

```bash
cd rust
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --all-targets
python scripts/baseline_hash.py --check   # 结构域不受影响，确认无回归
```

GUI 改动后：

```bash
cd gui
pnpm build
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
pnpm test:unit
pnpm test:cross
pnpm test:e2e
```

最后在 `docs/CHANGES-20261031.md` 顶部追加变更摘要（精确到秒）。

## 5. 验收标准

1. 新算法可在 CLI（`-a mipod` / `-a jmipod`）与 GUI 里选择。
2. PNG：`mipod` 写入的 carrier 在默认选项下可提取；`FeatureWord.algorithm_id == 3`；跨两次嵌入（不同 Rayon 线程数）逐位一致（同一 Seeded 输入）。
3. JPEG：`jmipod` 写入的 carrier 可提取；DC 从不改变。
4. 代价图：平坦区域代价显著高于纹理区域；所有代价有限且非负；J-MiPOD DC=wet。
5. 无 clippy warning、无测试失败、基线校验全绿。

## 6. 已知差异与风险

- 与官方实现不完全一致（wiener 窗口的边界处理、J-MiPOD 无后置滤波、p 选择）；每处均在代码注释中记录。
- α 仅塑造代价，不决定实际嵌入率；引擎不向模型传递真实载荷，这是架构限制。
- 极端 α 或全平坦图像的代价会趋于均匀，STC 自适应能力下降，但不会破坏提取。
- 跨平台 libm 末位差异理论上有机会翻转极近并列的代价；引擎的 `(cost bits, index)` 全序仍保证本机可复现。未做额外量化。

## 7. 实施结果（2026-10-31 20:41）

### 7.1 新增/修改文件

- 新增 `rust/src/stego/spatial_variance.rs`：2×2 零填充 Wiener 残差、可分离补空间方差估计（行带分块，镜像填充）、7×7 箱式平滑；含显式 `P_G^⊥` 对照测试（p=3/9、p=5/degree=4）。
- 新增 `rust/src/stego/cost_calibration.rs`：`ρ(e^ρ+2)=x` 单调牛顿（x∈[0,1e300] 无钳位）、稳定三元熵、Illinois 载荷标定、固定 4096 元素分块的确定性并行归约；Fisher 图原地转 log 再原地转代价，避免百 MP 级载体多分配两张全图。
- 新增 `rust/src/stego/png/cost/mipod.rs`、`rust/src/stego/jpeg/cost/jmipod.rs`。
- 接线：`png/registry.rs`（wire id 3）、`jpeg/registry.rs`、`options.rs`、`mipod`/`jmipod` 的 CLI 帮助与 i18n、GUI `ALGORITHMS` 与标签。
- 集成测试：`rust/tests/test_lifecycle/png_mipod.rs`、`jpeg_jmipod.rs`（6 个用例）。
- 新增 `scripts/stego_algorithm_matrix.py`：调用真实 release exe，对两组语料的每张 PNG/JPEG 逐一执行 embed→extract，校验载荷逐字节一致，输出 JSON 报告；支持 `--only`、`--dirs`、`--jobs`、`--timeout`、`--keep`、`--match`、`--limit`。
- 新增 `rust/tests/local/local_algorithm_matrix.rs`（ignored）：库 API 版本的全算法矩阵，PNG 覆盖 hill/suniward/mipod、JPEG 覆盖 uerd/juniward/jmipod，并额外断言 JPEG DC 不变；支持 `STRHIDE_ALGO_MATRIX_DIRS/ONLY/MAX_MP`。

### 7.2 验证

- `cargo fmt`、`cargo clippy --all-targets --all-features -- -D warnings` 全绿。
- 单元/集成：lib 388、test_lifecycle 154（含新增 6）、test_cli 131、test_regression 101、test_media 10、test_pe 40、test_security 18 全部通过。
- `python scripts/baseline_hash.py --check`：58/58 字节级一致。
- GUI：`pnpm build`、src-tauri clippy、`pnpm test:unit` 13、`pnpm test:cross` 5、`pnpm test:e2e` 23 全部通过。
- CLI 冒烟（1920×1280）：MiPOD 嵌入+提取往返 2.60 s；J-MiPOD 同类载体 1.66 s，小图 0.20 s。
- 关键单元测试：`solve_rho` 在 x=1.0/1.000001/1e-300/1e300 的方程残差 <1e-12；α=0.05 vs 0.80 排序完全一致；类内 ±1 改动后 MiPOD 代价图逐位不变；`BᵀSB` 对照 64×64 显式矩阵误差 <1e-9。
- **真实 exe 新算法矩阵**（`temp/teststego` + `temp/testhighres`，35 张 PNG/JPEG，`--only mipod,jmipod`）：28 PASS、7 SKIP（APNG/索引 PNG/交错 PNG/Progressive JPEG/超出引擎 MCU 或像素上限，均为设计拒绝）、0 FAIL，357.6 s；100 MP JPEG 与 66 MP PNG 均往返成功；最慢为 66 MP PNG MiPOD（embed 79.1 s + extract 35.7 s）。
- **全算法 local 矩阵**（`rust/tests/local/local_algorithm_matrix.rs`，`temp/teststego`，23 张图 / 69 个算法组合）：57 PASS、12 SKIP（APNG、索引 PNG、交错 PNG、Progressive JPEG，均为设计拒绝）、0 FAIL，耗时 184 s；PNG hill/suniward/mipod 与 JPEG uerd/juniward/jmipod 全部往返通过，JPEG DC 全部未改变。

### 7.3 实现与计划的差异

- 为提高算法保真度，Wiener 采用论文/官方一致的 2×2 零填充（而非参考 Python 的 3×3）；这是本实现与 `temp/code/mipod_jmipod_impl` 唯一有意的算法差异。
- 未做 J-MiPOD 官方 3×3 FI 后置滤波（论文未包含，且省一张 `blocks*64` 中间图）。
- 参考 Python 的多尺度 `min(3,5,7,9)` 方差未采用：单尺度（MiPOD 9/9、J-MiPOD 3/3）更接近论文/官方，且避免 4 倍计算量。
- PNG 代价图在 2.46 MP 上约 1–2 s（p=9 的 36 项可分离投影）；100 MP 级载体明显更慢，但内存保持在 GB 以内（行带 16 MB + 若干全图 f64）。

### 7.4 回归入口

```bash
# 真实 exe × 全部语料 × 新算法（也可去掉 --only 跑全部算法）
python scripts/stego_algorithm_matrix.py --only mipod,jmipod --jobs 2

# 库 API × 全算法（ignored；默认两组语料，可用环境变量缩小范围）
cargo test --release --all-features --test local_tests local_all_algorithms -- --ignored --nocapture
STRHIDE_ALGO_MATRIX_DIRS=temp/teststego STRHIDE_ALGO_MATRIX_ONLY=mipod,jmipod \
  cargo test --release --all-features --test local_tests local_all_algorithms -- --ignored --nocapture
```

引擎有意拒绝的载体（APNG、索引/交错 PNG、Progressive JPEG、JPEG MCU 上限、内容域像素上限）在两个入口中都记为 SKIP；只有真实 embed/extract 失败或载荷不一致才计为 FAIL。


