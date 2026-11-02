# MiPOD / J-MiPOD 算法原理、实现详解与总结

- 日期：2026-10-31
- 适用代码：`rust/src/stego/spatial_variance.rs`、`rust/src/stego/cost_calibration.rs`、`rust/src/stego/png/cost/mipod.rs`、`rust/src/stego/jpeg/cost/jmipod.rs`
- 论文：
  - MiPOD：V. Sedighi, R. Cogranne, J. Fridrich, "Content-Adaptive Steganography by Minimizing Statistical Detectability", IEEE TIFS 11(2), 2016.
  - J-MiPOD：R. Cogranne, Q. Giboulot, P. Bas, "Steganography by Minimizing Statistical Detectability: The Cases of JPEG and Color Images", ACM IH&MMSec 2020.
- 参考实现：DDE `MiPOD.m`、作者发布的 `JMiPOD_fast.m`（MATLAB）与 2024 Python 版、`uibk-uncover/conseal`、`temp/code/mipod_jmipod_impl`（纯 NumPy）。

## 1. 一句话概括

MiPOD / J-MiPOD 不靠“纹理越复杂越安全”这类启发式，而是把每个可修改元素建模成独立零均值高斯，直接在当前载体的**统计可检测性**下求最优改动概率，再把概率换算成 STC 的加性代价。

- 空域（PNG）：估计每个像素的噪声方差 `σ_n²` → Fisher 信息 `I_n = 2/σ_n⁴` → 解三元熵约束 → 代价。
- DCT 域（JPEG）：把空域像素方差经正交 DCT 线性变换传播到 64 个系数、除以量化步长平方 → Fisher 信息 → 同样的概率/代价求解。

两套算法共享同一个“方差估计 + 概率求解”内核，差别只在载体的域和方差传播方式。

## 2. 统计模型与最优性

### 2.1 三元嵌入

对每个元素 `n`：

```
P(y_n = x_n + 1) = β_n
P(y_n = x_n - 1) = β_n
P(y_n = x_n)     = 1 - 2β_n
```

`β_n ∈ [0, 1/3]`。三元熵（nats）：

```
H3(β) = -2β ln β - (1 - 2β) ln(1 - 2β)
```

### 2.2 可检测性与 Fisher 信息

在独立高斯模型下，最强大似然比检验的偏转系数（deflection）满足

```
ϱ² ∝ Σ_n β_n² I_n,     I_n = 2 / σ_n⁴
```

`I_n` 是 Fisher 信息：方差越小（越平坦）→ `I_n` 越大 → 改动越容易被检测 → 代价越高。这也是 MiPOD 与启发式代价模型的根本区别：代价来自载体统计模型，而不是局部滤波器响应。

> 实现中常数 2 被拉格朗日乘子吸收，写 `I=2/σ⁴` 只是与论文保持一致；改成 `1/σ⁴` 不会改变最终代价。

### 2.3 拉格朗日条件

在载荷约束 `R = Σ H3(β_n)`（nats）下最小化 `ϱ²`，得到

```
ln((1 - 2β_n) / β_n) = 2λ I_n β_n
R = Σ H3(β_n)
```

令

```
ρ_n = ln((1 - 2β_n) / β_n) = ln(1/β_n - 2)
x_n = 2λ I_n
```

则第一个方程变成只含 `ρ` 的形式：

```
ρ (e^ρ + 2) = x
```

这正是加法 STC 所需代价 `ρ_n`（论文 Eq. 20：`ρ_n = ln(1/β_n - 2)`）。

### 2.4 数值求解：为什么用 ρ 而不是 β

旧稿直接在 `β` 上做牛顿迭代并钳位 `β ∈ [1e-12, 1/3-1e-12]`，有两个真实问题：

1. `x≈1` 时初值分支选错，6 步牛顿回不到根（旧稿在 `x=1` 返回 `β≈6.4e-5`，真值 `0.298`）；
2. `x > 1e11` 硬返回最小 `β`，产生 `ρ≈27.63` 的代价平台，平坦区大量并列。

本实现改用 `ρ`：

- `h(ρ)=ρ(e^ρ+2)` 在 `ρ≥0` 上凸且严格递增；
- `ρ0 = ln(1+x)` 必有 `h(ρ0) = ln(1+x)(3+x) ≥ x`，即初值总在根的右侧；
- 从右侧做牛顿迭代单调收敛，`x ∈ [0, 1e300]` 全程有效（`ρ ≤ ~690`，中间量不溢出）；
- 不做任何 β/ρ 钳位，代价无平台。

`β` 与熵都可从 `ρ` 稳定恢复：

```
β = 1/(e^ρ + 2)
H3 = 2βL + p0 Lm
L  = ρ + Lm,  Lm = ln(1 + 2 e^-ρ),  p0 = e^-Lm
```

这避免了 `β→1/3` 时 `ln(1-2β)` 的抵消误差。

### 2.5 载荷标定

真实载荷在 strhide 中由用户/引擎决定，代价模型拿不到；`alpha` 只是**参考载荷**。标定目标是让

```
Σ H3(β_n) = R_ref
```

在 `t = ln(scale)` 上求根（`x_n = e^t · I_n`）。总熵对 `t` 严格递减，先夹逼再用 Illinois（改进 regula falsi），括号始终保留。

工程细节：

- 熵求和按固定 4096 元素分块并行，块内串行、块和按序累加 → 结果与 Rayon 线程数无关；
- Fisher 图原地转 `ln I`，标定后再原地转 `ρ`，百 MP 级载体不必多分配两张全图；
- 无 Fisher（`I≤0`/NaN）的元素视为 inactive，不参与熵；调用方自行决定其代价（J-MiPOD 的 DC 记为 wet）。

### 2.6 为什么 `alpha` 不进线上格式

`ρ` 是 `I` 的严格单调函数：对任意 `scale>0`，`ρ_n = h^{-1}(scale·I_n)`。因此改变 `alpha` 只改变代价的单调变换，**不改变槽位排序**。

PNG 引擎在提取端要在 stego 上重算代价图并重建排序；只要排序不变，`alpha` 就可以只作为嵌入端调参，不必写入 FeatureWord。实测 `alpha=0.05/0.20/0.80` 的排序完全一致（最便宜 1% 重合 100%）。

## 3. 空域方差估计（MiPOD 与 J-MiPOD 共用）

### 3.1 内容抑制：Wiener 残差

先用自适应 Wiener 滤波去掉内容，只留零均值残差：

```
r = z - wiener2(z)
```

`wiener2` 语义：局部均值 `m`、局部方差 `v`、噪声功率 `ν² = mean(v)`，

```
out = m + max(v - ν², 0)/v · (z - m)
r   = (z - m) · min(1, ν²/v)
```

论文固定 `w = 2`，官方 MATLAB 与 conseal 都是 `wiener2(X,[2 2])`；本实现同样用 2×2，零填充、左上对齐（Matlab `filter2` 语义）。

### 3.2 局部参数模型与 MLE 方差

在 `p×p` 邻域内把残差建模为

```
r_n = G a_n + ξ_n
```

`G` 的列是二维余弦多项式（离散三角多项式），MLE 方差为

```
σ_n² = ||P_G^⊥ r_n||² / (p² - q)
P_G^⊥ = I - G(G^T G)^{-1} G^T
```

论文推荐的 medium 配置：`p=9`，多项式阶 `l=9`，参数数 `q=l(l+1)/2=45`，自由度 `p²-q=36`。

### 3.3 可分离加速：不构造 81×81 矩阵

一维标准正交 DCT-II 基

```
φ_k(a) = c_k sqrt(2/p) cos(π k (2a+1)/(2p)),  c_0=1, c_k=1 (k>0)
```

本身是 `R^p` 的正交基。模型空间 `{ku+kv < l}` 恰好等于张量积基 `φ_ku ⊗ φ_kv` 在 `ku+kv < l` 下的张成空间，因此正交补就是

```
{φ_ku ⊗ φ_kv : ku + kv ≥ l}
```

由 Parseval：

```
||P_G^⊥ r_n||² = Σ_{ku+kv≥l} <φ_ku ⊗ φ_kv, r_n>²
```

每个内积都可分离成一维点积：先沿 x 投影得到 `p` 个通道，再沿 y 组合。`p=9/l=9` 时有 36 个补空间基，无需任何矩阵求逆。

数值核对：与显式 `P_G^⊥` 投影的误差在 `1e-14` 量级（见单元测试 `separable_complement_equals_explicit_projector`）。

实现上按输出行带处理：只保留 `(band + 2·half)` 行的一维投影（16 MB 预算），内存不随图像高度线性膨胀。邻域越界采用镜像填充（NumPy `symmetric` / 论文的 mirror padding）。

### 3.4 方差下界与 Fisher 平滑

```
σ_n² ← max(0.01, σ_n²)          (论文 Eq. 27)
I_n  = 2 / σ_n⁴
```

再对 `I_n` 做 7×7 箱式平滑（论文 §VI-F 推荐；conseal 也这样做）。平滑把高代价像素的影响扩散到邻域，使嵌入更保守，并提高纹理区的改动熵。

## 4. J-MiPOD：把空域方差传播到 DCT 域

### 4.1 步骤

1. **实值解压**：反量化 + 8×8 逆 DCT，得到像素平面 `X = iDCT(U ⊙ q)`。strhide 复用 `precover::decompress_luma`。
2. **空域方差**：在同一平面上运行第 3 节的估计器。按官方发布实现取小的 `p=3/l=3`；论文文字只说“使用 MiPOD 的估计器”，其推荐配置是 medium 9/9，两者都自洽，我们选择与官方代码一致、计算量更小的 3/3。
3. **方差传播**：独立像素模型下，未量化 DCT 系数的方差为

```
Var(u_{v,u}) = Σ_{y,x} C[y,v]² C[x,u]² σ²[y,x]
```

用 `B = C ⊙ C`（C 为 8×8 正交 DCT 矩阵），每块就是

```
V = Bᵀ S B
```

再除以量化步长平方得到量化系数方差：

```
σ_DCT²[k] = V[k] / q_k²
```

4. **Fisher 信息与代价**：`I = 2/σ_DCT⁴`，同一套 `ρ` 求解与载荷标定，DC 永远 wet（不参与熵、不嵌入）。

### 4.2 J-MiPOD 与空域的关键差异

论文明确警告：JPEG 域**不要**沿用空域的 `0.01` 方差下界，也不要加 `1/12` 量化噪声项。原因：

- `q_k²` 在中高频可达 `10³~10⁴`；
- 平面块的空域方差再大，除以 `q_k²` 后也可能极小；
- 若再加 `0.01` 或 `1/12`，平坦块的高频系数会被误判为“安全”，从而被过度修改。

本实现只在 DCT 方差上加官方的数值保护 `1e-5`；空域侧只留 `1e-6` 防零底限。

载荷口径采用官方代码的 `bpnzAC`（每非零 AC 系数的比特数）；全零 AC 的极端载体退回按 AC 总数计，避免参考载荷恒为 0。参考值默认 `0.20`.

### 4.3 与官方发布实现的差异（有意）

| 项 | 官方发布 | 本实现 | 原因 |
|---|---|---|---|
| 空域块大小 | `(3,3)` | `(3,3)` | 与官方一致 |
| 预载体加 128 | 是 | 否（`decompress_luma` 不加） | 内部像素统计位移不变；零填充 Wiener 只在最外一圈有差异 |
| Fisher 后置滤波 | 3×3 `[1 3 1; 3 4 3; 1 3 1]` | 不做 | 2020 论文 Algorithm 1 不含；省一张 `blocks*64` 中间图 |
| 方差下界 | DCT 域 `1e-5` | 同 | 与官方一致 |
| 载荷参考 | `bpnzAC` | 同 | 与官方一致 |

## 5. 与论文/参考实现的对照（MiPOD）

| 项 | 论文 | DDE `MiPOD.m` | conseal | 本实现 |
|---|---|---|---|---|
| Wiener 窗口 | `w=2` | `[2 2]` | `(2,2)` | 2×2 零填充 |
| 块大小 p / 阶 l | medium `9/9` | `5/4` | `9/9` | `9/9` |
| 方差下界 | `0.01` | `0.01` | `0.01` | `0.01` |
| 7×7 Fisher 平滑 | 推荐 | 注释掉 | 是 | 是 |
| 概率/代价求解 | Eq (18)-(20) | 查表 `ixlnx3` | 查表 | `ρ` 形式单调牛顿 |
| 提取端排序 | — | — | 不适用 | `pixel & 0xF8` 掩码保证逐位一致 |

说明：DDE 发布的 `MiPOD.m` 用 `(5,4)` 且把平滑注释掉了，与论文正文推荐不完全一致；本实现以论文 medium 配置 + conseal 的结构为准。

## 6. 代码结构与数据流

### 6.1 文件

| 文件 | 职责 |
|---|---|
| `rust/src/stego/spatial_variance.rs` | 2×2 Wiener 残差、可分离补空间方差估计（行带、镜像填充）、箱式平滑 |
| `rust/src/stego/cost_calibration.rs` | `ρ(e^ρ+2)=x` 求解、稳定熵、Illinois 标定、确定性分块归约、Fisher→ρ |
| `rust/src/stego/png/cost/mipod.rs` | PNG MiPOD：类掩码亮度、p=9/l=9、7×7 平滑、`alpha` 参考载荷 |
| `rust/src/stego/jpeg/cost/jmipod.rs` | JPEG J-MiPOD：解压、3×3 空域估计、`BᵀSB/q²`、DC wet、bpnzAC |
| `rust/src/stego/png/registry.rs` | wire id 3、名称/列表 |
| `rust/src/stego/jpeg/registry.rs` | `jmipod` 名称/列表（JPEG 无需 wire id） |
| `rust/src/stego/options.rs` | `SpatialAlgorithm::Mipod` / `JpegAlgorithm::Jmipod` |

### 6.2 PNG 数据流（嵌入与提取）

```
pixels ──(&0xF8 掩码 + 亮度)──▶ 方差估计 ──▶ I=2/σ⁴ ──7×7 平滑──▶ ρ(I, alpha) ──▶ 代价图
                                                                        │
                                            SlotPlan（按代价 + 索引全序排序）◀── 同一条路径在 stego 上重算
```

关键不变量：引擎只在像素的 8 值等价类内做 ±1 改动，`pixel & 0xF8` 在 cover/stego 上完全相同，因此两端代价图逐位一致。FeatureWord 记录 `algorithm_id=3`，提取端据此选模型。

### 6.3 JPEG 数据流（仅嵌入端需要代价）

```
系数 ──▶ 反量化+iDCT ──▶ 空域方差 ──▶ BᵀSB/q² ──▶ I ──▶ ρ ──▶ 每系数代价（DC=wet）
                                                                  │
                                                           STC 超块 + 熵编码
```

JPEG V3 的槽位由密码与几何决定，提取端**不计算代价**，所以新模型对解码零影响，也不需要 wire id。

## 7. 复杂度、性能与实测

### 7.1 复杂度

- 空域方差估计：`p=9` 时约 `p²`（水平）+ `p(p-1)/2 · p`（垂直）≈ 400 次乘加/像素；
- 平滑：两次一维箱式，O(N)；
- 标定：约 8-10 次 Illinois 评估 + 一次逐像素 ρ 求解，全部 Rayon 并行；
- 内存：行带 16 MB + 2-3 张全图 f64（方差/对数/代价已原地复用）。

### 7.2 实测（本机，release exe）

| 载体 | 算法 | 结果 |
|---|---|---|
| 1920×1280 PNG (2.46 MP) | mipod | embed+extract 2.6 s（冒烟） |
| 4000×6000 PNG (24 MP) | mipod | embed 30.3 s + extract 13.9 s |
| 10752×6144 PNG (66 MP) | mipod | embed 79.1 s + extract 35.7 s |
| 8192×12288 JPEG (100 MP) | jmipod | embed 55.2 s + extract 0.8 s |
| 10276×6850 PNG (70 MP) | mipod | 引擎拒绝（> 67108864 像素上限），SKIP |

PNG 提取需要重算代价图，因此约为嵌入侧的 40-50%；JPEG 提取不计算代价，仅需熵解码。

### 7.3 回归矩阵

- 真实 exe：`temp/teststego` + `temp/testhighres`，35 张 PNG/JPEG，新算法 28 PASS / 7 SKIP（引擎设计拒绝）/ 0 FAIL，357.6 s；
- local 库 API：`temp/teststego`，PNG hill/suniward/mipod + JPEG uerd/juniward/jmipod，57 PASS / 12 SKIP / 0 FAIL，184 s，JPEG DC 全部未变。

## 8. 验证要点

1. **可分离投影 = 显式投影**：`p=3/9`、`p=5/degree=4` 均与 `I-G(G^TG)^{-1}G^T` 对照，误差 ~1e-14。
2. **方差传播**：`BᵀSB` 对照完整 64×64 DCT 协方差对角，误差 <1e-9。
3. **ρ 求解**：`x` 从 `1e-300` 到 `1e300`（含 `x=1`、`1.000001`）方程残差 <1e-12。
4. **排序与载荷无关**：`alpha` 改变后槽位排序不变。
5. **提取一致性**：类内 ±1 改动后 PNG 代价图逐位不变。
6. **内容自适应性**：平坦区域代价显著高于纹理区域；JPEG 平坦块代价高于忙碌块，DC 恒 wet。
7. **端到端**：PNG 写入后可被默认选项提取；JPEG 写入后无需算法名即可提取。

测试入口：

```bash
cd rust
cargo test --all-features --lib mipod
cargo test --all-features --test test_lifecycle mipod
# 真实 exe 全语料（新算法）
python scripts/stego_algorithm_matrix.py --only mipod,jmipod --jobs 2
# 库 API 全算法（ignored）
cargo test --release --all-features --test local_tests local_all_algorithms -- --ignored --nocapture
```

## 9. 局限与后续可改进点

1. **模型假设**：独立高斯、忽略 DCT 系数间相关（论文指出非对角项很小，但并非为零）；如需更强安全可评估 SI-J-MiPOD / 多变量版本。
2. **载荷未知**：`alpha` 只是参考率，不随真实载荷变化；好在排序与 `alpha` 无关，不影响可解码性，只影响 STC 的权重形状。
3. **彩色策略未实现**：只嵌入亮度分量，未实现论文的 DeLS/DiLS 跨通道载荷分配。
4. **大图耗时**：MiPOD 的 p=9 可分离投影在 60 MP 级 PNG 上约 1-2 分钟/次；若要更快，可评估 `(3,3)` 或多尺度上限，但会改变代价形状。
5. **边界差异**：Wiener 零填充与官方 2×2 语义一致；J-MiPOD 预载体不加 128 电平位移，仅最外一圈统计略有差异。
6. **跨平台**：极端近并列的代价理论上会受 libm 末位差异影响；引擎按 `(cost bits, index)` 全序排序，本机可复现。

## 10. 总结

1. MiPOD 的核心是“用载体统计模型求最优改动概率”，不是启发式滤波器；`I=2/σ⁴` 决定了平坦区必须贵、纹理区可以便宜。
2. 可分离 DCT-II 补空间投影把论文的 `81×81` 矩阵运算降成 36 组分隔的一维内积，精度保持机器极限，同时可以行带处理控制内存。
3. 把方程改写为 `ρ(e^ρ+2)=x` 是数值稳定性的关键：单调牛顿全程无钳位，既消除旧稿的 `x≈1` 崩溃，也消除代价平台，并顺带证明排序与参考载荷无关。
4. J-MiPOD 只是把同一套方差估计搬到 DCT 域：`BᵀSB/q²` 完成协方差传播，再叠加 JPEG 特有的量化下界与 `bpnzAC` 口径；DC 永远 wet。
5. strhide 的接入方式是“代价模型 + 自描述载体”：PNG 用 FeatureWord 的 wire id 让提取端重放同一代价图，JPEG 的提取完全不需要代价，因此新模型对两端的解码路径都是纯增量。
6. 当前实现已在 2.46 MP～100 MP 的真实 PNG/JPEG 上完成全算法矩阵回归，新算法 0 失败；主要已知取舍（J-MiPOD 不做官方后置滤波、MiPOD 单尺度 p=9、`alpha` 仅作参考率）均已写入代码注释与本文档。
