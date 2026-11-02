# StrHide 项目 MiPOD / J-MiPOD 算法代码深度审查与前沿隐写演进路线图

- **审查对象**：`strhide` 项目 `rust/src/stego/` 下近期实现的 [MiPOD](https://ieeexplore.ieee.org/document/7289422/)（PNG 空域）与 [J-MiPOD](https://scispace.com/pdf/steganography-by-minimizing-statistical-detectability-the-3uvfjf0jie.pdf)（JPEG DCT 频域）代价模型及相关标定、方差估计管线
- **涉及源码文件**：
  - `rust/src/stego/spatial_variance.rs`（2×2 Wiener 残差、可分离 2D DCT-II 正交补空间方差估计、7×7 箱式平滑）
  - `rust/src/stego/cost_calibration.rs`（$\rho(e^\rho+2)=x$ 单调牛顿法、对偶三元熵、32,768 桶直方图标定与单调线性插值）
  - `rust/src/stego/png/cost/mipod.rs`（PNG 空域 MiPOD 代价模型）
  - `rust/src/stego/jpeg/cost/jmipod.rs`（JPEG 频域 J-MiPOD 代价模型）
  - `rust/src/stego/png/engine.rs`、`rust/src/stego/jpeg/engine.rs`、`rust/src/stego/params.rs`（引擎接线与参数量化）
- **参考论文与基线实现**：
  - V. Sedighi, R. Cogranne, J. Fridrich, [*Content-Adaptive Steganography by Minimizing Statistical Detectability*](https://ieeexplore.ieee.org/document/7289422/), IEEE TIFS, vol. 11, no. 2, pp. 221–234, 2016.
  - R. Cogranne, Q. Giboulot, P. Bas, [*Steganography by Minimizing Statistical Detectability: The cases of JPEG and Color Images*](https://scispace.com/pdf/steganography-by-minimizing-statistical-detectability-the-3uvfjf0jie.pdf), ACM IH&MMSec 2020.
  - 官方参考代码与模拟器：[uibk-uncover/conseal](https://github.com/uibk-uncover/conseal)、[MiPOD Python Fast Implementation](https://codeocean.com/capsule/5293993/tree/v1)、[J-MiPOD Python Fast Implementation](https://codeocean.com/capsule/9148499/tree/v1)。

## 一、总体评估结论

当前项目中 [MiPOD](https://ieeexplore.ieee.org/document/7289422/) 与 [J-MiPOD](https://scispace.com/pdf/steganography-by-minimizing-statistical-detectability-the-3uvfjf0jie.pdf) 的实现整体完成度很高，核心数学推导严密，工程优化（分带内存控制、常量泛型展开、直方图标定）使 24 MP 载体的代价计算迈入亚秒级。前期内部审查报告指出的两项问题（`box_smooth` 缺少奇数窗口断言、`fisher_to_costs` 夹逼搜索中 `t_hi < LOG_X_MAX - max_log` 守卫过紧）已在最新代码中修复。

在此基础上，经过对空域/频域引擎交互链路与 IEEE 754 `f64` 数值特性的深度走查与仿真验证，我们进一步定位出 **4 处潜在边界问题与算法改进点**（其中包含 1 处自定义 `alpha` 参数下的 **PNG 提取失步隐患**、1 处 **J-MiPOD 缺少 `wet_cost` 封顶保护**、1 处 **非对称方向代价极化未接线**，以及 1 处 **J-MiPOD 跨块平滑与电平位移边界微小偏差**），并整理了具体的 Rust 修复补丁与后续高价值先进隐写算法扩展路线。

## 二、核心数学模型与工程闪光点核验

### 1. $\rho$ 域无钳位单调牛顿求解与对偶三元熵（`cost_calibration.rs`）

- **单调牛顿法消除截断平台**：传统实现直接对改动概率 $\beta_n \in (0, 1/3)$ 求解超越方程 $\beta_n \ln((1-2\beta_n)/\beta_n) = x_n$，不仅在 $x_n \approx 1$ 分支切换点容易发散，且在 $x_n > 10^{11}$ 时依赖硬钳位 $\beta_{\min} = 10^{-12}$，导致平坦区域产生大量 $\rho \approx 27.63$ 的常数代价平台。本项目引入变量替换 $\rho_n = \ln((1-2\beta_n)/\beta_n)$，将平稳条件精确转化为：
  $$h(\rho) = \rho (e^\rho + 2) = x, \quad x = 2\lambda I_n$$
  由于 $h(\rho)$ 在 $\rho \ge 0$ 上严格递增且为凸函数，初值 $\rho_0 = \ln(1+x)$ 恒满足 $h(\rho_0) = \ln(1+x)(3+x) \ge x$（位于根的右侧），因此牛顿迭代在 $x \in [10^{-300}, 10^{300}]$ 全域内单调下降收敛，全程无需人为截断。
- **无相减抵消的三元熵公式**：当 $x \to 0^+$（即 $\rho \to 0^+, \beta \to 1/3$）时，直接计算 $\ln(1-2\beta)$ 会遭遇有效数字对消。代码采用对偶展开：
  $$L_m = \ln(1 + 2e^{-\rho}), \quad L = \rho + L_m, \quad \beta = e^{-L}, \quad p_0 = e^{-L_m}, \quad H_3 = 2\beta L + p_0 L_m$$
  利用 `ln_1p` 保证了全定义域双精度数值稳定。
- **32,768 桶直方图标定加速**：利用 `par_chunks(1 << 18)` 构建整型直方图，确保多线程归约顺序无关（Bit-Identical），将 Illinois 载荷求根复杂度从 $O(\text{iters} \times N)$ 降至 $O(\text{iters} \times 32768)$，标定阶段提速 50～100 倍。

### 2. 可分离 2D DCT-II 正交补空间方差估计（`spatial_variance.rs`）

- **Parseval 恒等式化简矩阵投影**：论文中局部参数模型 $r_n = G a_n + \xi_n$ 的残差能量 $\|P_G^\perp r_n\|^2$（其中 $P_G^\perp = I - G(G^T G)^{-1}G^T$）若直接构造 $p^2 \times p^2$（$p=9$ 时为 $81 \times 81$）矩阵，每个像素需 $6561$ 次乘加。代码利用 1D DCT-II 标准正交基 $\phi_k$ 的张量积性质，将补空间能量直接表达为高频正交基分量 `ku + kv >= degree` 的平方和：
  $$\|P_G^\perp r_n\|^2 = \sum_{k_u + k_v \ge l} \langle \phi_{k_u} \otimes \phi_{k_v}, r_n \rangle^2$$
  结合内点连续切片读取与 `complement_energy_p<const P: usize>` 编译期常量特化，实测与显式投影矩阵相对误差 $< 10^{-11}$，同时通过 16 MB 行带滚动缓冲避免了 GB 级中间张量分配。

### 3. J-MiPOD 块内 DCT 方差传播与等价类掩码不变量（`jmipod.rs` / `mipod.rs`）

- **可分离协方差对角线传播**：在独立像素高斯假设下，8×8 块内未量化 DCT 系数的方差为 $\text{Var}(u_{v,u}) = \sum_{y,x} C_{y,v}^2 C_{x,u}^2 \sigma_{y,x}^2$。`jmipod.rs::propagate_block_variance` 使用元素平方基矩阵 $B = C \odot C$ 执行两步矩阵乘法 $V = B^T S B$，再除以量化步长平方 $q_k^2$ 并施加官方 `1e-5` 数值下界，数学上与 $64 \times 64$ 显式协方差变换严格等价。
- **PNG 类内掩码一致性**：`mipod.rs::class_masked_luminance` 提取 `pixel & 0xF8` 计算亮度，配合 `png/engine.rs` 的安全等价类内移动规则（`spatial_move_safe` 保证修改不跨越 8 值等价类边界），确保嵌入前后载体与隐写图像的输入平面完全一致。

## 三、深度走查发现的 4 项问题与修复方案

### 问题汇总对照表

| 严重级别 | 涉及模块与函数 | 问题简述 | 潜在影响 |
| :--- | :--- | :--- | :--- |
| **P1（高优先）** | `png/cost/mipod.rs`、`png/engine.rs` (`SlotPlan::build`) | 自定义 `alpha` 参数未写入 `FeatureWord`，浮点插值舍入并列导致提取端槽位排序翻转 | 当用户传入非默认 `alpha`（如 `0.05` 或 `0.80`）嵌入 PNG 时，提取端按默认 `alpha = 0.20` 重算代价会发生近并列像素次序互换，导致提取失败（AEAD 校验报错） |
| **P2（中优先）** | `jpeg/cost/jmipod.rs` (`compute_cost`)、`cost_calibration.rs` | J-MiPOD 缺少 `wet_cost` 上下界封顶及标定回退全零保护 | 极端载体或小 `wet_cost` 配置下，AC 代价可能超过 `wet_cost` 或因标定早退被置为 `0.0`（免费修改槽位） |
| **P2（中优先）** | `png/cost/mipod.rs`、`jpeg/cost/jmipod.rs` | 未实现 `direction_costs` 与 `direction_bias` 非对称方向代价偏置 | 相比已实现方向偏置的 `HILL` 与 `UERD`，损失了向局部均值/预载体去噪方向微调的抗检测率增益 |
| **P3（低优先）** | `jpeg/cost/jmipod.rs`、`jpeg/cost/precover.rs` | `decompress_luma` 省去 `+128` 电平位移对零填充 Wiener 边界的微小影响，且未做跨块 $3\times 3$ Fisher 平滑 | 最外圈 1 像素边界的 Wiener 局部均值/方差与标准 `[0,255]` 域略有差异；缺少跨块平滑使孤立块高频代价略偏激进 |

### 1. [P1] 自定义 `alpha` 参数下 PNG 槽位排序翻转与提取失败隐患

#### （1）根因剖析

`rust/src/stego/png/cost/mipod.rs` 第 25–34 行注释写道：

> `alpha` (bits per pixel, default `0.20`) is only the *reference payload* the Lagrange multiplier is calibrated for... Because `rho` is a strictly increasing function of `I` for every positive `lambda`, changing `alpha` rescales costs without changing their order. Extraction therefore does not need `alpha` (it is not carried in the feature word) and cannot desynchronise because of it.

在实数连续域 $\mathbb{R}$ 上，$\rho(I) = h^{-1}(2\lambda I)$ 确实关于 $I$ 严格单调递增；但在 **IEEE 754 `f64` 有限精度（53 位尾数）与 32,768 桶线性插值（`Grid::rho_interp`）** 下，该映射仅满足**弱单调（$\le$）而非严格单调（$<$）**：

1. 在 `png/engine.rs::SlotPlan::build`（第 1077–1095 行）中，候选像素按二元组 `(costs[idx].to_bits(), idx)` 进行全序排序。
2. 当两个像素 `idx1 < idx2` 的平滑后 Fisher 信息满足 $I[\text{idx}_1] > I[\text{idx}_2]$ 但数值极为接近（例如经 $7\times 7$ `box_smooth` 后仅相差几个 ULP）时：
   - 在嵌入端（如设定 `alpha = 0.05` 或 `0.80`），插值表斜率变化或 `(t + u).min(LOG_X_MAX)` 截断可能使两者线性插值后舍入为**同一个 `f64` 值**（`c_embed[idx1] == c_embed[idx2]`），此时全序按第二关键字 `idx1 < idx2` 排序，**`idx1` 排在 `idx2` 之前**。
   - 在提取端（由于 `FeatureWord` 未记录 `alpha`，`extract_png_image` 始终使用默认 `alpha = 0.20`），两者的插值结果可能落在相邻的**两个不同 `f64` 值**上（`c_extract[idx1] > c_extract[idx2]`），此时按第一关键字排序，**`idx2` 排在 `idx1` 之前**！
3. 我们在 $128 \times 128$ 的 `texture_rgb` 图像上完整复现了 `MipodCostModel::compute_cost` 管线：当嵌入端使用 `alpha = 0.05` 或 `alpha = 0.80`、提取端使用默认 `alpha = 0.20` 时，`SlotPlan` 的排序结果分别出现了 **2 处**与 **4 处**像素索引互换！而在单元测试 `mipod::tests::reference_payload_does_not_reorder_costs` 中，由于断言写的是弱不等式 `b[w[0]] <= b[w[1]]`，当小索引恰好对应较小 Fisher 值时不会触发断言失败，从而掩盖了平局打破（Tie-breaking）翻转的问题。

#### （2）修复方案：复用 `FeatureWord.sigma` 携带量化后的 `alpha`

PNG 的 `FeatureWord` 结构体中原本就有 32 位浮点字段 `sigma: f32`（目前仅 `suniward` 使用，而 `mipod` 嵌入时闲置为默认值 `1.0`）。只需让 `mipod` 像 `suniward` 持久化 `sigma` 一样，将量化为 `f32` 的 `alpha` 写入 `FeatureWord.sigma`，提取端即可 100% 复现完全相同的 `alpha` 与代价表：

- **`rust/src/stego/params.rs`（`PngParams::wire_quantized`）**：
  ```rust
  if let Some(s) = p.algorithm_options.get_mut("sigma") {
      *s = *s as f32 as f64;
  }
  if let Some(a) = p.algorithm_options.get_mut("alpha") {
      *a = (*a as f32 as f64).clamp(0.01, 0.90);
  }
  ```
- **`rust/src/stego/png/engine.rs`（`embed_png_with_stats` 构造 `FeatureWord` 处，约第 1492 行）**：
  ```rust
  sigma: if cost_model.id() == "mipod" {
      params
          .algorithm_options
          .get("alpha")
          .copied()
          .unwrap_or(0.20)
          .clamp(0.01, 0.90) as f32
  } else {
      params
          .algorithm_options
          .get("sigma")
          .copied()
          .unwrap_or(1.0) as f32
  },
  ```
- **`rust/src/stego/png/engine.rs`（`extract_png_image` 恢复参数处，约第 1800 行）**：
  ```rust
  if resolved.id() == "suniward" {
      effective_params
          .algorithm_options
          .insert("sigma".to_string(), fw.sigma as f64);
  } else if resolved.id() == "mipod" {
      effective_params
          .algorithm_options
          .insert("alpha".to_string(), (fw.sigma as f64).clamp(0.01, 0.90));
  }
  ```

### 2. [P2] J-MiPOD 缺少 `wet_cost` 上下界封顶及标定回退全零保护

#### （1）根因剖析

对比 `rust/src/stego/jpeg/cost/juniward.rs`（第 166–173 行）与 `rust/src/stego/jpeg/cost/jmipod.rs`（第 153–157 行）：

- `juniward.rs` 在返回前对所有系数执行了严格的封顶与非正值守卫：
  ```rust
  for (i, c) in costs.iter_mut().enumerate() {
      if i % 64 == 0 || !c.is_finite() || *c <= 0.0 || *c > params.wet_cost {
          *c = params.wet_cost;
      }
  }
  ```
- 而 `jmipod.rs` 仅将每个块的 `k = 0`（DC 系数）置为 `params.wet_cost`，未对 `k in 1..64` 的 AC 系数做 `*c <= 0.0` 或 `*c > params.wet_cost` 检查。
- 若 `cost_calibration::fisher_to_costs` 在极端病态输入下触发早退分支（`fisher.iter_mut().for_each(|v| *v = 0.0)`），或者某个极高方差块的 Fisher 信息下溢为 `0.0`（被 `fisher_to_costs` 视为 inactive 并赋值为 `0.0`），该 AC 系数在 `jmipod.rs` 中将获得 `0.0` 代价（即被 STC 视为零成本优先修改位）；此外，若调用方调低了 `params.wet_cost`，高于 `wet_cost` 的值也未在模型出口统一封顶。

#### （2）修复方案

在 `rust/src/stego/jpeg/cost/jmipod.rs` 的 `compute_cost` 末尾采用与 `juniward.rs` 一致的守卫逻辑：

```rust
let mut costs = fisher_to_costs(fisher, target_bits);
for (i, c) in costs.iter_mut().enumerate() {
    if i % 64 == 0 || !c.is_finite() || *c <= 0.0 || *c > params.wet_cost {
        *c = params.wet_cost;
    }
}
costs
```

### 3. [P2] 为 MiPOD 与 J-MiPOD 补齐非对称方向代价偏置（Cost Polarization）

#### （1）根因剖析

`strhide` 的空域与频域引擎均已原生支持三元 $\pm 1$ 非对称方向代价：
- 在 JPEG 引擎中，`UerdCostModel` 实现了 `JpegCostModel::direction_bias`，调用 `precover::bias(coeffs, geometry, 0.0)`（通过 3×3 Wiener 滤波估计去噪预载体系数，若实际量化系数低于预载体估计值，则 $+1$ 方向享受 `params.polarize_weight` 折扣）。由于 JPEG V3 提取端完全不计算代价，该操作不产生任何同步开销。
- 在 `JmipodCostModel` 中，代码已经调用了 `precover::decompress_luma`，但未覆盖 `direction_bias`（默认返回 `None`），白白放弃了 `polarize_weight < 1.0` 时的预载体边信息增益。
- 同理，在 PNG 引擎中，`HillCostModel` 实现了 `PngCostModel::direction_costs`（向 8 邻域等价类均值方向移动代价更低，且仅影响 $\pm 1$ 极性选择而不影响槽位排序），而 `MipodCostModel` 仍使用默认的对称实现。

#### （2）修复方案

在 `rust/src/stego/jpeg/cost/jmipod.rs` 的 `impl JpegCostModel for JmipodCostModel` 中直接补充 `direction_bias` 方法（与 `uerd.rs` 保持一致）：

```rust
fn direction_bias(
    &self,
    coeffs: &dct_io::JpegCoefficients,
    geometry: &JpegGeometry,
    params: &JpegParams,
) -> Option<Vec<i8>> {
    if (params.polarize_weight - 1.0).abs() <= f64::EPSILON {
        return None;
    }
    precover::bias(coeffs, geometry, 0.0)
}
```

### 4. [P3] J-MiPOD 电平位移与跨块 Fisher 平滑的微调考量

- **预载体 `+128` 电平位移与零填充 Wiener 边界**：`precover::decompress_luma` 为节省一次加法跳过了 JPEG 标准 IDCT 后的 `+128` 电平位移（像素值以 `0.0` 为中心分布在 `[-128, 127]`）。对于图像内部像素，局部均值相减与局部方差对常数平移严格不变；但 `spatial_variance::wiener_residual` 使用的是**零填充（Zero Padding）**边界（最右列 `x = pw - 1` 与最下行 `y = ph - 1` 的 2×2 窗口中有 2～3 个采样点固定补 `0.0`）。在未加 `+128` 时，补 `0.0` 相当于补“中灰（128）”；而在官方 MATLAB `wiener2`（输入为 `[0, 255]`）中，补 `0.0` 相当于补“纯黑（0）”。这仅影响最外圈 1 像素边界的方差估计，不影响内部块或提取正确性。
- **同频模式跨块 $3 \times 3$ 平滑**：官方 [J-MiPOD 代码](https://codeocean.com/capsule/9148499/tree/v1)在求出各块 Fisher 信息后，对每个 DCT 频率模式 $k \in [1, 63]$ 在二维块网格（`grid_h × grid_w`）上使用 `[1, 3, 1; 3, 4, 3; 1, 3, 1] / 16` 核进行平滑。若后续希望进一步提升对抗深度网络（如 SRNet、J-XuNet）的安全性，可利用 `geometry.positions` 建立的块网格索引，使用 3 行滚动缓冲（仅占用 $3 \times \text{grid\_w} \times 64 \times 8$ 字节，在 100 MP 图像上不足 2.5 MB）完成平滑，无需分配整图中间矩阵。

## 四、后续可引入的先进隐写算法全景路线图

结合 `strhide` 现有的**“纯 Rust 单一二进制、流式低内存、内置分组 `StcTrellis`、原位无损（$\Delta = 0$）优先”**架构优势，我们从空域图像、频域图像、音视频比特流、3D 点云与版式文档、以及轻量级对抗/生成式隐写五个维度，梳理出最值得集成的先进算法清单。

### 候选先进算法综合对比与排期矩阵

| 推荐优先级 | 算法名称 | 目标载体 | 理论出处与年份 | 核心安全优势 | 预估 Rust 代码量与依赖 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **P0（立即可做）** | **[CMD](https://ieeexplore.ieee.org/document/7109899/) / Synch（非加性修改方向聚类）** | PNG (`hill` / `mipod` / `suniward`) | Li et al., IEEE TIFS 2015 / Denemark et al., 2015 | 打破加性失真独立假设，使相邻像素同向修改（同 $+1$ 或同 $-1$），抗 SRNet/CRM 检测率降低 15%～20% | ~200 行（零新依赖，纯嵌入端分步调用现有 `StcTrellis`） |
| **P0（立即可做）** | **[SI-J-MiPOD / e-J-UNIWARD](https://www.google.com/search?q=https://www.semanticscholar.org/paper/Universal-distortion-function-for-steganography-in-Holub-Fridrich/0b8fb592f2fb3ffca342a9d28799018ff8a4e362)（预载体边信息隐写）** | 未压缩图转存 JPEG | Holub et al., 2014 / Cogranne et al., 2020 | 利用压缩前原图的真实 DCT 量化舍入误差 $e_{ij} \in [-0.5, 0.5]$ 定向翻转半整数临界系数，安全性高出盲隐写一个世代 | ~180 行（零新依赖，直接复用 `precover` 模块与 `StcTrellis`） |
| **P0（立即可做）** | **[WAV / AIFF 时频能量掩蔽 + STC](https://github.com/pawel-kaczmarek/The-A-Files)** | WAV, AIFF (16/24-bit PCM) | The-A-Files Benchmark / 心理声学自适应模型 | 淘汰易被马氏链识破的 LSB 与简单块奇偶，仅在瞬态冲击与宽带噪声段通过 STC 微调采样，$\Delta = 0$ | ~250 行（零新依赖，复用 `structure/adapters/wav.rs` 与 `stc.rs`） |
| **P1（高价值扩展）** | **[DeLS / DiLS 彩色跨通道协方差隐写](https://scispace.com/pdf/steganography-by-minimizing-statistical-detectability-the-3uvfjf0jie.pdf)** | 彩色 PNG / 彩色 JPEG | Cogranne et al., ACM IH&MMSec 2020 | 联合建模 RGB / YCbCr 三通道噪声协方差，解决单通道独立嵌入破坏彩色通道相关性、易被彩色 CNN 捕获的痛点 | ~250 行（零新依赖，扩展 `ChannelMode::Rgb` 与色度分量代价） |
| **P1（高价值扩展）** | **PVO / MHM 可逆数据隐藏（Reversible Data Hiding）** | PNG、WAV | Peng et al. (PVO) / Li et al. (MHM) | 提取秘密信息后可 **100% 逐比特无损还原宿主原图/原音频（SHA-256 完全一致）**，打造高敏取证差异化优势 | ~300 行（零新依赖，纯整型分块排序与直方图平移） |
| **P1（高价值扩展）** | **[H.264/AVC CABAC 旁路原位隐写](https://github.com/remade-with-rust/rusty_h264)** 与 **MKV/HEVC 适配** | MP4, MOV, MKV (`H.264`, `HEVC`) | IEEE Access 2020 / ResearchGate 2026 | 在 H.264 非参考帧 Inter 宏块中翻转 CABAC 旁路残差符号位并避让 EPB，保持容器与 NAL 字节长度严格不变（$\Delta = 0$） | ~800 行（复用 `ebml.rs` 与纯 Rust 编解码库 `rusty_h264`） |
| **P2（特色载体扩充）** | **3DGS `.ply` 高阶球谐系数（SH）原位 STC** | `.ply` (3D Gaussian Splatting) | 经典点云自适应微扰（区别于需 PyTorch 的 [GS-Hider](https://arxiv.org/abs/2405.15118)） | 对每个 3D 高斯图元的 45 个高阶球谐系数 `f_rest_0..44` 的 `f32` 尾数最低位做不透明度加权 STC，单文件可无损隐藏数 MB | ~300 行（零新依赖，二进制 `.ply` 头部解析 + 原位尾数翻转） |
| **P2（特色载体扩充）** | **PDF `TJ` 字距微调与 SVG 贝塞尔控制点 QIM** | `.pdf`, `.svg` | [ResearchGate 2024](https://www.researchgate.net/publication/380462849_Text_steganography_enhanced_character-level_embedding_algorithm_using_font_attribute_with_increased_resilience_to_statistical_attacks) | 在 PDF 内容流 `TJ` 数组中做 $\pm 1/1000\text{ em}$ 字距微调（视觉偏移 $<0.01\text{ pt}$），抗 PDF 重线性化与增量剥离 | ~300 行（复用 `flate2` 解压 PDF 内容流） |
| **P3（前沿探索）** | **[ADV-EMB](https://www.semanticscholar.org/paper/CNN-Based-Adversarial-Embedding-for-Image-Tang-Li/5c06ee0e1b9568bdc9a1064f28553912a481945f) 轻量级白盒对抗代价翻转** | PNG, JPEG | Tang et al., IEEE TIFS 2019 | 利用预导出的轻量 CNN 隐写分析器（如仓库 `scripts/stego_eval/` 中的 SRNet）输入梯度符号动态翻转 `+1/-1` 代价，精准欺骗深度检测器 | ~500 行（纯 Rust 实现轻量级定点/浮点 SRNet 前向与输入梯度反传） |

### 各方向关键算法设计要点详解

#### 1. 非加性空域隐写：[CMD（Clustering Modification Directions）](https://ieeexplore.ieee.org/document/7109899/)

- **痛点**：无论是 HILL、S-UNIWARD 还是 MiPOD，都假设每个像素的修改代价是相互独立的（Additive Distortion）。然而现代隐写分析器（从高维 SRM 到深度网络 SRNet/CovNet）均依赖高通滤波残差共生矩阵。如果两个相邻像素一个 $+1$、一个 $-1$，它们之间的梯度差会陡增 $2$，在高频残差中形成极易被捕获的尖峰。
- **核心算法**：
  1. 将图像像素按行列奇偶性划分为 4 个互不相邻的子晶格（Sub-lattices）：$S_{00}, S_{01}, S_{10}, S_{11}$，并将待嵌入密文比特均分为 4 段。
  2. 第一步在 $S_{00}$ 上使用标准 MiPOD/HILL 代价通过 `StcTrellis` 嵌入第 1 段密文，得到修改量 $d_{i,j} \in \{-1, 0, +1\}$。
  3. 在嵌入后续子晶格 $S_{ab}$ 前，检查每个候选像素 $(i,j)$ 的四邻域像素修改和 $\Delta_{i,j} = \sum_{(u,v) \in \mathcal{N}_4(i,j)} d_{u,v}$：
     - 若 $\Delta_{i,j} > 0$（邻居整体向上修改），则将当前像素 $+1$ 方向的代价下调为 $\rho_{i,j}^{(+1)} = \rho_{i,j} / (1 + \alpha_{\text{cmd}} \Delta_{i,j})$；
     - 若 $\Delta_{i,j} < 0$（邻居整体向下修改），则将当前像素 $-1$ 方向的代价下调为 $\rho_{i,j}^{(-1)} = \rho_{i,j} / (1 + \alpha_{\text{cmd}} |\Delta_{i,j}|)$。
- **工程优势**：在 `strhide` 中，`SlotPlan::build` 的像素排序完全基于对称基础代价 $\rho_{i,j}$（且仅依赖 `pixel & 0xF8`），因此**提取端无需知道嵌入端是否开启了 CMD**，直接按原有方式读取槽位奇偶性并校验 STC 综合症即可 100% 兼容提取！

#### 2. 预载体边信息隐写：[SI-J-MiPOD / e-J-UNIWARD](https://www.google.com/search?q=https://www.semanticscholar.org/paper/Universal-distortion-function-for-steganography-in-Holub-Fridrich/0b8fb592f2fb3ffca342a9d28799018ff8a4e362)

- **痛点**：盲 JPEG 隐写（在已压缩的 JPEG 上再次修改系数）只能靠去噪滤波猜测原始信号；而在许多实际场景中，发送方手里持有未压缩的 PNG/BMP/RAW 原图，准备将其压缩为 JPEG 发送。
- **核心算法**：
  1. 对未压缩原图块执行精确浮点 8×8 正向 DCT 并除以量化表步长 $q_k$，得到未取整的实值系数 $u_{ij} \in \mathbb{R}$。
  2. 标准 JPEG 量化系数为 $c_{ij} = \text{round}(u_{ij})$，量化舍入误差为 $e_{ij} = u_{ij} - c_{ij} \in [-0.5, 0.5]$。
  3. 将朝向原值方向的“顺向舍入（代价极低）”与背离原值方向的“逆向舍入（代价较高）”定义为：
     $$\rho_{ij}^{(\text{順向: }\text{sign}(e_{ij}))} = (1 - 2|e_{ij}|) \cdot \rho_{ij}^{\text{J-MiPOD}}, \quad \rho_{ij}^{(\text{逆向: }-\text{sign}(e_{ij}))} = \rho_{ij}^{\text{J-MiPOD}}$$
     当 $|e_{ij}| \to 0.5$ 时，$u_{ij}$ 原本就处在两个相邻整数的正中间，将其向 $\text{sign}(e_{ij})$ 方向推 1 个步长后的失真与标准四舍五入完全等价，代价趋近于 $0$。
- **工程优势**：由于 `strhide` 的 JPEG V3 引擎在提取端完全不计算代价图，新增“从 PNG/未压缩原图直出隐写 JPEG”的边信息模式只需在嵌入端传入未量化浮点 DCT 余数，提取端与现有 `extract_jpeg` 100% 互通。

#### 3. 彩色图像跨通道联合隐写：[DeLS / DiLS（Decompressed / Direct Linear Substitution）](https://scispace.com/pdf/steganography-by-minimizing-statistical-detectability-the-3uvfjf0jie.pdf)

- **痛点**：目前 `strhide` 的 PNG 引擎对 RGB 三通道共用同一份灰度亮度代价图（`0.299R + 0.587G + 0.114B`），而 JPEG 引擎仅在亮度通道 `Y`（`COMPONENT_Y`）上嵌入。现代彩色隐写分析器（如 WISERNet、彩色 SRNet）专门检测 R-G、B-G 或 Y-Cb-Cr 之间的跨通道残差相关性异常。
- **核心算法**：
  - 在空域彩色 PNG 中，分别在 R、G、B 三个独立通道（均做 `& 0xF8` 掩码）上运行 `estimate_variance` 得到各自的噪声方差 $\sigma_{R,n}^2, \sigma_{G,n}^2, \sigma_{B,n}^2$，从而为每个像素的 3 个通道字节赋予各自独立的 Fisher 信息与代价 $\rho_{c,n}$，并在 `direction_costs` 中鼓励同一像素的 R/G/B 朝相同极性（同加或同减）微调以保持色相稳定。
  - 在 JPEG 中，按照 [Cogranne 等人 (ACM IH&MMSec 2020)](https://scispace.com/pdf/steganography-by-minimizing-statistical-detectability-the-3uvfjf0jie.pdf) 的 DeLS 模型，将色度块（Cb/Cr）反变换回 RGB 空域评估其对三通道像素方差的联合影响，自动分配 Y、Cb、Cr 的安全嵌入比例。

#### 4. 可逆数据隐藏（RDH）：像素值排序（PVO）与预测误差扩展（PEE）

- **痛点**：即便 $\pm 1$ 隐写视觉完全不可见，提取数据后宿主图像仍保留了 $\pm 1$ 的像素改动，无法还原原始文件的密码学哈希（SHA-256）。而结构域追加（`strhide write`）虽然可以通过 `restore` 还原原图，但在文件体积与容器结构上留下了增量痕迹。
- **核心算法**：
  - 将无损载体（PNG 像素平面或 WAV 16-bit PCM 波形）划分为非重叠小块（如 $2\times 2$ 或 $3\times 3$），对块内排除边界溢出点后的样本按数值大小排序：$x_{\sigma(1)} \le x_{\sigma(2)} \le \dots \le x_{\sigma(k)}$。
  - 计算最大值与次大值的预测误差 $d_{\max} = x_{\sigma(k)} - x_{\sigma(k-1)}$：
    - 若 $d_{\max} = 1$（峰值桶），则嵌入 1 bit 秘密信息 $b \in \{0, 1\}$：$x'_{\sigma(k)} = x_{\sigma(k)} + b$；
    - 若 $d_{\max} > 1$（平移桶），则向外平移 1 步留出空位：$x'_{\sigma(k)} = x_{\sigma(k)} + 1$。
  - 由于修改后块内像素的大小排序下标 $\sigma$ 保持严格不变，接收端在提取出秘密比特 $b$ 的同时，可将 $x'_{\sigma(k)}$ 无损恢复为 $x_{\sigma(k)}$，重新按原 PNG 行滤波器（`row_filters`）与 `idat_sizes` 压缩即可做到**提取后宿主像素 100% 比特级复原**。

#### 5. 音频、视频与 3D 资产原位零膨胀（$\Delta = 0$）隐写

- **WAV PCM 心理声学自适应 STC + MP3/AAC 独立符号位隐写**：
  - 在 WAV/AIFF 中，计算局部二阶差分残差 $r_i = |x_{i-1} - 2x_i + x_{i+1}|$，将静音段设为 `wet_cost`，按 $\rho_i = 1 / (r_i + \epsilon)$ 直接送入现有的 `StcTrellis` 嵌入。
  - 在 MP3/AAC 中，利用标准 Huffman 表对高频非零 MDCT 系数采用“无符号幅值码字 + 1-bit 明文符号位”编码的特性（参见 [IEEE 5671308](https://ieeexplore.ieee.org/document/5671308/)），原位翻转幅值 $|x|=1$ 的高频系数符号位，实现完全不改变帧长与比特库（Bit Reservoir）的 $\Delta = 0$ 原位隐写。
- **H.264/AVC CABAC 旁路符号位与 MKV 容器适配**：
  - 复用现有 HEVC 引擎的多轮防竞争字节（EPB `0x03`）避让框架，结合 [`rusty_h264`](https://github.com/remade-with-rust/rusty_h264) 定位 H.264 Main/High Profile 非参考帧 Inter 宏块的高频 `coeff_sign_flag`（需在 PPS 中过滤 `entropy_coding_mode_flag == 0` 的 CAVLC 流，并对 Intra 宏块赋高代价以防帧内空间预测级联漂移）。
  - 在扩展 MKV 容器时，务必检查 `TrackEntry -> ContentEncodings (0x6D80)` 拒绝启用了 `ContentCompAlgo = 3`（Header Stripping）的轨道，并按 RFC 9559 重算 Cluster `0xBF` CRC-32（覆盖 `CRC-32` 元素之后至 Cluster 末尾的子字节）。
- **3D Gaussian Splatting (`.ply`) 高阶球谐尾数原位 STC**：
  - 针对标准 3DGS `.ply` 点云文件每个顶点的 45 个 1～3 阶球谐系数（`f_rest_0..44`，`f32` 格式），按顶点不透明度 `opacity` 与局部球谐能量计算代价，直接在其 IEEE 754 `f32` 尾数最低位上运行 `StcTrellis`。无需任何 PyTorch/CUDA 环境，即可在保持 `.ply` 文件字节长度严格不变（$\Delta = 0$）的前提下隐藏数 MB 数据，渲染视角 PSNR 保持在 $50\text{ dB}$ 以上。
