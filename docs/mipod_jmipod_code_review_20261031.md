# MiPOD / J-MiPOD 代码审查与改进方案报告

- **日期**：2026-10-31 21:38:00
- **分支**：`mipod-jmipod-dev`
- **目标提交**：`4475ee7` (`feat(stego): add MiPOD and J-MiPOD cost models`)
- **参考依据**：
  - 实施计划：`docs/mipod_jmipod_impl_plan_20261031.md`
  - 原始论文：
    - V. Sedighi, R. Cogranne, J. Fridrich, *Content-Adaptive Steganography by Minimizing Statistical Detectability*, IEEE TIFS 11(2), 2016.
    - R. Cogranne, Q. Giboulot, P. Bas, *Steganography by Minimizing Statistical Detectability: The cases of JPEG and Color Images*, ACM IH&MMSec 2020.
  - 参考实现与源码：`temp/github/vazswk-MiPOD/`、`temp/github/capsule-7800700-code-jmipod/`、`temp/github/capsule-9148499-code/`、`temp/code/mipod_jmipod_impl/`。

---

## 1. 审查背景与范围

本次审查对分支刚提交的 `4475ee7` 进行了详细的代码走查、数学公式推导核验、边界条件分析及全套实证测试。涉及的核心文件包括：
- `rust/src/stego/spatial_variance.rs`（共享空域方差估计器）
- `rust/src/stego/cost_calibration.rs`（Fisher 信息至 $\rho$ 代价标定求解器）
- `rust/src/stego/png/cost/mipod.rs`（MiPOD 空域 PNG 代价模型）
- `rust/src/stego/jpeg/cost/jmipod.rs`（J-MiPOD 频域 JPEG 代价模型）
- 注册表接线、选项解析、CLI 帮助、GUI 列表及配套测试文件。

---

## 2. 核心数学模型与架构核验结论（确认无误）

经核实，提交代码完整实现了计划中的主要特性，并成功修复了旧版原型中的若干核心缺陷：

### 2.1 $\rho$ 域单调牛顿法与拉格朗日标定
- **原理**：令 $\rho = \ln((1-2\beta)/\beta)$，平稳条件等价于求解凸函数根：
  $$h(\rho) = \rho (e^\rho + 2) = x = \text{scale} \cdot I$$
  由 $\rho_0 = \ln(1+x)$ 出发的牛顿迭代自右侧单调收敛，在 $x \in [10^{-300}, 10^{300}]$ 内全程数值稳定，无需任何硬钳位截断（避免了代价平台）。
- **三元熵计算**：采用对偶展开形式 $H = 2\beta L + p_0 L_m$（其中 $L = \rho + L_m$，$L_m = \ln(1 + 2e^{-\rho})$），避免了在 $\beta \approx 1/3$ 处的差分对消问题。

### 2.2 可分离空域方差估计与行带内存控制
- **可分离投影**：利用 2D DCT-II 基底的正交性，将补空间能量 $\|P_G^\perp r_n\|^2$ 展开为可分离的 1D 投影点积平方和，等价于论文显式矩阵投影，且误差在双精度极限量级（$< 10^{-11}$）。
- **行带分块**：采用固定约 16MB 的行带缓存 `BAND_BYTES` 滚动处理水平投影，峰值内存与图像高度解耦。

### 2.3 JPEG DCT 方差传播与 DC 保护
- **方差传播**：采用 $V = B^T S B$（$B = C \odot C$）进行块内方差传播，单元测试验证与官方 $64 \times 64$ 显式 DCT 协方差矩阵对角线误差 $< 10^{-9}$。
- **DC 保护**：DC 分量在 Fisher 标定阶段保持 inactive（不计入载荷标定熵），且输出代价图中强制设为 `params.wet_cost`，全量测试中确认所有 JPEG 载体的 DC 系数 100% 未被改变。

### 2.4 PNG 提取端自描述与排序不变性
- PNG 载体通过 `FeatureWord.algorithm_id = 3` 自声明为 MiPOD。
- 提取端使用默认参数计算代价，由于 $\rho(x)$ 是关于 Fisher 信息的严格单调函数，参考载荷 $\alpha$ 仅改变代价数值尺度，不改变槽位全序关系（实测 50,000 点在不同标定参数下重排顺序差异为 0）。
- 代价输入采用类别掩码 `pixel & 0xF8`，在类内修改时完全保持不变，提取端与嵌入端具备严格一致性。

---

## 3. 发现的问题与隐患分析

### 3.1 `box_smooth` 窗口参数未做奇数保护（潜在权重放大隐患）
- **位置**：`rust/src/stego/spatial_variance.rs` 的 `box_smooth`
- **问题分析**：
  ```rust
  let half = (window / 2) as isize;
  let inv = 1.0 / window as f64;
  ...
  for d in -half..=half {
      sum += src[reflect_index(x as isize + d, w as isize)];
  }
  *dst = sum * inv;
  ```
  在均值滤波中，循环 `d in -half..=half` 实际遍历了 $2 \times \text{half} + 1$ 个元素。
  - 当 `window = 7`（奇数）时，`half = 3`，累加 7 个点除以 7，计算正确。
  - 若调用者传入偶数（如 `window = 4`），`half = 2`，实际累加了 5 个点（-2, -1, 0, 1, 2），分母却除以 4，导致权重总和为 $5/4 = 1.25$，会静默放大能量。
- **现状**：虽然当前 MiPOD 固定使用 `FI_SMOOTH_WINDOW = 7`，未受影响，但该函数作为公共辅助函数缺乏奇数约束或动态归一化分母。

### 3.2 `fisher_to_costs` 夹逼搜索中 `t_hi` 上界守卫过紧
- **位置**：`rust/src/stego/cost_calibration.rs` 行 194
- **问题分析**：
  ```rust
  while f_hi >= 0.0 && guard < 100 && t_hi < LOG_X_MAX - max_log {
      t_hi += 10.0;
      f_hi = total_entropy_nats(log_fi, t_hi) - target;
      guard += 1;
  }
  if f_hi >= 0.0 {
      fisher.iter_mut().for_each(|v| *v = 0.0);
      return fisher;
  }
  ```
  - 底层 `total_entropy_nats` 中每个元素已经具备 `(t + lg).min(LOG_X_MAX).exp()` 截断保护，即使个别极端像素的 `t + lg >= LOG_X_MAX`，其值也会安全饱和在 $10^{300}$，不会发生浮点溢出。
  - 在外层 `while` 条件中加入 `t_hi < LOG_X_MAX - max_log` 会人为限制 `t_hi` 向右寻找更小熵的能力。在极小载荷或超大动态范围的图像上，`t_hi` 触顶后可能导致 `f_hi >= 0.0` 仍成立，从而误判为求根失败，将整张代价图全置为 0.0。

---

## 4. 解决与改进方案

### 方案 1：修复 `box_smooth` 窗宽归一化与参数校验
在 `rust/src/stego/spatial_variance.rs` 中增加奇数断言，并将分母修改为实际采样的点数：
```rust
pub(crate) fn box_smooth(mut plane: Vec<f64>, w: usize, h: usize, window: usize) -> Vec<f64> {
    let n = w * h;
    if w == 0 || h == 0 || plane.len() < n || window <= 1 {
        return plane;
    }
    assert!(window % 2 == 1, "box_smooth window must be odd");
    let half = (window / 2) as isize;
    let count = (2 * half + 1) as f64;
    let inv = 1.0 / count;
    ...
```

### 方案 2：优化 `fisher_to_costs` 中的 `t_hi` 搜索退出逻辑
在 `rust/src/stego/cost_calibration.rs` 中移除循环条件中的 `t_hi < LOG_X_MAX - max_log`，由内部的 `LOG_X_MAX` 饱和机制和 `guard < 100` 安全控制步进：
```rust
    let mut t_hi = -min_log + 5.0;
    let mut f_hi = total_entropy_nats(log_fi, t_hi) - target;
    let mut guard = 0;
    while f_hi >= 0.0 && guard < 100 {
        t_hi += 10.0;
        f_hi = total_entropy_nats(log_fi, t_hi) - target;
        guard += 1;
    }
```

---

## 5. 测试与基线验证状态记录

截至当前提交，已通过全部标准测试验证：
1. **静态检查**：`cargo clippy`（Rust 根目录及 `gui/src-tauri`）全绿，0 warnings。
2. **测试套件**：全部 388 个库单元测试、154 个生命周期集成测试（含新增 MiPOD/J-MiPOD 6 个用例）通过。
3. **结构域基线**：`python scripts/baseline_hash.py --check` 全部 58 个测试例字节级一致（58/58 PASS）。
4. **真实产物算法矩阵**：`scripts/stego_algorithm_matrix.py` 与 `local_algorithm_matrix.rs` 往返通过，载荷一致。
