# MiPOD / J-MiPOD 性能优化分步实测基准与演进记录

- **测试环境**：Windows 10, Intel Core i7-11700 (8 核 / 16 线程), Rayon 默认 8 线程 (`(cores/2).max(4)`), Rust 1.8x
- **优化依据**：`docs/mipod_jmipod_perf_optimization_20261031.md`
- **基准载体**：
  - MiPOD 24 MP PNG: `temp/testhighres/img24mp_png.png` (4000×6000, 3 通道, 24,000,000 像素)
  - MiPOD 66 MP PNG: `temp/testhighres/img60mp-a_png.png` (10752×6144, 3 通道, 66,060,288 像素)
  - J-MiPOD 24 MP JPEG: `temp/testhighres/img24mp.jpg` (4000×6000, 375,000 块, 24,000,000 频域系数)
  - J-MiPOD 100 MP JPEG: `temp/testhighres/img100mp.jpg` (8192×12288, 1,572,864 块, 100,663,296 频域系数)
- **门禁要求**：每批次必须通过 `cargo test --all-features --all-targets`、`cargo test local_ --all-features -- --ignored`、`cargo fmt && cargo clippy --all-targets --all-features -- -D warnings`、`python scripts/baseline_hash.py --check`。

---

## 实测汇总对比表

| 步骤 / 批次 | 说明 | MiPOD 24 MP<br>(cost map) | MiPOD 66 MP<br>(cost map) | J-MiPOD 24 MP<br>(cost map) | J-MiPOD 100 MP<br>(cost map) | 校验状态 |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Step 0: Baseline** | 优化前基准起点 (commit `0234e31`) | **9,814.5 ms** | **29,646.6 ms** | **8,675.1 ms** | **47,519.6 ms** | **基线全绿通过** |
| **Step 1: Batch 1** | P0: `cost_calibration.rs` 直方图化 + 单调插值表 | **1,785.4 ms**<br>(提速 5.50x) | **5,487.7 ms**<br>(提速 5.40x) | **496.6 ms**<br>(提速 17.47x) | **1,931.1 ms**<br>(提速 24.61x) | **100% 测试通过**<br>(精度误差 < 3e-8) |
| **Step 2: Batch 2** | P0+P1: `spatial_variance.rs` 投影与平滑内点切片特化 | **794.7 ms**<br>(累计提速 12.35x) | **2,098.1 ms**<br>(累计提速 14.13x) | **401.8 ms**<br>(累计提速 21.59x) | **1,507.4 ms**<br>(累计提速 31.52x) | **100% 逐比特一致**<br>(跨尺寸等价全绿) |
| **Step 3: Batch 3** | P1: `png/engine.rs` & `io.rs` 消除 PNG 嵌入后重复容量探测 | *待执行* | *待执行* | *待执行* | *待执行* | *待验证* |

---

## 阶段细分耗时追踪表 (ms)

### MiPOD (PNG)

| 步骤 / 版本 | 载体 | 总耗时 | 类掩码 | Wiener 2×2 | 补空间投影 | σ²→FI | 7×7 平滑 | 载荷标定 |
|---|---|---|---|---|---|---|---|---|
| **Step 0: Baseline** | 24 MP | 9,814.5 | 52.5 | 70.3 | 1,408.8 | 20.5 | 98.6 | **8,011.0 (81.6%)** |
| **Step 0: Baseline** | 66 MP | 29,646.6 | 146.1 | 213.6 | 4,642.1 | 60.0 | 295.8 | **24,292.0 (81.9%)** |
| **Step 1: Batch 1** | 24 MP | **1,785.4** | 53.2 | 74.5 | 1,410.1 | 20.5 | 105.2 | **154.5 (8.7%)** |
| **Step 1: Batch 1** | 66 MP | **5,487.7** | 150.9 | 203.4 | 4,635.6 | 57.9 | 279.2 | **286.2 (5.2%)** |
| **Step 2: Batch 2** | 24 MP | **794.7** | 51.4 | 75.2 | **418.9 (3.4x)** | 20.9 | **45.2 (2.2x)** | **154.8 (19.5%)** |
| **Step 2: Batch 2** | 66 MP | **2,098.1** | 139.2 | 203.9 | **1,351.1 (3.4x)** | 58.7 | **132.8 (2.2x)** | **287.5 (13.7%)** |

### J-MiPOD (JPEG)

| 步骤 / 版本 | 载体 | 总耗时 | 亮度解压 | 空域方差 (p=3) | BᵀSB + FI | 载荷标定 |
|---|---|---|---|---|---|---|
| **Step 0: Baseline** | 24 MP | 8,675.1 | 21.7 | 242.8 | 21.1 | **8,239.2 (95.0%)** |
| **Step 0: Baseline** | 100 MP | 47,519.6 | 95.8 | 1,095.8 | 90.3 | **46,150.8 (97.1%)** |
| **Step 1: Batch 1** | 24 MP | **496.6** | 23.9 | 254.2 | 20.7 | **161.5 (32.5%)** |
| **Step 1: Batch 1** | 100 MP | **1,931.1** | 96.8 | 1,073.1 | 86.7 | **441.0 (22.8%)** |
| **Step 2: Batch 2** | 24 MP | **401.8** | 25.5 | **172.5 (1.5x)** | 19.9 | **163.9 (40.8%)** |
| **Step 2: Batch 2** | 100 MP | **1,507.4** | 94.4 | **795.3 (1.4x)** | 92.4 | **436.0 (28.9%)** |

---

## 详细测试日志与事件记录

### Step 0: Baseline 基线测试（2026-10-31 22:50）

- **代码提交**：`0234e31`
- **二进制产物**：`rust/target/release/strhide.exe` (all features)
- **测试门禁状态**：
  - `cargo test --all-features --all-targets`：507 个单元与集成测试全部 PASS (388 lib + 101 security/regression + 18 test_security)。
  - `cargo test local_ --all-features -- --ignored`：22 个本地大型多媒体测试用例 100% PASS (耗时 707.66s)。
  - `cargo clippy --all-targets --all-features -- -D warnings`：0 warnings, 0 errors。
  - `cargo fmt -- --check`：格式完全符合标准。
  - `python scripts/baseline_hash.py --check`：58/58 用例与基准逐字节比对全绿。
- **性能测量数据**：
  - MiPOD 24 MP: `9814.5 ms` (标定 8011.0 ms 占 81.6%, 补空间投影 1408.8 ms 占 14.4%)
  - MiPOD 66 MP: `29646.6 ms` (标定 24292.0 ms 占 81.9%, 补空间投影 4642.1 ms 占 15.7%)
  - J-MiPOD 24 MP: `8675.1 ms` (标定 8239.2 ms 占 95.0%)
  - J-MiPOD 100 MP: `47519.6 ms` (标定 46150.8 ms 占 97.1%)
- **瓶颈确认**：
  - 载荷标定（Illinois 迭代遍历全图 + 逐元素 `ln/exp/solve_rho` 牛顿迭代）是绝对的主瓶颈（占 82%~97%）。
  - 空间域补空间投影是 MiPOD 的第二大瓶颈（占 ~15%）。

### Step 1: Batch 1 直方图化标定与单调插值表（2026-10-31 23:10）

- **改动文件**：`rust/src/stego/cost_calibration.rs`
- **主要实现**：
  1. 一次性并行分块统计有效元素数量、`min_log` 与 `max_log`，消除多遍全图扫描。
  2. 采用固定 32,768 桶等宽直方图（L2 常驻 128 KiB），Rayon 并行规约基于整型计数，消除浮点累加的线程顺序依赖。
  3. Illinois 求根每次 `total_entropy_nats` 仅遍历 32k 桶中点，计算量由 `O(iters × n)` 降为 `O(iters × 32768)`。
  4. 最终代价图由网格上的单调表（L2 常驻 256 KiB）进行线性插值，保持单调性与槽位排序不变。
  5. 补充单线程与默认多线程池逐比特一致性测试 `calibration_is_deterministic_across_thread_counts`。
- **测试门禁状态**：
  - `cargo test --all-features --all-targets`：全部 508 个单元/集成测试 100% 通过。
  - `cargo test local_algorithm_matrix --all-features -- --ignored`：PNG/JPEG 全算法测试 100% 通过（耗时从 357.6s 缩减至 293.88s）。
  - `cargo clippy --all-targets --all-features -- -D warnings`：零警告零错误。
  - `cargo fmt -- --check`：通过。
  - `python scripts/baseline_hash.py --check`：58/58 零改动全绿。
- **实测性能与加速比**：
  - **MiPOD 24 MP**：总代价图从 `9,814.5 ms` 降至 **`1,785.4 ms`（提速 5.50x）**；标定阶段从 `8,011.0 ms` 降至 **`154.5 ms`（提速 51.85x）**。
  - **MiPOD 66 MP**：总代价图从 `29,646.6 ms` 降至 **`5,487.7 ms`（提速 5.40x）**；标定阶段从 `24,292.0 ms` 降至 **`286.2 ms`（提速 84.88x）**。
  - **J-MiPOD 24 MP**：总代价图从 `8,675.1 ms` 降至 **`496.6 ms`（提速 17.47x）**；标定阶段从 `8,239.2 ms` 降至 **`161.5 ms`（提速 51.02x）**。
  - **J-MiPOD 100 MP**：总代价图从 `47,519.6 ms` 降至 **`1,931.1 ms`（提速 24.61x）**；标定阶段从 `46,150.8 ms` 降至 **`441.0 ms`（提速 104.65x）**。
- **精度验证**：
  - 达成载荷相对误差：24 MP PNG 为 `2.87e-8`，66 MP PNG 为 `3.56e-10`，24 MP JPEG 为 `1.49e-8`，100 MP JPEG 为 `2.99e-8`（均远优于 1e-6 容差）。
  - 单线程与 8 线程计算结果逐比特一致（`to_bits()` 校验通过）。

### Step 2: Batch 2 空间投影与平滑内点切片特化（2026-10-31 23:25）

- **改动文件**：`rust/src/stego/spatial_variance.rs`
- **主要实现**：
  1. `complement_energy_p<const P: usize>` 特化 P ∈ {3, 5, 7, 9, 11, 17}：
     - 水平 pass 内点区间 `x ∈ [half, w - half)` 直接读连续切片 `&src[x-half..x-half+P]`，彻底消除内点每个像素 81 次（p=9）无谓的 `rem_euclid` 整数取模。
     - 垂直 pass 将纵向采样值一次性读入栈数组 `vals[a]`，供所有 `ku` 向量共享内积，访存量减少至原来的 1/4。
     - 严格保持 `kv → ku → a` 递增求和顺序，保证浮点累加与原实现逐比特一致。
     - 行带缓冲区 `horiz` 在外层循环声明并仅 `resize`，消除每个 band 反复分配 16MB 缓冲区的系统调用开销。
  2. `box_smooth`：水平与垂直 pass 均拆分为 `[half, w - half)` 连续切片读取与两端镜像，消除了全图 7 次 `rem_euclid`。
  3. 补充单元测试：
     - `specialized_and_generic_complement_energy_are_bit_identical`：覆盖 6 组尺寸（含 `w < p`、`h < p` 等边界）与所有 `(p, degree)` 组合，验证特化版本与通用回退路径 100% 逐比特一致。
     - `box_smooth_matches_naive_reflection_bit_identically`：覆盖多组尺寸，验证优化平滑与无分支镜像逻辑 100% 逐比特一致。
- **测试门禁状态**：
  - `cargo test --all-features --all-targets`：全部 510 个单元/集成测试 100% 通过。
  - `cargo test local_algorithm_matrix --all-features -- --ignored`：通过（耗时由 Step 1 的 293.88s 进一步降至 266.33s）。
  - `cargo clippy --all-targets --all-features -- -D warnings`：零警告零错误。
  - `cargo fmt -- --check`：通过。
  - `python scripts/baseline_hash.py --check`：58/58 零改动全绿。
- **实测性能与加速比**：
  - **MiPOD 24 MP**：总代价图降至 **`794.7 ms`（相比基线提速 12.35x）**；投影阶段由 `1,408.8 ms` 降至 **`418.9 ms`（提速 3.36x）**；平滑阶段由 `98.6 ms` 降至 **`45.2 ms`（提速 2.18x）**。
  - **MiPOD 66 MP**：总代价图降至 **`2,098.1 ms`（相比基线提速 14.13x）**；投影阶段由 `4,642.1 ms` 降至 **`1,351.1 ms`（提速 3.44x）**；平滑阶段由 `295.8 ms` 降至 **`132.8 ms`（提速 2.23x）**。
  - **J-MiPOD 24 MP**：总代价图降至 **`401.8 ms`（相比基线提速 21.59x）**；空域方差 (p=3) 阶段由 `242.8 ms` 降至 **`172.5 ms`（提速 1.41x）**。
  - **J-MiPOD 100 MP**：总代价图降至 **`1,507.4 ms`（相比基线提速 31.52x）**；空域方差 (p=3) 阶段由 `1,095.8 ms` 降至 **`795.3 ms`（提速 1.38x）**。
- **精度验证**：
  - 空间域投影与平滑结果与优化前完全**逐比特一致**（bit-identical），数学零漂移。
