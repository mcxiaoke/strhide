# HEVC 速度优化分步实测基准与演进记录

- **测试环境**：Windows 10, AMD / Intel 多核 CPU, Rust 1.8x, `rusty_h265` (`v1-20261025-2`)
- **基准载体**：`temp/bighevc/anime-b.mp4`（529.07 MiB，1920×1080 10-bit，23.98 fps，1437.0 s，34,454 个 VCL 切片）
- **测试载荷**：`temp/payload-1m.bin`（精确 1,048,576 字节 = 1.0 MiB，密码 `pwd1234`）
- **基线二进制归档**：`temp/bin_baselines/strhide-baseline-074.exe`（对应 commit `4fc9118`，已消除 `band_slots` 死内存）

## 实测汇总对比表

| 步骤 / 版本 | 说明 | `embed --capacity`<br>(采样 1000 切片) | `capacity --exact`<br>(全片 34,454 切片) | `embed 1 MiB`<br>(前 ~5,050 切片) | `extract 1 MiB`<br>(提取与比对) | 还原校验 |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Step 0: Baseline** | `strhide-baseline-074.exe`<br>(基线起点) | **4.34 s**<br>(0.58 GiB) | **173.22 s**<br>(0.59 GiB) | **60.94 s**<br>(4.75 GiB) | **35.46 s**<br>(1.67 GiB) | **100% 逐比特一致** |
| **Step 1: PR A** | 零输出变化的纯清理与并行预回放 | **3.75 s**<br>(0.58 GiB) | **171.34 s**<br>(0.59 GiB) | **50.38 s**<br>(4.75 GiB) | **35.64 s**<br>(1.56 GiB) | **100% 逐比特一致** |
| **Step 2: PR B** | 代价查表 LUT 与 STC Syndrome 字并行 | *待测* | *待测* | *待测* | *待测* | *待测* |
| **Step 3: PR C** | `rusty_h265` 环路滤波跳过显式化 | *待测* | *待测* | *待测* | *待测* | *待测* |
| **Step 4: PR D** | 确定性跨 GOP 多核并行解码 | *待测* | *待测* | *待测* | *待测* | *待测* |

---

## 详细测试日志与事件记录

### Step 0: Baseline 基线测试（2026-10-29 13:42）

- `binary`: `temp/bin_baselines/strhide-baseline-074.exe`
- `baseline_hash.py --check`: 58/58 全部通过。
- `embed --capacity (sampled 1000 slices)`: 4.34 s, Peak RSS 597.64 MiB (0.58 GiB)
- `embed --capacity --exact (all 34,454 slices)`: 173.22 s, Peak RSS 608.77 MiB (0.59 GiB)
- `embed 1 MiB payload`: 60.94 s, Peak RSS 4868.16 MiB (4.75 GiB)
- `extract 1 MiB payload`: 35.46 s, Peak RSS 1705.66 MiB (1.67 GiB)
- 提取校验：`>>> VERIFICATION: Payload extracted 100% BIT-PERFECT! <<<`

### Step 1: PR A 纯清理与并行预回放（2026-10-29 13:56）

- `binary`: `rust/target/release/strhide.exe` (commit PR A)
- `baseline_hash.py --check`: 58/58 零改动全绿。
- `cargo test --all-features --all-targets`: 760+ 用例 100% 绿灯。
- `cargo test local_ --all-features -- --ignored`: 21/21 用例 100% 绿灯（108.72s）。
- `cargo fmt && cargo clippy`: 零警告零错误。
- `embed --capacity (sampled 1000 slices)`: **3.75 s**（从 4.34s 提速 0.6s，下降 13.6%）
- `embed --capacity --exact (all 34,454 slices)`: **171.34 s**（从 173.22s 降 ~1.9s）
- `embed 1 MiB payload`: **50.38 s**（从 60.94s **净省 10.56 s，直接提速 17.3%**）
- `extract 1 MiB payload`: **35.64 s**，峰值 RSS 从 1.67 GiB 降至 **1.56 GiB**（净降 109 MiB）
- 提取校验：`>>> VERIFICATION: Payload extracted 100% BIT-PERFECT! <<<`
- **主要收益归因**：
  1. 彻底消除 `record_stego_sign` 中 8,390 万次无用 `powf` 评估；
  2. 步骤 3c 预回放校验 `replay_matches_cover` 从单核串行移入 Rayon 多核并行，串行停顿彻底抹平；
  3. STC Body 嵌入使用 `embed_with_cost_fn` 闭包代价，每轮消除 134 MB `body_costs` 冗余分配；
  4. `get_body_slot_indices` 消除 84 MB `is_sb` 全局分配，向量化区间扩容；
  5. `starts_picture` O(1) 化消除全片 34,454 次 NAL 转义扫描，单子流切片跳过 `nal_rbsp`。
