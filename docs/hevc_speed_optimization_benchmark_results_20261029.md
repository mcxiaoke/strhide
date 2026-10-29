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
| **Step 2: PR B** | 代价查表 LUT 与测试稳定性看门狗 | **2.73 s**<br>(0.55 GiB) | **97.67 s**<br>(0.56 GiB) | **35.23 s**<br>(4.80 GiB) | **18.61 s**<br>(1.52 GiB) | **100% 逐比特一致** |
| **Step 3: PR C** | `rusty_h265` 环路滤波跳过显式化与外部超时看门狗 | **2.34 s**<br>(0.55 GiB) | **93.09 s**<br>(0.56 GiB) | **36.62 s**<br>(4.74 GiB) | **18.77 s**<br>(1.68 GiB) | **100% 逐比特一致** |
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

### Step 2: PR B 代价查表 LUT 与测试稳定性看门狗（2026-10-29 15:12）

- `binary`: `rust/target/release/strhide.exe` (commit PR B)
- `baseline_hash.py --check`: 58/58 零改动全绿。
- `cargo test --all-features --all-targets`: 760+ 用例 100% 绿灯。
- `cargo test local_ --all-features -- --ignored`: 21/21 用例 100% 绿灯（127.49s，彻底修复了历史遗留的 ffmpeg 偶发卡死）。
- `cargo fmt && cargo clippy`: 零警告零错误。
- `embed --capacity (sampled 1000 slices)`: **2.73 s**（从 3.75s 降至 2.73s，相比基准累计提速 **37.1%**）
- `embed --capacity --exact (all 34,454 slices)`: **97.67 s**（从 171.34s **直接砍掉 73.67 秒！提速 1.77x，耗时下降 43.0%**）
- `embed 1 MiB payload`: **35.23 s**（从 50.38s **净省 15.15 秒！相比基线从 60.94s 降至 35.23s，提速 1.73x，耗时下降 42.2%**）
- `extract 1 MiB payload`: **18.61 s**（从 35.64s **耗时近乎腰斩，提速 1.91x，净省 17.03 秒！**）
- 提取校验：`>>> VERIFICATION: Payload extracted 100% BIT-PERFECT! <<<`
- **主要收益归因**：
  1. `COST_GEOM_LUT` 编译期常量查找表（~120 KB）：将 `cost_from_dq` 中每个切片、每个频域系数繁重的高频浮点除法、条件分支与曼哈顿距离平滑项全部消除为单一内存查表与单次乘法；
  2. 修复 `rust/tests/local/local_media.rs` 中长期存在的并发 `ffmpeg` 匿名管道死锁，加串行锁与 30s 看门狗超时机制，测试不再偶发卡死。

### Step 3: PR C `rusty_h265` 环路滤波跳过显式化与超时防御（2026-10-29 16:04）

- `binary`: `rust/target/release/strhide.exe` (commit PR C)
- `upstream`: `F:\Develop\github\strhide-vendor\rusty_h265` (`v1-20261029`)
- `baseline_hash.py --check`: 58/58 零改动全绿。
- `cargo test --all-features --all-targets`: 760+ 用例 100% 绿灯。
- `cargo test local_ --all-features -- --ignored`: 21/21 用例 100% 绿灯（127.42s 稳定通过，无任何卡顿）。
- `cargo fmt && cargo clippy`: 零警告零错误。
- `embed --capacity (sampled 1000 slices)`: **2.34 s**（相比 PR B 2.73s 继续提速，相比基线 4.34s 累计提速 **1.85x**）
- `embed --capacity --exact (all 34,454 slices)`: **93.09 s**（从基线 173.22s 累计**净省 80.13 秒，耗时下降 46.3%**）
- `embed 1 MiB payload`: **36.62 s**（保持在 35~36s 极速区间，相比基线 60.94s 提速 1.66x）
- `extract 1 MiB payload`: **18.77 s**（保持在 18s 极速区间，相比基线 35.46s 提速 1.89x）
- 提取校验：`>>> VERIFICATION: Payload extracted 100% BIT-PERFECT! <<<`
- **主要收益归因**：
  1. 在 `F:\Develop\github\strhide-vendor\rusty_h265` 的 `Decoder` 结构体上增加 `pub skip_loop_filters: bool` 显式字段及 `pub fn reset_sequence(&mut self)` 序列重置方法；
  2. 在 `strhide` 的 `probe_hevc_pool`、`extract_mp4_carrier` 与 `record_carrier_state` 中显式置 `skip_loop_filters = true`，全路径抹除不必要的 Deblocking 与 SAO 环路滤波耗时；
  3. 为 `rust/tests/local/local_media.rs` 中所有 `Command::new("ffmpeg")` 调用补充 `run_ffmpeg_with_timeout` 15~30s 进程级看门狗与 `.stdin(Stdio::null())` 句柄隔离，彻底防御 Windows 管道继承死锁。
