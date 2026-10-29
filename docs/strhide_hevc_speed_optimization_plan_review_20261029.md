# strhide HEVC 大视频优化方案审查报告

- 审查对象：`docs/strhide_hevc_speed_optimization_plan.md`（278 行，基线 `strhide 0.7.4` / `dcfc4ba`）
- 审查日期：2026-10-29
- 主仓源码：`C:\Home\Projects\strhide`（`rust/src/...`）
- 解码器源码：`C:\Home\github\strhide-vendor\rusty_h265`，commit `ba02bb5`，与 `rust/Cargo.toml` 的 `v1-20261025-2` checkout 相同
- 实测载体：`temp/bighevc/anime-b.mp4`（529.07 MiB，1920×1080，23.98 fps，1437.0 s，x265 10b）
- 实测日志：`C:\Home\Temp\strhide-cli-log.txt`
- 审查方法：逐条对照源码；从 MP4 抽出 Annex-B 后统计 NAL/GOP；用 `rusty_h265` 对同一 CRA 段分别做“全新解码器”和“复用解码器”解码；复测当前 embed 峰值内存。

## 0. 结论摘要

**方案方向部分成立，但不能按当前文档直接实施。** GOP 级并行、代价 LUT、预分配、去掉 `band_slots` 这些方向本身合理，但文档里最关键的三块前提有问题：

1. **GOP 并行的“逐比特一致”不成立。** 该载体不是 409 个 IDR/GOP，而是 1 个 IDR + 321 个 CRA；中段 CRA 后的 RASL 在现行全片顺序解码里会被解码，换成一个全新解码器则会按 H.265 §8.1.3 跳过。`map_init` 复用解码器还会让结果依赖线程调度。embed 与 extract 可能算出不同的槽池，直接导致嵌入/提取不一致。
2. **阶段 1/2 的提速数字大量张冠李戴。** §2.1 的 `powf`、§2.3 的预回放、§2.4 的 `band_slots` 都只在 `Capture::Full`（embed）下存在；`capacity --exact` 用 `Capture::Count`、`extract` 用 `Capture::Bits`，这三项对它们几乎不生效。因此 190→125 s、37.94→21.5 s 没有机制支撑。
3. **8 GiB 硬上限与“超限自动分批”没有落地路径。** `total_windows` 硬编码为 1，STC 是在整个窗口上全局求解的；所谓“每批生成 patch 后清日志”需要多窗口和 payload 切分，代码里没有。`MemoryBudgetGuard` 只是按字节估算，不是强制分配上限，“绝不 OOM”不成立。

| 级别 | 问题 | 影响 |
| :--- | :--- | :--- |
| P0-1 | CRA/RASL 语义与 `map_init` 复用解码器 | embed/extract 槽池不一致，可能损坏载荷 |
| P0-2 | 阶段 1/2 收益错配、阶段 3 `--capacity` 18x 未覆盖默认路径 | 进度与验收目标失真 |
| P0-3 | 8 GiB 硬上限、分批方案、9,000 切片内存账本 | “绝不 OOM”不可信，方案无法按描述实现 |
| P1 | IRAP/GOP/槽位数字、`body_costs`/`embed_with_cost_fn` 账本、LUT 对基线的破坏 | 结论与数字不可复现 |
| P1 | 删除预回放校验、0.0 cost 兜底、filter `any()`、u32 溢出 | 静默损坏或兼容性回归 |
| P2 | `starts_picture` O(1)、Count 模式、`band_slots` 删除、inspect 解释 | 正确，可保留 |

## 1. P0-1：GOP 并行的前提不成立（CRA/RASL）

### 1.1 载体的真实结构

对 `anime-b.mp4` 抽出的 Annex-B 统计结果：

| 项目 | 实测 | 计划文档 |
| :--- | :--- | :--- |
| VCL 切片/NAL | 34,454 | 34,454 |
| IRAP 总数 | **322** | 409 |
| IRAP 类型 | **1 个 IDR_N_LP（type 20）+ 321 个 CRA（type 21）** | 未区分，按 409 个独立 GOP 处理 |
| RASL | **88 个（65 个 RASL_N + 23 个 RASL_R）** | 未统计 |
| RADL / BLA | 0 / 0 | 未统计 |
| 平均 GOP | **约 107 个 VCL 切片/GOP** | 约 84 帧 |
| 最大/最小 GOP | 251 / 25 个 NAL | 未给出 |
| 含 RASL 的 GOP | **25 个（占 322 个 GOP 的 7.8%）** | 文档称“99% 为 IDR 或无 RASL 依赖的 CRA” |

这说明文档的核心假设——“每个 CRA 都是可独立解码的 Closed GOP，和从文件头顺序解码逐比特一致”——对这个基准载体不成立。

### 1.2 为什么“全新解码器 + CRA 起点”会改变槽池

`rusty_h265` 的判定在 `decoder.rs:449`：

```rust
self.no_rasl_output_flag = nt.is_idr() || nt.is_bla() || self.first_in_sequence;
```

- **现行全片顺序解码**：第一个图像是 IDR（type 20），解码后 `first_in_sequence = false`（`decoder.rs:692`）。后续中段 CRA 到达时 `no_rasl_output_flag = false`，其后的 RASL 会被正常解码并进入槽池。
- **每个 GOP 一个全新解码器**：从 CRA 开始时 `first_in_sequence = true`，于是 `no_rasl_output_flag = true`；`decoder.rs:451-456` 直接把 RASL 标记为 `skipping_picture` 并 `skipped_rasl += 1`，不产生任何槽位。同时 `decoder.rs:547-556` 在 `no_rasl_output_flag` 为真时会清空 DPB（CRA 推断 `NoOutputOfPriorPicsFlag = 1`）。
- 结果：25 个含 RASL 的 GOP、88 个 RASL 图像的槽位在并行路径里消失，后续所有槽位的全局下标随之前移。计划文档第 140 行声称“RASL 会被跳过，与 `record_carrier_state` 现行 `Ok(_) if recorder.substreams.is_empty() => {}` 逻辑一致”，这是把“RASL 被跳过”误当成了现行行为；现行顺序解码并不会跳过中段 CRA 的 RASL。

实测复现（同一 CRA 段）：

| 解码方式 | errors | skipped_rasl | generated_refs | pictures |
| :--- | :---: | :---: | :---: | :---: |
| 全新 `Decoder` 解 CRA 段 | 0 | 3 | 0 | 394 |
| 同一 `Decoder` 再解同一段 | 0 | 3 | **5** | 394 |

第二次解码出现 `generated_refs = 5`，说明 RASL 不再按“跳过”处理，而是用缺失参考帧的生成图像继续解码——槽池内容与第一次不同。

### 1.3 `map_init` 复用解码器是更严重的不确定性来源

计划第 145-156 行用 `map_init(|| init_ablate_decoder(...), |decoder, gop| ...)` 让每个 Rayon 线程复用一个 `Decoder`。问题在于：

- `Decoder::flush()` 只做了 `finish_picture()`、`flush_dpb_output()` 和 `first_in_sequence = true`（`decoder.rs:309-313`），**没有清空 DPB，也没有重置 `prev_tid0_poc`、`no_rasl_output_flag`、`skipping_picture`**。
- 一个线程解完第一个 GOP 后，`first_in_sequence = false`。再解下一个以 CRA 开头的 GOP 时，`no_rasl_output_flag = false`，该 GOP 的 RASL 会被解码，并去引用上一个 GOP 留在 DPB 里的图像。
- 哪个线程拿到哪个 GOP、线程池如何调度，都会改变“上一个 GOP”是谁，从而改变 RASL 的参考帧、POC、槽位数量与内容。embed 与 extract 只要线程数或调度不同，槽池就可能不同。
- 这不是“逐比特一致”，而是“逐次运行可能不一致”。

### 1.4 建议的修正

三选一，必须在 PR 之前定死：

1. **统一跳过 RASL（最简单）**：每个 GOP 用全新 `Decoder`，embed 和 extract 都走同一条 GOP 并行路径，并显式把 RASL 排除出槽池。代价是槽池布局相对现行版本改变，必须重新生成 `baseline_hash.py` 基线；不能再声称“与顺序解码逐比特一致”。
2. **保留 RASL（兼容现行布局）**：对含 RASL 的 25 个 GOP 做“前一个 GOP 尾部预热”，即从上一个 GOP 的 IRAP 或最后几个参考帧开始解码。这会把并行边界变得不均匀，且边界 GOP 要重复解码一部分。
3. **给解码器加显式 reset API**：新增 `reset_for_new_sequence()`，清空 DPB、POC、`no_rasl_output_flag` 等状态，并在每个 GOP 开始时调用；同时统一 RASL 策略。不要用 `flush()` 冒充 reset。

无论选哪种，都必须加一个确定性测试：同一文件用 1 线程与 N 线程各跑一遍，比较 `total_slots`、`slice_slot_ranges`、`band_bits`/`raw_bits` 的完整字节；再做一次 embed→extract 往返。这个测试不过，GOP 并行不能合入。

## 2. P0-2：阶段 1/2 的提速数字张冠李戴

### 2.1 §2.1/§2.3/§2.4 只对 embed 生效

| 计划项 | 代码事实 | 对 `capacity --exact` | 对 `extract` |
| :--- | :--- | :---: | :---: |
| §2.1 删 `provisional_sign_flip_cost` | `journals()` 只在 `RecordMode::Embed` 为真（`slot.rs:423-425`）；`record_carrier_state` 只在 `Capture::Full` 选 `Embed`（`engine.rs:2372-2376`） | 不执行 | 不执行 |
| §2.3 删单线程预回放 | 位于 `embed_hevc_patches_with_factor`（`engine.rs:1024-1049`） | 不存在 | 不存在 |
| §2.4 删 `band_slots` | 只在 `Capture::Full` push（`engine.rs:2299-2302`） | 不存在 | 不存在 |

`capacity --exact` 走 `Capture::Count` + `RecordMode::Slots`；`extract` 走 `Capture::Bits` + `RecordMode::Slots`。这两条路径里 `record_stego_sign` 的 `cost` 直接是 `0.0`（`slot.rs:515-519` 的 `else` 分支），根本不会调用 `powf`。所以 §2.1 对它们零收益。

真正对这两条命令生效的阶段 1 改动只有：

- §2.2 `starts_picture` 改成 O(1)：省掉对 529 MiB 的一次 `unescape` 扫描与 34,454 次分配。按内存带宽估算，量级是 **0.5–1 s**，不是几十秒。
- §2.4 的 Count 模式：省掉 6.15 亿次 `StegoSlot` push/drain。按 16 B/槽位约 9.8 GB 写入量估算，量级是 **几秒**。
- §2.4 单子流不调 `nal_rbsp`：再省一次 529 MiB 的 `unescape`，量级 **0.5–1 s**。

而 `capacity --exact` 的 190 s 里，绝对大头是单线程 CABAC 解码 37.9 亿决策 bin（约 20M bin/s），不是这几次内存扫描。`extract` 的 37.94 s 里，大头是解码前 5,050 个切片、构造 671 MB `all_body_indices`、以及 STC 提取；阶段 1 一项都没碰。因此：

- **190→125 s（1.52x）没有依据**，合理预期是 185 s 左右；
- **37.94→21.5 s（1.76x）没有依据**，合理预期是 36–37 s。

embed 的 67→31 s 也不该当成已证明的数字：§2.3 的预回放可能省 10–20 s，其余项几秒，31 s 是乐观外推，不是测量。

### 2.2 §2.5 环路滤波的真实增量是约 1.25x，不是 1.5–1.8x

项目自己的 `docs/HEVC-SYNTAX-ONLY-PERF-20261026.md` 给的是：

- 1080p 载体：ablate（`mc/intra/residual`）**1.45x**；ablate + 跳过滤波 **1.81x**。
- 增量 = 1.81 / 1.45 ≈ **1.25x**，即滤波约占 decode 时间的 20%，不是计划写的 35–45%。

计划第 255 行的阶段 2（0.9 s / 75 s / 19.5 s / 13.0 s）相当于在阶段 1 基础上再快 1.5–1.8x，这是把“ablate 的总收益”又算了一遍。正确做法是：以实测的 ablate 基线为起点，只乘 1.25x。

另外两点：

- `RH265_NO_LF` 已经存在（`filters.rs:18-22`，同时跳过去块和 SAO），**不需要 fork 就能先测收益**。如果最终要进库，给 `Decoder` 加一个显式 `skip_loop_filters` 标志即可，不必改环境变量。
- 计划建议 `if !self.ablate.any()`。`Ablate::any()` 是“任一开关为真”，只开 `mc` 的调用方也会被跳过滤波，像素输出会变。对 strhide 这种三项全开的场景没问题，但作为库的公共行为应改成 `if !(self.ablate.mc && self.ablate.intra && self.ablate.residual)`，或者用独立 flag。

### 2.3 `--capacity` 的 18x 没有覆盖默认路径

`embed --capacity`（非 `--exact`）不走 `record_carrier_state`，而是 `probe_hevc_pool` 自己的串行采样循环（`engine.rs:400-516`）：解析 MP4 → 逐个候选切片 `decode_nal_with_observer`，最多 1,000 个切片。计划第 6 节的 checklist 只改 `record_carrier_state`，没有改这个循环，所以“GOP 并行 → capacity 0.25 s”不会发生。

即使改了这个循环，18x 也不现实：

- 4.68 s 里包含 `std::fs::read` 整个 529 MiB 文件（`cli/cmd_stego.rs:46`）；0.25 s 还要覆盖这 529 MiB 的读取和 1,000 个切片的解码，余量极小，除非同时落地 §4 的按需读取，而 §4 根本不在 checklist 里。
- 前 1,000 个切片大约跨 10 个 GOP（31、63、47、127、244…），GOP 级并行的关键路径由最大的 GOP（约 251 个切片）决定，理论加速约 4x，不是 16x/18x。要接近线性，得做切片级工作窃取，而不是 GOP 级 `par_iter`。

### 2.4 阶段 3 的最终数字并非全部不可能，但表格不能作为验收依据

公平地说，阶段 3 的某些目标在量级上并非天方夜谭：

- `capacity --exact` 从 190 s 降到 10–14 s（约 15x）在 16 核、GOP 数 322、最大 GOP 只占 0.7% 工作量的条件下是可能的；
- `extract` 从 37.94 s 降到 2.2–3.2 s（约 13x）也大致成立；
- `embed` 从 67 s 降到 4.5–6.5 s 偏乐观，因为 STC 求解、重编码、I/O 仍有串行部分。

问题在于：**这些数字是建立在阶段 1/2 的错误基线之上的**，而且 `--capacity` 的 0.25 s 明显不成立。文档应把“阶段 1/2 数字”全部删掉或改成待测，把阶段 3 标成“目标区间，需实测”，而不是“基于实测基线推算”。

## 3. P0-3：8 GiB 硬上限与分批方案没有落地路径

### 3.1 只有一个窗口，STC 是全局的

- `HevcSuperblock.total_windows` 在 embed 时硬编码为 `1`（`engine.rs:889`），`window_slices` 是 `u16`；extract 侧也只处理单窗口（`engine.rs:1539-1550`）。
- Body STC 是在整个窗口的 `body_positions` 上一次性求解的（`engine.rs:958-982`），不是按 GOP/批次独立求解。
- 计划第 158 行说“超过 8 GiB 就把 K 个 GOP 分成多个超级窗口，每批并行解码、STC 求解并生成 `HevcCarrierPatch` 后立即 `.clear()` 释放该批日志”。要成立，至少需要：多窗口 superblock 元数据、payload 按窗口切分、extract 侧按窗口重组、跨窗口的全局槽位下标重映射。这些都没有实现。
- 更糟的是顺序：计划写的是“解码 → STC → 生成 patch → 清日志”。如果 STC 需要整个批次的槽位，那么在 STC 完成前不能清日志；真正要限内存，必须在**解码前**按字节预算限制批次大小，而计划的 K 是按目标槽位数估的，不是按字节。

### 3.2 没有真正的强制上限

`MemoryBudgetGuard` 按 `selectable_bytes` 估算内存，然后决定 K。它不是分配器层面的硬限制：

- `Vec` 增长会按倍增策略临时申请新块，峰值可能比估算高 1.5–2x；
- Rayon 的 GOP 任务一旦开始，无法在 GOP 中途因为预算超了而停下；
- 没有 `GlobalAlloc` 计数、没有信号量、没有 cgroup/Job Object 限制；
- `STRHIDE_MAX_MEMORY_GB` 只是读一个环境变量，代码里没有对应的强制检查点。

因此“内存永远被死死限制在 8–12 GiB 之内，绝不 OOM”是过度承诺。Windows 上还有页文件、其他进程、以及 529 MiB 载体缓冲，12 GiB 的进程内上限在 16 GB 机器上并不安全。

### 3.3 9,000 个切片装不进 8 GiB（按计划自己的数字）

计划第 116 行称 8 GiB 可驻留约 9,000 个切片。按它自己的 0.85 MB/切片：

- 9,000 × 0.85 MB = **7.65 GB ≈ 7.13 GiB**；
- 只剩约 0.87 GiB 给其他所有数组，但实际还需要：
  - `all_body_indices`：9,000 切片约 1.485 亿槽位 × 8 B = **1.19 GB**（改成 u32 也要 0.59 GB）；
  - `is_sb`：1 字节/槽位 = **149 MB**；
  - `body_positions` / `body_costs` / `body_cover_bits` / `body_moves` / `body_deltas`：数百 MB 到 1 GB 量级（1.8 MiB 载荷对应约 3,000 万槽位，仅 `body_positions` 就 240 MB，`body_costs` 再 240 MB）；
  - 载体 `std::fs::read` 缓冲：**529 MB**；
  - 16 个解码器：即便按计划的 400 MB 算，也要 0.4 GB。

合计已经 **>9 GiB**，8 GiB 装不下。12 GiB / 13,500 切片同理：13,500 × 0.85 = 11.5 GB ≈ 10.7 GiB，加上上述数组和载体、解码器，超过 12 GiB。这个结论不依赖 0.85 MB/切片是否精确——只要它是对的，账就已经爆了。

### 3.4 单解码器 20–30 MB 偏低

1080p 10-bit 4:2:0 一帧像素约 **6.2 MB**（1920×1080×2 + 2×960×540×2）。`rusty_h265` 即使在 `Ablate` 下仍然 `Picture::new` 分配完整平面（`decoder.rs:627`），DPB 通常保留 4–6 帧，再加当前帧、输出队列、`PicState`、`filter_scratch`。单个解码器更可能是 **40–60 MB**，16 个约 **0.6–1.0 GB**，不是 400 MB。这一点需要实测，不能拍脑袋。

## 4. P1：事实与账本错误

| 位置 | 文档说法 | 源码/实测 | 影响 |
| :--- | :--- | :--- | :--- |
| §1 表格/§3.1 | 409 个 IRAP、平均 84 帧/GOP | 322 个 IRAP（1 IDR + 321 CRA）、平均约 107 个 VCL/GOP | GOP 切分数量、并行度、内存估算全部偏 |
| §1/§3.1 | 5.71 亿有效槽位、6.15 亿总槽位 | 日志精确扫描 **559.36M**；默认估算 570.56M | 容量与内存数字对不上 |
| §1/§3.1 | 37.9 亿决策 bin、28 万 bins/切片、0.85 MB/切片 | 37.9B / 34,454 ≈ **110k bins/切片**；28 万 × 34,454 ≈ 96.5 亿 | 三个数字互相矛盾，至少两个错 |
| §3.3 | `body_costs` 134 MB，后又写“268 MB 的 f64 数组” | `16.78M × 8 B = 134 MB`；`back` 才是 268 MB | 账本前后不一致 |
| §3.3 | `embed_with_cost_fn` 是“零分配”，准备阶段“接近 0 ms” | 它内部仍分配 `back = vec![0u64; n * words_per_col]`（h=7,u=2 时 2 words/col，16.78M × 2 × 8 B = **268 MB**）和 `flip_kinds`（16.8 MB）（`stc.rs:626-628`） | 只省调用方的 `body_costs`，不省 STC 内部大数组 |
| §3.1 | `Capture::Bits` 全片仅 71 MB | `band_bits` + `raw_bits` 是两份，各约 2 KB/切片；extract 还要 `all_body_indices` 671 MB | “71 MB”只算了打包比特，漏了索引数组 |
| §3.3 | 每字节约 18 bins、3.2 个槽位 | 559.36M 槽位 / 529 MiB ≈ **1.01 槽位/字节** | `est_slots = len * 4` 约 4x 过分配；`ops` 的 18 bins/字节与 0.85 MB/切片的 280k bins 倒是一致，但与 37.9B 不一致 |
| §3.2 | LUT 改造后“不改变任何比特输出”，776 项测试和 baseline 全过 | `cost_from_dq` 的浮点运算顺序改变（`dq² × W` vs `peak² × ...`），f32 舍入会变；flip 集合随之变 | `baseline_hash.py --check` 很可能失败，除非重新生成基线并承认输出变化 |
| §3.2 | `bd_idx = (bd-8).min(4)` 覆盖 8/9/10/12-bit | 12-bit→4、14-bit→4 被合并，但表里的 `2^(bd-8)` 不同；项目当前只声明支持到 10-bit，解码器对 Range Extensions 报错 | 当前无影响；若以后支持 12/14-bit 就是错表 |
| §2.2 | `cmd_stego.rs:45` | 实际 `rust/src/cli/cmd_stego.rs:46` | 引用偏差一行，不影响结论 |
| §3.2 | `all_body_indices` 改 u32 后“L3 命中率翻倍” | 335 MB 仍远大于 L3；收益主要是带宽/容量，不是 L3 | 描述不准确 |

关于 LUT 再补一句：118 KB 表的压缩思路（`zero_axes 0..3 × manhattan_xy 0..63`）在数学上是成立的，因为 `freq_masking` 只依赖 `x_c+y_c`，`gx/gy` 只依赖 `x_c==0`/`y_c==0`。问题不在表结构，而在“改完输出不变”的断言。

## 5. P1：可靠性风险

### 5.1 删除 embed 的预回放校验会引入静默损坏

`replay_matches_cover`（`engine.rs:1391-1399`）是目前唯一能发现“日志重放出的字节与原始覆盖不一致”的检查。它允许最多 4 个尾部 0 字节（`cabac_zero_word`），其他任何长度或字节差异都判为 `BadSubstream`，把该子流排除出槽池。

计划 §2.3 要删掉这段单线程预回放，只在 `reencoded.len() != orig_sub_len` 时惰性调用一次。问题：

- **长度相同但字节不同**的重放不会被发现。这可能是 EPB 处理错误、上下文模型偏差、或语法模型漏项，最终写出的切片是坏的；
- 现在的预回放虽然慢，但它是“先验证再写入”的安全网。删掉它等于把静默损坏的风险交给运气；
- 正确做法不是删，而是**并行化**：把每个 `(slice_idx, sub_idx)` 的 `encode_substream(..., &[])` 放进 Rayon，或者每个子流只做一次并缓存（现在已经有 `replay_ok` 缓存）。成本可以降到可接受，安全性不丢。

### 5.2 删除 provisional cost 后，截断切片会得到 0.0 的最便宜槽位

`record_stego_sign` 里 `slot.cost` 先写 `provisional_sign_flip_cost`，随后 `record_stego_level` 用真实幅值覆写（`slot.rs:571-585`）。对完整解码的切片，这个“必然覆写”基本成立；但：

- 如果切片被截断、或观察者在 `record_stego_level` 之前结束，`cost` 会停在 `0.0`；
- `0.0` 是 STC 里最便宜的一档，最容易被翻转；
- release 构建没有断言，只有 `debug_assert`（`slot.rs:561-570`），线上不会报错。

建议在 `absorb_recorder` 时检查 `next_pending_slot == recorder.slots.len()`（或所有 slot 的 cost 都被 backfill 过），不满足就丢弃该切片；或者保留一个廉价的 fallback cost。不要只靠“应该是完整切片”的假设。

### 5.3 §2.6 的收益与复杂度不匹配

`extract_hevc` 的第一阶段用 `MinSlots(2048)`（`engine.rs:1485-1486`）。一个 1080p 切片平均约 1.65 万槽位，所以它在**第 1 个切片**就停了，不是计划说的“前 5,050 个切片”。第二阶段才解码到 `w0`（`engine.rs:1543-1550`）。

把 Superblock 校验塞进 `record_carrier_state` 循环、复用当前 decoder 继续解到 `w0`，确实能省掉“第一个切片 + 一次 MP4 解析 + 一次候选表构建”。但相对 37.94 s，这只值 **0.02% 量级**，却要把 `StopCondition` 改成带闭包的动态条件、把 `extract_hevc` 的密钥/校验逻辑拆进解码循环。投入产出不成立，建议降到 P2 或直接不做。

### 5.4 `!self.ablate.any()` 对部分 ablate 是错的

见 §2.2。对 strhide 无影响（三项全开），但这是 `rusty_h265` 的公共行为，建议用 `mc && intra && residual` 或独立 flag。

### 5.5 `all_body_indices` 改 u32 需要溢出保护

5.59 亿槽位用 u32 没问题；但 4K、更长视频或更高槽位密度可能超过 `u32::MAX`（4.29B）。代码里大量用 `usize` 索引，改成 u32 后要加 `try_into()` 或启动时 `assert!(total_slots <= u32::MAX as usize)`，不能静默截断。

### 5.6 `with_slice_mode` 拿不到 `slice_bytes`

计划 §3.3 的代码片段在 `CabacRecorder::with_slice_mode` 里用 `slice_bytes.len()` 预分配，但该函数的签名只有 `(slice_idx, band, mode)`（`slot.rs:401-413`），调用点在 `engine.rs:2496`，`slice_bytes` 在调用点可见。要么把长度传进去，要么在调用点预分配。不是大问题，但说明这段代码没有对照过签名。

另外，3.2 槽位/字节的比例与实测的约 1.0 不符，`est_slots = len * 4` 会 4x 过分配。`ops` 的 `22` 与 18 bins/字节接近，问题不大；但 `slots` 的比例要按实测改，否则“省内存”会变成“多占内存”。

### 5.7 “fork rusty_h265 + 1 天完成”不现实

- 项目通过 git tag `v1-20261025-2` 依赖 `rusty_h265`（`rust/Cargo.toml:79`），不是 path 依赖。改 `finish_picture` 需要新 tag、更新 `Cargo.lock`、走一遍 CI；这不是“1 行”。
- §3.1 的 GOP 并行还要处理全局 `slice_idx` 重映射、band 合并、`slice_slot_ranges` 合并、K 估计不足时的重试、以及 1.4 的确定性测试。按项目自己对高风险改动的估计是 3–5 天，不是 1 天。
- `map_init` 只解决“每线程一个 decoder”，没有解决“每个 GOP 从干净状态开始”。这两件事必须一起做。

### 5.8 K 估计 10% 余量可能不够

计划用前 2 个 GOP 测 `slots_per_byte`，再乘 1.1 估算 K。HEVC 的槽位密度随场景（静止对话 vs 动作）波动很大，前 2 个 GOP 不能代表全片。K 估少了会导致窗口不够、STC 不可行，需要“多解一个 GOP 再试”的重试循环；计划没有写这个循环。建议按 band 分别估密度，并保留失败后扩展窗口的路径。

### 5.9 `commit_carrier_patches` 仍会复制整个文件

`commit_carrier_patches` 用 `std::fs::copy` 把原文件整体复制到临时文件，再只覆盖 patch 区间（`core/commit.rs:211`）。所以 §4 的“省去后 85% 磁盘读取”只对**输入**成立，输出仍是全文件拷贝。对 529 MiB 载体，这部分 I/O 不能忽略；计划没有提。

## 6. 可保留/正确的部分

为了避免报告看起来全是否定，以下判断是对的，建议保留：

1. **`starts_picture` 改 O(1) 是正确的。** `candidate_slice` 要求 `nal[1] & 0x07 != 0`（`engine.rs:2602`），所以 `nal[1]` 不可能是 0；EPB `00 00 03` 不可能在 `nal[2]` 之前出现，`nal[2]` 的最高位就是 `first_slice_segment_in_pic_flag`。省掉 `unescape` 是纯赚。
2. **`Capture::Bits` 跳过 `count_pictures` 是安全的。** extract 不使用 `pictures`/`band_pictures`；但更好的做法是：MP4 的 `picture_count` 在 `parse_mp4_targets` 里已经是 `sample_count`（`mp4_boxes.rs:266`），`record_carrier_state` 却把它丢了，直接用它比 O(1) 扫描还快。
3. **删除 `band_slots` 是正确的。** 它在 `Capture::Full` 下被 push（`engine.rs:2300`），最后又被 `..` 丢弃（`engine.rs:2558-2565`），是纯重复的 1.34 GB。
4. **Count 模式方向正确。** `capacity` 只需要计数，不需要 16 B 的 `StegoSlot`；但 `substream_slot_counts` 要按 band/切片维度给足，别只给 substream。
5. **LUT 方向正确。** 代价公式的几何项确实是有限组合，118 KB 表可行；但必须先证明/接受输出变化，再谈基线。
6. **GOP 并行本身技术可行。** 用全新 decoder 从 CRA 段开始解码，实测 `errors=0`，说明熵解码不依赖前面的像素；问题只在 RASL 策略和确定性，不在“能不能解”。
7. **inspect 返回 false 的解释正确。** embed 用了 `-p pwd1234`，inspect 没传，`derive_magic` 用公开默认 secret 派生，魔数不匹配。补上密码即可。
8. **`provisional_sign_flip_cost` 的删除在完整切片上基本正确。** 观察者契约是“每个非 DC sign 后面跟一个 level”，完整解码时会被覆写；只需补 5.2 的兜底。

## 7. 建议的落地顺序与验收标准

不要按文档的“PR 1 半天 / PR 2 一天”推进。建议拆成四步，每步都有可验证的出口：

### Step 0：重测基线

在 `anime-b.mp4` 上重新记录四个命令的墙钟与峰值工作集（embed 1 MiB 实测约 **68.41 s / 5.74 GiB**，与文档的 6.5 GiB 基线有出入）。后续所有数字以此为准，不再用“推算”。

### PR A：零输出变化的清理（先拿真实收益）

- `starts_picture` O(1)；
- `Capture::Bits` 跳过 `count_pictures`（MP4 直接用 `picture_count`）；
- 删除 `band_slots`；
- 新增 `RecordMode::Count`，按 band 计数，不 push `StegoSlot`；
- 预分配 `ops`/`slots`，比例按实测（槽位约 1.0/字节，不是 3.2）；
- 跑 `cargo test --all-features --all-targets` + `baseline_hash.py --check`；
- 逐命令测收益。预期：embed 有可见下降；`capacity --exact` 和 `extract` 只有几秒级下降。**如果这里达不到“2.2x”，不要改文档数字，改预期。**

### PR B：有输出变化的优化（单独一轮）

- LUT 化 `cost_from_dq`；
- `embed_with_cost_fn` 去掉调用方 `body_costs`（注意 STC 内部仍有 `back` 268 MB）；
- `all_body_indices` 改 u32 + 溢出保护；
- `StcTrellis::extract` 字并行（先测 `row_syndrome` 占比，别预设 15x）；
- 重新生成 `baseline_hash.py` 基线，并在 CHANGES 里注明“输出变化，旧基线作废”；
- 测 embed/extract 的实际收益。若 LUT 不能证明 bit-identical，就不要在 PR A 里混入。

### PR C：滤波开关

- 先用 `RH265_NO_LF=1` 测真实收益（预期约 1.25x，不是 1.5–1.8x）；
- 如果值得进库，给 `Decoder` 加显式 flag（`mc && intra && residual` 或独立 `skip_loop_filters`），不要用 `any()`；
- 新 tag + `Cargo.lock` 更新 + CI。

### PR D：GOP 并行（最后做，且必须带确定性门禁）

前置条件：1.4 的 RASL 策略已定；`total_windows`/分批方案要么实现多窗口，要么删掉“8 GiB 自动分批”的承诺；内存 guard 从“估算”改成“可执行的准入控制”（至少在提交 GOP 前按字节预算和当前驻留量做准入，并给 `Vec` 预留 1.5x 余量）。

验收：

1. 同一文件 1 线程 vs 16 线程，`total_slots`、`slice_slot_ranges`、`band_bits`/`raw_bits` 字节完全一致；
2. embed→extract 往返 payload 一致；
3. `baseline_hash.py --check` 全绿（或明确记录新基线）；
4. 峰值内存不超过设定上限的 90%（留出 `Vec` 倍增余量）；
5. 在 `temp/testhevc` 的 HEVC 语料上跑 `cargo test local_ -- --ignored`，确认没有回归。

**工期**：PR A 半天到一天；PR B 一天；PR C 半天；PR D 3–5 天（含确定性测试与内存门禁）。文档的“PR 2 一天”不现实。

## 附录 A：实测数据

### A.1 `anime-b.mp4` 的 NAL/GOP 统计

| 类型 | 数量 |
| :--- | ---: |
| 总 NAL（含 VPS/SPS/PPS/SEI） | 36,709 |
| VCL 切片 | 34,454 |
| IRAP | 322（1 × IDR_N_LP + 321 × CRA） |
| RASL | 88（65 × RASL_N + 23 × RASL_R） |
| RADL / BLA | 0 / 0 |
| GOP 数 | 322 |
| 含 RASL 的 GOP | 25 |
| 最大/最小 GOP（NAL） | 251 / 25 |

### A.2 CRA 段解码对比

| 方式 | errors | skipped_rasl | generated_refs | pictures |
| :--- | :---: | :---: | :---: | :---: |
| 全新 decoder | 0 | 3 | 0 | 394 |
| 同一 decoder 第二次 | 0 | 3 | 5 | 394 |

### A.3 当前命令基线（日志 + 本机复测）

| 命令 | 日志耗时 | 备注 |
| :--- | ---: | :--- |
| `embed --capacity` | 4.68 s | 估算 570.56M 槽位，采样 1,000 切片 |
| `embed --capacity --exact` | 190 s | 精确 559.36M 槽位，34,454 切片 |
| `embed -d payload-1m.bin` | 67 s | 83.90M 槽位，high 档 |
| `extract -p pwd1234` | 37.94 s | 1 MiB 载荷 |
| `embed` 峰值（复测） | **68.41 s / 5.74 GiB** | 与文档 6.5 GiB 基线不同 |

## 附录 B：关键源码位置

| 主题 | 位置 |
| :--- | :--- |
| `Capture` 选择 `RecordMode` | `engine.rs:2372-2376` |
| `journals()` 只在 Embed 为真 | `slot.rs:423-425` |
| `provisional_sign_flip_cost` / 覆写 | `slot.rs:515-519`, `571-585` |
| `band_slots` push / 丢弃 | `engine.rs:2299-2302`, `2558-2565` |
| 预回放 / 并行重编码 | `engine.rs:1024-1049`, `1051-1073` |
| `replay_matches_cover` | `engine.rs:1391-1399` |
| extract 两阶段 | `engine.rs:1481-1489`, `1538-1550` |
| `body_costs` / `embed_with_cost_fn` | `engine.rs:958-982`, `stc.rs:512-522` |
| STC 内部 `back`/`flip_kinds` | `stc.rs:626-628` |
| `probe_hevc_pool` 串行采样 | `engine.rs:400-516` |
| `total_windows: 1` | `engine.rs:889` |
| `starts_picture` | `engine.rs:2704-2711` |
| `count_pictures` | `engine.rs:2669-2696` |
| `picture_count = sample_count` | `mp4_boxes.rs:266` |
| `RH265_NO_LF` | `filters.rs:18-22` |
| `no_rasl_output_flag` | `decoder.rs:449-456` |
| CRA 清 DPB | `decoder.rs:547-556` |
| `flush()` 不重置 DPB | `decoder.rs:309-313` |
| `inspect_hevc_mp4_file` | `engine.rs:1788` |
| `commit_carrier_patches` 全文件 copy | `core/commit.rs:211` |

## 最终判断

- **可以作为方向性草案保留**：GOP 并行、LUT、Count 模式、去掉 `band_slots`、O(1) `starts_picture` 都值得做。
- **不能按当前文档直接排期**：P0-1 的 RASL/确定性、P0-3 的内存门禁与多窗口、P0-2 的数字错配，必须先修正。
- **最需要补的实验**：1 线程 vs N 线程槽池一致性；embed/extract 往返；`baseline_hash.py --check`；`RH265_NO_LF` 的真实增量；16 个 decoder 的实际驻留内存。
- **最需要删的句子**：“100% 逐比特一致”“绝不 OOM”“5–15 倍”“776 项测试与 baseline 全过”——这些在现有证据下都不成立，改成“待验证”比写死数字更安全。
