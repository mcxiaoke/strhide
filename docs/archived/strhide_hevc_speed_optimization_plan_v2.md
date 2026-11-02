# strhide HEVC 大视频隐写优化方案（v2 修订版：基于代码与实测审查修正）

> **版本说明**：本版（v2）完整吸纳了 `strhide_hevc_speed_optimization_plan_review_20261029.md` 的实测审查结论，剔除了 v1 中未核实的代码假设与张冠李戴的耗时推算，修正了 **CRA/RASL 开放 GOP 并行确定性**、**预回放安全校验**、**8 GiB 内存账本** 以及 **分路径收益归因**。  
> **基准环境**：`strhide 0.7.4`（`dcfc4ba`）+ `rusty_h265`（`v1-20261025-2` / `ba02bb5`）  
> **实施状态**：**已于 2026-10-29 全部实施并严格验证通过**（PR A: `5f5e910`, PR B: `c01a11f`, PR C: `45abaa6`, PR D: `0cd75d7`）。实测 `capacity --exact` 从 173.22s 骤降至 **26.29s**（提速 **6.59x**），`extract 1 MiB` 从 35.46s 骤降至 **5.49s**（提速 **6.46x**），`embed 1 MiB` 降至 **23.00s**（提速 **2.65x**），58 例基线哈希 100% 保持一致，FFmpeg 软解 0 报错。实测与线程横向对比报告详见 [docs/hevc_speed_optimization_benchmark_results_20261029.md](file:///c:/Home/Projects/strhide/docs/hevc_speed_optimization_benchmark_results_20261029.md)。

## 1. v1 方案核心谬误复盘与修正对照

在深入代码与 `anime-b.mp4` 实测数据后，v1 文档中存在以下必须纠正的事实错误与设计缺陷：

| 谬误类别 | v1 文档中的错误假设/推算 | 源码与实测事实（审查修正） | v2 修正后的工程决策 |
| :--- | :--- | :--- | :--- |
| **P0-1：GOP 结构与 CRA/RASL 语义** | 误把报告中 `CRA + RASL = 409` 当作 409 个独立 Closed GOP；假设从任意 CRA 起全新解码器或用 `map_init` 复用解码器能与顺序解码“100% 逐比特一致”。 | 1. `anime-b.mp4` 实为 **322 个 IRAP（1 个 IDR_N_LP + 321 个 CRA）** 和 **88 个 RASL（65 RASL_N + 23 RASL_R，分布在 25 个 GOP 中）**；<br>2. 顺序解码时首帧 IDR 后 `first_in_sequence = false`，中段 CRA 的 `no_rasl_output_flag = false`，88 个 RASL **会被解码并入池**；而全新解码器从 CRA 起步时 `first_in_sequence = true` 会跳过 RASL，改变槽池；<br>3. `Decoder::flush()` 不清空 DPB 和 POC，`map_init` 跨 GOP 复用解码器会导致 RASL 引用其他线程残留帧（实测 `generated_refs = 5`），结果随线程调度不确定。 | 1. **严禁跨 GOP 直接复用未重置的 `Decoder`**；<br>2. **统一排除 RASL 或显式重置 sequence**：在 `picture_band` 中将 `NAL_RASL_N (8)` 与 `NAL_RASL_R (9)` 排除出槽池（仅占全片切片的 0.25%），并在每个 IRAP 起点重置解码器使 `no_rasl_output_flag = true`（单核与多核行为 100% 确定且一致，需更新基线哈希）。 |
| **P0-2：阶段 1/2 提速数字张冠李戴** | 声称阶段 1（删 `powf`、删预回放、删 `band_slots`）能让 `capacity --exact` 从 190s 降到 125s、`extract` 从 37.94s 降到 21.5s；声称跳过滤波能再快 1.5~1.8x。 | 1. `slot.rs:423` 的 `journals()` 仅在 `RecordMode::Embed`（`Capture::Full`）下为真，`capacity`（`Capture::Count`）和 `extract`（`Capture::Bits`）本来就走 `else { 0.0 }`，**根本不执行 `powf`、预回放或 `band_slots`**！阶段 1 对 `capacity`/`extract` 仅省去 `starts_picture` 和单子流 `nal_rbsp` 的 `unescape`（仅 1~5 秒收益）；<br>2. `HEVC-SYNTAX-ONLY-PERF-20261026.md` 实测 1080p 下 `Ablate` 为 1.45x，`Ablate + 跳过滤波` 为 1.81x，**跳过滤波的真实边际增量是 `1.81 / 1.45 ≈ 1.25x`（省 ~20%）**，而非 1.5~1.8x；且 `rusty_h265` 已内置环境变量 `RH265_NO_LF`（`filters.rs:18-22`）；<br>3. 默认 `embed --capacity` 走独立的 `probe_hevc_pool` 串行循环（`engine.rs:400-516`），不走 `record_carrier_state`。 | 1. 严格区分 **`embed` 专属优化** 与 **全路径通用优化（环路滤波跳过 + GOP 并行）**；<br>2. 先用现成的 `RH265_NO_LF=1` 实测滤波收益；<br>3. 若要加速默认 `--capacity`，必须同步改造 `probe_hevc_pool` 及文件读取方式。 |
| **P0-3：8 GiB 内存账本与分批承诺** | 声称 8 GiB 可装下 9,000 个切片，且超限时可按 8 GiB 自动分批跑 STC、生成补丁并 `.clear()` 释放日志，“绝不 OOM”。 | 1. 9,000 切片仅 `SliceContext + StegoSlot` 就占 ~7.13 GiB，加上 `all_body_indices`（1.19 GB）、STC 内部 `back` 回溯表（268 MB+）、载体缓冲（529 MB）、16 个解码器（10-bit 下 `Picture::new` 仍分配像素平面，单实例约 40~60 MB，16 个约 0.6~1.0 GB），**总计已超 9.5 GiB**；<br>2. 现行 `HevcSuperblock.total_windows` 硬编码为 `1`，Body STC 在整个窗口上全局求解，在未实现多窗口协议前**无法分批求解 STC 并提前清空日志**。 | 1. 诚实核算全链路内存（含解码器 DPB、STC `back` 表、索引表与 `Vec` 1.5x 扩容余量），在 8 GiB 目标下将单窗口安全并发上限设定为 **~5,000–5,500 个切片**；<br>2. 区分“单窗口并发内存准入控制”与“多窗口协议扩展（需修改 `total_windows > 1` 线格式）”。 |
| **P1：删除预回放导致静默损坏风险** | 建议直接删掉 `engine.rs:1026` 的单线程无翻转预回放（`replay_matches_cover`），仅在重编码长度不匹配时才校验。 | 若某个子流重编码后**长度恰好相等但字节内容不一致**（如上下文状态偏差或语法漏项），仅靠长度检查无法发现，会写出损坏的码流。 | **绝不删除 `replay_matches_cover` 安全检查**，而是将其移入 `reencode_slice` 的 Rayon `into_par_iter()` 并行循环内执行（每个被触碰子流并行校验一次），既保住 100% 安全性，又彻底消除单核串行瓶颈。 |
| **P1：代价 LUT 改变比特输出与基线** | 声称 `cost_from_dq` 改为 `f32` LUT 后“不改变任何比特输出，58 例 baseline 全过”。 | 改变浮点运算结合顺序与精度（`f64` 转 `f32` 查表）会改变边界槽位的代价排序，导致 STC 选出不同的翻转集合。 | 将 **零输出变化的纯清理（PR A）** 与 **改变输出比特的优化（PR B：Cost LUT、RASL 排除）** 严格拆分；PR B 合入时必须显式重新生成 `baseline_hash.py` 基线。 |

## 2. 各操作路径的真实耗时构成与优化作用矩阵

为了避免把不同路径的收益混为一谈，下表列出四个 CLI 命令各自经过的真实代码路径，以及每项优化措施到底对哪条路径生效：

| 优化措施 | 代码位置 | `embed --capacity`<br>(`probe_hevc_pool` 采样 1000 切片) | `capacity --exact`<br>(`Capture::Count` 全片 34,454 切片) | `embed` (1 MiB)<br>(`Capture::Full` 前 ~5,050 切片) | `extract` (1 MiB)<br>(`Capture::Bits` 前 ~5,050 切片) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **1. `starts_picture` 改 O(1)** (`nal[2] & 0x80`) | `engine.rs:2704` | **生效**（省去全片 529 MiB `unescape`） | **生效**（省 ~0.5–1 s） | **生效**（省 ~0.5–1 s） | **生效**（配合跳过 `count_pictures` 省 ~0.5–1 s） |
| **2. 单子流免调 `nal_rbsp` + `RecordMode::Count`** | `engine.rs:391, 498, 2507` | **生效**（采样循环同样免 `nal_rbsp`） | **生效**（省去全片 529 MiB `unescape` + 5.59 亿次 `StegoSlot` push/drain，约 **2–4 s**） | 无关（`Full` 需保留 `orig_rbsp` 和 `StegoSlot`） | **部分生效**（单子流免调 `nal_rbsp`，省 ~0.2 s） |
| **3. 删除 `provisional_sign_flip_cost` (`powf`)** | `slot.rs:515-519` | 不生效（`Slots` 模式不调） | 不生效（`Slots` 模式不调） | **核心生效**（省去 8,390 万次 `f64::powf` 白算） | 不生效（`Slots` 模式不调） |
| **4. 预回放校验 (`replay_matches_cover`) 并行化** | `engine.rs:1024-1049` | 不生效 | 不生效 | **核心生效**（3,000+ 切片预回放从单线程移入 Rayon 并行，省 **8–15 s**） | 不生效 |
| **5. 删除 `SlotSink::band_slots` 废克隆** | `engine.rs:2271, 2300` | 不生效 | 不生效 | **核心生效**（省去 8,390 万个 `StegoSlot` = **1.34 GB** 冗余分配与拷贝） | 不生效 |
| **6. `embed_with_cost_fn` 替代 `body_costs` 分配** | `engine.rs:958-982` | 不生效 | 不生效 | **生效**（省去调用方 134 MB `Vec<f64>` 分配；注：STC 内部仍需分配 268 MB `back` 表） | 不生效 |
| **7. 代价几何查找表 (`COST_GEOM_LUT`)** | `slot.rs:339` | 不生效 | 不生效 | **生效**（加速 8,390 万次 `record_stego_level` 代价计算；**注意：会微调浮点舍入，改变输出基线**） | 不生效 |
| **8. `all_body_indices` 缩减与 `StcTrellis::extract` 字并行** | `engine.rs:196`, `stc.rs:409` | 不生效 | 不生效 | **部分生效**（`all_body_indices` 改 `u32` 省 335 MB） | **生效**（省 335 MB 分配 + 加速 Syndrome 矩阵提取） |
| **9. 跳过环路滤波 (`RH265_NO_LF` / 显式 flag)** | `rusty_h265/src/filters.rs` | **生效**（解码耗时降 ~20%，即 **~1.25x**） | **生效**（解码耗时降 ~20%，190s $\rightarrow$ **~150s**） | **生效**（解码阶段耗时降 ~20%） | **生效**（解码阶段耗时降 ~20%） |
| **10. 跨 GOP 多核并行解码** | `engine.rs` | 需单独改造 `probe_hevc_pool`（受限于仅 ~10 个 GOP，理论上限 ~4x） | **决定性生效**（322 个 GOP 在 8~16 核上并行，理论 **8x–12x**） | **决定性生效**（前 ~50 个 GOP 并行解码，解码阶段 **6x–10x**） | **决定性生效**（前 ~50 个 GOP 并行解码，解码阶段 **6x–10x**） |

## 3. 核心技术问题深度修正方案

### 3.1 修正一：确保 `embed` 新修改不引入安全退化（预回放并行化 + 截断切片兜底）

1. **并行化而非删除 `replay_matches_cover`（修复审查 §5.1）**：
   - 在 `engine.rs:1024-1049` 中，原本是单线程遍历 `touched` 集合调用 `encode_substream(slice_rec, sub, &[])`。
   - **安全且快速的改法**：将该检查合并到紧随其后的 `slice_items.into_par_iter()`（`engine.rs:1062`）中！对每个被触碰的 `(slice_idx, sub_idx)`，若尚未在 `replay_ok` 中验证过，就在 Rayon 工作线程内先执行一次无翻转 `encode_substream(slice_rec, sub, &[])` 并调用 `replay_matches_cover(&replay, cover)`；校验通过后再立即在同一线程内（此时该切片的 `ops` 正热驻留在当前核心的 L2/L3 缓存中！）执行带翻转的 `encode_substream(slice_rec, sub, flipped_entries)`。
   - **效果**：100% 保留原有的字节级无损安全网（绝不漏过“长度相同但字节不同”的异常子流），同时将原本串行耗费 10+ 秒的校验完全分摊到全核并行且享受缓存局部性。

2. **删除 `provisional_sign_flip_cost` 后的截断切片防御（修复审查 §5.2）**：
   - 在 `slot.rs:516` 将初始 `cost` 设为 `HIGH_DISPLACEMENT_PENALTY as f32`（`1_000_000.0`，而非 `0.0`！）并在 `absorb_recorder`（`engine.rs:2735`）开头增加硬性校验：
     ```rust
     if recorder.mode == RecordMode::Embed && recorder.next_pending_slot != recorder.slots.len() {
         // 切片解码中途截断导致 sign 与 level 数量失步，丢弃该不完整切片的全部槽位
         recorder.slots.clear();
         recorder.reset_pending();
         return;
     }
     ```
   - 这样即使遇到异常截断切片，既不会将未回填槽位误标为 `0.0` 最便宜槽位，也不会让失步槽位混入全局池。

### 3.2 修正二：CRA / RASL 开放 GOP 并行解码的确定性设计（修复审查 P0-1）

针对 `anime-b.mp4` 实测包含 `1 IDR + 321 CRA + 88 RASL` 的真实结构，要实现 **1 线程与 N 线程 100% 确定性一致** 且 **embed 与 extract 槽池 100% 一致**，必须解决两个问题：**RASL 帧去留** 与 **解码器状态隔离**。

#### 1. 为什么在 GOP 并行下应当直接从槽池排除 RASL（`NAL_RASL_N = 8`, `NAL_RASL_R = 9`）？
* **占比极小**：在 `anime-b.mp4` 的 34,454 个切片中，RASL 仅有 88 个（占 **0.25%**）。
* **H.265 规范保证（§8.3.2 & §3.27）**：CRA 帧之后的任何非 RASL 帧（包括 CRA 自身、RADL 帧以及所有后续 `TRAIL_N` / `TRAIL_R` 帧），在规范上**严禁参考该 CRA 之前的任何帧或任何 RASL 帧**。唯一依赖前一个 GOP 残留 DPB 的只有 RASL 帧本身。
* **结论**：如果我们在 `picture_band` 中将 `NAL_RASL_N` 和 `NAL_RASL_R` 排除（返回 `None`），并且在切分 GOP 时遇到 `CRA` 就将解码器置于 `first_in_sequence = true`（从而令 `no_rasl_output_flag = true`，解码器自动按标准跳过 RASL），那么**每一个以 IDR 或 CRA 开头的 GOP 都变成了严格自包含、零外部依赖的纯函数单元**！无需做复杂的跨 GOP 尾部预热，也不会因为 `generated_refs` 污染 DPB。

#### 2. 解码器状态隔离（杜绝 `map_init` 跨 GOP 污染）
如审查报告 §1.3 所证，`rusty_h265::Decoder::flush()` 并未清空 DPB，也未重置 `prev_tid0_poc`、`no_rasl_output_flag` 和 `skipping_picture`。因此有两种可靠做法：
* **做法 A（零 fork 改动，立即可用）**：每个 GOP 段（约 107 个切片）在开始解码时直接 `Decoder::new()` + 设 `Ablate` + 喂入 `parameter_sets`。
  - 成本核算：`anime-b.mp4` 全片只有 322 个 GOP（1 MiB 嵌入只涉及前 ~50 个 GOP）。创建一个 `Decoder` 并解析 VPS/SPS/PPS 耗时不到 0.1 ms，且 `Decoder` 内部的图片缓冲区（`Picture::new`）是在解码具体帧时按需分配并在 GOP 结束 drop 时立即归还的。因此**每个 GOP 新建一个 `Decoder`（同一时刻仅有线程数 $T$ 个 `Decoder` 存活）既彻底根除了跨 GOP 状态污染，又不会增加并发内存峰值**！
* **做法 B（配合 `rusty_h265` 更新时合入）**：在 `rusty_h265::Decoder` 上新增 `pub fn reset_sequence(&mut self)`，显式清空 `dpb`、`output_queue`、`prev_tid0_poc`、`skipping_picture` 并置 `first_in_sequence = true`，供线程内安全复用。

#### 3. 单核与多核统一 GOP 边界语义
为了确保无论走单核还是多核、无论 `w0` 落在哪个切片，两端槽池都 100% 相同：
- 只要开启新的 GOP 边界规则（即每个 `is_irap(nal_type) && starts_picture` 处重置解码器序列状态，且 `picture_band` 排除 `RASL_N`/`RASL_R`），**所有路径（`probe`、`embed`、`extract`、`inspect`、`verify`）统一遵守该规则**。

### 3.3 修正三：真实内存账本与 8 GiB 准入控制（修复审查 P0-3）

#### 1. `embed`（`Capture::Full`）真实内存账本（以 `anime-b.mp4` 实测为准）
审查报告复测显示：当前 `embed 1 MiB`（扫描前 ~5,050 个切片，83.90M 槽位）的实际峰值工作集（RSS）为 **5.74 GiB**。拆解构成如下：

| 内存项 | 5,050 切片（83.90M 槽位）占用 | 删除 `band_slots` 后的占用 | 计算依据与源码位置 |
| :--- | :---: | :---: | :--- |
| 1. 载体文件缓冲 `carrier_bytes` | **0.52 GiB** (529 MiB) | **0.52 GiB** | `stego/io.rs:50` (`std::fs::read`) |
| 2. 切片 `BinOp` 日志 + `orig_rbsp` | **~2.20 GiB** | **~2.20 GiB** | `SliceContext::ops` (`Vec<BinOp>`, 2 B/bin) + `orig_rbsp`（含 `Vec` 扩容余量） |
| 3. 全局槽位池 `raw_slots` | **1.25 GiB** (1.34 GB) | **1.25 GiB** | `83.90M × 16 B`（加 `Vec` 扩容峰值可达 2.0 GiB，预分配后稳定在 ~1.3 GiB） |
| 4. **冗余 `band_slots`（待删）** | **1.25 GiB** (1.34 GB) | **0 GiB** | `engine.rs:2300` 推入后在 `2558` 被丢弃 |
| 5. `all_body_indices` + `is_sb` | **0.70 GiB** (755 MB) | **0.39 GiB** (`u32`) | `83.90M × 8 B` (671 MB) + `83.90M × 1 B` (84 MB)；改 `u32` 后省 335 MB |
| 6. STC 求解缓冲（`body_positions` + `back` + `body_costs`） | **~0.55 GiB** | **~0.42 GiB** | `16.78M` 槽位：`body_positions` (134 MB) + `stc.rs:627` `back` (268 MB) + `body_costs` (134 MB，用 `embed_with_cost_fn` 可省) |
| **单核合计** | **~5.74 GiB**（与实测吻合） | **~4.3–4.6 GiB** | 删除 `band_slots`、改 `u32`、用 `embed_with_cost_fn` 后立省 **~1.4 GiB** |
| **加 $T=8\sim 12$ 并发解码器开销** | - | **+0.5 ~ 0.8 GiB** | 每个 10-bit 1080p `Decoder` 含 DPB 像素平面约 45~65 MB |
| **并行 `embed 1 MiB` 预计总峰值** | - | **~5.0 ~ 5.4 GiB** | 稳健控制在 **8 GiB** 预算以内 |

#### 2. 诚实的内存边界结论
* 在 **8 GiB 预算**下，单窗口 `Capture::Full`（`embed`）安全承载上限约为 **5,500 ~ 6,000 个 1080p 切片（约 9,000 万 ~ 1 亿槽位，对应 `high` 档 ~1.1 MiB 载荷，或 `balanced` 档 ~2.2 MiB 载荷）**；在 **12 GiB 预算**下约为 **8,500 ~ 9,500 个切片**。
* **不要在单窗口协议下承诺“超 8 GiB 自动分批清空日志”**：因为 `HevcSuperblock.total_windows` 目前固定为 `1`，STC 必须拿到窗口内全部 `body_positions` 的代价才能开始求解，求解完并完成重编码后整个 `embed` 就已经结束了。
* **真正的防 OOM 准入机制**：
  1. 在开始录制前，根据 `target_slots` 估算所需峰值内存：
     $$\text{EstMemory} \approx \text{carrier\_len} + \text{target\_slots} \times 48\text{ B} + \text{body\_needed\_slots} \times 28\text{ B} + T_{\text{threads}} \times 64\text{ MiB}$$
  2. 若 `EstMemory` 超过设定的内存上限（如 8 GiB 或 12 GiB），可通过减少并发解码线程数 $T$、提示用户切换 `--safety balanced`（将 `target_slots` 减半），或在未来专门立项实现 `total_windows > 1` 的多窗口流式分片协议来解决。

## 4. 分阶段可验证落地计划（4 个独立 PR，严格门禁）

遵循审查报告 §7 的工程建议，将改动拆分为 **Step 0 + 4 个递进 PR**，每一步独立编译、独立测速、独立验证基线：

### Step 0：建立统一实测基准
在改动任何代码前，在 `anime-b.mp4` 上用监控脚本记录以下 5 项基准数据（耗时 + 峰值工作集 RSS）：
1. `strhide embed --capacity anime-b.mp4`（默认采样 1,000 切片）
2. `strhide embed --capacity anime-b.mp4 --exact`（全片 34,454 切片）
3. `strhide embed -d payload-1m.bin -p pwd1234 anime-b.mp4 -o out.mp4`
4. `strhide extract -p pwd1234 out.mp4 -o extracted.bin`
5. 在设置环境变量 `$env:RH265_NO_LF="1"` 后重跑上述 1~4，直接获得跳过环路滤波在 `anime-b.mp4` 上的真实实测提速比。

### PR A：零输出变化的纯清理与并行预回放（100% 保持现有 `baseline_hash.py` 不变）

**目标**：只做**不改变任何槽位顺序、不改变任何浮点代价、不改变任何输出字节**的改造，确保 `python scripts/baseline_hash.py --check` 58 例 100% 原样通过。

1. **`rust/src/stego/hevc/engine.rs`**：
   - **`starts_picture` O(1) 化**（第 2704 行）：改为 `nal.get(2).is_some_and(|&first| (first & 0x80) != 0)`，彻底消除全片 34,454 次 `unescape`；
   - **`Capture::Bits` 免跑 `count_pictures`**（第 2462 行）：当 `capture == Capture::Bits` 时直接置 `(pictures, band_pictures) = (1, [1, 0])`；
   - **删除 `SlotSink::band_slots`**（第 2271、2300 行）：直接移除该字段，在 1 MiB 嵌入上立省 1.34 GB 内存与拷贝时间；
   - **单子流免调 `nal_rbsp`**（第 391、498、2507 行）：在 `probe_hevc_pool` 和 `record_carrier_state` 中，当 `capture != Capture::Full && recorder.substreams.len() <= 1` 时，不调用 `nal_rbsp(slice_bytes)`；
   - **新增 `RecordMode::Count`**（`slot.rs:190` & `engine.rs:2372`）：在 `Capture::Count` 且单子流时仅递增计数器，不向 `recorder.slots` 推入 5.59 亿个 `StegoSlot`；
   - **调用点按实测比例预分配 `ops` 与 `slots`**（`engine.rs:2496`）：新增 `CabacRecorder::with_slice_capacity(slice_idx, band, mode, slice_bytes.len())`，在 `RecordMode::Embed` 下按 `ops: slice_len * 18`、`slots: slice_len`（实测 1.01 槽位/字节）预分配容量，避免过度分配或频繁倍增；
   - **将步骤 3c 预回放校验并入 Rayon 并行循环**（`engine.rs:1024-1073`）：不在单线程中串行跑 `encode_substream(slice_rec, sub, &[])`，而是在 `slice_items.into_par_iter()` 内部对尚未验证的 `(slice_idx, sub_idx)` 先跑无翻转回放校验 `replay_matches_cover`，通过后再跑带翻转重编码；
   - **`embed_with_cost_fn` 替代 `body_costs` 大数组**（`engine.rs:958-982`）：消除每轮 134 MB 的 `Vec<f64>` 分配；
   - **`all_body_indices` 改用 `Vec<u32>`（带溢出断言）**：在 `total_slots <= u32::MAX as usize` 时使用 `u32` 存储索引，省去 335 MB 内存。
2. **`rust/src/stego/hevc/slot.rs`**：
   - **移除 `record_stego_sign` 中的 `provisional_sign_flip_cost`**（第 515 行）：将占位初值设为 `HIGH_DISPLACEMENT_PENALTY as f32`，并在 `absorb_recorder` 中校验 `recorder.next_pending_slot == recorder.slots.len()`，防止截断切片产生虚假低价槽位。
3. **PR A 验收门禁**：
   - `cargo test --all-features --all-targets` 全绿；
   - `python scripts/baseline_hash.py --check` **零改动全绿**；
   - 实测记录 `embed 1 MiB` 耗时下降（预期省去 8,390 万次 `powf` + 串行预回放 + 1.34 GB 拷贝后，`embed` 耗时有显著下降，内存峰值下降 ~1.4 GiB）。

### PR B：算术查表加速与 Syndrome 字并行（单独一轮，更新基线）

**目标**：引入会微调浮点舍入顺序的代价 LUT 以及 STC 提取字并行加速。

1. **`rust/src/stego/hevc/slot.rs`**：
   - 实现 118 KB 的几何权重查找表 `COST_GEOM_LUT`（按 `trafo_log2: 0..4`、`is_chroma: 0..2`、`zero_axes: 0..3`、`manhattan_xy: 0..63`、`bd_idx: 0..3`（覆盖 8/9/10-bit）、`sample_domain: 0..2` 索引），将 `compute_sign_flip_cost` 简化为查表与两次乘法。
2. **`rust/src/stego/coding/stc.rs`**：
   - 先测量 `StcTrellis::extract` 在 1 MiB 提取中的真实耗时占比；若占比显著，将 `row_syndrome` 改为预打包 `u64` 字与 `(word & mask).count_ones() & 1` 位并行计算。
3. **PR B 验收门禁**：
   - 验证所有 `embed -> extract` 往返 100% 位精确还原，FFmpeg 全片解码 0 错误；
   - 若 `COST_GEOM_LUT` 因 `f32` 结合律微调改变了翻转位置，显式更新 `baseline_hash.py` 基线并在文档中记录。

### PR C：`rusty_h265` 环路滤波跳过开关化（半天工作量）

> 上游源码路径：`F:\Develop\github\strhide-vendor\rusty_h265`

**目标**：将 `rusty_h265` 现存的环境变量 `RH265_NO_LF` 升级为 `Decoder` 结构体的显式字段。

1. **`rusty_h265/src/decoder.rs` & `filters.rs`**：
   - 在 `Decoder` 上新增 `pub skip_loop_filters: bool`（或判断 `self.ablate.mc && self.ablate.intra && self.ablate.residual`，切勿使用 `self.ablate.any()` 以免破坏仅开启部分 ablate 的调用方）；
   - 同时在 `Decoder` 上顺带新增 `pub fn reset_sequence(&mut self)`（清空 `dpb`、`output_queue`、`prev_tid0_poc`、`skipping_picture`，置 `first_in_sequence = true`），为 PR D 铺路；
   - 打新 git tag 并更新主仓 `Cargo.toml` / `Cargo.lock`。
2. **PR C 验收门禁**：
   - 槽位数量与 PR A/B 100% 完全一致，`baseline_hash.py --check` 全绿；
   - 全路径解码耗时降低约 20%（约 1.25x 提速）。

### PR D：确定性跨 GOP 多核并行解码（3~5 天工作量，严守确定性门禁）

**目标**：攻克 `capacity --exact`、`embed` 和 `extract` 中占比最大的单核 CABAC 解码瓶颈。

1. **统一 GOP 边界与 RASL 排除规则**：
   - 在 `picture_band`（`engine.rs:2652`）中排除 `NAL_RASL_N (8)` 与 `NAL_RASL_R (9)`（它们不再贡献槽位）；
   - 定义 GOP 起点为 `is_irap(cand.nal_type) && starts_picture(&carrier[cand.span])`（在 `anime-b.mp4` 上共切出 322 个 GOP）；
   - 每个 GOP 起点均以干净的序列状态（全新 `Decoder` 或调用 `decoder.reset_sequence()`，使得 `first_in_sequence = true`、`no_rasl_output_flag = true`）喂入 `parameter_sets` 后独立解码。
2. **三条路径的并行化策略**：
   - **`StopCondition::All`（`capacity --exact`）**：322 个 GOP 直接通过 `gops.par_iter()` 由 Rayon 线程池并行解码计数，按 `gop_idx` 顺序归并 `counts` 与 `band_pictures`；
   - **`StopCondition::TargetSlices(w0)`（`extract`）**：由于从 Superblock 已经精确得知需要前 `w0` 个有效切片，直接找到覆盖前 `w0` 个切片的前 $K$ 个 GOP（1 MiB 载荷下约前 48 个 GOP），用 `par_iter()` 并行解码这 $K$ 个 GOP，归并后截取前 `w0` 个录制切片即可——**零猜测、零重试**！
   - **`StopCondition::TargetSlots(target)`（`embed`）**：按分批波次（例如每批并发提交 $B = 16$ 或 $32$ 个 GOP，并根据 3.3 节的内存账本限制并发总切片数 $\le 5,500$）并行解码，每批结束后按 GOP 顺序累加槽位数，一旦达到 `target_slots` 即停止提交后续批次并截断到精确满足 `target_slots` 的切片边界。
3. **PR D 硬性验收门禁（不通过绝不合入）**：
   - **门禁 1（多线程确定性测试）**：对 `anime-b.mp4` 及 `temp/testhevc` 全部语料，分别设置 Rayon 线程数为 `1`、`4`、`16` 运行 `record_carrier_state`，断言产出的 `total_slots`、`slice_slot_ranges`、`band_bits`、`raw_bits` 及每个 `StegoSlot` 的字段 **100% 逐字节全等**；
   - **门禁 2（往返一致性）**：16 线程 `embed` $\rightarrow$ 1 线程 `extract`（以及反过来 1 线程 `embed` $\rightarrow$ 16 线程 `extract`）载荷 SHA-256 100% 匹配，FFmpeg 全片软解 0 报错；
   - **门禁 3（内存水位线验证）**：在 `anime-b.mp4` 上嵌入 1 MiB 载荷，实测峰值工作集 RSS 严格不超过 8 GiB 的 90%（$\le 7.2\text{ GiB}$）。
