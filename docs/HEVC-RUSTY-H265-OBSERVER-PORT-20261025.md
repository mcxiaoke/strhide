# rusty_h265 CABAC Observer 移植与验证报告

| 项 | 内容 |
| :--- | :--- |
| **文档编号** | `HEVC-RUSTY-H265-OBSERVER-PORT-20261025` |
| **编制日期** | 2026-10-25 |
| **性质** | **可行性门禁（feasibility gate）**：把 strhide 在用的 `rust_h265` fork 的 `CabacObserver` 契约移植到 `rusty_h265` fork，并以真实语料做逐 bin 等价性验证。移植阶段**主仓零改动**；2026-10-25 22:46 起主仓已完成解码侧接入（`Cargo.toml`/`engine.rs`/`slot.rs`，见 §9），fork 改动已推为 tag `v1-20261025`。 |
| **关联文档** | `HEVC-MP4-MOV-SOURCES-EVAL-20261025.md`（底座选型，本移植的对象）、`HEVC-MP4-MOV-EMBED-EXTRACT-PLAN-20261025.md` §4/§11（vendor tiles 死局与止损记录） |
| **结论** | **门禁通过**：槽集合与 vendor **逐字段完全一致**（3 个共享语料共 7,225,909 个槽）；决策 bin 位级一致（7,204 万）；vendor 卡死的 2 个小米 tiles 文件在移植后录到 **944 万 / 635 万**个槽；未挂 observer 时帧哈希与上游完全一致。两项编号/口径事项**已按 H.265 规范裁定并落地**（见 §5）：上下文编号**不需要翻译表**（编码器对编号无状态，快照补长到 179 槽即可，索引保持原生）；transform-skip 的 `abs_dq` 已按 §8.6.2 折算为样本域（level 一致率 bframes 99.68%/tiles 100%）。**端到端重编码闭环已验证（§6）**：rusty 的日志经 `oxideav` 编码器回放，573 切片 / 6,914 子流 / 2.48 亿字节与 cover **逐字节相同（零 padding 容忍）**；翻转样本 40/40 与 5 例全槽翻转（22.4 万符号 bin）全部被真实解码器逐 bin 读回，长度零变化。 |

---

## 1. 移植范围（只搬 strhide 真正消费的接口）

先看 strhide 本体到底需要什么，再决定移植面。现状（`rust/src/stego/hevc/`）：

- `slot.rs` 的 `CabacRecorder` 实现了 7 个回调；引擎只消费其中三类数据：`ops`（完整 bin 序列，**CABAC 重编码的输入**）、`slots`（符号槽 + 代价）、`substreams`（子流边界 + 初始上下文）。
- 编码侧在**另一个 fork**（`oxideav-h265` 的 `CabacEncoder`），消费的是 strhide 自己的 `BinOp`/`SubstreamRecord` 类型。**所以移植面只在解码侧**，编码器零改动。
- 引擎的驱动方式（`engine.rs:984/1024`）：`decoder.decode_nal_with_observer(&unit, &mut recorder)`，先喂参数集、再逐 slice 挂 recorder。

据此确定移植的最小集合 = 1 个 trait + 1 个入口 + 7 个挂钩点。

## 2. 实现（8 个文件，+266/−28 行）

| 文件 | 改动 |
| :--- | :--- |
| `src/observer.rs` **（新增 100 行）** | `CabacObserver` trait（7 个回调）、`ContextSnapshot = [u8; ENCODER_CONTEXTS]`（**179**，与 `rust_h265` 的 `HEVC_CONTEXTS` 同宽）、`context_snapshot()` 把原生 157 状态补长到 179 槽 |
| `src/cabac.rs` +78 | `Cabac<'a, 'o>` 增加 `observer: Option<&'o mut dyn CabacObserver>`（**独立生存期**，见 §3）；`new_with_observer`；`decode`→`record_decision`、`bypass`→`record_bypass`、`terminate`→`record_terminate`；`bypass_bits` 拆出 `bypass_bits_inner(n, record)`（保持批量读的优化，同时可按 bin 上报）；`bypass_ones` 逐 bin 上报（k 个 1 + 终止 0）；`bypass_sign_bits(n, qp, trafo_size, c_idx, coords)` 批量读符号位并逐 bin 上报 `record_stego_sign` |
| `src/ctu.rs` +46 | `SliceInputs<'a,'o>` 增加 `observer`；`SliceDecoder<'a,'o>`；`pending_substream`（子流切换时先记下，待下一轮上下文最终确定后再上报）；三处子流钩子：slice 起始 `start_substream(0, data_offset, ctx)`、WPP/tile 切换 `start_substream(idx, start, ctx)`、`end_of_slice_segment` 时 `finish_slice(rbsp_len)` |
| `src/ctu/residual.rs` +90 | 抽出 `block_qp(c_idx)`（与 `reconstruct_residual` 共用，含 chroma QP 映射）；符号位读取改 `bypass_sign_bits` 并预先构造 `(x_c, y_c)` 坐标表；层循环内 `record_stego_level`（`dequant_one` 给 §8.6.3 的 `d`，transform-skip 再按 §8.6.2 折算为样本域） |
| `src/decoder.rs` +38 | `push_slice` → `push_slice_obs(..., observer)` + 薄包装；新增 `pub fn decode_nal_with_observer(&mut self, nal: &[u8], observer: &mut dyn CabacObserver)`（非 VCL 回落 `push_nal`） |
| `src/itx.rs` +20 | `dequant_one(level, x, y, n, qp, bit_depth, m)`——与 `dequant` 逐项同式的单系数版本（不重构热路径，避免 perf 风险） |
| `src/lib.rs` +1 / `ctu/inter.rs` ±1 | 导出模块 / impl 生存期 |

**没有用 unsafe**：rusty 核心的 `#![forbid(unsafe_code)]` 保持有效（对照：rust_h265 fork 用 `*mut dyn` + transmute 存 observer）。

## 3. 两个实现层面的关键决策

1. **生存期**：observer 的借用必须与切片数据（局部量）解耦，否则 `SliceInputs<'a>` 把所有字段统一到 `'a` 时推断失败（实测报 `sh does not live long enough`）。方案：`Cabac<'a, 'o>` 双生存期，`SliceDecoder<'a, 'o>` / `SliceInputs<'a, 'o>` 透传，零 unsafe 解决。
2. **符号位是批量读的**：rusty 的 `bypass_bits(nsigns)` 一次读整组符号（性能优化），不像 fork 逐位 `decode_stego_sign`。移植时保留批量读、在其内部逐 bin 上报（`bypass_sign_bits`），因此**热路径没有退化**，且观察到的 bin 序列与逐位读完全等价（已由 §4 的逐 bin 对比证明）。

## 4. 验证（`temp/mp4_verify/obssmoke/`）

同时链接三个 crate：`rust_h265` fork（现役，带 observer）、移植后的 `rusty_h265` fork、原始上游 `rusty_h265`（回归对照）。同一 Annex-B 语料分别驱动两边 recorder，按子流逐段比对。

### 4.1 等价性（两个解码器都能解的文件）

| 语料 | 切片 | 决策 bin | 决策位 | 槽（bit/qp/trafo/c_idx/x_c/y_c 全字段） | 子流边界（idx+RBSP 字节区间） | 逐子流 bin 流 |
| :--- | :--- | ---: | :---: | :--- | :--- | :--- |
| seg_bframes（iPhone 4K I/P/B，无 WPP） | 78/78 | 30,554,490 | **一致** | **2,780,623 = 2,780,623** | 78 = 78 | **78/78 完全相同** |
| seg_mov（iPhone MOV 开放 GOP，**每切片 34 个 WPP 子流**） | 183/183 | 39,204,161 | **一致** | **3,796,578 = 3,796,578** | **6,222 = 6,222** | **183 完全相同 + 6,039 = 完全相同 + 末尾 `end_of_subset_one_bit`** |
| tiles_x265（x265 合成） | 10/10 | 2,291,091 | **一致** | **648,708 = 648,708** | 10 = 10 | **10/10 完全相同** |

- **零无法解释的差异**：MOV 的 6,039 = 6,222 − 183，恰好等于子流切换次数——每个切换处 rusty 比 vendor 多记录一个 `T(1)`。
- **该差异有规范背书**：H.265 §7.3.8.1 在子流边界编码 `end_of_subset_one_bit`（ae(v)，§7.4.9.1「shall be equal to 1」）。vendor 不解它、直接 `reinit_at` 跳到下一个 entry point；rusty 忠实解码并记录。引擎编码器现有代码 `if !matches!(ops.last(), Some(BinOp::Terminate { bit: 1 })) { encode_terminate(1) }` **对两种记录方式都成立**（幂等），因此集成时无需改动。
- **上下文编号是纯重标号**：138~148 个不同的 fork-ctx 全部是**一对一一致映射**（例：fork 17→rusty 16、37→31、42→36、118→108），决策位全等。vendor 的编号与 FFmpeg 参考实现完全相同（179 上下文，`93/137/161`），rusty 为自研 157 布局。规范不强制唯一内部编号，故不构成违规。见 §5 待办 1。

### 4.2 覆盖（vendor 完全解不动的文件）

| 语料 | 切片 | 解码错误 | 槽 | 子流 |
| :--- | :--- | :---: | ---: | ---: |
| seg_refonly（小米 1080p60 tiles，vendor 卡在 1082/2040 CTU） | 181 | **0** | **9,446,382** | 362（2 tiles/切片） |
| seg_xiaomi_new（小米新拍 tiles，vendor 卡在 1107/2040） | 121 | **0** | **6,354,012** | 242 |

对照文档1：vendor 在这两个文件上 `capacity` 报 **0 槽**。移植后不但可解，槽量与 iPhone 文件同量级。

### 4.3 回归（未挂 observer 时行为中性）

5/5 语料与**上游原始 rusty_h265** 逐帧哈希一致、帧数一致、零错误：

| 语料 | 帧数 | 哈希 |
| :--- | ---: | :--- |
| seg_bframes | 78/78 | `8ab37bc87cda07bc` 相同 |
| seg_mov | 183/183 | `968de73e973673a1` 相同 |
| seg_refonly | 181/181 | `4dae94eef5c7584f` 相同 |
| seg_xiaomi_new | 121/121 | `88595682a9c9da43` 相同 |
| tiles_x265 | 10/10 | `ac2018f7ef8834ea` 相同 |

### 4.4 工程门禁

| 项 | 结果 |
| :--- | :--- |
| `cargo build --release` | **0 error / 0 warning** |
| `cargo test --release` | 39 + 30 + 1 + 1 全绿（1 ignored = 缺 JCT-VC 向量库的 conformance） |
| `cargo fmt --check`（本仓 `max_width = 200`） | 我改的 8 个文件全部 fmt-clean；剩余差异在 `bin/`、`prof.rs`、`accel/lib.rs`（**上游既有**，未触碰） |
| `cargo clippy --all-targets` | 与上游同为 4 个警告（全在既有代码），**新增 0** |

## 5. 编号与口径的处理（已按规范裁定实施）

两项都已落地，且都比原计划更轻：**不需要翻译表，也不需要改引擎**。

### 5.1 上下文编号：补长快照，索引保持原生

- **事实**：vendor 布局 = **FFmpeg 参考实现**（ELEM 累计和 179；`SIG_COEFF=93`/`GT1=137`/`GT2=161` 逐项吻合）；rusty 为自研 157 紧凑布局（`83`/`127`/`151`）。规范 **Table 9-4** 按 initType 给出 ctxIdx 区间，**不强制唯一内部编号**——只要求「语法元素 × ctxInc × initType → 状态/initValue」一致；两边都能解 147/147 一致性流，故不存在谁违规。
- **关键判断**：CABAC 编码器对编号是**无状态**的——strhide 的 `encode_substream` 只做 `ctx_array[ctx_idx]`，并用 `init_contexts` 初始化模型数组。因此可回放的充要条件是「索引与快照同布局」，而不是「索引等于另一解码器的编号」。手写 157→179 映射表既非必要，也做不到干净（rusty 的 `ref_idx`/`mvd` 上下文数与 vendor 不同，属多对一，不是函数）。
- **实施**：`observer::ContextSnapshot` 改为 `[u8; ENCODER_CONTEXTS=179]`，`context_snapshot()` 把原生 157 个模型状态放进 `0..NUM_CTX`，其余补 0（永不引用）。**索引继续报 native**（全部 < 179，满足引擎的越界检查）。strhide 的 `CabacRecorder` 只需把 trait 路径从 `rust_h265::CabacObserver` 换成 `rusty_h265::observer::CabacObserver`，方法体一字不改。
- **验证**：三个共享语料的 ops 逐子流全等、决策位全等、槽全等（见 §4.1）；测试侧增加两条守卫——快照 `NUM_CTX..` 必须全 0（已通过）、level 回调坐标必须与 sign 槽一致（两侧均 0 错位）。

### 5.2 level 回填：transform-skip 按 §8.6.2 折算为样本域

- **规范裁定**：§8.6.3 给出 `d[x][y]`（含 `+ (1 << (bdShift−1))` 舍入，`bdShift = BitDepth + Log2(nTbS) − 5`）；transform-skip 时 §8.6.2 再走 `(8-298) d << tsShift`（`tsShift = 5 + Log2(nTbS)`）与 `(8-299) >> bdShift`（`bdShift = Max(20−bitDepth, …)`），8bit 净效果 `d >> (15 − bitDepth − Log2(n))`。这正是 vendor 的 `ts_shift` 折算口径。
- **实施**：`record_stego_level` 的 `abs_dq` 对 transform-skip 块按上式折算（`(d + half) >> ts_shift`，`ts_shift > 0` 时）；`cu_transquant_bypass` 仍报原始 level。`dequant_one` 本身保持 §8.6.3 原式（含舍入）。
- **效果**：seg_bframes 的 level 一致率 **99.09% → 99.68%**（差异由 816 vs 26 收窄为 26 vs 25 这类 ±1）；tiles_x265 保持 **100%**；seg_mov 仍 97.47%。
- **残余 ±1 的归属**：两侧 level 回调坐标 0 错位（排除配对错误），且用 §8.6.3 公式手算两个样例（qp=32/4×4/8bit → 816；qp=15/32×32/8bit → 86）都与 rusty 一致、推不出 vendor 的值——**偏差在 vendor 一侧，±1 量级**（对代价是 ~4% 的四舍五入级影响，不影响槽集合与可嵌入性）。根因未深挖，记为已知差异。

### 5.3 剩余集成项

1. ~~**端到端重编码验证**：用 `oxideav` 的 `CabacEncoder` 回放 rusty 记录的 ops，与 cover 子流字节比对（引擎现成的 `replay_matches_cover`）。~~ **已完成，见 §6**：5 个语料 6,914 个子流全部 byte-exact（零 padding 容忍），翻转样本 40/40 + 5 例全槽翻转均经真实解码器回读 bin 级一致。
2. **代价模型补 transform-skip 分支**（主仓 `slot.rs`）：`compute_sign_flip_cost` 的 `dq·gx·gy/64` 是按变换路径的 64 倍基增益标定的；transform-skip 块没有该增益，折算后的样本域值再除以 64 会低估 ~32×。需按 `trafo_size`/skip 标志分档，或对 skip 块改用无 `/64` 的公式。**这是既有 vendor 路径就存在的隐性偏差，不是移植引入的。**
3. **性能**：挂 observer 的耗时未测；批量读保留后预计与不挂接近，待集成时用 release 数据确认。

## 6. 端到端重编码验证（原 §5.3.1，已完成）

验收问题：把解码侧录下的日志交给**编码侧**（strhide 真正发货的 `oxideav_h265::CabacEncoder`），能否逐字节重建 cover？这是编号补齐与快照布局的闭环判据——引擎判断"日志是否可翻"用的就是这条（`replay_matches_cover`）。

### 6.1 装置（`temp/mp4_verify/obssmoke/src/replay.rs`）

- **`replay`**：把引擎 `encode_substream` 的每一步照搬，不做任何"近似"——`[ContextModel::init(154,26); 179]` 起始表 → 用快照覆盖 `p_state_idx = state>>1` / `val_mps = state&1` → 逐 op `encode_decision` / `encode_bypass` / `encode_terminate` → 末 bin 不是 `Terminate{1}` 时补 `encode_terminate(1)` → `align_zero`。判据沿用引擎：完全相同；或 cover 多出的尾部全 0 且 ≤4 字节（`cabac_zero_word`）；其余算失败。
- **对照**：vendor `rust_h265` 跑同一套装置。它是在用的生产 recorder，若连它也报错，说明装置有问题而不是被验对象有问题。
- **`flip`**：抽样子流翻一个系数符号 bypass bin → 重编码 → 用**真实解码器的算术引擎**（`rusty_h265::cabac::Cabac::new(rbsp, byte_start, ctx)`）把新字节回读，要求翻转点之后的**每一个** bin 都与意图一致（不只是"长度没变"）。

### 6.2 回放结果

| 语料 | 切片 | 子流 | cover 字节 | 回放 bin | byte-exact |
| :--- | ---: | ---: | ---: | ---: | :---: |
| seg_bframes | 78 | 78 | 4,246,946 | 41,753,618 | **78/78** |
| seg_mov（34 WPP 子流/切片） | 183 | 6,222 | 5,095,124 | 51,843,958 | **6,222/6,222** |
| tiles_x265 | 10 | 10 | 438,554 | 3,972,587 | **10/10** |
| seg_refonly（vendor 0 槽） | 181 | 362 | 8,901,100 | 98,444,224 | **362/362** |
| seg_xiaomi_new（vendor 0 槽） | 121 | 242 | 6,143,135 | 68,698,292 | **242/242** |
| **合计** | **573** | **6,914** | **24,824,859** | **264,712,679** | **6,914/6,914** |

- **零容忍余量**：6,914 个子流全部与 cover 逐字节相同，一次都没用到 `cabac_zero_word` 的 4 字节余量——比引擎判据更严。
- **快照填充位门禁**：6,914 个子流的 `ctx[157..179]` 全为 0（rusty 不引用的槽位确实没被写入，符合 §5.1 的契约）。
- **两种日志形态、同一份字节**：vendor 对照 3 个共享语料 6,310 子流同样 100% byte-exact（41,753,618 / 51,837,919 / 3,972,587 bin）。mov 上 rusty 比 vendor 多 6,039 个 bin = 子流切换数，即它多记的 `end_of_subset_one_bit`；**回放字节仍然完全一致**，等于在 6,039 个切换点上实证了引擎"末 bin 不是 `Terminate{1}` 才补"这条幂等逻辑。
- **覆盖不打折**：vendor 完全解不动的两个小米 tiles 文件（944 万 / 635 万槽），其子流同样 100% 可回放。
- **耗时（release，单线程，解码+记录+回放全流程）**：rusty 侧 5 文件合计约 20 s（4.6/4.4/0.2/6.0/4.2），vendor 对照 3 文件约 23 s（12.9/10.0/0.3）。

### 6.3 翻转回读

两种翻转强度，都以「重编码 → 拼回切片 RBSP → 用真实解码器算术引擎逐 bin 回读」验收：

| 项 | 抽样单点翻转（每语料沿载体均匀抽 8 个子流，各翻 1 个符号 bin） | 全槽翻转（每语料 1 个子流，翻**全部**符号 bin） |
| :--- | :--- | :--- |
| 样本 | 40 个子流 | 5 个子流 / 共 **224,394** 个符号 bin |
| 回读 bin 级一致 | **40/40**，1,464 万 bin，0 处不一致 | **5/5**，181 万 bin，0 处不一致 |
| 子流长度变化 | **0 字节**（40 个样本 delta 全 0） | **0 字节**（5 个样本 delta 全 0，最大一例翻 136,424 bin） |
| 含义 | 翻转只改值不改长度——Δ=0 零比特膨胀的机制证据；且编码器产出在真实解码器下自洽，不只是"长度对上" | 大规模翻转（一个子流内 13.6 万 bin）同样不胀不缩、逐 bin 自洽，排除了"单点翻转偶然对齐"的可能 |

分语料明细（全槽翻转）：bframes 10,069 bin / mov 198 / tiles_x265 64,747 / refonly 12,956 / xiaomi_new 136,424，均 delta = 0 B。

### 6.4 装置自身的一处缺陷（已修，记录备查）

首轮回放 5 个语料**全部报失败**，症状高度一致：回放比 cover 短 4 字节、首个差异在末尾、cover 多出 `00 00 00 01`。定位结果是 `obssmoke` 的 Annex-B 切分器把**下一个 NAL 的起始码**算进了当前 NAL 的尾部（span 结束点取了起始码**之后**），于是 cover 的 RBSP 尾部多出 4 字节。改为「span 结束于下一个起始码的第一个字节，并裁掉 `trailing_zero_8bits`」后全部转 PASS。

该修正不改变任何 bin 判定：修正后复跑 `obssmoke all`，ops 逐子流（78 identical / 183 + 6,039 边界 T(1) / 10 identical）、决策位（3,055 万 / 3,920 万 / 229 万）、槽（2,780,623 / 3,796,578 / 648,708）、子流边界、5 个帧哈希与修正前**逐项相同**。

### 6.5 边界（本次未覆盖）

编码侧的**拼接层**不在本次范围内：EPB（`00 00 03`）重插入、`slot_map` 定位、`SlotBitTrace` 的 bit 区间、以及 embed→extract 全链路。它们都在引擎里、与解码器无关，等 `engine.rs` 真正换成 rusty 时一并验。本次结论严格限定为：**rusty 记录的日志在 CABAC 层可被编码器无损重建，翻转后可被解码器逐 bin 读回**。

## 7. 复现

```bash
# 1) 移植后的 fork（C:\Home\github\strhide-vendor\rusty_h265）
cargo build --release && cargo test --release

# 2) 等价/覆盖/回归三组验证（temp/mp4_verify/obssmoke）
cd temp/mp4_verify/obssmoke
cargo run --release              # all：equiv + coverage + regress（约 1.5 min）
cargo run --release -- equiv     # 只看逐 bin 等价

# 3) 端到端重编码验证（§6）
cargo run --release -- replay    # 只跑回放：日志 vs cover 字节
cargo run --release -- flip      # 只跑翻转回读
cargo run --release -- reenc     # replay + flip（约 1 min）
```

注 1：`temp/github/rusty_h265`（上游快照）为消解 Cargo 锁文件同名冲突，工作区版本号临时改为 `0.6.3`；仅该临时副本受影响。
注 2：`replay.rs` 依赖 `oxideav-h265`，版本与本仓 `rust/Cargo.toml` 一致（tag `v1-20261024`），保证验的就是发货的那份编码器。

## 8. 结论

**CABAC observer 可以成功移植**，且证据强于预期：不只是"能录到槽"，而是**槽集合与现役 vendor 逐字段完全一致**、决策 bin 位级一致、子流边界一致，同时把 vendor 三年未解的 tiles 语料（小米）覆盖率从 0 变成 181/121 切片零错误、944 万/635 万槽。未挂 observer 时行为与上游逐帧一致。

更关键的是**闭环已通**：rusty 的日志经 `oxideav` 编码器回放，573 个切片、6,914 个子流、2.48 亿字节与 cover **逐字节相同（零 padding 容忍）**；翻转样本 40/40 与 5 例全槽翻转（224,394 个符号 bin）均被真实解码器逐 bin 读回且长度零变化。剩下的是三件集成层的事：代价模型的 transform-skip 分档（既有偏差，非移植引入）、挂 observer 的耗时实测、以及引擎拼接层（EPB/槽映射/全链路）随 `engine.rs` 换用 rusty 时一并验收。

## 9. 主仓接入（2026-10-25 22:46，步骤 1-3）

移植层已进入生产路径。**改动 4 文件**：`rust/Cargo.toml`、`rust/Cargo.lock`、`src/stego/hevc/engine.rs`（+117/−77）、`src/stego/hevc/slot.rs`（+8/−5）。主仓未提交（按项目规则不自发 commit）。

| 步骤 | 内容 |
| :--- | :--- |
| 依赖 | `rust_h265 = tag v1-20261025-2` → `rusty_h265 = tag v1-20261025`；`rust_h265` 曾临时降为 `[dev-dependencies]`，22:57 已随示例/测试迁移**完全移除**（仓库内零引用）。fork 的 8 文件移植已提交 `fcef5b8`，tag 已推送 |
| slot.rs | trait 路径换成 `rusty_h265::observer::CabacObserver`，快照宽度换成 `ENCODER_CONTEXTS`（仍 179）。**7 个回调方法体一字未改**，印证 §5.1 |
| engine.rs | 删 `nal_type_to_u8`（30 行 match，span 已带字段）；参数集 `push_nal`、切片直接喂原始 NAL；`orig_rbsp` 改本地 `nal::unescape(&nal[2..])`；SPS 尺寸按 Table 6-1 从 `conf_win` 折算（rusty 无 `cropped_width()`）；被 §8.1.3 跳过的图片不占 `slice_idx` |
| 内存 | 新增 `drain_frames()`：每切片后排空输出队列。`Frame.picture` 是 `Arc<Picture>`，不拉帧就钉住每帧平面。**同一 4K 78 帧文件实测：排空 1,357 MB / 不排空 3,099 MB**（差 1.74 GB）；剩余 1.36 GB 是 journal 本身 |
| 错误策略 | 聚合首个解码错误，一条切片都没录到就返回 `UnsupportedFormat("HEVC carrier could not be decoded: …")`，不再静默 0 容量 |

**验证**：`build --release` 0/0、`fmt --check` clean、`clippy --all-targets` 0、`cargo test` 全绿（250+113+128+9+39+87+18+6）、`cargo test --test local_tests -- --ignored` **19/19**（含 ffmpeg PSNR、真实照片批量、确定性上界、HEIF bridge 4 项）。CLI 冒烟：HEIC 与 `bear.hevc` 往返 OK；**两个小米 tiles 文件从 0 槽变为可嵌入并成功往返**；4 个隐写产物 ffmpeg 解码 0 错误、帧数一致；RExt 4:4:4 与孤立 RASL 片段按预期 fail-closed 并给出可读原因；`seg_bframes` 槽数 2,780,623 与 §4.1 完全相同。

**剩余**：步骤 4 已完成（示例/测试迁到 rusty，`rust_h265` 依赖已从 `Cargo.toml`/`Cargo.lock` 移除；注意 rusty 的静图要 `flush()` 后才会出帧）。剩下 §5.3 的两项标定工作：transform-skip 的代价分档、observer 耗时实测。

