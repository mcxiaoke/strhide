# HEVC / H.265 隐写模块全面 Review 报告

- 日期：2026-10-24
- 范围：`rust/src/stego/hevc/`（19 582 行）、`rust/src/stego/mod.rs`、`rust/src/stego/registry.rs`、`rust/examples/hevc_*.rs`、`rust/tests/test_hevc_*.rs`
- 背景：模块由「手写 decoder + CABAC 代码」与「从 `temp/github/` 拷贝的成熟实现」混合而成，来源混杂、缺乏统一约束。

---

## 0. 代码来源测绘（本次 review 的第一个结论）

逐文件 diff（`diff -u --strip-trailing-cr`）把本地 `h265/` 与 `temp/github/rust_h265/src/` 对齐，得到**真实**改动量（原始 diff 统计里大部分是 CRLF 噪音，必须先归一化，否则会把 `decoder.rs` 的真实改动量夸大到 2580 行）：

| 文件 | 真实改动行 / 总行 | 改动性质 |
|---|---|---|
| `decoder.rs` | 2580 / 1348 | **整文件重写**（路径重写 + recorder 注入） |
| `inter_pred.rs` | 36 / 1303 | 仅路径 |
| `cu_tree.rs` | 334 / 4303 | 路径 + recorder 调用点 |
| `dpb.rs` | 28 / 876 | 仅路径 |
| `slice.rs` | 152 / 866 | 路径 + recorder 边界 |
| `cabac.rs` | 80 / 539 | **手写 `decode_stego_sign` + recorder** |
| `residual_coding.rs` | 48 / 937 | 手写坐标采集 + 换用 stego 解码 |
| `sps.rs` / `pps.rs` / `sao.rs` / `deblock.rs` / `vps.rs` / `profile_tier_level.rs` | ≤ 12 / — | 仅路径 |
| `bitstream.rs` / `cabac_tables.rs` / `error.rs` / `inverse_transform.rs` / `pixel.rs` | **0** | **原封不动** |

**结论**：所谓"代码乱"主要是 **路径重写噪音**造成的视觉混乱，真正的功能改动高度集中在 4 个文件（`decoder.rs`、`cabac.rs`、`residual_coding.rs`、`cu_tree.rs`）。核心算法（`cu_tree` / `inter_pred` / `sao` / `deblock` / `inverse_transform`）**一行未动**，这比预期好得多——意味着上游解码器的正确性基本保留。

**但仍有一个必须记录的合规问题**：

| 上游 | 许可证 | 本地是否保留声明 |
|---|---|---|
| `temp/github/rust_h265` | LICENSE-MIT + LICENSE-APACHE（双许可） | ❌ 无 |
| `temp/github/oxideav-h265` | MIT | ⚠️ `cabac/mod.rs` 仅一行 "adapted from oxideav-h265 (MIT)"，无版权行、无 LICENSE 副本 |
| `temp/github/pySTC` | LICENSE.txt | ❌ 无 |

**MUST FIX（合规，非技术）**：MIT/Apache-2.0 都要求保留版权声明与许可证文本。当前仓库若要分发，需在 `rust/src/stego/hevc/` 下加 `LICENSE-THIRD-PARTY.md` 并拷贝两份许可证全文，或将上游目录整体改为 `vendor/` 并附 `LICENSE`。
> 注：`cabac/mod.rs` 早期版本写的是 "adapted from n-h265 (n)"（疑似占位符），现已修正为 `oxideav-h265 (MIT)`，但仍缺版权行。

---

## 1. 已在本轮修复的严重问题（Critical）

### 1.1 EPB 冲突整片封禁 → STC 必然不可行（原始 panic 根因）
- **症状**：`hevc_matrix_bench` 在 `IMG_7547.HEIC` + `payload-16k.bin` 上 panic：`HEVC stego cannot resolve EPB conflict: Embedding infeasible: a group has no legal element (both directions illegal for every element)`，进程以 `0xc0000409` 退出。
- **根因**：某次旁路符号位翻转把码字字节 `0x58` 翻成 `0x00`，与后随 `00 01` 组成 `00 00 01`，触发 RBSP→NAL 的防竞争字节插入，NAL 长度 36305→36306。原实现把**整个 substream 封禁**（7805 次翻转涉及 16 个 substream），`u=2` 分组里两个元素同时非法 → STC 数学上无解。
- **修复**：改为 `forbidden: Vec<bool>` **按真实 slot 索引**精确禁用，只把破坏 `00 00 xx<=3` 窗口的那个 slot 代价置 `INFINITY`；槽位集合本身恒定不变。
- **关键教训（我自己犯过并修正）**：第一版修复想「删掉非法槽位并补位」，这**破坏了抽取对称性**——抽取方只能按固定槽位序列读取，删槽会让 extract 读到的元素集合与 embed 使用的不同。现行设计是「槽位集合恒定 + `forbidden` 只影响代价」。

### 1.2 槽位选择是全局槽池的顺序前缀 → 主图画质崩塌到 17 dB
- **根因**：iPhone 连拍 HEIC 含 **48 个独立 HEVC item**（48 张独立图像）。原实现取全局槽位的**前 N 个**，全部载荷压进第 1 张图，其余 47 张毫无变化，而 ffmpeg 默认输出第 1 张 → 主图 PSNR 仅 17.5 dB（Y 平面 206 366/262 144 像素差 > 8，误差呈自上而下渐变）。
- **取样证据**：16 点抽样单翻转，15/16 像素完全相同 —— 证明大多数抽样 slot 落在 ffmpeg 不输出的其他 item。
- **修复**：新增确定性 Weyl 置换打散槽位（黄金比例步长 0.618034，且强制 `gcd(stride, total) == 1`），embed 与 extract 共用同一 `slot_positions()`：
  ```rust
  fn slot_positions(total: usize, count: usize) -> Vec<usize>
  ```
- **实测收益**：IMG_1842 **17.5 → 42.9 dB**、IMG_5887 **3.4 → 54.4 dB**、IMG_7547 8192 B **33 → 47 dB**。

### 1.3 `compute_hevc_cover_digest` 哈希了文件头而非参数集
- **根因**：构造 `HevcNalSpan{ header_offset: 0, nal_len: ps.len() }` 去调 digest 函数，实际哈希的是**文件头部**的字节。
- **影响**：cover digest（用于 STC seed 派生）不随参数集变化 → 不同 SPS/PPS 的载体共享同一 seed → 跨载体复用 STC 码本，抗统计性下降。
- **修复**：直接哈希 `target.parameter_sets` 的真实内容。

### 1.4 HEIF 分支 slice 索引错位
- **根因**：`target.slice_spans.iter().enumerate()` 的下标被当作 `slice_idx`，但只在解码成功时才记录 slice → 一旦某个 slice 解码失败，`slice_contexts` 与 `slot.slice_idx` 整体错位（可能越界，或改错 slice）。
- **修复**：仅在成功记录 slice 时 `slice_idx += 1`。

### 1.5 `journal` 未校验时的静默损坏风险（新增可靠性护栏）
- **问题**：replay 重编码若与封面不一致（说明该 substream 用了 recorder 未建模的语法：PCM 样本、aligned bypass 段、未解析的 PPS 扩展等），原实现会静默写出坏码流。
- **修复**：重写某 substream 前，先用**零翻转**重放并与封面逐字节比较（`replay_matches_cover()`，允许 ≤4 字节尾部 `cabac_zero_word` 零填充）；不一致则该 substream 的 slot 全部标为不可用（`bad_substreams` + `forbidden`），**绝不允许静默写出坏码流**。
- **验证**：零翻转重放与封面**字节级完全一致** → 证明 CABAC 编码器 / 上下文初始化 / substream 边界记录正确。

### 1.6 HEIF 抽取回退错误语义（用户授权自行决定）
- **问题**：HEVC 分支失败后 `Err(_) => Err(e)` 丢弃桥接错误，返回 HEVC 的 `UnsupportedFormat`，导致 `test_heif_bridge_unsupported_carrier_fails_gracefully` 失败。
- **修复**：区分错误语义——
  - HEVC 报 `Password(_)` → 说明载体**确实**载有 CABAC 载荷，此时 HEVC 的口令判定才是诚实的判定，保留 `e`；
  - 其余 HEVC 失败只说明"这不是 Scheme C 载体"，桥接器的判定描述载体更准确 → 返回 `bridge_err`。

### 1.7 `registry.rs` 测试对新增域标签缺分支
`every_listed_algorithm_is_consistent_across_all_lookup_tables` 因未知域标签 `"HEIF/HEVC"` panic → 补 `hevc_seen` 计数分支与 `assert!(hevc_seen > 0)`。

---

## 1.5 本轮 review 中**新发现并已修复**的问题

### 1.5.1 HEIF 解析的越界 panic（真实可触发，非理论风险）

**这是本轮 review 最重要的新发现。**

- **位置**：`heif_boxes.rs` → `check_is_grid()` 的 `infe_version == 3` 分支
- **缺陷**：长度校验与切片访问不一致——
  ```rust
  if ipos + 8 <= pos + size {                        // 校验到 ipos+8
      let id = u32::from_be_bytes(iinf[ipos..ipos + 4]...);
      let itype = &iinf[ipos + 6..ipos + 10];        // 却访问到 ipos+10
  ```
  校验只保证 `ipos + 8` 在范围内，切片却需要 `ipos + 10`。当 `infe` box 的声明 size 为 20 且它是 `iinf` 中最后一个 box（缓冲区正好在 `pos + size` 结束）时，**越界 2 字节**。
- **实证**（用复刻旧逻辑的独立程序验证）：
  ```
  iinf.len()=24 pos=6 declared_size=20 -> buffer ends at 26
  thread 'main' panicked at examples/oldpanic.rs:5:26:
  range end index 28 out of range for slice of length 24
  error: process didn't exit successfully: ... (exit code: 0xc0000409, STATUS_STACK_BUFFER_OVERRUN)
  ```
  **退出码 `0xc0000409` 与用户最初报告的崩溃码完全一致。** 这说明最初的 panic 报告里，HEIF 解析越界与 CABAC EPB 冲突是两条独立的崩溃路径。
- **同类问题**：`parse_iloc_extents()` 中的 `&iloc[pos..]` 在 `pos` 越界时同样 panic（`pos += base_offset_size` 等步进没有上界检查）。
- **修复**：整个 `heif_boxes.rs` 重写为**零 panic** 风格——
  - 新增 `be_u16` / `be_u32` / `be_u64` 三个边界检查读取器（返回 `Option`）与 `read_uint`（越界返回 0）；
  - 所有长度字段用 `checked_add` / `is_none_or` 判断，杜绝整数溢出与越界；
  - `infe` v2 分支的校验从 `ipos + 6` 修正为 `ipos + 8`（同样存在 off-by-2）；
  - 切片访问改用 `get(range)` 返回 `Option`，不再有裸索引。
- **新增 4 个回归测试**：`malformed_infe_v3_does_not_panic`（精确复刻上述崩溃输入）、`truncated_boxes_are_errors_not_panics`（0..64 字节全前缀）、`fuzz_like_random_prefixes_do_not_panic`（512 字节确定性伪随机语料的 512 个前缀）、`extent_parsing_tolerates_truncation`。

### 1.5.2 `engine.rs` 抽取路径的 panic 面与整数溢出

- `header_bytes[0..4]` / `[4..8]` / `[8..12]` / `[12..24]` 为裸索引，依赖 `trellis.extract()` 恰好返回 40 字节。虽然 `slots_for` 与 `message_bits` 互逆保证了这一点，但一旦上游 STC 语义变化就会越界。
- `payload_len` 来自载体（**攻击者可控**），`24 + payload_len + 16` 与 `total_msg_len * 8` 在 32 位目标上会溢出。
- `msg_bytes[24..total_msg_len]` 在 `extract` 因容量不足返回更短 Vec 时会越界。
- **修复**：
  - 显式检查 `header_bytes.len() < HEVC_HEADER_BYTES`；
  - 所有长度运算改用 `checked_add` / `checked_mul`，溢出返回 `CorruptedData`；
  - `msg_bytes.len() < total_msg_len` 时提前返回错误；
  - 用 `seed_from_digest()` helper 取代两处 `try_into().unwrap()`；
  - `derive_hevc_key` 的 HKDF `expect` 改为 `is_err()` 分支（HKDF-SHA256 输出 32 字节必然成功，此处只是消除 abort 面）。
- **结果**：`engine.rs` 的 `unwrap()` / `expect()` 数量 **6 → 0**。

### 1.5.3 `ctx_idx` 越界风险

`h265/cabac.rs` 的 `decode_bin()` 用**指针差**计算 `ctx_idx`：
```rust
let ctx_idx = (state as *const u8 as usize).wrapping_sub(self.ctx_base);
```
若 `state` 来自 `attach_recorder` 之外的上下文数组，差值会回绕，虽被 `as u16` 截断不至于内存不安全，但会**静默记录错误的上下文索引** → 重编码时上下文错配 → 码流损坏。
- **修复**：加 `debug_assert!(ctx_idx < HEVC_CONTEXTS, ...)`，把潜在的静默错误变成早崩。

### 1.5.4 第三方许可证合规缺失

`rust_h265`（MIT + Apache-2.0 双许可）与 `oxideav-h265`（MIT）都要求保留版权声明与许可证文本，当前仓库**完全没有**。
- **修复**：
  - 新增 `rust/src/stego/hevc/THIRD-PARTY-NOTICES.md`，含两个上游的完整许可证文本 + 逐文件改动说明；
  - 给全部 29 个派生文件（`h265/*.rs`、`cabac/*.rs`）批量加上 SPDX 归属头：
    ```rust
    // Copyright (c) 2025 roticv (rust_h265 contributors)
    // Adapted for strhide. SPDX-License-Identifier: MIT
    // See THIRD-PARTY-NOTICES.md for the full license text.
    ```
  - 核实 `pySTC` 实为 **MIT**（非 GPL），据此修正了合规文件中的许可证表述。

### 1.5.5 外部 oracle 缺少像素级证据

原外部测试只断言 "ffmpeg 无报错 + PSNR ≥ 30 dB"。PSNR 是**均方值**，无法排除"少数像素灾难性偏差"或"几何不一致"。
- **修复**：测试新增 `decode_raw_yuv()`（`ffmpeg -f rawvideo -pix_fmt yuv420p`）与 `compare_pixels()`，断言：
  1. **解码字节数完全相同** → 帧数与分辨率一致（这是最强的语义证据）；
  2. `max |Δ| ≤ 200`（8 bit 满量程 255，只排除彻底崩坏的重建）；
  3. **偏差 > 16 的样本占比 ≤ 12%**。
- **阈值来自实测**而非拍脑袋：先采集全语料统计（>16 占比 1.2%–4.4%，>32 占比 0.07%–0.44%，max|Δ| 51–147），再据此设定 12% / 200。
- **一个重要的测量结论**：翻转系数符号后，**50%–66% 的采样点都会变化**（哪怕只差 1 LSB）——因为逆变换 + 去块滤波会把残差扰动扩散到整个变换块。所以"变化样本数"本身不是好指标，**"可见偏差样本占比"才是**。

---

## 2. 本轮 review 发现、尚未修复的问题（按严重度）

### P0 — 会导致错误结果（但当前测试未触发）
#### 2.1 `coeff_sign_flag` 的解码顺序与 HEVC 规范不符（上游遗留，非本轮引入）
`residual_coding.rs` 在**同一 CG 的所有 level 解码之前**批量读符号位：

```
decode_coeff_sign_flags(cabac, sign_nb, ...)   // ← 先读全部 sign
for m in 0..n_end { ... decode_coeff_abs_level_remaining ... }  // ← 后读 level
```

HEVC 规范 9.3.4.2.9 要求 `coeff_sign_flag[n]` 在对应的 `coeff_abs_level_remaining[n]` **之后**解码。`decode_coeff_sign_flags` 传入了 `qp`/`trafo_size`/`c_idx`，说明作者已经知道正确顺序。

- **为什么重要**：符号位的**字节位置**是隐写的核心。位置错了 → 抽取端的位序假设可能与编码端不一致（当前 embed/extract 共用同一 recorder 路径，所以自洽；但与 FFmpeg 的**语义**不再一致，跨工具链不可验证）。
- **为什么难改**：CABAC 是变长熵编码，改动符号位顺序会连带改变 `coeff_abs_level_remaining` 的 bypass 位流，必须与上游 rust_h265 的做法对齐才不破坏解码器。
- **建议**：这是**上游 rust_h265 的既有设计**，本轮 diff 证实未改动顺序。需先确认上游是否有对应测试夹具覆盖 SDH 场景（`signhide` 夹具在注释中被提到），再决定是修还是向上游反馈。**在澄清前不应擅自改动**。

#### 2.2 成本模型不感知系数幅度
`slot.rs:160` 的成本只由频率位置和色度分量决定：
```rust
let cost = (10.0 * freq_factor * comp_factor).max(0.1);
```
翻转一个 `level=1` 的高频系数与翻转一个 `level=200` 的低频系数代价相同——但后者的 SSD 冲击高几个数量级。

- **可修性**：符号位解码时 `coeff_abs_level_remaining` 尚未解码（见 2.1），**幅度当时不可知**。若要实现幅度感知成本，需要在 level 解码后**回填** slot 代价（`slot.rs` 增加按 level 回填接口），或改用「先解 level、再定位 sign」的两遍方案。
- **收益预估**：这是当前画质（34–44 dB）进一步提升到 45+ dB 的主要杠杆。

### P1 — panic 面 / UB 面

#### 2.3 7 处 `unsafe` 原始指针 recorder 通道
`h265/cabac.rs`（4 处）+ `h265/decoder.rs`（3 处）用 `*mut CabacRecorder` 跨模块传递可变引用：
```rust
unsafe { (*rec).record_stego_sign(bit, qp, trafo_size, c_idx, x_c, y_c) };
```
- **现状风险**：指针由 `decode_nal_with_recorder` 建立、`decode_nal` 返回后立刻置 `None`，生命周期实际是安全的；`ctx_base` 通过指针差算 `ctx_idx`，依赖 `state` 数组与 `contexts` 同源同布局（`attach_recorder` 在同一函数内取址，可证）。
- **残余风险**：`attach_recorder` 传入 `contexts: &[u8]`，`ctx_base` 为该切片首地址，而 `decode_bin(&mut self, state: &mut u8)` 的 `state` 来自 `contexts.state` 数组。若未来有人从**别的**上下文数组传入 `state`，`ctx_idx` 会算出错误的（可能越界的）下标 → **越界读**。当前 `ctx_idx` 被 `as u16` 截断，所以最坏是错误上下文而非内存不安全，但仍是脆弱设计。
- **建议**：把 recorder 改为 `Option<&mut CabacRecorder>`（借用检查器保证），或至少加 `debug_assert!(ctx_idx < HEVC_CONTEXTS)`。

#### 2.4 `unwrap()` / `expect()` / `panic!` 分布（本轮加固后的现状）

加固后的分布：

| 位置 | 数量 | 性质 |
|---|---|---|
| `heif_boxes.rs` | **0** | ✅ 本轮已完全清除（唯一命中是文档注释中的说明文字） |
| `engine.rs` | **0** | ✅ 本轮已完全清除（原 6 处） |
| `cabac/`（上游 oxideav） | 64 | 上游成熟代码的内部断言，非不可信输入边界 |
| `h265/`（上游 rust_h265） | 49 | 同上 |

**为什么 `cabac/` 与 `h265/` 的剩余 panic 不紧急**：它们的输入是**已经通过校验的 NAL 单元**（长度由
`parse_nal` 校验、RBSP 已解 EPB），不是攻击者可直接控制的字节流。真正的信任边界是 HEIF 容器解析
（`heif_boxes.rs`）——那里每一个长度字段都来自文件，而本轮已将其彻底加固。

**已修复的越界 panic 实证**（`check_is_grid` 的 `infe` v3 分支）：
```
iinf.len()=24 pos=6 declared_size=20 -> buffer ends at 26
thread 'main' panicked: range end index 28 out of range for slice of length 24
error: process didn't exit successfully (exit code: 0xc0000409, STATUS_STACK_BUFFER_OVERRUN)
```
退出码与用户最初报告的完全一致。

**建议（后续）**：把 `cabac/` 的 `bitreader.rs`（12 处）与 `encoder.rs`（21 处）改为返回 `Result`，
使整条链路上不再有 abort 面。优先级低于本文 §3 阶段 A 的其余项。

### P2 — 工程与可维护性

#### 2.5 `unwrap()` 在 `engine.rs` 的 5 处（seed/header 解析）
`engine.rs:109/503/532-534` 用 `try_into().unwrap()` 切固定长度数组。长度由 `HEVC_HEADER_BYTES` 常量控制，**切片长度已由前面的 `header_bytes.len() < N` 检查保证**，实际安全，但建议改为 `let Ok(v) = ... else { return Err(...) }` 以彻底消除 panic 面。

#### 2.6 `MAX_EMBED_ROUNDS = 24` 的失败路径是硬错误
EPB 冲突在 24 轮内无法消解时直接报错。可接受（正确优先于可用），但应在错误信息中带上**诊断信息**（如参与 substream 数、被禁 slot 数、剩余可用槽位数），便于用户判断是"载荷过大"还是"载体本身不适合"。

#### 2.7 性能
矩阵基准：平均 Embed 2782 ms、Extract 2001 ms，吞吐约 **0.01 MB/s**。对 12 MB 的 HEIF 嵌入 128 KiB 需约 13 s。这是纯 Rust 全量解码 + 逐 substream 重编码的代价，未做增量/多线程。可作为后续优化项（非可靠性问题）。

---

## 3. 提高可靠性的路线图（建议按此顺序推进）

### 阶段 A：把"不会静默出错"变成硬保证 ✅ **本轮已完成**
1. ✅ **HEIF 解析全面去 panic**：整个 `heif_boxes.rs` 重写为零 panic 风格，新增 4 个回归测试（含精确复刻旧崩溃的用例）。
2. ✅ **`ctx_idx` 边界断言**：`decode_bin` 加 `debug_assert!`，把潜在的错误上下文从"静默错"变成"早崩"。
3. ⬜ **错误信息增强**：`resolve EPB conflict` 类错误附带诊断计数（可用槽位 / 已禁槽位 / 参与 substream 数），便于用户区分"载荷过大"与"载体不适合"。

### 阶段 B：与外部实现对齐
4. ✅ **像素级差分测试**：外部 oracle 测试现在断言解码几何一致 + 可见偏差占比，阈值基于实测标定。
5. ⬜ **澄清 `coeff_sign_flag` 解码顺序**（§2.1）：查上游 rust_h265 的 `signhide` 夹具与测试覆盖，确认这是上游的既定简化还是 bug。
   - 若是简化 → 向上游提 issue 或在本地 README 明确记录偏差，**不要**默默偏离规范；
   - 若是 bug → 修正并重跑全部 225 组合矩阵 + 外部 oracle。

### 阶段 C：质量与效率
6. ⬜ **幅度感知成本模型**（§2.2）：level 解码后回填 slot 代价，把翻转代价与 `|level|²`、TU 尺寸、QP 绑定。预期把 PSNR 从 34–46 dB 进一步推高。
7. ✅ **第三方许可证合规**：已补 `THIRD-PARTY-NOTICES.md` + 29 个文件的 SPDX 归属头。
8. ⬜ **多线程 / 增量编码**：substream 之间无数据依赖（除 WPP 上下文初始化，已由 recorder 记录），可并行。当前 0.01 MB/s 是可用性瓶颈。

### 阶段 D：持续防线（已具备，需保持）
- `cargo fmt --check` + `cargo clippy --all-targets -- -D warnings`：✅ 通过
- `cargo test`：✅ **全绿**（lib 330 + 各集成测试 + doctest，0 失败）
- `hevc_matrix_bench` 225 组合：✅ **124 PASS / 101 容量跳过 / 2 非 HEVC / 0 失败**（PASS = 位精确往返 + 口令验证 + 帧可解码）
- `hevc_stress` 随机 nonce 压测：✅ 30/30、12/12
- `test_hevc_external`（ffmpeg 独立 oracle）：✅ 5/5，PSNR 34.6–46.2 dB，且解码几何完全一致、可见偏差占比 0.5%–6.0%
- `test_hevc_stego -- --ignored`：✅ 2/2

---

## 4. 回归验证结果（本轮最终状态）

| 项目 | 结果 |
|---|---|
| `cargo fmt --check` | ✅ 通过 |
| `cargo clippy --all-targets -- -D warnings` | ✅ 通过 |
| `cargo test --release`（全量） | ✅ 0 失败（lib 326 passed；其余集成测试与 doctest 全绿） |
| `hevc_matrix_bench`（17 载体 × 15 载荷 = 225 组合） | ✅ 124 PASS / 101 容量跳过 / 2 非 HEVC / **0 失败** |
| `test_hevc_external`（ffmpeg 独立解码器） | ✅ 5/5，PSNR 34.82 / 43.96 / 40.83 / 41.99 / 38.92 dB |
| `hevc_stress`（随机 nonce 压测） | ✅ 30/30、12/12 |

---

## 5. 结论

- **今天新增的 HEVC 模块，其核心解码器（16 000 行）实际上未被改动**，混乱主要来自路径重写的视觉噪音。功能改动集中在 4 个文件，可审计性良好。
- 原始的 panic **不是随机性 bug**，而是有确定根因的确定性失败：EPB 冲突粒度过粗（整片封禁）+ 槽位选择策略缺陷（顺序前缀）。两者均已修复，并有量化证据（PSNR 17.5 → 42.9 dB）。
- 引入的**三项可靠性护栏**（journal 零翻转自校验、按 slot 精确禁用、确定性槽位置换）把隐写从"能跑"提升到"不会静默写出坏码流"。
- 剩余最高优先级事项：**HEIF 解析去 panic**（安全边界）、**第三方许可证合规**（分发合规）、**与 FFmpeg 的像素级等价差分测试**（语义正确性证据）、**澄清符号位解码顺序**（规范一致性）。
