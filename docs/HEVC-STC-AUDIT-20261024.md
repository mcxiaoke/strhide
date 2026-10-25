# HEVC / STC 代码审查报告

- 日期：2026-10-25 00:28:56
- 范围：`rust/src/stego/hevc/**`、`rust/src/stego/coding/stc.rs`、`rust/src/stego/heif/thumb_bridge.rs`
- 方式：源码逐行走查 + 临时审计测试实证（已删除，未改动任何生产代码）
- 环境验证：`cargo clippy --all-targets` 无告警；工作区 `git status` 干净

---

## 0. 结论摘要

| 模块 | 结论 |
| :--- | :--- |
| STC 算法内核 (`coding/stc.rs`) | **算法正确且达到最优**（实证通过），但有 2 个真实缺陷 |
| HEVC 引擎 (`hevc/engine.rs`) | **主路径可用**（零膨胀、往返、错误口令均通过），但有 3 个 Major 级缺陷 |
| `heif_boxes.rs` | **ISOBMFF 语义层有 2 个 Critical**（会破坏宿主文件 / DoS） |
| `heif/thumb_bridge.rs` | **有 3 个 Critical**，其中 1 个与同仓写入端自相矛盾 |

**最应该优先修的 5 项**：

1. `probe_hevc_capacity` 容量虚报 1 字节（14 个语料文件命中 9 个，64%）— P1
2. `heif_boxes.rs` 未解析 `construction_method` → idat 项偏移被当文件偏移，会写坏宿主文件 — P1
3. `thumb_bridge.rs` 多 extent 时 `delta` 被重复施加 N 次 → 容器长度声明与实际不符 — P1
4. `thumb_bridge.rs` `iloc` v2 越界读取 → 可稳定触发 panic — P1
5. `extract_hevc` 硬编码 24/16 而非取 `fmt.header_bytes` → 私有方言 `header_bytes < 24` 时 panic — P2

---

## 1. STC 内核：`coding/stc.rs`

### 1.1 实证结论：算法正确、最优

我写了独立审计测试（遍历 2^n 个校验子向量的穷举 oracle，与 trellis 无任何共用代码），在 HEVC 实际使用的 `(h=7,u=2)`、`(8,2)`、`(7,3)`、`(8,1)`、`(4,2)` 上全部通过：

- 达到代价 == 穷举最优（误差 < 1e-9） ✅
- 全部矩阵行（**含 h-1 个预热行**）满足 `H x = m` ✅
- 被禁用槽位（cost = INFINITY）**从未**被翻转 ✅
- embed → extract 往返一致 ✅
- 列向量推导与实现一致（交叉校验通过）✅

手工推导也一致：前向 `dest = src ^ (parity ? col_mask : 0)`，回溯求逆在累积列与判决列两条路径上均严格互逆；AVX2 内核的 `vpermq` 换道与收窄路径的边界（`states` 为 2 的幂且 ≥16，索引均为 4 的倍数）安全。

> 结论：STC 本身**没有算法错误**。`cargo clippy --all-targets` 亦无告警。

### 1.2 [Major] 槽位被排除时 STC 直接不可行 —— HEVC 继承了这一硬约束

`embed_hevc` 用「给槽位打 INFINITY 代价」来排除 EPB 冲突槽与不健全子流。但一旦某组的 u 个元素全被禁用，该组的行校验子就失去自由度，整条 trellis 塌缩成 INFINITY → `TrellisInfeasible`，**且无任何恢复路径**（round 0 失败即直接返回 Err）。

实测（h=7,u=2，n=492，随机消息 240 bit）：

| 被排除比例 | 散布式失败率 | 聚集式（连续段）失败率 |
| :--- | :--- | :--- |
| 5% | 0/20 | **20/20** |
| 10% | 1/20 | **20/20** |
| 20% | **6/20 (30%)** | **20/20** |
| 30% | **8/20 (40%)** | **20/20** |
| 50% | 19/20 | 20/20 |

- HEVC 排除的是「整条子流」，在 **slot 池中是连续的**，但 Weyl 置换会把它们打散到置换空间，所以实际更接近「散布式」一栏。
- 即：一个 WPP 载体若有 20%~30% 的槽位落在不健全子流里，嵌入**有 30%~40% 概率直接失败**。
- 若上游（如某个容器把禁用位置连续排列）落到「聚集式」，5% 排除即 100% 失败。

**建议**：把「排除」改成「改排列」——不健全子流不要用 INFINITY 打，而是让 `slot_positions` 在生成时跳过它们（两端都只依赖 `total_slots` 与 pool 顺序，可保持一致），这样被使用的 u 元组永远可用。或按组粒度（u 个一组）整体排除，而不是按单个槽位排除。

### 1.3 [Major] 穷举 oracle 本身有 off-by-one，最优性保证只测了一半消息空间

`stego/coding/stc.rs:939-947`：

```rust
let want = if row + 1 > h {
    message_bit(self.message, row - (h - 1))
} else { 0 };
```

而 embedder（`stc.rs:658-663`、`:764-769`）对组 `g` 取 `row = g - (h-1)`，`row >= 0` 时取消息位 —— 即**消息位 0 位于第 `h-1` 行**。

两者差 1 行：oracle 强制第 `h-1` 行的校验子为 0，embedder 则把它置为消息位 0。

该测试之所以通过，只是因为它唯一的消息字节是 `0x5A`（MSB = 0），即消息位 0 恰好为 0。若把测试消息换成首 bit 为 1 的常量，oracle 的可行集为空 → 返回 INFINITY → 断言 `(achieved - optimum).abs() < 1e-9` 直接失败。

**影响**：`embed_matches_exhaustive_optimum_and_round_trips` 是最优性的唯一看门人，而它实际只在「消息位 0 == 0」这半个空间里成立。改任何一个测试常量就会假失败，掩盖真实回归。

**修法**：`row + 1 > h` → `row + 1 >= h`。

### 1.4 [Minor] 热路径里有 27 行不可达代码

`transfer_column` 的 `u = 1` 分支（`stc.rs:287-313`）与调用点 `transfer_column::<true, false>`（`:679`）**永远不会执行**：`u == 1` 在 `:549` 已经提前返回，而 `<false, _>` 只可能在 `u > 1` 时到达。

**影响**：最热的函数里带着一段永不执行且从未被测试覆盖的分支，还拖着 `parity_bit` 参数。建议删除并把 `transfer_column` 收敛为 `<DECIDE, true>` 两个实例。

### 1.5 [Minor] `from_seed_grouped` 的 O(u²) 去重

`stc.rs:360` 的 `cols.contains(&col)` 在重试循环里线性扫描。u ≤ 64 时绝对耗时可忽略，但 `(u, h)` 组合使 `distinct_patterns = 2^(h-2)` 很小时（如 h=4 → 4 个可用模式）会多绕几圈。量级可忽略，属可选项。

---

## 2. HEVC 引擎：`hevc/engine.rs`

### 2.0 实证结论：主路径契约成立

对 `temp/testhevc` 全部 20 个文件端到端跑通（25% 容量、口令 "pw"）：

- 输出长度 == 输入长度（零膨胀成立）✅
- 往返一致 ✅
- 错误口令一律失败（无 oracle 泄漏）✅

### 2.1 [Major] `probe_hevc_capacity` 容量虚报 1 字节（14 个语料命中 9 个）

`hevc/engine.rs:100-112`：

```rust
let available_bits = (total_slots / 2).saturating_sub(header_bits);
Ok(available_bits / 8)
```

而 `slots_for(bits) = u * (bits + h - 1)`。正确的上界应是其逆 `message_bits(n) = n/u - h + 1`：

```
可用消息位 = total_slots/u - (h-1) - header_bits
```

现实现**同时**犯了两个错：把码率 1/2 写死（忽略 `u`），且漏掉了 `h-1` 个预热行。对 `DEFAULT_HEVC_FORMAT`（u=2, h=7）净效果是高估 6 bit，进位后正好虚报 1 字节。

实测（每个文件都按 probe 报告的容量去嵌）：

```
IMG_1133.HEIC        cap=373505  →  EMBED-ERR  needed 5976732, available 5976722  (仅 373504 可嵌)
IMG_1904.HEIC        cap=51292   →  拒绝，51291 可嵌
IMG_20261016_115109  cap=140160  →  拒绝，140159 可嵌
IMG_20261018_113710  cap=121274  →  拒绝，121273 可嵌
IMG_4381.HEIC        cap=210314  →  拒绝，210313 可嵌
IMG_5887.HEIC        cap=8980    →  拒绝，8979 可嵌
IMG_7547.HEIC        cap=297056  →  拒绝，297055 可嵌
IMG_9052.HEIC        cap=250872  →  拒绝，250871 可嵌
test.heic            cap=16619   →  拒绝，16618 可嵌
```

**影响**：`capacity` 子命令与 `--dry-run` 报告「能嵌 N 字节」，用户照着嵌 N 字节却被拒。命中率 9/14（64%）——因为虚报 6 bit 是否跨过字节边界取决于 `total_slots` 的奇偶。

**修法**：直接用现成的逆函数，顺带修好 `u` 硬编码：

```rust
let cap_bits = trellis.message_bits(total_slots).saturating_sub(fmt.header_bytes * 8);
Ok(cap_bits / 8)
```

### 2.2 [Major] `extract_hevc` 硬编码 24/16，且 `header_bytes` 的语义是错的

`hevc/engine.rs:639-666`：

```rust
let total_msg_len = 24usize.checked_add(payload_len).and_then(|v| v.checked_add(16))...;
let ciphertext = &msg_bytes[24..total_msg_len];
```

而 `DEFAULT_HEVC_FORMAT.header_bytes == 40`（`format.rs:216`），注释写的是「magic 4 + len 4 + crc 4 + nonce 12 + tag 16 = 40」。

真实线上布局是：embedder 只写 **24** 字节头（magic+len+crc+nonce，`:161-166`），tag 在**消息末尾**而非 24..40。所以：

- 「40」实际 = 24 字节真头 + 顺带多读的 16 字节密文（被丢弃）。功能上侥幸自洽。
- 但 `24` 与 `16` 是**硬编码**，与 `fmt.header_bytes` 无关。`format.rs` 的方言文档却写 `header_bytes` → 「different fixed header size」——这是假的：改它只改「偷看长度」，不改真实头长。
- **私有方言若设 `header_bytes < 24`，`header_bytes[12..24]` 直接 slice 越界 panic**（`:637`）。

**修法**：从 `fmt` 派生常量（`HEADER = 24`、`TAG = 16` 提升为 `HevcFormatProfile` 字段，或至少把 `header_bytes` 定义成它真正的含义），并在 `:614` 之前按 `>= 24` 校验。

### 2.3 [Major] MP4 被嗅探认下，却完全没有实现

`sniff.rs:41` 会把 `.mp4/.mov` 认成 `HevcCarrierKind::Mp4Container`，但 `engine.rs:801-805` 的 `_ =>` 分支直接返回 `UnsupportedFormat`。实测：

```
VID_20250228_120825_C.mp4  PROBE-ERR Carrier format not supported yet for HEVC stego
VID_20261002_154545.mp4    PROBE-ERR 同上
VID_20261007_203536.mp4    PROBE-ERR 同上
```

**影响**：嗅探层对外宣称支持，能力层不兑现；`probe_hevc_capacity` 对 MP4 抛错而不是返回 0。要么实现（复用 `bitstream.rs` 里现成但已死的 `parse_hvcc_spans`），要么在 `sniff_hevc_carrier` 里就别认 MP4。

### 2.4 [Major] 每条子流每轮被 CABAC 重编码两次

- `engine.rs:259-265`（3a，日志保真）：`encode_substream(slice_rec, sub, &[])`
- `engine.rs:309-342`（3b，实际重编码）：`encode_substream(slice_rec, sub, &flipped_ops)`

3a 检查的正是 3b 之后要重编码的那一批子流，等于把最热的 CABAC 重编码做了两遍（1 倍冗余）。3a 结果可缓存（`replay_ok` 已有 HashMap，但缓存的是 bool 而非编码产物），或直接把 3a 并入 3b 的长度/内容校验。

### 2.5 [Major] 每次嵌入/提取都把整个容器解析两遍

- `record_carrier_state` 内部：`parse_heif_targets(carrier)`（HEIF）或 `parse_annex_b_spans(carrier)`（AnnexB）
- `derive_carrier_digest` 内部：又一次 `parse_heif_targets` / `parse_annex_b_spans`

`embed_hevc` 与 `extract_hevc` 都同时调用两者 → 对 HEIF 是两次完整 ISOBMFF 遍历。实测单次 probe 0.45~0.78 s、单次 embed 0.7~1.5 s（1~3 MB 文件），其中相当一部分是重复解析。

**修法**：`derive_carrier_digest` 接受已解析结果（`HeifHevcTarget` / `spans`）而非原始 `carrier`。

### 2.6 [Minor] 其他

| 位置 | 问题 |
| :--- | :--- |
| `engine.rs:161` | `Vec::with_capacity(20 + ciphertext.len())` 但要 push 24 字节 → 必然 realloc |
| `engine.rs:292-299` | op → 子流的定位是线性扫描，O(\|op_indices\| × \|substreams\|)；子流有序，可二分 |
| `engine.rs:442` | `conflicts[0]` 无空判断。当前不可达（不健全子流会先 `continue`），但很脆，建议改 `conflicts.first()` |
| `engine.rs:465` | `ContextModel::init(154, 26)` 建的默认值随后被 `init_contexts` 全覆盖，是无效初始化 |

---

## 3. `hevc/bitstream.rs`

### 3.1 [Minor] 两个仅供自测的死函数

- `is_epb_safe_flip`（`:142`，35 行 + 1 个测试）：全仓仅被自己的测试调用。它是被「日志重放 + EPB 窗口比对」方案取代的旧 EPB 思路的遗留。
- `parse_hvcc_spans`（`:93`）：同样仅被自己的测试调用。讽刺的是，修 2.3 的 MP4 支持正好需要它。

建议：删 `is_epb_safe_flip`（旧方案遗留，与新设计语义不兼容，留着会误导）；`parse_hvcc_spans` 要么用起来（支持 MP4）要么也删。

### 3.2 [Minor] `HevcError` 有 8/10 的变体从未被构造

实测各变体在 `stego/hevc/` 内的构造点数量：

| 变体 | 构造点 | 变体 | 构造点 |
| :--- | :--- | :--- | :--- |
| `Truncated` | 多 | `MissingParameterSet` | **0** |
| `InvalidData` | 多 | `Unsupported` | **0** |
| `ContainerMalformed` | 7 | `TooLarge` | **0** |
| `NoSlices` | 1 | `MissingBox` | **0** |
| | | `BoxTooLarge` | **0** |
| | | `MissingItem` | **0** |
| | | `CyclicDerivation` | **0** |
| | | `Malformed` | **0** |

这些变体是为「iloc 环检测 / 缺项 / 超大盒」准备的守卫，但对应的守卫代码还没写。

---

## 4. `hevc/heif_boxes.rs`（Critical 级）

以下 4 条我已亲自读到源码核实。

### 4.1 [Critical] `construction_method` 完全未解析 → idat 项偏移被当文件偏移

`heif_boxes.rs:500-502`：

```rust
if version >= 1 {
    pos += 2; // construction_method     ← 位置跳过了，值从未读出
}
```

接着 `:527` 无条件 `base_offset + ext_offset` 当文件绝对偏移。而 `construction_method == 1` 时 extent_offset 是相对 `idat` 盒载荷的，`== 2` 时相对另一个 item —— 两者都被当成文件偏移。

后果：拿到错误的 slice 字节区间交给 `engine.rs:732` 做 CABAC 改写 → **写坏宿主文件**（且两端对称，提取「成功」但图已坏）；或误报 `Truncated`。

对照：同仓 `stego/heif/thumb_bridge.rs:755-765` 明确读出了该字段，说明项目自己承认必须区分。

### 4.2 [Critical] `iloc` 双层循环可被零推进打成 DoS

`heif_boxes.rs:518-523`：

```rust
for _ in 0..extent_count as usize {
    pos += index_size;                                        // 0
    let ext_offset = read_uint(&iloc[pos.min(iloc.len())..], offset_size);   // 0
    pos += offset_size;                                       // 0
    let ext_len = read_uint(&iloc[pos.min(iloc.len())..], length_size);      // 0
    pos += length_size;                                       // 0
    if is_target { extents.push(...); }
}
```

当 `offset_size == length_size == index_size == 0` 时内层循环**零字节推进**却执行 `extent_count`（≤65535）次；外层每 item 只推进 8 字节。总迭代 ≈ `(iloc.len()/8) × 65535`，命中时还会 push 同样多的元组。这是公开 CVE 级的 ISOBMFF DoS 模式。文件头注释自称「every malformed structure is reported as HevcError」，这里既没报错也没上界。

**修法**：进入内层前校验 `index_size + offset_size + length_size > 0`（全 0 组合按规范非法，直接 Err）；并给 `extents` 总量设上界。

### 4.3 [Major] `u64 as usize` 裸转 → 32 位平台静默截断

`heif_boxes.rs:527-528`：

```rust
extents.push(((base_offset.saturating_add(ext_offset)) as usize, ext_len as usize));
```

同文件 `:63-65` 处理 64 位盒长时已经用了 `usize::try_from(...).map_err(...)`，唯独这条真正危险的路径用裸 `as`。在 32 位目标上偏移被截断 → slice 区间指向文件头 → 写坏数据。另 `offset_size/length_size`（4 bit 字段）未校验取值必须在 {0,4,8}，取 9..15 时 `read_uint` 高位被移出，得到静默错误的偏移。

### 4.4 [Major] 未解析 `ipma`，直接取 `ipco` 里第一个 `hvcC`

`heif_boxes.rs:394-399`，全仓 grep `ipma` 零命中。多编解码器属性并存时拿到错误的 `length_size` 与 `parameter_sets`，进而 NAL 切分全错、cover digest 错。

### 4.5 [Minor] 其他

- `:159` `primary_id.unwrap_or(1)`：`pitm` 缺失时静默假定 item 1，可能拿 Exif/缩略图去切 NAL。
- `:411-437` 畸形 `hvcC` 数组全部 `break`，且 `break` 只跳出内层、外层仍按坏 `rpos` 继续 → 把 NAL 载荷字节当 array header 读进 `parameter_sets`。
- `:298-300` `check_is_grid` 只认 `infe` v2/v3，v0/v1 恒为 false。

---

## 5. `heif/thumb_bridge.rs`（Critical 级）

### 5.1 [Critical] `infe` v3 的 `item_type` 偏移错了 2 字节（已交叉验证）

`thumb_bridge.rs:711-714` 读 `[ipos+20 .. ipos+24]`。

按 ISO/IEC 14496-12，v3 布局是 `item_ID[12..16]`、`protection[16..18]`、**`item_type[18..22]`**。

同仓交叉证据 —— `adapters/isobmff.rs` 的写入端把 `item_type` 写在 `[18..22]`，且它声明的盒长 23 正好自洽：

```
4(size) + 4('infe') + 1(ver) + 3(flags) + 4(id) + 2(prot) + 4(type) + 1(null) = 23
```

后果：v3 `infe` 文件的 `item_type` 全是垃圾 → 优先级 1/2/3 全部落空 → 退化到全文件扫描。另 `:712` 的守卫 `infe_sz >= 24` 过严（最小合法 v3 infe 是 23）。

### 5.2 [Critical] 目标 item 有多个 extent 时 `delta` 被重复施加 N 次（已核实）

`thumb_bridge.rs:296-303`：

```rust
if is_target_item {
    for ext in &item.extents {
        if ext.length_sz > 0 && ... {
            let new_extent_len = ((ext.length as i64) + delta).max(0) as u64;
            patch_uint(&mut out, ext.length_pos, ext.length_sz, new_extent_len)?;
        }
    }
}
```

被改的只有 `[file_offset, +length)` 这一段，总长变化只应是 1 次 `delta`。代码对**每个** extent 都 `+delta`，且从未校验该 extent 是否就是被替换的那一个（`ext.offset` 未与 `target.file_offset` 比对）。结果：声明总长 = `Σlen_i + N·delta`，实际只变了 `delta` → 容器静默损坏。

### 5.3 [Critical] 未解析 `pitm`/`iref`/`thmb` → 可能把主图当缩略图载体

`parse_isobmff`（`:645-817`）从不读 `pitm` 与 `iref`。`find_bridge_target`（`:396-451`）的优先级 1 是「找第一个 `item_type == jpeg` 且有 extent 的 item」，无法排除 `pitm` 指向的主图、也无法优先 `thmb` 引用的缩略图。

这与模块文档 `:6`「The primary HEVC/AVIF photo stream remains 100% bit-exact and untouched」的契约正面冲突，且失败是静默的。

### 5.4 [Major] `iloc` v2 在 `>= 16` 守卫下读 `[14..18]` → 可稳定 panic（已核实）

`thumb_bridge.rs:723-740`：

```rust
if iloc_buf.len() >= 16 {
    ...
    let item_cnt = if iloc_ver < 2 {
        u16::from_be_bytes(iloc_buf[14..16]...)   // 需 len >= 16 ✓
    } else {
        u32::from_be_bytes(iloc_buf[14..18]...)   // 需 len >= 18，但守卫只保证 >= 16 ✗
    };
```

16 或 17 字节的 `iloc` 盒 + version ≥ 2 → `index out of bounds` panic，而不是返回 `Err`。这是处理不可信输入时直接 abort。

### 5.5 [Major] 其他

| 位置 | 问题 |
| :--- | :--- |
| `:287-324` | 补丁位置用「原文件坐标」写入，未做位移重映射（被改区之后的所有字节已平移 `delta`）→ `meta`/`iloc` 在修改区之后时补丁写错位置 |
| `:326-342` | 只 patch 顶层盒，`idat`/`iloc`/`iinf` 等 meta 子盒尺寸永不更新 |
| `:608-635` | `fallback_scan_jpeg` 每命中一个 SOI 就线性扫到文件尾找 EOI，找不到时不推进 → O(n²) |
| `:114-134` | `DirectSpatial` 把 `unci` 原始像素喂给 PNG 引擎，而 `png::embed_png` 首行就校验 PNG 签名 → 该分支必然失败 |
| `:300/307/330` | `.max(0)` 静默钳位而非报错；`as i64` 对 > i64::MAX 的 u64 会回绕 |
| `:400-402` | `item.base_offset + ext.offset`（u64）与 `start + len`（usize）均为无检查加法 |

---

## 6. 验证方法说明

- 生产代码**未做任何改动**，审计用的两个临时测试（`tests/tmp_audit_stc.rs`、`tests/tmp_audit_hevc.rs`）已删除，`git status` 干净。
- 所有「Critical / Major」条目中，2.1、3.2、4.1、4.2、4.3、5.1、5.2、5.4 由我亲自读源码 + 实测核实；5.3、5.5 其余条目来自子代理报告，未逐条复核。
- 1.1 的 STC 正确性结论基于独立穷举 oracle，不是基于仓库自带测试。

## 7. 建议的修复顺序

1. `probe_hevc_capacity` 改用 `message_bits`（2.1）
2. `heif_boxes.rs` `construction_method` + `iloc` 循环上界（4.1、4.2）
3. `thumb_bridge.rs` 多 extent 的 delta、iloc v2 越界、`infe` v3 偏移（5.1、5.2、5.4）
4. `extract_hevc` 的 24/16 硬编码（2.2）
5. STC oracle off-by-one + 删除不可达分支（1.3、1.4）
6. HEVC 的两次解析 / 两次重编码（2.4、2.5）
7. MP4 要么实现要么别嗅探（2.3）
