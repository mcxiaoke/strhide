# pe_slack Mode 2（跨 padding 分段）设计与可靠性评估

> 文档编号：STRHIDE-DOC-20261019-03
> 状态：方案评估（**未实现，本文不含代码改动**）
> 关联文档：`pe_slack_strategy_proposal.md`（Mode 1 已落地）、`pe_codebits_plugin_design.md`、`pe_codebits_chunked_diff_design.md`
> 实测脚本：`temp/pe_slack_mode2_probe.py`（只读，不属于构建）

---

## 1. 结论

**建议实现，但只实现"确定性槽位索引"这一种形态，不引入分块描述表之外的任何协商逻辑。**

理由来自实测（`temp/testapps` 真实 PE，2026-10-19）：

| 载体 | codebits ≤ | Mode 1 ≤ | Mode 2 预估 ≤ | Mode 2 / Mode 1 |
|---|---|---|---|---|
| `clink_x64.exe` | 0 | 488 | 1,724 | 3.5× |
| `perl.exe` | 17 | 496 | 2,728 | 5.5× |
| `Encode.xs.dll` | 267 | 496 | 2,608 | 5.3× |
| `Storable.xs.dll` | 482 | 496 | 2,916 | 5.9× |
| `Associate files…exe` | 165 | 336 | 1,295 | 3.9× |
| `qtiff.dll` | 365 | 379 | 1,592 | 4.2× |
| `AcmVorbis64.dll` | 418 | 432 | 1,662 | 3.8× |
| `libdav1d.dll` | 378 | 392 | 1,088 | 2.8× |
| `Qt5Widgets.dll` | 442 | 456 | 1,985 | 4.4× |
| `mpcresources.sv.dll` | 0 | 488 | 1,248 | 2.6× |

两条关键事实：

1. **Mode 1 的容量几乎等于 codebits**。codebits 的 slack 需求是 `14 + ube`（要停放还原 diff），Mode 1 是 `ube`（信封原地写入），两者都受"最长单段零 run"约束，所以 `mode1_cap = codebits_cap + 14`——表格里 `379/365`、`432/418`、`392/378`、`456/442`、`496/482` 全部精确差 14 字节。例外是 `.text` 指令位不足（`perl.exe` 只有 17 B）或非 x86 架构。
2. **padding 总量是单段最大值的 2.6–5.9 倍**，因为每个节的尾部对齐填充被节数据隔开，天然碎片化。Mode 2 把这部分用起来才是这个策略真正的价值；只做 Mode 1 时，`auto` 几乎永远轮不到它（仅在 codebits 被 `.text` 位密度卡死或架构不支持时才生效）。

---

## 2. 目标与不变量

Mode 2 是把**逻辑信封**切段写进多个零 run。任何设计都必须满足：

| 编号 | 不变量 |
|---|---|
| I1 | 只写"写入前确认为全零"的字节。每个目标区间（索引区 + 每个 chunk）写前二次校验，校验失败即整体放弃。 |
| I2 | 逻辑流与物理布局由索引**唯一确定**；索引与物理事实不一致时一律拒绝，不做"尽量修复"。 |
| I3 | 还原 = 把索引区与各 chunk 区清零，**绝不触碰区间之间的字节**（不是 `[inject_offset, inject_offset+size)` 的连续区间）。 |
| I4 | 文件尺寸严格不变，不追加、不改 PE 头（`VirtualSize`/`SizeOfRawData`/checksum 全部不动）。 |
| I5 | 索引位置只由 PE 节表派生（与文件内容无关），因此定位是 O(1)，且还原不需要口令。 |
| I6 | 所有校验都在写盘前完成；`remove` 先校验后输出，失败时不留半成品（引擎已有 tmp + rename 保证）。 |

I5 是这套设计能"可靠"的核心：**不靠 magic 扫描找索引，靠可推导的固定槽位**。

---

## 3. 候选方案与取舍

| 方案 | 做法 | 问题 |
|---|---|---|
| A. 逐段自描述帧 | 每个碎片带 `magic+seq+len+crc`（14 B/段），定位靠扫 magic | 每段都有魔数 → 静态特征面成倍增加；多封信封时碎片会混在一起；仍要两遍扫描 |
| B. 头部索引 + 任意位置 | 索引放任意 run，头部记录索引偏移 | 偏移要么写进 `inject_offset`（被引擎用来打 header 补丁，冲突）、要么滥用 `patch_offset`；stealth 下 strip 拿不到口令、也拿不到等价锚点 |
| C. 从节表推导布局 | 完全不存索引，读时按 headers 重算切分 | 不可行：写入后用来判断"哪段是零 run"的信息被覆盖，布局不再可推导 |
| **Z. 确定性槽位索引（选定）** | 索引固定放在**第一个 ≥16 字节的 padding range 起始处**；索引自描述长度；chunk 偏移全在索引里 | 需要 `ranges[0]` 全零且索引能装下；容量上限受槽位大小约束（实测余量充足） |

A 的方案额外开销更大且更难验证；B 会污染已有字段语义；C 有信息论上的硬伤。Z 只用 PE 头就能定位索引，restore 不需要口令，也不碰任何已有字段。

---

## 4. 方案 Z 详细设计

### 4.1 物理布局

```
PE 文件
 ├─ 头部 / 节表
 ├─ padding range #0  ← 索引槽位（固定）
 │    [ index_hdr 16B | entries 8B × N | 允许剩余零字节 ]
 ├─ 节数据 ...
 ├─ padding range #1  ← chunk k（整段或前缀）
 ├─ 节数据 ...
 ├─ padding range #2  ← chunk k+1
 └─ ...
```

- **槽位定义**：`slot = 第一个长度 ≥ 16 的 padding range`（`slack_ranges()` 输出，纯 header 派生）。要求该 range 全零，否则 Mode 2 不可用。
- **chunk**：每个 chunk 是某个零 run 的前缀（长度由索引记录），首尾都落在该 run 内。
- **chunk 0 必须是逻辑流的开头**，且所在 run 长度 ≥ 112，因为引擎会把 112 字节 header 补丁打在 `inject_offset`（= chunk 0 起点）上。

### 4.2 索引格式（小端）

| 偏移 | 字段 | 说明 |
|---|---|---|
| 0 | `magic[4]` | `mix4(header_magic)`：标准模式是固定常量，stealth 模式随口令派生（避免固定签名被 `scan`/AV 直接识别） |
| 4 | `version u8` | 1 |
| 5 | `flags u8` | 0（保留） |
| 6 | `chunk_count u16` | 1..=N，且 `16 + 8*N ≤ slot.len` |
| 8 | `ube_total_size u32` | 逻辑信封总长（与 trailer 交叉校验） |
| 12 | `crc32 u32` | 覆盖 `[0..12)` + 全部 entries |
| 16 | `entries[N] = {offset u32, len u32}` | 物理偏移与长度，按逻辑顺序排列（同时要求物理递增） |

u32 偏移是安全的：PE 的 `PointerToRawData` 本身就是 u32，padding 永远落在 4 GiB 以内；超过 4 GiB 的只有文件尾 overlay，而本策略从不写那里。

索引长度 `16 + 8*N` 由 `chunk_count` 自描述：读端先读 16 字节拿到 N，再读 entries，再做 CRC——不存在"要先知道长度才能读索引"的循环依赖。

### 4.3 规划算法（写端与容量报告共用同一个纯函数）

```text
plan(ranges, ube_len) -> Option<Plan>:
  slot := 第一个 len >= 16 的 range; 不存在 -> None
  slot 不全零                                                  -> None   # I1
  runs := 全部零 run（文件顺序）; 槽位自身算一个 run
  n_cap := min(MAX_CHUNKS, (slot.len - 16) / 8)

  outside := 槽位之外的 run（整段）
  n_max := min(#outside, n_cap)
  若 slot.len > 16 + 8*(n_max + 1):
      n_max += 1          # 槽位剩余部分也作为一个段（留出 1 字节以上数据）
  index_reserve := 16 + 8 * n_max          # 上界预留，避免"索引长度依赖段数"的循环

  segs := outside + [slot.start + index_reserve, slot.end)
          按文件顺序排列，丢弃空段
  若不存在 len >= 112 的段                                  -> None   # chunk 0 要放 header
  若 sum(len(segs)) < ube_len                                -> None

  chunk0 := 文件顺序第一个 len >= 112 的段
  chunks := chunk0 先装满，其余段按文件顺序贪心装满 ube_len
  返回 Plan { index_off = slot.start, index_reserve,
              chunks, index_len = 16 + 8 * len(chunks) }
```

要点：

- **槽位剩余段的起点用 `index_reserve`（上界）而不是实际 `index_len`**，这样"段的位置"不依赖最终段数，彻底避免循环依赖。实际索引比预留短时，中间那几十字节保持原样（本来就是零），还原时也无需处理。
- 函数只依赖 `(ranges, 零 run 几何, ube_len)`，不依赖别的状态 → `choose_auto_strategy`、`inspect`、`inject` 三处结果必然一致（TOCTOU 由写前零校验兜底）。
- 段之间**按文件顺序**排列，chunk 0 先取第一个 ≥112 的段：header 落在靠前位置，便于人工核对。
- `MAX_CHUNKS` 建议 32：索引上界 272 B，真实载体的 padding range 通常 3–15 个，远超需求。

### 4.4 写入

1. `plan()` 得到布局；失败则按“Mode 1 → 报错（提示 overlay）”降级。
2. 对**每个**目标区间（索引区 + 每个 chunk）流式复读，确认全零；任一非零 → `UnsupportedFormat`，不产出任何文件（I1）。
3. 流式拷贝宿主，在对应偏移处替换为信封的相应片段（索引区写索引，chunk 写逻辑流切片）。
4. 返回 `(chunk0.off, total, 0, 0)`，引擎据此：
   - 在 `chunk0.off` 打 112 字节 header 补丁（正确）；
   - trailer 补丁位置由新增钩子给出 `last_chunk_end - 24`（见 §4.7）。

### 4.5 定位（locate）

```text
1. slot := 第一个 len>=16 的 range（header 派生，O(1)）
2. 读 16B 索引头：magic / version / flags / count / total / crc
3. 校验 1 <= count 且 16 + 8*count <= slot.len；读 entries，校验 CRC32
4. 逐条校验：len>0；[off, off+len) 完全落在某个 padding range 内；
   物理偏移严格递增、互不重叠、不覆盖索引区；sum(len) == total；
   total >= MIN_UBE_PLAIN 且 <= host_size
5. chunk0 处校验 header magic（标准模式要求 standard/legacy；stealth 跳过，
   由第 6 步的口令派生 trailer 兜住）
6. 最后一个 chunk 末尾 24B 必须是 trailer：用 expected_trailer_magic 解包成功、
   total 一致、且位置 == last_chunk.off + last_len - 24
7. 返回 (chunk0.off, total, "pe_slack")
```

任一条不满足即 `None`（对 `read` 就是“没有隐藏数据”），并回落到 Mode 1 的 trailer 扫描，保证已写入的 Mode 1 文件仍可读。

### 4.6 读取与还原

- `open_ube_reader(chunk0.off, total)`：在 slot 读到有效索引且 `entries[0].off == chunk0.off && total` 一致 → 返回**跨段虚拟流**（顺序遍历 chunks，逻辑偏移映射到物理偏移）；否则退回连续 `SubStream`（Mode 1）。引擎其余逻辑（header 校验、L3 解密、payload SHA）完全复用。
- `strip`：`header.strategy_id == 9` 时按下列顺序判定，**不猜**：
  1. 若 slot 解析出有效索引，且 `header.inject_offset == entries[0].off`、`header.inject_size == total` → Mode 2：逐个复核 chunk 落在 padding 内，然后一次性流式拷贝，把**索引区与每个 chunk 区**替换为零（多区间 patch，绝不清零间隙）。
  2. 否则，若 `[inject_offset, inject_offset+inject_size)` **完整落在单个 padding range 内**（即 Mode 1 的既有不变量）→ 走 Mode 1 清零。
  3. 否则 → `CorruptedData`，不写盘。

  第 2 步的区间守卫是 Mode 1/2 的机械判别器，也是防灾难的闸门：Mode 2 的逻辑跨度必然跨过至少一个非 padding 间隙（否则等价于 Mode 1，写入时就会选 Mode 1），所以**索引损坏的 Mode 2 文件不可能误入 Mode 1 的连续清零**，不会把节数据清掉。

### 4.7 需要的最小引擎改动（唯一一处）

引擎目前按 `actual_ube_offset + ube_total_size - 24` 打 trailer 补丁，这个公式对非连续布局不成立（末 chunk 之前的间隙让物理跨度 > 逻辑长度）。**不能**改 `inject_offset` 去凑：那会把 112 字节 header 打到别处。

建议新增一个带默认实现的 trait 钩子（约 10 行）：

```rust
/// 引擎写入最终 trailer 的物理位置；`None` 表示沿用默认的
/// `ube_offset + ube_total_size - 24`。非连续信封（pe_slack Mode 2）
/// 返回末 chunk 末尾 - 24。
fn trailer_patch_offset(
    &self, _stego: &mut dyn SeekRead, _ube_offset: u64, _ube_total_size: u64,
) -> Result<Option<u64>, StrHideError> { Ok(None) }
```

其余适配器全部保持默认，行为零变化；PE 实现读一次索引即可（此时索引已落盘、header 尚未补丁，索引内容已是最终值）。

替代方案（不采用）：让 Mode 2 变成"scattered"策略、由适配器自己写 header/trailer——需要新 strategy id、需要适配器重建 stealth 掩码 CRC、还要给 `strip` 加锚点参数，改动面明显更大。

### 4.8 容量与自动选择

```
mode1_cap = max(零 run 长度)
mode2_cap = plan(ranges, ube_len) 可行时的 sum(段长)（且不超过 ube_len 所需口径）
报告容量   = max(mode1_cap, mode2_cap)
实际选择   = ube <= mode1_cap ? Mode 1 : (plan 可行 ? Mode 2 : 报错)
```

- **优先 Mode 1**：单一区间、足迹最小；只有在 Mode 1 装不下时才用 Mode 2，所以小载荷不会无谓地铺开。
- `auto` 顺序保持 `pe_codebits → pe_slack → pe_overlay`（你此前的要求）。Mode 2 生效后，slack 的容量上限从"最长单段"变成"padding 总和"，才会在大载荷场景赢过 codebits。
- `inspect` 的 note 建议写成：`≤ 2,916 B (file size unchanged; 496 B in a single run, 2,916 B fragmented over 11 ranges)`，让用户能看出代价（碎片数）。

---

## 5. 可靠性论证（逐条故障/攻击路径）

| 场景 | 检测点 | 结果 |
|---|---|---|
| 索引槽位已被占用（含旧 stealth 信封） | 槽位必须全零（I1） | 拒绝写入；旧信封在其它 run 时，新信封只会落在仍为零的 run 上（与 Mode 1 同级的既有风险，由 `scan`/`suspicious_structures` 提示） |
| 规划后文件被外部改动 | 写前逐区间零校验 + 引擎 tmp/rename | 拒绝或原子失败，无半成品 |
| 索引字节被篡改 | magic（标准模式）/ CRC32 / 结构自洽 | locate 返回 None；strip 返回 `CorruptedData` |
| 索引把 chunk 指向节数据 | 每条 entry 必须完整落在 padding range 内 | 拒绝；**绝不清零可执行字节** |
| 索引兄弟区间重叠/乱序/求和不等 | 物理严格递增 + 不重叠 + `sum == total` | 拒绝 |
| 末 chunk 被截断 | `last_chunk.off + len <= host_size` + trailer 位置等式 | 拒绝 |
| 信封内容被改（密文） | 引擎 L3（AES-GCM 分块认证） | `read` 报错；`remove` 仍可逐比特还原（清零与内容无关） |
| 还原后仍有残留 | 引擎 `orig_host_size` + SHA-256 全文件比对 | `RestoreMismatch`，不落盘 |
| 随机 padding 恰好像索引 | magic(32b) + CRC32(32b) + 6 项结构检查 + trailer 魔数 | 误判概率 ≤ 2^-64 量级，再叠加结构校验 |
| stealth 模式下被静态识别 | 索引魔数与 trailer 魔数均由口令派生 | 无固定签名；`scan` 仍只能报 `pe:nonzero-padding` |
| 重复写入同一载体 | 槽位全零校验 + 引擎 `locate` 拒绝 | 已知口令时直接拒绝；未知口令的 stealth 旧信封只能靠 `scan` 提示（既有行为） |
| 旧版本 strhide 读 Mode 2 文件 | 旧 `locate` 的"`ube_offset + total == trailer_start + 24`"等式在碎片布局下不成立 | 返回"未发现隐藏数据"（干净漏检），**不会读出错误内容** |

---

## 6. 边界与限制

1. **槽位约束**：`ranges[0]` 必须全零且 ≥ 16 B。实测 12/12 真实 PE 满足；不满足时 Mode 2 直接不可用（回落 Mode 1），不做"再找一个槽位"的猜测——那会破坏 I5。
2. **chunk 数上限**：`n ≤ (slot.len-16)/8`，典型槽位 300–600 B → 35–73 段，远大于真实节数（3–15）。超出时按文件顺序取前 n 段，剩余 padding 不使用。
3. **chunk 0 所在段 ≥ 112 B**：否则无处置放 112 字节 header。真实载体的最长段通常 ≥ 300 B。
4. **文件 > 4 GiB**：padding 偏移仍是 u32；仅"文件尾 overlay"可能超过 4 GiB，而本策略不碰那里。
5. **Python 兼容性**：Python 端不认识 `pe_slack`（Mode 1 也不认识），因此 Mode 2 文件是 Rust 单向可读。与现有 `pe_codebits` 的兼容性级别一致，不新增退化。
6. **足迹**：碎片数 = 被点亮的 padding 区间数。Mode 1 优先策略保证只有确实需要时才铺开；`inspect`/`write` 结果里显式给出段数。

---

## 7. 实施顺序与验证清单

1. `pe_slack.rs`：索引编解码 + `plan()` + 容量函数（纯逻辑，先补单元测试）。
2. `pe_slack::inject` 增加分段写入与逐区间零校验；`strip` 增加多区间清零；`locate` 增加索引路径并保留 Mode 1 回落。
3. `pe.rs`：`trailer_patch_offset` 钩子（PE 实现）+ 容量报告拆成"单段/碎片"两档。
4. `engine.rs`：`trailer_pos` 改为先问钩子（约 10 行，其余适配器默认无变化）。
5. 测试：
   - 单元：索引 CRC/长度/越界/重叠/求和；`plan()` 确定性（同输入同输出、容量与实际写入一致）。
   - 集成：多节合成 PE（单段装不下、总量装得下）→ 写入/读取/还原逐比特一致；只改 padding 字节；`-s pe_slack` 与 `auto` 的模式选择；ARM64；加密/stealth；索引篡改；strip 拒绝指向节数据的索引；重复写入拒绝；Mode 1 与 `pe_codebits` 回归。
   - 语料：`batch_corpus` 增加 `-s pe_slack` 一轮；对 13 个可修改的真实 PE 断言 SHA、尺寸、段数与 `inspect` 报的容量一致。
6. 文档：`pe_slack_strategy_proposal.md` 状态更新；`README` 的 PE 行补一句"fragmented padding"。

**规模估计**：实现 ~300–380 行，测试 ~250 行，引擎改动 ~10 行。风险集中在"布局规划与索引校验的一致性"，全部可被上面的单元/集成测试覆盖；不触碰信封格式、不改 PE 头、不影响其他格式。

---

## 8. 明确不做的事

- 不做逐段自描述帧（方案 A）：多一层魔数，检测面更大，且多封信封时会串味。
- 不做"无索引、从节表推导布局"（方案 C）：写入后零 run 几何不可恢复。
- 不做跨 4 GiB overlay 的分段：`eof`/`pe_overlay` 已覆盖大载荷场景。
- 不新增 strategy id：索引自描述，`strategy_id = 9` 同时承载 Mode 1/2，旧文件与协议字段零变化。
