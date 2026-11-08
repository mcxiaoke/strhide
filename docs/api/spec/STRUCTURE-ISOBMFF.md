# ISO-BMFF 结构域适配器：MP4/MOV 与 HEIF/HEIC

本文规定 `format_name = "MP4"`（`Mp4Adapter`）与 `format_name = "HEIF"`（`HeifAdapter`）的结构域（UBE）适配器，两者共用 `isobmff.rs` 的盒流实现。信封的 112B 头、24B 尾标、AAD、`offset_delta` 语义见 [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2–§15（`WIRE_SPEC_STRUCTURE.md` 仅为历史对照，冲突以本目录为准）；内容域 HEVC/HEIF 见 [CONTENT-HEVC.md](CONTENT-HEVC.md)，二者互不替代。

## 1 范围、导航与稳定性

- 载体：顶层为 ISO/IEC 14496-12 Box 的 MP4/MOV、碎片化 MP4/CMAF，以及 HEIF/HEIC（含 AVIF 品牌）。适配器只按盒头跳跃，不解码任何媒体数据。
- 适配器注册与检测优先级：`rust/src/structure/registry.rs:25-36`；HEIF 排在 MP4 之前，因此同一 `ftyp` 文件先由 HEIF 判定。
- 策略 ID：`box_uuid = 3`、`eof = 1`、`item_hidden = 12`、`free_box = 13`（`rust/src/structure/registry.rs:90-104`）。

| 级别 | 本域内容 |
| --- | --- |
| **F** | MP4 首盒 4CC 白名单；HEIF `ftyp` 尺寸/品牌判定；`MP4_UUID_NEUTRAL` 16B usertype；`uuid` box 的 24/32B 头与 `calc_prefix_len` 切换点；`free`/`mdat` 8B 头；`item_hidden` 的 `infe` v2/v3、`iloc` 条目与第二 `mdat`；`offset_delta` 24/32/8/0；locate 的 24/32/8B 头识别规则；末盒后追加的物理布局 |
| **D** | 无。UUID usertype、item type `resv`、`infe`/`iloc` 模板均为常量；信封魔数、密钥、stealth 域只在信封层生效（`STRUCTURE-ENVELOPE.md` §3.1、§11） |
| **I** | 宿主复制的分块/缓冲方式、`meta` 扫描实现、`strategy_note` 文案、错误消息措辞；读侧不得依赖 |

与内容域的区别：内容域 HEVC 修改 VCL 中 CABAC `coeff_sign_flag` 并按原日志重放子流（`docs/api/spec/CONTENT-HEVC.md` §2），HEIF 面向主图或 `grid` 瓦片；结构域只改写/追加 Box，`mdat` 中的媒体字节逐字节复制（`rust/src/structure/adapters/isobmff.rs:85-86`、`:1178-1181`）。`item_hidden` 新增的是一个孤立项，不重编码主图，也不访问缩略图。

## 2 格式识别（detect）

`detect` 只读文件头并恢复调用前流位置，不返回错误（`rust/src/structure/adapters/mp4.rs:25-60`、`heif.rs:21-51`）。

**MP4 路径**：读前 8B，取 `[4..8]` 作 4CC，必须属于下列白名单之一，否则 `false`（`mp4.rs:33-57`）：

```text
ftyp styp moov moof mdat sidx emsg free skip wide uuid pdin
```

不校验品牌、`moov`/`mdat` 是否存在、也不校验后续盒链；首盒为 `mdat`/`uuid`/`free` 的文件同样通过 detect。

**HEIF 路径**：首盒必须是 `ftyp`，其 32 位 size 必须在 `12..=4096` 内，读满该盒后调用 `is_heif_bytes`（`heif.rs:30-41`）。品牌判定为：`payload = bytes[8..size]`，按 4B 遍历，跳过下标 1（`minor_version`），主品牌（下标 0）与全部兼容品牌都比对 `HEIF_BRANDS`；命中即真（`rust/src/formats/sniff.rs:189-212`、`:23-26`）：

```text
heic heix hevc hevx mif1 msf1 heim heis avif avis
```

拒绝条件：无前导 `ftyp`、`ftyp` size 越界、无命中品牌。`detect` 不要求 `meta`/`iinf`/`iloc`，这些只在 `item_hidden` 准入时检查。

**写前结构闸门**：无论 detect 结果如何，`write_core` 先调用 `isobmff_verify_structure`，失败即 `CorruptedData("Refusing to write into a malformed … carrier")`（`rust/src/structure/engine.rs:1028-1035`）。该验证逐盒检查：`size == 1` 时读 64 位 `largesize`（头 16B），`size == 0` 视为延伸到 EOF；`size < 头长`、越 EOF、u64 加法溢出、顶层盒数超过 1,000,000 均拒绝；至少一个显式尺寸盒且存在 `ftyp`（`isobmff.rs:239-359`）。因此“合法但无 `ftyp` 的 CMAF 片段”能通过 detect，却会在写前被拒绝；`moov`、`mdat` 始终不是准入条件。

## 3 支持策略、auto 与容量

| 适配器 | 策略 | id | 实际行为 | 出处 |
| --- | --- | --- | --- | --- |
| MP4 | `box_uuid` | 3 | 文件末尾追加 `uuid` box（24/32B 头） | `mp4.rs:62-64`、`isobmff.rs:92-111` |
| MP4 | `eof` | 1 | 文件末尾直接追加 UBE，无容器头 | `mp4.rs:62-64`、`isobmff.rs:119-121` |
| HEIF | `item_hidden` | 12 | 改写 `meta`，在末尾追加第二 `mdat` | `heif.rs:53-55`、`isobmff.rs:818-1195` |
| HEIF | `free_box` | 13 | 文件末尾追加 `free` box（8B 头） | `heif.rs:53-55`、`isobmff.rs:112-118` |
| HEIF | `box_uuid` | 3 | 同 MP4 | `heif.rs:53-55` |
| HEIF | `eof` | 1 | 同 MP4 | `heif.rs:53-55` |

`free_box` 在共享注入器中可用，但 `Mp4Adapter` 未声明该策略；对 MP4 显式传 `free_box` 会被引擎以“不支持”拒绝（`engine.rs:1248-1253`）。适配器也不复用既有 `free`/`skip` 盒，均新建盒。

**auto**（单次选择，不重试、不回退，`engine.rs:1242-1255`）：

- MP4：恒选 `box_uuid`，与 UBE 大小无关（`mp4.rs:66-68`）。
- HEIF：`ube_total_size <= ITEM_HIDDEN_MAX_ENVELOPE` 且 `isobmff_can_item_hidden(reader)` 为真时选 `item_hidden`，否则选 `box_uuid`（`heif.rs:57-68`）。`ITEM_HIDDEN_MAX_ENVELOPE = u32::MAX - 8 = 4,294,967,287`（`isobmff.rs:19`）。
- 不存在“主策略失败自动退 `eof`”路径；`eof` 只能显式选择。

容量报告：`box_uuid`/`eof` 报 `capacity_bytes = None`、`limit = "unlimited (file grows)"`；HEIF `item_hidden`/`free_box` 同样报 `None`，但文本写明“up to ~4 GiB envelope”（`isobmff.rs:415-472`）。`inspect` 会把所有可用策略的 `None` 统一钳到 `structure_payload_limit(host_len) = clamp(256 × host_len, 64 MiB, 1 GiB)`（`engine.rs:1938-1975`、`:2604-2611`；`available = false` 的条目不填数），因此显示值通常为 64 MiB～1 GiB，而非 4 GiB。

## 4 注入布局、`offset_delta` 与容量

### 4.1 共同点

四个策略都先把宿主 `[0, host_len)` 逐字节写入输出，`inject_offset = host_len`（`eof`、`box_uuid`、`free_box`）；`item_hidden` 的宿主前缀因 `meta` 增长而变长，见 §4.4。所有策略都在文件末尾结束，信封尾标位于文件最后 24B（默认 `trailer_offset = actual_ube_offset + ube_total_size - 24`，`adapters/mod.rs:357-359`）。`eof`/`box_uuid`/`free_box` 只在 EOF 追加，既有盒的物理起点不变，因此 `stco`/`co64`/`iloc`/`sidx` 均保持原值；`item_hidden` 的 `iloc` 改写见 §4.4。

### 4.2 `box_uuid`

UBE 前固定写一个 `uuid` box，usertype 为 16B 常量 `MP4_UUID_NEUTRAL`（`isobmff.rs:11-13`，字节 `d4 1a 8e 9c 4f 21 4e 87 9a 33 5b 6d 12 84 ef 70`）：

```text
32 位头（24 + ube < 0xFFFFFFFF）：
  +0  u32be size = 24 + ube_total_size
  +4  "uuid"
  +8  MP4_UUID_NEUTRAL[16]              ← UBE 起点 = 注入点 + 24
64 位头（24 + ube >= 0xFFFFFFFF）：
  +0  u32be 1
  +4  "uuid"
  +8  u64be largesize = 32 + ube_total_size
  +16 MP4_UUID_NEUTRAL[16]              ← UBE 起点 = 注入点 + 32
```

切换点唯一由 `calc_prefix_len(ube_size)` 决定（`isobmff.rs:30-32`），写入与 `offset_delta` 共用；单测固定了 `24 + ube == 0xFFFFFFFE` 用 24B、`== 0xFFFFFFFF` 用 32B（`isobmff.rs:1670-1679`）。32 位形式可承载 `ube <= 0xFFFFFFE6`；64 位形式的 `largesize` 为 u64。`inject_size = 头长 + ube`（`isobmff.rs:92-111`）。

### 4.3 `free_box`

```text
+0  u32be size = 8 + ube_total_size
+4  "free"
+8  UBE[0 .. ube_total_size)          ← offset_delta = 8
```

只写 32 位 size；`8 + ube` 超出 `u32` 时报 `Envelope too large for 32-bit free box`（`isobmff.rs:112-118`）。上限 `u32::MAX - 8 = 4,294,967,287`。读侧同时接受既有 `free`/`skip` 头（`isobmff.rs:209-216`），写侧只产出 `free`。

### 4.4 `item_hidden`

前置准入 `check_item_hidden_layout`（`isobmff.rs:522-609`，探测 `isobmff_can_item_hidden` 复用同一函数，`:611-633`）要求：`meta`、`iinf`、`iloc` 均为 8B 头（禁止 `size == 1`）；`iloc` 版本 ≤ 2；`off_sz`/`len_sz ∈ {4,8}`；`base_sz ∈ {0,4,8}`；`iinf` 版本 ≤ 1；`meta` 结束位置 ≤ 1 GiB（`MAX_ISOBMFF_META_SCAN`，`:481`、`:855-859`）。

写入步骤（`isobmff.rs:818-1195`）：

1. 顶层盒流式扫描定位 `meta`，只缓冲 `[0, m_end)`（`:830-863`）。
2. 拆出 `meta` 子盒（保留 `<8B` 的 `meta_tail` 原样，`:870-893`）。
3. `new_id = max(iinf 现有 item_id) + 1`；`u32::MAX` 时拒绝（`:908-959`）。
4. 新 `infe`：`new_id <= 0xFFFF` 用 v2、21B；否则 v3、23B。内容为 `item_type = "resv"`、`item_protection_index = 0`、空 `item_name`；不写 mime、不置 hidden 标志（`:961-984`）。
5. 新 `iloc` 条目：`item_id`（v0/v1 2B，v2 4B）、v≥1 时 `construction_method = 0`、`dref = 0`、`base_offset = 0`、`extent_count = 1`、可选 `extent_index`、`extent_offset`、`extent_length`（`:1029-1046`）。`extent_offset = host_size + delta_meta + 8`，`extent_length = ube_size`，即指向第二 `mdat` 数据区（`:1026-1027`）。
6. `delta_meta = infe_len + iloc_item_len`；`meta`、`iloc`、`iinf` 的 32 位 size 与条目数各自 +1/加长（`:1128-1160`），并重建 `meta`（`:1162-1174`）。
7. 输出 `[0, m_off)` + 新 `meta` + 宿主 `[m_end, host_size)`，随后追加：

```text
+0  u32be size = 8 + ube_total_size
+4  "mdat"
+8  UBE[0 .. ube_total_size)          ← offset_delta = 8
```

返回 `inject_offset = host_size + delta_meta`（第二 `mdat` 头位置）、`inject_size = 8 + ube`（`:1183-1194`）。`meta` 增长发生在 `inject_offset` 之前，不计入 `inject_size`。

**既有 `iloc` 偏移处理**：仅处理 `construction_method == 0` 的项。若 `base_offset >= m_end`（且非 0、`base_sz > 0`），`base_offset` 与指向其后的 extent 都加 `delta_meta`；若 base 留在原处但 extent 绝对位置 `base + extent_offset >= m_end`，只加 extent；数据位于 `meta` 之前的项不变；`construction_method != 0`（`idat` 等）不解析、不改写（`isobmff.rs:1050-1126`）。适配器全程不读取 `stco`/`co64`/`sidx`，因此含 `moov/trak` 且 `stco` 指向 `meta` 之后数据的 HEIF 不在校正范围内。

**容量**：`ube <= 4,294,967,287`；此外当 `off_sz == 4` 时，`host_size + delta_meta + 8` 必须 ≤ `u32::MAX`，否则 `write_sized_uint` 报 32 位 iloc 溢出（`isobmff.rs:753-756`、`:1045`）。该载体相关上限不进入容量表。

### 4.5 `eof`

无容器头，`inject_size = ube_size`、`offset_delta = 0`（`isobmff.rs:119-121`、`mp4.rs:117-122`、`heif.rs:126-133`）。允许任意可被引擎接受的载荷；无容器结构上限。

### 4.6 `offset_delta` 汇总

| 适配器 | 策略 | `offset_delta` | 出处 |
| --- | --- | --- | --- |
| MP4 | `box_uuid` | `calc_prefix_len(ube)` = 24 或 32 | `mp4.rs:111-122`、`isobmff.rs:30-32` |
| MP4 | `eof` | 0 | 同上 |
| HEIF | `box_uuid` | 24 或 32 | `heif.rs:120-133` |
| HEIF | `free_box` / `item_hidden` | 8 | 同上 |
| HEIF | `eof` | 0 | 同上 |

`offset_delta` 在封装 header 前计算并进入 AAD；写入后 `actual_ube_offset = inject_offset + offset_delta`（`engine.rs:1267-1278`、`:1407`、`:1428-1441`）。

## 5 locate 路径

MP4 与 HEIF 共用 `isobmff_locate`，都没有覆写 `locate_with_hint`，因此 header 魔数提示被忽略（`mp4.rs:84-90`、`heif.rs:84-90`、`adapters/mod.rs:218-225`）。顺序如下（`isobmff.rs:128-237`）：

1. **尾标**：`EnvelopeTrailer::read_from_tail` 按期望 trailer 魔数读取并校验 CRC；随后要求 `ube_total_size >= 136` 且 `ube_offset + ube_total_size <= file_size`（`:132-154`）。
2. **24B 头**：`ube_offset >= 24` 时读 `[ube_offset-24, ube_offset)`；类型 `uuid`、usertype 与 `MP4_UUID_NEUTRAL` 相等、`size == 24 + total` → `(ube_offset, total, "box_uuid")`（`:156-176`）。
3. **32B 头**：`size == 1`、类型 `uuid`、`largesize == 32 + total`、usertype 匹配 → `box_uuid`（`:178-200`）。
4. **8B 头**：`size == 8 + total` 时，类型 `free`/`skip` → `free_box`；类型 `mdat` 且 `isobmff_has_iloc_item(ube_offset, total)` 为真 → `item_hidden`（`:202-228`）。
5. **EOF 回退**：`trailer.locate_start(file_size)` 在 `ube_offset + total == file_size` 时返回记录值，否则返回 `file_size - total` → `"eof"`（`:230-234`；`envelope.rs:870-879`）。

`item_hidden` 的确认不是按 item id，而是在顶层 `meta` 的 `iloc` 中查找 `absolute_offset == ube_offset && extent_length == total` 的 extent（`construction_method == 0` 时用 base+offset，否则用 offset）；找不到即 `false`（`isobmff.rs:1542-1658`）。因此若 8B 头匹配但 `iloc` 不匹配，同一位置会落到 EOF 分支并被标为 `eof`。

locate 只提出候选，不验证头魔数或密码；物理包含与坐标交叉由引擎统一校验（`engine.rs:191-207`、`:2828-2902`）。

## 6 remove 还原

- **MP4**：使用 `HostAdapter::strip` 默认实现，复制 `[0, inject_offset)`、跳过 `inject_size`、再复制余下字节（`adapters/mod.rs:236-260`；`mp4.rs` 未覆写）。`box_uuid` 删除整个 `uuid` box，`eof` 只删除 UBE。
- **HEIF**：`strip` 转调 `isobmff_strip`（`heif.rs:92-99`、`isobmff.rs:635-657`）。`strategy_id == 12` 时走 `heif_item_hidden_strip`，否则与默认实现语义相同。
- **`item_hidden` 还原**（`isobmff.rs:1197-1540`）：要求 `inject_offset >= m_end` 且 `inject_offset + inject_size == file_size`（`:1254-1269`）；重新扫描 `meta`，从 `iloc` 末尾删除一个条目、从 `iinf` 末尾删除实际尾随 `infe`（长度按条目自身 size 遍历得出，不信任 21/23 模板，`:1304-1367`）；对 `construction_method == 0` 且绝对位置 ≥ `m_end` 的 extent/base 减去 `delta_meta`（`:1411-1477`）；重建 `meta` 后只复制到 `inject_offset`，丢弃第二 `mdat`（`:1525-1539`）。
- 引擎对还原流重算长度与 SHA-256，必须等于 header 的 `orig_host_size`/`orig_host_sha256`，否则 `RestoreMismatch`；残留信封以 `suspicious_structures` 提示逆序删除（`engine.rs:2299-2361`）。

## 7 边界与错误语义

| 情形 | 行为 |
| --- | --- |
| 碎片化 MP4（首盒 `styp`/`moof`/`sidx`） | detect 接受；写前 `verify_structure` 仍要求存在 `ftyp`，纯 CMAF 片段被拒；追加在文件末尾，不改 `moof`/`mdat` 索引（`mp4.rs:33-57`、`isobmff.rs:351-353`） |
| 多个 `ftyp` | detect 只看首盒；验证只要求“存在” `ftyp`，不拒绝重复（`isobmff.rs:275-277`、`:351-353`） |
| 64 位顶层盒（`size == 1`） | 验证按 16B 头跳跃；`box_uuid` 的 64 位信封头可定位；`item_hidden` 明确拒绝 64 位 `meta`/`iloc`/`iinf` 头（`isobmff.rs:279-291`、`:526-530`、`:553-558`） |
| `size == 0` 盒 | 验证视为延伸到 EOF；若全文件只有 `size == 0` 盒则拒绝。若同一文件另有显式盒与 `ftyp`，追加在 EOF 的信封在语义上可能落入该“到 EOF”盒内部，代码不额外拦截（`isobmff.rs:249-254`、`:292-297`、`:342-349`） |
| 盒链损坏 | 截断头、`size < 头长`、越 EOF、u64 溢出、盒数超限均使写前验证失败并拒绝写入（`isobmff.rs:257-340`） |
| HEIF 缩略图 | detect 仅看 `ftyp` 品牌，缩略图文件与主图文件不可区分；结构域不解析 `pitm`/`iref`/缩略图关系，`item_hidden` 只按文件自身 `iinf`/`iloc` 追加 `resv` 项，主图像素与缩略图字节均不变（`isobmff.rs:961-984`、`:1183-1189`） |
| 既有 `free`/`skip`/`mdat` 注入物 | `suspicious_structures` 只识别尾部 24/32B `uuid` box，不识别 `free_box` 或 `item_hidden` 残留（`isobmff.rs:361-413`） |
| 未知策略 | `UnsupportedFormat`（`isobmff.rs:79-83`） |
| 显式 `free_box` 且 UBE > `u32::MAX-8` | `General("Envelope too large for 32-bit free box")`（`isobmff.rs:114-115`） |
| `item_hidden` 无 `meta`/`iinf`/`iloc` 或布局不支持 | `UnsupportedFormat`，auto 已提前改选 `box_uuid`（`isobmff.rs:840-842`、`:895-906`、`:522-609`） |

`avif`/`avis` 品牌按 HEIF 路径处理；对二者执行 `item_hidden` 仍取决于其 `meta` 布局，不做编解码器特判。

## 8 写侧 I 级与自检

- **不重编码**：宿主盒与媒体字节按原顺序复制，只新增盒/改写 `meta` 三处计数与 `iloc` 偏移；不合并、不拆分、不补填充盒（`isobmff.rs:85-86`、`:1162-1189`）。
- **流式内存**：`item_hidden` 最多缓冲 `[0, m_end)`（≤1 GiB），其余宿主与 UBE 流式写出（`isobmff.rs:861-863`、`:1176-1181`）。
- **确定性**：UUID 常量、`new_id = max+1`、`resv` 模板、盒 size 计算均为确定值；`iinf`/`iloc` 计数耗尽或 `item_id == u32::MAX` 直接失败，不截断（`isobmff.rs:954-959`、`:1021-1025`、`:1144-1148`）。
- **写后自检**：注入返回坐标后，引擎回填 header/trailer，再以本次 trailer 魔数调用 `locate`；必须精确返回 `(actual_ube_offset, ube_total_size)`，否则中止且不提交（`engine.rs:1454-1472`）。
- **单测锚点**：`prefix_len_switches_to_the_large_header_at_the_u32_bound`、`inject_writes_exactly_calc_prefix_len_header_bytes`、`locate_and_verify_accept_a_64_bit_box`、`verify_rejects_a_forged_24_byte_trailer_tail`、`suspicious_structures_distinguishes_the_two_header_forms`、`item_hidden_roundtrips_on_a_synthetic_meta_heif`、`item_hidden_strip_rejects_forged_coordinates`（`isobmff.rs:1670-1816`、`:2127-2185`、`:2340-2393`）。
- **回归命令**：

```bash
cargo test --all-features --lib structure::adapters::isobmff
cargo test --all-features --lib structure::adapters::heif
python scripts/baseline_hash.py --check
```
