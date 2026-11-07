# EBML/Matroska 容器适配器：Void 注入（ebml_void）

本文件规定 `format_name = "MKV"`（Matroska/WebM）的结构域（UBE）适配器。信封、尾标、AAD、`offset_delta` 与策略 ID 的公共定义见 [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md)、[WIRE_SPEC_STRUCTURE.md](../WIRE_SPEC_STRUCTURE.md) §2–§3、§9、§14、§15；本文只定义 EBML 容器的 detect、策略、Void 布局、容量、定位与还原。内容域 HEVC 视频（含 MKV 封装）见 [CONTENT-HEVC.md](CONTENT-HEVC.md)，二者互不替代。

## 1 范围、导航与稳定性

载体是以 4 字节 EBML 头魔数开始的 EBML 文档，适配器只做顶层元素搬运与末尾 Void 追加：不解码任何轨道、不解析 `Segment` 内部、不重写 `Cues`/`SeekHead`。所有原载体字节逐字节复制（`rust/src/structure/adapters/mkv.rs:79-80`）。

| 级别 | 本域内容 |
| --- | --- |
| **F** | EBML 头魔数 `1A 45 DF A3`；`doc_type` 不参与识别；Void ID `EC`；VINT 编码规则与全 1 保留；`inject_offset = host_len`；`offset_delta = 1 + vint_len`（2..9）；`inject_size = 1 + vint_len + ube_total_size`；`patch_offset = 0`；信封结束于物理文件尾；不修改任何原字节 |
| **D** | `auto` 恒取 `ebml_void`；显式 `eof`；VINT 字节数由 UBE 大小决定；已知大小 / 未知大小 `Segment`；同一宿主上的 `ebml_void` 与 `eof` 产物的 `offset_delta` 差异 |
| **I** | 复制缓冲与流式实现、`strategy_note` 文案、错误文本、`suspicious_structures` 的提示措辞；读侧不依赖 |

与内容域 HEVC/MKV 隐写的区别：内容域改写的对象是视频码流中 CABAC bypass `coeff_sign_flag`（TU 内非 DC 系数符号），宿主长度与容器布局不变，信封是内容域微信封（`rust/src/stego/hevc/slot.rs:581-589`、`CONTENT-HEVC.md` §2）。结构域不触碰任何码流位，只在文件尾新增一个 EBML `Void` 顶层元素并把 UBE 放在其中；两套信封派生域与结构互不可读（`WIRE_SPEC_STRUCTURE.md` §1）。

## 2 格式识别（detect）

`detect` 只做两步（`mkv.rs:17-37`）：保存调用前流位置 → 定位到 0 → 读 4 字节并与 `EBML_HEADER_ID = 0x1A45_DFA3` 比较（`ebml.rs:9`、`mkv.rs:27-29`）→ 再调用一次 `read_vint_size` 且只要返回 `Ok` 即通过（`mkv.rs:30`）。随后恢复原位置（`mkv.rs:35`）。

- **不读取 DocType**：`0x4282` 的 `matroska` / `webm` 字符串从未被解析，`EBMLVersion`（`0x4286`）与 `DocTypeVersion` 也不校验。测试载体虽含 `42 86 81 01 42 82 88 "matroska"`（`rust/tests/common/mod.rs:269-275`），代码路径与它无关。因此 WebM、`.ebml` 及任意 DocType 的 EBML 文档都会通过 detect。
- **不检查** `Segment`、`SeekHead`、`Cues`、文件最小长度或大小是否未知；5 字节的“魔数 + 合法 VINT”也能通过 detect。
- **不校验 EBML Header 的大小**：`read_vint_size` 只证明第一个 VINT 可解析，既不按声明长度跳过 Header，也不要求声明长度与实际内容一致（`mkv.rs:26-33`）。
- 适配器顺序为 PNG…PE、`MkvAdapter` 最后（`rust/src/structure/registry.rs:25-36`），失败时统一报 `UnsupportedFormat`（`registry.rs:51-87`）。

写前 L1 才做结构校验（`engine.rs:1027-1035` 调用 `mkv.rs:146-245`），拒绝条件：

1. 文件 < 12 字节 → `"MKV file too small for EBML container"`（`mkv.rs:151-154`）。
2. 顶层元素 ID 读取失败：首字节全零或 ID 长度 > 4（`ebml.rs:43-54`）。
3. 顶层元素大小 VINT 解析失败：首字节全零或长度 > 8（`ebml.rs:69-80`）。
4. 声明大小使元素越过文件尾，或偏移加法溢出（`mkv.rs:205-225`）。
5. 找不到 EBML Header 或 Matroska Segment（`mkv.rs:234-239`）。
6. 显式请求未知策略 → `UnsupportedFormat`（`mkv.rs:73-77`）；UBE 大小超出 VINT 范围 → `General("Envelope size exceeds the EBML VINT range")`（`mkv.rs:87-89`）。

`verify_structure` 不证明“存在信封”，只证明顶层 EBML 链自洽；`suspicious_structures` 才做信封形状提示（`mkv.rs:247-290`）。

## 3 策略、auto 与容量报告

| 名称 | `strategy_id` | 行为 | 出处 |
| --- | --- | --- | --- |
| `ebml_void` | 11 | 在物理 EOF 追加 `Void` 元素，UBE 作 Void 数据 | `registry.rs:101`；`mkv.rs:86-92` |
| `eof` | 1 | 在物理 EOF 直接追加 UBE，无 Void、无容器头 | `registry.rs:91`；`mkv.rs:93-95` |

支持列表 `["ebml_void", "eof"]` 即优先级（`mkv.rs:39-41`）；`auto` 无条件返回 `"ebml_void"`，不测量宿主、不考虑 UBE 大小（`mkv.rs:43-45`）。因此 VINT 溢出时 `auto` 不会自动降级到 `eof`，而是按 §2 第 6 条报错。显式策略必须落在支持列表内（`engine.rs:1242-1255`），`inject` 再拒绝一次（`mkv.rs:73-77`）。

容量报告（`mkv.rs:47-64`）：两者均 `capacity_bytes = None`、`limit = "unlimited (file grows)"`，`ebml_void` 附注 `"Embedded into compliant EBML Void element (0 trailing bytes)"`。`inspect` 随后把无上限策略钳到引擎载荷上限（`engine.rs:1916-1934`、`:2604-2611`）：`structure_payload_limit(host_len) = clamp(256 × host_len, 64 MiB, 1 GiB)`（`engine.rs:1902-1907`；`rust/src/core/crypto.rs:786`）。

## 4 注入布局

### 4.1 `ebml_void`

```text
偏移 inject_offset = host_len（原载体物理末尾）
  +0                 EC                      ← EBML Void ID（1 字节，ebml.rs:8）
  +1                 VINT(ube_total_size)     ← 1..8 字节（ebml.rs:25-37）
  +1+vint_len        UBE[0 .. ube_total_size)  ← offset_delta = 1 + vint_len
```

- VINT 规则：对 `len ∈ 1..=8`，长度标记位为 `1 << (7*len)`；当 `val < (1<<(7*len)) - 1` 时输出 `len` 字节大端 `(marker | val)`（`ebml.rs:26-34`）。首个 1 位之前的高位为长度标记，其余 `7*len` 位为数据。
- 边界值必须进位：`126` 仍为 1 字节，`127` 必须编码为 `40 7F`，否则会撞上“所有数据位为 1 = 大小未知”的保留值（`ebml.rs:28-31`、测试 `ebml.rs:111-127`）。`val >= 2^56 - 1` 返回 `None`，调用方按失败处理（`ebml.rs:36`）。
- `offset_delta` 由同一 VINT 推导（`mkv.rs:292-306`），写入前参与 AAD（`engine.rs:1267-1278`），上限 `MAX_OFFSET_DELTA = 64`（`rust/src/structure/envelope.rs:74-81`）；本策略最大 9，天然满足。
- `inject` 返回 `(host_len, 1 + vint_len + ube_total_size, 0, 0)`（`mkv.rs:86-99`）：`patch_offset = 0`，不改写宿主任何字段。Void 数据长度恰为 UBE 长度，**无补位、无尾部填充**。

具体字节示例（UBE 起点在 `host_len + offset_delta`）：

| `ube_total_size` | VINT 字节 | `offset_delta` | `inject_size` |
| --- | --- | --- | --- |
| 214（最小可写） | `40 D6` | 3 | 217 |
| 16,383 | `20 3F FF` | 4 | 16,387 |
| 16,384 | `20 40 00` | 4 | 16,388 |
| 1 MiB（1,048,576） | `30 00 00` | 4 | 1,048,580 |

### 4.2 插入位置与不更新的结构

- 位置固定为物理文件尾 `host_len`（`mkv.rs:79-85`）：不会插在 `SeekHead` 之后、不会插在 EBML Header 与 Segment 之间、不会插在 `Cues` 旁，也不会复用已有的尾部 `Void`；每次注入总是新建一个顶层 `Void`。
- 不更新 `Segment` 大小（`mkv.rs` 全文无 size 写回，且 `finalize` 未覆写，`adapters/mod.rs:364-370`）；已知大小的 Segment 之后追加的 Void 是 Segment 的**同级顶层元素**，与原 Segment 边界无关。未知大小（`0x01FFFFFFFFFFFFFF`）的 Segment 扩展到文件尾，Void 仍被当作顶层元素读取。
- 不更新 `SeekHead`/`Cues`：所有既有字节原样复制，原有相对与绝对偏移不变，因此无需修补；代价是这些索引不覆盖新增 Void。

### 4.3 `eof`

`inject_offset = host_len`、`inject_size = ube_total_size`、`offset_delta = 0`、无 Void（`mkv.rs:93-95`、`mkv.rs:292-306`）。信封首字节即物理 EOF 处的 UBE 起点。

## 5 容量与上下界

记 `N = ube_total_size`、`L = vint_len(N)`。

| `N` 范围 | `L` | `offset_delta = 1+L` | `inject_size` |
| --- | --- | --- | --- |
| 0 ..= 126 | 1 | 2 | N+2 |
| 127 ..= 16,382 | 2 | 3 | N+3 |
| 16,383 ..= 2,097,150 | 3 | 4 | N+4 |
| 2,097,151 ..= 268,435,454 | 4 | 5 | N+5 |
| 268,435,455 ..= 34,359,738,366 | 5 | 6 | N+6 |
| 34,359,738,367 ..= 4,398,046,511,102 | 6 | 7 | N+7 |
| 4,398,046,511,103 ..= 562,949,953,421,310 | 7 | 8 | N+8 |
| 562,949,953,421,311 ..= 2^56-2 | 8 | 9 | N+9 |

- VINT 可表示上限为 `2^56 - 2`（8 字节、数据位不得全 1）；`2^56-1` 是未知大小哨兵，写入端拒绝。
- Segment 大小不是约束：适配器不读取、不比较、不更新它，因此不存在 32/64 位容器长度上限。
- 引擎实际约束：写侧 `raw_size <= structure_payload_limit(orig_host_size)`（`engine.rs:1082-1094`），读侧同一函数（`engine.rs:1955-1967`）；`inspect` 报告的容量被钳到同一值。
- 最小 UBE：`locate` 物理门槛 `HEADER_SIZE + TRAILER_SIZE = 136`（`engine.rs:191-207`、`envelope.rs:870-879`）；实际可产出信封从 1 字节载荷的 `min_ube_len(1) = 214` 起（`envelope.rs:116-132`、`WIRE_SPEC_STRUCTURE.md` §14.3）。
- 现有 Void 复用：无。即使宿主尾部已有 Void，也另起一个；旧 Void 内容不变，读侧只按尾标定位最后一个信封。

## 6 locate 路径

`mkv.rs:102-137` 的顺序：

1. `file_size = seek(End(0))`，用 `EnvelopeTrailer::read_from_tail(stego, expected_trailer_magic)` 读末 24 字节；魔数不符返回 `None`（正常“无信封”），魔数匹配但 CRC/解析失败报 `CorruptedData`（`envelope.rs:831-859`）。
2. `start = trailer.locate_start(file_size)`：若 `ube_offset + ube_total_size == file_size` 取记录值，否则要求 `ube_total_size >= 136` 并取 `file_size - ube_total_size`，允许内容域重写导致的整体平移（`envelope.rs:870-879`）。减法下溢即 `None`，伪造超大 `ube_total_size` 因此无效（`mkv.rs:118-120`；回归 `rust/tests/test_security/forge.rs:191-198`）。
3. 前缀反推：用 `encode_vint(trailer.ube_total_size)` 求 `prefix_len = 1 + vint_len`；若 `start >= prefix_len`，读 `[start-prefix_len, start)`，要求 `prefix[0] == 0xEC` 且其后字节与 VINT 完全相等，命中返回 `(start, ube_total_size, "ebml_void")`（`mkv.rs:121-132`）。
4. 前缀不匹配则无条件回退 `(start, ube_total_size, "eof")`（`mkv.rs:135-136`）；因此 `eof` 写入的 UBE 若恰好被形如 `EC + 匹配 VINT` 的字节前缀，会被误标为 `ebml_void`（仅影响策略名，坐标仍一致）。

`locate` 不做 EBML 链扫描、不解析 Segment 边界、不查 `SeekHead`/`Cues`；完整的顶层链扫描只在 `verify_structure` 中（`mkv.rs:162-232`）。适配器未覆写 `locate_with_hint`，`expected_header_magic` 被忽略，只使用尾标魔数（`adapters/mod.rs:218-225`）；引擎在有密码时先试 stealth 尾魔数、再试方言魔数（`engine.rs:145-166`）。

引擎统一收紧：`ube_total_size >= 136` 且 `ube_offset + ube_total_size <= file_len`（`engine.rs:191-207`）。因为尾标必须位于物理文件尾、`start` 又由文件尾反推，追加型策略实际满足“信封结束 == 文件尾”；但该等式来自适配器的定位方式，不是 `confine_location` 的显式检查。

## 7 remove 还原

`MkvAdapter` 不覆写 `strip`，使用默认实现（`adapters/mod.rs:236-289`）：复制 `[0, inject_offset)`，跳过 `inject_size` 字节，再复制其余字节；`patch_offset == 0`，无字段回写。

- `ebml_void`：`inject_offset = 原 host_len`，跳过的是 `EC + VINT + UBE` 整块，输出逐字节等于原载体。由于注入时未改 Segment 大小、SeekHead、Cues 或任何原字节，**没有需要恢复的字段**。
- `eof`：只跳过 UBE 本身，同样输出原载体。
- 引擎在 `remove_core` 先解密元数据、再做坐标交叉校验，然后 `strip`（`engine.rs:2210-2255`）；`verify_restored` 重算长度与 SHA-256，必须等于 header 中的 `orig_host_size` / `orig_host_sha256`，否则 `RestoreMismatch`（`engine.rs:2299-2312`）。
- 多层信封必须按注入逆序删除；残留信封会被诊断提示（`engine.rs:2314-2330`）。

## 8 边界与异常结构

- **未知大小 Segment**：`read_vint_size` 把数据位全 1 解释为 `None`（`ebml.rs:94-98`），`verify_structure` 直接令 `offset = file_size` 结束扫描（`mkv.rs:227-230`）。此时追加的 Void 仍是顶层元素；L1 在扫描结束后只检查“有 Header + 有 Segment”，不要求信封存在（`mkv.rs:234-244`）。
- **已知大小 Segment（含 size = 0）**：扫描跳过整个 Segment 后继续读顶层元素，新 Void 作为 Segment 的同级被正常解析（`mkv.rs:205-226`）；不校验 Segment 是否铺满文件。
- **EBML 头后已有 Void**：可能是宿主自带的 Void；`verify_structure` 正常跳过，注入仍发生在文件尾，不复用、不填充、不删除该 Void。
- **多 Segment**：只要求至少出现一次 `MATROSKA_SEGMENT_ID`（`mkv.rs:188-189`、`:237-239`），不限制数量与顺序；Void 追加在最后一个 Segment 之后。
- **WebM**：与 MKV 无差别，DocType 不读、版本不读；检测、注入、定位、还原完全同一路径。
- **内容域重写后的平移**：`locate_start` 允许信封滑动，但 `envelope_coordinates_agree` 只对 `chunk`/`eof` 放行坐标不一致（`engine.rs:2867-2874`），`strip_coordinates_for_location` 同样只放行这两者（`engine.rs:2280`）。因此 `ebml_void` 信封一旦因前置字节长度变化而滑动，`verify`/`remove` 会报坐标不一致；写侧当前不受影响。
- **损坏/截断**：写前 L1 返回 `(false, 详情)` 即 `CorruptedData` 拒绝写入（`engine.rs:1027-1035`）；`locate` 遇截断只回退 `eof`，不视作错误。
- **尾部伪造**：`suspicious_structures` 只读末 24 字节并要求 `ube_offset + ube_total_size == file_size`，随后检查 `EC + VINT` 前缀（`mkv.rs:247-290`）；它不校验尾标魔数与 CRC，仅用于“可能已存在信封”的警告。

## 9 I 级写侧与自检

- **I 级**：复制缓冲大小、是否边读边写、Void 前缀的构造方式、`strategy_note` 文案与错误文本可由实现决定；Void ID、VINT 字节、追加位置、`offset_delta` 与 `inject_size` 不得更改。
- 写序列：L1 校验（`engine.rs:1027-1035`）→ `inject` 复制全部宿主字节并追加 Void 或裸 UBE（`mkv.rs:79-99`）→ 引擎在 `actual_ube_offset = inject_offset + offset_delta` 回填 header，在默认位置 `actual_ube_offset + ube_total_size - 24` 回填尾标（`engine.rs:1407-1441`；`adapters/mod.rs:356-359`）。未覆写 `finalize`，无 CRC 类后处理。
- 写后自检：`locate` 必须返回本次写入的精确 `(actual_ube_offset, ube_total_size)`，否则中止且不提交半成品（`engine.rs:1454-1472`）；落盘为临时文件 + 原子重命名（`engine.rs:1534-1601`）。
- 回归：`ebml_void` 的写读删矩阵（`rust/tests/test_lifecycle/matrix.rs:113`、`:128`、`:400`、`:426`）；伪造 `ube_total_size` 不分配缓冲且不误读（`rust/tests/test_security/forge.rs:191-198`）。
