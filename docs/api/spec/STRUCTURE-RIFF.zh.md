# RIFF 容器适配器：WAV / WebP 私有块注入（riff_chunk）

本文件规定 `format_name = "WAV"` 与 `"WEBP"` 的结构域（UBE）适配器。信封、尾标、AAD、`offset_delta` 与策略 ID 的公共定义见 [STRUCTURE-ENVELOPE.zh.md](STRUCTURE-ENVELOPE.zh.md) §2–§15（`WIRE_SPEC_STRUCTURE.md` 仅为历史对照，冲突以本目录为准）；本文件只定义 RIFF 容器的 detect、策略选择、块布局、容量与还原。内容域（WAV PCM LSB / FLAC 残差）见 [CONTENT-AUDIO.zh.md](CONTENT-AUDIO.zh.md)，二者互不替代。

## 1 范围、导航与稳定性

载体是以 12 字节 RIFF 头开始的 `WAVE` 或 `WEBP` 容器。适配器只读写顶层 chunk 流：不解码 PCM、不解码 WebP 图像、不重编码任何内容，信封只以新增顶层 chunk 的形式追加。

| 级别 | 本域内容 |
| --- | --- |
| **F** | `"RIFF"` + `u32le` size + form type（`WAVE`/`WEBP`）；块名 `"SHRD"`；块长字段 `u32le`；UBE 前置 8 字节块头；物理文件末尾追加；奇数字节补 `0x00`；`riff_chunk` 的 `offset_delta = 8`、`patch_offset = 4`；`inject_size = 8 + ube_total_size + (ube_total_size & 1)`；RIFF size 字段按 §4.3 更新；locate 的坐标交叉规则 |
| **D** | 载体分支：WebP Extended（12 字节后首块为 `VP8X`）才允许 `riff_chunk`，Simple Format 只能 `eof`；RIFF 声明边界是否等于物理末尾、chunk 表是否精确铺满决定 `riff_chunk` 可用性；UBE 奇偶决定补位 |
| **I** | 缓冲/流式复制方式、扫描实现、`strategy_note` 文案、错误文本、`auto` 谓词调用次数；读侧均不依赖 |

与内容域 WAV/FLAC 的区别：本域只增加 RIFF chunk，`data` chunk 内的 PCM 采样、FLAC 残差帧逐字节不变；PCM LSB / 残差修改属于内容域（CONTENT-AUDIO.zh.md），其信封、容量与校验不进入本文件。

## 2 格式识别（detect）

`detect` 只读前 12 字节：`buf[0..4] == "RIFF"` 且 `buf[8..12]` 等于期望 form type（WAV 用 `b"WAVE"`，WebP 用 `b"WEBP"`），成功返回 `true`，失败返回 `false`，不产生错误，并恢复调用前的流位置（`rust/src/structure/adapters/riff.rs:13-31`、`wav.rs:18`、`webp.rs:18`）。它不校验 size 字段、chunk 表、最小文件长度或 WebP 的 `VP8X`，因此 12 字节的伪 RIFF 文件也能通过 detect。适配器按 `registry.rs:25-36` 的顺序尝试，`WEBP` 在 `WAV` 之前，但 form type 不同不会互相误判。

结构门槛发生在写前校验与注入：

1. 文件长度 < 12 → `CorruptedData("<format> file too small for a valid RIFF header")`（`riff.rs:62-68`）。
2. `host_len != 8 + old_riff_size`（size 字段为 0 或 `0xFFFFFFFF` 的流式 WAV、尾部垃圾）→ `CorruptedData`，提示改用 `--strategy eof`（`riff.rs:93-99`）。
3. chunk 表不能精确铺满声明边界 → `CorruptedData`；末块奇数长但缺 pad 单独报 `MissingFinalPad`（`riff.rs:107-121`、`:389-446`）。
4. WebP Simple Format 显式请求 `riff_chunk` → `UnsupportedFormat`，提示改用 `--strategy eof`（`webp.rs:53-68`）。
5. 写路径还会先跑 L1：WAV 要求存在 `fmt ` 与 `data` 块，WebP 要求存在 `VP8 `、`VP8L` 或 `VP8X` 之一（`wav.rs:77-85`、`webp.rs:96-104`、`engine.rs:1027-1035`）；不满足即 `CorruptedData` 拒绝写入。

## 3 策略、auto 与容量报告

| 名称 | `strategy_id` | 行为 | 出处 |
| --- | --- | --- | --- |
| `riff_chunk` | 10 | 在物理文件末尾新建 `SHRD` 顶层 chunk，UBE 作为块数据 | `registry.rs:90-104`；`riff.rs:81-161` |
| `eof` | 1 | 在文件 EOF 后追加 UBE，不改 RIFF 头 | `registry.rs:91`；`riff.rs:73-78` |

两个适配器的支持列表均为 `["riff_chunk", "eof"]`，顺序即优先级（`wav.rs:21-23`、`webp.rs:21-23`）。`auto` 规则：

- WAV：`riff_can_chunk(reader, ube_size)` 为真取 `riff_chunk`，否则 `eof`（`wav.rs:25-35`）。
- WebP：仅当 12 字节后首块是 `VP8X` **且** `riff_can_chunk` 为真取 `riff_chunk`，否则 `eof`（`webp.rs:25-36`）。

`riff_can_chunk` 同时复刻注入的硬检查：`host_len == 8 + old_riff_size`、chunk 表为 `Exact`、`old_riff_size + inject_size <= u32::MAX`（`riff.rs:454-479`）。`auto` 不测量“空隙”，`riff_chunk` 总是让文件增长；显式策略由引擎校验是否在支持列表内（`engine.rs:1242-1255`），`riff_inject` 再次拒绝未知策略（`riff.rs:56-60`）。

容量报告（`riff.rs:520-560`）：**动态查询**（`reader != None`）时 `riff_chunk` 上报真实 headroom `capacity_bytes = u32::MAX - old_riff_size - 8`（`riff.rs:483-503`），而非 `None`；若该余量低于最小可写信封 `min_ube_len(0)`，则置 `available = false`、`capacity_bytes = None` 并在 note 说明只能回退 `eof`（`riff.rs:506-518`、`:546-556`）。**静态表**（`reader == None`）仍报 `capacity_bytes = None`、`limit = "up to 4GB RIFF limit (file grows)"`；`eof` 恒为无上限。`reader != None` 时若边界谓词失败，`riff_chunk` 同样置 `available = false` 并附注回退 `eof`；WebP Simple Format 另行置 `available = false`（`webp.rs:38-51`）。`reader == None` 的静态表不区分 WebP 子格式。`inspect` 随后把两者统一钳到引擎载荷上限 `structure_payload_limit(host_len) = clamp(256 × host_len, 64 MiB, 1 GiB)`（`engine.rs:1938-1975`、`:2604-2611`；上限常量见 `rust/src/core/crypto.rs:786`），且不再为 `available = false` 的条目填数。

## 4 注入布局

### 4.1 `riff_chunk`

```text
偏移 inject_offset = host_len（原载体物理末尾）
  +0                "SHRD" (53 48 52 44)
  +4                u32le chunk_size = ube_total_size
  +8                UBE[0 .. ube_total_size)        ← offset_delta = 8
  +8+ube_total_size 0x00（仅当 ube_total_size 为奇数）
```

- 块名常量逐字为 `SHRD`（`riff.rs:11`）；块长字段只计块数据，**不含**自身 8 字节块头，也**不含**补位字节（`riff.rs:147-157`）。
- 块固定追加在所有现有 chunk 之后，不插入 `data` 前、不插到 `LIST` 后、不重排任何既有块（`riff.rs:142-145`）。
- `inject_size = 8 + ube_total_size + (ube_total_size & 1)`（`riff.rs:123-124`）；`inject` 返回 `(host_len, inject_size, 4, old_riff_size)`（`riff.rs:160`），即补丁覆盖 stego 偏移 4 的 4 字节字段。

### 4.2 RIFF 总长度字段

`new_riff_size = old_riff_size + inject_size`，越界检查 `new_riff_size <= u32::MAX`（`riff.rs:126-133`）；随后写出 `"RIFF" + u32le(new_riff_size) + form type`（`riff.rs:136-138`）。RIFF size 的语义是“文件长度 − 8”（form type 与全部 chunk 区域），因此注入后文件长度为 `8 + new_riff_size`。除偏移 4 的 size 字段外，原 12 字节头其余部分与所有原 chunk 字节逐字节复制（`riff.rs:142-143`）。

### 4.3 `eof`

RIFF 头完全不变；`inject_size = ube_total_size`、`inject_offset = host_len`、`offset_delta = 0`、无补丁（`riff.rs:73-78`、`wav.rs:100-104`、`webp.rs:118-122`）。信封首尾坐标由引擎按 `actual_ube_offset = inject_offset + offset_delta` 和默认 trailer 位置 `ube_offset + ube_total_size - 24` 回填（`engine.rs:1407`、`:1428-1441`；`adapters/mod.rs:356-359`）。

## 5 WAV 与 WebP 的差异

| 项 | WAV | WebP |
| --- | --- | --- |
| form type | `WAVE` | `WEBP` |
| 私有块名 | `SHRD` | `SHRD`（同一常量） |
| `riff_chunk` 前置条件 | 任意满足 §2 的 `RIFF/WAVE` | 必须是 Extended Format：12 字节后首块为 `VP8X`（`webp.rs:25-36`、`:53-68`） |
| L1 必需块 | `fmt ` 与 `data`（`wav.rs:77-85`） | `VP8 ` / `VP8L` / `VP8X` 任一（`webp.rs:96-104`） |
| 容量不可用注记 | 边界不匹配 → “auto falls back to eof”（`riff.rs:499-505`） | 另加 Simple Format 无 `VP8X` 的注记（`webp.rs:44-49`） |
| 追加位置 | 物理 EOF（通常在 `data`/`LIST` 之后） | 物理 EOF（所有顶层 chunk 之后） |

## 6 容量公式、上下界与超限行为

记 `H = host_len`、`R = old_riff_size`（`u32le`）、`N = ube_total_size`、`P = N & 1`。`riff_chunk` 可写当且仅当：

```text
H == 8 + R
chunk 表精确铺满 H
R + 8 + N + P <= 0xFFFF_FFFF        ⇔  R + inject_size <= u32::MAX
```

由此：块长字段（`u32`）最多能记 `N`，但真正先触发的是 RIFF size 上限；`N` 的精确上限为满足 `N + P <= 0xFFFF_FFFF - R - 8` 的最大值，即单块上限受 `R` 挤占，而不是独立的 `u32::MAX`。注入后文件长度最大为 `0xFFFF_FFFF + 8` 字节。

- 结构下界：`locate` 要求块长 `>= 24`（`riff.rs:194`），`confine_location` 要求 `ube_total_size >= 112 + 24 = 136`（`engine.rs:191-207`）。实际可产出的信封为 `min_ube_len(0) = 213`（0 字节载荷）与 `min_ube_len(1) = 214`（CLI 允许的最小载荷，`rust/src/structure/envelope.rs:123-140`）。代码中**没有** `MIN_UBE_PLAIN`/`MIN_UBE_ENCRYPTED` 两个常量，容量报告一律用 `min_ube_len(...)` 计算。
- 引擎载荷上限另设为 `raw_size <= clamp(256 × orig_host_size, 64 MiB, 1 GiB)`（`engine.rs:1123`、`:1938-1943`）。
- 超限行为：`auto` 在 `riff_can_chunk` 失败时改走 `eof`；显式 `riff_chunk` 在 size 溢出时报 `General("RIFF 4GB container size overflow")`（`riff.rs:126-133`），在边界/表不匹配时报 `CorruptedData` 并提示 `--strategy eof`（`riff.rs:93-121`）。`eof` 无容器上限，只受引擎载荷上限约束。

## 7 locate 路径

`riff_locate` 按以下顺序（`riff.rs:163-228`）：

1. 文件 < 12 或前 4 字节不是 `"RIFF"` → `Ok(None)`；**不**校验 form type 与 size 字段（`riff.rs:167-176`）。
2. 从偏移 12 正向扫描顶层 chunk：读 `[4CC][u32le size]`，按 `8 + size + (size & 1)` 前进，加法溢出即停（`riff.rs:180-218`）。
3. 命中 `SHRD` 且 `size >= 24`、块数据不越过文件尾时，读取 `块数据末尾 − 24` 的 24 字节尾标，用期望 trailer 魔数解包；仅当 `trailer.ube_offset == 块数据偏移` 且 `trailer.ube_total_size == size` 才返回 `(块数据偏移, size, "riff_chunk")`（`riff.rs:192-210`）。
4. 扫描不中则做 EOF 回退：从文件尾读 24 字节尾标，`locate_start(file_size)` 在尾对齐时返回记录的 `ube_offset`，否则返回 `file_size - ube_total_size`（要求 `>= 136`），返回 `("eof")`（`riff.rs:221-225`；`envelope.rs:870-879`）。
5. 提示：适配器未覆写 `locate_with_hint`，`expected_header_magic` 被忽略，只使用 `expected_trailer_magic`（`adapters/mod.rs:218-225`、`wav.rs:51-57`）。引擎持密码时先试 stealth 尾魔数、再试 profile 魔数（`engine.rs:145-166`）。
6. 引擎统一收紧：`ube_total_size >= 136` 且 `ube_offset + ube_total_size <= 文件长度`（`engine.rs:191-207`）；随后用 `offset_delta` 与 trailer 坐标交叉核对（`engine.rs:2828-2902`）。`riff_chunk` 不允许像 PNG `chunk` 那样按定位结果平移 `inject_offset`，坐标不符即 `CorruptedData`（`engine.rs:2268-2296`）。

## 8 remove 还原

`WavAdapter`/`WebpAdapter` 不覆写 `strip`，使用默认实现：复制 `[0, inject_offset)`，跳过 `inject_size` 字节，再复制其余全部字节；若 `patch_offset != 0`，在输出流 `patch_offset` 处写回 `orig_patch_val`（`adapters/mod.rs:236-289`）。

- `riff_chunk`：跳过的是完整 `SHRD` 块（8 字节头 + UBE + 可能的补位）。注入时写入偏移 4 的 `new_riff_size` 已随 `[0, inject_offset)` 被复制，随后默认实现因 `4 < inject_offset` 在输出偏移 4 写回 `old_riff_size`，RIFF 总长度恢复原值；其余块与字节逐字不变。
- `eof`：只复制 `[0, host_len)`，`patch_offset = 0`，不存在需要修正的字段。
- 还原结果由 `verify_restored` 重新计算长度与 SHA-256，必须等于 header 中的 `orig_host_size` 与 `orig_host_sha256`，否则 `RestoreMismatch`（`engine.rs:2298-2312`）；失败时还会检查残留信封并提示按注入逆序删除。

## 9 边界与异常结构

- `LIST`/`INFO`：按普通顶层 chunk 处理，只读外层 4CC 与长度，不解析子块；`INFO` 子块与 `LIST` 内嵌结构原样保留，补位按外层长度判定（`riff.rs:180-218`、`:406-446`）。
- `fact`：不检查、不要求；WAV 的 L1 只要求 `fmt ` 与 `data`，`fact` 缺失不影响写入或定位。
- `data`：结构域不读取、不修改其内容；`SHRD` 总是追加在 `data` 之后。PCM 采样改动属内容域，不影响 `riff_chunk` 的偏移（音频内容域保持长度不变）。
- WebP `VP8X`：代码只比较 12 字节后的 4CC 是否为 `VP8X`（`riff.rs:36-47`），不解析 flags、canvas 尺寸、保留位或 `VP8X` 块长；损坏但标签正确的 `VP8X` 仍可进入 `riff_chunk`，L1 只按“存在图像块”兜底。
- 损坏 chunk：注入前 `riff_chunk_table` 返回 `None` 或 `MissingFinalPad` 即拒绝；`verify_structure` 对截断、越界、缺 pad 返回 `(false, 详情)`（`riff.rs:292-336`）；`locate` 扫描遇错只停止并尝试 EOF 回退，不报错。
- 流式 WAV（size = 0 / `0xFFFFFFFF`）：`riff_chunk` 拒绝，`auto` → `eof`；`verify_structure` 允许在 chunk 边界处的 EOF overlay，不要求声明边界等于物理末尾（`riff.rs:263-290`）。
- `suspicious_structures` 对任意长度的 `SHRD` 都报告（`riff.rs:348-386`），不设大小门槛，因此与 PNG 私有块的判定口径不同。

## 10 I 级写侧与自检

- **I 级**：复制缓冲区大小、是否边读边写、扫描是否缓存、`strategy_note` 文案与错误文本可由实现决定；写入的字节布局、块名、补位、size 更新与 `offset_delta` 不由实现更改。
- 写序列：写前 L1 校验（`engine.rs:1027-1035`）→ `riff_inject` 写新 RIFF 头、复制原 chunk 区、追加 `SHRD` → 引擎在 `actual_ube_offset` 回填 header、在默认 trailer 位置回填尾标（`engine.rs:1428-1441`）。RIFF 不覆写 `finalize`，无 CRC 类后处理（`adapters/mod.rs:364-370`）。
- 写后自检：`locate` 必须返回本次写入的精确坐标 `(actual_ube_offset, ube_total_size)`，否则中止且不提交半成品（`engine.rs:1454-1472`）；文件落盘为临时文件 + 原子重命名（`engine.rs:1601`）。
- 回归测试：`tests/test_regression/review_20261025.rs:123-175` 固定 `inject_offset = host_len`、`patch_offset = 4`、`inject_size = 8 + ube_total_size` 与 locate 返回 `(host_len + 8, ube_total_size)`；`:186-` 覆盖末块缺 pad 的写前拒绝。`tests/test_lifecycle/matrix.rs:734-793` 覆盖 Simple WebP 的 `auto → eof` 与显式 `riff_chunk` 拒绝；`:798-` 覆盖流式 WAV 哨兵 size 经 `eof` 后 L1 仍通过。
