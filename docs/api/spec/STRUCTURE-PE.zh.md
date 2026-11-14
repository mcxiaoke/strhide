# STRUCTURE-PE：Windows PE 适配器（pe_overlay / pe_codebits / pe_slack）

本文件规定 `format_name = "PE"` 的结构域（UBE）适配器。112B 信封头、24B 尾标、AAD、策略 ID 等公共布局不在本文重复，见 [STRUCTURE-ENVELOPE.zh.md](STRUCTURE-ENVELOPE.zh.md) §2–§15；限额速查见 [CAPACITY.zh.md](CAPACITY.zh.md) §4（`WIRE_SPEC_STRUCTURE.md` 仅为历史对照，冲突以本目录为准）。本文所有布局与常量均以 `rust/src/structure` 的可执行代码为准。

## 1 范围、导航与稳定性

适用载体：DOS `MZ` 头 + NT `PE\0\0` 签名的 Windows 可执行映像（EXE、DLL、SYS、SCR 等不按扩展名区分）。三种策略共用同一适配器与同一信封：

| 策略 | `strategy_id` | 形态 | 文件大小 |
| --- | --- | --- | --- |
| `pe_overlay` | 7 | 在文件 EOF（PE 映像边界之后）追加完整 UBE | 增长 `ube_total_size` |
| `pe_codebits` | 8 | 将 UBE 逐比特编码进 `.text` 指令等价编码；还原 diff 存入零值 padding | 不变 |
| `pe_slack` | 9 | 将完整 UBE 覆盖写入节对齐 padding | 不变 |

策略 ID 的唯一事实来源是 `rust/src/structure/registry.rs:90-104`；适配器声明见 `rust/src/structure/adapters/pe.rs:148-169`。

| 级别 | 本域内容 |
| --- | --- |
| **F** | `MZ`/`PE\0\0` 识别门槛；PE32/PE32+ 可选头魔数 `0x10B`/`0x20B` 与 Security 目录偏移；策略名与 ID 7/8/9；overlay 注入点与尾标定位条件；slack 区间推导；`ChannelHeader` 14B 布局、掩码与 176 槽前缀；diff 位图布局；codebits 指令形态与过滤规则 |
| **D** | `StructureProfile` 的头/尾魔数、默认密钥、stealth 域；它们改变 `pe_slack` 的头魔数校验、`pe_codebits` 的信道魔数与掩码 IKM 是否可公开推导；构建特性 `structure-pe` 决定 `pe_codebits` 是否存在 |
| **I** | 容量/`strategy_note` 文案；扫描与复制缓冲区大小；自动策略只决定“先试哪一个”；`slack_off` 超 4 GiB 时的拒绝文案；写侧对已有 overlay 的警告而非拒绝 |

F 级改动会令既有载体不可读或破坏字节级基线；D 级换值产生互不可读的新方言；I 级读侧不得依赖。

## 2 格式识别（detect）

`detect` 调用 `parse_pe_headers`，成功即返回 `true`，并恢复调用前的流位置（`rust/src/structure/adapters/pe.rs:138-146`）。识别顺序与门槛：

1. 文件长度 `< 0x40`、偏移 0 非 `MZ`、`e_lfanew` 不满足 `>= 0x40` 且 `e_lfanew + 24 <= host_size`、或 `e_lfanew` 处非 `PE\0\0`，任一成立即拒绝（`pe.rs:28-62`）。
2. 20B COFF 头：`NumberOfSections` 在 `+2..+4`，`SizeOfOptionalHeader` 在 `+16..+18`（`pe.rs:64-68`）。
3. 可选头魔数 `0x10B` 记 `PE32`、`0x20B` 记 `PE32+`；其他值记 `Unknown` 但不在此处拒绝（`pe.rs:73-87`）。
4. Security 目录：PE32 在可选头 `+128`，PE32+ 在 `+144`；仅当 `size_of_optional_header >= offset + 8` 时读取，VA 与 size 均非零即 `has_authenticode = true`（`pe.rs:89-101`）。
5. 节表起点 `e_lfanew + 24 + size_of_optional_header`；逐节读 40B 头，取 `raw_size(+16)` 与 `raw_ptr(+20)`，`pe_image_end = max(e_lfanew + 24 + opt_size, raw_ptr + raw_size)`；节头读失败即提前停止（`pe.rs:104-120`）。

**拒绝条件与边界**：`detect` 不校验 DLL/EXE 特征位、节表完整性或 `.text` 是否存在，这些交由注入路径或 `pe_layout`；`parse_pe_headers` 不拒绝未知可选头魔数，但 `pe_geometry` 要求 `0x10B`/`0x20B`，否则 `NotPe`（`pe_layout.rs:125-132`）。签名 PE 能通过 `detect`，写侧在注入前拒绝（`pe.rs:391-395`），预写检查亦独立拒绝（`rejection.rs:381-393`）。若 `host_size < pe_image_end`，任何策略均拒绝（`pe.rs:397-402`）。

## 3 支持策略、关系与 auto

三种策略互斥使用，不组合写入：`pe_overlay` 为连续追加型，UBE 位于文件尾部，隐蔽性最差但容量无限；`pe_slack` 为连续覆盖型，UBE 必须完整落在**单个**零值 padding 区间内，文件大小不变；`pe_codebits` 为散落型，UBE 没有连续文件偏移，`inject_offset = inject_size = 0`，引擎不得按文件偏移回写信头/尾标（`mod.rs:196-204`、`engine.rs:1420-1452`）。

`choose_auto_strategy` 对 PE 的实际优先级是 **`pe_slack` → `pe_overlay`**（`pe.rs:176-210`）；`pe_codebits` **不在 `auto` 的候选内**，只能显式 `-s pe_codebits`：

1. 若能解析节表且存在长度 `>= ube_len` 的连续零值 slack，选 `pe_slack`。
2. 否则选 `pe_overlay`。

为什么排除 `pe_codebits`：它用 iced 线性扫描 `.text`，只过滤 `Code::INVALID`，不建 CFG、不识别内联跳转表/常量表；被误判为指令的数据字节一旦落在改写槽位上，程序只会在读取该表的那条分支上出错，任何“写入后仍能运行”的冒烟测试都看不出来。它因此被定为**高级/显式**策略：`supported_strategies` 与 `inspect` 的列表都把它排在最后，并在 note 中标注 opt-in。

`auto` **不会**选择 `eof`；`eof` 仅在显式指定时使用，且注入行为与 `pe_overlay` 相同，只是 `strategy_id = 1` 且 locate 时不做“位于映像边界之后”的检查。`auto` 只做一次判定，失败不回退、不重试；显式策略不支持时由引擎返回 `UnsupportedFormat`（`engine.rs:1242-1255`）。

## 4 pe_overlay

### 4.1 几何与写入

`inject` 先完整复制宿主 `[0, host_size)`，再把 UBE 原样追加到新 EOF，返回 `(inject_offset = host_size, inject_size = ube_size, 0, 0)`（`pe.rs:416-422`）：

```text
[0, host_size)                 宿主原样（含已有 overlay）
[host_size, host_size+ube)     UBE（header ‖ hint ‖ meta ‖ payload ‖ trailer）
```

- **无对齐、不重排节表**：不按 `FileAlignment`/`SectionAlignment` 对齐，直接接在当前物理 EOF 之后；节头、节数据、证书表全部字节级保留。
- **已有 overlay 允许存在**：新 UBE 追加在旧 overlay 之后，旧 overlay 不被扫描或改写。仅在 `host_size > pe_image_end + 136` 时给出结构警告，不拒绝（`pe.rs:555-566`、`engine.rs:1368-1372`）。
- `offset_delta = 0`：PE 适配器未覆写 `envelope_offset_delta`（`mod.rs:345-352`、`engine.rs:1267-1278`）；尾标由引擎写在文件最后 24B（`mod.rs:354-359`）。

### 4.2 容量、签名与定位

- 容量无架构上限，`capacity_bytes: None`、`limit: "unlimited (file grows)"`（`pe.rs:346-351`）；`inspect` 最终仍受 `structure_payload_limit(host_len)` 钳制（见 [CAPACITY.zh.md](CAPACITY.zh.md) §3）。
- **会影响 Authenticode**：追加字节改变文件哈希，签名必然失效。注入前与预写检查均拒绝已签名 PE（`pe.rs:391-395`、`rejection.rs:381-393`）；容量报告把全部策略标为不可用（`pe.rs:362-372`）。
- `locate` 从文件尾部读 24B trailer，要求 `ube_offset >= pe_image_end` 且 `ube_offset + ube_total_size == file_size` 才返回 `"pe_overlay"`（`pe.rs:441-459`）；不满足第一条时可能落入通用 `eof` 分支（`pe.rs:471-479`）。还原按 `header.inject_offset` 截断（`pe.rs:530-536`）。

## 5 pe_codebits

仅在 `structure-pe` 特性下存在（`pe.rs:148-169`、`rust/src/structure/adapters/pe_codebits.rs:1`）。

### 5.1 可承载指令与槽位选择

线性解码 `.text` 扫描窗口 `[text_offset, text_offset + text_scan_len)`，其中 `text_scan_len = min(VirtualSize, SizeOfRawData)`（`pe_layout.rs:235-249`、`:386-402`）。逐条指令应用以下过滤（`pe_codebits.rs:204-306`）：

| 过滤 | 规则 | 出处 |
| --- | --- | --- |
| F0 | `iced` 解码为 `INVALID` 的字节（数据、跳转表等）跳过 | `:223-226` |
| F1 | 必须是语义对或可交换形式 | `:228-237` |
| F2 | 两个操作数都必须是裸寄存器（`mod = 11`）；内存/SIB/立即数操作数全部拒绝 | `:239-243` |
| F3 | TEST 的两个寄存器相等时不承载信息 | `:245-249` |
| F4 | 重新编码必须与原始字节完全一致，拒绝非最小编码/冗余前缀 | `:270-275` |
| F5 | 反向形式重新编码后的长度必须与原指令相同 | `:277-293` |

语义对覆盖 `ADD/ADC/AND/OR/XOR/SUB/SBB/MOV/CMP` 的 8/16/32/64 位寄存器-寄存器形式（`pe_codebits.rs:77-163`）：“store”形式 `op rm, r` 记 bit `0`，“load”形式 `op r, rm` 记 bit `1`；两者仅 opcode/ModR/M 方向不同，语义与长度相同。`TEST rm8/r8`、`TEST rm16/r16`、`TEST rm32/r32`、`TEST rm64/r64` 为可交换形式（`pe_codebits.rs:167-172`），其 bit 定义为 **`ordinal(r0) < ordinal(r1)`**，`r0` 是 `op0`（r/m）、`r1` 是 `op1`（reg），不得按汇编书写的左右顺序理解（`pe_codebits.rs:245-253`、测试 `:760-777`）。

槽位按扫描顺序逐一编号；通道字节流按 **MSB-first** 展开，第一个 bit 写入第一个可用槽位（`pe_codebits.rs:320-328`、`:623-657`）。每个改写都是等长替换，因此 `profile(text, bitness)` 在嵌入前后返回相同的位置列表（`pe_codebits.rs:198-206`、测试 `:805-827`）。

### 5.2 `ChannelHeader`（14B）

通道头占用前 112 个槽位，紧随其后 8 个 UBE 字节（64 槽）提供掩码 IKM；读侧必须扫描前 **176** 个槽位（`pe_codebits.rs:43-51`、`:460-477`）。

| 偏移 | 长度 | 字段 | 类型 | 掩码 | 说明 |
| --- | --- | --- | --- | --- | --- |
| 0 | 4 | `magic` | `[u8;4]` | 否 | 标准 = `STANDARD_TRAILER_MAGIC = 78 e6 66 d2`；stealth = 密码派生尾魔数 |
| 4 | 1 | `version` | u8 | 是 | 固定 `1`（`CHANNEL_VERSION`） |
| 5 | 1 | `flags` | u8 | 是 | 保留，写侧置 0；读侧不校验 |
| 6 | 4 | `ube_len` | u32 LE | 是 | 散落嵌入的 UBE 总字节数（含 24B trailer） |
| 10 | 4 | `slack_off` | u32 LE | 是 | diff 位图的绝对文件偏移 |

- 布局与打包见 `pe_codebits.rs:358-400`、常量 `:41-44`。魔数取 UBE 最后 4 字节（尾标魔数，`:602-604`）；掩码 IKM 取 UBE 前 8 字节，对应通道 bit 位置 112..176（`:466-476`、`:608-612`）。
- 掩码：`derive_channel_header_mask` 以 `IKM = envelope_header_magic(8B)`、`HKDF-SHA256(salt=None)`、`info = b"strhide-pe-channel-mask-v2"` 展开 10B；仅 `bytes[4..14] ^= mask[0..10]`（`rust/src/core/crypto.rs:342-348`、`pe_codebits.rs:393-400`）。
- 读侧校验：`header_from_positions` 先要求 `prof.len() >= 176`，否则视为无通道；`read_channel_header` 解掩码后要求 `magic` 等于期望值（或 `CHANNEL_MAGIC`）、`version == 1`、`136 <= ube_len <= 64 MiB`，**不校验全量容量**；`extract_ube` 读载荷时才要求槽位数 `>= (14 + ube_len) * 8`（`pe_codebits.rs:460-497`、`:541-554`、`:559-571`）。标准模式 IKM 公开，掩码仅为格式混淆；载荷机密性由 UBE 的 AEAD 层提供。

### 5.3 `slack_off` 指向的 diff 紧凑格式

diff 不是记录列表，而是**定长稠密位图**，没有 magic、长度、CRC 或任何字段头；其长度由 `ChannelHeader.ube_len` 隐式计算：

```text
diff_len = CHANNEL_HEADER_LEN + ube_len        （单位：字节，pe_codebits.rs:446-448、:777）
bit i    = 第 i 个通道槽位是否被改写       （i 从 0 起，按 profile 扫描顺序）
字节内    = MSB-first；set_bit 写 1 << (7 - (i % 8))（:320-350）
```

第 i 位为 1 表示写侧把第 i 个槽位从原形式翻转到等价形式；为 0 表示未改动。前 `14 * 8` 个 bit 同样覆盖信道头自身，还原时先读出头部再逐位回滚，因此头部槽位也回到原始宿主指令（`pe_codebits.rs:624-657`、`:665-723`）。

`slack_off` 的约束：

- 写侧必须是 `u32` 可表示；超出 4 GiB 拒绝（`pe.rs:716-722`）。
- 必须在当前节表推导出的某个零值 padding 区间内，且 `slack_off + diff_len` 不越过该区间；否则写侧找不到、读侧拒绝清零（`pe.rs:705-714`、`:779-793`）。

### 5.4 100% 还原、容量与风险边界

还原顺序（`pe.rs:770-818`）：重新解析布局并读取 `.text` → 解码 `ChannelHeader` 并计算 `diff_len` → 校验 `[slack_off, slack_off + diff_len)` 完整落在 padding 区间内 → 读取 diff 位图并用 `apply_diff` 将置位槽位翻回原形式 → 将同一区域写回全零、其余字节逐字节复制。引擎随后重算 `orig_host_size` 与 `orig_host_sha256`，与信封头记录值比对，不一致返回 `RestoreMismatch`（`engine.rs:2298-2361`、`:2305-2311`）。

`apply_diff` 自身也要求 diff 长度等于 `14 + ube_len`、当前 `.text` 槽位数不小于通道总位数，否则拒绝（`pe_codebits.rs:665-690`）。

容量（`pe.rs:248-283`）：

```text
cap_bits  = floor(可用槽位数 / 8) - 14
cap_slack = 最长连续零值 run - 14
capacity  = min(cap_bits, cap_slack)
available = capacity >= min_ube_len(1)        （1 字节载荷的最小可写 UBE，当前为 214B）
```

槽位需求为 `(14 + ube_len) * 8`，slack 需求为 `14 + ube_len`（`pe_codebits.rs:310-314`）。`MIN_UBE_LEN = 136` 只是读侧结构下界，不代表可写容量（`pe_codebits.rs:53-58`）。

**语义与崩溃边界**：本策略保证“被改写的指令在 x86/x64 解码语义上等价且长度不变”（F4/F5）。它不保证：

- 对 .NET / CLR IL、UPX 或加壳后的压缩数据、把数据混在 `.text` 中的自修改/跳转表代码仍能保持可执行语义；代码只按 `iced` 线性解码过滤，不建 CFG，也不识别 CLR/加壳。
- 对非 x86/x64 的机器类型可用；`Machine` 不是 `0x14C`/`0x8664` 时直接 `UnsupportedMachine`（`pe_layout.rs:229-233`）。

失败与重试：显式 `pe_codebits` 在容量/零值 slack 不足时返回硬错误，不自动改写为其他策略（`pe.rs:705-710`）。载体已有合法通道时，第二次 `pe_codebits` 注入被拒绝（`pe.rs:692-703`）。`auto` 根本不进入本策略，因此在默认路径上不存在“选错 `pe_codebits`”的可能。

## 6 pe_slack

### 6.1 slack 空间的位置

候选区间由节表推导，按文件顺序（`pe_layout.rs:161-200`）：

1. 节表末尾 `sec_table_end` 到第一个节 raw data 起点之间的空隙（若 `first_raw > sec_table_end`，`pe_layout.rs:173-183`）；
2. 每个节的尾部：`raw_ptr + min(VirtualSize, SizeOfRawData)` 到 `min(raw_ptr + SizeOfRawData, host_size)`（`pe_layout.rs:184-193`）；
3. 再减去所有节实际使用的 `[raw_ptr, raw_ptr + min(VirtualSize, SizeOfRawData))`（`pe_layout.rs:162-170`、`:196-199`、`:203-223`）。

文件尾部 overlay 区域被**有意排除**（`pe_layout.rs:157-160`）。`VirtualSize == 0` 的节不产生尾部候选（`:185-187`）。因此 `pe_slack` 与 `pe_overlay` 的写入区域互不重叠。

### 6.2 写入、容量与还原

- 选择“能容纳 `needed` 的**最小**连续零值 run”（`pe_layout.rs:254-279`、`:406-465`）；负载必须完整落在单个区间内，写入前再次验证该 run 全零（`pe_layout.rs:535-545`、`pe_slack.rs:82-84`）。
- 注入是**原地覆盖**：复制 `[0, off)`、写入 UBE、复制 `[off + ube_size, host_size)`，返回 `(off, ube_size, 0, 0)`，文件大小不变（`pe_slack.rs:52-92`）。
- 容量 = 最长连续零值 run，`available = run >= min_ube_len(1)`（当前 214B），报 `capacity_bytes = run`、`limit = "<= N B (file size unchanged)"`（`pe.rs:308-330`）；136B 只用于 locate 合理性检查（`pe_slack.rs:195-197`）。
- 还原按 header 的 `inject_offset`/`inject_size` 校验区间不越界且完整位于某个 padding range，再复制前段、写入等长全零、复制后段（`pe_slack.rs:218-254`）；写前已验证全零，故字节级恢复成立。不依赖 `.text` 或机器类型，ARM64、.NET 等 PE 只要可选头为 `0x10B`/`0x20B` 即可用（`pe_layout.rs:112-155`、`:347-383`）。

## 7 locate 路径与 hint 交叉

`PeAdapter::locate` 的固定顺序为 **codebits → overlay → slack → eof**（`pe.rs:425-482`），引擎把结果再交给 `confine_location` 做物理包含检查（`engine.rs:191-207`）：

| 顺序 | 路径 | 证据 | 返回 |
| --- | --- | --- | --- |
| 1 | `ChannelHeader` | 解析 `.text` → `read_channel_header`；魔数不匹配即“无通道” | `(0, ube_len, "pe_codebits")`（`pe.rs:746-765`） |
| 2 | 尾部 trailer | `EnvelopeTrailer::read_from_tail`；`ube_offset >= pe_image_end` 且 `ube_offset + ube_total_size == file_size` | `"pe_overlay"`（`pe.rs:441-459`） |
| 3 | 扫描 padding | 在每个 slack 区间内搜索 trailer magic（偏移 20），`unpack` 校验魔数与 CRC；边界必须等于 `[ube_offset, trailer_start)`；整体在**单个**区间；标准信封还要求 8B header magic | `"pe_slack"`（`pe_slack.rs:101-214`） |
| 4 | 尾部 trailer | 仅要求 `ube_offset + ube_total_size == file_size` | `"eof"`（`pe.rs:471-479`） |

- `locate_with_hint` 未在 PE 适配器中覆写，因此引擎传入的 `expected_header_magic` 被忽略；PE 只消费 `expected_trailer_magic`（`mod.rs:218-225`、`engine.rs:137-172`）。
- `pe_codebits` 把该 trailer magic 用作 `ChannelHeader.magic` 的期望值；无密码/官方方言时退回 `CHANNEL_MAGIC`（`pe_codebits.rs:541-553`）。
- `pe_slack` 在 `expected_magic = None`（官方方言）时额外校验 header 前 8B 等于 `STANDARD_HEADER_MAGIC`；私有方言或 stealth 只依赖尾标魔数 + CRC（`pe_slack.rs:118-121`、`:207-212`）。
- 伪造尾标无法通过引擎坐标检查：`pe_overlay` 要求 `inject_offset + offset_delta == trailer.ube_offset`，`pe_slack` 同理，二者都不在 `chunk`/`eof`/`ebml_void` 的“允许平移”白名单内（`engine.rs:2867-2912`）。

## 8 remove 还原顺序与字节级一致性

单次 `remove` 只剥离一个信封，顺序由 `locate` 与 `strip` 共同决定：

1. `strip` 先按 `header.strategy_id` 分派：`pe_codebits` 优先，其次 `pe_slack`，最后按 `pe_overlay`/`eof` 的连续截断处理（`pe.rs:513-537`）。
2. `pe_codebits` 在同一遍内先回滚 `.text`（`apply_diff`），再把 `[slack_off, slack_off + diff_len)` 清零；`copy_with_patches` 只替换这两个互不重叠的区间，其余字节逐字节复制（`pe.rs:769-818`、`:609-653`）。
3. `pe_slack` 将信封覆盖的 padding 区间等长清零（`pe_slack.rs:218-254`）。
4. `pe_overlay`/`eof` 截断到 `header.inject_offset`（`pe.rs:530-536`）。
5. 引擎重算还原文件的长度与 SHA-256，与 AAD 内的 `orig_host_size` / `orig_host_sha256` 比对；失败时若仍能定位到信封或结构扫描命中，报告“存在残余信封”（`engine.rs:2298-2361`）。

堆叠信封必须按注入的逆序逐个 remove。PE 的 locate 固定先找 codebits，因此“codebits 在内、overlay 在外”时单次 remove 会先剥离内层，哈希校验将因外层仍在而失败；正常写侧会通过 `locate` 预先拒绝第二次注入，只有未知密码的 stealth 信封可能绕过该检查。

## 9 边界情形

| 情形 | 行为 |
| --- | --- |
| 已签名 PE | 所有策略拒绝写入；容量报告全部 `available = false`（`pe.rs:362-372`、`:391-395`） |
| 32 位 / 64 位 | PE32 Security 目录 `+128`，PE32+ `+144`；codebits 由 COFF `Machine` 决定 `bitness = 32`（`0x14C`）或 `64`（`0x8664`），不看可选头魔数（`pe_layout.rs:229-233`） |
| DLL / EXE / SYS / SCR | 不区分；不读取 COFF `Characteristics` 的 DLL 位，也不按扩展名限制 |
| .NET / CLR | 无专门检测；`pe_slack`/`pe_overlay` 可用；`pe_codebits` 对 IL 字节无语义保证，应视为不可用/危险 |
| UPX / 加壳 | 无检测；压缩或加密的 `.text` 可能被误判为可改写指令，`pe_codebits` 可能破坏可执行性；优先 `pe_slack`/`pe_overlay` |
| 节表异常 | 节表超出前 64 KiB 头窗口时 `pe_geometry` 返回 `NotPe`（`pe_layout.rs:295-301`、`:360-365`）；`raw_ptr + raw_size > host_size` 时注入拒绝；slack 区间一律按 `host_size` 截断 |
| 已有 overlay | 允许；`pe_overlay` 追加在旧 overlay 之后，`pe_slack` 不受影响；超过 `pe_image_end + 136` 时给出非致命结构警告（`pe.rs:555-566`） |
| 未知可选头魔数 | `detect`/overlay 路径仍可工作（`arch = "Unknown"`）；`pe_slack`/`pe_codebits` 不可用 |
| 空载荷 | `pe_codebits` 与 `pe_slack` 显式拒绝（`pe.rs:668-674`、`pe_slack.rs:59-63`） |
| `slack_off > 4 GiB` | `pe_codebits` 拒绝，避免 u32 截断后清零错误区域（`pe.rs:716-722`） |
| 已有合法 codebits 通道 | 第二次注入拒绝，避免覆盖首个信道头并孤立其 diff（`pe.rs:692-703`） |

## 10 I 级写侧与自检

写侧自由项不属于线格式：

- `choose_auto_strategy` 只决定首次尝试；显式策略由引擎校验是否在 `supported_strategies()` 内；不做同策略重试（`engine.rs:1242-1255`）。
- 容量报告对可写性统一使用 `min_ube_len(1)`（当前 214B），而非 136B 结构下界或 178B 保守值（`pe.rs:266-268`、`:312-315`、`rust/src/structure/envelope.rs:116-132`）。
- `strategy_capacities(reader = None)` 只给静态能力；`Some(reader)` 才测量本载体的 `.text` 槽位与最长零 run（`pe.rs:208-340`）。
- 写后自检：引擎 flush 后调用 `locate`，要求返回坐标与本次写入的 `(actual_ube_offset, ube_total_size)` 完全一致；`pe_codebits` 的坐标按定义为 `(0, ube_len)`（`engine.rs:1454-1475`）。
- `verify_structure` 只重新解析 PE 头/节表，不检查签名、不检查机器类型（`pe.rs:539-553`）；签名检查由 `rejection::check_content` 独立完成。

**PE / `pe_codebits` 专属自检命令**（在 `rust/` 下执行）：

```bash
cargo test --all-features --test test_pe codebits::   # codebits 集成套件（PE32/PE64/stealth/容量/篡改/双重注入）
cargo test --all-features --test test_pe slack::      # pe_slack 集成套件（auto 选择、零增长、字节级还原）
cargo test --all-features pe_codebits::tests::        # 指令形态、位序、掩码、diff 往返等单元测试
cargo test --all-features test_pe_authenticode_rejection  # 签名 PE 拒绝
```
