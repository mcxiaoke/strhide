# PDF 结构域适配器：增量更新（incremental）

本文件规定 `format_name = "PDF"` 的结构域（UBE）适配器。信封布局见 [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md)（`offset_delta` 见其 §12，策略 ID 见其 §14）；容量口径汇总见 [CAPACITY.md](CAPACITY.md) §4。引用写作 `文件:行`（相对仓库根）。`WIRE_SPEC_STRUCTURE.md` 仅为历史对照，冲突以本目录为准。

## 1 范围、导航与稳定性

载体为 ISO 32000-1 PDF。适配器不解析页面树、内容流、对象流或 xref 条目，只读取文件尾部的 `startxref`/`%%EOF`/trailer 文本，并追加一个合规的增量更新。UBE 作为普通流对象的载荷嵌入。

| 级别 | 本域内容 |
| --- | --- |
| **F** | `%PDF-` 探测（`pdf.rs:8`、`:672-684`）；最后 `%%EOF` 的 1 MiB 反向搜索（`pdf.rs:121`、`:143-155`）；`startxref`/trailer 的 64 KiB 窗口（`pdf.rs:308`）；XRef 流字典的 8 KiB 窗口与平衡 `<<>>` 解析（`pdf.rs:214`、`:177-198`）；`/Size`、`/Root`、`/Encrypt` 的取值规则；对象头模板与 `END_OBJ`（`pdf.rs:589-591`、`:784`）；经典 `xref`/`trailer` 与 XRef 流两种增量段布局（`pdf.rs:793-865`）；`/Prev` 链；`offset_delta = 46 + digits(N) + digits(L)`（`pdf.rs:589-591`、`:1171-1188`）；`%%EOF` 后的 EOL 吸收（`pdf.rs:313-320`）；脏尾保留位置（`pdf.rs:873-874`）；策略 ID `incremental = 6`、`eof = 1`（`registry.rs:91`、`:96`） |
| **D** | 仅尾魔数/头魔数（标准、Profile 方言、stealth 派生）；由 `locate`/`verify_structure` 的 `expected_trailer_magic` 传入，不改变几何（`engine.rs:145-166`） |
| **I** | 64 KiB/8 KiB/1 MiB 等扫描窗口取值（`pdf.rs:120-121`、`:214`、`:308`）；`strategy_note` 与容量文案（`pdf.rs:708-740`、`:1070-1080`）；候选 `endstream` 的枚举方式 |

## 2 格式识别（detect）与写前拒绝

`detect` 只比较偏移 0 处的 5 字节 `%PDF-`（`pdf.rs:8`、`:672-684`）：记录流位置 → `seek(Start(0))`（失败即 `false`）→ `read_exact` 前 5 字节（不足即 `false`）→ 等于 `PDF_MAGIC` 才返回 `true`（`pdf.rs:673-681`）→ 恢复原位置（`pdf.rs:682`）。

因此：合法的前置垃圾或 BOM 使 `%PDF-` 不在偏移 0 的 PDF **不会**被识别（多数阅读器容忍头位于前 1024 B 内，代码更严格）；`%PDF-1.x` 版本号不解析；扩展名无关。适配器在 `ADAPTERS` 中排在 ZIP 之后（`registry.rs:25-36`）。

结构门槛由 `find_last_eof`（`pdf.rs:108-160`）承担：

- 若物理尾部存在与文件尾精确吻合的 EOF 信封（用期望尾魔数解包，`ube_offset + ube_total_size == file_size`），有效尾部退到 `t.ube_offset`（`pdf.rs:124-141`）；
- 否则从 `file_size` 向前最多 1 MiB（`pdf.rs:121`、`:143`），按 64 KiB 分块（`pdf.rs:120`）反向查找**最后一次**出现的 `%%EOF`（`pdf.rs:145-155`）；找不到即 `CorruptedData("Valid PDF %%EOF marker not found within tail window")`（`pdf.rs:157-159`）。

多个 `%%EOF`/xref 的“增量更新链”不逐节遍历：只取最后一次标记与其前最近的 `startxref`（`pdf.rs:322-334`）；更早修订仅通过 64 KiB 尾部窗口影响 `/Root`、`/Info` 的兜底取值（`pdf.rs:440-445`）。

线性化 PDF：代码不识别 `/Linearized` 字典或 hint 表，不做任何特判；按普通增量更新处理（新修订位于文件尾，阅读器以最后的 `startxref` 为准），hint 表与线性化参数保留原值、不再匹配。

加密 PDF：**增量策略的拒绝条件**（`parse_pdf_trailer_info`，`pdf.rs:50-96`）为下列任一成立：

1. 最新 trailer（经典 `trailer` 或 XRef 流字典）中出现**间接引用** `/Encrypt N G R` → `CorruptedData("PDF is encrypted (/Encrypt in the newest trailer)…")`（`pdf.rs:60-66`、`:390`、`:245`）；
2. 下一个对象号无法确定（无 `/Size` 且无 `N G obj` 可扫描）→ `pdf.rs:68-72`；对象号 `>= 0x7FFF_FFFF`（2,147,483,647）或 `>= u64::MAX - 1` → `pdf.rs:73-77`；
3. 无法确定 `/Root` → `pdf.rs:82-86`；
4. 找不到 `%%EOF`、`startxref` 或 `startxref` 整数不可解析 → `pdf.rs:157-159`、`:323-334`。

`/Encrypt` 只认最新 trailer，且**不**沿 `/Prev` 回溯（`pdf.rs:39-44`、`:435-439`）：最新 trailer 漏写 `/Encrypt` 的文档不会被判为加密；`/Encrypt << … >>` 这类直接字典也匹配不到 `find_indirect_ref`（`pdf.rs:514-529`）。加密判定的唯一后果是 `incremental` 不可用、`auto` 退 `eof`（`pdf.rs:697-705`）；`eof` 策略本身不读 trailer。

带数字签名的 PDF 在任何字节落盘前被独立守卫拒绝：流式扫描同一 64 KiB+1 KiB 重叠窗口内的 `/ByteRange` 与 `/Sig`（含 `/Type /Sig`、`/Type/Sig`）（`rejection.rs:158-209`、`:395-397`）。

## 3 支持策略与 auto

| 名称 | `strategy_id` | 行为 | 出处 |
| --- | --- | --- | --- |
| `incremental` | 6 | 在旧 `%%EOF` 之后追加流对象、增量 xref 段与新 `%%EOF`，信封作为流载荷 | `pdf.rs:742-877`；`registry.rs:96` |
| `eof` | 1 | 委托 `EofAdapter`，UBE 追加在整个文件物理末尾（脏尾之后） | `pdf.rs:749-751`；`eof.rs:35-56`；`registry.rs:91` |

`auto` 只调用一次 `choose_auto_strategy(host, exact_ube_size)`，不重试（`engine.rs:1242-1246`）：`parse_pdf_trailer_info` 成功且 `pdf_obj_header(new_obj_num, ube_size).len() <= MAX_OFFSET_DELTA(128)` → `incremental`；其余（含解析失败、加密、头长度超 128）→ `eof`（`pdf.rs:690-706`；`envelope.rs:81`）。显式策略必须属于 `supported_strategies`（`pdf.rs:686-688`、`engine.rs:1248-1253`），否则引擎报 `UnsupportedFormat`。

## 4 注入布局

UBE **位于新的增量更新段内部**（`%%EOF` 之前），不是追加在最终 `%%EOF` 之后；写入顺序（`pdf.rs:768-874`）：

```text
[0, eof_offset)                          原样复制：含旧 %%EOF 与其后至多 16 B 的 CR/LF
                                          （eof_offset = 标记起点+5+换行数，pdf.rs:313-320）
eof_offset                               inject_offset
+ obj_header                             "\n{N} 0 obj\n<< /Type /Metadata /Length {L} >>\nstream\n"
                                         （pdf.rs:589-591，前导 \n 归入 offset_delta）
+ UBE                                    header 112 B … trailer 24 B（原样写入）
+ "\nendstream\nendobj\n"                18 B（pdf.rs:784）
+ xref 段                               经典或 XRef 流，见下
+ 脏尾                                  原 [eof_offset, EOF) 逐字节复制到新段的 %%EOF 之后
                                         （pdf.rs:873-874）
```

- `offset_delta` 精确值为 `pdf_obj_header(N, L).len() = 46 + digits(N) + digits(L)`：`46` 为模板定长部分，`digits` 为十进制位数（`pdf.rs:589-591`；测试口径 `pdf.rs:1171-1188`）。`inject_offset + offset_delta` 即信封首字节，引擎据此写回 trailer 坐标（`engine.rs:1407`、`:1428-1441`）。
- 对象号 `N = new_obj_num`：经典文档取最新 trailer 的 `/Size`（`/Size` 定义为最大对象号+1，`pdf.rs:336-343`、`:384-391`）；XRef 流文档取流字典 `/Size`（`pdf.rs:405-419`）；两者都失败时用 64 KiB 窗口内 `max(N)+1`（`pdf.rs:420-431`）、`:535-579`）。锚点非经典时对 `/Size` 与扫描值取较大者，避免陈旧 `/Size` 撞号（`pdf.rs:422-431`）。
- 经典段（最新 xref 锚点为 `xref` 关键字，`pdf.rs:262-289`）：`xref\n{N} 1\n{actual_obj_offset:010} 00000 n \n`，随后 `trailer\n<<\n/Size {N+1}\n`、可选 `/Root`、`/Info`、`/Prev {prev_startxref}\n>>\nstartxref\n{xref_offset}\n%%EOF\n`（`pdf.rs:846-864`）。`actual_obj_offset = inject_offset + 1` 指向 `N 0 obj` 的起始字节（`pdf.rs:776`、`:822-826`）。
- XRef 流段（最新锚点为 `N G obj` 且字典含 `/Type /XRef`，`pdf.rs:363-370`、`:237-239`）：新增对象 `M = N + 1`，字典含 `/Type /XRef`、`/Size {M+1}`、`/W [1 4 2]`、`/Index [N 2]`、`/Root`、`/Info`、`/Prev {prev_startxref}`、`/Length 14`；14 B 数据为两条 `type=1 | offset(4B BE) | gen=0(2B)` 记录，偏移依次为 `actual_obj_offset` 与 `xref_offset`；结尾 `\nendstream\nendobj\nstartxref\n{xref_offset}\n%%EOF\n`（`pdf.rs:802-830`）。方言必须与最新修订一致，经典文档不会收到 XRef 流（`pdf.rs:787-792`、`:1441-1448`）。
- `xref_offset = inject_offset + obj_header.len() + ube_size + 18`（`pdf.rs:791`）：经典段中它指向 `xref` 关键字，XRef 流段中指向 `M 0 obj`。
- 不新增页树对象，不改旧 trailer，只增加一次修订；`inject` 返回 `(eof_offset, inject_size, 0, 0)`（`pdf.rs:876`），`inject_size = 对象头 + ube_size + 18 + xref 段长度`（`pdf.rs:867`）。文件增长恰为 `inject_size`；脏尾不计入注入区，只被整体后移后逐字节复制（`fixes.rs:408`）。
- 阅读器容忍：新段完全遵循 ISO 32000-1 增量更新（末 `%%EOF` → 其前 `startxref` → `/Prev` 指向旧 xref，旧字节仍按原偏移有效）。新 `%%EOF` 仍是全文件最后一次标记（脏尾按定义不含 `%%EOF`，否则会被 `find_last_eof` 选中，`pdf.rs:143-155`），因此尾部脏数据如同追加垃圾，仅被忽略。

## 5 容量与上限

`strategy_capacities` 对两策略均报 `capacity_bytes = None`、`limit = "unlimited (file grows)"`（`pdf.rs:709-739`）。`incremental` 的 `available` 取决于当前载体能否 `parse_pdf_trailer_info`：失败即 `false` 并提示退 `eof`（`pdf.rs:716-729`）；静态查询（`reader == None`）一律 `available = true`。

真实硬约束（按代码）：

```text
offset_delta = 46 + digits(N) + digits(L) <= 128       // 否则 auto 退 eof；显式 incremental 报错
N <= 0x7FFF_FFFE                                       // parse 拒绝 >= 0x7FFF_FFFF
经典 xref：actual_obj_offset <= 9_999_999_999          // 10 位定宽字段，>= 10^10 拒绝
XRef 流：  xref_offset < 2^32                          // 4 B 定宽偏移，>= 4 GiB 拒绝
有效载荷 <= clamp(256 × host_len, 64 MiB, 1 GiB)        // 引擎读侧上限
```

- 128 B 位移上限（`MAX_OFFSET_DELTA`，`envelope.rs:88`）约束的是“对象号 + `/Length` 的十进制位数”，不是载荷容量：两个 10 位十进制数即 66 B，旧值 64 会把这条合法路径打死。超出时 `auto` 退 `eof`（`pdf.rs:692-706`），显式 `incremental` 在引擎报 `General("… exceeds the 128 bytes the header can record")`（`engine.rs:1303-1310`）。
- 对象号上限与经典 10 位字段分别在解析期与写入期失败：`UnsupportedFormat("… larger than 10 GB …")`（`pdf.rs:839-845`）；XRef 流 4 GB 失败为 `UnsupportedFormat("… larger than 4 GB …")`（`pdf.rs:795-801`）。
- `inspect` 把 `None` 钳到 `structure_payload_limit(host_len) = clamp(256 × host_len, 64 MiB, 1 GiB)`（`engine.rs:1938-1943`、`:1952-1975`；`crypto.rs:786`），故报告值通常为 1 GiB 或 67,108,864。读侧对 `raw_size` 执行同一上限（`engine.rs:1996`），超过则在读取时拒绝。
- UBE 下界：`locate` 候选必须满足 `ube_offset >= 8`（`pdf.rs:644-648`）与 `ube_total_size >= 136`（`engine.rs:199-201`）；实际可产出的最小加密信封为 214 B（`min_ube_len(1)`，`STRUCTURE-ENVELOPE.md` §16）。

## 6 locate 路径与方言提示

`locate` 先校验 `%PDF-`（`pdf.rs:884-888`），再按两条路径（`pdf.rs:879-935`）：

1. **incremental**：`find_last_eof` 成功后，在其前 64 KiB 窗口内**从后向前**枚举 `endstream`（`pdf.rs:898-923`），对每个位置用 `try_locate_endstream` 验证：在 `endstream` 之前 24+3 B 窗口内允许 0..3 个尾随 CR/LF，解包 24 B 尾标并要求 `trailer.ube_offset + ube_total_size == abs_stream_end`、`ube_offset >= 8`，再读 `ube_offset - 8` 的 8 B 确认以 `stream\r\n`、`stream\n` 或 `stream` 结尾（`pdf.rs:613-665`）。命中返回 `(ube_offset, ube_total_size, "incremental")`。
2. **eof**：`EnvelopeTrailer::read_from_tail` 命中且 `ube_offset + ube_total_size == file_size` → `(ube_offset, ube_total_size, "eof")`（`pdf.rs:927-932`）。
3. 否则 `Ok(None)`（`pdf.rs:934`），非错误。

UBE 起点直接取尾标记录值，不经 `inject_offset + offset_delta` 反推；后者只在校验阶段使用（`engine.rs:2268-2296`）。路径 1 的窗口以“最后一次 `%%EOF` 的标记起点”为终点（`pdf.rs:899-905`），可跨越先前修订，但只从后向前取第一个通过校验的 `endstream`；它不校验该流属于哪一次修订，也不解析 xref（损坏的 xref 不影响定位）。

`locate_with_hint` 默认忽略 `expected_header_magic`，PDF 未覆写（`adapters/mod.rs:218-225`）。引擎在有密码时先以 stealth 尾魔数、再以 Profile 尾魔数调用（`engine.rs:145-166`）；候选最终由 `confine_location` 校验 `ube_total_size >= 136` 且 `ube_offset + ube_total_size <= file_len`（`engine.rs:191-207`）。

## 7 remove 还原

PDF 不覆写 `strip`，使用引擎默认实现（`adapters/mod.rs:236-290`）：复制 `[0, inject_offset)` → 跳过 `inject_size` 字节 → 复制剩余全部；`patch_offset == 0` 故无字段回滚（`pdf.rs:876`、`engine.rs:2255`）。对两种策略均成立：

- `incremental`：跳过对象头 + UBE + `endstream/endobj` + xref 段，脏尾（位于 `inject_offset + inject_size` 之后）被逐字节接回，得到 `[0, eof_offset) + 脏尾` = 原文件；旧 `%%EOF` 与换行已包含在前缀内（`pdf.rs:313-320`、`:873-874`）。
- `eof`：`inject_offset = host_len`、`inject_size = ube_len`，剩余为空，还原为原文件（`eof.rs:48-56`、`:74-83`）。

前置校验：`strip_coordinates_for_location` 要求 `inject_offset + offset_delta == ube_offset`，`incremental` 不在 `chunk`/`eof` 平移豁免内，不一致即 `CorruptedData`（`engine.rs:2268-2296`）；`envelope_coordinates_agree` 另要求 `ube_total_size <= inject_size` 且注入区不越过文件尾（`engine.rs:2828-2902`）；`patch_offset` 由 `validate_against` 约束（`STRUCTURE-ENVELOPE.md` §3.2）。还原后重算大小与 SHA-256，必须等于 `orig_host_size`/`orig_host_sha256`，否则 `RestoreMismatch`（`engine.rs:2299-2361`）。

## 8 边界情形

| 情形 | 行为 |
| --- | --- |
| xref 表内容损坏 / `startxref` 缺失 | 仅表内容损坏时解析不校验表，`incremental` 仍可用；`startxref` 缺失或整数不可解析时 `incremental` 不可用、`auto` 退 `eof`，L1 报 "Corrupted PDF structure"（`pdf.rs:323-334`、`:944-971`）。已写入的增量信封只要 `%%EOF` 与 `stream` 前缀完好仍可被 `locate` 找到（不解析 xref） |
| 增量更新链（多个 `%%EOF`/xref） | 只解析最后一次 `%%EOF` 与其前 `startxref`；`/Prev` 不遍历，旧 trailer 仅在 64 KiB 窗口内作为 `/Root`、`/Info` 兜底（`pdf.rs:440-445`） |
| 注释中出现 `%%EOF` | 若位于真实标记之后，反向搜索会把它当作边界，`eof_offset` 落入注释，注入点随之前移；若真实标记仍是最后一次出现则无影响（`pdf.rs:143-155`） |
| 注释中出现 `trailer`/`startxref` | `rfind` 可能截断 trailer 切片；随后由 `N G obj` 扫描与尾窗 `/Root` 兜底恢复，或整体解析失败（`pdf.rs:322-334`、`:384-391`、`:420-431`） |
| 二进制流中出现 `obj`/`startxref` 文本 | 64 KiB 窗口按 UTF-8 lossy 文本匹配，可能误判对象号；`/Size` 与扫描值取较大者、锚点仅认 `xref`/数字开头且需 `/XRef` 字典，可缓解但不能完全排除（`pdf.rs:262-289`、`:363-370`、`:422-431`） |
| 线性化 PDF | 无特判、不拒绝；新修订追加在后，线性化 hint 表保持旧值、不再自洽 |
| 加密 PDF（最新 trailer 含间接 `/Encrypt`） | `incremental` 拒绝、`auto` 退 `eof`；`eof` 信封不改动 trailer，阅读器仍可解密正文（`pdf.rs:60-66`、`review_20261025.rs:441-494`） |
| 尾部脏数据 | 原样保留在新 `%%EOF` 之后，注入不吞掉任何原有字节（`pdf.rs:869-874`、`fixes.rs:408`）；脏尾大于 128 KiB 仍可定位（`review_20261025.rs:350`） |
| `eof` 信封大于 1 MiB | 1 MiB 搜索窗可能凑不到旧 `%%EOF`，路径 1 跳过；路径 2 仍以尾标命中（`pdf.rs:121`、`:927-932`；`p2_protocol.rs:432`） |
| `%PDF-` 不在偏移 0 | `detect` 失败，不会被选为 PDF 载体（`pdf.rs:672-684`） |

`suspicious_structures` 另做无密码结构扫描：尾部 128 KiB 内“`endstream` 前 24 B 尾标形状 + `stream` 前缀”或“`%%EOF` 之后 24 B 尾标形状”各报一条，下界 `112 + 24`（`pdf.rs:973-1055`、`:974`）。

## 9 写侧 I 级与自检

- **流式复制**：`copy_exact` 以 64 KiB 缓冲搬运，短读即 `CorruptedData("Unexpected EOF while copying stream")`（`io.rs:11-30`；`pdf.rs:769-781`）。
- **不重编码**：`[0, eof_offset)`、旧 `%%EOF`、脏尾、`/Root`/`/Info` 引用文本均逐字节复制或原样引用，仅新增对象与 xref 段（`pdf.rs:768-874`）。
- **写后自检**：flush 后以本次尾魔数重跑 `locate`，要求返回坐标恰为 `(actual_ube_offset, ube_total_size)`，否则整体失败、不提交半成品（`engine.rs:1454-1472`）。
- **L1**：`verify_structure_with_magic` 只解析尾部；缺少 `/Root` 的最新 trailer 不算损坏（可由 `/Prev` 继承），仅在详情中说明增量写入被禁用（`pdf.rs:944-971`；`p2_protocol.rs:319-364`）。
- **I 级差异**：`strategy_note` 文案（`pdf.rs:1070-1080`）、容量 `limit`/`note` 措辞（`pdf.rs:708-740`）、扫描窗口与候选枚举实现均不进入线格式，读侧不依赖。
- **自检命令**：`cargo test --all-features --all-targets`（PDF 用例 `pdf.rs:1119-1466`、`p2_protocol.rs:130-364`、`review_20261025.rs:350-494`、`fixes.rs:408`）；`python scripts/baseline_hash.py --check` 比对 `structure.strategy = incremental` 与 `stego_size - orig_size`。
