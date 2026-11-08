# PNG 结构域适配器：私有块注入（prIv）

本文件规定 `format_name = "PNG"` 的结构域（UBE）适配器。信头、尾标、AAD、策略 ID 等公共布局不在本文重复，见 [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2–§15 与 [CAPACITY.md](CAPACITY.md) §4（[WIRE_SPEC_STRUCTURE.md](../WIRE_SPEC_STRUCTURE.md) 仅为历史对照，冲突以本目录为准）；内容域（LSB/像素域）见 [CONTENT-PNG.md](CONTENT-PNG.md)，二者互不替代。

## 1 范围、导航与稳定性

载体为以标准 8 字节 PNG 签名开头的文件；适配器只读写块流，不解码像素。

| 级别 | 本域内容 |
| --- | --- |
| **F** | 8 字节签名 `89 50 4E 47 0D 0A 1A 0A`；策略名 `chunk`/`eof` 与 `strategy_id` 2/1；私有块类型 `prIv`；`[u32be len][type][data][u32be crc32]` 布局；注入点=最后一个 `IEND` 块起始；`offset_delta = 8`；CRC32 覆盖 `type‖data`；locate 的候选/位移接受规则 |
| **D** | 无。没有可选块、可选字段或版本分支；`stEg` 仅为读侧兼容别名，不写出 |
| **I** | 复制缓冲区大小、CRC 计算方式、`strategy_note` 文案、是否额外补块（当前不补）；读侧均不依赖 |

常量来源：签名与块名 `rust/src/structure/adapters/png.rs:11-15`，策略注册表 `rust/src/structure/registry.rs:90-104`，信封尺寸见 [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2。

## 2 格式识别（detect）

`detect` 只比较前 8 字节签名，成功与否返回 `bool`，不产生错误；它会恢复调用前的流位置（`rust/src/structure/adapters/png.rs:101-113`）。因此 8 字节短文件也能通过 detect，真正的结构门槛在注入前由 `find_iend_offset` 把关（`png.rs:27-92`）：

1. 文件长度 ≥ 8 + 12 = 20 B，否则 `CorruptedData("File too small to be a valid PNG")`（`png.rs:31-35`）；
2. 前 8 字节必须等于签名，否则 `UnsupportedFormat("Invalid PNG magic signature")`（`png.rs:39-43`）；
3. 从偏移 8 起按块头 4 字节大端长度跳跃；块头截断、`length > 0x7FFFFFFF`、加法溢出或下一块越过文件尾即停止扫描（`png.rs:48-76`）；
4. 只把 `length == 0` 的 `IEND` 记为候选并保留**最后一个**（`png.rs:78-83`）；扫完仍无候选则 `CorruptedData("Valid PNG IEND chunk not found")`（`png.rs:85-91`）。

若扫描在破坏点之前已记录过 `IEND`，函数会返回该较早偏移而不报错，其余字节按脏尾保留；这是有意的宽松行为。写入路径在调用注入前还会做一次全块 CRC 校验，非法宿主直接 `CorruptedData`（`rust/src/structure/engine.rs:1028-1035`、`png.rs:342-426`）。

## 3 支持策略与 auto

| 名称 | `strategy_id` | 行为 | 出处 |
| --- | --- | --- | --- |
| `chunk` | 2 | 在最后 `IEND` 前新建 `prIv` 辅助块，UBE 作为块数据 | `png.rs:13`、`:148-215`；`registry.rs:92` |
| `eof` | 1 | 委托 `EofAdapter`，在文件 EOF 后追加 UBE（含 IEND 后的脏尾之后） | `png.rs:155-157`；`eof.rs:48-55`；`registry.rs:91` |

`auto` 只看 UBE 精确尺寸：`ube_total_size > 0x7FFFFFFF` 时选 `eof`，否则选 `chunk`（`png.rs:119-125`）。它不测量载体余量，也不做除上述阈值外的重试/回退（引擎侧选择见 `engine.rs:1242-1255`）。显式策略不在列表内返回 `UnsupportedFormat`（`png.rs:159-163`）。

容量报告（`strategy_capacities`，`png.rs:127-146`）为 `chunk = 0x7FFFFFFF`、`eof = None`（无上限、文件增长）。`inspect` 会把两者统一钳到引擎载荷上限 `structure_payload_limit(host_len) = clamp(256 × host_len, 64 MiB, 1 GiB)`（`engine.rs:1938-1975`、`:2604-2611`），因此实际显示值通常远小于 2 GiB；基线中 stego 为 87,105 B 的 PNG 用例（原载体 86,854 B）两策略均报 `67,108,864`（`temp/baseline/baseline.json:757-777`）。

## 4 注入点与块布局

`chunk` 的注入区域紧接在最后一个 `IEND` 块头之前，即该 `IEND` 的全部字节（含其后的脏尾）原样后移（`png.rs:174-180`、`:211-212`）：

```text
偏移 inject_offset
  +0   u32be  length = ube_total_size
  +4   "prIv" (70 72 49 76)
  +8   UBE[0 .. ube_total_size)        ← offset_delta = 8
  +8+ube_total_size  u32be CRC32(type ‖ data)
```

- 块总长为 `ube_total_size + 12`，`inject` 返回的 `inject_size = 4 + 4 + ube_total_size + 4`（`png.rs:189-208`、`:214`）。
- CRC32-IEEE 覆盖 4 字节类型与块数据，大端写在数据之后；`inject` 边写边算（`png.rs:186-206`），`finalize` 在信头/尾标回填后再按同一范围重算（`png.rs:484-508`）。
- UBE 首字节相对注入点位移固定为 8（`chunk`），`eof` 为 0（`png.rs:475-482`），该值写入 header 的 `offset_delta` 并进入 AAD（`engine.rs:1267-1278`）。
- `prIv` 的 4 个类型字节为 `70 72 49 76`；按 PNG 大小写位：首字母小写 = ancillary(1)，第二字母小写 = public(0)，第三字母大写 = reserved bit 0，末字母小写 = safe-to-copy(1)。代码与 CLI 文案称其为 “private ancillary chunk” 属功能性称呼，不改变上述位值。
- 其余块不重排、不重编码；IEND 及其后的任意字节逐字节复制（`png.rs:211-212`）。`eof` 策略下 IEND 与脏尾保持在原位置，UBE 追加在文件末尾（`eof.rs:48-55`）。

## 5 信封偏移、容量与下界

`actual_ube_offset = inject_offset + offset_delta`（`engine.rs:1407`）；`trailer_offset` 使用默认实现 `ube_offset + ube_total_size - 24`，即尾标位于 `prIv` 数据区最后 24 字节（`adapters/mod.rs:357-359`、`engine.rs:1432-1441`）。写后自检要求 `locate` 必须返回 `(actual_ube_offset, ube_total_size)`，否则中止写入（`engine.rs:1454-1472`）。

```text
chunk: 增长字节数 = 12 + ube_total_size；单块上限 0x7FFFFFFF
eof:   增长字节数 = ube_total_size；无块长度上限
注入区域关系: ube_total_size <= inject_size；注入区末尾 <= 文件长度
```

容量不来自“可用空隙/填充”：适配器不复用已有零填充或私有块空间，始终新建块，因此没有按载体测量的容量函数（`png.rs:127-146`）。写侧真正生效的是载荷上限：`raw_size <= structure_payload_limit(orig_host_size)`（`engine.rs:1123`）。UBE 下限分两层：`locate`/`confine` 的结构下界为 `112 + 24 = 136`（`engine.rs:199-201`、`png.rs:268`、`:431`）；实际可产出的最小加密信封为 214 B（`min_ube_len(1)`，`rust/src/structure/envelope.rs:123-140`）。显式 `chunk` 遇到 `ube_total_size > 2 GiB − 1` 时注入失败并提示改用 `--strategy eof`（`png.rs:168-172`）；`auto` 已在选择阶段改走 `eof`。

## 6 locate 路径与方言提示

`locate_with_hint` 按三条路径依次尝试（`png.rs:225-340`）：

1. **正向块扫描**：签名校验后从偏移 8 逐块读取 8 字节块头，不做 CRC 校验（`png.rs:238-268`）。对类型为 `prIv` 或 `stEg` 且 `length >= 136` 的块，读取 `data_offset + length - 24` 处的 24 字节尾标，用期望 trailer 魔数解包（`png.rs:268-275`）。
2. **自描述确认**：仅当 `trailer.ube_total_size == length` 且满足下列之一才接受：`trailer.ube_offset == data_offset`（精确）；或该块数据前 8 字节等于期望 header 魔数（内容域 IDAT 重压缩导致的物理位移）。返回 `(data_offset, length, "chunk")`（`png.rs:283-299`）。仅凭尾标而不核对块自身的旧实现在此处被拒绝。
3. **EOF 回退**：从文件尾读 24 字节尾标，`locate_start(file_size)` 在尾对齐时返回记录偏移，否则返回 `file_size - ube_total_size`；同样要求精确或魔数匹配（`png.rs:319-337`；`envelope.rs:870-879`）。返回 `(start, ube_total_size, "eof")`。

魔数提示（hint）没有版本字段：入口是 `expected_header_magic: Option<[u8; 8]>` 与 `expected_trailer_magic: Option<&[u8; 4]>`；未提供头提示时默认 `STANDARD_HEADER_MAGIC`（`png.rs:235-237`；`adapters/mod.rs:218-225`）。引擎在持密码时先试 stealth 派生魔数、再试 profile 魔数（`engine.rs:145-166`）。`confine_location` 统一再校验 `ube_total_size >= 136` 且 `ube_offset + ube_total_size <= 文件长度`（`engine.rs:191-207`）。

特殊结构：串接 PNG 流在块头位置出现签名时被跳过（`png.rs:56-59`、`:305-315`）；`locate` 遇到 `IEND` 时若其后 8 字节仍是签名则继续扫描，否则停止，因此写在**最后一个** `IEND` 前的信封总能被找到。CgBI（Apple 私有块位于 IHDR 前）、APNG（`acTL`/`fcTL`/`fdAT`）、颜色类型、位深与隔行方式均不做特判：适配器把它们当作普通块顺序遍历，只依赖长度与 `IEND`。APNG 等内容域限制属 [CONTENT-PNG.md](CONTENT-PNG.md)，不约束结构域注入。

## 7 remove 还原

`remove` 使用 `HostAdapter::strip` 的默认实现：复制 `[0, inject_offset)`，跳过 `inject_size` 字节，再复制其余全部字节（`adapters/mod.rs:236-260`）。对 `chunk` 而言，跳过的正是 `[len][prIv][UBE][crc]` 整个块，后移的 IEND 与脏尾回到原始位置，其他块逐字节不变。

- 若内容域重压缩使块位移，`strip_coordinates_for_location` 仅对 `chunk`/`eof` 按定位结果平移 `inject_offset`（`engine.rs:2268-2296`）；平移后的注入区仍受 `envelope_coordinates_agree` 约束：`ube_total_size <= inject_size`、区域不越过文件尾（`engine.rs:2828-2902`）。
- 还原结果重新计算大小与 SHA-256，必须等于信头中的 `orig_host_size` 与 `orig_host_sha256`，否则返回 `RestoreMismatch`；若检测到残留信封或信封形状结构，会置 `residual_envelope` 提示需按逆序删除（`engine.rs:2299-2360`）。
- 校验通过即“逐比特还原”，包括 IEND 后的脏尾；原文件 SHA-256 是最终判据。

## 8 写侧 I 级（非规范）

- **不重编码像素**：结构域写入不改变 IDAT 的 deflate 级别、行滤波器或块内数据，只复制原始字节（`png.rs:177-179`、`:211-212`）；这些细节属于内容域写入（见 [CONTENT-PNG.md](CONTENT-PNG.md) §8），读侧不依赖本域。
- **块顺序**：`prIv` 固定紧邻最后一个 `IEND` 之前；不插入填充块，不合并/拆分既有块。
- **CRC 重算**：由于信头与尾标在 `inject` 后才回填，`finalize` 必须重算 CRC，读取起点为 `ube_offset - 4`（块类型），长度为 `4 + ube_total_size`（`png.rs:490-506`；调用点 `engine.rs:1443-1451`）。
- **重试**：适配器没有信封级重试；写后 `locate` 自检失败即整体失败，不提交半成品（`engine.rs:1454-1472`）。文件落盘的 `rename_with_retry` 与信封无关（`engine.rs:1601`）。

## 9 已知限制与错误语义

| 情形 | 结果 |
| --- | --- |
| 文件 < 20 B / 签名错误 / 无零长度 IEND | `CorruptedData` / `UnsupportedFormat` / `CorruptedData`（`png.rs:31-35`、`:39-43`、`:85-91`） |
| 块流中途截断或长度越界 | 扫描停止；若此前已有 IEND 则以其为注入点，否则报“未找到 IEND”（`png.rs:48-83`） |
| `ube_total_size > 0x7FFFFFFF` 且显式 `chunk` | `UnsupportedFormat`，提示改用 `eof`（`png.rs:168-172`） |
| 未知策略名 | `UnsupportedFormat`（`png.rs:159-163`） |
| UBE 流短于声明长度 | `CorruptedData("Envelope stream ended before its declared size")`（`png.rs:196-201`） |
| 非 PNG 载体调 `locate` | `Ok(None)`，非错误（`png.rs:240-243`） |
| 块 CRC 损坏 | `verify_structure` 返回 `(false, "CRC32 mismatch for chunk …")`；写入前被引擎拒绝（`png.rs:399-407`；`engine.rs:1028-1035`） |
| 尾标魔数匹配但 CRC/解析失败 | 报 `CorruptedData`（`envelope.rs:844-858`），不静默当作无信封 |

其他限制：`locate` 不校验块 CRC，也不认证尾标，只提出候选；安全性由引擎的物理包含、坐标交叉与还原哈希兜底（`STRUCTURE-ENVELOPE.md` §12、`engine.rs:191-207`、`:2867-2912`）。`prIv`/`stEg` 的存在与大小本身可被结构扫描发现：`suspicious_structures` 对 `length >= 136` 的私有块报警（`png.rs:428-473`），`verify_structure` 在详情中报告块名（`png.rs:421-425`）。串接流的注入落在最后一个 `IEND` 前；若调用方期望写入首个流，需自行拆分。

## 10 自检

- 单元测试（`png.rs:526-583`）：`locate_rejects_a_trailer_that_describes_another_region`（外来尾标必须拒绝）、`locate_accepts_a_trailer_that_describes_its_chunk`（自描述尾标返回块数据偏移与长度）。
- 回归：`tests/test_regression/review_20261030.rs:233-252` 固定 `chunk` 的 `offset_delta == 8`、`inject_offset == 块数据偏移 − 8`，`eof` 为 0 且等于原文件长度；`tests/test_regression/fixes.rs:947-969` 覆盖内容域重压缩后 `prIv` 位移仍可读；`tests/test_security/stealth.rs:223-228` 构造伪造 `prIv` 块。
- 字节基线：`scripts/baseline_hash.py:263-314` 的 `structure_pass` 对每个含结构域的 PNG 执行 `write -t <固定载荷> → inspect --json → read → restore`，`--check` 按 `id` 与展平键逐项比较（忽略 `elapsed_ms`/`note`，`scripts/baseline_hash.py:470-524`）。PNG 用例定位方式：`ext == "png"` 的条目读取 `structure.strategy`（应为 `chunk`）、`ube_total_size`、`strategy_capacities`、`payload_sha256`、`restored_equals_original`；样例见 `temp/baseline/baseline.json:757-777`（`stego_size 87,105 = 86,854 + 239 + 12`）。

```bash
cargo test --all-features --lib structure::adapters::png
cargo test --all-features --test test_regression
python scripts/baseline_hash.py --check
```
