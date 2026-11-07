# ZIP 结构域适配器：中央目录前注入（pre_cd_inject）

本文件规定 `format_name = "ZIP"` 的结构域（UBE）适配器。信头、尾标、AAD、`strategy_id` 等公共布局见 [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) 与 [WIRE_SPEC_STRUCTURE.md](../WIRE_SPEC_STRUCTURE.md) §3.3、§14、§15；容量口径汇总见 [CAPACITY.md](CAPACITY.md)。所有引用写作 `文件:行`（相对仓库根）。

## 1 范围、导航与稳定性

载体为 EOCD（End of Central Directory）可定位的 ZIP 归档及其同构格式（.jar/.docx/.xlsx/.pptx）。适配器只做字节搬运与 EOCD 字段补丁，不解压、不解析本地文件头，也不校验条目 CRC。

| 级别 | 本域内容 |
| --- | --- |
| **F** | EOCD 魔数 `PK\x05\x06` 与探测窗口 65,558 B；注入点 = EOCD 声明的 `cd_offset`；UBE 紧邻中央目录之前；EOCD+16 改写为 `cd_offset + ube_size`；`offset_delta = 0`；`patch_offset = eocd_pos + 16 + ube_size`；`inject_size = ube_size`；策略名 `pre_cd_inject`/`eof` 与 ID 4/1；32 位容量不等式；ZIP64/空档案/溢出的拒绝条件 |
| **D** | 无。适配器不读取 `Profile`，唯一随方言变化的是 `locate` 收到的期望尾标魔数（stealth 派生值 vs profile 值），不影响几何 |
| **I** | 复制缓冲区 64 KiB（`rust/src/structure/adapters/io.rs:6`）、`strategy_note` 文案（`zip.rs:494-504`）、EOCD 候选的收集方式、容量/提示字符串的措辞 |

常量来源：`rust/src/structure/adapters/zip.rs:10-14`（`ZIP_LOCAL_MAGIC` `PK\x03\x04`、`ZIP_EOCD_MAGIC` `PK\x05\x06`、`ZIP_SPAN_MAGIC` `PK\x07\x08`、`ZIP_CD_MAGIC` `PK\x01\x02`）；策略注册表 `rust/src/structure/registry.rs:90-104`（`pre_cd_inject` = 4，`eof` = 1）。

## 2 格式识别（detect）

`detect` 只做首 4 字节比较，并在返回前恢复流位置（`zip.rs:123-139`）：

1. 记录当前位置，`seek(Start(0))` 失败即 `false`（`zip.rs:124-130`）；
2. `read_exact` 取前 4 字节；≤3 字节的文件读失败即 `false`；
3. 仅当等于 `PK\x03\x04`、`PK\x05\x06` 或 `PK\x07\x08` 时返回 `true`（`zip.rs:131-136`）；
4. 恢复原位置（`zip.rs:137`）。

由此：EOCD-only 的 22 B 空档案可被识别，因为首 4 字节即 `PK\x05\x06`（回归 `rust/tests/test_regression/review_20261025.rs:59-70`）；`PK\x07\x08` 实为数据描述符签名（代码常量名为 `ZIP_SPAN_MAGIC`，`zip.rs:12`），识别它只是容忍以该签名开头的异常/残缺文件，并非分卷标志。识别与扩展名、EOCD、ZIP64、加密状态均无关；`ADAPTERS` 按固定优先级依次探测（`rust/src/structure/registry.rs:25-47`）。

`find_eocd_offset`（`zip.rs:16-75`，写读共用）是真正的结构门槛：

- 窗口 `scan_len = min(file_size, 65536 + 22)`，整段读入内存后从尾部反序枚举所有 4 字节等于 `PK\x05\x06`（`0x06054b50`）的位置（`zip.rs:19-41`）；因此 EOCD 必须位于最后 65,558 B 内，否则直接视为不存在。
- 两遍扫描：第一遍要求记录刚好结束于 EOF（`eocd_pos + 22 + comment_len == file_size`），第二遍放宽为 `<= file_size`（用于 `eof` 信封追加在 EOCD 之后的情形）（`zip.rs:43-55`）。
- 只接受同时满足下列条件的候选：`cd_offset + cd_size <= eocd_pos`（或 `cd_offset == cd_size == 0` 的空档案），且 `cd_offset` 处 4 字节确为 `PK\x01\x02`（`zip.rs:57-64`、`:87-93`）。注释里伪造的 EOCD 形状字节因此无法把注入点搬到注释内（`zip.rs:25-34`；回归 `fixes.rs:557-570`）。
- 全部失败返回 `CorruptedData("Valid ZIP EOCD (End of Central Directory) record not found")`（`zip.rs:72-74`）。

EOCD 字段只读 `cd_size`（+12）、`cd_offset`（+16）、`comment_len`（+20）；磁盘号（+4/+6）、条目计数（+8/+10）不读不校验（`zip.rs:48-63`）。

ZIP64 只做位置探测：`has_zip64_locator` 读取 `eocd_pos - 20` 处的 4 字节，等于 `PK\x06\x07`（ZIP64 EOCD locator，`0x07064b50`）即为 ZIP64（`zip.rs:105-114`）。ZIP64 EOCD 记录魔数 `PK\x06\x06`（`0x06064b50`）**从不解析**，其长度/字段也不读取。真实 ZIP64 归档若把 32 位字段写成哨兵 `0xFFFFFFFF`，`cd_offset + cd_size <= eocd_pos` 与 CD 魔数校验都不可能成立，`find_eocd_offset` 直接返回 `CorruptedData`；只有"经典字段仍为真实值 + locator 存在"的 ZIP64 才会先被找到、再按 §5 拒绝（`review_20261025.rs:498-536`）。

SFX 容忍是算法层的：`find_eocd_offset` 不检查 CD 之前的前缀，注入时 `[0, cd_offset)` 原样复制，自解压 stub 与任意前置垃圾都被保留（`zip.rs:286-287`）。但 `detect` 要求文件首 4 字节是上述三种魔数，`MZ` 开头的真 SFX 不会进入 ZIP 适配器（`rust/src/structure/registry.rs:40-47`）。

加密条目、数据描述符、分卷均不特判：适配器从不解析条目，加密的本地数据与 CD 原样搬运。写入侧另有一道独立守卫会拒绝含 `META-INF/*.SF|RSA|DSA` 的签名 JAR，并在 CD 无法解析时失败关闭（`rust/src/structure/rejection.rs:346-352`、`:369-377`），不属于本适配器。

## 3 支持策略与 auto

| 名称 | `strategy_id` | 行为 | 出处 |
| --- | --- | --- | --- |
| `pre_cd_inject` | 4 | 在 `cd_offset` 处插入 UBE，并改写 EOCD 的 `cd_offset` 字段 | `zip.rs:240-315`；`registry.rs:94` |
| `eof` | 1 | 委托 `EofAdapter`，UBE 追加在文件 EOF 之后 | `zip.rs:247-249`；`rust/src/structure/adapters/eof.rs:35-56`；`registry.rs:91` |

`auto` 只依载体几何与精确 UBE 尺寸一次性决定，不重试、不回退（`zip.rs:145-171`；引擎调用 `rust/src/structure/engine.rs:1242-1255`），顺序为：

1. `find_eocd_offset` 返回 `cd_offset == 0`（空档案，UBE 会落在偏移 0 并覆盖归档自身魔数）→ `eof`（`zip.rs:151`）；
2. 存在 ZIP64 locator → `eof`（`zip.rs:155-157`）；
3. `patch_limit = max(cd_offset, eocd_pos + 16)`，若 `patch_limit + ube_size >= 0xFFFFFFFF` → `eof`（`zip.rs:162-167`）；
4. 其余 → `pre_cd_inject`；
5. `find_eocd_offset` 报错 → `eof`（`zip.rs:169`）。

显式策略必须属于 `supported_strategies`（`zip.rs:141-143`），否则引擎报 `UnsupportedFormat`（`engine.rs:1248-1253`）；适配器内部对非 `pre_cd_inject`/`eof` 的名字也返回 `UnsupportedFormat`（`zip.rs:251-255`）。

## 4 注入布局

UBE 位于中央目录**之前**、最后一个本地条目之后；`offset_delta = 0`（默认实现 `rust/src/structure/adapters/mod.rs:345-352`），即 UBE 首字节就是 `inject_offset`，尾标落在 UBE 最后 24 B（默认 `trailer_offset`，`adapters/mod.rs:357-359`）。

```text
[0, cd_offset)           原样复制（前缀 stub、本地文件头与数据，全部不动）
[cd_offset, +ube_size)   UBE（header 112 B … trailer 24 B）   inject_offset = cd_offset
cd_offset + ube_size     中央目录（原始字节整体后移，内容不变）
...                      （ZIP64 record/locator 等，若存在且未被拒绝）
eocd_pos + ube_size      EOCD：+12 cd_size 不变；+16 cd_offset = 原 cd_offset + ube_size
                         +20 comment_len 与注释逐字节复制
```

- 写入顺序：复制 `[0, cd_offset)` → 写 UBE → 复制 `[cd_offset, eocd_pos + 16)`（CD 与 EOCD 头至 `cd_offset` 字段之前，长度 `(eocd_pos + 16) - cd_offset`）→ 写新 `cd_offset` → 跳过原 4 字节字段 → 复制剩余（`zip.rs:286-312`）。
- `inject` 返回 `(inject_offset, inject_size, patch_offset, orig_patch_val) = (cd_offset, ube_size, eocd_pos + 16 + ube_size, 原 cd_offset)`（`zip.rs:303-314`）。`patch_offset` 是 stego 坐标；`offset_delta = 0` 使它同时满足 `inject_offset + offset_delta == trailer.ube_offset`（`engine.rs:1407`、`:2851-2859`）。
- 文件增长恰好 `ube_size` 字节，不新增本地文件头，也不新增 CD 条目：UBE 占据"最后一个本地条目与中央目录之间"的松弛区。ZIP 读取器只按 EOCD 的 `cd_offset` 跳到 CD，随后按 CD 条目内的相对本地头偏移取数据；这些偏移都指向 `cd_offset` 之前，未因插入而改变，因此 UBE 不会被当作本地文件数据，也不会被当成条目。
- 引擎随后在 `actual_ube_offset` 回写信头、在 `ube_offset + ube_total_size - 24` 回写尾标（`engine.rs:1426-1441`），两者都落在 UBE 内；`finalize` 为默认空操作（`adapters/mod.rs:364-370`）。

## 5 容量与下界

被补丁的只有 EOCD 的 32 位 `cd_offset`；`cd_size` 保持原值。适配器要求

```text
patch_limit = max(cd_offset, eocd_pos + 16)
patch_limit + ube_size < 0xFFFFFFFF          // 新 cd_offset 与补丁位置都必须落在 u32
=> 容量上限 = 0xFFFFFFFE - patch_limit
```

检查见 `zip.rs:162-167`、`:278-283`，报告值见 `zip.rs:205-215`（`saturating_sub`）。溢出时显式 `pre_cd_inject` 报 `UnsupportedFormat("Central directory or EOCD patch offset overflow (>4GB) …")`（`zip.rs:278-283`），`auto` 已改为 `eof`。

| 情形 | `pre_cd_inject` 报告 | 出处 |
| --- | --- | --- |
| 正常归档 | `available = true`，`capacity_bytes = 0xFFFFFFFE - patch_limit` | `zip.rs:194-216` |
| 空档案（`cd_offset == 0`） | `available = false`，提示改 `eof` | `zip.rs:189-193` |
| ZIP64（locator 存在） | `available = false`，提示改 `eof` | `zip.rs:198-203` |
| EOCD 缺失/损坏 | `available = false`，提示改 `eof` | `zip.rs:218-222` |
| `eof` | `None`（无上限、文件增长） | `zip.rs:230-236` |

静态查询（`reader == None`）只报 `carrier-dependent (4 GiB - EOCD offset)`（`zip.rs:176-185`）。`inspect` 会把两者统一钳到引擎载荷上限 `structure_payload_limit(host_len) = clamp(256 × host_len, 64 MiB, 1 GiB)`（`engine.rs:1902-1907`、`:1916-1934`；`rust/src/core/crypto.rs:786`），故小载体的报告值通常为 67,108,864（基线 `temp/baseline/baseline.json:420-447`，75,238→75,477 的用例两策略均报该值）。

UBE 下界：`locate` 要求 `cd_offset >= 112 + 24 = 136`（`zip.rs:323-325`），引擎 `confine_location` 再要求 `ube_total_size >= 136` 且 `ube_offset + ube_total_size <= file_len`（`engine.rs:191-207`）。实际可产出的最小加密信封为 214 B（`WIRE_SPEC_STRUCTURE.md` §14.3）。

## 6 locate 路径与方言提示

`locate` 按两条路径依次尝试（`zip.rs:317-349`）：

1. **pre-CD**：`find_eocd_offset` 成功且 `cd_offset >= 136` 时，读取 `cd_offset - 24` 处的 24 B 尾标，用 `expected_trailer_magic` 解包（`zip.rs:323-330`）；仅当 `trailer.ube_offset.checked_add(trailer.ube_total_size) == Some(cd_offset)` 才接受，返回 `(ube_offset, ube_total_size, "pre_cd_inject")`（`zip.rs:330-336`）。
2. **EOF 回退**：`EnvelopeTrailer::read_from_tail` 命中且 `ube_offset + ube_total_size == file_size` 时返回 `(ube_offset, ube_total_size, "eof")`（`zip.rs:341-346`）。
3. 都不成立返回 `Ok(None)`（`zip.rs:348`），非错误。

坐标反推：UBE 起点直接取尾标内记录的 `ube_offset`，不依赖"EOCD 的 `cd_offset` 减去 UBE 长度"；后者只作为等式校验。`locate` 不读取头魔数，也不认证尾标——`locate_with_hint` 的默认实现忽略 `expected_header_magic`（`adapters/mod.rs:218-225`）。引擎在有密码时先试 stealth 尾魔数、再试 profile 尾魔数（`engine.rs:145-166`），最终仍由 `confine_location` 与后续 AEAD 兜底。

损坏处理：EOCD 缺失、`cd_offset` 不再指向 CD、注释长度与文件尾不吻合时，`find_eocd_offset` 报错，第 1 条路径被跳过；pre-CD 信封因此返回 `None`（读侧表现为"无隐藏数据"），而 eof 信封不受影响。多 EOCD 时按"从尾部向前、先精确 EOF 后宽松"取第一个自洽候选（`zip.rs:35-70`），即文件尾最近的合法记录获胜。

## 7 remove 还原

`strip` 覆写默认实现（`zip.rs:351-408`）。`strategy_id` 映射为 `eof` 时委托 `EofAdapter`（复制 `orig_host_size` 字节，`zip.rs:357-359`；`eof.rs:74-83`）。否则按 stego 坐标流式还原：

1. 复制 `[0, inject_offset)`（`zip.rs:362-363`）；
2. `inject_end = inject_offset.checked_add(inject_size)`，定位到 `inject_end`，复制 `patch_offset - inject_end` 字节（`zip.rs:372-390`）；
3. 在该逻辑位置写入 `orig_patch_val` 的 4 字节小端，即恢复 EOCD+16 的原 `cd_offset`（`zip.rs:393`）；
4. 跳过 stego 中被改写的 4 字节字段，复制剩余全部字节（`zip.rs:396-405`）。

前置校验：`validate_against` 要求 `patch_offset ≥ 4` 且 `patch_offset + 4 ≤ host_len`（`STRUCTURE-ENVELOPE.md` §3.2）；`strip_coordinates_for_location` 只允许 `chunk`/`eof` 平移，`pre_cd_inject` 坐标不一致即 `CorruptedData`（`engine.rs:2268-2296`）；`envelope_coordinates_agree` 要求 `ube_total_size <= inject_size`、注入区不越过文件尾（`engine.rs:2828-2902`）。还原后重算大小与 SHA-256，必须等于 `orig_host_size`/`orig_host_sha256`，否则 `RestoreMismatch`（`engine.rs:2299-2311`）。通过后即逐字节还原，含 EOCD 注释与 CD 前的前缀垃圾。

## 8 边界情形

| 情形 | 行为 |
| --- | --- |
| EOCD 魔数出现在注释里 | 第一遍要求记录结束于 EOF，第二遍要求 `cd_offset` 处为 `PK\x01\x02`，伪造注释被排除（`zip.rs:43-67`；`fixes.rs:557-570`、`:573-599`）；若伪造记录恰好结束于 EOF 且 `cd_offset` 指向真 CD，仍会被采纳，这是两遍启发式的残余选择 |
| 空 ZIP（仅 22 B EOCD） | `detect` 通过；`auto` 退 `eof`；显式 `pre_cd_inject` 报 `UnsupportedFormat("Empty archive …")`（`zip.rs:258-264`；`review_20261025.rs:59-116`） |
| ZIP64（locator 在 `eocd_pos - 20`） | `auto`/容量退 `eof`；显式注入报 `UnsupportedFormat("ZIP64 archive (EOCD64 locator present) …")`（`zip.rs:265-271`；`review_20261025.rs:520-560`） |
| 32 位字段为哨兵的 ZIP64 | `find_eocd_offset` 直接失败（`cd_offset + cd_size` 越界且 CD 魔数不可达），`verify_structure` 报"Corrupted ZIP"（`zip.rs:410-432`） |
| 数据描述符 `PK\x07\x08` | 不作为条目解析；仅在文件首 4 字节时被 `detect` 接受（`zip.rs:131-136`） |
| 分卷归档 | 不读磁盘号字段；能否处理完全取决于 `cd_offset` 是否指向 `PK\x01\x02` 且边界自洽，失败与普通损坏同路径 |
| `MZ` 开头的 SFX | 算法可容忍前缀，但 `detect` 首字节校验失败，不会被选为 ZIP 载体 |
| EOCD 距文件尾 > 65,558 B | 写入路径不会产生这种 pre-CD stego；但超大 `eof` 信封会遮住 EOCD，使 L1 `verify_structure` 与 pre-CD 探测都不可见（`zip.rs:19-20`、`:410-432`） |
| 签名 JAR / CD 不可解析 | 独立守卫失败关闭（`rejection.rs:346-352`、`:369-377`） |

`suspicious_structures` 另做无密码结构扫描：CD 前 `>=136` 字节且 `ube_offset + ube_total_size == cd_offset` 的 24 B 尾标形状、或 EOCD 之后同样形状的尾部数据，各报一条（`zip.rs:434-492`，下界常量 `zip.rs:441`）。

## 9 写侧 I 级与自检

- **流式复制**：`copy_exact` 以 64 KiB 缓冲逐块搬运，短读即 `CorruptedData("Unexpected EOF while copying stream")`，避免写出被截断的信封（`io.rs:11-30`；`zip.rs:291-294`）。
- **不重排、不重编码**：中央目录、EOCD 其余字段、注释与 CD 前数据全部逐字节复制（`zip.rs:286-312`）；仅 `[eocd_pos+16, +20)` 4 字节被替换。
- **写后自检**：flush 后以本次尾标魔数重跑 `locate`，要求返回值恰为 `(actual_ube_offset, ube_total_size)`，否则整体失败、不提交半成品（`engine.rs:1454-1472`）。
- **I 级差异**：`strategy_note` 文案（`zip.rs:494-504`）、容量 `limit` 字符串格式、候选收集实现（`Vec` 一次性收集 vs 逐次重扫，`zip.rs:35-41`）均不进入线格式，读侧不依赖。
- **自检命令**：`cargo test --all-features --test test_regression`（ZIP 用例 `fixes.rs:557-636`、`:1128-1205`，`review_20261025.rs:59-116`、`:498-560`）；`python scripts/baseline_hash.py --check` 比对 `structure.strategy = pre_cd_inject` 与 `stego_size - orig_size`（基线 `temp/baseline/baseline.json:420-447`）。
