# JPEG 结构域适配器规范（APP 段注入）

> 范围：本文件只定义 JPEG 作为**结构域载体**时的检测、策略、注入布局、定位与还原。
> 信封字段、AAD、加密与 Trailer 语义见 [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md)；
> 线格式总表见 [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2–§15 与 [CAPACITY.md](CAPACITY.md) §4；
> [WIRE_SPEC_STRUCTURE.md](../WIRE_SPEC_STRUCTURE.md) 已冻结为历史对照（非规范），与其冲突时以本目录为准；
> JPEG 的 DCT 内容域（UERD/J-UNIWARD）见 [CONTENT-JPEG.md](CONTENT-JPEG.md)，两者互不替代。
> 适配器实现见 `rust/src/structure/adapters/jpeg.rs`，注册名 `JPEG`（`:230-232`），
> 在 `ADAPTERS` 中排在 PNG 之后（`rust/src/structure/registry.rs:25-36`）。

## 1. 导航与术语

- **注入点** `inject_offset`：本适配器为第一个 SOS 的 `0xFF` 字节偏移（`jpeg.rs:344-356`）。
- **UBE 起点** = `inject_offset + offset_delta`；本策略 `offset_delta = 4`（`jpeg.rs:553-564`，引擎在密封前写入并纳入 AAD，`rust/src/structure/engine.rs:1267-1278`）。
- **链**：多个 APP15 段按文件顺序串联，逻辑 UBE 跨段连续，段间空出 4 字节段头。
- **首 SOS**：标记流扫描的终点；SOS 之后的熵编码数据不参与任何解析（`jpeg.rs:108-116`）。

## 2. 稳定性分级（F / D / I）

| 级别 | 内容 |
| :--- | :--- |
| **F** | APP15 标记 `FF EF`、段长字段语义与 65533 上限、插入点=首个 SOS、`offset_delta=4`、链邻接关系（下段载荷 = 上段载荷尾 + 4）、Trailer 位于末段载荷尾部、`partition_jpeg_payload_lengths` 分段函数、locate 只认 APP15 与 EOF 尾标 |
| **D** | 无。本适配器没有可替换的私有字段或方言参数 |
| **I** | `auto` 策略选择与回退、容量报告文案、`JPEG_MAX_TOTAL_CAPACITY` 快路径、`suspicious_structures` 的 136 字节阈值、`verify_structure` 文案、64 KiB 读取缓冲 |

F 级中的 16 MiB 扫描上限（`jpeg.rs:18`）决定"写出的载体是否还能被本实现定位"，改动会使既有大载体不可读，按 F 对待。

## 3. detect

`detect` 只做一件事：定位到偏移 0，读取 2 字节并比较 `FF D8`（`jpeg.rs:234-246`）。读完恢复调用前位置（`:244`）。

- 不检查 EOI（`FF D9` 常量仅定义于 `:13`，检测与结构校验都不使用它）。
- 不要求 APP0/JFIF、不要求 EXIF、不检查扩展名。
- 只要文件前两字节是 `FF D8` 即被识别为 JPEG；格式路由按 `registry.rs:25-36` 顺序，PNG 先于 JPEG。
- 读/定位失败返回 `false`，不返回错误。

## 4. 支持策略与 auto

`supported_strategies = ["app_segment", "eof"]`（`jpeg.rs:248-250`），线上 ID 分别为 5 与 1（`registry.rs:90-104`）。

`auto` 是**单次判定、不回退重试**（`engine.rs:1242-1255`），顺序如下（`jpeg.rs:252-269`）：

1. `ube_size > 64 MiB` → `eof`（`:253-254`）。
2. `find_jpeg_sos_offset` 失败（无 SOS、段长损坏、16 MiB 扫描超限、连续非标记字节超限）→ `eof`（`:260-262`）。
3. `ube_size > app_segment_payload_capacity(sos_offset)` → `eof`（`:265-267`）。
4. 否则 `app_segment`。

容量报告（`jpeg.rs:271-322`）：`app_segment` 给出精确字节数；`eof` 为无上限、文件增长。注意物理追加在文件末尾，正常 JPEG 即 EOI 之后；但 EOF 策略不解析 EOI 位置（`rust/src/structure/adapters/eof.rs:48-55`）。

**APPn 选择（以代码为准）**：写入固定使用 APP15（`JPEG_APP15 = FF EF`，`jpeg.rs:14`）；不存在 APP2–APP14 的轮选或回退逻辑。`JPEG_COM`（`:15`）只在 `suspicious_structures` 中作为"可疑旧信封"被读取（`:542-547`），`locate` 明确不把 COM 当作通道（回归测试 `tests/test_lifecycle/jpeg_multisegment.rs:156-187`）。因此 COM 与其它 APPn 均不是本实现的写通道。

## 5. 注入布局

在 `sos_offset` 处依次写出（`jpeg.rs:352-371`）：

```text
FF EF | len_hi len_lo（大端 u16，含长度字段自身 2 字节）| payload[len-2]
```

- 段最大长度字段 `65535` ⇒ 单段载荷上限 `65533`（`jpeg.rs:16`、`:122-127`、`:363-366`）。
- `inject_size = Σ(4 + payload_len)`（`:366`）；引擎按 `inject_offset + 4` 写入 Header（`engine.rs:1407`、`:1428-1429`）。
- 后续段从前一载荷末尾**再前进 4 字节**开始；逻辑 UBE 读取器据此跨段拼接（`jpeg.rs:500-514`、`adapters/mod.rs:403-470`）。
- 全链 Trailer 位于最后一个载荷的末 24 字节：`inject_offset + inject_size - 24`（`jpeg.rs:566-572`）。

**超过 65533 的处理**：不拒绝，改为多段链。`partition_jpeg_payload_lengths` 每段尽量取 65533；若最后余量 `< 24`，从当前段借 1024 字节，使末段 ≥ 1024（`jpeg.rs:172-195`；函数上方注释写"≥24"，代码实际为 1024，以代码为准）。不存在"超限即改 eof"的隐式回落：`inject` 只接受 `app_segment`，容量不足返回 `UnsupportedFormat` 并建议 `--strategy eof`（`:344-350`）。

## 6. 容量口径

`app_segment_payload_capacity(sos)`（`jpeg.rs:205-225`）要求注入后首 SOS 仍落在 16 MiB 扫描窗口内：

```text
budget = 16 MiB - sos_offset
fits(p) = p + 4 * ceil(p / 65533) <= budget
capacity = max{ p ≤ min(budget, 64 MiB) | fits(p) }
```

因此 `app_segment` 的实际上限通常略小于 `16 MiB - sos_offset`（链头开销约 1 KiB/16 MiB），**永远不会达到 64 MiB**；64 MiB 只在 `auto` 快路径与二分上界中出现（`jpeg.rs:17`、`:215`）。`sos_offset` 越大，容量越小。

## 7. 段插入位置与既有段

- 插入点是**第一个 SOS 之前**，不是 SOI 之后（`jpeg.rs:352-356`）。因此 APP0/JFIF、APP1/EXIF、其它 APPn、DQT/DHT/SOF、既有 COM/APP15 全部原样保留在注入链之前。
- 不重排、不合并、不替换既有 APP15；新链紧贴首 SOS。
- 首 SOS 起的全部字节（含熵编码数据与后续扫描）原样复制（`:373-375`），渐进式/多扫描 JPEG 的后续 SOS 不受影响。
- 重复写入：正常 API 在写前用 `locate` 检查，已有信封会被拒绝（`engine.rs:1046-1058`）；若通过其他手段叠加，`locate` 从后向前遍历候选，靠近 SOS 的较晚链优先命中（`jpeg.rs:406`），移除必须按注入逆序进行。

## 8. locate

1. 偏移 0 校验 `FF D8`，否则返回 `None`（`jpeg.rs:385-389`）。
2. 扫描首个 SOS 之前的所有段，收集每个 APP15 的 `(载荷偏移, 载荷长度)`（`:391-400`）。
3. 候选从最后一个向前（`:406`）：载荷 `< 24` 跳过（`:407-409`）；读取末 24 字节并用期望的 Trailer 魔数解包（`:410-420`）。
4. 单段命中：`trailer.ube_offset == 载荷偏移` 且 `ube_total_size == 载荷长度`（`:423-431`）。
5. 多段命中：从当前段向前累加，要求 `curr_off + curr_len == next_off - 4`（段头 4 字节），累加和等于 `ube_total_size`，且起点等于 `trailer.ube_offset`（`:434-464`）。
6. APP15 未命中时回退 EOF 尾标 `read_from_tail`，按 `locate_start(file_size)` 定位，策略名 `eof`（`:474-480`）。
7. 引擎统一做物理包含校验：`ube_total_size ≥ 112 + 24` 且 `ube_offset + ube_total_size ≤ 文件长度`（`engine.rs:191-207`）；APP15 不要求贴住文件尾。

**hint 交叉**：`locate` 只接收 `expected_trailer_magic`；`locate_with_hint` 对 JPEG 使用默认实现，忽略 header magic hint（`adapters/mod.rs:218-225`）。引擎先试密码派生的 stealth trailer magic，再试方言 magic（`engine.rs:145-166`）。返回的策略名来自实际通道；`inspect` 优先展示 header 内的 `strategy_id`（`:2726-2730`），该字段不在 AAD 内，只用于报告。`remove`/`verify` 要求 `inject_offset + offset_delta == trailer.ube_offset`，`app_segment` 不属于可重定位策略（`engine.rs:2828-2873`）；只有 `pe_codebits` 按 ID 豁免（`:2845-2850`）。

## 9. remove 还原

JPEG 未覆盖 `strip`，使用默认实现（`adapters/mod.rs:236-290`）：

1. 复制 `[0, inject_offset)`；
2. 跳过 `[inject_offset, inject_offset + inject_size)`，即整条 APP15 链（段头 + 载荷）；
3. 复制其余全部字节。

由于链路之外没有任何字节被改写、`patch_offset = 0`，还原结果就是原始 JPEG 字节。随后引擎比对 `orig_host_size` 与 `orig_host_sha256`（`engine.rs:2299-2311`），不一致返回 `RestoreMismatch`（`:2354-2360`）。`eof` 产物同样走默认 `strip`（注入点=原文件长度，跳过量=UBE 长度），结果等价于直接截断。

## 10. 边界与拒绝条件

- **EXIF/JFIF 共存**：既有 APP0/APP1 原样保留；扫描按段长直接跳过 APP1 载荷（`jpeg.rs:135-140`），因此 EXIF 缩略图内部的 `FF D8` 不会被当作新 JPEG，也不会被收集。`detect` 只看文件偏移 0，内嵌缩略图无法触发适配器。
- **既有大 APP15/COM**：载荷 ≥ `112 + 24 = 136` 字节时仅产生可疑提示，不拒绝写入（`jpeg.rs:530-551`）。
- **段损坏**：段长 `< 2` 返回 `MalformedLength`，`find_jpeg_sos_offset` 转为 `CorruptedData`（`:122-125`、`:162-167`）；段声明长度越过文件末尾会在后续读取时以 `Eof` 结束扫描（`:118-121`、`:135-140`）。
- **扫描拒绝**：首个 SOS 前连续非 `0xFF` 字节超过 4096 → `NonMarkerRun`（`:80-85`）；标记流越过 16 MiB → `HeaderScanLimit`（`:72-75`）；找不到 SOS → `CorruptedData`（`:166`）。
- **渐进式/多扫描**：不做特殊处理，也不因此拒绝；只要求首个 SOS 可达，后续扫描字节整体平移后保持不变。
- **写前结构校验**：无论 `auto` 最终选 `eof` 还是显式 `eof`，引擎都会先调用 `verify_structure`（即 `find_jpeg_sos_offset`），SOS 不可达的 JPEG 一律拒绝写入（`engine.rs:1027-1035`，`jpeg.rs:517-528`）。
- **64 MiB 常量**：在 16 MiB 扫描窗口下对 `app_segment` 不可达，不构成实际边界。

## 11. I 级写侧行为

- `auto` 只判定一次；探测失败选 `eof`，但随后写前校验仍可能拒绝损坏载体，不会"成功写入却读不回"（`jpeg.rs:252-269`、`engine.rs:1027-1035`）。
- 容量文案、`available` 标记与 `limit` 文本为报告行为（`jpeg.rs:271-322`）。
- 可疑结构阈值、`verify_structure` 文案、错误消息、64 KiB `BufReader` 均为实现细节，不进入线格式（`:63-69`、`:530-551`、`:517-528`）。
- 分段尾段借用 1024 字节属 F 级分段函数的一部分；第三方写多段链若要被本实现读取，必须复现该函数（`jpeg.rs:172-195`、`:500-514`）。

## 12. 自检方式

```bash
cd rust
cargo test --all-features --all-targets
cargo test jpeg_ --all-features
cargo test jpeg_app_segment_capacity_keeps_relocated_sos_in_scan_window --all-features
python ../scripts/baseline_hash.py --check
```

人工核对：用 `strhide inspect` 确认策略为 `app_segment`、`ube_offset` 前 4 字节为 `FF EF`；`strhide restore` 后与原始 JPEG 做 SHA-256 比对；对多段链分别验证 `x + len == next - 4` 与末段尾部 Trailer。内容域回归见 [CONTENT-JPEG.md](CONTENT-JPEG.md)。
