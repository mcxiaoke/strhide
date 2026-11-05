# strhide 独立第三方发布前代码审查报告

- 审查对象：`C:\Home\Projects\strhide`，版本 v0.9.0，HEAD `2ec5798`，构建时间 `2026-11-05T09:35:59Z`
- 审查日期：2026-11-05
- 审查性质：独立审查，不沿用任何既有报告结论；结论全部来自本次通读文档/源码与实测
- 审查范围：`AGENTS.md`、`README.md`、`docs/api/ARCHITECTURE.md`、`docs/api/WIRE_SPEC.md`、`docs/api/STEGO-API.md`、`rust/src` 全量、`rust/tests`、CLI/GUI 调用点
- 约束遵守：本轮**未修改任何源码**，未 commit、未 push、未触碰 `.git`；测试样本与脚本仅写入 `temp/audit/`

---

## 1. 摘要结论

**总体判断：本版本可以作为发布基线。** 在本次覆盖范围内未发现 P0（必现数据损坏/安全问题），也未证实 P1。写入路径的原子性、认证覆盖、双域互斥、提取失败折叠等关键防护实现完整，1020 个测试全部通过，heavy 算法矩阵与双域矩阵全绿。

但存在一组**"容量报告与实际可写量不一致"**的问题，会让用户严格按报告的数字操作时必然失败。它们不会损坏文件（均在写入前失败），但会显著损害可用性与信任度，建议发布前至少修复第 1、2、3 条：

1. PNG 容量探测不参与 pipeline 内存预算，超大载体（实测 62.91 MP）报告 `is_estimated:false` 的 `max_raw_payload_bytes` 却无法真正写入。
2. 结构域 `inspect` 对 `eof`/`free_box`/`box_uuid` 报告 "unlimited (file grows)"，对 `chunk` 报告 "2 GiB - 1"，而引擎真实上限是 `256×host` 且被 clamp 到 `[64 MiB, 1 GiB]`。
3. JPEG 的 `max_raw_payload_bytes` 不含文件名开销，默认（保留文件名）按报告值嵌入必失败，且失败被报成"不支持的文件格式 / Huffman 过度优化"。
4. PNG 内容域载体经任何改变 ancillary chunk 元数据的无损重编码后无法提取（实测必现），文档未声明该边界。

---

## 2. 问题计数表

| 级别 | 数据损坏① | 算法/安全② | 内存/耗时③ | 健壮性④ | 架构/接口⑤ | 测试覆盖⑥ | 合计 |
|---|---|---|---|---|---|---|---|
| P0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |
| P1 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |
| P2 | 2（#1、#3） | 0 | 1（#5） | 1（#4） | 2（#2、#3） | 3（G1–G3） | **8** |
| P3 | 0 | 2（#8、#9） | 1（#10） | 0 | 3（#6、#7、#9） | 2（G4–G5） | **7** |

> 编号与正文一致；G1–G5 为"测试覆盖缺口"，在同一问题体系内计数，避免重复条目。

---

## 3. 分章详述

### 3.1 P2-1 PNG 容量探测忽略 pipeline 预算：超大载体过度承诺【实测】

**现象**
`strhide capacity` 对 8192×7680（62.91 MP）RGB PNG 报告：

```text
available_slots: 99082944
max_raw_payload_bytes: 12385345
recommended_max_bytes: 597914
is_estimated: false
```

按 `max_raw_payload_bytes = 12,385,345` 构造随机载荷执行 embed，在 7.1 s 后被拒绝（exit 1）：

```text
[ERROR] PNG carrier is too large for this payload: it needs about 9015 MiB of working memory
and the 8192 MiB budget would be exceeded (use the Hamming codec, a smaller --stc-h, or a smaller payload)
```

**触发条件（精确）**
RGB PNG、总像素数足够大（本机实测 62.91 MP 必现；按 `PIPELINE_BYTES_PER_PIXEL=61`、`MAX_PIPELINE_BYTES=8 GiB` 反解，约 >57.6 MP 即可能触发，具体取决于有效槽位与 codec/u），使用默认 `exclusion` 与 `Auto(STC)`，并严格按 `max_raw_payload_bytes` 嵌入。小图不受影响，因为基础预算远低于 8 GiB。

**证据**
- 容量计算只按"槽位 ≤ 池"记账，没有任何内存预算参与：
  - `rust/src/stego/png/engine.rs:2423-2453` `body_payload_fits` 唯一判据是
    `slots_for_codec(bits, codec, params.stc_h, u)? <= pool`
  - `rust/src/stego/png/engine.rs:2461-2483` `max_raw_payload_for_pools` 只是对上述函数二分
  - `rust/src/stego/png/engine.rs:2514` `let max_raw_payload_bytes = max_raw_payload_for_pools(...)` 
  - `rust/src/stego/png/engine.rs:2545-2554` / `2562-2603` probe 路径完全不调用预算检查
- 预算检查只存在于 embed/extract：
  - `rust/src/stego/png/engine.rs:536-551` `check_pipeline_budget`
  - 调用点仅 `rust/src/stego/png/engine.rs:1629`（embed）与 `2102`（extract）
- 用于反算"预算内最大槽位"的函数被限定为测试专用，无法被 probe 复用：
  - `rust/src/stego/png/engine.rs:553-558`

```rust
/// Body slots whose working set still fits the pipeline budget.
#[cfg(test)]
fn max_body_slots_within_pipeline(total_pixels: usize, trellis_h: Option<u8>) -> usize {
    let remaining = MAX_PIPELINE_BYTES.saturating_sub(pipeline_base_bytes(total_pixels));
    usize::try_from(remaining / pipeline_bytes_per_slot(trellis_h)).unwrap_or(usize::MAX)
}
```

**影响**
容量 API 的三项承诺同时失真：`max_raw_payload_bytes`（最大可写）、`is_estimated:false`（精确）、`recommended_max_bytes`（推荐值在极端载体下也不可靠，因为它基于 `ratio_slots` 而不是内存预算）。后果是用户/自动化流程"按报告准备载荷 → 必然失败"。**没有文件损坏**：失败发生在任何像素修改之前，载体保持原样。

**最小修法（不动 wire、不动公开函数签名）**
1. 将 `max_body_slots_within_pipeline` 去掉 `#[cfg(test)]`，作为内部函数保留（`rust/src/stego/png/engine.rs:553-558`）。
2. 在 `build_png_capacity_with_pools`（`2489`）计算完 pools 后，用 probe 解析出的 codec 与 `params.stc_h` 求 `slots_for_codec` 的最小 u，得到"该载体可承载的最大 ciphertext 位数"，再与 `max_body_slots_within_pipeline(total_pixels, Some(h))` 取 min，把结果折回 `max_raw_payload_bytes`。
   - 若在 `Auto` 下 u 会随载荷变化，保守做法是：对 `max_raw_payload_for_pools` 的返回值用 `body_payload_fits` 加一维预算判据（即"该 raw 字节对应的 codec/u 槽数 ≤ 预算内槽数"），保持"探测与写入同一条记账规则"的既有原则。
3. 若折算后与槽位上限不同，可把 `is_estimated` 置为 `true`；这是公开结构体字段语义的收紧，但不会破坏 wire。
4. 错误类型：预算超限应返回容量类错误（见 P2-5），不要把"容量不足"包装成 `UnsupportedFormat`。

**成本与风险**
低。单文件、纯探测侧改动，不触碰嵌入/提取算法路径；风险集中在"探测值略保守"（推荐值下降），不会造成无法写入。

**验收**
新增测试（建议 `rust/tests/heavy_tests.rs` 或 PNG 单元测试）：
- 合成 62 MP RGB PNG，得到 `probe.max_raw_payload_bytes = m`；
- 用 `m` 嵌入必须成功并提取一致；
- 用 `m + 1` 必须返回容量类错误（而非 `UnsupportedFormat`）；
- 小图（如 600×600）探测值保持现有回归基线。

---

### 3.2 P2-2 结构域 per-strategy 容量文案与引擎真实上限不一致【实测】

**现象**
对 86,854 B 的 `sample.png` 执行 `inspect`：

```text
chunk ... <= 2,147,483,647 B (2 GiB - 1)
eof: unlimited (file grows)
```

实际写入 73,400,320 B（70 MiB）失败：

```text
[ERROR] Payload (73400320 bytes) exceeds the maximum supported by this carrier
(67108864 bytes for a 86854 byte host)
```

**触发条件**
任何结构域载体的小/中尺寸场景都会出现（`eof` 永远显示 unlimited）；用户按 `inspect` 报告的 `capacity`/`limit` 准备载荷即触发。与密码、stealth、平台无关。

**证据**
- 引擎统一上限：`rust/src/structure/engine.rs:1849-1862`

```rust
fn structure_payload_limit(carrier_len: u64) -> u64 {
    const FLOOR: u64 = 64 * 1024 * 1024;
    carrier_len
        .saturating_mul(256)
        .clamp(FLOOR, crate::crypto::MAX_VERIFY_PAYLOAD_SIZE)
}
```

- 写入前按该上限拒绝：`rust/src/structure/engine.rs:1047` `let max_payload = structure_payload_limit(orig_host_size);`
- 读取端同一上限：`rust/src/structure/engine.rs:1883`
- 容量文案来源：
  - `rust/src/structure/adapters/eof.rs:25-33`：`capacity_bytes: None`、`limit: "unlimited (file grows)"`
  - `rust/src/structure/adapters/isobmff.rs:427`、`437`、`465`、`474`：同样 `"unlimited (file grows)"`
  - `chunk` 的 `2 GiB - 1` 来自适配器声明的单 chunk 上限，未与引擎上限取 min

**影响**
容量报告高估 1–3 个数量级（小载体尤甚：86 KB 宿主报告 2 GiB，真实 64 MiB）。用户按报告准备载荷后失败；自动化批处理会把失败归因于"载体损坏"而不是"超过上限"。**无损坏**：写入前拒绝。

**最小修法（不动 wire）**
在 `strategy_capacities` 的汇总处（或每个适配器返回值处）把 `capacity_bytes` 改为：

```rust
Some(min(strategy_native_limit, structure_payload_limit(host_len)))
```

`host_len` 由调用方在 inspect 时已知（`read_core` 同样读取 `carrier_len`，`rust/src/structure/engine.rs:1875`）。`limit` 文案用该实际值格式化，不再出现 `unlimited`；`eof` 的 `note` 保留 "appended at file EOF"。

**成本与风险**
低。纯展示层 + `StrategyCapacity` 数值口径变化；不像 wire，不影响已写入载体的读取。风险：某些适配器（如 ZIP 缺陷回退 eof）可能依赖 `None` 表示"无上限"，需要逐一确认调用方只读不写。

**验收**
- `inspect sample.png` 输出的所有 strategy 上限 ≤ 64 MiB；
- 对 100 KB 宿主报告上限 = 64 MiB（floor 生效）；
- 对 8 MiB 宿主报告上限 = 2 GiB（256× 生效，但被 1 GiB 上限截断为 1 GiB）；
- 按报告上限写入成功、上限 +1 失败。

---

### 3.3 P2-3 JPEG 容量不含文件名开销，默认嵌入失败且错误被误报【实测】

**现象**
`textures14.jpg` 的 `max_raw_payload_bytes = 10,364`：
- `--no-filename` 嵌入 10,364 B → 成功，提取 SHA-256 一致；
- 10,365 B → 被拒绝；
- 默认（保留文件名）嵌入 10,364 B → 失败，CLI 文案：

```text
[ERROR] 不支持的文件格式 ... This JPEG's Huffman table is over-optimised:
it cannot encode the modifications required for this payload size.
Please reduce payload or re-save the carrier with a standard (Annex K) table.
```

**触发条件**
JPEG 载体、载荷接近容量上限、**未指定 `--no-filename`**（CLI 默认携带文件名）。文件名长度 n 时，实际可用上限比报告值少 `1 + n` 字节（微头 `0x01` + 文件名长度前缀语义）。该现象在普通业务载荷（带文件名）下很容易触发，因为用户通常按报告值准备载荷。

**证据**
- 开销口径：`rust/src/stego/envelope.rs:81-89`

```rust
/// Note: this constant reflects minimal overhead for raw/text payloads without
/// a filename. When a payload carries a filename, the micro-header spends an additional
/// `1 + name_len` bytes. Capacity reports (`max_raw_payload_bytes`) reflect this minimal baseline.
pub const BODY_OVERHEAD: usize = 4 + 1 + MICRO_OVERHEAD_MIN + TAG_LEN; // 22 bytes
```

- 容量扣除：`rust/src/stego/jpeg/engine.rs:1828`
  `let max_raw_payload_bytes = max_ciphertext_bytes.saturating_sub(BODY_OVERHEAD);`
- 预算不足被映射为 `UnsupportedFormat` + Huffman 文案：
  `rust/src/stego/jpeg/engine.rs:890-891`、`978-979`、`1035-1036`、`1954-1955`
- 文件名开销已在变更日志中记录：`docs/CHANGES-20261104.md:105`（P2-8），但仅记录为"容量报告口径"，**未解决默认行为下的失败与错误分类**。

**影响**
默认选项下"按报告值嵌入"必失败；错误文案把容量不足归因于"不支持的文件格式/Huffman 表"，用户会去换载体或重存，而不是减小载荷。**无损坏**（写入前失败）。

**最小修法（不动 wire）**
1. 容量输出层面：`capacity`/`inspect` 明确输出"不含文件名"（或在 JSON 增加 `filename_overhead_bytes` 说明字段；这是公开结构体字段新增，向后兼容）。
2. 错误分类：`build_jpeg_capacity_info` 与写入路径中"分组/预算不足"的分支返回 `PayloadTooLarge` 或新增容量类错误，而不是 `UnsupportedFormat`；`Huffman over-optimised` 文案只保留给真正的"该系数方向无法编码"（即 Huffman 表本身不可用）情形。
3. CLI 不再对容量类错误加"不支持的文件格式"前缀。

**成本与风险**
低—中。错误变体变更会影响 CLI/GUI 的文案映射与既有测试断言；需同步 `core/i18n/messages.rs` 与相关测试。不动 wire、不改已写入载体。

**验收**
- 带 14 字符文件名嵌入 `max - 15` 成功；嵌入 `max` 返回容量类错误（不是 `UnsupportedFormat`）；
- `--no-filename` 行为保持不变；
- GUI 与 CLI 的错误文案均显示"容量不足/请减小载荷"，不显示"不支持的文件格式"。

---

### 3.4 P2-4 PNG 内容域载体经无损重编码后不可读【实测】

**现象**
对已嵌入内容域载荷的 600×600 PNG，用 Pillow 做**像素完全不变**的无损重编码：

```python
im = Image.open("content_pw.png")
im.save("content_pw_reenc.png", optimize=True)
```

随后提取：

```text
[ERROR] No valid payload found     (exit=1)
```

原文件 `content_pw.png` 用同一密码可正常提取（`hello fuzz payload`），说明载荷本身、密码和像素 LSB 都未被破坏。

**触发条件**
任何会改变"非 IDAT/prIv chunk 集合或 chunk 内容"的工具处理载体后（Pillow 重存、`optipng`/`oxipng` 的元数据整理、图像编辑器删除/新增 `tEXt`/`pHYs`/`gAMA`/`iCCP` 等、重新排列 chunk）。仅做 IDAT 重压缩且 ancillary chunk 完全不变时不受影响。

**证据**
- `png_pre_salt` 哈希所有非 IDAT/prIv chunk 的类型、长度与内容：`rust/src/stego/png/engine.rs:1142-1174`

```rust
let mut meta = Sha256::new();
for chunk in &image.chunks {
    if chunk.ty == *b"IDAT" || chunk.ty == *b"prIv" { continue; }
    meta.update(chunk.ty);
    meta.update((chunk.data.len() as u32).to_be_bytes());
    meta.update(&chunk.data);
}
```

- 该 `pre_salt` 进入 L1：`rust/src/stego/png/engine.rs:1477-1478`（embed）、`1913-1914`（extract）、`2600-2601`（probe）。
- 文档只承诺"嵌入前后不变"，未承诺"外部重编码后仍可读"：`docs/api/WIRE_SPEC.md:523-524`
  > `pre_salt` 只用嵌入前后不变的元数据（WAV 排除 PCM 摘要、FLAC 排除 STREAMINFO MD5；其他格式用参数集/像素布局摘要）。
- 变更日志中同类设计取舍（JPEG/HEVC）也写明"只使用嵌入不会改变的元数据"，例如 `docs/CHANGES-20261103.md:78`。

**影响**
用户用常见图像工具做无损优化后内容域载荷永久不可读，且失败表现为 "No valid payload found"，与"密码错误/无数据"无法区分，容易误判为载体损坏或密码记错。**不是文档承诺的功能缺陷**，但当前 CLI/GUI 与 README 没有把这一边界写清，属于能力边界 + 文档缺口。定级 P2（因实际使用中高频发生且不可逆）。

**最小修法**
- **本版（推荐，低成本）**：在 `README.md`（内容域章节）与 `docs/api/STEGO-API.md` 明确写出："内容域载荷依赖载体元数据作为 KDF salt；任何改变 PNG ancillary chunk / JPEG 元数据 / FLAC STREAMINFO 之外容器的处理都会导致不可读，请保留原始载体文件。"并在 `extract` 的 `NoHiddenData` 提示中加一句"如果载体被重编码，请使用原始输出文件"。
- **若要真正支持重编码（不建议本版做）**：把 `png_pre_salt` 改为只哈希 IHDR/尺寸/位深/通道等稳定字段，或对 chunk 排序规范化后再哈希。这会改变 L1 输入，**使既有全部 PNG 内容域载体不可读**，属于 wire 兼容性破坏，必须版本化并保留旧格式读取路径。

**成本与风险**
文档方案零风险；改 salt 方案高风险（破坏兼容性 + 需双格式读取），不建议发布前实施。

**验收**
- 文档与 CLI 提示更新（人工核对）；
- 新增回归测试：`ancillary_chunk_change_makes_payload_unreadable`（固化当前语义，避免未来静默改变）；
- 新增回归测试：`idat_only_recompression_keeps_payload_readable`（仅重压缩 IDAT、保留 chunk 元数据时必须可读）——这一条目前**未测**，G4。

---

### 3.5 P2-5 容量/内存类错误被归类为 `UnsupportedFormat`（与 P2-1、P2-3 同源）

**现象**
- PNG 预算超限：`rust/src/stego/png/engine.rs:544` 返回 `StrHideError::UnsupportedFormat(...)`
- JPEG 预算不足：`rust/src/stego/jpeg/engine.rs:890-891`、`978-979`、`1035-1036`、`1954-1955` 同样返回 `UnsupportedFormat`
- CLI 对所有 `UnsupportedFormat` 统一加"不支持的文件格式"前缀

**触发条件**
按容量报告的上限嵌入（见 P2-1/P2-3）；或载体大但内存预算不足时。

**影响**
错误语义与事实相反：文件格式完全受支持，问题是容量/内存。GUI/CLI 的错误处理、脚本退出码与用户决策都会被误导。**无数据损坏**。

**最小修法**
在 `errors.rs` 中使用既有容量类变体（若存在 `PayloadTooLarge`）或新增 `CapacityExceeded { needed, available }`；仅当真正的格式解析失败（变体不支持、Huffman 表不可编码）才用 `UnsupportedFormat`。同步更新 `core/i18n/messages.rs` 与测试断言。不动 wire。

**验收**
- 62 MP 超限场景返回容量类错误，CLI 不出现"不支持的文件格式"；
- 真正的渐进 JPEG / 调色板 PNG 仍返回 `UnsupportedFormat`（回归基线保持）。

---

### 3.6 P3-6 文档常量与实现不一致：`MAX_PLAINTEXT_LEN`

**现象**
`docs/api/WIRE_SPEC.md:509`：

```text
- `MAX_PLAINTEXT_LEN = HEADER_LEN_MAX = 2^26 - 1`（26 位上限，超出直接拒绝）。
```

实现 `rust/src/stego/envelope.rs:86-89`：

```rust
pub const MAX_PLAINTEXT_LEN: usize =
    (crate::stego::header::HEADER_LEN_MAX as usize).saturating_sub(BODY_OVERHEAD);
```

即 `67,108,863 - 22 = 67,108,841`。

**证据**：两处引用如上；`rust/src/stego/envelope.rs:361-364` 用该常量拒绝超限明文。

**影响**：文档读者会按 26 位边界设计载荷，比实现多 22 字节；`params.rs:649` 把该值作为 `max_payload_bytes` 对外暴露，API 文档与代码同样不一致。

**最小修法**：把 WIRE_SPEC:509 改为 `MAX_PLAINTEXT_LEN = HEADER_LEN_MAX - BODY_OVERHEAD = 67,108,841`，并注明 "26 位上限作用于 `body_len`（密文含 tag），明文再扣除 22B 微头/框架开销"。**不动 wire**。

**验收**：文档与 `envelope.rs:88` 数值一致；`params.rs` 单测（`1189-1198`）仍通过。

---

### 3.7 P3-7 WIRE_SPEC 要求 probe 与 embed 同公式，PNG 实测违反

**现象**：`docs/api/WIRE_SPEC.md:644-645` 声明容量探测与嵌入必须复用同一公式，否则容量与实际可写长度不一致。P2-1 的实测正是该条的反例。

**证据**：WIRE_SPEC:644-645；`rust/src/stego/png/engine.rs:2545-2584`（probe 无预算检查）对照 `1629`（embed 有）。

**影响**：规范自洽性被破坏；修复 P2-1 后该条自动满足。**修法**：修 P2-1，不单独改文档；或在文档补充"内存预算不属于线格式容量，probe 需额外折算"。

**验收**：同 P2-1。

---

### 3.8 P3-8 stealth 错密码提示与可否认性表述的张力

**现象**
结构域在 stealth 模式下用错误密码读取，CLI 输出：

```text
No hidden strhide data found
Note: the carrier shows envelope-shaped structures (private chunk 'prIv' at offset 86842
carries 222 bytes ...); a stealth envelope may exist under a different password.
```

**证据**
- 提示生成：`rust/src/structure/engine.rs:796-808`（`password_supplied` 分支 `800`、未提供密码分支 `805`）
- 可否认性声明：`docs/api/ARCHITECTURE.md:469` "自定义 magic 在 stealth 下被忽略（stealth 的魔数由密码派生，固定魔数会破坏可否认性）"
- 结构域错误密码返回 `Password("Invalid password or corrupted metadata")`：`rust/src/structure/engine.rs:1830`

**影响**：对"持有文件但无密码"的观察者，`inspect`/`read` 主动指出"这里有一个信封形状的私有 chunk（含偏移与长度）"，削弱了 stealth 面向的结构性可否认性；内容域则是统一 `NoHiddenData`（`docs/api/ARCHITECTURE.md:392`）。两者语义不一致。属于产品安全语义取舍，**不是可导致数据损坏的缺陷**。

**最小修法**：产品决策二选一：
1. 保持提示（对合法用户友好），在文档中明确"结构域不承诺抗结构性检测，内容域才承诺统一 `NoHiddenData`"；
2. stealth 模式下仅在用户显式 `--verbose`/`verify` 时输出结构提示，默认只输出 `NoHiddenData`。

**成本/风险**：仅 CLI 文案与文档，无 wire 影响。

**验收**：默认 `read`（stealth + 错密码）输出与内容域一致的单一错误；`--verbose` 才显示 hints。

---

### 3.9 P3-9 结构域与内容域错误语义差异未在文档声明

**现象**：结构域错密码返回 `Password("Invalid password or corrupted metadata")`（`rust/src/structure/engine.rs:1830`），内容域任一失败折叠为 `NoHiddenData`（`docs/api/ARCHITECTURE.md:392`）。实测结构域非 stealth 错密码确实输出"密码错误或缺失: Invalid password or corrupted metadata"，内容域输出 "No valid payload found"。

**影响**：跨域调用方若按"统一错误即可否认"编写逻辑会误判；文档只对内容域声明了统一折叠。

**最小修法**：在 `docs/api/ARCHITECTURE.md` 结构域章节补充"结构域有意区分密码错误与无数据（UBE 有魔数，无法否认），内容域统一 `NoHiddenData`"。**不动代码**。

**验收**：文档声明与实测行为一致。

---

### 3.10 P3-10 62 MP 载体的容量探测资源消耗

**现象**：62.91 MP PNG 的 `capacity` 探测耗时约 5.8 s；按 `PIPELINE_BYTES_PER_PIXEL = 61`（`rust/src/stego/png/engine.rs:520`）静态折算，仅基础工作集即 62.91 M × 61 B ≈ 3.6 GiB，另加解码像素与载荷相关结构。实测失败 embed 的 7.1 s 与预算文案 "needs about 9015 MiB" 与该量级吻合（该 "9015 MiB" 由实际 `total` 打印，非估算）。

**触发条件**：合法的大 PNG（≤ `MAX_PNG_PIXELS = 64 MP`，`engine.rs:506`）或声明 64 MP 的极小恶意 PNG（解码即分配像素缓冲）；`probe`/`inspect` 在计算 cost map 前没有可用内存门限。`rust/src/core/sysmem.rs:11` 已提供 `available_physical_memory()`，但从 PNG probe 路径未使用。

**影响**：交互式 `inspect`/`capacity` 可能造成数 GiB 峰值内存与数秒停顿；在低内存机器上可能触发 OOM（进程 `panic = "abort"`）。受 64 MP 上限约束，不会无限放大。

**最小修法（低风险）**：在 `probe_png_capacity`（`2562`）解码后、`compute_cost`（`2587`）前，用 `available_physical_memory()` 与 `pipeline_base_bytes(total_pixels)` 比较，超限则返回资源类错误而非继续计算；`embed` 侧已有 `check_pipeline_budget`，可复用同一门限。**不动 wire**。

**成本/风险**：低；但需避免在 CI/容器中因"可用内存波动"造成不稳定测试（阈值取保守比例，如 60%）。

**验收**：模拟可用内存不足（可用单元测试注入上限或环境变量）时，probe 快速返回资源错误而不是分配数 GiB；62 MP 正常机器行为不变。

---

### 3.11 测试覆盖缺口

| 编号 | 缺口 | 级别 | 为什么重要 | 现有覆盖情况（核对方式） |
|---|---|---|---|---|
| G1 | 大载体 PNG "probe 上限 = 可写入上限"的一致性测试 | P2 | 正是 P2-1 的直接护栏；当前 `max_body_slots_within_pipeline` 仅 `#[cfg(test)]`，但没有测试把它接到 probe | 通读 `rust/src/stego/png/engine.rs:2423-2584` 与测试模块；heavy 矩阵未见 62 MP probe |
| G2 | 结构域 per-strategy 容量 ≤ 引擎上限的断言 | P2 | 防止 `unlimited`/`2 GiB-1` 文案回归 | 检索 `rust/tests` 未见对 `strategy_capacities` 数值与 `structure_payload_limit` 交叉校验 |
| G3 | JPEG "带文件名按 max 嵌入"边界测试 | P2 | 锁定文件名开销与错误分类 | `textures14.jpg` 极值实测覆盖 `--no-filename`；测试侧未覆盖默认文件名边界 |
| G4 | PNG `pre_salt` 稳定性语义测试（仅 IDAT 重压缩可读 / ancillary 变化不可读） | P3 | 防止未来无意改动 salt 输入导致全量旧载体失效，或反之误以为支持重编码 | 通读 `rust/src/stego/png/engine.rs:1142-1174` 与测试模块；未见到 chunk 变异用例 |
| G5 | 内容域伪造头（CRC 合法、参数越界）错误分类负面测试 | P3 | 验证提取失败是否统一 `NoHiddenData`，而非 `General` | 静态推断：`effective_params.validate()?` 可能把 `General` 直接上抛；未构造样本，列为未证实 |

**建议最小新增测试集**
1. `png_probe_matches_embed_at_pipeline_limit`（G1）
2. `structure_strategy_capacity_never_exceeds_payload_limit`（G2）
3. `jpeg_max_capacity_with_filename_boundary`（G3）
4. `png_ancillary_chunk_change_invalidates_and_idat_recompress_keeps_payload`（G4）
5. `forged_content_header_is_indistinguishable_from_no_payload`（G5，先证实再决定是否修复）

---

## 4. 已核实无问题清单（避免下一轮重复"发现"）

| 项目 | 核对方式 | 结论 |
|---|---|---|
| 结构域写入原子性 | 通读 `rust/src/core/commit.rs`：`TmpGuard 103-123`、`temp_path_for 158-164`、`write_bytes_atomic 466-482`、`rename_with_retry 487-503`、`create_carrier_backup 198-210`（`create_new`）、`reject_read_only_target 221-236`、`TargetLock 255-290`、`commit_carrier_bytes 308-346` | 完整：temp + fsync + rename，失败可回滚，不覆盖既有目标 |
| 同文件/同路径误覆盖 | `same_file 43-77`、`reject_carrier_output 86-96` | 有显式拒绝 |
| 恢复前完整性校验 | `rust/src/structure/engine.rs` 约 `2090-2400`：按 `orig_host_sha256` 校验后才提交 | 载体被改动时安全失败（README:58 "fails closed if the carrier was re-encoded"） |
| 内容域写入后自校验 | PNG `verify_png`（结构可解析→header→AEAD 三级）、JPEG dct-io 重编码校验 | 写入成功后能反读，否则不提交 |
| header 与 body 槽位记账 | `rust/src/stego/png/engine.rs` `SlotPlan::build` / `header_pool` / `permute_prefix`（`1131-1187`）；class-preserving moves `rust/src/stego/coding.rs:355-395` | header 槽位不出现在 body 池；permutation 前缀稳定；HILL 用 `class_value`（`&0xF8`）使 header/body 嵌入不改变 cost 排序 |
| header 全字段校验 | `rust/src/stego/header.rs` `validate_common`/`decode`（约 `150-430`）：version/flags/suite/body_len/CRC/reserved/ext_len/algorithm_id/channel_mode/class_rule/codec_id/stc_h/u/p1/p2/epsilon/sigma | 齐全；CRC 仅拦意外损坏，安全由 AEAD AAD 保证 |
| AAD 覆盖 | `rust/src/stego/envelope.rs:94-107` `build_v4_aad = prefix || format_id || base_header || extension` | header/扩展区/格式 id 全部认证 |
| 错误密码语义（内容域） | 实测：错密码 → `No valid payload found`；`docs/api/ARCHITECTURE.md:392` | 统一折叠，符合设计 |
| 随机性与 nonce | `rust/src/core/crypto.rs`：salt 16B 随机、nonce 12B、Seeded 模式 binding 含 payload 避免 nonce 复用、chunk nonce = base XOR index 且 1 GiB 上限内无 32 位回绕 | 未发现复用/可预测问题 |
| 极值往返 | 实测：JPEG 10,364 B、WAV 351,775 B、FLAC 33,076 B 均恰好成功，+1 拒绝；最大容量嵌入后提取 SHA-256 一致 | 探测与写入在正常/最大值下一致（PNG 大图例外见 P2-1） |
| 双域共存 | 实测 heavy `dual_domain_coexistence_matrix` 80/80 PASS（10 载体 × 80 场景） | 两域顺序无关 |
| 双信封叠加 | 实测：写入第二个 stealth 信封会打印 "injecting now would stack a second envelope"；restore 顺序错误时明确要求 reverse order，两个密码均可读 | 非静默损坏 |
| 变异鲁棒性 | 实测 360 次单比特变异（PNG content/structure/capacity/embed/write、JPEG/WAV extract/inspect/capacity），0 panic/崩溃 | 解码路径未发现 panic |
| Hamming 编解码测试 | `rust/src/stego/coding.rs:610-700`：k=2..5 全消息/全初态、k=1..5 多长度 | 覆盖充分 |
| 大文件整数边界 | 通读 RIFF/ZIP/ISO-BMFF 路径：存在显式 4 GiB 检查，ZIP64 回退 eof | 未发现 >4 GiB 截断 |
| 构建与静态检查 | `cargo build --release --all-features` 成功（约 1 min 10 s）；`cargo clippy --all-features --all-targets` 无警告 | 无编译/clippy 阻塞 |
| 全量测试 | `cargo test --all-features --all-targets`：**1020 passed, 0 failed, 26 ignored**（535+149+139+115+41+25+14+2）；日志 `temp/test-all.log` | 全绿 |
| heavy 算法矩阵 | `cargo test --release --test heavy_tests -- --ignored heavy_all_algorithms_png_jpeg_matrix`：**PASS 39 / SKIP 12 / FAIL 0**，47.3 s；24 MP/48 MP PNG（hill/suniward/mipod）与 JPEG（uerd/juniward/jmipod）往返成功；调色板/APNG/隔行 PNG、渐进 JPEG 被优雅拒绝 | 算法实现无回归 |

---

## 5. 未证实项清单

| 编号 | 推断 | 缺什么证据 | 结论 |
|---|---|---|---|
| U1 | 内容域提取时，CRC 合法但参数越界（如 `stc_u`、`epsilon` 超限）的伪造头会让 `effective_params.validate()?` 返回 `General` 而非 `NoHiddenData`，从而与"无数据/错密码"可区分 | 需要构造"CRC 重算 + 参数越界"的 PNG/JPEG 样本并实测 CLI 输出与退出码 | **未证实**。本轮变异测试仅做单比特翻转，未覆盖 CRC 合法化后的参数越界 |
| U2 | 62 MP 探测峰值内存精确值约 4 GB | 需要外部采样（如 Process Explorer/VMMap 峰值 Commit） | 仅静态折算（61 B/px ≈ 3.6 GiB）+ 预算文案 9015 MiB 间接印证；未精确测量 |
| U3 | 跨平台（Linux/macOS）`rename`/目录 fsync/`TargetLock` 行为与 Windows 一致 | 需要 Linux/macOS 实机或 CI 运行写入-中断-恢复用例 | **未证实**。本轮仅在 Windows 10 实测 |
| U4 | GUI 调用点对容量类错误的展示是否与 CLI 同样误导 | 需要阅读 `gui/src-tauri/src/commands/*` 与前端 i18n 的错误映射（本轮仅抽查 CLI） | **未证实**。报告不据此下结论，但建议修 P2-5 时一并核对 |
| U5 | `chunk` 策略报告的 `2 GiB - 1` 是否还有适配器层面的真实单 chunk 限制叠加 | 需要阅读 `structure/adapters/png.rs` 等 chunk 注入实现（本轮只核对了报告值来源与引擎上限） | **未证实**。不影响 P2-2 的"文案与引擎上限不一致"这一已证实结论 |

> 未列入本表的"可能/也许"类猜测一律不写入报告，避免凑数。

---

## 6. 建议修复顺序（分批，每批可独立验证）

**批次 A（发布前建议完成，均为容量一致性，不改 wire）**
1. P2-1 PNG probe 接入 pipeline 预算（含 G1 测试）。
2. P2-2 结构域 per-strategy 容量取 min（含 G2 测试）。
3. P2-3 + P2-5 JPEG 文件名口径与错误分类（含 G3 测试）。
   - 验证：`cargo test --release` 对应新测试 + 手工 62 MP/86 KB/JPEG 极值三组实测。

**批次 B（发布前或发布后首批，文档/CLI 语义）**
4. P3-6 `MAX_PLAINTEXT_LEN` 文档修正。
5. P3-8 / P3-9 两个域的可否认性语义声明与 CLI 提示收敛。
6. P2-4 的"能力边界"文档 + G4 回归测试（不改 `pre_salt`）。

**批次 C（可排期，性能/资源）**
7. P3-10 probe 前内存门限（复用 `sysmem::available_physical_memory`）。
8. U1 先构造样本证实，再决定是否把伪造头路径折叠为 `NoHiddenData`（G5）。
9. U2/U3/U4 补测：峰值内存采样、Linux/macOS CI、GUI 错误文案核对。

每批完成后统一运行 `cargo test --all-features --all-targets` + `cargo clippy --all-features --all-targets`，并对批次 A 追加 `heavy_all_algorithms_png_jpeg_matrix` 与 `dual_domain_coexistence_matrix`。

---

## 附录：本轮实际执行的验证命令与结果

| 命令 | 结果 |
|---|---|
| `cargo build --release --all-features` | 成功，约 1 min 10 s |
| `cargo test --all-features --all-targets` | 1020 passed, 0 failed, 26 ignored |
| `cargo clippy --all-features --all-targets` | 无警告 |
| `cargo test --release --test heavy_tests -- --ignored heavy_all_algorithms_png_jpeg_matrix` | PASS 39 / SKIP 12 / FAIL 0（47.3 s） |
| `cargo test --release --test heavy_tests -- --ignored heavy_dual_domain_coexistence_matrix` | 80/80 PASS（42.15 s） |
| `strhide capacity temp/audit/px62mp.png --json` | `max_raw_payload_bytes=12385345`, `is_estimated=false`，约 5.8 s |
| 按 12,385,345 B 嵌入 62 MP PNG | 失败：需约 9015 MiB，预算 8192 MiB（exit 1，7.1 s） |
| `strhide inspect temp/audit/sample.png` | `chunk ... 2 GiB - 1`；`eof: unlimited (file grows)` |
| 结构域写入 70 MiB 至 86,854 B 宿主 | 失败：上限 67,108,864 B |
| JPEG `textures14.jpg` `--no-filename` 嵌 10,364 B | 成功，提取 SHA-256 一致；10,365 B 拒绝 |
| JPEG 默认文件名嵌 10,364 B | 失败：`UnsupportedFormat` / "Huffman table is over-optimised" |
| WAV `remake02.wav` 351,775 B / FLAC `01_Sphere.flac` 33,076 B | 往返一致 |
| PIL 无损重编码 `content_pw.png` → `content_pw_reenc.png` 后 extract | `No valid payload found`（exit 1） |
| 单比特变异 360 次（`temp/audit/fuzz*.ps1`） | 0 panic / 0 崩溃 |

---

## 修复跟进（2026-11-05 19:24，审查当日完成批次 A）

以下条目已在审查当日修复并实测验证，详见 `docs/CHANGES-20261105.md` 顶部条目：

| 条目 | 状态 | 验证 |
|---|---|---|
| P2-1 PNG probe 忽略 pipeline 预算 | **已修**（probe 复用 embed 预算公式） | 62.9 MP：报告值 12,385,345 → 10,457,650；按新上限（`--no-filename`）嵌入 30.31 s、提取 SHA-256 一致；旧值快速拒绝 |
| P2-2 结构域容量文案 | **已修**（`apply_engine_payload_limit` clamp） | 85,189 B 宿主 inspect 报 `<= 67,108,864 B`；写 70 MiB 被拒为"容量不足" |
| P2-3/P2-5 错误分类 | **已修**（新增 `PayloadTooLarge`，容量类错误全部归类） | JPEG 默认文件名按 max 嵌入 → `容量不足: Payload too large for this carrier: its over-optimised Huffman table ...`；`--no-filename` 嵌入/提取一致 |
| P2-4 重编码边界 | **文档 + 回归测试**（不改 `pre_salt`，语义固化） | 新增 `idat_only_recompression_keeps_payload_readable` / `ancillary_chunk_change_makes_payload_unreadable`；README/STEGO-API 已声明边界 |
| P3-6 `MAX_PLAINTEXT_LEN` 文档 | **已修** | WIRE_SPEC:509 改为 67,108,841 |
| P3-7 probe/embed 同公式 | **已修**（随 P2-1） | WIRE_SPEC §13.6 补预算条款 |
| G1/G2/G4 测试缺口 | **已补** | 见 CHANGES 测试清单 |
| G3 / P3-8 / P3-9 / P3-10 / U1–U5 | 未动 | 按报告批次 B/C 排期 |

`cargo test --all-features --all-targets` 全绿；`cargo clippy --all-features --all-targets` 无警告。
