# 私有 Profile 审计报告评审与实施路线

> 评审对象：`docs/PRIVATE_PROFILE_AUDIT_20261108.md`
> 评审方式：逐条对照 `rust/src` 实际代码核对（行号以本次核对时为准）
> 结论：**事实核对基本准确，逻辑框架有偏差，方案方向正确但优先级与实现路径需要重排**

---

## 1. 总体结论

| 维度 | 评价 | 说明 |
| :--- | :--- | :--- |
| 事实准确性 | 约 90% | 列出的硬编码常量、标签、行号绝大多数能在代码中实证命中；有 1 处明确错误、1 处无效工作、若干行为定性偏差 |
| 问题归因 | 部分混淆 | 把「**可观测的容器指纹**」和「**不可观测的 KDF 标签**」放在同一张问题清单里，导致优先级失真 |
| 设计原则 | 正确 | 「私有参数必须是编译期常量」与现有架构（`Dialect` / `StructureProfile` / `StegoProfile` 全 `const`）一致，也符合 `src/cli/helpers.rs:380` 已有的注释约定 |
| 扩展方案 | 结构合理，成本估算缺失 | 4.1 / 4.2 的字段设计（`Option<&'static …>` + `Copy` + `const fn`）可行；但 `adapter_tags` 要穿到 `HostAdapter` trait，报告未提及这是跨 13 个 impl 的改动 |
| 4.3 落地方案 | 可直接使用 | 已核对：`StrHide::new()`（const）、`with_dialect()`、`run_cli_from()` 均真实存在，主入口 `cli::run_cli()` 正是 `StrHide::new().run_cli_from(env::args_os())`，替换点清晰 |
| 结论强度 | 过度承诺 | 「即可实现 100% 消除开源公开指纹」不成立 |

---

## 2. 逐条核对

### 2.1 容器适配器硬编码（§2.1 全表核对通过）

| 报告条目 | 代码事实 | 判定 |
| :--- | :--- | :--- |
| `png.rs:13-14` `CHUNK_PRIV`/`CHUNK_STEG` | 常量定义在 13-14 行；写入 190、546 行，locate 匹配 266/361/444 行 | 准确，且**高价值**：chunk 树是明文，第三方 `pngcheck` 级工具直接可见 |
| `riff.rs:11` `RIFF_CHUNK_FOURCC = *b"SHRD"` | 11 行定义，144 写、188/370 匹配 | 准确，**高价值** |
| `isobmff.rs:11-13` `MP4_UUID_NEUTRAL` | 16 字节常量，102/109 写、160/184/380/398 匹配 | 准确，**高价值** |
| `jpeg.rs:14` `JPEG_APP15` | 14 行；注入路径写 `0xFF 0xEF`；同文件已存在 `JPEG_COM` 常量 | 准确，**高价值**（改动成本最低，已有 COM 分支可复用） |
| `pdf.rs:588-590` `/Type /Metadata` | `pdf_obj_header()` 在 589 行返回固定格式串 | 准确，价值中等（PDF 增量更新对象本身合法，`/Type` 名可换但收益有限） |
| 行号漂移 | 报告 png/engine 1710 → 实际 1508/1741；audio/core 464 → 实际 196；jpeg 723 → 725 | 不影响结论 |

### 2.2 结构域 KDF 与协议常量（§2.2 核对通过，但定性需修正）

| 报告条目 | 代码事实 | 判定 |
| :--- | :--- | :--- |
| `PBKDF2_ITERATIONS = 100_000` | `core/crypto.rs:106`，全仓仅 `crypto.rs:214` 一处使用 | 准确，且**改动面极小**（只有 1 个调用点） |
| 5 个 HKDF 标签（payload/metadata/header-mask/stealth×2/pe-mask） | 245/247/264/266/268/293/295/308/341 行全部命中 | 准确 |
| `derive_trailer_crc_mask` 盐 `b"STEA"` | `crypto.rs:317-328`，硬编码 `0x53,0x54,0x45,0x41` | 准确，**且是全仓已有的「CRC 掩码」先例**，报告未指出这点 |
| `CURRENT_VERSION = 0x02` | `structure/envelope.rs:59` | 准确。但版本字节位于被密钥流掩码的 `ChannelHeader` 内，定制它**只增加隔离、不消除可观测指纹** |

### 2.3 内容域（§3 大部分成立，含 1 处错误 + 1 处无效项）

| 报告条目 | 代码事实 | 判定 |
| :--- | :--- | :--- |
| `V4_AAD_PREFIX` 硬编码 | `stego/envelope.rs:105` | 准确 |
| `hdr-stc` / `ext-stc` 种子标签未暴露 | `format.rs:482-483` 直接写死；`WireCipherProfile`（`format.rs:308-323`）确实只有 5 个标签 | 准确，是真缺陷（功能上的域隔离缺口） |
| **三大引擎硬编码 `b"strhide-v4-hdr-magic"`** | `png/engine.rs:1508/1741/1950/2674`、`jpeg/engine.rs:725/1243/1509`、`audio/core.rs:196` | **代码事实准确，但结论无效**：见 §3.1 |
| 格式 ID 常量 | `PNG=1`（png/engine.rs:76）、`WAV=2`/`FLAC=3`（audio/mod.rs:49-51）、`JPEG=4`（jpeg/engine.rs:65）、`HEVC=5`（hevc/engine.rs:97） | 准确，但报告低估了改动成本：见 §3.2 |
| `CONTENT_L1_PBKDF2_ITERATIONS = 200_000` | `crypto.rs:114` | 准确 |
| FLAC 相位标签 | `audio/mod.rs:108` `flac_body_phase()` | 准确（对体相位域分离，只在体块生效） |
| **`audio/perm.rs:29` `PERM_LABEL` 绕过 Profile** | **错误**：见 §3.1 | 需更正 |
| HEVC 会话盐标签 | `hevc/engine.rs:454` `hevc_session_salt()` | 准确 |
| KB 高通核 / `kernel_id` 固定 0 | `params.rs:138-141` 注释明确说明是**有意为之**；`header.rs:409` 对 `kernel_id != 0` 直接报错 | 准确，但报告把「一个被显式拒绝的字段」当成「漏掉的字段」 |
| 无掩码 CRC32 | `header.rs:288/426`、`jpeg/header_v4.rs:86`、`hevc/engine.rs:188/260` 全部是裸 `crc32fast::hash` | 准确，**且有真实检测价值**：见 §3.3 |

---

## 3. 三处需要更正/降级的问题

### 3.1 `audio/perm.rs` 的 `PERM_LABEL` 不是「绕过 Profile」

报告称「此处没有读取 `WireCipherProfile.perm_label`，导致配置的置换标签在音频引擎中未生效」。

实际链路是：

1. `format.rs:503` `let perm_info = suite_info(cipher.perm_label, domain, suite);` → `derive_l3_session_keys` 用 **profile 的 `perm_label`** 派生 `perm_seed`（32 字节，密钥态）；
2. `perm.rs:59` `KeyedPermutation::new(seed, n)` 拿到的就是上面的 `perm_seed`，文档注释也写明「already domain separated by the format profile」；
3. `PERM_LABEL` 是对**已经域分离的密钥态种子**再加一层内部域分隔（`SHA256("strhide-audio-perm-v1" ‖ seed ‖ n)` → Feistel 轮密钥）。

所以自定义 `perm_label` **是生效的**，`PERM_LABEL` 是一个纯内部常量，不承担指纹作用。**报告这一条应删除**，否则会把一次无效改动写进计划。

### 3.2 `magic_label` 对 PNG/JPEG/WAV/FLAC 是死参数（提出了无效工作）

`format.rs:477-484`：`magic_label` 只参与 `magic4`（4 字节）的派生，`HeaderLocatorKeys.magic4` 的文档写明「Derived 4-byte HEVC magic (unused by the other formats)」。全仓使用 `magic4` 的只有 `hevc/engine.rs:1382/2119`（写 superblock 魔数、读回校验）。

`format.rs:846` 的测试甚至直接断言 `png.magic4 == hevc.magic4, "magic label is not per-format"`。

结论：给 `PngFormatProfile` / `JpegFormatProfile` / `AudioFormatProfile` 加 `magic_label` 字段**不会改变载体中的任何字节、任何密钥**，只多一个没人读的字段。报告把它列为「4.2 第 2 条要修复的遗漏调用」是**无效工作**。

正确做法二选一：
- **推荐**：不改接口，把 `derive_l2_locator_keys` 的 `magic_label` 参数改为仅 HEVC 使用的内部常量（或把 `magic4` 的派生移进 HEVC 模块），顺手消除「四个引擎传同一字面量」的误导感；
- 或者按报告加字段，同时在 `is_official()` 之外明确标注该字段为 no-op —— 不推荐。

### 3.3 「100% 消除开源公开指纹」不成立

需要把两类东西分开，这也是整份报告最需要修的地方：

| 类别 | 举例 | 是否出现在载体/线路上 | 定制后的实际收益 |
| :--- | :--- | :--- | :--- |
| **A. 可观测指纹** | `prIv`/`stEg` chunk、`SHRD` fourcc、`MP4_UUID_NEUTRAL`、APP15、PDF 字典串、裸 CRC32、`CURRENT_VERSION` 字节、`format_id` 字节 | **是**（明文容器结构 / 明文头部字段） | **消除第三方静态扫描特征**，这是报告标题声称的目标 |
| **B. KDF 派生标签** | `strhide-payload`、`hdr-stc`、`aad_prefix`、`flac-body-phase`、`hevc-session` | **否**，只参与密钥派生，永不落盘 | **只买到「两个私有构建互不兼容」**，对检测率零影响 |

也就是说：把 §2.2、§3.1 全部 B 类参数都做完，含 `strhide` 字样的公开指纹一个都没少（它们本来就不在线路上）；真正改善第三方检测观感的，是 §2.1 的容器 tag 和 §3.3 的 CRC 掩码。

报告把这两类混在一起，导致**优先级排反了**：成本最低、收益最大的容器 tag 和「无法判定优先级的标签」并列，甚至把无效项（magic_label）排进实施清单。

> **2026-11-08 更正**：本节初稿曾据此认定「裸 CRC + 明文头部可用廉价暴力探测命中」。复核 `png/engine.rs:1205-1209` 与 `prng.rs:231-234` 后确认**该推断错误**：`fisher_yates_prefix_from` 的 `j = i + gen_range(n - i)` 使前缀槽位集合从**整个候选池**中密钥化抽取，未持密钥既不知集合也不知顺序，无法重组 64 字节头部。
> 因此**内容域头部的明文字段（`version` / `format_id` / 裸 CRC32）在抗定向检测上收益为 0**，CRC 掩码也不值得做。详细论证与排序见 `docs/PRIVATE_PROFILE_COSTED_PLAN_20261108.md` §1.1。

### 3.4 其他行为定性偏差

- `format_id`：报告说「参与 AAD 认证与头格式解析」。实际 `header.rs:333-337` 校验 `format_id == expected_format && (1..=3).contains(&expected_format)`，并且 PNG 特有校验是 `if format_id == 1 { … }` 分支。**改成非 1..=3 的值会直接击穿分支逻辑**，不是加个 profile 字段能解决的（见 §5 Phase 3）。
- `kernel_id`：报告建议「支持编译期注入自定义核」。注意 `header.rs:409` 明确拒绝 `kernel_id != 0`，且 `bytes[43]`/`bytes[57]` 保留字节必须为 0。做这件事 = 新增一个 wire identity（`kernel_id = 1`）+ 解码放行 + 成本模型分派 + 提取侧一致，属于中型特性，不是「补一个字段」。

---

## 4. 报告遗漏的问题（建议补入计划）

1. **分析器是方言盲的（自检不一致）**
   `analysis.rs:1135` 直接用 `STANDARD_HEADER_MAGIC` 扫描，`AnalysisFacade`（`facade.rs:1182-1185`）持有 `&StrHide` 却标注 `#[allow(dead_code)] engine` 完全没用。
   后果：私有构建改掉 magic 之后，**自己内置的隐写分析器认不出自己产出的载体**，只会退化到容器启发式。这属于「私有版本必须自洽」的硬要求，报告完全没有涉及。
   反向的好消息：`analysis.rs:660-700` 的 PNG 分类不特判 `prIv`/`stEg`，任何私有 chunk 都会被报成 `png:private-chunk`，所以改 tag **不需要**同步改分析器。

2. **`WireCipherProfile` 不是 `#[non_exhaustive]`**
   `format.rs:308` 起是裸结构体，4 个 `pub const` 常量用结构体字面量初始化。加字段对库外使用者是**破坏性变更**。项目未发布（`AGENTS.md`），可以做，但必须在计划里显式写明「4 个 official const 同步更新 + crates 语义化版本说明」。

3. **`StructureProfile` 加 `adapter_tags` 的穿参成本被隐去**
   `HostAdapter`（`adapters/mod.rs:157`）是**无状态的 `&'static dyn` 全局单例**（`registry.rs` 的 `ADAPTERS` 数组），没有 per-instance 配置入口。要让 tag 生效，必须给 `inject` / `locate` / `locate_with_header_magic` 增加 `&ContainerTags` 参数：13 个 `inject` impl、约 8 处测试直接调用点、`engine.rs` 5 处调用。机械但要一次性做完，不能只加字段。

4. **没有被评估的容器面**
   ZIP（注释/EOCD 区）、MKV（`void`/自定义 Element）、PE（`pe_codebits` 指令替换 `crypto.rs` 之外的 `pe_codebits.rs:918` 标签为 v1，与 `derive_channel_header_mask` 的 v2 不一致）。报告只覆盖 PNG/JPEG/MP4/HEIF/RIFF/PDF。

5. **字节级护栏缺失**
   任何一处默认路径被改动都会破坏 `scripts/baseline_hash.py --check` 与现有测试断言。计划里必须写死「官方默认必须字节不变」。

6. **没有「隔离验证」的验收口径**
   现有 `examples/private_profile.rs` 已演示「私有方言必须让官方方言读到 `NoHiddenData`」这一不变量，新参数应逐个扩展这个 example / 加集成测试，而不是只加字段。

---

## 5. 实施路线（按价值 × 成本重排）

### Phase 0：护栏（0.5 天）

- `python scripts/baseline_hash.py --check` 先跑一次拿绿基线；
- 新增 `tests/private_profile_isolation.rs`：对每个待定制维度断言「私有写 → 私有读 OK，官方读 `NoHiddenData`」；
- 扩展 `examples/private_profile.rs` 覆盖容器 tag。

验收：`cargo test --all-features --all-targets` 全绿 + baseline 绿。

### Phase 1：容器标识（A 类，收益最高，成本中等）★ 优先

1. `structure/params.rs` 新增：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContainerTags {
    pub png_chunk: [u8; 4],        // b"prIv"
    pub png_legacy_chunk: [u8; 4], // b"stEg"：读侧仍接受的第二 tag
    pub riff_chunk: [u8; 4],       // b"SHRD"
    pub isobmff_uuid: [u8; 16],    // MP4_UUID_NEUTRAL
    pub jpeg_marker: [u8; 2],      // [0xFF, 0xEF]
    pub pdf_dict_type: &'static str, // "/Metadata"
}
impl ContainerTags { pub const OFFICIAL: Self = ...; }
```

2. `StructureProfile` 新增 `pub container_tags: Option<&'static ContainerTags>` + `with_container_tags()` + `tags()`（返回 `&ContainerTags`，`None` → `&ContainerTags::OFFICIAL`），并更新 `is_official()`。
3. `HostAdapter` 的 `inject` / `locate` / `locate_with_header_magic` 增加 `tags: &ContainerTags` 参数；13 个 impl 多数忽略，实际消费的只有 png / riff(wav,webp) / isobmff(mp4,heif) / jpeg / pdf。
4. `analysis.rs` 不需改（见 §4.1），但要补一条测试断言私有 chunk 会被报 `png:private-chunk`。
5. 约束：PNG chunk 名必须满足规范位语义（第 3 字母大写 = private ancillary，第 4 字母小写 = safe-to-copy），在 `ContainerTags` 上加 `const` 校验函数并在 `validate()` 里调用。

验收：官方默认 baseline 字节不变；自定义 tag 的载体用官方 `locate` 返回 `NoHiddenData`；`cargo clippy -D warnings`。

### Phase 2：派生标签补全（B 类，隔离价值，几乎无检测价值，成本最低）

1. `WireCipherProfile` 增加 `hdr_stc_label`、`ext_stc_label`、`aad_prefix`（后者虽在 `stego/envelope.rs`，但语义属 cipher 表）；4 个 official const 填回现值，保证字节不变。
2. `HevcFormatProfile` 增加 `session_salt_label`；`AudioFormatProfile` 增加 `flac_body_phase_label`（仅 FLAC 侧消费）。
3. `StructureProfile` 增加 `pbkdf2_iterations: Option<u32>`（`crypto.rs:214` 唯一调用点，穿一个 `&StructureProfile` 即可）；顺带把 `crc_salt: Option<[u8;4]>` 补上（`derive_trailer_crc_mask`）。
4. 删除报告 4.2 第 2 条中的 `magic_label` 扩容项（§3.2）。
5. 保留 `stealth_domain`/`magic` 在 stealth 模式下失效的既有语义（`structure/params.rs:50` 文档已说明）。

验收：官方字节不变；`cargo test --all-features` 全绿；`examples/private_profile.rs` 扩展后通过。

### Phase 3：内容层 wire 常量（A 类，收益中，成本高，需单独评审）

按成本从低到高，建议拆三个独立 PR（**注：1 与 2 经复核后判定收益为 0，见上方更正与成本评估文档，实际不推荐实施**）：

1. **CRC 掩码**（推荐先做）：`SpatialHeaderV4` / `JpegHeaderV4` / `HevcSuperblockV4` 的 encode/decode 增加 `crc_mask: u32`（0 = 官方裸 CRC），掩码值由 cipher/profile 派生（可复用 `derive_trailer_crc_mask` 的模式：`CRC32(master ‖ label)`）。收益：击穿 §3.3 的廉价暴力探测。
2. **`format_id` / `version` 定制**：需先把 `header.rs:333-337` 与 `if format_id == 1` 的硬分支改成「profile 声明本引擎 id + 引擎自校验」，再做常量下沉。风险最高的部分，必须单独立项。
3. **自定义高通核**：新增 `kernel_id = 1` wire identity，`header.rs:409` 放行为白名单，`png/cost/hill.rs` 增加 `Kernel::Private(&'static [[f32; N]; N])` 分派。收益是**抗统计检测**而非抗格式扫描，和本报告的目标不同，建议独立评估。

### Phase 4：私有构建入口 + 文档

1. 新增 `src/bin/strhide-private.rs`（feature `private-build` 门控），内容即报告 4.3 的写法（已核对 API 可用）：`StrHide::new().with_dialect(PRIVATE_DIALECT).run_cli_from(env::args_os())`。
2. `AnalysisFacade` 改为使用 `self.engine.dialect()` 的 magic 扫描（Phase 4 与 Phase 2 的 `magic` 定制配套）。
3. `docs/` 增补一份 `PRIVATE_BUILD.md`：字段效果表（照 `HevcFormatProfile` 文档那种「改它会怎样」表），加一句硬约束「私有方言与官方方言必须互相 `NoHiddenData`，不得给出可区分的错误」。

---

## 6. 优先级一览

| 项 | 类别 | 检测收益 | 隔离收益 | 成本 | 建议 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 容器 tag（PNG/RIFF/UUID/APP15/PDF） | A | 高 | 高 | 中（穿参 13 impl） | Phase 1 先做（= 成本评估 S1） |
| 结构域注入形状（段数/长度规律） | A | 高 | 低 | 高 | 原报告未提，见成本评估 S2 |
| 私有成本模型（核/权重） | 统计面 | 中高 | 高 | 中 | 抗定向检测唯一有效杠杆（S3） |
| `aad_prefix` / stc 标签 / phase / session 标签 / PBKDF2 | B | 无 | 中 | 低 | Phase 2（= S4） |
| CRC 掩码 | — | **0（已更正）** | 中 | 中 | **不做** |
| `format_id` / `CURRENT_VERSION` | — | **0（已更正）** | 高 | 中/极低 | **不做** |
| 自定义高通核 | 统计面 | 中（抗模型检测） | 高 | 高 | 单独立项 → 归入 S3 |
| `magic_label` 扩容 | — | **无** | **无** | 低 | **不做** |
| `audio/perm.rs` 改读 `perm_label` | — | — | — | — | **不做（前提就不成立）** |

---

## 7. 需要决策的三点

1. **私有参数走 `Profile` 还是「单文件常量模块」？**
   若私有版本永远由本项目自己编译分发，`structure/tags.rs` 单文件常量（`#[cfg(feature = "private-build")]` 覆盖）能以约 1/5 的成本拿到同等效果，且完全不动 `HostAdapter` trait。只有需要「库使用者在不 fork 的前提下定制 tag」时才值得走 Phase 1 的穿参方案。这是本方案最大的岔路口。
2. **Phase 3-2（`format_id` / `version`）是否真的需要？**
   两者都在密钥派生的槽位 + 明文头部里，可观测性依赖攻击者先能定位头部。若目标是「抗静态格式扫描」，Phase 1 已足够；若目标是「抗定向探测」，则 CRC 掩码 + 整头部掩码（比报告建议的更强）更值得做。
3. **是否把「分析器方言化」纳入本次范围？**
   它不消除指纹，但没有它，私有构建无法自检自己的载体，实操上会很难验收。
