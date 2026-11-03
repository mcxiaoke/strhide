# stego V4 内容信封实施审查报告

> 审查对象：commit `dfc69f9` feat(stego): replace V2/V3 envelopes with V4 content envelope  
> 对应方案：`docs/stego_content_envelope_v4_final_plan_20261103.md`  
> 审查时间：2026-11-03 22:20:28（初版）；2026-11-03 22:25:00（二次深度复审补充）；
> 2026-11-03 22:58:26（逐条复核并完成修复，状态见第八节）  
> 审查方式：逐文件核对实现与方案条款；运行全部质量门禁与字节基线；对可疑行为写临时测试实测验证（验证后已删除，未提交改动）  

## 0. 门禁与实测结果

| 项目 | 命令 | 结果 |
| :--- | :--- | :--- |
| 全量测试 | `cargo test --all-features --all-targets` | 通过（lib 482 passed / 1 ignored；test_cli 132、test_lifecycle 143、test_regression 101、test_pe 40、test_security 18、test_media 12 全绿） |
| 格式 | `cargo fmt --check` | 无 diff |
| 静态检查 | `cargo clippy --all-targets --all-features -- -D warnings` | 0 warning |
| 架构边界 | `python scripts/import_lint.py` | OK（structure !-> stego、stego !-> structure、core !-> {formats, structure, stego, cli}） |
| 字节基线 | `python scripts/baseline_hash.py --check` | 28/28 与基线一致（修复后因 seeded binding 变更已 `--write` 重建） |
| 补充实测 | PNG `FileKey` 往返 / PNG critical TLV 写入后提取 | FileKey 往返正常、错误 key 拒绝；critical TLV 写入成功但提取返回 `NoHiddenData` |

结论：实现整体质量高，与方案主体条款贴合（三套基础头布局与 CRC / golden 向量自洽、L1/L2/L3 与 AAD 构造严格按方案、提取侧校验顺序落实、FLAC 两段抽稀符合 FIX-02、HEVC 扩展 STC 与 keyed `band_positions` 已落地、无 V2/V3 读路径）。但复审发现仍存在多处**功能缺陷与跨引擎行为不一致**、**私有构建隔离失效**、**L1 派生重复开销**、**错误语义违背**及**文档与参数缺失**，详见下文。

---

## 一、功能缺陷与跨引擎行为不一致

### 1. HEIF 缩略图桥接的提取路径丢掉了 `key`

位置：`rust/src/stego/engine.rs:540-546`

```rust
Err(e) => {
    match thumb_bridge::extract_heif_bridge(
        carrier,
        &crate::stego::options::BridgeOptions::new(dialect)
            .with_password(opts.password.unwrap_or_default())
            .with_domain(opts.domain.unwrap_or_default()),
        ...
```

embed 侧（`engine.rs:490-501`）完整透传了 `dialect/password/key/domain/suite_id/extensions/tuning/safety/freshness/no_filename`，方案 FIX-05 也明确要求 BridgeOptions 透传这些字段；extract 侧只传了 password 与 domain，**`key` 被丢弃**。

后果：用 `Credential::FileKey` 写入、且因 Scheme C 不可用而落到缩略图桥接的 HEIC，用同一把 key 提取会失败——桥接内部 `resolve_credential` 只看到 `password: None`，回落到 dialect 私有口令或 `PUBLIC_DEFAULT_SECRET`。

对照：`inspect`/`verify` 的桥接调用是逐个显式传 `opts.password/opts.key/opts.domain` 的（`engine.rs:653-661`、`702-710`），因此只有 extract 一条路径有问题。

### 2. 写侧接受 critical TLV，写出的载体自己读不回来

置位点：`png/engine.rs:1574`、`jpeg/engine.rs:909-918`、`hevc/engine.rs:1273-1278`、`audio/core.rs:726-733`，只要 `extensions` 里存在 critical TLV 就写 `FLAG_EXT_CRITICAL`。

而所有提取路径见到 unknown critical 一律返回 `NoHiddenData`（`png/engine.rs:1864-1869`、`jpeg/engine.rs:1343-1345`、`hevc/engine.rs:2159+`、`audio/core.rs:554-559`），且 V4 尚未定义任何已知 critical TLV（方案 §8.1 也写明 critical 只用于负测）。

实测：PNG 以 `Tlv { type_id: 0x81, value: vec![1,2,3] }` 嵌入成功，随后 `extract_carrier` 返回 `NoHiddenData("No valid payload found")`。

建议：embed/probe 阶段拒绝 critical TLV（或维护已实现 critical 白名单），避免"写入成功、永远读不出"的陷阱。

### 3. `extract_png` 盲目吞掉 AEAD 认证后的解帧损坏与限额错误（跨引擎不一致）

位置：`rust/src/stego/png/engine.rs:2010-2019`

```rust
let aad = build_v4_aad(PNG_FORMAT_ID, &base_bytes, &extension);
unpack_v4_envelope_parts(
    suite,
    &session.enc_key,
    &header.nonce,
    &aad,
    &ciphertext,
    limits,
)
.map_err(|_| no_hidden()) // <-- 强行折叠为 NoHiddenData
```

方案要求（§4.3、§8.2）：
- 在 AEAD tag 校验失败或之前的步骤才返回 `NoHiddenData`；
- 一旦 AEAD 认证成功，说明密码与密文认证标签完全有效。此时内部 frame 解包校验失败、保留位非法、解压流损坏，或 `orig_len > limits.max_payload_bytes` 超限，**必须返回具体的 `CorruptedData` 或 `UnsupportedVersion`**。

现状与后果：
- `unpack_v4_envelope_parts` 内部逻辑是正确的（解密失败返回 `NoHiddenData`，解密成功后解帧/超额返回 `CorruptedData`）；
- **复核修正**：初审补充时写的“JPEG/HEVC 已透传”不准确。实际是 `png/engine.rs:2018`、
  `jpeg/engine.rs:1339`、`hevc/engine.rs:2154` **三处都** `.map_err(|_| no_hidden())`，
  只有 `audio/core.rs:889` 直接返回 `unpack_v4_envelope_parts` 的结果。
- 因此该缺陷是“PNG/JPEG/HEVC 一致地违背方案 §4.3，音频正确”，而不是“PNG 单点不一致”。
  修复时三者一并改为透传（AEAD 失败仍由 envelope 内部折叠为 `NoHiddenData`）。

### 4. `audio/core.rs` 的 `read_extension` 在未认证前直接返回 `CorruptedData`

位置：`rust/src/stego/audio/core.rs:536-553`

```rust
if header_slots > carrier.slot_count() {
    return Err(corrupted("extension area does not fit the carrier"));
}
...
header.validate_ext_critical(&extension)
    .map_err(|_| corrupted("invalid extension area"))?;
let records = parse_extension(&extension)
    .map_err(|_| corrupted("invalid extension area"))?;
```

方案要求（§4.3）：
在通过 AEAD tag 认证之前，所有头部定位、CRC、版本、扩展区槽位越界以及 TLV 解析损坏等错误，在对外 `extract` 接口上**必须统一返回 `NoHiddenData`**，以防未认证的伪随机噪声泄露内部结构判断，杜绝区分错口令与随机数据。

现状与后果：
- 在 PNG（`png/engine.rs:1848, 1862`）、JPEG（`jpeg/engine.rs:1255`）、HEVC（`hevc/engine.rs:1280`）中，扩展区槽位不足或 TLV 解析失败均严格折叠为 `no_hidden()` / `no_data()`；
- 唯独 Audio 在 `read_extension` 中直接返回了 `CorruptedData`，在未验证密文前过早暴露了损坏报错，违反了错误折叠规范。

### 5. `verify_hevc_v4` 缺失 L1 PBKDF2 门槛策略检查，导致诊断错误归类失真

位置：`rust/src/stego/hevc/engine.rs:2652-2740`

方案要求（§4.1 步骤 2、§4.2）：
若凭据为口令且 `max_pbkdf2_iterations < 200_000`，立即在 L1 前拒绝；`extract` 返回 `NoHiddenData`，`verify` 必须在 Level 2 记为策略拒绝（L2 policy fail）：
- `verify_png`（`png/engine.rs:2192-2210`）与 `verify_jpeg`（`jpeg/engine.rs:1637-1655`）均在 Level 2 开头检查并记录了：
  `VerifyLevel::fail(2, "Stego header", format!("PBKDF2 iteration limit {} is below the V4 L1 cost {}", ...))`。
- 但 `verify_hevc_v4` 顶层缺失该判断。**复核修正**：`inspect_hevc_record` 内部确实先调
  `check_l1_floor`（`hevc/engine.rs:2255`）并返回 `empty_info`，因此 Level 2 报的是
  `"No valid HEVC stego signature found (or wrong password)"`；
- 但 `verify` 的 Level 3 仍会走进 `extract_hevc_from_sb_record_v4`，其 `check_l1_floor`
  同样生效，于是先白跑一次 `read_hevc_header_v4`（含 200k PBKDF2）再返回 `NoHiddenData`。
  所以真实后果是“策略被误报成口令错误 + 多付一次 L1”，不是单纯文案问题。

### 6. `Freshness::seeded_binding` 未按方案 §3.5 扩展

位置：`rust/src/stego/envelope.rs:196-202`

```rust
pub fn seeded_binding(carrier: &[u8], payload: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&sha2::Sha256::digest(carrier));
    out[32..].copy_from_slice(&sha2::Sha256::digest(payload));
    out
}
```

方案要求（§3.5）：
`binding` 由 `Freshness::seeded_binding(carrier,payload)` 扩展为：
`binding || u8(format_id) || u8(version_major) || u8(version_minor) || encode_extension(extensions)`。
保证同一 `(master, session_salt, nonce)` 严格一对一绑定，不同 format/version/ext 在相同种子下派生的 salt/nonce 必须强隔离。

现状（**复核修正**）：PNG / JPEG / 音频在调用点手工追加了 `format_id`、`CONTENT_ENVELOPE_VERSION`
与 `extension`；**只有 HEVC** 仍只传 `carrier || payload`（`hevc/engine.rs:1236`）。所以真实缺陷是
“HEVC 不绑定 + 三处逻辑重复”，而不是“全部未绑定”。修复方式是把绑定收进
`Freshness::seeded_binding(carrier, payload, format_id, extension)`，四个引擎统一调用。

### 7. CLI 命令行层完全缺失 `--key-file` 与 `--max-payload` 参数

位置：`rust/src/cli/args.rs`

方案要求（§7 Step 9、§8.3）：
CLI 必须支持 `--key-file`（传入 32B 文件密钥，接入 `Credential::FileKey`）与 `--max-payload`（解密负载保护上限，接入 `ExtractParams.max_payload_bytes`）。

现状：
- CLI 中完全未定义 `--key-file` 与 `--max-payload` 参数；
- 导致 V4 核心特性 `Credential::FileKey` 仅能通过 Rust 库代码调用，在 CLI 命令行工具中处于**完全无法使用**状态；
- 同时用户在命令行也无法指定最大允许提取的明文字节上限。

---

## 二、私有构建（PngFormatProfile）隔离实际失效

### 8. `PngFormatProfile` 只有一个字段真正生效

方案 §6.2 要求该类型收敛为 `{ hpos_salt, cipher }`，`OFFICIAL_PNG_CIPHER` 通过 `PngFormatProfile` 注入。实际（`rust/src/stego/format.rs:250-274`）仍保留旧字段：

```rust
pub struct PngFormatProfile {
    pub fallback_secret: &'static str,
    pub domain_label: &'static [u8],
    pub hpos_salt: &'static [u8],
    pub hpos_label: &'static [u8],
    pub stc_label: &'static [u8],
    pub body: &'static JpegFormatProfile,
}
```

其中既没有 `cipher`，生产代码也只读 `hpos_salt`；PNG 引擎四处硬编码官方 cipher：

- `png/engine.rs:1377`（embed）
- `png/engine.rs:1825`（extract）
- `png/engine.rs:2072`（inspect）
- `png/engine.rs:2402`（probe）

后果：私有构建改动 `domain_label / hpos_label / stc_label / fallback_secret` 全部无效，官方构建与"私有"构建仍然互读——与 `WIRE_SPEC §13.10`、`STEGO-API` 中"改任一派生标签即产生不兼容线格式"的承诺相反。`fallback_secret` 现在只被 PNG 测试 shim 使用（`png/engine.rs:2431`），生产走 `StegoProfile.default_secret` / `PUBLIC_DEFAULT_SECRET`。

测试 `private_png_format_bidirectional_isolation`（`png/engine.rs:3864`）因为只依赖 `hpos_salt` 变化就通过，掩盖了该问题。

对照：JPEG/HEVC 用 `fmt.cipher`，音频用 `profile.cipher`，PNG 是唯一漏网的格式。

### 9. 音频默认 suite 取官方常量而非方言

`engine.rs:1040-1044`（FLAC）与 `engine.rs:1107-1111`（WAV）用 `OFFICIAL_AUDIO_CIPHER.default_suite`，而 JPEG/HEVC 用 `dialect.jpeg_format()` / `dialect.hevc_format().cipher.default_suite`。官方 profile 下无差异，私有 profile 下行为不一致。

---

## 三、方案 M-14 未落实：verify 重复派生 L1

- PNG：`verify_png` 先 `inspect_png_image`（`png/engine.rs:2226`，内部 `derive_locator_master`），再 `extract_png_image`（`:2241`，再次 `derive_locator_master`）。
- HEVC：`verify_hevc_v4` 先 `inspect_hevc_record`（`hevc/engine.rs:2720`），再 `extract_hevc_from_sb_record_v4`（`:2746`），两者都进 `read_hevc_header_v4`（`:1991`）→ 两次 L1。

每次多付 200,000 轮 PBKDF2（约 100–200 ms）。方案 §3.2 / §7 要求 verify 顶层只派生一次（`PreparedCarrier`），并用计数器断言"每格式只调用 1 次"。JPEG（把 `matched` master 传给 `extract_jpeg_from`）与音频（`PreparedCarrier`）做到了，PNG/HEVC 没做，也没有对应断言测试。

---

## 四、清理残留（与"旧 header 已删除"的说法矛盾）

### 10. V2/V3 头相关符号仍留在 `stego/header.rs`
`FeatureWord`、`HEADER_V2_ESCAPE_H`、`encode_header_word` / `decode_header_word`、`FEATURE_WORD_*`、`V2_TOTAL_HEADER_SLOTS` 全部还在（`header.rs:99-346`）。生产代码只用到 `FeatureWord::quantize_epsilon`（`params.rs:205`、`png/engine.rs:1399`），其余仅被测试引用；`png/engine.rs:60-61` 的那组 import 实际只服务测试（`:2972-2979`）。而 `docs/api/STEGO-API.md:17` 写着"旧 `FeatureWord` 已删除"。

建议：把 epsilon 量化挪成 `header.rs` 的独立函数（如 `quantize_epsilon_k`），删除 `FeatureWord` 及其编解码与 V2 槽位常量。

### 11. 其他残留
| 位置 | 问题 |
| :--- | :--- |
| `engine.rs:555` | `matches!(e, StrHideError::Password(_))` 死分支仍在，方案 §6.2 明确要求删除 |
| `png/engine.rs:2218` | 用户可见文案仍写 "…or FeatureWord found" |
| `format.rs:107-123` | `JpegFormatProfile` 的 rustdoc 字段表仍在描述 `format_major/minor`、`hpos_label/stc_label/suites` 等已删字段（HEVC 那张表已更新，JPEG 这张遗漏） |

---

## 五、WIRE_SPEC 与代码不一致

该提交声明"同步 WIRE_SPEC"，但以下条目与实现不符。golden 向量测试（`header.rs:888-1102`）与代码一致，因此均属文档错误。

### 12. §13.4.1 的 64 字节头偏移表整段错位（`WIRE_SPEC.md:513-534`）

| 字段 | 代码实际偏移 | 文档偏移 |
| :--- | :--- | :--- |
| reserved | 43（1B，必须 0） | 未列出 |
| `p1_window` | 44 | 43 |
| `p2_window` | 46 | 45 |
| `neg_log2_epsilon` | 48 | 47 |
| `exclusion_permille` | 50 | 49 |
| `sigma` | 52，**f32 小端** | 51，f32 大端 |
| `kernel_id` | 56 | 55 |
| reserved | 57（1B，必须 0） | 未列出 |
| `ext_len` | 58（2B） | 56 |
| reserved | — | 58（2B） |
| CRC32 | 60 | 60 |

代码见 `header.rs:555-582`（`encode`）与 `:588-722`（`decode`）；`sigma` 用 `to_le_bytes`。

### 13. §13.6 与 §14.2 把 JPEG `base_slots` 写成 352（`WIRE_SPEC.md:595`、`:679`）
352 是基础头的**位数**，槽数是 `JPEG_SUPERBLOCK_SLOTS = 718`（`format.rs:127`、`jpeg/engine.rs:824`）。照文档计算会把容量高估 366 槽。

### 14. §13.5 扩展槽公式适用范围写错（`WIRE_SPEC.md:579`）
文档称 `ext_slots = stc_u * (8 * ext_len + stc_h - 1)` 对"JPEG/空间域"都成立。实际空间域/音频扩展区是 `8 * ext_len` 裸 bit 槽，不经过 STC（`png/engine.rs:1085`、`audio/core.rs:645`）；该公式只对 JPEG（以及 HEVC 的固定 `h=7,u=2`）成立。

### 15. §13.1 头部位置来源写错（`WIRE_SPEC.md:460`）
文档称"基础头占用的槽位由 L2 `header_stc_seed` 选出"。实际位置由 `locate_seed` 决定，`header_stc_seed` 只用于 JPEG/HEVC 基础头的 STC 编码（`png/engine.rs:1083-1088`、`audio/core.rs:232-239`、`jpeg/engine.rs:848`）。

### 16. HEVC 口径过期
| 文档位置 | 文档写法 | 实际实现 |
| :--- | :--- | :--- |
| `:632`、`:686` | `magic4 = SHA-256(magic_label \|\| effective_secret)[..4]` | `magic4 = HKDF-Expand(master, info(magic_label))`（`format.rs:451-456`） |
| `:686` | `magic_label = b"strhide-hevc-magic-v1"` | `b"strhide-hevc-magic-v4"`（`format.rs:101`） |
| `:688` | `domain` 标签 `b"strhide-hevc-domain-v1"` | 共享 `b"strhide-stego-domain-v1"`（`format.rs:361`） |
| `:633` | "头部槽位只由参数集决定，与密码无关" | 头部槽位由凭据派生的 `locate_seed` 决定 |

### 17. §13.4.1 第 40 行 `stc_u（1..=64）`（`WIRE_SPEC.md:525`）
空间域/音频实际校验 `1..=3`（`header.rs:664-670`，与 `MAX_STC_U = 3` 一致）。

---

## 六、较低优先级与口径澄清

| 编号 | 位置 | 问题 / 说明 |
| :--- | :--- | :--- |
| 18 | `cli/args.rs:459-464` | `--cipher-suite` 仍 `hide = true` 且归在 "JPEG DCT Tuning" 分组，但现在对所有格式生效 |
| 19 | `cli/helpers.rs:211` | `has_per_format_flags` 仍把 `cipher_suite` 当 per-format flag，可能在不可嗅探载体上误报"给了格式参数" |
| 20 | `hevc/engine.rs:929` | `available_slots` 报 `total_slots`（含 header 槽），PNG/音频报的是扣除 header 后的可用槽，语义不统一 |
| 21 | `hevc/engine.rs:861-888` | `band_slots` 未扣除落在 band 内的 header 槽，视频档 recommended 理论上有 ≤524 槽高估（实测影响可忽略） |
| 22 | `hevc/engine.rs:2090-2101` | 未认证的 `window_slices` 直接驱动 `record_carrier_state(TargetSlices(w0))` 重扫，仅受 u16 与载体实际切片数约束，无额外硬上限（只放大耗时，不会越界/分配爆炸） |
| 23 | `audio/core.rs:933` | **方案口径澄清**：`probe` 中计算 `PreparedCarrier` 跑 200k PBKDF2 系方案 §0 第 6 点与 §10 明确规定的"probe 与 embed 同源同算，即使无密码也付 200k"的既定权衡设计，非性能疏忽；但其丢弃 `prepared`（`let _ = prepared;`）确实表明底层采样域槽位计数无需使用 locator seed |
| 24 | `tests/` | `FileKey` 端到端集成测试零覆盖（全仓测试搜不到 `FileKey` / `with_key`），仅有底层 KDF golden 向量与 options 单元测试 |

---

## 七、建议修复顺序

1. **修复 `hevc_extract` 桥接路径**：补上 `.with_key(opts.key)`，并补一条 FileKey + 缩略图桥接提取的回归测试；
2. **对齐 `PngFormatProfile`**：按方案 §6.2 收敛为 `{ hpos_salt, cipher }`，PNG 引擎改用 `spatial.cipher`；音频默认 suite 改为 `dialect.*_format().cipher.default_suite`；
3. **修复提取侧错误折叠语义**：
   - `png/engine.rs:2018`：移除 `.map_err(|_| no_hidden())`，允许解密成功后的帧结构与限额 `CorruptedData` 正常抛出；
   - `audio/core.rs:536-553`：`read_extension` 未认证前将槽位越界和 TLV 解析错误折叠为 `no_hidden()`，与其他引擎统一；
4. **修复 HEVC verify 策略判定**：`verify_hevc_v4` 顶层增加 `max_pbkdf2_iterations < CONTENT_L1_PBKDF2_ITERATIONS` 检查并在 Level 2 输出 policy fail；
5. **限制写侧 Critical TLV**：embed/probe 阶段拒绝 unknown critical TLV，避免写入不可读载荷；
6. **落实 M-14 密钥复用**：PNG/HEVC 的 verify 复用同一份 L1/L2 结果（`PreparedCarrier` 或已解码 header），并补充"每格式只派生一次"的断言测试；
7. **补齐 Freshness 绑定与 CLI 参数**：`seeded_binding` 补齐 format/version/extensions 绑定；CLI `args.rs` 增加 `--key-file` 与 `--max-payload` 选项，将 `--cipher-suite` 提升为通用选项；
8. **清理残留与同步文档**：清理 `FeatureWord` 系列残留、`StrHideError::Password` 死分支、旧文案与旧 rustdoc 字段表；按第五节修正 WIRE_SPEC（优先修复 64B 偏移表与 JPEG 718 槽）。

---

## 八、修复记录（2026-11-03 23:05:28）

本轮按报告逐条实施，并在实施前复核了二次复审新增的第 3/5/6 条（发现其“影响面”描述有偏差，已在上文就地更正）。修复后门禁全绿：

| 项目 | 结果 |
| :--- | :--- |
| `cargo fmt --check` | 0 diff |
| `cargo clippy --all-targets --all-features -- -D warnings` | 0 warning（GUI 侧 `cargo clippy --manifest-path src-tauri/Cargo.toml` 同样 0 warning） |
| `cargo test --all-features --all-targets` | lib 482 passed / 1 ignored；lifecycle 143、cli 132、media 12、pe 40、regression 101、security 18 全绿 |
| `cargo test local_ -- --ignored` / `heavy_ -- --ignored` | 18 / 5 全绿 |
| `python scripts/import_lint.py` | OK |
| `python scripts/baseline_hash.py --check` | 28/28（`seeded_binding` 变更后按方案 §8.3 以 `--write` 重建） |

### 8.1 逐条状态

| # | 问题 | 处理 |
| :--- | :--- | :--- |
| 1 | HEIF 桥接提取丢 `key` | 已修：`hevc_extract` 的 bridge 回退透传 `key`/`domain`/`suite_id`/`extensions` |
| 2 | 写侧接受 critical TLV | 已修：新增 `header::encode_extension_for_write`，五个引擎 embed/probe 全部改走它；负测改为“写侧拒绝 + 伪造载体后读侧仍 fail-closed” |
| 3 | AEAD 后错误被折叠 | 已修：PNG/JPEG/HEVC 三处去掉 `map_err(no_hidden)`，改由 envelope 自身区分（AEAD 前折叠、AEAD 后 `CorruptedData`/限额）；新增 `oversized_plaintext_after_aead_is_corrupted_data_not_no_payload` 断言 |
| 4 | 音频 `read_extension` 过早返回 `CorruptedData` | 已修：未认证前的槽位越界 / TLV 解析失败统一 `no_hidden()`，与其余引擎一致 |
| 5 | `verify_hevc_v4` 缺 L1 策略门槛 | 已修：Level 2 增加 policy fail 分支并跳过 L3，不再白跑 PBKDF2 |
| 6 | `seeded_binding` 未按 §3.5 绑定 | 已修：签名改为 `seeded_binding(carrier, payload, format_id, extension)`，统一追加 major/minor + 扩展区；WAV/FLAC/PNG/JPEG/HEVC 全部改调用它（原实现中 HEVC 完全未绑定，其余三处为调用点手工拼接） |
| 7 | CLI 缺 `--key-file` / `--max-payload` | 已修：embed/capacity/extract/inspect/verify 支持 `--key-file`（32 原始字节或 64 位 hex），extract 支持 `--max-payload`；`--cipher-suite` 解除隐藏、改归 `Stego Envelope` 组并加 `--suite` 别名；`DualOptions` 增加 `key` |
| 8 | `PngFormatProfile` 隔离失效 | 已修：类型收敛为 `{ hpos_salt, cipher }`，PNG 引擎四处改用 `spatial.cipher`；`private_png_format_bidirectional_isolation` 改为真正的“私有 cipher + 私有 salt”隔离测试 |
| 9 | 音频默认 suite 取官方常量 | 已修：改取 `dialect.audio_format().cipher.default_suite` |
| 10 | `FeatureWord` / V2 头残留 | 已清理：删除 `FeatureWord`、`HEADER_V2_ESCAPE_H`、`encode/decode_header_word`、`FEATURE_WORD_*`、`V2_TOTAL_HEADER_SLOTS`；epsilon 量化改为 `header::quantize_epsilon_k`，相关“虚假测试”（`feature_word_roundtrip_and_validation`、`feature_word_carries_the_algorithm_id`、`hamming_and_stc_headers_differ_only_in_the_flag_bits`）一并删除 |
| 11 | 死分支 / 旧文案 / 旧 rustdoc | 已清理：`StrHideError::Password` 死分支、`"...or FeatureWord found"` 文案、`JpegFormatProfile` 过期字段表 |
| 12 | WIRE_SPEC 64B 偏移表 | 已修：按 `SpatialHeaderV4::encode` 逐字节重写（含 43/57 reserved、sigma little-endian、stc_u 1..=3） |
| 13 | JPEG `base_slots = 352` | 已修：§13.6 与 §14.2 均改为 718 槽 |
| 14 | 扩展槽公式适用范围 | 已修：区分空间域 `8*ext_len`、JPEG STC、HEVC 固定 `h=7,u=2` |
| 15 | 头部位置来源写成 `header_stc_seed` | 已修：§13.1 与 ARCHITECTURE §5.5 改为 `locate_seed`（`header_stc_seed` 仅用于 JPEG/HEVC 基础头 STC） |
| 16 | HEVC 魔数/标签/独立性描述过期 | 已修：改为 HKDF-Expand + `strhide-hevc-magic-v4` + 共享 domain 标签 |
| 17 | §13.4.1 `stc_u（1..=64）` | 已修：空间域 1..=3 |
| 18 | `--cipher-suite` 分组/隐藏 | 已修（同 #7） |
| 19 | `has_per_format_flags` 误含 cipher_suite | 已修：从 per-format 判定中移除 |
| 20 | HEVC `available_slots` 语义 | 未改：需要与 GUI 展示口径一起评估，保留为已知差异 |
| 21 | HEVC band 容量未扣 header 槽 | 未改：偏差 ≤524 槽且被 gate_slots 收紧，保留观察 |
| 22 | 未认证 `window_slices` 驱动重扫 | 未改：只放大耗时，受 u16 与载体实际切片数约束 |
| 23 | 音频 probe 付 PBKDF2 | 保持现状：二次复审已确认是方案 §0/§10 的既定权衡（probe 与 embed 同源同算） |
| 24 | `FileKey` 零覆盖 | 已补：`tests/test_lifecycle/stego_credentials.rs`（FileKey 往返、错误 key、password/key 互斥、critical 拒绝、单次派生、AEAD 后限额）+ CLI `key_file_and_max_payload_round_trip` |

### 8.2 新增/删除测试

新增：

- `tests/test_lifecycle/stego_credentials.rs`（5 例）：FileKey 端到端、password/key 互斥、critical TLV 写侧拒绝 + 非 critical 往返、`verify` 单次 L1 派生（`locator_derivation_count() == 1`）、AEAD 成功后超额明文返回 `CorruptedData`。
- `tests/test_cli/cli_unification.rs::key_file_and_max_payload_round_trip`：`--key-file`（二进制/hex）、无 key 读不出、与 `-p` 互斥、`--max-payload` 拒绝。
- `header.rs`：`epsilon_quantisation_is_exact_for_powers_of_two`、`critical_tlvs_are_refused_at_write_time`。
- `envelope.rs`：binding 对 format/extension 的分离断言。

删除（随实现消失、不再有意义的“虚假测试”）：

- `header.rs::feature_word_roundtrip_and_validation`、`png/registry.rs::feature_word_carries_the_algorithm_id`、`png/engine.rs::hamming_and_stc_headers_differ_only_in_the_flag_bits`。
- 3 个“写入 critical TLV 再期待读失败”的用例改为“写侧拒绝 + 伪造载体读侧仍拒绝”（PNG/WAV），FLAC 保留写侧断言（读侧由共享的 `read_extension` 覆盖）。

### 8.4 独立复审（`stego_content_envelope_v4_review_independent_20261103.md`）的额外项

该报告与本文重叠的 B-1/B-2/M-1/M-2/M-3/M-4/M-6/M-7 均已在 8.1 修复。它独有的三项也一并处理：

| 独立报告条目 | 处理 |
| :--- | :--- |
| Minor 5：`jpeg/header_v3.rs` 内实为 V4 头，模块名误导 | 已改：`git mv` 为 `jpeg/header_v4.rs`，`mod`/`use` 同步（仅 2 处引用） |
| Minor 6：音频不支持 Hamming，但 golden WAV 头是 `codec_id=0` | 已在 WIRE_SPEC §13.4.1 加注：音频域 `codec_id=0` 保留未用，golden 向量只校验布局/CRC |
| Minor 8：`CHANGES-20251103.md` 年份笔误 | 已修：今日 V4 记录并入 `CHANGES-20261103.md`（按时间倒序），删除笔误文件 |
| Minor 10：FLAC `inspect`/`verify` 用未认证的 `ext_len` 构造 carrier，越界时冒泡为 `Err` | 已修：两处都先判 `header_slots > analysis.tails` 与 `body_slots > analysis.usable`，分别返回空头 / Level-2 fail；新增 `flac_unreadable()` 复用判定 |

未处理（保留为已知项）：Minor 9（基线未覆盖 HEVC 内容域）、独立报告 §5 的 audio Hamming 语义（已按“保留未用”定案并写进规范）、GUI 仍只有密码凭据（方案 §11 的 GUI 字段属后续工作）。

### 8.3 需要注意的行为变化

1. **Seeded 输出改变**：`seeded_binding` 现在绑定 format/version/扩展区，因此 `--seed` 生成的载体与旧版本不再逐字节相同（项目未发布，方案 §3.5 明确要求）；`baseline_hash` 已据此重建。
2. **critical TLV 写入被拒绝**：此前可以写、写了读不回；现在直接返回 `General` 错误。
3. **PNG/JPEG/HEVC 超额明文错误码**：AEAD 成功后不再折叠成 `NoHiddenData`，改为 `CorruptedData`（可暴露给调用方）。
4. **`PngFormatProfile` 破坏性变更**：字段收敛为 `{ hpos_salt, cipher }`，私有构建需改写 profile 字面量（`fallback_secret`/`domain_label`/`hpos_label`/`stc_label`/`body` 已删除）。
5. **CLI**：`--cipher-suite` 不再隐藏且对所有格式生效；新增 `--key-file`、`--max-payload`。
