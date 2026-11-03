# V4 内容信封重构独立审查（commit `dfc69f95`）

- 审查对象：`dfc69f9578dc8f52a487cbc077b58bc2df68b619`，父提交 `2c11b77`，分支 `stego_content_envelope_v4`
- 审查方式：`git show --stat` / `git diff 2c11b77..dfc69f95` 分文件核对 + 全库 Grep + 关键路径小范围 Read
- 参照：`docs/stego_content_envelope_v4_final_plan_20261103.md`、`docs/api/WIRE_SPEC.md`、`docs/api/ARCHITECTURE.md`、`docs/api/STEGO-API.md`、golden vectors、`AGENTS.md`

## 结论

**当前提交不建议直接作为 V4 基线。** 五引擎的 `Credential` + `CipherSuiteId` + `build_v4_aad` + suite 分发主体已经统一，suite 2 也经 CLI 实测可用；但私域 wire profile 在 PNG 上实际失效，HEIF 桥接提取丢失 FileKey，另有若干错误语义/校验顺序/测试矩阵缺口。建议先修完第 1 节的 Blocking 项和“最小修复集合”中的 Major 项，再冻结基线。

已执行的验证：

- `cargo check --all-features --all-targets`：通过，无 warning。
- `cargo clippy --all-targets --all-features -- -D warnings`：通过。
- `cargo test --all-features --lib`：通过（含 golden vectors 单元测试）。
- `python scripts/baseline_hash.py --check`：重建 release 二进制后 28/28 一致；HEVC/HEIC/MP4/MKV 用例均为 `content=-`，只有结构哈希。
- 手工 CLI 往返：PNG / WAV / FLAC / HEVC 均以 `--cipher-suite 2` 成功嵌入并提取；JPEG 由 `stego_jpeg_v4` 集成测试覆盖。
- 未执行 GUI 测试，未逐行审完 51 个变更文件的全部非关键路径。

---

## 1. Blocking（建议先修）

### B-1 PNG 私域 profile 实际失效：`PngFormatProfile` 未切到 `WireCipherProfile`，cipher 被硬编码

**问题**：PNG 的 L1/L2/L3 派生、probe、inspect 全部固定使用 `OFFICIAL_PNG_CIPHER`，而不是 `PngFormatProfile` 提供的 cipher；`PngFormatProfile` 仍是旧的 `fallback_secret / domain_label / hpos_label / stc_label / body` 结构，没有 `cipher` 字段。

**证据**：

- [format.rs](file:///c:/Home/Projects/strhide/rust/src/stego/format.rs#L252-L264)：`PngFormatProfile` 字段仍是旧形态，无 `cipher`。
- [engine.rs](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1377)：embed 写死 `let cipher = &OFFICIAL_PNG_CIPHER`。
- 同类写死：[engine.rs L1825](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1825)（extract）、[L2072](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L2072)（inspect）、[L2402](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L2402)（probe）、[L2453](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L2453)（probe 无凭据回退）。
- 默认 suite 也写死官方值：[stego/engine.rs L188-L192](file:///c:/Home/Projects/strhide/rust/src/stego/engine.rs#L188-L192)（PNG）；WAV/FLAC 同类：[L1039-L1043](file:///c:/Home/Projects/strhide/rust/src/stego/engine.rs#L1039-L1043)、[L1172-L1176](file:///c:/Home/Projects/strhide/rust/src/stego/engine.rs#L1172-L1176)。
- 文档仍承诺该字段存在：[STEGO-API.md L125](file:///c:/Home/Projects/strhide/docs/api/STEGO-API.md#L125) 写有 `PngFormatProfile { /* 派生标签 + cipher + body 引用 */ }`，与实现不符。
- 现有“私域隔离”测试是假阳性：[png/engine.rs L3871-L3950](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L3871-L3950) 同时改了 `fallback_secret` 和 `hpos_salt`，所以即使 `domain_label/hpos_label/stc_label/body` 全部被忽略，测试仍会通过。

**影响**：私有构建只修改 `domain_label/hpos_label/stc_label/body`（文档推荐做法）时，PNG 载体仍会被官方构建正常读取，私域隔离静默失效；只有修改 `hpos_salt` 才有效。`fallback_secret` 在生产路径也不再是有效旋钮（公共 `resolve_credential` 已走 `PUBLIC_DEFAULT_SECRET`）。这是安全能力与文档承诺的直接偏离。

**建议修法**：

1. 把 `PngFormatProfile` 改为 `{ hpos_salt, cipher: &'static WireCipherProfile }`，删除旧字段；`OFFICIAL_PNG_FORMAT` 指向 `OFFICIAL_PNG_CIPHER`。
2. PNG 五处派生全部改用 `spatial.cipher`；PNG/WAV/FLAC 默认 suite 改为各自 profile 的 `cipher.default_suite`（`dialect.png_format().cipher` / `audio_format().cipher` / `flac_format().cipher`）。
3. 增加一个只改 label、不改 salt 的私域往返测试，并断言官方读者返回 `NoHiddenData`；该测试在修前应失败。

**对应方案**：§6.2 Step 4（PNG `PngFormatProfile` 切到 `hpos_salt + cipher`）、§13 实施状态表 PNG 行；默认 suite 属 §3.1/§6.2 统一配置。

### B-2 HEIF 缩略图桥接的 extract 丢失 `key`，FileKey 载体无法读取

**问题**：主 HEVC 提取失败后进入 HEIF thumbnail bridge 时，只传 `password` 和 `domain`，没有传 `opts.key`；而 bridge 本身支持 `with_key`。

**证据**：[stego/engine.rs L540-L546](file:///c:/Home/Projects/strhide/rust/src/stego/engine.rs#L540-L546)：

```rust
BridgeOptions::new(dialect)
    .with_password(opts.password.unwrap_or_default())
    .with_domain(opts.domain.unwrap_or_default()),
```

同文件其它 bridge 路径（inspect/verify）都正确传了 `opts.key`，例如 [L655-L656](file:///c:/Home/Projects/strhide/rust/src/stego/engine.rs#L655-L656)、[L704-L705](file:///c:/Home/Projects/strhide/rust/src/stego/engine.rs#L704-L705)。

**影响**：用 `Credential::FileKey` 嵌入到 HEIC 缩略图桥接路径的载体，公开 `extract` 会以错误凭据（默认口令）尝试，最终返回 `NoHiddenData`。这是 V4 核心凭据模式在已支持载体上的功能缺陷。

**建议修法**：`.with_key(opts.key)` 与 `.with_password(...)` 一起传入；补一个 HEIC bridge + FileKey 的往返测试（当前全库测试中没有 FileKey 端到端用例，见 M-5）。

**对应方案**：§3.1 凭据优先级（`key` 优先）、§6.2 Step 8 HEIF 桥接、§8.1 FileKey 矩阵、§11 验收。

---

## 2. Major

### M-1 PNG 在 AEAD 成功后的解帧错误被折叠成 `NoHiddenData`

**问题**：PNG 对 `unpack_v4_envelope_parts` 的所有错误 `.map_err(|_| no_hidden())`，包括 AEAD 已通过后的 frame/长度/解压失败；而 JPEG/HEVC/audio 透传 `CorruptedData`。

**证据**：[png/engine.rs L2009-L2018](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L2009-L2018)；对照 [jpeg/engine.rs L1331-L1343](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L1331-L1343)、[hevc/engine.rs L2146-L2158](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L2146-L2158)、[audio/core.rs L889-L897](file:///c:/Home/Projects/strhide/rust/src/stego/audio/core.rs#L889-L897)。

**影响**：方案 §4.3 明确要求“AEAD 成功后 frame/长度/解压失败 → `CorruptedData`/`Capacity`”。当前 PNG 会把真实损坏伪装成“无数据”，既丢失诊断信息，也与其它三引擎语义不一致。

**建议修法**：仅把 `UnsupportedVersion`/header/body 预检失败折叠为 `NoHiddenData`；AEAD 成功后的解帧错误原样返回（或统一映射到 `CorruptedData`）。补一个“AEAD 通过但 frame 损坏”的 PNG 用例。

**对应方案**：§4.3 错误语义表第 495 行。

### M-2 `verify_hevc` 未做 `max_pbkdf2_iterations` 策略分级

**问题**：`verify_hevc_v4` 在 L2 直接调用 `inspect_hevc_record`，没有在 L1 前检查 `Credential::Password + max_pbkdf2_iterations < 200_000`；inspect 内部只返回空 header，verify 因而把 policy 拒绝报成“无头/错密码”。

**证据**：[hevc/engine.rs L2652-L2743](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L2652-L2743) 无 policy 分支；对照 [png/engine.rs L2066-L2070](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L2066-L2070)、音频 verify 的显式 policy 处理。

**影响**：方案 §4.2 要求 verify 对 `Password + max_pbkdf2_iterations < 200_000` 记 L2 policy fail、且不跑 PBKDF2；当前 HEVC 仍会进入派生并在 L2 给出错误的“错口令”分类。属于策略绕过/错误信息分类缺陷，不涉及机密泄露。

**建议修法**：在 `verify_hevc_v4` 开头按 `Credential` 判型；Password 且阈值不足时直接产出 L2 policy fail（FileKey 不受限），不进入 `inspect_hevc_record`。

**对应方案**：§4.2 第 442 行、§8.2 负面表第 739 行。

### M-3 HEVC 的 Freshness binding 未纳入 format/version/extension，存在 nonce 复用条件

**问题**：PNG/JPEG/WAV/FLAC 都把 `format_id + version + extension` 追加到 `Freshness::seeded_binding` 后再取 salt/nonce；HEVC 只用 `carrier + payload`，且用 nonce 直接作为 L3 session salt。

**证据**：[hevc/engine.rs L1236-L1243](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L1236-L1243)；对照 [png L1383-L1388](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1383-L1388)、[jpeg L727-L730](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L727-L730)、[audio L659-L664](file:///c:/Home/Projects/strhide/rust/src/stego/audio/core.rs#L659-L664)。

**影响**：`Freshness::Seeded` 下，同一 cover + 同一 payload、但不同 `extensions` 的两次 HEVC 嵌入会复用同一 nonce，进而复用同一 session key（HEVC 的 salt 由 nonce 派生），只是 AAD 不同。虽然明文相同，实际泄露面有限，但违反方案“不同 ext 必须改变 binding → salt/nonce”的硬性要求，也削弱 AEAD nonce 唯一性证明。

**建议修法**：与其它引擎一致，在 HEVC binding 追加 `HEVC_FORMAT_ID`、`CONTENT_ENVELOPE_VERSION` 和 `extension`；加“同 cover/payload、不同 ext → nonce 不同”的断言。

**对应方案**：§3.5 Freshness、§8.1 nonce/binding 矩阵。

### M-4 写侧接受 critical TLV，产出的载体本实现永远读不出

**问题**：四个引擎的 embed 都会在扩展含 critical tag 时设置 `FLAG_EXT_CRITICAL`；extract 则在 AEAD 前看到任一 critical tag 就直接 `NoHiddenData`。V4 尚未定义任何已知 critical TLV，因此写侧一旦写入就是“自读失败”。

**证据**：写侧 [png/engine.rs L1575](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1575)、[audio/core.rs L733](file:///c:/Home/Projects/strhide/rust/src/stego/audio/core.rs#L733)、[hevc/engine.rs L1275](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L1275)、[jpeg/engine.rs L915](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L915)；读侧拒绝 [png L1860-L1868](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1860-L1868)、[audio L550-L558](file:///c:/Home/Projects/strhide/rust/src/stego/audio/core.rs#L550-L558)。

**影响**：公开 `extensions: Vec<Tlv>` 是调用方可见能力，写入 critical TLV 后无法自校验；这是“方案缺口 + 易踩陷阱”，不是密钥泄露。方案 §8.1 只说 critical 仅用于负测，未明确禁止写侧。

**建议修法**：embed 遇到 `TLV_CRITICAL` 时返回参数错误（或至少文档显式标注“写入即不可读，仅限负测”）；若未来定义已知 critical TLV，再放行白名单。

**对应方案**：§4.3 表第 492 行、§8.1 第 714 行；建议在方案补一条写侧禁令。

### M-5 方案 §8.1 的测试矩阵基本未落地；FileKey 端到端为零

**问题**：方案要求“5 格式 × suite 1/2 × Password/FileKey × payload 多档 × Random/Seeded × extensions=[]/1 noncritical”。实际：

- suite 2 只有 JPEG 集成测试覆盖；PNG/WAV/FLAC/HEVC 无 suite 2 集成用例（本次手工 CLI 已证明可用）。
- `extensions` 非空场景没有 probe==embed 断言；全库仅 HEVC 注释提到 probe==embed。
- `Credential::FileKey` 在 `rust/tests` 中零引用；CLI/GUI 也没有 key 入口，能测的只有库层，但库层也没有。

**证据**：`grep -r "FileKey" rust/tests gui` 无结果；`grep -r "suite_id: Some(2)" rust/tests` 仅 JPEG 用例；`grep "seeded_binding"` 显示各引擎 binding 分歧（见 M-3）。

**影响**：五引擎 suite 分发目前靠代码结构保证 + 本次手工抽查，没有回归保护；FileKey 作为 V4 核心凭据模式没有端到端证据，且已被 B-2 证明存在缺陷。

**建议修法**：至少补一组跨引擎 smoke：PNG/WAV/FLAC/HEVC × suite 1/2 × Password/FileKey × ext 0/1，断言 embed→extract→verify 和 probe==embed；再补 HEIC bridge + FileKey。

**对应方案**：§8.1 第 714 行、§11 验收。

### M-6 verify 重复 L1（方案 M-14 未完成）

**问题**：`verify_png` 先 `inspect_png_image`（内部一次 L1），再 `extract_png_image`（内部再一次 L1）；`verify_hevc_v4` 同样先 inspect 后 extract。JPEG/音频走 matched Header + body 路径，不重复。

**证据**：[png/engine.rs L2213、L2241](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L2213)；[hevc/engine.rs L2720、L2746](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L2720)。

**影响**：verify 在 200k PBKDF2 模式下固定跑两次慢哈希，放大 CPU 成本；与方案 M-14“复用 PreparedCarrier”不符。

**建议修法**：让 verify 复用 inspect 返回的 `PreparedCarrier` / 已解出的 header 与 session，不再二次派生。

**对应方案**：§3.2 / §M-14（方案第 829 行）。

### M-7 音频扩展区在 AEAD 前的结构错误返回 `CorruptedData`，与其它引擎/错误表不一致

**问题**：audio 的 `read_extension` 在未认证阶段对“扩展区装不下”“TLV 结构非法”直接返回 `CorruptedData`；PNG/JPEG/HEVC 同类情况返回 `NoHiddenData`。

**证据**：[audio/core.rs L536-L537](file:///c:/Home/Projects/strhide/rust/src/stego/audio/core.rs#L536-L537)、[L550-L553](file:///c:/Home/Projects/strhide/rust/src/stego/audio/core.rs#L550-L553)。

**影响**：方案 §4.3 把“长度/参数”和“body 槽位不足/截断”归为 `NoHiddenData`，且 extract 不应显式区分“头 CRC 恰好通过但扩展损坏”。当前行为跨引擎不一致，也让音频的失败面多出一类可观察错误。方案 §5.2 对 TLV parser 又写 `CorruptedData`，属于方案内部表述冲突。

**建议修法**：先统一语义并回写方案：未认证的 header/ext 长度/槽位上界失败一律 `NoHiddenData`；只有 AEAD 通过后的 TLV/帧结构错误才 `CorruptedData`。然后让四个引擎共用同一 helper。

**对应方案**：§4.3 第 489/493/495 行、§5.2 第 521 行（存在冲突）。

---

## 3. Minor

1. **V3/V2 删除不彻底，且文档宣称已删**。`FeatureWord`、`encode_header_word`、`decode_header_word`、`HEADER_V2_ESCAPE_H`、`V2_TOTAL_HEADER_SLOTS` 仍在 [header.rs L69-L113、L131、L215-L243](file:///c:/Home/Projects/strhide/rust/src/stego/header.rs#L69-L113)，并由 [png/engine.rs L59-L62](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L59-L62) 公开 re-export；verify 文案仍写 “No valid stego header or FeatureWord found” [L2218](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L2218)。`STEGO-API.md L17` 却声称 `FeatureWord` 已删除。方案 §13 也写“旧 header 已删除”。建议：仅保留 `quantize_epsilon` 所需逻辑并改为普通 helper，删除旧 word/常量/re-export/测试。
2. **WIRE_SPEC 空间头字段偏移整体错位**。文档 [WIRE_SPEC.md L525-L534](file:///c:/Home/Projects/strhide/docs/api/WIRE_SPEC.md#L525-L534) 写 `p1_window` 在 43、`epsilon` 47、`sigma` 51（BE）、`ext_len` 56；实现为 43 reserved、p1 44、p2 46、epsilon 48、sigma LE、ext_len 58、无尾部 reserved（[header.rs L552-L583](file:///c:/Home/Projects/strhide/rust/src/stego/header.rs#L552-L583)）。这会让第三方按文档实现必然失败。
3. **WIRE_SPEC 其它数值/派生描述与实现不符**：
   - `stc_u（1..=64）`，空间域实现上限是 3（[WIRE_SPEC L525](file:///c:/Home/Projects/strhide/docs/api/WIRE_SPEC.md#L525) vs [header.rs L636-L668](file:///c:/Home/Projects/strhide/rust/src/stego/header.rs#L636-L668)）。
   - JPEG `base_slots = 352`，实现 `header_slots(0) = 718`（[WIRE_SPEC L595/L679](file:///c:/Home/Projects/strhide/docs/api/WIRE_SPEC.md#L595) vs [format.rs L157-L170](file:///c:/Home/Projects/strhide/rust/src/stego/format.rs#L157-L170)）。
   - HEVC 魔数写 `SHA-256(magic_label || secret)`、`...-v1`；实现是 HKDF-SHA256、`...-v4`（[WIRE_SPEC L632/L686](file:///c:/Home/Projects/strhide/docs/api/WIRE_SPEC.md#L632) vs [format.rs L98-L103、L460-L477](file:///c:/Home/Projects/strhide/rust/src/stego/format.rs#L460-L477)）。
   - 基础头槽位写“由 `header_stc_seed` 选出”；实际由 `locate_seed` 选出，`header_stc_seed` 只用于 STC 编码（[WIRE_SPEC L460](file:///c:/Home/Projects/strhide/docs/api/WIRE_SPEC.md#L460) vs [png L1083-L1091](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1083-L1091)）。
   - `ext_slots = stc_u*(8*ext_len+stc_h-1)` 写成通用规则，但 PNG/WAV/FLAC 是固定 8 槽/字节，不适用该公式（[WIRE_SPEC L579](file:///c:/Home/Projects/strhide/docs/api/WIRE_SPEC.md#L579)）。
4. **Rustdoc 与结构体字段脱节**。`JpegFormatProfile` 文档仍列 `format_major/minor`、`hpos_label/stc_label`、`enc_label`、`suites`，实际字段为 `cover_digest_tag/cipher/sb_*/ext_*/grid_rule`（[format.rs L80-L102](file:///c:/Home/Projects/strhide/rust/src/stego/format.rs#L80-L102)）；`PngFormatProfile.hpos_salt` 注释称 HKDF salt for hpos，实际进入 `pre_salt`（[format.rs L257-L258](file:///c:/Home/Projects/strhide/rust/src/stego/format.rs#L257-L258)、[png L1068](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1068)）。
5. **模块名残留**：`jpeg/header_v3.rs` 内实际是 `JpegSuperblockV4`，文件名/模块名仍为 v3，易误导（[header_v3.rs L1-L60](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/header_v3.rs#L1-L60)）。
6. **音频 Hamming 的声明/实现不一致（已确认）**。空间头解码接受 `codec_id=0`（Hamming，`stc_h/stc_u` 必须为 0），WIRE_SPEC 也把 0 定义为 Hamming；但音频 embed 明确拒绝 Hamming（[audio/core.rs L680-L684](file:///c:/Home/Projects/strhide/rust/src/stego/audio/core.rs#L680-L684)），extract 对 `codec_id=0` 直接返回 `NoHiddenData`（[L601-L617](file:///c:/Home/Projects/strhide/rust/src/stego/audio/core.rs#L601-L617)）。更直接的证据是 golden 向量本身：WAV golden 头写 `codec_id=0/stc_h=0/stc_u=0`（[header.rs L587-L594](file:///c:/Home/Projects/strhide/rust/src/stego/header.rs#L587-L594)），即该向量描述的是音频引擎既写不出、也读不回的头。影响：golden vectors 与“可互操作线格式”语义不符，第三方按 Hamming 实现音频会永远读不到数据。建议：golden WAV 改为真实 `codec_id=1/stc_h/stc_u` 向量，并在 WIRE_SPEC 明确“WAV/FLAC 仅 STC，codec 0 保留未用”。
7. **CLI/GUI 能力缺口（已知，非安全缺陷）**：CLI 只有隐藏的 `--cipher-suite`（[args.rs L459-L464](file:///c:/Home/Projects/strhide/rust/src/cli/args.rs#L459-L464)），没有 `--key-file` / `--max-payload` / `--extensions` / PBKDF2 上限；GUI 没有 suite/extensions/key 字段。方案 §11 要求的 CLI/GUI 字段仍未做。
8. **变更日志文件名年份笔误**：提交新增 [CHANGES-20251103.md](file:///c:/Home/Projects/strhide/docs/CHANGES-20251103.md)，但提交日期是 2026-11-03，按 AGENTS 应为 `CHANGES-20261103.md`；建议重命名（文档类文件可用日期时间戳避免覆盖）。
9. **baseline 的 HEVC/HEIC 内容域未覆盖**：`baseline_hash --check` 中 `bbb.hevc`、`*.MOV`、`*.HEIC`、`*.mp4` 均为 `content=-`，只比结构哈希；HEVC 内容域回归仍依赖 `hevc_stress`，不是字节基线。
10. **FLAC inspect/verify 未先校验 header 槽位上界（待确认）**。`inspect_flac`/`verify_flac` 直接用未认证的 `header.ext_len` 构造带 `header_slots` 的 `FlacCarrier`，没有像 extract 那样先判 `header_slots > analysis.tails`（[audio/mod.rs L430-L500](file:///c:/Home/Projects/strhide/rust/src/stego/audio/mod.rs#L430-L500) 对照 extract 处的检查）。若 `FlacCarrier::new` 内部不会自行拒绝，可能把“损坏头”报成 Err 而非空头；需补测/确认。

---

## 4. 方案 vs 实现缺口清单

- `PngFormatProfile` 未切到 `hpos_salt + cipher`（B-1）——已实现代码与 §6.2 Step 4 不符。
- PNG/WAV/FLAC 默认 suite 未取 profile 的 `cipher.default_suite`（B-1 附带）。
- `Credential::FileKey` 在 §8.1 矩阵、§11 CLI/GUI 均未落地；HEIC bridge 还存在 B-2 的代码缺陷。
- critical TLV 写侧行为无明确方案（M-4）。
- §8.1 的 5×2×2×… 矩阵未实现（M-5）。
- `verify` 复用 PreparedCarrier（M-14）未做（M-6）。
- WIRE_SPEC 多处数值/偏移/派生描述仍是旧稿（Minor 2-3）。
- `FeatureWord` 删除未完成（Minor 1）。

## 5. 待确认（不作为已确认缺陷）

- audio Hamming：实现侧已一致拒绝（embed 拒绝、extract 返回 `NoHiddenData`），但 golden WAV 向量使用 `codec_id=0`，待方案明确该值是“保留未用”还是应支持（Minor 6）。
- FLAC inspect/verify 的 header 槽位上界：需确认 `FlacCarrier::new` 是否 fail-closed（Minor 10）。
- `StrHideError::Password` 在 [engine.rs L555](file:///c:/Home/Projects/strhide/rust/src/stego/engine.rs#L555) 的分支是否仍可达：`extract_hevc` 已统一折叠错误，若不可达应删除。
- 音频 `read_extension` 在未认证阶段返回 `CorruptedData` 的最终口径，需与 §4.3/§5.2 统一（M-7）。

## 6. 最小修复集合（冻结 V4 基线前）

**代码必须修**：

1. B-1：`PngFormatProfile` 接入 `WireCipherProfile`，删除全部 `OFFICIAL_PNG_CIPHER` 硬编码；PNG/WAV/FLAC 默认 suite 读 profile。
2. B-2：HEIF bridge extract 传 `opts.key`。
3. M-1：PNG 只在未认证阶段折叠 `NoHiddenData`，AEAD 成功后保留 `CorruptedData`。
4. M-2：`verify_hevc` 补 PBKDF2 policy 分级。
5. M-3：HEVC Freshness binding 追加 format/version/extension。
6. M-6：verify 复用 PreparedCarrier，避免二次 L1。

**测试/文档必须补**：

7. PNG 私域仅改 label 的隔离测试；HEIC bridge + FileKey 测试。
8. 五引擎 suite 1/2 × Password/FileKey × ext 0/1 的 smoke 矩阵（至少 1 组/组合），以及 probe==embed 断言。
9. 修正 WIRE_SPEC 的空间头偏移/sigma endianness/ext_len、stc_u、JPEG base_slots、HEVC 魔数；删除 `FeatureWord` 或修正文档声明。
10. M-4 的 critical TLV 写侧策略至少要在方案/文档中明确；若采纳“写入即拒绝”，一并实现。

完成 1-6 且补上 7-8 后，可把该提交作为 V4 基线；第 9-10 项可以紧随基线修复，但 WIRE_SPEC 在作为对外规范前必须先修正。
