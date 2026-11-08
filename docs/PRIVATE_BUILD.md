# 私有构建指南（消除来源指纹）

> 适用：需要「产物无法被归因到 strhide」的私有构建 / 第三方集成
> 参考实现：`rust/tests/private_provenance.rs`（可运行、逐项断言的配方）
> 边界：本指南只改**派生链与身份常量**，不改嵌入算法、不改统计面

---

## 1. 两类旋钮，别混用

| 类别 | 作用 | 旋钮 |
| :--- | :--- | :--- |
| **隔离型** | 官方二进制 / 第三方工具**读不出**私有载体（即使知道口令） | `default_secret`、`domain`、五个载体的盐、`WireCipherProfile` 标签表、`aad_prefix`、`flac_body_phase_label`、`session_salt_label` |
| **统计型** | 改变 steganalysis 的检测率 | 成本模型、`stc_h`/`stc_u`、`grid_rule`、参数基线。**本指南不涉及**，改它们也不会影响"能否归因" |

一句话：**标签与盐从不落盘**，改它们对检测率零影响，只断开归因链。

---

## 2. 必设项（漏一个就漏一层）

| 项 | 位置 | 说明 |
| :--- | :--- | :--- |
| `default_secret` | `StegoProfile` | 「无口令」路径唯一的密钥来源。不设 = 公开常量 `strhide-default-content-stego-key-2026`，**任何 strhide 二进制都能读** |
| `domain` | `StegoProfile` | HKDF 域分隔，跳过它会让同一口令在不同部署间共用 L1 子密钥 |
| `hpos_salt`（PNG / WAV / FLAC） | 各 `AudioFormatProfile` / `PngFormatProfile` | 混进 `pre_salt`，决定 L1 master。**五个载体必须各不相同** |
| `cover_digest_tag`（JPEG） | `JpegFormatProfile` | JPEG 的 `pre_salt` 域分隔 |
| `cover_salt`（HEVC） | `HevcFormatProfile` | HEVC 封面摘要的域分隔 |
| `WireCipherProfile` 全表 | `PNG`/`JPEG`/`HEVC`/`AUDIO` | 见 §3 的字段清单 |
| `flac_body_phase_label` | `AudioFormatProfile` | 只影响 FLAC 体相位 |
| `session_salt_label` | `HevcFormatProfile` | 只影响 HEVC 的 L3 会话盐 |
| `magic_label`（HEVC） | `HevcFormatProfile` | 决定 HEVC superblock 的 4 字节魔数 |

---

## 3. 完整配方

```rust
use strhide::core::crypto::CipherSuiteId;
use strhide::facade::Dialect;
use strhide::stego::format::{
    AudioFormatProfile, GridRule, HevcFormatProfile, JpegFormatProfile, PngFormatProfile,
    WireCipherProfile, DEFAULT_JPEG_FORMAT, DEFAULT_HEVC_FORMAT,
};
use strhide::stego::params::StegoProfile;

// 标签表：9 个字段全部替换（值取随机 ASCII 即可，长度不敏感）。
const PRIVATE_CIPHER: WireCipherProfile = WireCipherProfile {
    domain_label:   b"acme-domain-v1",
    hpos_label:     b"acme-hpos-v1",
    enc_label:      b"acme-enc-v1",
    perm_label:     b"acme-perm-v1",
    stc_label:      b"acme-stc-v1",
    hdr_stc_label:  b"acme-hdr-stc-v1",   // 仅 JPEG / HEVC 消费
    ext_stc_label:  b"acme-ext-stc-v1",   // 仅 JPEG / HEVC 消费
    aad_prefix:     b"acme-envelope-v4\0",// 官方值以 NUL 结尾，保持一致习惯
    default_suite:  CipherSuiteId::Aes256Gcm,
};

const PRIVATE_PNG: PngFormatProfile = PngFormatProfile {
    hpos_salt: b"acme-png-hpos-2026",
    cipher: &PRIVATE_CIPHER,
};

const PRIVATE_JPEG: JpegFormatProfile = JpegFormatProfile {
    cover_digest_tag: b"acme-jpeg-cover-2026",
    cipher: &PRIVATE_CIPHER,
    sb_bytes: DEFAULT_JPEG_FORMAT.sb_bytes,
    sb_h: DEFAULT_JPEG_FORMAT.sb_h,
    sb_u: DEFAULT_JPEG_FORMAT.sb_u,
    ext_h: DEFAULT_JPEG_FORMAT.ext_h,
    ext_u: DEFAULT_JPEG_FORMAT.ext_u,
    grid_rule: GridRule::ALL_AC,
};

const PRIVATE_WAV: AudioFormatProfile = AudioFormatProfile {
    hpos_salt: b"acme-wav-hpos-2026",
    cipher: &PRIVATE_CIPHER,
    flac_body_phase_label: b"acme-flac-phase-2026",
};

const PRIVATE_FLAC: AudioFormatProfile = AudioFormatProfile {
    hpos_salt: b"acme-flac-hpos-2026",
    cipher: &PRIVATE_CIPHER,
    flac_body_phase_label: b"acme-flac-phase-2026",
};

const PRIVATE_HEVC: HevcFormatProfile = HevcFormatProfile {
    cipher: &PRIVATE_CIPHER,
    magic_label: b"acme-hevc-magic-v1",
    cover_salt: b"acme-hevc-cover-2026",
    session_salt_label: b"acme-hevc-session-v1",
    stc_h: DEFAULT_HEVC_FORMAT.stc_h,
    stc_u: DEFAULT_HEVC_FORMAT.stc_u,
};

pub const PRIVATE_DIALECT: Dialect = Dialect::new().with_stego_profile(
    StegoProfile::new()
        .with_default_secret("acme-no-password-key-2026")
        .with_stego_domain("acme-domain-v1")
        .with_png_format(PRIVATE_PNG)
        .with_jpeg_format(PRIVATE_JPEG)
        .with_hevc_format(PRIVATE_HEVC)
        .with_audio_format(PRIVATE_WAV)   // 注意：WAV 用 audio_format
        .with_flac_format(PRIVATE_FLAC),
);
```

私有二进制入口（替换 `src/main.rs` 的单行调用）：

```rust
fn main() {
    let code = strhide::facade::StrHide::new()
        .with_dialect(PRIVATE_DIALECT)
        .run_cli_from(std::env::args_os());
    std::process::exit(code);
}
```

---

## 4. 三个常见错误

1. **只改一个盐就以为隔离完成。** 严格来说够（L1 master 已不同），但一旦有人复用口令、或只替换标签表而忘了盐，就会退化成「官方读得出」。配方里所有项**一起换**，不要挑。
2. **复用同一个盐给多个载体。** 同一个 `pre_salt` + 同一口令会让不同格式的 L1 master 相同，跨格式可互相推断。五个盐各用各的。
3. **绕过 facade 直接调 `stego::hevc::embed_hevc(...)`。** 这些 pre-V4 入口拿不到 `StegoProfile`，现在会**直接报错**而不是退回公开密钥（`hevc/engine.rs` 的 `legacy_credential`）。请一律走 `StrHide` / `EmbedOptions` 路径。

---

## 5. 验证

```bash
cd rust
cargo test --all-features --test private_provenance
```

该测试逐项锁定：

| 测试 | 锁定的旋钮 |
| :--- | :--- |
| `private_content_carriers_roundtrip` | 私有方言自洽（PNG / JPEG / WAV / FLAC，带口令与不带口令） |
| `official_content_dialect_cannot_read_private_carriers_with_the_password` | 盐 + 标签表的整体隔离 |
| `official_content_dialect_cannot_read_private_carriers_without_the_password` | `default_secret` |
| `aad_prefix_alone_separates_two_dialects` | `aad_prefix` 确实进了 AEAD |
| `l2_trellis_labels_alone_separate_two_dialects` | `hdr_stc_label` / `ext_stc_label`（JPEG 载体） |
| `flac_body_phase_label_alone_separates_two_dialects` | `flac_body_phase_label` |
| `legacy_hevc_entry_point_rejects_an_absent_secret` | pre-V4 入口不再静默使用公开密钥 |

另外每次改完必须过：

```bash
cargo build --release --all-features
cargo test --all-features --all-targets
python ../scripts/baseline_hash.py --check    # 官方默认必须逐字节不变
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
python ../scripts/import_lint.py
```

---

## 6. 适用边界（别期待错东西）

- **本方案不提升抗 steganalysis 能力。** 统计检测率与官方版本完全一致：几何、成本模型、参数都没动。
- **结构域不在覆盖范围。** `prIv` / `stEg` / `SHRD` / `MP4_UUID_NEUTRAL` / JPEG APP15 仍是明文容器标记，第三方静态扫描照样能看到；`StructureProfile` 目前只有 `default_secret` / `stealth_domain` / `magic` 三个字段。要覆盖结构域需另做 `ContainerTags`。
- **二进制层字符串**（程序名、版本、帮助文本）仍是 `strhide`，要隐藏需在 `build.rs` / CLI 层做品牌串替换。
