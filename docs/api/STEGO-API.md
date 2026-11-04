# stego 内容域公开 API 规范（单一事实源）

> 本文档是 `strhide::stego` 对外接口的权威说明：公开面分层、命名规范、
> 凭据优先级、第三方编译期定制配方（以 CarrotHash 为范本）与 CLI 映射。
> 线格式细节见 [WIRE_SPEC.md](./WIRE_SPEC.md)，架构总览见
> [ARCHITECTURE.md](./ARCHITECTURE.md)。随接口变更同步更新。
>
> **阶段 4 变更**：`StegoOptions` 已删除并拆成强类型选项
> （`EmbedOptions` / `ProbeOptions` / `ExtractOptions` / `InspectOptions` /
> `VerifyOptions` + `StegoTuning`）；方言类型由 `params::Profile` 改为
> `stego::params::StegoProfile`（`facade::Dialect` 组合它）；统一入口的
> `_with_profile` 后缀改为 `_with_dialect`。
>
> **V4 内容信封变更**：凭据统一为 `Credential::{Password, FileKey}`；
> 套件枚举 `CipherSuiteId`（1 = AES-256-GCM 默认，2 = ChaCha20-Poly1305，
> append-only）；选项新增 `key` / `suite_id` / `extensions: Vec<Tlv>`；
> 旧 `CipherSuite` / `SUITES` / `FeatureWord` / `header_v3::Superblock` 已删除，
> `FeatureWord` 的 epsilon 量化改为 `header::quantize_epsilon_k`。
> CLI 暴露 `--cipher-suite`（别名 `--suite`）、`--key-file`（embed/capacity/
> extract/inspect/verify，接受 32 原始字节或 64 位十六进制）与 `--max-payload`
> （extract）；`--extensions` 仍未接线。
>
> **2026-11-04 API 整理**：`StegoCodec::id()` 更名为
> `StegoCodec::wire_id()`，明确它返回信封头部的线格式 id（`Auto` 与 `Stc`
> 都为 1），不是 Rust 层的算法区分；`heif::BridgeTargetKind::DirectSpatial`
> 已删除（全仓从未构造该变体，`unci` 原始像素并非 PNG 流）。

---

## 1. 公开面三层模型

| 层 | 内容 | 稳定性承诺 |
|---|---|---|
| **稳定面 Stable** | 统一入口 `stego::{embed_carrier, embed_carrier_with_dialect, extract_carrier, extract_carrier_with_dialect, extract_carrier_payload, inspect_carrier[_with_dialect], verify_carrier[_with_dialect], probe_carrier_capacity[_with_dialect], list_stego_algorithms, algorithms_for_format}`；选项 `EmbedOptions` / `ProbeOptions` / `ExtractOptions` / `InspectOptions` / `VerifyOptions` / `StegoTuning` / `SafetyPolicy` / `SafetyLevel` / `SafetyEnforcement` / `PngParams` / `JpegParams` / `StegoCodec` / `ExtractParams` / `Freshness`；凭据 `Credential`（`Password` / `FileKey`）；套件 `CipherSuiteId`；扩展 `Tlv`；方言 `params::StegoProfile`；结果 `StegoCapacityInfo` / `StegoHeaderInfo` / `StegoVerifyResult` / `EmbedOutput` / `StegoAlgorithmInfo` / `core::media::MediaInfo`；格式身份 `format::{JpegFormatProfile, PngFormatProfile, HevcFormatProfile, GridRule, DEFAULT_JPEG_FORMAT, OFFICIAL_PNG_FORMAT, DEFAULT_HEVC_FORMAT}`；`registry::CostModelRegistry`；`traits::{PngCostModel, JpegCostModel, JpegGeometry}`；`io::{embed_carrier_file, extract_carrier_file, extract_carrier_file_payload}`；`facade::StrHide::stego()` | 破坏性变更只随 major |
| **专家面 Expert** | 域引擎入口 `png::engine::{embed_png, extract_png, probe_png_capacity}`、`jpeg::engine::{embed_jpeg, extract_jpeg, probe_jpeg_capacity}`、`heif::*`、`hevc::{embed_hevc, extract_hevc, probe_hevc_capacity}`、`audio::{embed_audio, extract_audio, probe_audio_capacity}`；图像/音频编解码与解析；模型实现 `png::cost::*`、`jpeg::cost::*`、`audio::flac::*`、`audio::wav::*` | 小版本可演进，CHANGES 公告 |
| **内部面 Internal**（`#[doc(hidden)]`，无承诺） | `coding`、`envelope`、`header`、`prng`、`wavelet`、`jpeg::{dht, geometry, header_v3, v3_layout}`、`hevc::{bitstream, error, heif_boxes, slot, sniff}` | 路径可达但不入文档；随时可变 |

**命名规范**：按载体格式命名（Jpeg / Png / Hevc 前缀），参数类型 `XxxParams`、
线格式身份 `XxxFormatProfile`、常量 `DEFAULT_XXX_FORMAT` / `OFFICIAL_XXX_FORMAT`。
统一入口以 carrier（载体）命名，域引擎与 facade 与之一致。

---

## 2. 统一入口与凭据优先级

```rust
// 推荐入口（自动格式嗅探：PNG / JPEG / HEIF / HEVC Annex-B / MP4·MOV）
stego::embed_carrier(carrier_bytes, &payload, &options)                        // 官方方言
stego::embed_carrier_with_dialect(carrier_bytes, &payload, &options, &dialect) // 私有方言
stego::extract_carrier[_with_dialect](carrier_bytes, &options[, &dialect])
stego::probe_carrier_capacity[_with_dialect](carrier_bytes, &options[, &dialect])
```

### 2.1 凭据与方言优先级（单一规则）

| 旋钮 | 解析顺序 |
|---|---|
| **credential**（KDF 凭据） | `Credential::{Password(str), FileKey(&[u8; 32])}`：`password` 与 `key` 互斥（同时给非空值报错）；都没有时取 `StegoProfile.default_secret`，再没有则公开默认常量 `PUBLIC_DEFAULT_SECRET`。空串密码视为未提供 |
| **suite**（AEAD 套件） | `EmbedOptions.suite_id`（运行时覆盖）> `WireCipherProfile.default_suite`（编译期）。读取端始终以头部 `suite_id` 为准，`ExtractParams.allowed_suites` 只做试枚举白名单 |
| **domain**（HKDF 域隔离） | `EmbedOptions.domain`（运行时）> `StegoProfile.domain`（编译期）> 官方默认派生 |
| **safety**（容量策略） | `EmbedOptions.safety: SafetyPolicy { level, enforcement }`——**单一事实源**，tuning 不携带 safety |
| **freshness** | `EmbedOptions.freshness: Freshness`（`Random` 生产默认；`Seeded([u8; 32])` 可复现运行，PNG/JPEG/HEVC 全部支持；CLI 为 `--seed`） |
| **extensions** | `EmbedOptions.extensions: Vec<Tlv>`；`ProbeOptions.extensions` 必须与将要写入的一致 |
| **线格式身份** | 仅来自 `StegoProfile.{jpeg, png, hevc}`（编译期），无运行时覆盖——可切换的格式就是可枚举的指纹 |

规则：**读写必须一致的量（P 类）走 `StegoProfile` 或 `facade::Dialect` 并保持两侧相同；
只影响写侧行为的量（L 类）随便每次调用变。**

### 2.2 选项构造

阶段 4 起**写侧与读侧的选项彻底分开**：提取端不再被迫传代价图超参数，
`extract_carrier` 头部那句 `png_params.validate()?` 的误拦也随之消失。

```rust
use strhide::stego::{
    EmbedOptions, ExtractOptions, ProbeOptions, StegoTuning, SpatialAlgorithm, PngParams,
    SafetyLevel, SafetyEnforcement, Tlv, CipherSuiteId,
};

// 写侧：给算法与参数，二者绑在同一个枚举臂里，不可能错配格式。
let embed = EmbedOptions {
    password: Some("pw"),
    key: None,                       // 与 password 互斥
    suite_id: Some(1),               // 1=AES-256-GCM（默认），2=ChaCha20-Poly1305
    extensions: vec![Tlv { type_id: 0x01, value: b"x".to_vec() }],
    safety: SafetyPolicy::new(SafetyLevel::High, SafetyEnforcement::Advisory),
    tuning: StegoTuning::Png { model: SpatialAlgorithm::Hill, params: PngParams::default() },
    ..Default::default()
};

// 读侧：只有凭据与上限（默认 max_pbkdf2_iterations = 200,000）。
let extract = ExtractOptions {
    password: Some("pw"),
    key: None,
    domain: None,
    limits: ExtractParams::default(),
    ..Default::default()
};

// 只读探测：与 embed 同一组调参、同一套扩展，容量答案才对得上将要执行的那次嵌入。
let probe = ProbeOptions { tuning: embed.tuning.clone(), extensions: embed.extensions.clone(), ..Default::default() };
```

`StegoTuning` 是 `Auto` 与三个按格式分臂的联合体：

```rust
pub enum StegoTuning {
    #[default] Auto,
    Png  { model: SpatialAlgorithm, params: PngParams },
    Jpeg { model: JpegAlgorithm,    params: JpegParams },
    Hevc { mode: HevcMode,          params: HevcParams },
}
```

`SafetyLevel` 实现 `FromStr`：`paranoid|high|balanced` 或数字别名 `0|1|2`。

---

## 3. 第三方编译期定制（私有方言配方）

以 CarrotHash 为范本——一份 `const Dialect` 声明全部私有方言，
`cargo build` 即得与官方互不兼容的二进制，零运行时成本：

```rust
use strhide::facade::Dialect;
use strhide::stego::format::{HevcFormatProfile, JpegFormatProfile, PngFormatProfile};
use strhide::stego::params::StegoProfile;

// 以官方常量为模板，只替换派生标签/几何。
// 字段全集与默认值见 format::JpegFormatProfile / HevcFormatProfile / PngFormatProfile 的 rustdoc。
const STEGO_JPEG: JpegFormatProfile = JpegFormatProfile { /* cover_digest_tag + cipher + 44B 几何 */ };
const STEGO_PNG: PngFormatProfile = PngFormatProfile { /* 派生标签 + cipher + body 引用 */ };
const STEGO_HEVC: HevcFormatProfile = HevcFormatProfile {
    /* cipher + magic_label + cover_salt + stc_h/stc_u */
};

pub const DIALECT: Dialect = Dialect::new()
    .with_default_secret("acme-deployment-secret")  // 两域共用一把部署密钥
    .with_stego_profile(
        StegoProfile::new()
            .with_stego_domain("org.acme.stego")    // 可选：域隔离
            .with_jpeg_format(STEGO_JPEG)
            .with_png_format(STEGO_PNG)
            .with_hevc_format(STEGO_HEVC),
    );
```

要点：
- 改任意派生标签即产生不同线格式；官方二进制读私有载体报 `NoHiddenData`
  （与错密码不可区分），反之亦然。
- **HEVC 的 `magic_label`**：官方格式的魔数按
  `SHA-256(magic_label ‖ effective_secret)[..4]` 派生——私有构建改标签即可
  消除开源指纹，且无凭据者无法用固定魔数判定载体存在性（头部槽位仅由
  参数集决定，与密码无关，这是设计要求；威胁模型见 WIRE_SPEC §13）。
- 套件默认值在 `WireCipherProfile.default_suite` 中；私有构建可改默认套件，
  但读写仍以头部 `suite_id` 为准（1=AES-256-GCM，2=ChaCha20-Poly1305）。
- 只想私有化图像域时用 `StegoProfile`；`Dialect::with_default_secret` 会同时
  设置结构域与图像域两半，两域派生域不同，同一字符串得到两把不相关密钥。
- 仅开启 `features = ["content-png"]` / `["content-jpeg"]` / `["content-hevc"]`
  即可只编入需要的内容域引擎；`strhide::stego::io::embed_carrier_file` 提供
  临时文件 + rename 原子提交、`.bak` 备份与时间戳保留，宿主无需自建 I/O。
- 文件级便捷入口（`StrHide::stego().embed_file` / `extract_file`）内部委托
  同一 `stego::io` 实现；GUI 不依赖 `cli` 特性即可用。

---

## 4. 算法动态自省与元数据 API

核心库提供算法元数据自省机制（`StegoAlgorithmInfo`），消除前端与调用方的硬编码：

```rust
use strhide::stego::{list_stego_algorithms, algorithms_for_format, StegoAlgorithmInfo};
use strhide::formats::FileFormat;

// 获取全量算法列表（覆盖 PNG, JPEG, HEVC, Audio）
let all_algos: Vec<StegoAlgorithmInfo> = list_stego_algorithms();

// 获取适用于特定格式的算法（如 PNG -> HILL, S-UNIWARD, MiPOD）
let png_algos = algorithms_for_format(FileFormat::Png);
for info in png_algos {
    println!("{}: {} ({})", info.id, info.name, info.desc);
}
```

支持算法矩阵：
- **PNG**: `hill` (默认), `suniward`, `mipod`
- **JPEG**: `uerd` (默认), `juniward`, `jmipod`
- **HEVC**: `hevc` (CABAC 旁路符号位原位隐写，支持 MP4, MOV, MKV, HEIF/HEIC, Annex-B)
- **Audio**: `wav_pcm` (WAV PCM LSB 匹配), `flac_residual` (FLAC 预测残差多项式匹配)

---

## 5. 扩展点

- **自定义代价模型**：实现 `traits::PngCostModel` / `JpegCostModel`，
  经专家面域引擎入口以 `&dyn` 传入（见 `examples/stego_profile.rs`）。
  注意：PNG 提取端由 64B V4 基础头（`algorithm_id`）声明算法，
  统一入口不接受 trait 对象；自有模型请直接调用域引擎，并保证嵌入与
  提取传入同一模型实例。
- **容量探测前置嗅探**：`formats::sniff::sniff_bytes(bytes) -> Option<FileFormat>`，
  调用方可在嵌入前预判格式与路由（`CarrierFormat` 枚举在阶段 0 已删除：
  它与 `FileFormat` 重复且漏了 MP4）。

---

## 6. CLI 映射（命令 → 库入口）

| 命令 | 库入口 | 说明 |
|---|---|---|
| `embed` | `embed_carrier_with_dialect` | 日常层：`-t/-d/-p/-o/--in-place/-a/--safety/--enforce-safety`；专家层按格式分成两节——`PNG Spatial Tuning`（`--exclusion-rate/--p1-window/--p2-window`）与 `JPEG DCT Tuning`（`--neighbor-weight/--stc-h`）；隐藏参数：`--slot-budget/--cipher-suite`；`Reproducibility` 节：`--seed`；`--dry-run` 全内存演练不落盘 |
| `extract` | `extract_carrier_with_dialect` | 仅保留活参数：`--p1-window/--p2-window`（PNG 代价图重算必需）；`-a` 仅 `hevc/cabac` 影响路由；算法/排除率等由载体自描述；支持 `CARRIER...` + `-o <DIR>` 批量 |
| `capacity` | `probe_carrier_capacity_with_dialect` | 独立只读探测子命令（与 `embed --capacity` 同一实现），`--json` 输出 `StegoCapacityInfo`；`--exact` 强制全量精确扫描（长视频默认开启前 20% 样本加权快速估算）；与 embed 共享同一组调参/凭据参数 |
| `embed --capacity` | 同上 | 别名形式保留，支持 `--exact` |

**未实现的 CLI 能力**：`--extensions`（TLV 扩展区）；库 API 已支持，CLI/GUI 未接线。
`--key-file`（`Credential::FileKey`）与 `--max-payload`（`ExtractParams.max_payload_bytes`）
已接线（GUI 仍只有密码）。套件参数为 `--cipher-suite`（别名 `--suite`，`1`/`2`，
对所有内容格式生效，归在 `Stego Envelope` 分组）。

提取端自描述范围（无需在提取时重复）：算法 id、排除率（`exclusion_permille`）、
codec、`h`、`u`、通道模式、`format_id`、`suite_id`、`body_len`、扩展区（64B/44B/32B 基础头）；
**不自描述**、提取端必须重复：PNG 的 `--p1-window` / `--p2-window`、
凭据（password/key/domain）、方言（`Dialect`）。

配置文件中可用 `[stego]` 段固定三个部署策略项，命令行标志始终优先：

```toml
[stego]
safety         = "high"    # paranoid | high | balanced
enforce_safety = false     # true 时超限直接拒绝而非只告警
algorithm      = "auto"
```

---

## 7. 守卫

- `tests/cli_help_guard.rs`：localize（en/zh）后全命令树每个可见参数 help
  非空——stego 参数 help 的事实源在 i18n 消息表，条目缺失即测试失败。
- `hevc::engine::dialect_tests`：`DEFAULT_HEVC_FORMAT` 字面量与
  WIRE_SPEC §13 钉死；魔数随凭据变化；公开默认密钥唯一。
- `tests/test_lifecycle/facade.rs`：一个 `Dialect::with_default_secret`
  必须同时隔离两域；只私有化图像域时结构域仍保持官方行为。
