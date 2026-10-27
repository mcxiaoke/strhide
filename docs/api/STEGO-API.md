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

---

## 1. 公开面三层模型

| 层 | 内容 | 稳定性承诺 |
|---|---|---|
| **稳定面 Stable** | 统一入口 `stego::{embed_carrier, embed_carrier_with_dialect, extract_carrier, extract_carrier_with_dialect, extract_carrier_payload, inspect_carrier[_with_dialect], verify_carrier[_with_dialect], probe_carrier_capacity[_with_dialect]}`；选项 `EmbedOptions` / `ProbeOptions` / `ExtractOptions` / `InspectOptions` / `VerifyOptions` / `StegoTuning` / `SafetyPolicy` / `SafetyLevel` / `SafetyEnforcement` / `PngParams` / `JpegParams` / `StegoCodec` / `ExtractParams` / `Freshness`；方言 `params::StegoProfile`；结果 `StegoCapacityInfo` / `StegoHeaderInfo` / `StegoVerifyResult` / `EmbedOutput` / `core::media::MediaInfo`；格式身份 `format::{JpegFormatProfile, PngFormatProfile, HevcFormatProfile, GridRule, CipherSuite, SUITES, DEFAULT_JPEG_FORMAT, OFFICIAL_PNG_FORMAT, DEFAULT_HEVC_FORMAT}`；`registry::CostModelRegistry`；`traits::{PngCostModel, JpegCostModel, JpegGeometry}`；`io::{embed_carrier_file, extract_carrier_file, extract_carrier_file_payload}`；`facade::StrHide::stego()` | 破坏性变更只随 major |
| **专家面 Expert** | 域引擎入口 `png::engine::{embed_png, extract_png, probe_png_capacity}`、`jpeg::engine::{embed_jpeg, extract_jpeg, probe_jpeg_capacity}`、`heif::*`、`hevc::{embed_hevc, extract_hevc, probe_hevc_capacity}`；图像编解码 `png::engine::{decode_png, encode_png, RawImage, PngChunk}`；模型实现 `png::cost::*`、`jpeg::cost::*` | 小版本可演进，CHANGES 公告 |
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
| **secret**（KDF 凭据） | `EmbedOptions.password`（显式，空串视为未提供）> `StegoProfile.default_secret`（编译期私有方言）> 公开默认常量（结构域 `BUILTIN_DEFAULT_KEY`、图像域 `PUBLIC_DEFAULT_SECRET`——两者独立、不同名） |
| **domain**（HKDF 域隔离） | `EmbedOptions.domain`（运行时）> `StegoProfile.domain`（编译期）> 官方默认派生 |
| **safety**（容量策略） | `EmbedOptions.safety: SafetyPolicy { level, enforcement }`——**单一事实源**，tuning 不携带 safety |
| **freshness** | `EmbedOptions.freshness: Freshness`（`Random` 生产默认；`Seeded([u8; 32])` 可复现运行，PNG/JPEG/HEVC 全部支持；CLI 为 `--seed`） |
| **线格式身份** | 仅来自 `StegoProfile.{jpeg, png, hevc}`（编译期），无运行时覆盖——可切换的格式就是可枚举的指纹 |

规则：**读写必须一致的量（P 类）走 `StegoProfile` 或 `facade::Dialect` 并保持两侧相同；
只影响写侧行为的量（L 类）随便每次调用变。**

### 2.2 选项构造

阶段 4 起**写侧与读侧的选项彻底分开**：提取端不再被迫传代价图超参数，
`extract_carrier` 头部那句 `png_params.validate()?` 的误拦也随之消失。

```rust
use strhide::stego::{
    EmbedOptions, ExtractOptions, ProbeOptions, StegoTuning, SpatialAlgorithm, PngParams,
    SafetyLevel, SafetyEnforcement,
};

// 写侧：给算法与参数，二者绑在同一个枚举臂里，不可能错配格式。
let embed = EmbedOptions {
    password: Some("pw"),
    safety: SafetyPolicy::new(SafetyLevel::High, SafetyEnforcement::Advisory),
    tuning: StegoTuning::Png { algorithm: SpatialAlgorithm::Hill, params: PngParams::default() },
    ..Default::default()
};

// 读侧：只有凭据与上限。
let extract = ExtractOptions { password: Some("pw"), ..Default::default() };

// 只读探测：与 embed 同一组调参，容量答案才对得上将要执行的那次嵌入。
let probe = ProbeOptions { tuning: embed.tuning.clone(), ..Default::default() };
```

`StegoTuning` 是 `Auto` 与三个按格式分臂的联合体：

```rust
pub enum StegoTuning {
    #[default] Auto,
    Png  { algorithm: SpatialAlgorithm, params: PngParams },
    Jpeg { algorithm: JpegAlgorithm,    params: JpegParams },
    Hevc { mode: HevcMode,              params: HevcParams },
}
```

`SafetyLevel` 实现 `FromStr`：`paranoid|high|balanced` 或数字别名 `0|1|2`。

---

## 3. 第三方编译期定制（私有方言配方）

以 CarrotHash 为范本——一份 `const Dialect` 声明全部私有方言，
`cargo build` 即得与官方互不兼容的二进制，零运行时成本：

```rust
use strhide::facade::Dialect;
use strhide::stego::format::{
    GridRule, HevcFormatProfile, JpegFormatProfile, PngFormatProfile, SUITES,
};
use strhide::stego::params::StegoProfile;

const STEGO_JPEG: JpegFormatProfile = JpegFormatProfile { /* 派生标签 + 几何 + suites */ };
const STEGO_PNG: PngFormatProfile = PngFormatProfile { /* 派生标签 + body 引用 */ };
const STEGO_HEVC: HevcFormatProfile = HevcFormatProfile {
    magic_label: b"acme-hevc-magic-v1",   // 头部魔数 = SHA-256(label ‖ secret)[..4]
    cover_salt: b"acme-hevc-cover-v1",    // cover digest 前缀
    kdf_info: b"acme-hevc-aes-key",       // AES 密钥 HKDF info
    stc_h: 7,
    stc_u: 2,
    header_bytes: 40,
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
- **HEVC 的 `magic_label`**：官方格式已将魔数从固定 `SH25` 改为按
  `SHA-256(magic_label ‖ effective_secret)[..4]` 派生——私有构建改标签即可
  消除开源指纹，且无凭据者无法用固定魔数判定载体存在性（头部槽位仅由
  参数集决定，与密码无关，这是设计要求；威胁模型见 WIRE_SPEC §13.11.2）。
- 只想私有化图像域时用 `StegoProfile`；`Dialect::with_default_secret` 会同时
  设置结构域与图像域两半，两域派生域不同，同一字符串得到两把不相关密钥。
- 仅开启 `features = ["content-png"]` / `["content-jpeg"]` / `["content-hevc"]`
  即可只编入需要的内容域引擎；`strhide::stego::io::embed_carrier_file` 提供
  临时文件 + rename 原子提交、`.bak` 备份与时间戳保留，宿主无需自建 I/O。
- 文件级便捷入口（`StrHide::stego().embed_file` / `extract_file`）内部委托
  同一 `stego::io` 实现；GUI 不依赖 `cli` 特性即可用。

---

## 4. 扩展点

- **自定义代价模型**：实现 `traits::PngCostModel` / `JpegCostModel`，
  经专家面域引擎入口以 `&dyn` 传入（见 `examples/stego_profile.rs`）。
  注意：PNG 提取端由载体头部（`FeatureWord.algorithm_id`）声明算法，
  统一入口不接受 trait 对象；自有模型请直接调用域引擎，并保证嵌入与
  提取传入同一模型实例。
- **容量探测前置嗅探**：`formats::sniff::sniff_bytes(bytes) -> Option<FileFormat>`，
  调用方可在嵌入前预判格式与路由（`CarrierFormat` 枚举在阶段 0 已删除：
  它与 `FileFormat` 重复且漏了 MP4）。

---

## 5. CLI 映射（命令 → 库入口）

| 命令 | 库入口 | 说明 |
|---|---|---|
| `embed` | `embed_carrier_with_dialect` | 日常层：`-t/-d/-p/-o/--in-place/-a/--safety/--enforce-safety`；专家层按格式分成两节——`PNG Spatial Tuning`（`--exclusion-rate/--p1-window/--p2-window`）与 `JPEG DCT Tuning`（`--neighbor-weight/--stc-h`）；隐藏参数：`--slot-budget/--cipher-suite`；`Reproducibility` 节：`--seed`；`--dry-run` 全内存演练不落盘 |
| `extract` | `extract_carrier_with_dialect` | 仅保留活参数：`--p1-window/--p2-window`（PNG 代价图重算必需）；`-a` 仅 `hevc/cabac` 影响路由；算法/排除率等由载体自描述；支持 `CARRIER...` + `-o <DIR>` 批量 |
| `capacity` | `probe_carrier_capacity_with_dialect` | 独立只读探测子命令（与 `embed --capacity` 同一实现），`--json` 输出 `StegoCapacityInfo`；`--exact` 强制全量精确扫描（长视频默认开启前 20% 样本加权快速估算）；与 embed 共享同一组调参/凭据参数 |
| `embed --capacity` | 同上 | 别名形式保留，支持 `--exact` |

提取端自描述范围（无需在提取时重复）：算法 id、排除率（`exclusion_permille`）、
codec、`h`、`u`、通道模式（PNG `FeatureWord`）；`h`/`u`、套件 id（JPEG 超块）。
**不自描述**、提取端必须重复：PNG 的 `--p1-window` / `--p2-window`、
凭据（secret/domain）、方言（`Dialect`）。

配置文件中可用 `[stego]` 段固定三个部署策略项，命令行标志始终优先：

```toml
[stego]
safety         = "high"    # paranoid | high | balanced
enforce_safety = false     # true 时超限直接拒绝而非只告警
algorithm      = "auto"
```

---

## 6. 守卫

- `tests/cli_help_guard.rs`：localize（en/zh）后全命令树每个可见参数 help
  非空——stego 参数 help 的事实源在 i18n 消息表，条目缺失即测试失败。
- `hevc::engine::dialect_tests`：`DEFAULT_HEVC_FORMAT` 字面量与
  WIRE_SPEC §13.11 钉死；魔数随凭据变化；公开默认密钥唯一。
- `tests/test_lifecycle/facade.rs`：一个 `Dialect::with_default_secret`
  必须同时隔离两域；只私有化图像域时结构域仍保持官方行为。
