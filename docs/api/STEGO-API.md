# stego 内容域公开 API 规范（单一事实源）

> 本文档是 `strhide::stego` 对外接口的权威说明：公开面分层、命名规范、
> 凭据优先级、第三方编译期定制配方（以 CarrotHash 为范本）与 CLI 映射。
> 线格式细节见 [WIRE_SPEC.md](./WIRE_SPEC.md)，架构总览见
> [ARCHITECTURE.md](./ARCHITECTURE.md)。随接口变更同步更新。

---

## 1. 公开面三层模型

| 层 | 内容 | 稳定性承诺 |
|---|---|---|
| **稳定面 Stable** | 统一入口 `stego::{embed_carrier, embed_carrier_with_profile, extract_carrier, extract_carrier_with_profile, probe_carrier_capacity, probe_carrier_capacity_with_profile}`；配置类型 `StegoOptions` / `SafetyPolicy` / `SafetyLevel` / `SafetyEnforcement` / `PngParams` / `JpegParams` / `StegoCodec` / `ExtractParams` / `Freshness` / `StegoCapacityInfo`；格式身份 `format::{JpegFormatProfile, PngFormatProfile, HevcFormatProfile, GridRule, CipherSuite, Kdf, Aead, SUITES, DEFAULT_JPEG_FORMAT, OFFICIAL_PNG_FORMAT, DEFAULT_HEVC_FORMAT}`；`registry::CostModelRegistry`；`traits::{PngCostModel, JpegCostModel, JpegGeometry}`；`sniff_carrier` / `CarrierFormat`；`io::{embed_carrier_file, extract_carrier_file}`；`facade::StrHide`（结构域 + 内容域门面） | 破坏性变更只随 major |
| **专家面 Expert** | 域引擎入口 `png::engine::{embed_png, extract_png, probe_png_capacity}`、`jpeg::engine::{embed_jpeg, extract_jpeg, probe_jpeg_capacity}`、`heif::*`、`hevc::{embed_hevc, extract_hevc, probe_hevc_capacity}`；图像编解码 `png::engine::{decode_png, encode_png, RawImage, PngChunk}`；模型实现 `png::cost::*`、`jpeg::cost::*` | 小版本可演进，CHANGES 公告 |
| **内部面 Internal**（`#[doc(hidden)]`，无承诺） | `coding`、`envelope`、`header`、`prng`、`wavelet`、`jpeg::{dht, geometry, header_v3, v3_layout}`、`hevc::{bitstream, error, heif_boxes, slot, sniff}` | 路径可达但不入文档；随时可变 |

**命名规范**：按载体格式命名（Jpeg / Png / Hevc 前缀），参数类型 `XxxParams`、
线格式身份 `XxxFormatProfile`、常量 `DEFAULT_XXX_FORMAT` / `OFFICIAL_XXX_FORMAT`。
统一入口以 carrier（载体）命名，域引擎与 facade 与之一致。

---

## 2. 统一入口与凭据优先级

```rust
// 推荐入口（自动格式嗅探：PNG / JPEG / HEIF / HEVC Annex-B / MP4·MOV）
stego::embed_carrier(carrier_bytes, payload, &options)                       // 官方方言
stego::embed_carrier_with_profile(carrier_bytes, payload, &options, &profile) // 私有方言
stego::extract_carrier[_with_profile](carrier_bytes, &options[, &profile])
stego::probe_carrier_capacity[_with_profile](carrier_bytes, &options[, &profile])
```

### 2.1 凭据与方言优先级（单一规则）

| 旋钮 | 解析顺序 |
|---|---|
| **secret**（KDF 凭据） | `StegoOptions.password`（显式，空串视为未提供）> `Profile.stego.default_secret`（编译期私有方言）> 公开默认常量（结构域 `BUILTIN_DEFAULT_KEY`、图像域 `PUBLIC_DEFAULT_SECRET`——两者独立、不同名） |
| **domain**（HKDF 域隔离） | `StegoOptions.domain`（运行时）> `Profile.stego.domain`（编译期）> 官方默认派生 |
| **safety**（容量策略） | `StegoOptions.safety: SafetyPolicy { level, enforcement }`——**单一事实源**，参数结构体不携带 safety |
| **freshness** | `StegoOptions.freshness: Freshness`（`Random` 生产默认；`Seeded([u8; 32])` 可复现运行，PNG/JPEG/HEVC 全部支持） |
| **线格式身份** | 仅来自 `Profile.stego.{jpeg, png, hevc}`（编译期），无运行时覆盖——可切换的格式就是可枚举的指纹 |

规则：**读写必须一致的量（P 类）走 Profile 或 Options 的同名字段并保持两侧相同；
只影响写侧行为的量（L 类）随便每次调用变。**

### 2.2 运行时选项构造（链式 builder）

```rust
let options = StegoOptions::default()
    .with_password("pw")
    .with_algorithm("hill")            // hill / suniward / uerd / juniward / hevc / cabac / auto
    .with_domain("org.acme.stego")     // 可选：HKDF 域隔离
    .with_safety(SafetyLevel::High, SafetyEnforcement::Advisory)
    .with_freshness(Freshness::Random);
```

`SafetyLevel` 实现 `FromStr`：`paranoid|high|balanced` 或数字别名 `0|1|2`。

---

## 3. 第三方编译期定制（私有方言配方）

以 CarrotHash 为范本——一份 `const Profile` 声明全部三个域的私有方言，
`cargo build` 即得与官方互不兼容的二进制，零运行时成本：

```rust
use strhide::params::Profile;
use strhide::stego::format::{
    GridRule, HevcFormatProfile, JpegFormatProfile, PngFormatProfile, SUITES,
};

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

pub const DIALECT: Profile = Profile::new()
    .with_stego_secret("acme-stego-secret")     // 无密码载体的私有密钥
    .with_stego_domain("org.acme.stego")        // 可选：域隔离
    .with_jpeg_format(STEGO_JPEG)
    .with_png_format(STEGO_PNG)
    .with_hevc_format(STEGO_HEVC);
```

要点：
- 改任意派生标签即产生不同线格式；官方二进制读私有载体报 `NoHiddenData`
  （与错密码不可区分），反之亦然。
- **HEVC 的 `magic_label`**：官方格式已将魔数从固定 `SH25` 改为按
  `SHA-256(magic_label ‖ effective_secret)[..4]` 派生——私有构建改标签即可
  消除开源指纹，且无凭据者无法用固定魔数判定载体存在性（头部槽位仅由
  参数集决定，与密码无关，这是设计要求；威胁模型见 WIRE_SPEC §13.11.2）。
- 仅开启 `features = ["stego"]`（不含 engine）即可使用本模块与
  `stego::io` 文件级接口；`strhide::stego::io::embed_carrier_file` 提供
  临时文件 + rename 原子提交、`.bak` 备份与时间戳保留，宿主无需自建 I/O。
- 文件级便捷入口（`StrHide::embed_file` / `extract_file`）在 `engine`
  特性下可用，内部委托同一 `stego::io` 实现。

---

## 4. 扩展点

- **自定义代价模型**：实现 `traits::PngCostModel` / `JpegCostModel`，
  经专家面域引擎入口以 `&dyn` 传入（见 `examples/stego_profile.rs`）。
  注意：PNG 提取端由载体头部（`FeatureWord.algorithm_id`）声明算法，
  统一入口不接受 trait 对象；自有模型请直接调用域引擎，并保证嵌入与
  提取传入同一模型实例。
- **容量探测前置嗅探**：`stego::sniff_carrier(bytes) -> CarrierFormat`
  （`Png / Jpeg / Heif / HevcAnnexB / Unsupported`），调用方可在嵌入前
  预判格式与路由。

---

## 5. CLI 映射（命令 → 库入口）

| 命令 | 库入口 | 说明 |
|---|---|---|
| `embed` | `embed_carrier_with_profile` | 日常层：`-t/-d/-p/-o/--in-place/-a/--safety/--enforce-safety`；专家层（Fine-Tuning Options 分组）：`--exclusion-rate/--neighbor-weight/--p1-window/--p2-window/--stc-h`；隐藏层（`hide = true`）：`--slot-budget/--cipher-suite`；`--dry-run` 全内存演练不落盘 |
| `extract` | `extract_carrier_with_profile` | 仅保留活参数：`--p1-window/--p2-window`（PNG 代价图重算必需）；`-a` 仅 `hevc/cabac` 影响路由；算法/排除率等由载体自描述 |
| `capacity` | `probe_carrier_capacity_with_profile` | 独立只读探测子命令（与 `embed --capacity` 同一实现），`--json` 输出 `StegoCapacityInfo`；与 embed 共享同一组调参/凭据参数 |
| `embed --capacity` | 同上 | 别名形式保留 |

提取端自描述范围（无需在提取时重复）：算法 id、排除率（`exclusion_permille`）、
codec、`h`、`u`、通道模式（PNG `FeatureWord`）；`h`/`u`、套件 id（JPEG 超块）。
**不自描述**、提取端必须重复：PNG 的 `--p1-window` / `--p2-window`、
凭据（secret/domain）、方言（Profile）。

---

## 6. 守卫

- `tests/cli_help_guard.rs`：localize（en/zh）后全命令树每个可见参数 help
  非空——stego 参数 help 的事实源在 i18n 消息表，条目缺失即测试失败。
- `hevc::engine::dialect_tests`：`DEFAULT_HEVC_FORMAT` 字面量与
  WIRE_SPEC §13.11 钉死；魔数随凭据变化；公开默认密钥唯一。
