# strhide stego 库使用者指南

> 适用版本：strhide 0.7.1（`rust/`），`stego` feature。
> 本文面向**以库形式使用内容域隐写（stego）模块**的开发者，逐一列出所有公开入口与参数，不含 CLI 使用说明（CLI 对照见 §14）。
> 参数审查发现的问题与不一致清单见 `docs/stego_params_consistency_audit_20261025.md`。

---

## 1. 概述

`stego` 模块是 strhide 的**内容域自适应隐写**实现：把载荷直接嵌进载体的感知内容（像素 / DCT 系数 / CABAC 旁路位），与结构域（`engine` 的容器附加写）完全解耦。

- 支持载体：PNG（空间域）、JPEG（DCT 域）、HEIF/HEIC 容器（HEVC Scheme C 或 JPEG/PNG 缩略图桥接）、裸 HEVC Annex-B 码流。
- 载荷全程 AES-256-GCM 认证加密；提取时密码错误与"无隐藏数据"返回同一种错误（`NoHiddenData` / `Password`），不给探测者任何 oracle。
- 需要在 `Cargo.toml` 中启用 feature：`stego`（默认已启用）。仅用 stego 时不需要 `engine` feature；`stego::io` 的文件级 API 也只依赖 `stego`。

三个格式引擎（PNG/JPEG/HEVC）的调参入口**并不对称**（详见 §10 与审查报告），使用前建议通读 §4–§9。

---

## 2. 快速开始：统一入口

统一入口自动嗅探载体格式并路由到对应引擎，位于 `strhide::stego`：

```rust
use strhide::stego::{embed_carrier, extract_carrier, probe_carrier_capacity, StegoOptions};

// 嵌入（内存到内存）
let stego_bytes: Vec<u8> = embed_carrier(&carrier_bytes, b"payload", &StegoOptions {
    password: Some("pw".into()),
    ..StegoOptions::default()
})?;

// 提取
let payload: Vec<u8> = extract_carrier(&stego_bytes, &StegoOptions {
    password: Some("pw".into()),
    ..StegoOptions::default()
})?;

// 容量探测
let info = probe_carrier_capacity(&carrier_bytes, &StegoOptions::default())?;
println!("{}", info.summary_string());
```

带私有方言（`Profile`）的版本：

```rust
use strhide::stego::{embed_carrier_with_profile, extract_carrier_with_profile, probe_carrier_capacity_with_profile};
use strhide::params::Profile;

const PROFILE: Profile = Profile::new().with_stego_secret("my-private-secret");
let out = embed_carrier_with_profile(&carrier, b"payload", &StegoOptions::default(), &PROFILE)?;
```

文件级便利 API（`strhide::stego::io`，原子提交 + 可选 `.bak` + 时间戳克隆）：

```rust
use strhide::stego::io::{embed_carrier_file, extract_carrier_file};

embed_carrier_file(
    std::path::Path::new("cover.png"),
    None,                       // None = 原地替换；Some(path) = 写到新文件
    b"payload",
    &StegoOptions::default(),
    &Profile::default(),
    true,                       // backup：原地写时保留 <carrier>.bak
)?;                             // 返回 Ok(Some(bak_path)) 或 Ok(None)

let payload = extract_carrier_file(
    std::path::Path::new("cover.png"),
    &StegoOptions::default(),
    &Profile::default(),
)?;
```

### 格式嗅探与路由规则

`strhide::stego::sniff` 提供与统一入口一致的判定：

```rust
use strhide::stego::sniff::{sniff_carrier, CarrierFormat};
let f = sniff_carrier(&bytes);
// CarrierFormat::{Png, Jpeg, Heif, HevcAnnexB, Unsupported}
// f.is_supported()、f.as_str()（"png"/"jpeg"/"heif"/"hevc"/"unsupported"）、Display
```

`embed_carrier_with_profile` 内部路由（顺序固定）：

| 判定 | 引擎 | 备注 |
|---|---|---|
| `\xFF\xD8` 开头 | `stego::jpeg` | 按 `algorithm` 查 JPEG cost model，查不到报错 |
| `\x89PNG\r\n\x1a\n` 开头 | `stego::png` | 按 `algorithm` 查空间域 cost model，查不到报错 |
| `crate::sniff::is_heif_bytes` | HEIF：`algorithm` 为 `"hevc"`/`"cabac"` 时强制 Scheme C；否则先试桥接（`heif::embed_heif_bridge`），失败回退 Scheme C | |
| `hevc::sniff::is_hevc_annexb` | `stego::hevc`（Scheme C） | `algorithm` 被忽略 |
| 其余 | `Err(UnsupportedFormat)` | |

`extract_carrier_with_profile` 的 HEIF 分支顺序相反：**先试 Scheme C，失败再试桥接**（若 `algorithm` 为 `"hevc"`/`"cabac"` 则只走 Scheme C）。提取 PNG/JPEG 分支**不查 `algorithm`**——载体自描述（JPEG V3 的槽集是几何的；PNG 的 feature word 记录了算法 id），拼错的算法名不会导致可读载体被拒绝。

---

## 3. `StegoOptions`（统一入口的全部参数）

```rust
#[derive(Debug, Clone, Default)]
pub struct StegoOptions {
    pub algorithm: Option<String>,        // 见 §3.1
    pub password: Option<String>,         // 见 §12
    pub domain: Option<String>,           // HKDF 域隔离标签
    pub safety: SafetyPolicy,             // 容量安全策略（§5）
    pub png_params: PngParams,            // 空间域调参（§6）
    pub jpeg_params: JpegParams,          // DCT 域调参（§7）
    pub extract_params: ExtractParams,    // 提取策略（§8）
    pub freshness: Freshness,             // salt/nonce 来源（§9）
}
```

builder 方法（链式）：`with_password`、`with_algorithm`、`with_domain`、`with_safety(level, enforcement)`、`with_freshness`、`with_png_params`、`with_jpeg_params`。

每次调用统一入口（embed / extract / probe）都会先执行 `png_params.validate()` 与 `jpeg_params.validate()`，非法组合在入口处报 `StrHideError::General`，不会进入引擎。

### 3.1 `algorithm` 的合法取值

| 值 | 域 | 说明 |
|---|---|---|
| `None` / `"auto"` | PNG→HILL；JPEG→UERD | 默认模型（依据 2025–2026 CNN 评测，HILL 优于 UNIWARD 族；UERD 性价比优于 J-UNIWARD） |
| `"hill"` | PNG | 高低低通内容自适应（Li et al., ICIP 2014） |
| `"suniward"` | PNG | S-UNIWARD（读 `algorithm_options["sigma"]`，默认 1.0） |
| `"uerd"` | JPEG | UERD（`neighbor_weight`；支持方向偏置/polarize） |
| `"juniward"` | JPEG | J-UNIWARD（读 `algorithm_options["sigma"]`，默认 1/64） |
| `"hevc"` / `"cabac"` | 仅 HEIF 分支 | 强制走 Scheme C，跳过桥接 |

对**裸 Annex-B HEVC**，`algorithm` 完全被忽略。未知名字在 embed/probe 的 PNG、JPEG、HEIF-bridge 分支报 `General("Unknown or incompatible … algorithm")`；extract 阶段一律忽略（见 §2 路由规则）。

### 3.2 `domain`

HKDF 域隔离标签：显式值优先，其次 `Profile::stego_domain()`，都为 `None`/空串时使用官方默认推导。读写必须同 `domain`，否则与密码错误不可区分。

---

## 4. 容量探测结果 `StegoCapacityInfo`

`probe_carrier_capacity*` 与各格式的 `probe_*` 返回：

```rust
pub struct StegoCapacityInfo {
    pub format: String,               // "PNG" / "JPEG" / "HEIF (JPEG Thumbnail Bridge)" / "HEIF/HEVC" / "HEVC-AnnexB"
    pub algorithm: String,            // "hill"/"suniward"/"uerd"/"juniward"/"HEVC-CABAC-InPlace"
    pub total_elements: usize,        // PNG=像素数；JPEG=luma 块数×64（系数总数）；HEVC=像素数（无 SPS 时为槽位数）
    pub available_slots: usize,       // 可用于载荷体的槽位数（已扣除 header 槽）
    pub max_raw_payload_bytes: usize, // 物理上限（不计安全层）
    pub max_raw_is_grouped: bool,     // true = 上限被"过度优化 Huffman 表"约束压到 u>=3 的分组界限（仅 JPEG）
    pub recommended_max_bytes: usize, // 按 safety tier 折算的建议上限
    pub estimated_change_rate: f64,   // 每 payload bit 的期望修改槽位数（Hamming k=3 ≈0.2917；STC u=3 ≈0.23）
    pub safety_level: String,         // 本探测使用的 tier 名
    pub safety_bpp_limit: f64,        // 本探测使用的 bpp 上限
}
impl StegoCapacityInfo {
    pub fn fits_recommended(&self, payload_len: usize) -> bool;
    pub fn fits_max(&self, payload_len: usize) -> bool;
    pub fn summary_string(&self) -> String;
}
```

注意语义差异：`safety_bpp_limit` 名义上是 bits/pixel，但 JPEG 侧按 `total_elements`（luma 系数）计。PNG 的容量**依赖凭据**（512 个 header/feature 槽由 `password + domain` 的置换决定并从 body 池扣除），JPEG 的容量与凭据无关，HEVC 的容量与凭据无关（槽位由码流决定）。

---

## 5. 容量安全：`SafetyPolicy` / `SafetyLevel` / `SafetyEnforcement`

```rust
pub struct SafetyPolicy { pub level: SafetyLevel, pub enforcement: SafetyEnforcement }
// 默认：High / Advisory；SafetyPolicy::new() 为官方默认

pub enum SafetyLevel { Paranoid, High /*default*/, Balanced }
// bpp 上限：0.06 / 0.10 / 0.15；目标槽位比 r = slots/bits：11.5 / 6.9 / 4.6
// SafetyLevel::parse("high")            -> Option（大小写不敏感，仅名字）
// "high".parse::<SafetyLevel>()         -> Result（额外接受数字别名 "0"/"1"/"2"）
// as_str() -> "paranoid"|"high"|"balanced"；bpp_limit()、target_ratio()

pub enum SafetyEnforcement { Advisory /*default*/, Enforced }
// Advisory：超出建议容量仅告警；Enforced：直接拒绝（错误含实际 bpp 与阈值）
```

**适用范围（重要）**：`Enforced` 只在 PNG / JPEG 引擎内生效（`embed_png`、`embed_jpeg` 检查后拒绝）。**`embed_hevc` 没有 safety 参数，Enforced 对 HEVC/HEIF(Scheme C) 载体不生效**；统一入口的 HEIF 分支也不会替你检查。需要硬约束时，请在调用前用 `probe_hevc_capacity_info`（含 `SafetyLevel`）自行比对 `recommended_max_bytes`。CLI 的 `--enforce-safety` 同样只约束 PNG/JPEG。

---

## 6. `PngParams`（空间域 / PNG 全部参数）

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PngParams {
    /// 第一级低通窗口（奇数，默认 3；校验 1..=63 且为奇）
    pub p1_window: usize,
    /// 第二级低通窗口（奇数，默认 15；校验同上）
    pub p2_window: usize,
    /// 数值 epsilon（默认 f32::EPSILON = 2^-23）。
    /// 有效线格式只有 2^-k（k∈1..=127）：embed/probe 一律先经 wire_quantized()
    /// 就近取 2 的幂。validate 只要求有限正数；>= 1.0 会被静默降为 0.5，
    /// 建议显式取 2 的幂。
    pub epsilon: f64,
    /// 最平滑像素的排除比例（文档范围 0.0..=0.9，默认 0.30）。
    /// validate 不检查；引擎内静默 clamp(0.0, 0.9)。建议自行保证范围。
    pub exclusion_percentile: f64,
    /// 矩阵编码层，默认 Auto（STC 自适应 u）。注意：不是 Hamming。
    #[serde(default)]
    pub codec: StegoCodec,
    /// STC 约束高度 h（codec 为 Stc/Auto 时校验 4..=10，默认 8）
    #[serde(default = "default_stc_h")]
    pub stc_h: u8,
    /// STC 组大小 u：0 = auto（默认）；2/3 = 每 u 槽 1 bit。
    /// 校验：非 0 时须 1..=MAX 且 u <= stc_h。
    #[serde(default = "default_stc_u")]   // 0
    pub stc_u: u8,
    /// 非 HILL 模型的标量旋钮袋（键值均可扩展，未知键被忽略）。
    /// 已知键："sigma"（S-UNIWARD 用，默认 1.0；写入载体时按 f32 量化）。
    #[serde(default)]
    pub algorithm_options: BTreeMap<String, f64>,
}
```

辅助方法：

- `PngParams::validate()`：窗口为正奇数且 ≤63；epsilon 有限且 >0；Stc/Auto 时校验 `stc_h`（4..=10）与 `stc_u`（非 0 时 ≤ h）；`algorithm_options` 键非空、值有限。
- `PngParams::wire_quantized() -> Self`：把 epsilon 量化为 2^-k、sigma 量化为 f32 精度。embed/probe 自动执行；需要手工对齐两侧计算时可直接调用。
- `model_option(key, default) -> f64`：读模型私有旋钮。

`StegoCodec`：

```rust
pub enum StegoCodec { Auto /*default*/, Hamming, Stc }
// Auto：按可用槽位/载荷位之比自适应选 STC 的 u（u=3 / u=2 / u=1）。
//       Hamming(7,3)：固定 7 槽 3 bit，至多改 1 槽（~0.2917 改动/bit）。
// Stc：显式 STC，u 取 stc_u（0 = auto）。
// 线格式：id() -> Hamming=0，Stc/Auto=1（wire 上不存在 Auto；载体记录的是
// 实际选定的 u，提取端从 feature word 读回）。
// from_id(id)、describe(stc_h, stc_u) 供诊断。
```

线格式约束（可写进载体的取值）：`p1_window`/`p2_window` ≤ 1023（10 bit 字段）；`epsilon` 仅 2^-k；`exclusion_percentile` 以千分数记录（`exclusion_permille`）；`sigma` 以 f32 记录。超界值经量化/clamp 后写入，读取端以载体记录为准（提取时会用 feature word 中的值**覆盖**调用方传入的对应参数）。

---

## 7. `JpegParams`（DCT 域 / JPEG 全部参数）

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JpegParams {
    /// UERD 8-邻域块能量权重（默认 0.25；校验有限且 >= 0）
    pub neighbor_weight: f64,
    /// 不可修改系数的代价（默认 1e13；校验有限且 > 0）
    pub wet_cost: f64,
    /// STC 约束高度 h，写入 superblock（默认 8；校验 4..=10）
    #[serde(default = "default_stc_h")]
    pub stc_h: u8,
    /// trellis 预算（槽位数）。None = 自动（默认）：body 槽的 1/4，
    /// 下限 DEFAULT_SLOT_BUDGET(1.2M)，上限按 MAX_AUTO_BACKTRACK_BYTES 换算。
    /// Some(v) = 显式值（即使恰好等于默认值也按显式处理）；校验 >= 8。
    /// 仅影响嵌入侧搜索；线格式无关（提取端信任 superblock 中的 u）。
    #[serde(default)]
    pub slot_budget: Option<usize>,
    /// 写入 superblock 的密码套件 id（默认 DEFAULT_SUITE_ID=1；校验非 0；
    /// embed 时要求该 id 在 fmt.suites 内，否则报 UnsupportedVersion）
    #[serde(default = "default_cipher_suite")]
    pub cipher_suite: u16,
    /// 方向偏置折扣（默认 1.0 = 关闭；有效 (0,1]，>1 被拒绝）。
    /// <1 时引擎用 UERD 的 direction_bias() 给"更不可见方向"打折（如 hstego 用 0.65）。
    #[serde(default = "default_polarize_weight")]
    pub polarize_weight: f64,
    /// 写入扩展 TLV 区的记录（默认空）。类型 strhide::stego::jpeg::header_v3::Tlv
    /// { type_id: u8 /*bit7=critical*/, value: Vec<u8> /*<=255B*/ }。
    /// type 0 保留为 padding。每个 TLV 使 header 多占 ext_u*(8*len+h-1) 槽。
    #[serde(default)]
    pub extensions: Vec<Tlv>,
    /// 非 UERD 的 JPEG 模型标量旋钮袋。已知键："sigma"（J-UNIWARD，默认 1/64）。
    #[serde(default)]
    pub algorithm_options: BTreeMap<String, f64>,
    /// 强制标量 kernel（禁 AVX2/FMA），保证逐位可复现。
    /// 统一入口在 Freshness::Seeded 时自动置 true；直接调 embed_jpeg 需自行设置。
    #[serde(skip)] #[doc(hidden)]
    pub deterministic: bool,
}
```

相关常量与函数（`strhide::stego::params`）：

```rust
pub const DEFAULT_SLOT_BUDGET: usize = 1_200_000;   // 自动预算下限
pub const MAX_AUTO_BACKTRACK_BYTES: usize = 4 << 30; // 自动预算内存上限（4 GiB）
pub const MAX_GROUPED_BACKTRACK_BYTES: usize = 4 << 30; // 正确性驱动预算上限（4 GiB）
pub fn max_grouped_backtrack_slots(h: u8) -> usize;  // 该上限在高度 h 下折合的槽位数
pub fn grouped_body_budget(body_slots, bits, h, auto_budget) -> Option<usize>;
// 过度优化 Huffman 表的载体上，把预算抬到 u>=3 或返回 None（要求拒绝嵌入）
```

辅助方法：`validate()`（见上）、`model_option(key, default)`、`effective_slot_budget(body_slots) -> usize`（解析 None 的自动预算）。

---

## 8. `ExtractParams`（提取策略）

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractParams {
    /// 允许尝试的密码套件 id（升序）。None = 该 profile 的全部套件。
    pub allowed_suites: Option<Vec<u16>>,
    /// 单次尝试允许执行的 PBKDF2 最大迭代数（防伪造 suite_id 的 DoS）。
    /// 默认 MAX_PBKDF2_ITERATIONS = 2_000_000。
    pub max_pbkdf2_iterations: u32,
}
impl ExtractParams {
    pub fn allows_suite(&self, suite_id: u16) -> bool;
}
```

只影响提取开销与套件白名单，不影响载体的可读性：策略不同的两个提取器读同一个载体结果一致。当前仅 JPEG V3 提取使用它（PNG/HEVC 的提取不经套件枚举）。

---

## 9. `Freshness`（salt/nonce 来源）

```rust
pub enum Freshness {
    Random,          // 默认：每次从 OS 取随机 salt(16B)/nonce(12B)
    Seeded([u8; 32]),// 可复现：由 seed + SHA-256(cover)||SHA-256(payload) 绑定推导
}
impl Freshness {
    pub fn is_seeded(&self) -> bool;
    pub fn seeded_binding(carrier: &[u8], payload: &[u8]) -> [u8; 64];
    pub fn salt(&self, attempt: u32, binding: &[u8]) -> [u8; SALT_LEN];    // 16
    pub fn nonce(&self, attempt: u32, binding: &[u8]) -> [u8; NONCE_LEN];  // 12
}
```

- `Seeded` 使同一 (载体, 载荷, 凭据, seed) 产出**逐字节相同**的 stego 文件（限同一 git 修订与 target triple；JPEG 需标量 kernel，统一入口已自动处理 `jpeg_params.deterministic`）。
- 绑定上下文保证不同输入永不复用 (key, nonce) 对（防 AES-GCM 两time pad）。
- JPEG 的 Huffman 重试（最多 6 次）以 `attempt` 区分，整个重试序列可复现。

---

## 10. 密码与凭据解析（三种格式共用）

统一入口按以下优先级解析凭据（`StegoOptions::secret(&Profile)` / `domain(&Profile)`）：

1. `options.password`（**空字符串视为未提供**，不会屏蔽 profile secret）；
2. `profile.stego_secret()`（私有方言的无密码秘密）；
3. `None` → 引擎内部用官方公共常量（PNG 的 `OFFICIAL_PNG_FORMAT.fallback_secret`；JPEG V3 的 `PUBLIC_DEFAULT_SECRET`；HEVC 的推导分支）。

解析结果以 `password: Option<&str>`（JPEG/PNG）或 `secret: Option<&str>`（HEVC）传入专家入口。**读写必须同源**：私有秘密与官方常量互不可读，失败统一表现为 `NoHiddenData`/`Password`，与密码错误不可区分。

---

## 11. 私有方言：`Profile` 与线格式 profile

`strhide::params::Profile`（结构域与内容域共用的方言对象）：

```rust
impl Profile {
    pub const fn with_stego_secret(self, secret: &'static str) -> Self; // 内容域无密码秘密
    pub const fn with_stego_domain(self, domain: &'static str) -> Self; // 内容域 HKDF 域
    pub const fn with_jpeg_format(self, format: JpegFormatProfile) -> Self;
    pub const fn with_png_format(self, png: PngFormatProfile) -> Self;
    pub const fn with_hevc_format(self, hevc: HevcFormatProfile) -> Self;
    // 读取：stego_secret() / stego_domain() / jpeg_format() / png_format() / hevc_format()
}
```

三个线格式 profile 都是 `Copy` 值类型，改任一字段即产生**互不可读的新格式**：

### 11.1 `JpegFormatProfile`（JPEG V3）

```rust
pub struct JpegFormatProfile {
    pub format_major: u8,            // 默认 1
    pub format_minor: u8,            // 默认 0
    pub cover_digest_tag: &'static [u8], // header 定位 KDF 盐标签
    pub hpos_label: &'static [u8],   // header 置换种子 HKDF info
    pub stc_label:  &'static [u8],   // body trellis 种子 HKDF info
    pub enc_label:  &'static [u8],   // AEAD key HKDF info
    pub perm_label: &'static [u8],   // body 置换种子 HKDF info
    pub sb_bytes: u8,                // superblock 字节数（44）
    pub sb_h: u8, pub sb_u: u8,      // superblock trellis（8 / 2）
    pub ext_h: u8, pub ext_u: u8,    // 扩展区 trellis（8 / 4）
    pub grid_rule: GridRule,         // 槽网格（默认全部 AC：k∈1..=63）
    pub suites: &'static [CipherSuite],
}
// 方法：superblock_bits()=352、superblock_slots()=718、
//       extension_slots(ext_bytes)、header_slots(ext_bytes)、
//       suite(id)、default_suite()、validate()（几何自洽性全查）
pub const DEFAULT_JPEG_FORMAT: JpegFormatProfile;
```

`GridRule { k_min: u8, k_max: u8 }`，`GridRule::ALL_AC = {1,63}`；`slots_per_block()`。**k_min 必须 ≥1**（DC 是 header 定位 KDF 的盐，永不参与嵌入）。

### 11.2 `PngFormatProfile`（空间域）

```rust
pub struct PngFormatProfile {
    pub fallback_secret: &'static str, // 无凭据时的替身秘密
    pub domain_label: &'static [u8],   // 域子键 HKDF info
    pub hpos_salt: &'static [u8],      // header 置换种子 HKDF salt
    pub hpos_label: &'static [u8],     // header 置换种子 HKDF info
    pub stc_label: &'static [u8],      // body trellis 种子 HKDF info
    pub body: &'static JpegFormatProfile, // 套件与 body 密钥派生沿用 JPEG 表
}
pub const OFFICIAL_PNG_FORMAT: PngFormatProfile;
```

### 11.3 `HevcFormatProfile`（Scheme C）

```rust
pub struct HevcFormatProfile {
    pub magic_label: &'static [u8], // 4B header magic 派生标签
    pub cover_salt:  &'static [u8], // cover digest 盐（参数集哈希前缀）
    pub kdf_info:    &'static [u8], // AES-256-GCM key HKDF info
    pub stc_h: u8,                  // trellis 高度（默认 7）
    pub stc_u: u8,                  // 组大小（默认 2）
    pub header_bytes: usize,        // 固定前缀预算（默认 40；>=24）
}
pub const DEFAULT_HEVC_FORMAT: HevcFormatProfile;
```

HEVC 的 `stc_h/stc_u` **只能经 profile 改**（无运行时参数结构）。读写两侧必须一致（header 不携带它们）。

### 11.4 密码套件 `CipherSuite`

```rust
pub struct CipherSuite { pub id: u16, pub name: &'static str, pub kdf: Kdf, pub aead: Aead }
// salt_len()=16、nonce_len()=12、tag_len()=16、cost()=PBKDF2 迭代数
pub const SUITE_PBKDF2_200K: CipherSuite;  // id=1（默认）
pub const SUITE_PBKDF2_600K: CipherSuite;  // id=2
pub const RESERVED_SUITE_ARGON2ID: u16 = 3; // 保留未实现
pub const SUITES: &[CipherSuite];           // [1, 2]
pub const DEFAULT_SUITE_ID: u16 = 1;
pub const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000; // 解码侧迭代上限
// Kdf::Pbkdf2HmacSha256 { iterations: u32 }；Aead::Aes256Gcm
```

---

## 12. 专家入口：直接调用各格式引擎

统一入口之外，私有构建可跳过嗅探直呼引擎（`embed_carrier` 内部正是这样路由的）。

### 12.1 PNG（`strhide::stego::png::engine`）

```rust
pub fn embed_png(
    carrier_bytes: &[u8], payload: &[u8],
    password: Option<&str>, domain: Option<&str>,
    spatial: &PngFormatProfile,
    cost_model: &dyn PngCostModel,     // 先 CostModelRegistry::get_spatial_model(..)?
    params: &PngParams, safety: SafetyPolicy, freshness: Freshness,
) -> Result<Vec<u8>, StrHideError>;

pub fn extract_png(
    carrier_bytes: &[u8],
    password: Option<&str>, domain: Option<&str>,
    spatial: &PngFormatProfile,
    cost_model: &dyn PngCostModel,     // 仅作提示：载体 feature word 声明的模型优先
    params: &PngParams,                // 过滤窗口/epsilon 等会被载体记录值覆盖
) -> Result<Vec<u8>, StrHideError>;

pub fn probe_png_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn PngCostModel, params: &PngParams,
    safety_level: SafetyLevel,
    password: Option<&str>, domain: Option<&str>,  // 影响 512 header 槽的分配
    spatial: &PngFormatProfile,
) -> Result<StegoCapacityInfo, StrHideError>;
```

工具函数（同模块）：`decode_png(&[u8]) -> RawImage`、`encode_png(&RawImage) -> Vec<u8>`、常量 `SPATIAL_ELIGIBLE_MIN=8` / `SPATIAL_ELIGIBLE_MAX=247`、`ChannelMode::{Green, Rgb}`（嵌入通道模式由 embedder 按容量选择并记入 feature word，Alpha 永不触碰）。`RawImage { width, height, channels, pixels, chunks, idat_sizes, row_filters, idat_info }` 保留全部 ancillary chunk 与行滤镜；不支持交错（Adam7）与 16-bit。

PNG 嵌入结构：256 槽 32B 基础 header（salt16|nonce12|长度字）+ 256 槽 32B feature word（`FeatureWord`：version/codec/u/h/channel_mode/class_rule/p1/p2/neg_log2_epsilon/exclusion_permille/algorithm_id/sigma/kernel_id）。class rule 固定为 safe `[1,6]`（值类内移动，永不越 0/255）。

### 12.2 JPEG（`strhide::stego::jpeg::engine`）

```rust
pub fn embed_jpeg(
    carrier_bytes: &[u8], payload: &[u8],
    password: Option<&str>, domain: Option<&str>,
    fmt: &JpegFormatProfile,
    params: &JpegParams, safety: SafetyPolicy,
    cost_model: &dyn JpegCostModel,    // CostModelRegistry::get_jpeg_model(..)?
    freshness: Freshness,
) -> Result<Vec<u8>, StrHideError>;    // Huffman 重试最多 6 次（fresh salt）

pub fn extract_jpeg(
    carrier_bytes: &[u8],
    password: Option<&str>, domain: Option<&str>,
    fmt: &JpegFormatProfile,
    extract: &ExtractParams,           // 套件枚举与 PBKDF2 上限
) -> Result<Vec<u8>, StrHideError>;    // 无 cost model 参数：提取不用代价图

pub fn probe_jpeg_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn JpegCostModel,    // 仅提供 info.algorithm 名字
    params: &JpegParams, safety_level: SafetyLevel, fmt: &JpegFormatProfile,
) -> Result<StegoCapacityInfo, StrHideError>;

pub fn layout_for_payload(             // 诊断：给定载荷的 u / body_n 布局
    carrier_bytes: &[u8], payload_len: usize,
    params: &JpegParams, fmt: &JpegFormatProfile,
) -> Result<Layout, StrHideError>;
```

嵌入结构：44B superblock（718 槽）+ TLV 扩展区 + body 几何网格（`grid_rule`）。载体 Huffman 表过度优化时自动抬预算到 u≥3（`grouped_body_budget`），装不下则明确报错并建议重存为标准表。

### 12.3 HEVC Scheme C（`strhide::stego::hevc`）

```rust
pub fn embed_hevc(
    carrier: &[u8], payload: &[u8],              // payload 不得为空
    secret: Option<&str>, domain: Option<&str>,
    fmt: &HevcFormatProfile, freshness: Freshness,
) -> Result<Vec<u8>, StrHideError>;              // 注意：无 safety 参数

pub fn extract_hevc(
    carrier: &[u8], secret: Option<&str>, domain: Option<&str>,
    fmt: &HevcFormatProfile,
) -> Result<Vec<u8>, StrHideError>;

pub fn probe_hevc_capacity(carrier: &[u8], fmt: &HevcFormatProfile)
    -> Result<usize, StrHideError>;              // 最大可嵌字节数（原始值）

pub fn probe_hevc_capacity_info(
    carrier: &[u8], fmt: &HevcFormatProfile, safety_level: SafetyLevel,
) -> Result<StegoCapacityInfo, StrHideError>;    // 结构化容量

pub fn extract_hevc_dimensions(carrier: &[u8]) -> Result<(u32, u32), StrHideError>;
```

载体形态：HEIF/HEIC 容器或裸 Annex-B；**MP4/MOV 明确报不支持**（提示 remux）。线上消息：magic4 | len4 | crc4 | nonce12 | ciphertext(+16B tag)，总开销 40B（`header_bytes` 默认值）。修改只落在 CABAC 旁路符号位（零码率膨胀）；位流重编码后提取。HEVC 特有错误见 `strhide::stego::hevc::error::HevcError`（Truncated / InvalidData / Unsupported / MissingParameterSet / TooLarge / NoSlices / ContainerMalformed / …）。

### 12.4 HEIF 桥接（`strhide::stego::heif`）

```rust
pub enum BridgeTargetKind {
    DirectJpeg { item_id: u32 },       // item_type == "jpeg"
    DirectSpatial { item_id: u32 },    // item_type == "unci"（未压缩空间项）
    ExifJpeg { exif_item_id: u32, tag_0202_file_offset: Option<usize>, is_little_endian: bool },
    ContainerJpegFallback,             // 容器级 JPEG 回退
}
pub struct BridgeTarget { pub kind: BridgeTargetKind, pub file_offset: usize, pub length: usize }

pub fn find_bridge_target(data: &[u8]) -> Result<BridgeTarget, StrHideError>; // 缩略图(iref thmb)优先；绝不改主图
pub fn embed_heif_bridge(carrier_bytes: &[u8], payload: &[u8],
                         options: &StegoOptions, profile: &Profile) -> Result<Vec<u8>, StrHideError>;
pub fn extract_heif_bridge(carrier_bytes: &[u8], options: &StegoOptions, profile: &Profile)
    -> Result<Vec<u8>, StrHideError>;
pub fn probe_heif_bridge_capacity(carrier_bytes: &[u8], options: &StegoOptions, profile: &Profile)
    -> Result<StegoCapacityInfo, StrHideError>;  // info.format = "HEIF (JPEG Thumbnail Bridge)"
```

桥接把 HEIF 内嵌的 JPEG/未压缩项交给 §12.1/§12.2 引擎处理，参数即 `StegoOptions` 全集；主 HEVC/AVIF 照片流保持逐位不变。

---

## 13. 成本模型与注册表（扩展点）

```rust
use strhide::stego::traits::{PngCostModel, JpegCostModel};

pub trait PngCostModel: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn compute_cost(&self, pixels: &[u8], width: usize, height: usize,
                    channels: usize, params: &PngParams) -> Vec<f64>;
    // 方向代价（默认对称 = base）；槽排序永远用 base，方向只影响块内 +1/-1 选择
    fn direction_costs(&self, base: &[f64], pixels: &[u8], width: usize, height: usize,
                       channels: usize, channel: usize, slots: &[usize]) -> (Vec<f64>, Vec<f64>);
}

pub trait JpegCostModel: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn compute_cost(&self, coeffs: &dct_io::JpegCoefficients,
                    geometry: &JpegGeometry, params: &JpegParams) -> Vec<f64>;
    // 三值方向偏置（Some: +1/-1/0 per 系数），配合 JpegParams::polarize_weight；
    // 仅嵌入侧使用。UERD 实现；J-UNIWARD 未实现（返回 None）。
    fn direction_bias(&self, coeffs: &dct_io::JpegCoefficients,
                      geometry: &JpegGeometry, params: &JpegParams) -> Option<Vec<i8>>;
}

pub struct JpegGeometry {   // dct-io 的 MCU 交错块序 -> (row, col) 映射
    pub grid_w: usize, pub grid_h: usize,
    pub positions: Vec<(usize, usize)>,
    pub luma_q: [u16; 64],  // 文件自己的亮度量化表（缺省回退 Annex K）
}
```

内置模型（`strhide::stego::png::cost::{HillCostModel, SuniwardCostModel}`、`strhide::stego::jpeg::cost::{UerdCostModel, JuniwardCostModel}`；`UerdCostModel` 同时在 crate 根 re-export）。

注册表（`strhide::stego::registry::CostModelRegistry`）：

```rust
get_spatial_model(Option<&str>) -> Option<Arc<dyn PngCostModel>>  // None/"auto"/"hill" -> HILL；"suniward"
get_jpeg_model(Option<&str>)    -> Option<Arc<dyn JpegCostModel>> // None/"auto"/"uerd" -> UERD；"juniward"
spatial_wire_id(&str) -> Option<u8>            // "hill"=1（SPATIAL_ALGORITHM_HILL）、"suniward"=2
spatial_name_from_wire_id(u8) -> Option<&'static str>
spatial_model_from_wire_id(u8) -> Option<Arc<dyn PngCostModel>>   // 未知 id 不回退默认
list_algorithms() -> Vec<(&'static str, &'static str, &'static str)> // name, 域, 描述（含 "hevc" 条目）
```

自定义 PNG 模型：新模型要有永久 wire id（加入 `spatial_wire_id` 与 `list_algorithms`）；`PngParams.algorithm_options` 供其声明私有旋钮（无需改参数结构体）。自定义 JPEG 模型无需 wire id（提取不依赖模型）。

---

## 14. CLI 与库参数对照

| 库参数 | CLI | 备注 |
|---|---|---|
| `StegoOptions.password` | `--password`（`embed`/`capacity`/`extract` 等） | |
| `algorithm` | `--algorithm` / `-a` | |
| `safety.level` | `--safety` | `paranoid`/`high`/`balanced`（CLI 解析同 `FromStr`） |
| `safety.enforcement` | `--enforce-safety` | 仅对 PNG/JPEG 生效（见 §5） |
| `png_params.exclusion_percentile` | `--exclusion-rate` | 注意 CLI 名字是 rate |
| `png_params.p1_window` / `p2_window` | `--p1-window` / `--p2-window` | |
| `stc_h`（png+jpeg 同时设置） | `--stc-h` | CLI 无 `--stc-u`/`--codec` |
| `jpeg_params.neighbor_weight` | `--neighbor-weight` | |
| `jpeg_params.slot_budget` | `--slot-budget`（hidden） | |
| `jpeg_params.cipher_suite` | `--cipher-suite`（hidden） | |
| `domain` | **无 CLI 对应** | 只能经编译期 `Profile` |
| `png_params.codec` / `stc_u` / `epsilon` | 无 CLI 对应 | |
| `jpeg_params.wet_cost` / `polarize_weight` / `extensions` | 无 CLI 对应 | |
| `extract_params` | 无 CLI 对应 | |
| `Freshness::Seeded` | 无 CLI 对应 | 用 `examples/repro_embed.rs` |

---

## 15. 错误类型速查（`strhide::errors::StrHideError`）

| 变体 | 出现场景 |
|---|---|
| `NoHiddenData` | 提取端：无载荷 / 密码错 / 方言不匹配 / 算法 id 未知——**全部同型，无 oracle** |
| `Password` | HEIF 分支中 Scheme C 认证失败（提取端据此优先采纳该判定） |
| `UnsupportedFormat` | 非 PNG/JPEG/HEIF/Annex-B 载体；交错 PNG；MP4/MOV HEVC |
| `UnsupportedVersion` | 套件 id 未实现；PBKDF2 迭代越界；`header_bytes` 过小 |
| `CorruptedData` | 线格式字段非法（feature word 版本、未知矩阵编码 id 等） |
| `General` | 参数校验失败、容量不足、安全阈值拒绝（Enforced）、JPEG Huffman 编码失败等 |

---

## 16. 常用配方

### 可复现嵌入（回归测试 / bug 复现）

```rust
use strhide::stego::{Freshness, StegoOptions, embed_carrier};
let seed = [7u8; 32];
let opts = StegoOptions::default()
    .with_password("pw").with_freshness(Freshness::Seeded(seed));
let a = embed_carrier(&cover, b"payload", &opts)?;
let b = embed_carrier(&cover, b"payload", &opts)?;
assert_eq!(a, b);
```

### 私有方言（官方二进制读不了）

```rust
use strhide::params::Profile;
use strhide::stego::{embed_carrier_with_profile, extract_carrier_with_profile, StegoOptions};

const P: Profile = Profile::new()
    .with_stego_secret("only-us-know")
    .with_stego_domain("team-x");
let stego = embed_carrier_with_profile(&cover, b"msg", &StegoOptions::default(), &P)?;
let msg   = extract_carrier_with_profile(&stego, &StegoOptions::default(), &P)?;
```

### 自定义 J-UNIWARD + 方向偏置 + 强制安全

```rust
use strhide::stego::{JpegParams, SafetyEnforcement, SafetyLevel, StegoOptions, embed_carrier};
let mut jp = JpegParams::default();
jp.algorithm_options.insert("sigma".into(), 1.0 / 64.0);
jp.polarize_weight = 0.65;
let opts = StegoOptions::default()
    .with_password("pw").with_algorithm("juniward").with_jpeg_params(jp)
    .with_safety(SafetyLevel::High, SafetyEnforcement::Enforced);
let out = embed_carrier(&cover_jpeg, b"msg", &opts)?;
```

### 容量预算

```rust
use strhide::stego::{SafetyLevel, StegoOptions, probe_carrier_capacity};
let info = probe_carrier_capacity(&cover, &StegoOptions::default().with_password("pw"))?;
if !info.fits_recommended(payload.len()) { /* 换更大载体或更低 tier */ }
```

更多端到端示例见 `rust/examples/`：`repro_embed.rs`（可复现）、`stego_profile.rs`（专家入口直调 + 全算法对比）、`private_profile.rs`（方言）、`in_memory.rs`（结构域字节 API）。

---

## 17. 已知陷阱清单

1. **HEVC 不吃 `SafetyEnforcement::Enforced`**（§5）——需自行用 `probe_hevc_capacity_info` 把关。
2. **PNG 探测容量依赖凭据**：`probe_png_capacity`（及统一入口对 PNG 的探测）必须传与 embed 相同的 `password`/`domain`，否则报出的容量不可达。
3. **提取时 PNG/JPEG 不看 `algorithm`**：传错算法名不影响提取（载体自描述）；但 embed/probe 会因未知名字直接报错。
4. **`epsilon` 请用 2 的幂**（或接受就近量化）；`exclusion_percentile` 请自行保证 0.0..=0.9（越界被静默 clamp，不报错）。
5. **JPEG 载荷上限**：envelope 上限 64 MiB（`MAX_PLAINTEXT_LEN = 1<<26`）；Huffman 受限载体由引擎自动抬预算/重试/拒绝，`max_raw_is_grouped=true` 时 `max_raw_payload_bytes` 才是真实上限。
6. **profile 是编译期常量**：`with_stego_secret` 等接受 `&'static str`；运行期字符串需泄漏或用 `Profile::default()` 之外的构造方式（见 `strhide::params` 文档）。
7. **同密码同载体重嵌不可复现**：默认 `Freshness::Random`；需要逐位一致请用 `Seeded`（§16）。
