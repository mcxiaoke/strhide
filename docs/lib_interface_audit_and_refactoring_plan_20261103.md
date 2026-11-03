# strhide 库级接口审计与重构方案报告

> 日期：2026-11-03  
> 适用版本：strhide 0.8.x（开发中，未正式发布）  
> 涉及模块：`rust/src/{lib.rs, facade.rs, stego/*, structure/*, core/*}`  
> 性质：内部技术审计与架构改进规划

---

## 1. 背景与问题定义

第三方项目（如 CarrotHash 等私有方言构建方）在接入 `strhide` 扩展音频隐写能力时，遇到了如下定义约束：

```rust
pub const CARROT_AUDIO_BODY_FORMAT: JpegFormatProfile = JpegFormatProfile {
    format_major: 1,
    format_minor: 0,
    cover_digest_tag: b"carrot-audio-cover-v1",
    hpos_label: b"carrot-audio-hpos",
    stc_label: b"carrot-audio-stc-v1",
    enc_label: b"carrot-audio-enc-v1",
    perm_label: b"carrot-audio-perm-v1",
    sb_bytes: 44,                 // JPEG 超块尺寸（音频不使用）
    sb_h: 8,                      // JPEG STC 约束高度（音频不使用）
    sb_u: 2,                      // JPEG STC 分组宽度（音频不使用）
    ext_h: 8,                     // JPEG 扩展区约束高度（音频不使用）
    ext_u: 4,                     // JPEG 扩展区分组宽度（音频不使用）
    grid_rule: GridRule::ALL_AC,  // JPEG AC 变换域频带（音频不使用）
    suites: SUITES,
};
```

下游开发者对“为什么配置音频隐写载荷格式必须实例化一个类型为 `JpegFormatProfile` 的结构体，并填写 JPEG 专有的 DCT 几何字段”提出了疑问。

本报告对该技术问题进行溯源定位，并以此为契机，对整个 `strhide` Rust 库的公开接口（Public API）、导出符号、数据结构与参数命名进行系统核对与技术审计。

---

## 2. 音频绑定 `JpegFormatProfile` 的代码核对与根本原因

### 2.1 代码核对实证

审查 `rust/src/stego/format.rs`（第 460-526 行）：

```rust
pub struct AudioFormatProfile {
    pub fallback_secret: &'static str,
    pub domain_label: &'static [u8],
    pub hpos_salt: &'static [u8],
    pub hpos_label: &'static [u8],
    pub stc_label: &'static [u8],
    /// Suite list and body key/permutation labels.
    pub body: &'static JpegFormatProfile,
}
```

同模块中，PNG 空间域的定义（第 434-447 行）同样将 `body` 类型声明为 `&'static JpegFormatProfile`。

而在音频引擎实际执行嵌入与提取的代码中（`rust/src/stego/audio/core.rs` 第 546-551 行与第 804-810 行）：

```rust
let suite = profile.body.default_suite();
let (enc_key, perm_seed) = body_keys(profile.body, &master, &salt, domain);
```

以及 `rust/src/stego/format.rs` 中 `body_keys` 的实现（第 598-614 行）：

```rust
pub fn body_keys(
    fmt: &JpegFormatProfile,
    master: &[u8; 32],
    salt: &[u8],
    domain: Option<&str>,
) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let enc_info = info_with_domain(fmt.enc_label, domain);
    let perm_info = info_with_domain(fmt.perm_label, domain);
    let mut enc_key = [0u8; 32];
    let mut perm_seed = [0u8; 32];
    hk.expand(&enc_info, &mut enc_key).expect("HKDF expand payload key");
    hk.expand(&perm_info, &mut perm_seed).expect("HKDF expand permutation seed");
    (enc_key, perm_seed)
}
```

经静态核对：
1. 音频引擎对 `profile.body` **仅使用两个逻辑元素**：
   - `profile.body.suites`（密码套件列表，用于通过 `default_suite()` 读取默认 AEAD/KDF 算法与迭代次数）；
   - `profile.body.enc_label` 和 `profile.body.perm_label`（供 `body_keys` 进行 HKDF 派生，获取载荷对称密钥与置换种子）。
2. `JpegFormatProfile` 中的其余 8 个字段：
   - `sb_bytes`、`sb_h`、`sb_u`（JPEG 44 字节超块几何）；
   - `ext_h`、`ext_u`（JPEG 扩展区 STC 几何）；
   - `grid_rule`（JPEG AC 系数频带约束）；
   - `cover_digest_tag`、`hpos_label`（JPEG 头部特征定位标签）；
   在音频引擎及 PNG 空间域引擎中**均完全未被读取**。

### 2.2 根本原因

1. **历史演进包袱**：V3 版本的通用线格式（HKDF 密钥派生 + AEAD 密码套件 + STC 矩阵嵌入）最早在 JPEG 引擎上成型，当时承载这些密码学标签的结构体直接被命名为 `JpegFormatProfile`。
2. **通用密码层与载体几何层强耦合**：`JpegFormatProfile` 同时承担了“载荷密码套件与派生标签”（通用机制）与“JPEG 超块/AC 系数网格”（特定格式几何）两个不同层次的职责。
3. **复用具体类型替代抽象解耦**：后续在开发 PNG 空间域和音频域（WAV / FLAC）时，为避免复制定义相似的字段，上游直接复用了既有的 `JpegFormatProfile` 类型作为其 `body` 成员，注释也注明此项设计是为了防止密码套件列表维护漂移。但这导致非 JPEG 载体被迫依赖 JPEG 专有类型与冗余字段。

---

## 3. 全局 Lib 接口审计与问题清单

经对 `rust/src/` 整体公共接口的系统梳理，发现除上述问题外，当前接口还存在以下 8 处命名不协调、类型不对称或设计缺陷：

### 3.1 常量命名前缀不一致（`DEFAULT_` 与 `OFFICIAL_` 混用）

- **涉及位置**：
  - `rust/src/stego/format.rs`
  - `rust/src/lib.rs`
- **代码现状**：
  - `DEFAULT_JPEG_FORMAT: JpegFormatProfile`（前缀为 `DEFAULT_`）
  - `DEFAULT_HEVC_FORMAT: HevcFormatProfile`（前缀为 `DEFAULT_`）
  - `OFFICIAL_PNG_FORMAT: PngFormatProfile`（前缀为 `OFFICIAL_`）
  - `OFFICIAL_WAV_FORMAT: AudioFormatProfile`（前缀为 `OFFICIAL_`）
  - `OFFICIAL_FLAC_FORMAT: AudioFormatProfile`（前缀为 `OFFICIAL_`）
- **技术问题**：在库的设计规范与方法名（如 `Dialect::is_official()`、`StegoProfile::is_official()`）中，均使用“Official（官方方言）”作为术语标准，但常量命名在前缀上存在两套规则，增加了调用方的记忆负担。
- **改进建议**：统一更名为 `OFFICIAL_JPEG_FORMAT` 与 `OFFICIAL_HEVC_FORMAT`，旧名称保留为常量别名以确保向后兼容。

---

### 3.2 `StegoProfile` 中的音频格式存取器不对称

- **涉及位置**：`rust/src/stego/params.rs`（第 705 与 821-836 行）
- **代码现状**：
  ```rust
  pub struct StegoProfile {
      ...
      #[cfg(feature = "content-audio")]
      pub audio: Option<crate::stego::format::AudioFormatProfile>,
  }

  impl StegoProfile {
      pub const fn with_audio_format(mut self, audio: AudioFormatProfile) -> Self { ... }
      pub fn flac_format(&self) -> &AudioFormatProfile { ... }
      pub fn audio_format(&self) -> &AudioFormatProfile { ... }
  }
  ```
- **技术问题**：
  1. `OFFICIAL_WAV_FORMAT` 与 `OFFICIAL_FLAC_FORMAT` 本身具备不同的派生标签，以保障同一密码在不同格式间的密钥隔离；然而 `StegoProfile` 仅包含一个 `audio` 字段，调用方调用 `with_audio_format` 会同时覆盖 WAV 与 FLAC，无法对两类音频载体分别定制方言。
  2. 获取器命名混淆：`audio_format()` 内部在未配置时返回的是 `OFFICIAL_WAV_FORMAT`，名称使用泛指的 `audio_format` 而非具体的 `wav_format`。
- **改进建议**：
  将内部字段区分为 `wav` 与 `flac`，提供对称的存取方法：
  - `with_wav_format(...)` / `wav_format(&self)`
  - `with_flac_format(...)` / `flac_format(&self)`
  - `with_audio_format(...)` 仅作为同时设置两者的便捷组合方法保留。

---

### 3.3 根模块 `rust/src/lib.rs` 遗漏 Audio Format Profile 的导出

- **涉及位置**：`rust/src/lib.rs`（第 252-258 行）
- **代码现状**：
  ```rust
  #[cfg(feature = "content-hevc")]
  pub use stego::format::{DEFAULT_HEVC_FORMAT, HevcFormatProfile};
  #[cfg(feature = "content-jpeg")]
  pub use stego::format::{DEFAULT_JPEG_FORMAT, JpegFormatProfile};
  #[cfg(feature = "content-png")]
  pub use stego::format::{OFFICIAL_PNG_FORMAT, PngFormatProfile};
  ```
- **技术问题**：`content-audio` 特性已支持 WAV 和 FLAC 隐写，但根模块仅导出了 HEVC、JPEG 和 PNG 的 Profile，缺少 `AudioFormatProfile`、`OFFICIAL_WAV_FORMAT` 和 `OFFICIAL_FLAC_FORMAT` 的导出，破坏了 API 的平铺一致性。
- **改进建议**：在 `rust/src/lib.rs` 补充 `content-audio` 门控的对应导出。

---

### 3.4 孪生方言结构体接口风格不对称（`StructureProfile` vs `StegoProfile`）

- **涉及位置**：
  - `rust/src/structure/params.rs`（`StructureProfile`）
  - `rust/src/stego/params.rs`（`StegoProfile`）
- **代码现状对比**：

| 关注点 | `StructureProfile` (结构域) | `StegoProfile` (内容域) | 不对称表现 |
|---|---|---|---|
| **域名字段** | `stealth_domain: Option<&'static [u8]>` | `domain: Option<&'static str>` | 字段名与基础类型不同（字节切片 vs 字符串） |
| **域名设置方法** | `with_stealth_domain(self, &[u8])` | `with_stego_domain(self, &str)` | 一个含 `stealth_`，一个含 `stego_` |
| **域名获取方法** | `domain(&self) -> &[u8]` | `stego_domain(&self) -> Option<&str>` | 一个叫 `domain` 且自带默认回退，一个叫 `stego_domain` 且返回 `Option` |
| **密钥获取方法** | `secret(&self) -> &str` (回退到内置默认密钥) | `secret(&self) -> Option<&str>` (无回退) | 语义不同：一个是解析后实际使用的密钥，一个是配置项的原始状态 |

- **改进建议**：两端统一方法命名规则，建议统一提供带回退生效值的获取方法与纯配置状态检查方法。

---

### 3.5 动词语义偏差：`remove_carrier` 与还原语义冲突

- **涉及位置**：
  - `rust/src/structure/engine.rs`（第 678 行及相关函数）
  - `rust/src/structure/options.rs`（`RestoreOptions`）
  - `rust/src/facade.rs`（`restore_file` / `restore_bytes`）
- **代码现状**：
  - 核心自由函数命名为：`remove_carrier`、`remove_carrier_with_dialect`、`remove_carrier_bytes`；
  - 结果结构体命名为：`RemoveResult`；
  - 对应的选项结构体命名为：`RestoreOptions`；
  - 对应的门面方法命名为：`restore_file`、`restore_bytes`；
  - 对应的 CLI 命令为：`strhide restore`。
- **技术问题**：在标准库和常规开发习惯中，`remove` 常用于表示物理删除目标文件（如 `std::fs::remove_file`）。该函数的功能实质是“剥离信封并无损还原载体”，使用 `remove_carrier` 容易引发误解，且与门面、选项及 CLI 处的 `restore` 完全割裂。
- **改进建议**：
  核心自由函数更名为 `restore_carrier` / `restore_carrier_with_dialect` / `restore_carrier_bytes`，结果结构体更名为 `RestoreResult`；保留 `remove_*` 名称作为别名以保证兼容性。

---

### 3.6 自由函数后缀规则不统一（`_with` 与 `_with_dialect` 混用）

- **涉及位置**：
  - `rust/src/structure/engine.rs`
  - `rust/src/stego/mod.rs`
- **代码现状**：
  - `structure` 模块中：
    - `write_carrier_with`（后缀为 `_with`）
    - `read_carrier_with_dialect`（后缀为 `_with_dialect`）
    - `remove_carrier_with_dialect`（后缀为 `_with_dialect`）
    - `inspect_carrier_with`（后缀为 `_with`）
    - `verify_carrier_with`（后缀为 `_with`）
  - `stego` 模块中：
    - `embed_carrier_with_dialect`
    - `extract_carrier_with_dialect`
    - `extract_carrier_payload`（需传入 dialect 参数，但无后缀，且未提供不传 dialect 的默认版本）
    - `inspect_carrier_with_dialect`
    - `verify_carrier_with_dialect`
    - `probe_carrier_capacity_with_dialect`
- **技术问题**：自由函数在表达“使用显式方言 Profile 调用”这一概念时，后缀命名规范在同一模块内未严格对齐。
- **改进建议**：凡是接收显式方言参数的自由函数，统一规范为 `_with_dialect` 后缀；`extract_carrier_payload` 补齐无后缀的默认方言版本。

---

### 3.7 `StegoTuning` 枚举缺失 `Audio` 分支且缺少公开的 `AudioParams`

- **涉及位置**：
  - `rust/src/stego/options.rs`（第 259-287 行）
  - `rust/src/stego/audio/cost.rs`（第 80 行）
- **代码现状**：
  ```rust
  pub enum StegoTuning {
      Auto,
      #[cfg(feature = "content-png")]
      Png { model: SpatialAlgorithm, params: PngParams },
      #[cfg(feature = "content-jpeg")]
      Jpeg { model: JpegAlgorithm, params: JpegParams },
      #[cfg(feature = "content-hevc")]
      Hevc { mode: HevcMode, params: HevcParams },
      // 缺失 Audio 分支
  }
  ```
  音频的代价参数 `CostParams` 定义于 `rust/src/stego/audio/cost.rs`，声明为 `pub(crate)`。
- **技术问题**：
  1. 调用方在针对 WAV 或 FLAC 载体使用 `EmbedOptions` 或 `ProbeOptions` 时，无法指定特定于音频的调优配置，只能使用 `StegoTuning::Auto`。
  2. 外部无法对音频的 STC 约束高度 `h`、分组宽度 `u`、RMS 窗口大小 `window` 以及灵敏度底数 `epsilon` 进行参数化调整。
- **改进建议**：
  1. 定义并导出公共结构体 `AudioParams`；
  2. 在 `StegoTuning` 中增加 `Audio { params: AudioParams }` 分支，并在 `StegoTuning::applicable_to` 中加入对 `FileFormat::Wav` 与 `FileFormat::Flac` 的合法性校验。

---

### 3.8 载荷抽象类型割裂（`PayloadSource` vs `core::payload::Payload`）

- **涉及位置**：
  - `rust/src/structure/engine.rs`（`PayloadSource`）
  - `rust/src/core/payload.rs`（`Payload`）
- **代码现状**：
  - 结构域的写入操作强制接收 `structure::PayloadSource`（枚举：`Bytes`, `File`, `Text`, `Stdin`, `Buffered`）；
  - 内容域的嵌入操作强制接收 `core::payload::Payload`（结构体：`data: Cow<[u8]>`, `kind: PayloadKind`, `name: Option<String>`）；
  - 提取阶段：
    - 结构域返回 `ReadResult`（包含 `data`、`filename`、`is_file` 等）；
    - 内容域门面 `stego.extract` 返回 `Payload<'static>`；
    - 内容域自由函数 `extract_carrier` 返回 `Vec<u8>`；
    - 自动分派门面 `smart_extract` 返回 `ExtractOutcome`。
- **技术问题**：`core::payload::Payload` 的设计初衷是作为跨两域的统一载荷类型，但结构域的核心写入函数未对接该类型，导致同时调用两个域的应用程序需要针对同一种数据反复转换不同载荷类型。
- **改进建议**：
  为 `PayloadSource` 与 `Payload` 建立相互转换机制（实现 `From` trait），使结构域函数可直接接收或构造 `Payload`。

---

## 4. 重构设计方案（推荐实施规范）

### 4.1 核心解耦：引入 `WireCipherProfile`

在 `rust/src/stego/format.rs` 中抽离通用的载荷线格式密码配置：

```rust
/// 通用内容域载荷密码与置换派生配置（格式无关层）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireCipherProfile {
    /// 线格式主版本号
    pub format_major: u8,
    /// 线格式次版本号
    pub format_minor: u8,
    /// HKDF 载荷对称加密密钥派生标签
    pub enc_label: &'static [u8],
    /// HKDF 载荷置换伪随机种子派生标签
    pub perm_label: &'static [u8],
    /// 支持并协商的密码套件列表
    pub suites: &'static [CipherSuite],
}

impl WireCipherProfile {
    pub fn default_suite(&self) -> &'static CipherSuite {
        self.suites
            .iter()
            .find(|s| s.id == DEFAULT_SUITE_ID)
            .or_else(|| self.suites.first())
            .expect("WireCipherProfile must have at least one cipher suite")
    }
}
```

改造相关 Profile 的定义：

```rust
// 1. Audio 仅组合通用密码层，彻底去除 JPEG 几何字段
pub struct AudioFormatProfile {
    pub fallback_secret: &'static str,
    pub domain_label: &'static [u8],
    pub hpos_salt: &'static [u8],
    pub hpos_label: &'static [u8],
    pub stc_label: &'static [u8],
    pub body: &'static WireCipherProfile,
}

// 2. PNG 同样改用通用密码层
pub struct PngFormatProfile {
    pub fallback_secret: &'static str,
    pub domain_label: &'static [u8],
    pub hpos_salt: &'static [u8],
    pub hpos_label: &'static [u8],
    pub stc_label: &'static [u8],
    pub body: &'static WireCipherProfile,
}

// 3. JpegFormatProfile 独立保留其专属几何，且内部组合或并列通用标签
pub struct JpegFormatProfile {
    pub cipher: WireCipherProfile,
    pub cover_digest_tag: &'static [u8],
    pub hpos_label: &'static [u8],
    pub stc_label: &'static [u8],
    pub sb_bytes: u8,
    pub sb_h: u8,
    pub sb_u: u8,
    pub ext_h: u8,
    pub ext_u: u8,
    pub grid_rule: GridRule,
}
```

改造后的 `body_keys` 函数签名：
```rust
pub fn body_keys(
    cipher: &WireCipherProfile,
    master: &[u8; 32],
    salt: &[u8],
    domain: Option<&str>,
) -> ([u8; 32], [u8; 32])
```

### 4.2 补充 `AudioParams` 与 `StegoTuning::Audio`

在 `rust/src/stego/params.rs` 中公开定义：

```rust
/// 音频采样域隐写调优参数
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AudioParams {
    /// 局部能量计算窗口半径（槽位单位，默认 16）
    pub window: usize,
    /// 敏感度数值底数（默认 1e-3）
    pub epsilon: f64,
    /// 矩阵编码方式（默认 Auto，支持 Stc / Hamming）
    pub codec: StegoCodec,
    /// STC 约束高度（默认 8）
    pub stc_h: u8,
    /// STC 分组宽度（默认 0 为自适应）
    pub stc_u: u8,
}

impl Default for AudioParams {
    fn default() -> Self {
        Self {
            window: 16,
            epsilon: 1e-3,
            codec: StegoCodec::Auto,
            stc_h: 8,
            stc_u: 0,
        }
    }
}
```

扩展 `StegoTuning`：

```rust
pub enum StegoTuning {
    Auto,
    #[cfg(feature = "content-png")]
    Png { model: SpatialAlgorithm, params: PngParams },
    #[cfg(feature = "content-jpeg")]
    Jpeg { model: JpegAlgorithm, params: JpegParams },
    #[cfg(feature = "content-hevc")]
    Hevc { mode: HevcMode, params: HevcParams },
    #[cfg(feature = "content-audio")]
    Audio { params: AudioParams },
}
```

---

## 5. 实施路线与优先级排序

| 优先级 | 改造项 | 改造内容 | 破坏性等级 | 建议实施时机 |
|:---:|:---|:---|:---:|:---|
| **P0** | 密码层抽象解耦 | 引入 `WireCipherProfile`，消除 `AudioFormatProfile.body` 和 `PngFormatProfile.body` 对 `JpegFormatProfile` 的强耦合 | 源码破坏性（私有方言构建受影响） | **立即执行**（发布前重构窗口） |
| **P0** | 音频调优完备化 | 导出 `AudioParams`，在 `StegoTuning` 增加 `Audio` 臂，对接音频底层引擎 | 增量非破坏性 | **立即执行** |
| **P1** | 常量与导出统一 | 统一 `OFFICIAL_*_FORMAT` 命名；在 `lib.rs` 补齐 Audio Profile 导出 | 兼容（旧常量作别名） | 随 P0 同步执行 |
| **P1** | 还原动词规范化 | `remove_carrier*` / `RemoveResult` 更名为 `restore_carrier*` / `RestoreResult` | 兼容（旧函数作别名） | 随 P0 同步执行 |
| **P1** | 音频方言存取器解耦 | `StegoProfile` 分离 `wav` 与 `flac` Profile 配置项，保障格式隔离 | 增量非破坏性 | 随 P0 同步执行 |
| **P2** | 自由函数后缀对齐 | 将接收方言的自由函数后缀统归为 `_with_dialect` | 兼容（保留旧函数） | 次要批次 |
| **P2** | 方言 Profile 规范对齐 | 对齐 `StructureProfile` 与 `StegoProfile` 的域名与密钥存取方法规范 | 增量非破坏性 | 次要批次 |
| **P2** | 载荷抽象互通 | 实现 `PayloadSource` 与 `Payload` 之间的双向互转 | 增量非破坏性 | 次要批次 |
