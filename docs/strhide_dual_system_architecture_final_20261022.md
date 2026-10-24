# strhide 双系统架构辨析与现代化 Facade API 重构方案（v2 源码核定版）

> **编制日期**：2026-10-22  
> **状态**：方案核定版（已对齐 `rust/` 源码与 `docs/api/ARCHITECTURE.md`）  
> **核心定位**：厘清 [strhide](https://github.com/mcxiaoke/strhide) 内部两套彼此独立的隐写子系统，终结“C 语言式散装函数传参”的调用摩擦，补齐 `const fn` 编译期方言构造、全链路 `FormatProfile` 透传、文件/内存对称操作与 CLI 实例注入能力，为 CarrotHash 等宿主工具提供零运行时开销的私有方言嵌入方案。

## 1. 问题背景与重构动机

在将 `strhide`（[`rust/Cargo.toml`](https://github.com/mcxiaoke/strhide/blob/master/rust/Cargo.toml)）作为依赖库嵌入其他宿主工具（如 `CarrotHash`，通过隐藏参数 `-s / --stego` 切换为私有方言隐写模式）时，现有公開 API 暴露出明显的工程摩擦：

* **调用繁琐且缺少状态绑定**：每次执行操作都必须像面向过程函数一样，把 `&Profile`、`&LocalParams`、`&WriteOptions` 等对象作为入参重复传递；外部程序无法先初始化一个绑定了私有方言的 `StrHide` 实例再连续调用读写方法。
* **命名非正交且签名不对称**：在 [`rust/src/engine.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/engine.rs) 中，写操作叫 `write_carrier_with`（接收 `local` 与 `profile`），读操作却叫 `read_carrier_with_profile`（因为 `read_carrier_with` 第 4 个参数只接收 `overwrite: bool`），剥离操作又叫 `remove_carrier_with` / `remove_carrier_with_options`（多达 6 个扁平位置参数），检查与验证则叫 `inspect_carrier_with` / `verify_carrier_with`。
* **配置类型职责分散与硬编码盲区**：调用方需要在 `Profile`、`StegoProfile`、`FormatProfile`、`LocalParams`、`WriteOptions`、`StegoOptions` 之间手动拼装参数，且高层入口存在写死官方默认常量的断层。

## 2. 底层真相：两套完全独立的隐写子系统对比

依据 [`docs/api/ARCHITECTURE.md`](https://github.com/mcxiaoke/strhide/blob/master/docs/api/ARCHITECTURE.md) 与 [`docs/api/WIRE_SPEC.md`](https://github.com/mcxiaoke/strhide/blob/master/docs/api/WIRE_SPEC.md)，`strhide` 内部并存着**两套哲学不同、数学原理不同、载体范围不同、操作语义完全正交**的隐写子系统：

| 维度 | 系统 A：结构域容器无损隐写（Carrier / Structure Domain） | 系统 B：内容域图像自适应隐写（Adaptive Stego / Content Domain） |
| :--- | :--- | :--- |
| **核心模块** | [`engine`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/engine.rs) + [envelope](https://www.google.com/search?q=https://github.com/mcxiaoke/strhide/blob/master/rust/src/envelope.rs) + [adapters](https://www.google.com/search?q=https://github.com/mcxiaoke/strhide/blob/master/rust/src/adapters/mod.rs) + [router](https://www.google.com/search?q=https://github.com/mcxiaoke/strhide/blob/master/rust/src/router.rs) | [`stego`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/stego/mod.rs)（`spatial` / `jpeg` / `hevc` / `coding` / `registry` / `format`） |
| **设计哲学** | **100% 无损挂载、格式保持、可逆还原** | **内容微调、有损不可逆、抗取证统计分析** |
| **工作原理** | 在容器合法的结构性空隙（PNG `prIv` 块、JPEG `APP15`、MP4 `uuid`、PE slack/codebits、ZIP pre-CD、PDF 增量更新等）注入完整信封 | 基于失真代价模型（JPEG UERD/J-UNIWARD、PNG HILL/S-UNIWARD、HEVC Scheme C 旁路符号位），通过 STC 校验格编码微调像素值、DCT 系数或 CABAC 符号位 |
| **支持载体** | PNG, JPEG, WEBP, HEIF, MP4, WAV, ZIP, PDF, PE, MKV | **图像与视频载体**：JPEG（DCT 频域系数）、PNG（空域像素）、HEIF/HEIC 及 HEVC Annex-B（CABAC 旁路符号位 Scheme C，零比特率膨胀 Δ = 0） |
| **信封协议** | **UBE v2.2**（112B Header + Hint + 加密紧凑元数据块 + 分块 AES-256-GCM 载荷 + 24B Trailer） | **JPEG V3 Superblock**（44B 头部 + TLV 扩展区 + 密文）或 **Spatial Micro-Envelope**（16B salt + 12B nonce + 密文，无静态魔数） |
| **宿主可逆性** | **支持 bit-for-bit 还原**：信封记录原文件尺寸与 SHA-256，`restore` / `remove` 强校验还原一致性 | **无还原能力**：像素或 DCT 系数一经微调不可逆，不支持 `restore` |
| **核心动词** | **`write`** / **`read`** / **`restore`**（别名 `remove`）/ **`inspect`** / **`verify`** | **`embed`** / **`extract`** / **`probe`**（容量探测） |
| **私有方言参数** | `default_secret`、`stealth_domain`、自定义魔数对 `MagicPair` | `stego.default_secret`、`stego.stego_domain`、自定义 `FormatProfile` |

### 架构红线

1. **动词天然正交，严禁混为一谈**：系统 A 的核心动词是 `write / read / restore / inspect / verify`；系统 B 的核心动词是 `embed / extract / probe`。绝不能设计一个隐式猜测走“结构注入”还是“像素修改”的模糊入口，也绝不能对系统 B 暴露无意义的 `restore`。
2. **文件 I/O 与内存 I/O 职责对齐**：系统 A 在 [`rust/src/engine.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/engine.rs) 中同时具备文件级与 `_bytes` 内存级入口；系统 B 在 [`rust/src/stego/mod.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/stego/mod.rs) 中仅接收 `&[u8]`，而安全落盘（[`engine::commit_carrier_bytes`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/engine.rs) 提供的临时文件、原子替换、`.bak` 备份与时间戳保留）此前散落在 [`rust/src/cli.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/cli.rs) 中，重构时应统一收归门面层。

## 3. 现有代码的六大结构与实现缺陷（源码级核查）

### 缺陷 1：面向过程散装传参，缺乏实例级生命周期
在 [`rust/src/engine.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/engine.rs) 与 [`rust/src/stego/mod.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/stego/mod.rs) 中，所有 API 均为无状态顶层函数：

```rust
// 现状：每次调用都必须显式传递 &local_params 与 &profile
write_carrier_with(path, source, &write_opts, &local_params, &profile)?;
read_carrier_with_profile(path, output, password, overwrite, &profile)?;
remove_carrier_with_options(path, output, password, backup, &profile, overwrite)?;
embed_carrier_with_profile(&carrier_bytes, payload, &stego_opts, &profile)?;
```

对于 `CarrotHash` 等宿主工具，私有方言 `Profile` 在编译期或进程启动时即已固定。逼迫调用方在每一处调用点手动传 `&profile`，一旦某处误调了不带 `_with_profile` 的同名函数，就会静默退回官方方言导致读写不互通。

### 缺陷 2：`#[non_exhaustive]` 阻断了外部 Crate 定义 `const` 私有方言
在 [`rust/src/params.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/params.rs)（第 227、282 行）中，`Profile` 与 `StegoProfile` 均标注了 `#[non_exhaustive]`，外部 crate 无法使用结构体字面量初始化；而现有的链式方法（如 `with_default_secret<S: Into<Cow<'static, str>>>`）依赖运行时 trait 转换而非 `const fn`。这导致外部宿主无法声明零运行时开销的 `const CARROT_PROFILE: Profile = ...;`。

### 缺陷 3：内容域 3 处高层入口写死 `DEFAULT_FORMAT`，私有 `FormatProfile` 无法透传
在 [`rust/src/stego/mod.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/stego/mod.rs) 中，高层入口虽然接收了 `&Profile`，但以下 **3 处路径**全部写死了官方 `&format::DEFAULT_FORMAT`：

1. **`embed_carrier_with_profile`（第 88 行）**：调用 `jpeg::embed_jpeg` 时硬编码传入 `&format::DEFAULT_FORMAT`。
2. **`extract_carrier_with_profile`（第 151 行）**：调用 `jpeg::extract_jpeg` 时硬编码传入 `&format::DEFAULT_FORMAT`。
3. **`probe_carrier_capacity_with_profile`（第 256 行）**：调用了 `jpeg::probe_jpeg_capacity`，而该函数在 [rust/src/stego/jpeg/engine.rs](https://www.google.com/search?q=https://github.com/mcxiaoke/strhide/blob/master/rust/src/stego/jpeg/engine.rs)（第 900 行）硬编码委托给 `&DEFAULT_FORMAT`；同时结构域的 `inspect_carrier_with`（[`rust/src/engine.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/engine.rs) 第 2095 行）也调用了 `probe_carrier_capacity_with_profile`。由于 `FormatProfile` 决定了 `grid_rule`（AC 系数子集）与 `sb_bytes / sb_h / sb_u`（头部槽位开销），写死 `DEFAULT_FORMAT` 会导致私有格式下的容量探测与实际可嵌入容量失真。

### 缺陷 4：载荷入参语义歧义与读取结果元数据丢失风险
* 在 [`rust/src/engine.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/engine.rs)（第 334 行）中，`PayloadSource` 严格区分 `Text(&str)`（执行 NFC 归一化，`is_file = false`）、`File(&Path)`（记录 basename，`is_file = true`）与 `Bytes(&[u8])`。若门面 API 设计为 `engine.write("photo.png", "secret")`，第二个字符串参数无法区分是“明文文本”还是“文件路径”。
* `read_carrier_with_profile` 返回的 `ReadResult`（第 424 行）包含 `data`、`filename`、`is_file`、`is_encrypted`、`raw_size` 等关键字段。若链式读取仅提供 `.to_vec()`，调用方在内存读取时将丢失原始文件名与加密状态。

### 缺陷 5：`cli.rs` 内部 6 处硬编码 `Profile::default()`，且直接切片 `args[1..]` 会破坏 `clap` 解析
在 [`rust/src/cli.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/cli.rs) 中：
* **6 处方言硬编码**：`handle_write`（第 1194 行调 `write_carrier`）、`handle_read`（第 1225/1248 行调 `read_carrier_with`）、`handle_restore`（第 1356 行传 `&Profile::default()`）、`handle_inspect`（第 1492/1504 行调 `inspect_carrier`）、`handle_verify`（第 1596/1613 行调 `verify_carrier`）、以及 `handle_embed --capacity`（第 2043 行传 `&Profile::default()`）全部写死了官方默认 `Profile`。此外，`handle_embed`（第 2095 行）与 `handle_extract`（第 2220 行）调用 `stego_profile()` 时从 `Profile::default()` 新建对象，会抹掉外部注入的 `FormatProfile` 与结构域方言。
* **`argv[0]` 陷阱**：`std::env::args_os()` 的第 0 个元素是二进制程序名，隐藏开关 `-s` 位于 `args[1]`。`clap` 的 `try_get_matches_from`（第 877 行）与 `scan_subcommand`（第 814 行 `argv.iter().skip(1)`）均要求切片首元素为程序名 `argv[0]`。若直接传入去掉 `argv[0]` 的子命令切片，子命令名会被 `clap` 误认为程序名而触发 `MissingSubcommand`。

### 缺陷 6：单次操作缺乏对 `LocalParams` 与 `StegoOptions` 细粒度参数的逃生舱
将 `LocalParams` 绑定到 `StrHide` 实例后，若某次写入需临时调整 `RejectionPolicy::Skip` 或 `CompressionStrategy::Never`，或某次内容域嵌入/提取需传入自定义 `SpatialParams` / `JpegParams` / `ExtractParams`（如自定义 `--p1-window` 或 `--slot-budget`），操作句柄（Op Builder）必须保留单次覆盖入口。

## 4. 重构方案：Profile 体系整合与 `const fn` 构造链

### 4.1 两层参数心智模型

将所有配置收敛为清晰的 **2 层结构**：

1. **方言与引擎默认层（`Profile` + 默认 `LocalParams`）**：决定“与谁通信”及引擎基线策略，生命周期绑定于 `StrHide` 实例，支持 `const` 编译期构造。
2. **单次操作层（Operation Builder）**：决定“本次操作的目标、凭据与临时调优”，通过链式调用按需设置并在 `.execute()` 时消费。

### 4.2 `Profile` 与 `StegoProfile` 结构演进（`rust/src/params.rs`）

[`FormatProfile`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/stego/format.rs) 本身已是 `Copy` 类型（仅包含整数与 `'static` 引用），为其补充 `PartialEq, Eq` 派生后，可直接以 `Option<FormatProfile>` 存入 `StegoProfile`，无需包裹 `Cow`：

```rust
use crate::stego::format::{DEFAULT_FORMAT, FormatProfile};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StegoProfile {
    /// 无密码模式下替代 PUBLIC_DEFAULT_SECRET 的私有密钥
    pub default_secret: Option<Cow<'static, str>>,
    /// 隔离 HKDF 密钥派生域的自定义标签
    pub stego_domain: Option<Cow<'static, str>>,
    /// 自定义 JPEG V3 线格式身份规范（None 表示使用 DEFAULT_FORMAT）
    pub format: Option<FormatProfile>,
}

impl StegoProfile {
    pub const fn new() -> Self {
        Self {
            default_secret: None,
            stego_domain: None,
            format: None,
        }
    }

    pub const fn with_static_secret(mut self, secret: &'static str) -> Self {
        self.default_secret = Some(Cow::Borrowed(secret));
        self
    }

    pub const fn with_static_domain(mut self, domain: &'static str) -> Self {
        self.stego_domain = Some(Cow::Borrowed(domain));
        self
    }

    pub const fn with_format(mut self, format: FormatProfile) -> Self {
        self.format = Some(format);
        self
    }

    pub fn format_profile(&self) -> &FormatProfile {
        self.format.as_ref().unwrap_or(&DEFAULT_FORMAT)
    }

    pub fn is_official(&self) -> bool {
        self.secret().is_none()
            && self.stego_domain().is_none()
            && self.format.is_none()
    }
}
```

在 `Profile` 上同步提供编译期 `const fn` 构造器（保留现有泛型 `with_*` 方法以确保 100% 向前兼容）：

```rust
impl Profile {
    pub const fn new() -> Self {
        Self {
            default_secret: None,
            stealth_domain: None,
            magic: None,
            stego: StegoProfile::new(),
        }
    }

    pub const fn with_static_secret(mut self, secret: &'static str) -> Self {
        self.default_secret = Some(Cow::Borrowed(secret));
        self
    }

    pub const fn with_static_stealth_domain(mut self, domain: &'static [u8]) -> Self {
        self.stealth_domain = Some(Cow::Borrowed(domain));
        self
    }

    pub const fn with_magic(mut self, magic: MagicPair) -> Self {
        self.magic = Some(magic);
        self
    }

    pub const fn with_static_stego_secret(mut self, secret: &'static str) -> Self {
        self.stego = self.stego.with_static_secret(secret);
        self
    }

    pub const fn with_static_stego_domain(mut self, domain: &'static str) -> Self {
        self.stego = self.stego.with_static_domain(domain);
        self
    }

    pub const fn with_format_profile(mut self, format: FormatProfile) -> Self {
        self.stego = self.stego.with_format(format);
        self
    }

    pub fn format_profile(&self) -> &FormatProfile {
        self.stego.format_profile()
    }
}
```

同时，在 [`rust/src/params.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/params.rs) 中为 `LocalParams` 增加 `pub const fn new() -> Self`，使其同样支持编译期常量构造。

### 4.3 修复 `src/stego/mod.rs` 的 3 处 `DEFAULT_FORMAT` 硬编码

在 [`rust/src/stego/mod.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/stego/mod.rs) 中，将 `profile.format_profile()` 贯穿至全部三个入口：

* **第 88 行（`embed_carrier_with_profile`）**：将 `&format::DEFAULT_FORMAT` 替换为 `profile.format_profile()`。
* **第 151 行（`extract_carrier_with_profile`）**：将 `&format::DEFAULT_FORMAT` 替换为 `profile.format_profile()`。
* **第 256 行（`probe_carrier_capacity_with_profile`）**：将 `jpeg::probe_jpeg_capacity(...)` 替换为 `jpeg::probe_capacity_with_format(carrier_bytes, &*model, &options.jpeg_params, options.safety_level, profile.format_profile())`。

## 5. 重构方案：统一门面与实例化引擎（`StrHide` Facade）

新增 `rust/src/facade.rs` 并在 [`rust/src/lib.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/lib.rs) 顶层重导出 `pub use facade::*;`。

### 5.1 `StrHide` 主结构体与双层调用模型

提供**显式子系统命名空间**（`engine.carrier()` / `engine.stego()`）与**根级正交动词直通**两种完全等价的调用方式：

```rust
#[derive(Debug, Clone, Default)]
pub struct StrHide {
    profile: Profile,
    local: LocalParams,
}

impl StrHide {
    /// 创建官方默认方言引擎（支持 const 静态初始化）
    pub const fn new() -> Self {
        Self {
            profile: Profile::new(),
            local: LocalParams::new(),
        }
    }

    /// 创建绑定私有方言 Profile 的引擎实例（支持 const 静态初始化）
    pub const fn with_profile(profile: Profile) -> Self {
        Self {
            profile,
            local: LocalParams::new(),
        }
    }

    /// 设置引擎级默认 LocalParams（写端分块大小、压缩策略、预写拒绝策略）
    pub const fn with_local_params(mut self, local: LocalParams) -> Self {
        self.local = local;
        self
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    pub fn local_params(&self) -> &LocalParams {
        &self.local
    }

    // === 形态 1：显式子系统命名空间 ===
    pub const fn carrier(&self) -> CarrierSubsystem<'_> {
        CarrierSubsystem { engine: self }
    }

    pub const fn stego(&self) -> StegoSubsystem<'_> {
        StegoSubsystem { engine: self }
    }

    // === 形态 2：根级直通方法（动词严格正交） ===
    // 结构域（文件与内存对称）
    pub fn write<'a>(&'a self, carrier: &'a Path) -> WriteOp<'a> {
        self.carrier().write(carrier)
    }
    pub fn write_bytes<'a>(&'a self, carrier: &'a [u8]) -> WriteBytesOp<'a> {
        self.carrier().write_bytes(carrier)
    }
    pub fn read<'a>(&'a self, carrier: &'a Path) -> ReadOp<'a> {
        self.carrier().read(carrier)
    }
    pub fn read_bytes<'a>(&'a self, carrier: &'a [u8]) -> ReadBytesOp<'a> {
        self.carrier().read_bytes(carrier)
    }
    pub fn restore<'a>(&'a self, carrier: &'a Path) -> RestoreOp<'a> {
        self.carrier().restore(carrier)
    }
    pub fn restore_bytes<'a>(&'a self, carrier: &'a [u8]) -> RestoreBytesOp<'a> {
        self.carrier().restore_bytes(carrier)
    }
    pub fn inspect<'a>(&'a self, carrier: &'a Path) -> InspectOp<'a> {
        self.carrier().inspect(carrier)
    }
    pub fn inspect_bytes<'a>(&'a self, carrier: &'a [u8]) -> InspectBytesOp<'a> {
        self.carrier().inspect_bytes(carrier)
    }
    pub fn verify<'a>(&'a self, carrier: &'a Path) -> VerifyOp<'a> {
        self.carrier().verify(carrier)
    }

    // 内容域（内存与文件对称）
    pub fn embed<'a>(&'a self, cover_bytes: &'a [u8], payload: &'a [u8]) -> EmbedOp<'a> {
        self.stego().embed(cover_bytes, payload)
    }
    pub fn embed_file<'a>(&'a self, carrier: &'a Path, payload: &'a [u8]) -> EmbedFileOp<'a> {
        self.stego().embed_file(carrier, payload)
    }
    pub fn extract<'a>(&'a self, stego_bytes: &'a [u8]) -> ExtractOp<'a> {
        self.stego().extract(stego_bytes)
    }
    pub fn extract_file<'a>(&'a self, carrier: &'a Path) -> ExtractFileOp<'a> {
        self.stego().extract_file(carrier)
    }
    pub fn probe<'a>(&'a self, cover_bytes: &'a [u8]) -> ProbeOp<'a> {
        self.stego().probe(cover_bytes)
    }
}
```

### 5.2 结构域 Fluent Operation 句柄设计

通过显式载荷设置器（`.text()` / `.file()` / `.bytes()` / `.stdin()` / `.source()`）彻底消除字符串歧义，并在 `ReadOp` 中同时保留 `.execute()`（返回完整 `ReadResult`）与 `.to_vec()`（直接取字节）：

```rust
pub struct WriteOp<'a> {
    engine: &'a StrHide,
    carrier: &'a Path,
    source: Option<PayloadSource<'a>>,
    options: WriteOptions<'a>,
    local: LocalParams,
}

impl<'a> WriteOp<'a> {
    /// 隐藏 UTF-8 文本载荷（写入前自动 NFC 归一化）
    pub fn text(mut self, text: &'a str) -> Self {
        self.source = Some(PayloadSource::Text(text));
        self
    }

    /// 隐藏磁盘文件载荷（自动记录 basename 与 is_file = true）
    pub fn file(mut self, path: &'a Path) -> Self {
        self.source = Some(PayloadSource::File(path));
        self
    }

    /// 隐藏原始字节切片载荷
    pub fn bytes(mut self, data: &'a [u8]) -> Self {
        self.source = Some(PayloadSource::Bytes(data));
        self
    }

    /// 直接传入已构造的 PayloadSource
    pub fn source(mut self, source: PayloadSource<'a>) -> Self {
        self.source = Some(source);
        self
    }

    pub fn output(mut self, path: &'a Path) -> Self {
        self.options.output_path = Some(path);
        self
    }

    pub fn password(mut self, password: &'a str) -> Self {
        self.options.password = Some(password);
        self
    }

    pub fn password_hint(mut self, hint: &'a str) -> Self {
        self.options.password_hint = Some(hint);
        self
    }

    pub fn strategy(mut self, strategy: &'a str) -> Self {
        self.options.strategy = strategy;
        self
    }

    pub fn stealth(mut self, enabled: bool) -> Self {
        self.options.stealth = enabled;
        self
    }

    pub fn backup(mut self, enabled: bool) -> Self {
        self.options.backup = enabled;
        self
    }

    pub fn preserve_time(mut self, enabled: bool) -> Self {
        self.options.preserve_time = enabled;
        self
    }

    /// 单次操作覆盖压缩策略（L 类参数逃生舱）
    pub fn compression(mut self, strategy: CompressionStrategy) -> Self {
        self.local.compression = strategy;
        self
    }

    /// 单次操作覆盖预写拒绝检查粒度（L 类参数逃生舱）
    pub fn rejection(mut self, policy: RejectionPolicy) -> Self {
        self.local.rejection = policy;
        self
    }

    pub fn execute(self) -> Result<WriteResult, StrHideError> {
        let source = self.source.ok_or_else(|| {
            StrHideError::General("WriteOp requires a payload source (.text, .file, .bytes, or .source)".into())
        })?;
        crate::engine::write_carrier_with(
            self.carrier,
            source,
            &self.options,
            &self.local,
            &self.engine.profile,
        )
    }
}
```

读取与还原句柄同样保持链式正交：

```rust
pub struct ReadOp<'a> {
    engine: &'a StrHide,
    carrier: &'a Path,
    output_path: Option<&'a Path>,
    password: Option<&'a str>,
    overwrite: bool,
}

impl<'a> ReadOp<'a> {
    pub fn password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    /// 指定输出文件路径或目标目录（若为目录，自动使用信封内清洗后的原始文件名）
    pub fn output(mut self, path: &'a Path) -> Self {
        self.output_path = Some(path);
        self
    }

    pub fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// 执行读取并返回完整 ReadResult（含 data、filename、is_file、is_encrypted 等元数据）
    pub fn execute(self) -> Result<ReadResult, StrHideError> {
        crate::engine::read_carrier_with_profile(
            self.carrier,
            self.output_path,
            self.password,
            self.overwrite,
            &self.engine.profile,
        )
    }

    /// 快捷终结方法：仅提取载荷字节到内存 Vec<u8>
    pub fn to_vec(self) -> Result<Vec<u8>, StrHideError> {
        Ok(self.execute()?.data)
    }

    /// 快捷终结方法：写入指定路径或目录并返回完整 ReadResult
    pub fn save_to(mut self, path: &'a Path) -> Result<ReadResult, StrHideError> {
        self.output_path = Some(path);
        self.execute()
    }
}
```

### 5.3 内容域 Fluent Operation 句柄设计（含安全原子落盘）

内容域提供内存级 `EmbedOp` / `ExtractOp` 与文件级 `EmbedFileOp` / `ExtractFileOp`，其中 `EmbedFileOp` 直接复用 [`engine::commit_carrier_bytes`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/engine.rs)（第 1319 行），使库调用方无需手写临时文件与 `.bak` 备份逻辑：

```rust
pub struct EmbedFileOp<'a> {
    engine: &'a StrHide,
    carrier: &'a Path,
    payload: &'a [u8],
    output_path: Option<&'a Path>,
    options: StegoOptions,
    backup: bool,
    preserve_time: bool,
}

impl<'a> EmbedFileOp<'a> {
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.options.password = Some(password.into());
        self
    }

    pub fn algorithm(mut self, alg: impl Into<String>) -> Self {
        self.options.algorithm = Some(alg.into());
        self
    }

    pub fn safety_level(mut self, level: SafetyLevel) -> Self {
        self.options.safety_level = level;
        self
    }

    pub fn enforce_safety(mut self, enforce: bool) -> Self {
        self.options.safety_enforcement = if enforce {
            SafetyEnforcement::Enforced
        } else {
            SafetyEnforcement::Advisory
        };
        self
    }

    pub fn output(mut self, path: &'a Path) -> Self {
        self.output_path = Some(path);
        self
    }

    pub fn backup(mut self, backup: bool) -> Self {
        self.backup = backup;
        self
    }

    pub fn preserve_time(mut self, preserve: bool) -> Self {
        self.preserve_time = preserve;
        self
    }

    /// 高阶逃生舱：直接配置底层 JpegParams / SpatialParams
    pub fn with_jpeg_params(mut self, f: impl FnOnce(&mut JpegParams)) -> Self {
        f(&mut self.options.jpeg_params);
        self
    }

    pub fn with_spatial_params(mut self, f: impl FnOnce(&mut SpatialParams)) -> Self {
        f(&mut self.options.spatial_params);
        self
    }

    /// 执行图像内容域隐写并安全原子落盘（返回可选的备份文件路径）
    pub fn execute(self) -> Result<Option<PathBuf>, StrHideError> {
        let cover_bytes = std::fs::read(self.carrier)?;
        let stego_bytes = crate::stego::embed_carrier_with_profile(
            &cover_bytes,
            self.payload,
            &self.options,
            &self.engine.profile,
        )?;
        let target = self.output_path.unwrap_or(self.carrier);
        crate::engine::commit_carrier_bytes(
            self.carrier,
            target,
            &stego_bytes,
            self.backup,
            self.preserve_time,
        )
    }
}
```

## 6. CLI 注入改造与 CarrotHash 落地效果

### 6.1 `cli.rs` 实例驱动改造要点

为让 `StrHide::run_cli_from` 真正使用实例绑定的私有方言，需在 [`rust/src/cli.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/cli.rs) 完成以下对接：

1. **消除 6 处 `Profile::default()` 硬编码**：
   * `handle_write`、`handle_read`、`handle_restore`、`handle_inspect`、`handle_verify`、`handle_embed (--capacity)` 统一接收 `engine: &StrHide`；
   * 内部全部调用 `engine.write(...)`、`engine.read(...)`、`engine.restore(...)`、`engine.inspect(...)`、`engine.verify(...)`、`engine.probe(...)`。
2. **`stego` 参数采用 Overlay 增量覆盖而非重置**：
   * 在 `handle_embed` 与 `handle_extract` 中，以 `let mut profile = engine.profile().clone();` 为基底；仅当 CLI 参数、环境变量或配置文件显式提供了 `stego_secret` / `stego_domain` 时，才调用 `profile = profile.with_stego_secret(...)` 覆盖对应字段，从而完整保留 `engine` 预设的 `FormatProfile` 和私有默认密钥。
3. **`run_cli_from` 安全处理 `argv[0]`**：
   * `pub fn run_cli()` 内部直接委托给 `StrHide::new().run_cli_from(std::env::args_os())`。

### 6.2 在 CarrotHash 中的落地方案

#### 阶段定义：编译期零开销声明私有方言与引擎

```rust
use strhide::facade::StrHide;
use strhide::params::{MagicPair, Profile};
use strhide::stego::format::{DEFAULT_FORMAT, FormatProfile, GridRule};

const CARROT_JPEG_FORMAT: FormatProfile = FormatProfile {
    format_major: 1,
    format_minor: 0,
    cover_digest_tag: b"carrot-cover-v1",
    hpos_label: b"carrot-hpos",
    stc_label: b"carrot-trellis",
    enc_label: b"carrot-enc",
    perm_label: b"carrot-perm",
    sb_bytes: 44,
    sb_h: 8,
    sb_u: 2,
    ext_h: 8,
    ext_u: 4,
    grid_rule: GridRule::ALL_AC,
    suites: DEFAULT_FORMAT.suites,
};

const CARROT_PROFILE: Profile = Profile::new()
    .with_static_secret("carrot-structure-secret-2026")
    .with_static_stealth_domain(b"carrot-stealth-domain-v1")
    .with_magic(MagicPair {
        header: *b"\x89CARROT!",
        trailer: *b"CRRT",
    })
    .with_static_stego_secret("carrot-image-secret-2026")
    .with_static_stego_domain("org.carrothash.stego")
    .with_format_profile(CARROT_JPEG_FORMAT);

pub const CARROT_STEGO: StrHide = StrHide::with_profile(CARROT_PROFILE);
```

#### 场景 A：检测到 `-s / --stego` 时直接挂载完整 strhide CLI

```rust
// CarrotHash src/main.rs
let raw_args: Vec<std::ffi::OsString> = std::env::args_os().collect();
if raw_args.get(1).and_then(|s| s.to_str()).is_some_and(|s| s == "-s" || s == "--stego") {
    // 保留 raw_args[0]（程序名），仅剔除 raw_args[1]（"-s"/"--stego"），确保 clap 子命令解析正常
    let forwarded = std::iter::once(raw_args[0].clone()).chain(raw_args.into_iter().skip(2));
    std::process::exit(CARROT_STEGO.run_cli_from(forwarded));
}
```

#### 场景 B：CarrotHash 内部按需调用编程式 API

```rust
match mode {
    Mode::ContainerHide => {
        CARROT_STEGO
            .write(carrier_path)
            .file(payload_path)
            .password("my-pass")
            .stealth(true)
            .execute()?;
    }
    Mode::ContainerExtract => {
        let res = CARROT_STEGO
            .read(carrier_path)
            .password("my-pass")
            .execute()?;
        println!("提取成功: 文件名={}, 大小={} 字节", res.filename, res.raw_size);
    }
    Mode::ContainerRestore => {
        CARROT_STEGO.restore(carrier_path).execute()?;
    }
    Mode::ImageStegoEmbed => {
        CARROT_STEGO
            .embed_file(carrier_path, &payload_bytes)
            .safety_level(strhide::stego::SafetyLevel::High)
            .execute()?;
    }
    Mode::ImageStegoExtract => {
        let data = CARROT_STEGO.extract_file(carrier_path).execute()?;
        println!("图像隐写提取成功: {} 字节", data.len());
    }
}
```

## 7. 分步演进路径与向前兼容策略

为确保现有 480+ 个单元与集成测试 100% 零破坏通过，按三阶段稳妥推进：

| 阶段 | 核心任务 | 涉及文件 | 兼容性影响 |
| :--- | :--- | :--- | :--- |
| **Stage 1：底层参数打通与 `const fn` 补齐** | 1. 为 `FormatProfile` 派生 `PartialEq, Eq`<br>2. 在 `StegoProfile` 中新增 `pub format: Option<FormatProfile>`，更新 `is_official()`<br>3. 为 `Profile`、`StegoProfile`、`LocalParams` 增加 `const fn` 构造链<br>4. 修复 `src/stego/mod.rs` 第 88、151、256 行共 3 处 `DEFAULT_FORMAT` 硬编码，并补充私有 `FormatProfile` 端到端测试 | [`rust/src/stego/format.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/stego/format.rs)<br>[`rust/src/params.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/params.rs)<br>[`rust/src/stego/mod.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/stego/mod.rs) | **100% 向前兼容**（纯增量字段与方法，现有函数签名零改动） |
| **Stage 2：构建 `StrHide` 门面与 Op 链式体系** | 1. 新建 `rust/src/facade.rs`，实现 `StrHide`、`CarrierSubsystem`、`StegoSubsystem` 及各 `*Op` 构建器<br>2. 在 `rust/src/lib.rs` 顶层导出 `StrHide` 与核心类型<br>3. 新增针对门面 API 的集成测试与文档示例 | `rust/src/facade.rs`<br>[`rust/src/lib.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/lib.rs) | **100% 向前兼容**（旧函数保留，内部与 Facade 共享同一核心） |
| **Stage 3：CLI 实例驱动化与宿主接入** | 1. 改造 `rust/src/cli.rs` 中 6 处 `Profile::default()` 硬编码，改为由 `&StrHide` 驱动<br>2. 暴露 `StrHide::run_cli_from(args)`，原 `cli::run_cli()` 委托给 `StrHide::new().run_cli_from(std::env::args_os())`<br>3. 在 `CarrotHash` 中接入 `StrHide` 完成集成验证 | [`rust/src/cli.rs`](https://github.com/mcxiaoke/strhide/blob/master/rust/src/cli.rs)<br>`rust/src/facade.rs` | **100% 向前兼容**（原二进制 `main.rs` 行为与 CLI 测试完全不变） |
