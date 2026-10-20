# strhide 库定制性审计与 Public API 演进蓝图

> **决策更新（2026-10-20）**：经评估，**UBE v3 协议演进已决定不实施**（收益不明确、工作量过大）。
> 因此本文第 4 节蓝图已修订：删除一切依赖 v3 线格式扩展的配置项（cipher 套件替换、zstd、PBKDF2 轮数可配、自定义元数据），
> 收敛为 **v2.2 线格式约束内可落地**的改造子集。修订记录见 `docs/CHANGES-20261020.md`。

本文档针对 `strhide`（Rust 实现）作为公共库（Library）供外部项目、子 Crate 或第三方开发者调用时的**可定制性、硬编码限制、以及向专业 Public API 改造的演进方案**进行系统性技术审计。

---

## 目录
1. [审计背景与设计现状](#1-审计背景与设计现状)
2. [硬编码限制系统梳理（7 大维度）](#2-硬编码限制系统梳理7-大维度)
3. [定制能力对比总览表](#3-定制能力对比总览表)
4. [Public API 架构改造蓝图](#4-public-api-架构改造蓝图)
5. [API 文档与测试体系规划](#5-api-文档与测试体系规划)

---

## 1. 审计背景与设计现状

当前 `strhide` 在 `rust/Cargo.toml` 中配置了 `[lib]` 和 `[[bin]]`，核心业务（载体解析、加解密、隐写、信封封包）均位于 `src/lib.rs` 及其子模块中。

然而，审查代码实现后可以发现，当前代码架构的重心主要服务于**“单一官方 CLI 二进制工具”**，库模块的许多核心参数、策略选择和 I/O 接口是以内部消费为前提设计的，尚未完全具备作为一个通用、灵活、高扩展性 SDK（Public API）的能力。

---

## 2. 硬编码限制系统梳理（7 大维度）

### 2.1 文件头与信封协议（Envelope Protocol 限制）
- **魔数（Magic Header/Trailer）写死**：
  - 标准模式魔数硬编码在 `src/envelope.rs`：`STANDARD_HEADER_MAGIC` (`0xb7542c827e311d6e`) 与 `STANDARD_TRAILER_MAGIC` (`0x78e666d2`)。
  - 隐蔽（Stealth）模式魔数由 `derive_stealth_magics(pwd, b"strhide-stealth-v1")` 派生，域分隔符写死为常量。
  - **实证补充**：`engine::STEALTH_DOMAIN` 常量虽已定义，但 7 个调用点中仅 1 处使用它，其余 6 处（envelope.rs:336、engine.rs:695/765/1398/1692、crypto.rs:509）直接写字面量 `b"strhide-stealth-v1"`——问题不是"写死"，而是**没有单一事实源**，改动域时有漂移风险，应优先收敛为常量引用再谈可配置。
  - **影响**：外部调用者无法指定私有魔数（例如构建企业内部专用格式或规避公共特征库扫描）。只要安装了官方 strhide，任何人都能轻易探测到该信封。
- **信封结构（112B Header + 24B Trailer）不可扩展**：
  - 头部尺寸与字段偏移完全固定，没有预留扩展字段（如 TLV 格式或元数据扩展区）。
- **元数据内容不可自定义**：
  - `CarrierMetadata` 结构体仅硬编码记录了 `filename`、`raw_size`、`raw_sha256`、`created_at`。外部调用者无法注入业务自定义元数据（如版本号、作者标识、数字签名、过期时间等）。

### 2.2 加密算法与密钥派生（Crypto 机制限制）
- **加密套件纯绑定**：
  - 内部纯硬编码绑定 `Aes256Gcm`，无法切换到 ChaCha20-Poly1305 或抗重放攻击的 AES-GCM-SIV。
- **PBKDF2 迭代轮数固定**：
  - `PBKDF2_ITERATIONS = 100_000` 作为常量写死。在超大批量写入或受限嵌入式场景下无法降低轮数以提升性能；在高安全防御场景下也无法提高轮数。
- **分块大小（Chunk Size）写死**：
  - `CHUNK_SIZE = 2 * 1024 * 1024` (2MB) 硬编码，无法为微型载体（如几十 KB 的图标）缩小块以降低内存开销，也无法为几十 GB 的视频载体调大分块以增加吞吐。
- **内置公开密钥固定**：
  - `BUILTIN_DEFAULT_KEY` 为硬编码字符串，无密码模式下所有用户共享同一组静态密钥，外部无法替换为企业内预共享的公钥。

### 2.3 数据压缩策略
- **压缩引擎单一**：
  - 仅支持 Raw Deflate (`flate2`)，不支持切换为压缩率更高或解压极快的现代算法（如 `zstd` / `lz4`）。
- **压缩决策阈值硬编码**：
  - 在 `src/engine.rs` 中写死判断：`comp_len * 100 < raw_size * 98`（即必须节省至少 2% 体积才保留压缩），外部无法配置“强制压缩”或“完全禁用压缩”。

### 2.4 载体适配与路由机制（Adapters & Strategy Routing）
- **无法注册自定义载体格式（HostAdapter）**：
  - `router::ADAPTERS` 是一个静态常量切片，仅包含内置的 10 种格式（PNG, JPEG, WEBP, HEIF, MP4, WAV, ZIP, PDF, PE, MKV）。
  - 即使第三方实现了 `HostAdapter` trait（例如想要支持 DICOM 医学影像、ELF 二进制、DOCX 文档），也**无法注册进引擎**，因为 `find_adapter_or_reject` 只遍历静态切片。
- **策略注册表写死**：
  - `STRATEGY_REGISTRY` 是写死在代码里的 `[(&str, u8)]`，策略 ID 被限制在常量 `11` 内，外部实现的新策略无法分配 ID。

### 2.5 自适应隐写算法（Adaptive Stego 模块限制）
- **统揽入口 `stego::embed_carrier` 无法传入自定义代价模型**：
  - `StegoOptions.algorithm` 仅接收 `Option<String>`。
  - 内部依赖 `CostModelRegistry::get_spatial_model(name)`，该注册表内部是静态 `match` 匹配（仅支持 "hill" 和 "uerd"），**没有运行时动态注册机制**。外部自己实现的 `SpatialCostModel` 无法通过统揽入口生效。
- **结构隐藏（`engine`）与内容隐写（`stego`）两套体系割裂**：
  - 主入口 `engine::write_carrier` 目前只支持结构域策略（`chunk`, `app_segment` 等），不支持将内容自适应隐写作为普通策略透传调用。

### 2.6 安全安全校验机制（Rejection Engine）
- **无条件强制拒绝，不可旁路**：
  - `write_carrier` 会无条件调用 `run_all_rejection_checks`。
  - 若调用者用于安全测试、逆向研究或特定沙箱环境，明确需要往带签名的 PE/PDF 注入数据时，引擎直接抛出错误终止，外部**无法配置跳过检查**（无类似 `allow_signed` 或 `force` 选项）。

### 2.7 I/O 绑定死在文件路径（Path-only 限制）
- **缺少内存流与通用流支持**：
  - `engine::write_carrier` 和 `engine::read_carrier` 的签名接收的是 `&Path`，在底层直接调用 `File::open` 与 `File::create`。
  - **严重痛点**：不支持内存流（In-Memory Stream）。在 Web 服务、微服务或云原生场景中，载体往往是内存中的 `Vec<u8>` 或 HTTP 字节流，当前必须先写入物理磁盘临时文件，再调用 strhide，最后再读回磁盘，造成严重的 I/O 损耗与并发文件锁冲突。

---

## 3. 定制能力对比总览表

| 核心维度 | 现有现状 | 外部作为库调用能否自定义 | 影响评估 |
|---|---|:---:|---|
| **信封魔数 (Magic)** | 标准魔数固定 / Stealth 派生串固定 | ❌ 无法自定义 | 无法构建私有互不兼容的隐蔽通道 |
| **元数据字段 (Metadata)** | 固定 4 个系统字段 | ❌ 无法扩展 | 无法传递自定义业务标签/版本号 |
| **加密算法 (Cipher)** | 仅支持 AES-256-GCM | ❌ 无法替换 | 无法使用 ChaCha20-Poly1305 等 |
| **KDF 轮数 (PBKDF2)** | 固定 100,000 轮 | ❌ 无法调整 | 无法在安全级别与执行性能间取舍 |
| **分块大小 (Chunk Size)** | 固定 2MB | ❌ 无法配置 | 极小/极大文件内存与吞吐效率欠佳 |
| **压缩策略** | Deflate / 2% 阈值写死 | ❌ 无法配置 | 无法使用 Zstd，无法强制关闭压缩 |
| **载体适配器 (Adapter)** | 静态硬编码 10 种内置格式 | ❌ 无法注册新格式 | 外部无法扩展私有文件格式 |
| **自适应隐写模型** | 内部硬编码 match "hill"/"uerd" | ❌ 无法动态注入 | 自定义代价模型无法通过统一入口调用 |
| **安全检查 (Rejection)** | 签名文件/只读强制拦截报错 | ❌ 无法跳过/旁路 | 渗透测试与特定评估场景被卡死 |
| **I/O 形式** | 仅支持物理磁盘 `&Path` | ❌ 不支持内存流 | 云原生及高并发内存处理场景效率低 |

### 3.1 范围裁定（2026-10-20，v3 取消后）

上表 10 个维度并非全部进入本期改造。UBE v3 已决定不实施，凡需要 v2.2 信封**不具备的扩展位**（TLV / suite ID / 加密清单）的项一律移出：

| 维度 | 本期裁定 | 理由 |
|---|:---:|---|
| 信封魔数 / Stealth 域 | ✅ 可落地 | 走**读写两侧对称配置**（§4.4），不改变线格式；代价是与官方二进制互斥 |
| 分块大小 | ✅ 可落地 | 纯本地参数；读侧需同步放宽 `CHUNK_SIZE+16` 反伪造上限（crypto.rs:359） |
| 压缩策略（开关/阈值/等级） | ✅ 可落地 | 不改变 `FLAG_COMPRESSED` 语义（仍为 raw deflate） |
| 载体适配器注册 | ✅ 可落地 | 注册表下沉到 `Engine`，纯本地机制 |
| 自适应隐写模型注入 | ✅ 可落地 | trait 对象注入，embed/extract 两侧对称 |
| 安全检查（Rejection） | ✅ 可落地 | 布尔开关改为细粒度 `RejectionPolicy` |
| I/O 形式（流式） | ✅ 可落地 | crypto 层本就流式，engine 层改造量低于原估计 |
| 加密算法替换 | ⛔ 暂缓 | 需协议标志位 + 新 AEAD 路径 + 全量测试；AES-256-GCM 已满足需求 |
| 压缩算法替换（zstd） | ⛔ 暂缓 | 需新依赖 + 压缩算法标志位；收益不明确 |
| PBKDF2 轮数可配 | ⛔ 暂缓 | v2.2 头部无存储位（鸡生蛋）；且下调轮数是安全倒退 |
| 自定义元数据 | ⛔ 暂缓 | v2.2 紧凑元数据块为定长位置编码，无扩展位；最小兼容方案复杂/收益比失衡 |

---

## 4. Public API 架构改造蓝图

为了让 `strhide` 演进为专业、现代化且灵活的 Rust SDK，在 **UBE v3 不实施** 的前提下，按以下设计模式在 v2.2 约束内重构。两条硬约束：

1. **不改变 v2.2 线格式**——或仅在空闲标志位内扩展，且旧读取端可安全拒绝/跳过；
2. **读写两侧对称**——任何写侧可配项必须有对应读侧入口，否则写出的信封自己读不回来（原方案最大的设计缺口）。

### 4.1 本地配置收敛 (`EngineConfig`，不含线格式参数)

只收敛**不进入信封线格式**的本地参数。线格式参数（cipher/KDF/压缩算法/元数据/魔数）在 v3 取消后一律不进 config——
魔数与 Stealth 域改走读写两侧对称配置（§4.4），其余暂缓（§3.1 / §4.5）：

```rust
/// 本地性能与行为配置。只影响本次调用，不写入信封，不影响互读性。
pub struct EngineConfig {
    /// 加密分块大小（默认 2MB）。仅影响写入侧分帧；
    /// 读取侧按 4B 长度前缀顺序解析，需同步放宽 `CHUNK_SIZE + 16` 反伪造上限。
    pub chunk_size: usize,
    /// 压缩策略（始终为 raw deflate，不改变 FLAG_COMPRESSED 语义）。
    pub compression: CompressionStrategy,
    /// 预写安全检查策略（默认 Strict）。
    pub rejection: RejectionPolicy,
}

/// 压缩决策。替代 engine.rs:725 写死的 `comp_len * 100 < raw_size * 98`。
pub enum CompressionStrategy {
    /// 节省不足阈值则不压缩（当前行为，默认阈值 2%）。
    AdaptiveDeflate { threshold_percent: u8 },
    /// 总是压缩，即使体积变大（等级 0-9）。
    AlwaysDeflate { level: u32 },
    /// 从不压缩。
    Disabled,
}

/// 拒绝检查粒度。替代布尔量 `bypass_rejection`（全跳过太危险）。
pub enum RejectionPolicy {
    /// 全量执行 `run_all_rejection_checks`（默认）。
    Strict,
    /// 允许注入带签名载体（PE Authenticode / PDF ByteRange 等），其余照常。
    AllowSigned,
    /// 全部跳过。仅限调用方自有沙箱/安全研究场景，需自行承担后果。
    SkipAll,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            chunk_size: 2 * 1024 * 1024,
            compression: CompressionStrategy::AdaptiveDeflate { threshold_percent: 2 },
            rejection: RejectionPolicy::Strict,
        }
    }
}
```

### 4.2 I/O 抽象化：解耦物理路径，支持泛型流

现状比原审计估计的更接近目标：**crypto 层本就是流式的**（`encrypt_stream_to_chunks` / `decrypt_stream_from_chunks` / `compress_stream` / `decompress_stream`），真正绑死在 `&Path` 的只有 engine 层（`File::open` + `compute_file_sha256` + `into_buffered()` 全量缓冲）。因此改造重点是 engine 层下沉 + 载荷侧增量化的"另一半"：

```rust
/// 核心底层接口：支持内存 Cursor<Vec<u8>>、File 等任意 SeekRead/SeekWrite。
/// 注意：要求两侧均可 Seek；网络流/stdin 等不可 Seek 输入由调用方
/// 先经 `buffered()` 包装降级（内部缓冲为 Cursor）。
pub fn write_envelope_stream<R, W>(
    reader: &mut R,
    writer: &mut W,
    source: PayloadSource,
    options: &WriteOptions,
    config: &EngineConfig,
) -> Result<WriteResult, StrHideError>
where
    R: std::io::Read + std::io::Seek,
    W: std::io::Write + std::io::Seek,
{
    // 纯基于流的处理，无需关心数据是否在磁盘
}

/// 上层文件便捷接口：保留现有 temp 文件 + rename 的原子提交语义，
/// 内部委托给 write_envelope_stream。
pub fn write_carrier_with(
    carrier_path: &Path,
    source: PayloadSource,
    options: &WriteOptions,
    config: &EngineConfig,
) -> Result<WriteResult, StrHideError> { /* ... */ }

/// 旧签名保留，委托 `EngineConfig::default()`（遵循 read_carrier_with 先例）。
pub fn write_carrier(
    carrier_path: &Path,
    source: PayloadSource,
    options: &WriteOptions,
) -> Result<WriteResult, StrHideError> { /* ... */ }
```

三个必须写明的边界：

1. **载荷侧流式化**：`PayloadSource` 增加 `Reader(R)` 变体，走增量压缩+加密，消灭 `into_buffered()` 的"整个文件进内存"（10GB 载荷场景）；
2. **原子性退化**：流式写入**不提供** temp+rename 原子语义（调用方自管 W 的生命周期），文件便捷层保留现有原子行为；
3. **元数据操作退化**：`backup` / `preserve_time` 在流模式下无意义（无路径可备份、无文件时间戳可克隆），文档需明示为空操作。

### 4.3 动态注册机制（Registry Pattern）

1. **HostAdapter 动态注册**（下沉到 `Engine`/`EngineBuilder`，替换全局 `static ADAPTERS`）：
   ```rust
   pub struct AdapterRegistry {
       // 用 Arc 而非 Box：trait 已约束 Send + Sync，便于多 Engine 共享同一份注册表
       adapters: Vec<Arc<dyn HostAdapter>>,
   }

   impl AdapterRegistry {
       pub fn new_with_defaults() -> Self;
       /// 插入顺序即检测优先级（与现有 ADAPTERS 语义一致）。
       /// 已知坑：HEIF 曾被 MP4 适配器误收，注册新适配器需复核检测顺序。
       pub fn register(&mut self, adapter: Arc<dyn HostAdapter>);
       pub fn find_adapter(&self, reader: &mut dyn SeekRead) -> Option<&dyn HostAdapter>;
   }
   ```
   牵连面：`find_adapter_or_reject` / `no_hidden_data_error` 等处的 `&'static dyn HostAdapter` 签名要改为借用注册表生命周期。
2. **策略 ID 分配规范**：`STRATEGY_REGISTRY` 1–11 为官方保留段；外部策略从 **12 起私有段**自行分配，且必须文档明示"私有 ID 信封无法被官方二进制剥离"（剥离依赖 `adapter.strip`）。另注意 `MAX_KNOWN_STRATEGY_ID = 11` 的解掩码启发式（envelope.rs:376）会把未知 ID 当噪声，私有段信封在默认模式下不可读。
3. **Stego 代价模型直接注入**：在 `StegoOptions` 中开放 Trait 对象直接注入，优先于内置名称匹配：
   ```rust
   pub struct StegoOptions {
       pub algorithm: Option<String>,
       /// 直接传入外部实现的自定义空间域模型
       pub custom_spatial_model: Option<Arc<dyn SpatialCostModel>>,
       /// 直接传入外部实现的自定义 JPEG 模型
       pub custom_jpeg_model: Option<Arc<dyn JpegCostModel>>,
       pub spatial_params: SpatialParams,
       pub jpeg_params: JpegParams,
   }
   ```
   约束：`stego/envelope.rs` 的微信封**不记录算法 ID**，embed 与 extract 必须传入**同一个模型实例**，否则表现为 `NoHiddenData`（AEAD 失败）。这一点必须写进文档，否则调用方会以为注入即生效。

### 4.4 读取侧对称配置（原方案完全缺失，本次补入）

任何写侧可配项都必须有读侧入口，否则自定义配置写出的信封**自己读不回来**。读取侧配置只承载"调用方约定的私有参数"，不进信封：

```rust
/// 读取侧配置：read_carrier_with / remove_carrier / inspect / verify 对称接收。
pub struct ReadConfig {
    /// 写侧使用的自定义信封魔数（None = 官方标准魔数）。
    pub custom_magic: Option<MagicPair>,
    /// 写侧使用的自定义 Stealth 派生域（默认官方域 b"strhide-stealth-v1"）。
    /// 用 Cow 而非 &'static [u8]，避免借用约束折磨调用方。
    pub stealth_domain: Cow<'static, [u8]>,
}

pub struct MagicPair {
    pub header: [u8; 8],
    pub trailer: [u8; 4],
}
```

必须随 API 一起写明的两条权衡：

- **互斥性**：自定义魔数/域的信封**无法被官方二进制定位与读取**（定位逻辑只认标准魔数 + 官方域派生值）。这是私有通道的代价，不是缺陷；
- **反扫描诉求走错门**：固定私有魔数是**新的静态指纹**（一次泄露永久失效），抗扫描应使用 stealth 模式（密码派生魔数）。`custom_magic` 的唯一正当用途是企业私有格式互操作。

### 4.5 本期明确不做（候选项，非遗忘）

| 项 | 卡点 | 重启条件 |
|---|---|---|
| cipher 套件替换（ChaCha20-Poly1305 / AES-GCM-SIV） | 需协议标志位 + 第二 AEAD 路径 + 全量回归；AES-256-GCM 已满足需求 | 出现明确性能/合规诉求 |
| zstd 压缩 | 需新依赖 + 压缩算法标志位（`FLAG_COMPRESSED` 无法区分算法） | deflate 成为实测瓶颈 |
| PBKDF2 轮数可配 | v2.2 头部无存储位（鸡生蛋）；下调轮数是安全倒退 | 协议获得 KDF 参数扩展位 |
| 自定义元数据 | v2.2 紧凑元数据块为定长位置编码，无扩展位 | 协议获得 TLV/清单类扩展机制 |

---

## 5. API 文档与测试体系规划

针对目前“缺乏系统 API 文档、仅有 docs.rs 自动生成签名”的现状，建议构建如下标准化文档体系：

```text
docs/
├── api/
│   ├── ARCHITECTURE.md          # 模块职责拓扑图与内部数据流转说明
│   ├── QUICKSTART.md            # 基础嵌入、提取与无损还原 5 分钟上手
│   ├── COOKBOOK.md              # 常用实战配方（内存中免落盘流式处理、隐蔽模式、批量处理等）
│   ├── EXTENSION_GUIDE.md       # 自定义 HostAdapter、自定义 CostModel 扩展实战
│   └── WIRE_SPEC.md             # UBE v2.2 二进制信封协议线格式规范
```

同时，在代码库的公共 API 注释中全面引入 Rust 标准的 **Doc-tests**（文档测试代码块），确保每次在本地或 CI 执行 `cargo test --doc` 时，文档中的代码示例均保持 100% 可编译与可执行，杜绝文档与代码实现脱节。

补充（相对原规划的增补）：

- **`examples/` 目录**：COOKBOOK 的配方同步落为可编译的 cargo examples（比纯 doc-test 更适合多文件场景），CI 以 `cargo build --examples` 守护；
- **`docs/SECURITY.md` + 威胁模型**：密码学/隐写工具刚需，含漏洞披露流程、stealth 模式的威胁边界、`RejectionPolicy::SkipAll` 的后果声明；
- **wire 兼容矩阵**：一张表写清"哪个版本读哪个版本、哪个配置组合互斥"（自定义魔数/私有策略 ID/compact_meta 各自的兼容性），随每次线格式相关改动更新；
- **发布 checklist**：`rust-version`(MSRV) 声明、`[features]`（`cli` 后移或 gate 掉 clap/rpassword）、`#[non_exhaustive]` on `StrHideError`、`cargo publish --dry-run`。
