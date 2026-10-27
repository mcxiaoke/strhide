# strhide 工程架构重组与 API / CLI 易用性升级方案（v2）

**基线**：`strhide 0.7.2`，`rust/src` 43,703 行；`tests` + `examples` 22,981 行，668 个 `#[test]`
**复核时间**：2026-10-26 22:23（逐条对源码核对，文中 `文件:行号` 均为实测）；2026-10-27 12:05 增补 §五「前端就绪层」与 §十 第 17–18 条。
**v1 → v2 的全部变更**见 §十 勘误表（6 处 v1 硬伤 + 2 处 v2 自查缺陷）。

---

## 零、摘要

**保留的（诊断成立）**：双域边界错位、`facade` 被 feature 绑死、结构域反向读整文件探内容域、格式嗅探三处分裂、ISOBMFF 解析三份重复、重型依赖无法裁剪——均有源码证据，见 §一。

**修正的（v1 硬伤）**：

1. v1 §4.3 的 feature 表编译不过（`structure-base` 缺 `serde_json`；`analysis` 依赖写错层级）。
2. "隔离到 feature 后即可 publish crates.io" 不成立（optional 不豁免 git 依赖）。
3. v1 §4.2 的 DAG 与 v1 §4.1 的目录互相矛盾（`analysis` 实际依赖结构域；`core/params.rs` 会反向依赖内容域）。
4. 内容域 trait 签名与 §三 自己的方案打架（I/O 混进 trait、`&[u8]` 载荷、缺 `inspect`/`verify`、`detect` 与 `sniff` 重复）。
5. `content-hevc` 挂着两条本可去掉的依赖边。
6. `default` feature 保留了 v1 自己批判的"全量默认"。

**新增的（v2 自查 + GUI 就绪，见 §五）**：

- i18n / 配置模型 / 批量编排下沉到 `core/`——`errors.rs:136` 依赖 `i18n`，原先放在 `cli/` 会让最小构建编不过。
- `core::control` 提供进度与取消；`WriteOptions` / 内容域 options 带 `control` 与 `pool`。
- `WriteResult` / `MediaInfo` / `ErrorDetail` 结构化，语言改为显式 `RenderCtx`，不再用 thread_local。
- 结论：GUI 作为 `cli/` 的兄弟消费者接入，不重写任何业务逻辑。

**落地顺序**：阶段 0（基线 + 3 个独立缺陷）→ 1（嗅探统一 + 能力表 + feature 图 + i18n/config 下沉）→ 2（内容域 trait 化 + 参数强类型 + 进度取消）→ 3（微头 + 双域诊断）→ 4（门面 + 结果结构化 + CLI 收尾）。总估 **14–18 人日**（不含 HEVC 语料回归的机器时间），见 §六。

**三条不做**：不拆多 bin；不做 `stego` → `content` 改名；不把非重复的格式解析搬进 `formats`。理由见 §八。

---

## 一、现状诊断（已逐条核对）

### 1.1 领域边界错位

- 结构域独占通用命名：`engine.rs`、`envelope.rs`、`router.rs`、`adapters/`，对应 feature 叫 `engine`；内容域被压进 `stego/`。
- `src/lib.rs:164` 的 `pub mod facade;` 挂在 `#[cfg(feature = "engine")]` 下，只开 `stego` 的下游拿不到推荐入口。
- `facade.rs` 上平铺 15 个动词（5 路径 + 5 内存 + 3 内容域内存 + 2 内容域文件），两域混用。

### 1.2 隐式双向耦合

- **结构域反向读整个载体探内容域**：`engine.rs:1972` 的 `inspect_core` 在 `engine.rs:1990-2010` 通过 `#[cfg(feature = "stego")]` 把载体读进 `Vec<u8>`（上限 `engine.rs:148` `MAX_CONTENT_STEGO_BYTES = 512 MiB`），再调 `stego::probe_carrier_capacity_with_profile`。破坏结构域"纯 `SeekRead` 流式、O(1) 内存"的契约。
- **`HostAdapter` 被塞入内容域知识**：`adapters/mod.rs:267` 的 `fn supports_content_stego(&self) -> bool`，在 `png.rs:61`、`jpeg.rs:204`、`heif.rs:21`、`mp4.rs:25` 四处覆写。
- **嗅探分裂三处**（不是四处，`router.rs` 只是遍历 `ADAPTERS` 调各自的 `detect`）：
  1. `sniff.rs`：`is_png_bytes` / `is_jpeg_bytes` / `is_heif_bytes`；
  2. `stego/sniff.rs`：`CarrierFormat` 枚举（且漏 MP4，见 B2）；
  3. `stego/mod.rs` 里 `embed_carrier`（`:99-193`）、`extract_carrier`（`:239-298`）、`probe_carrier_capacity`（`:424-481`）**三处**手写魔数比对的 if-else 瀑布，外加 `stego/hevc/sniff.rs` 的 `is_mp4_bytes` / `is_hevc_annexb`。
- **ISOBMFF 解析三份**：`adapters/isobmff.rs` 1,768 行 + `stego/hevc/heif_boxes.rs` 950 行 + `stego/hevc/mp4_boxes.rs` 867 行。
- **`src/jpeg/dqt.rs` 孤悬顶层**：消费者只有 `analysis/calibration.rs`、`stego/jpeg/geometry.rs`、`stego/jpeg/cost/uerd.rs`，结构域完全不碰。

### 1.3 巨型文件（实测行数）

| 文件 | 行数 | 混杂职责 |
|---|---:|---|
| `stego/png/engine.rs` | 3,007 | 解码/滤波还原、并行 Deflate、八值类约束、置换、STC 编排、容量探测 |
| `cli.rs` | 2,606 | 10 个子命令、密码/载荷解析、业务分发、表格与 i18n 渲染 |
| `engine.rs` | 2,459 | 元数据编解码、信封定位、5 大流程、原子提交、内容域容量跨界探测 |
| `analysis.rs` | 2,344 | 结构扫描、尾随熵、Chi2/SPA/RS、JPEG 盲校准、评分 |
| `adapters/isobmff.rs` | 1,768 | MP4/HEIF 解析、注入、偏移重算、校验 |
| `stego/hevc/engine.rs` | **1,899** | Annex-B/MP4/HEIF 路由、CABAC 位提取、EPB、Weyl、STC |

> v1 表里 `stego/hevc/engine.rs` 记为 1,644、`mp4_boxes.rs` 记为 859，与当前源码（1,899 / 867）不符，动手前须重新 baseline。

### 1.4 依赖无法裁剪

`Cargo.toml:38,41` 的 `oxideav-h265` / `rusty_h265` 是无条件 git 依赖（连 `stego` feature 都没挂）；`Cargo.toml:51` 的 `iced-x86` 挂在 `engine` 上；`Cargo.toml:21` 的 `cli = ["engine", "stego", ...]` 把两个域强制捆绑。

### 1.5 三个已确认的行为缺陷（与重构无关，先修）

| 编号 | 缺陷 | 证据 |
|---|---|---|
| **B1** | HEVC 分支丢 `SafetyEnforcement`：`--enforce-safety` 对 HEVC 无效 | `stego/mod.rs:162/173/190/202` 只传 `options.safety.level`；PNG/JPEG 在 `:115/:138` 传整个 `options.safety` |
| **B2** | 公开 API 对 MP4 误判为不支持 | `stego/sniff.rs:16-28` 的 `CarrierFormat` 无 `Mp4` 变体。该枚举**当前零调用点**，属死代码，直接删除而非修补 |
| **B3** | 门面无法覆盖写 | `facade.rs:162` 与 `:173` 把 `overwrite` 硬编码为 `false`，只能退回 5 参数自由函数 |

> 三项均已在阶段 0 修复（2026-10-27），见 `docs/CHANGES-20261027.md`。B1 的修复带出一个连带问题：HEIF 分支的兜底会把任何错误改写成桥接器的 "No bridgeable image carrier"，安全拦截必须用独立错误变体才能穿透它。

---

## 二、目标架构

### 2.1 依赖方向（修正后的 DAG）

```text
                     cli
                      │   只调 facade 与各域公共 API
                   facade
        ┌─────────────┼──────────────┐
   structure         stego         analysis
        └──────┬───────┘              │
               ▼                      │
            formats ◄─────────────────┘
               │
              core
```

**铁律（由 §七 的 import lint + 最小构建强制，不靠自觉）**：

1. `structure ↛ stego`，`stego ↛ structure`（双向禁止）。
2. `analysis → structure` **允许**：`analysis.rs:43-44` 实际依赖 `adapters::{pe_codebits, pe_slack}` 与 `envelope::{MIN_UBE_PLAIN, STANDARD_HEADER_MAGIC}`，黑盒分析必须能认 UBE 信封与 PE 指令。v1 的 DAG 把这条边画掉了，是错的。
3. `analysis ↛ stego`：JPEG 盲校准只用 `formats::jpeg_segments` + `jpeg-decoder`，不碰隐写实现。
4. `core` 不引用任何 format profile（v1 的 `core/params.rs` 装着 `Profile`，而 `Profile` 内嵌 `stego: StegoProfile`（`params.rs:408-437`），会立刻反向依赖内容域，见 §3.5）。
5. `formats` 允许含写操作：`isobmff/iloc.rs`、`stbl.rs` 的偏移修补是**两个域的共同需求**（结构域注入 box、内容域桥接缩略图都要重算偏移）。v1 声称 `formats` "零业务语义"却又列出"偏移平移/修补"，自相矛盾；本版明确它是"共享的容器搬运工具层"。
6. `core ↛ cli`：i18n、配置模型、批量编排、进度/取消都属 `core`。`errors.rs:136` 的 `category()` 返回 `crate::i18n::Msg`，所以 i18n 必须在 `core` 之下，否则 `cli` 一关就编不过（见 §5.1）。

### 2.2 目录拓扑（含 v1 漏掉的模块落位）

```text
rust/src/
├── lib.rs                  # prelude + 按域门控的导出
├── facade.rs               # StrHide：.structure() / .stego() 子门面 + 文件级 I/O 策略
│
├── core/                   # 零格式耦合，也不依赖 cli
│   ├── crypto.rs           # AES-256-GCM、PBKDF2、HKDF、Deflate、SHA-256
│   ├── payload.rs          # PayloadSource / Payload / 紧凑元数据编解码
│   ├── io.rs               # SeekRead/SeekWrite、SegmentedSubStream、TmpGuard（原 commit.rs）
│   ├── params.rs           # MagicPair、CompressionStrategy、RejectionPolicy、LocalParams、Freshness
│   ├── control.rs          # ★ Progress / CancelToken / Stage（见 5.2）
│   ├── config.rs           # ★ Settings：配置模型与合并规则（不含路径发现）
│   ├── pipeline.rs         # ★ 批量编排：preflight、默认输出路径、overwrite 检查（见 5.1）
│   ├── i18n/               # ★ Msg 目录与 Lang（原 cli/i18n，errors.rs:136 依赖它）
│   └── errors.rs           # StrHideError + ErrorDetail
│
├── formats/
│   ├── sniff.rs            # 唯一格式真值源：FileFormat + sniff_bytes/sniff_stream
│   ├── capability.rs       # ★ 新增：能力表（见 2.3）
│   ├── isobmff/{mod,parser,iloc,stbl}.rs   # 三份合一
│   └── jpeg_segments.rs    # 原 src/jpeg/dqt.rs 迁入
│
├── structure/              # 原 engine + adapters + router
│   ├── mod.rs
│   ├── envelope.rs         # UBE v2.2 线格式 + 供 analysis 复用的公开常量
│   ├── engine.rs           # 剥离元数据编码与 stego 跨界调用后约 900 行
│   ├── params.rs           # ★ StructureProfile（见 3.5）
│   ├── rejection.rs
│   ├── registry.rs         # HostAdapter trait + ADAPTERS（原 router.rs）
│   └── adapters/           # eof/png/jpeg/webp/wav/heif/mp4/mkv/zip/pdf/pe*
│
├── stego/                  # 原样保留（不改名，理由见 §八）
│   ├── mod.rs              # 基于 StegoEngine 注册表调度，无 if-else
│   ├── traits.rs           # StegoEngine trait
│   ├── params.rs           # EmbedOptions / ProbeOptions / ExtractOptions / InspectOptions / VerifyOptions / StegoTuning / SafetyPolicy
│   ├── format.rs           # ★ 三个 FormatProfile + CipherSuite + GridRule（v1 漏项）
│   ├── envelope.rs         # 内容域信封（阶段 3 加微头）
│   ├── prng.rs
│   ├── io.rs               # ★ embed_carrier_file / extract_carrier_file（v1 漏项）
│   ├── header.rs           # ★ 64B FeatureWord 编解码（v1 误放 png/header.rs，JPEG V3 也在用）
│   ├── coding/{mod,stc}.rs
│   ├── png/{mod,codec,layout,engine}.rs + cost/{hill,suniward,wavelet}.rs + registry.rs
│   ├── jpeg/{mod,dht,geometry,header_v3,v3_layout,engine}.rs + cost/ + registry.rs
│   └── hevc/{mod,bitstream,slot,bridge,error,engine}.rs
│
├── analysis/{mod,structural,spatial_stats,dct_calibration}.rs
└── cli/{mod,args,cfg_paths,helpers,render,cmd_structure,cmd_stego,cmd_diag}
```

`cli/` 只做三件事：参数绑定（`args`）、配置路径发现与 TOML 解析（`cfg_paths`）、渲染（`render`，含 `RenderCtx { lang }`）。配置语义、批量编排、i18n 文案都在 `core/`，GUI 与 HTTP 服务可直接复用（见 §五）。

相对 v1 的三处修正：`stego/format.rs`、`stego/io.rs`、`stego/registry.rs`（拆成 `png/registry.rs` + `jpeg/registry.rs`）原先无家可归；`header.rs` 从 `png/` 提到 `stego/` 顶层。

### 2.3 单一能力表（先解决"三个事实源"）

现在能力信息散在 `HostAdapter::supports_content_stego`、`CarrierFormat`、以及 v1 新增的 `FileFormat::supports_*`。改为一张表：

```rust
// formats/capability.rs
pub struct Capability {
    pub format: FileFormat,
    pub structure: &'static [&'static str],   // 结构域策略族；空 = 不支持
    pub stego: &'static [StegoKind],          // 内容域引擎；空 = 不支持
    pub feature: &'static str,                // 缺 feature 时用于错误提示
}

pub enum StegoKind { PngSpatial, JpegDct, HevcCabac, HeifBridge }

pub static CAPABILITIES: &[Capability] = &[ /* 每格式一行 */ ];
```

四个消费者全部从表派生：

1. `HostAdapter` 注册表只保留"怎么读写"，策略列表由表校验（`debug_assert` + 一致性测试）；
2. `FileFormat::supports_structure()` / `supports_stego()`；
3. CLI `list` 输出（不再手写表格文案）；
4. 错误提示：`"ZIP supports the structure domain (use 'write'), not content steganography"`。

**删除** `stego::sniff::CarrierFormat`（0 调用点的死代码），公开 API 改用 `FileFormat`。

### 2.4 Feature 设计（可编译版）

> **落地状态（2026-10-27）**：`core-io` / `structure` / `content` / `analysis` / `config` / `cli` 六个开关已生效，四条最小构建零告警。下面表中的 `structure-base` / `structure-pe` / `content-png` / `content-jpeg` / `content-hevc` / `content-heif-bridge` **尚未暴露**——实测拆不动，卡在两项阶段 2 的前置工作（`Profile` 的方言拆分、`stego/format.rs` 对 jpeg 线常量的依赖），详见 §六 阶段 1 的进度注记。

```toml
[features]
# 库的默认值：两个域 + 分析，不含 cli（cargo add 不该拖 clap/toml/rpassword）。
# 实现时把 analysis 留在了默认集：它只多一个 jpeg-decoder，且是主打能力之一。
default = ["structure", "content", "analysis"]

# ── 地基 ──
core-io        = ["dep:filetime"]                 # TmpGuard、时间戳保留

# ── 结构域 ──
structure-base = ["core-io", "dep:serde_json"]    # serde_json 必需：engine.rs:431 的
                                                 # InspectResult.metadata: Option<serde_json::Value>
structure-pe   = ["structure-base", "dep:iced-x86"]
structure      = ["structure-base", "structure-pe"]

# ── 内容域 ──
content-base        = ["core-io", "dep:rayon"]
content-png         = ["content-base"]
content-jpeg        = ["content-base", "dep:dct-io"]
content-hevc        = ["content-base", "dep:oxideav-h265", "dep:rusty_h265"]
content-heif-bridge = ["content-hevc", "content-png", "content-jpeg"]

# ── 分析 ──
# 需要结构域（PE 代码位 + UBE 信封常量）与 DCT 读取（JPEG 盲校准直接用 dct-io），
# 但不需要内容域的嵌入引擎。
analysis = ["structure", "dep:jpeg-decoder", "dep:dct-io"]

# ── CLI ──
cli = ["structure", "content-png", "content-jpeg", "content-hevc", "content-heif-bridge",
       "analysis", "dep:clap", "dep:rpassword", "dep:toml", "dep:base64"]
```

三处关键修正：

1. **`structure-base` 补 `serde_json`**——否则 `--no-default-features --features structure-base` 直接编译失败。
2. **`analysis` 依赖 `structure` 而非 `structure-base`**——`analysis.rs:43` 用了 `pe_codebits`（iced-x86）。若将来要瘦身，再拆 `analysis-pe`。
3. **新增 `content-heif-bridge`**——`content-hevc` 对 png/jpeg 的依赖只来自 `stego/heif/thumb_bridge.rs:13-16`（桥接内嵌 JPEG/PNG 缩略图）与 `stego/registry.rs:21-22`。HEVC 引擎自身（CABAC/Annex-B/MP4）不需要它们。拆开后 `content-hevc` 单开即可编译，HEIF 的 Scheme C 主路径仍可用，桥接降级为可选。

验证目标（§七 CI）：`structure-base` / `content-png` / `content-jpeg` / `content-hevc` / `analysis` 五个最小构建全部独立可编。

### 2.5 命名决策

- `engine` → **`structure`**：`engine` 是无语义的通用词，且它同时是 feature 名，必须改。
- `stego` → **保持 `stego`**：v1 想改成 `content`。不改的理由：(a) `stego` 是领域标准词，`content` 并不更准确（HEVC CABAC 是码流域）；(b) 改名要动 13 个 example、6 处测试/文档里的 `stego::` 路径，收益是审美，成本是 2.3 万行测试面。若要对称命名，用 `media` 比 `content` 好，但仍列入 §八 不做清单。
- `Profile` → **`Dialect`**（见 3.5）。
- 门面访问器：`.structure()` / `.stego()`。

---

## 三、Library API 改造

### 3.1 门面与子门面

`facade` 移出 `#[cfg(feature = "engine")]`，改为"总是存在、方法按域门控"：

```rust
const ENGINE: StrHide = StrHide::new()
    .with_dialect(Dialect::new().with_default_secret("my-org-key"));

// 结构域
ENGINE.structure().write_file("carrier.png", PayloadSource::Text("secret"), &WriteOptions::default())?;
ENGINE.structure().read_file("carrier.png", &ReadOptions::default().with_password("pw"))?;
ENGINE.structure().restore_file("carrier.png", &RestoreOptions::default().with_overwrite(true))?;

// 内容域
ENGINE.stego().embed_file("photo.jpg", None, PayloadSource::Bytes(b"secret"), &EmbedOptions::default(), false)?;
let payload = ENGINE.stego().extract_file("photo.jpg", &ExtractOptions::default().with_password("pw"))?;
```

> ⚠️ **`ReadOptions` / `RestoreOptions` 今天并不存在**（只有 `engine.rs:582` 的 `WriteOptions<'a>`，读/还原走的是 `Option<&str>` + `bool`）。v1 的样例直接用了它们却没有任何阶段负责新建。本版把它们列进阶段 4 的交付物（§六），不许悬空。

子门面持有 `&StrHide`（`StrHide` 是 `Copy`，无生命周期负担），文件级 I/O 策略（`output_path` / `overwrite` / `backup` / `preserve_time`）只存在于这一层，不下沉到引擎 trait。

### 3.2 统一载荷类型（`core::payload`）

```rust
pub enum PayloadSource<'a> { Text(&'a str), File(&'a Path), Bytes(&'a [u8]) }

pub struct Payload<'a> {
    pub data: Cow<'a, [u8]>,
    pub kind: PayloadKind,          // Text | File
    pub name: Option<String>,       // 原文件名，NFC 归一化
}
```

内容域从 `&[u8]` 换成 `&Payload`，一次性解决 v1 §2.1 痛点 3 的"载荷不统一"。

**顺序约束**：阶段 2 就让 trait 接收 `&Payload`，但 `name` / `kind` 暂不写入线格式（此时文档明确标注"内容域暂不保存文件名"），阶段 3 加微头后才真正落盘。这样签名只变一次——v1 的写法（阶段 2 用 `&[u8]`、阶段 3 再加微头）必然二次改签名。

### 3.3 内容域引擎 trait

```rust
pub trait StegoEngine: Send + Sync {
    fn format(&self) -> FileFormat;

    fn probe(&self, carrier: &[u8], opts: &ProbeOptions<'_>, dialect: &StegoProfile)
        -> Result<CapacityInfo, StrHideError>;

    fn embed(&self, carrier: &[u8], payload: &Payload<'_>, opts: &EmbedOptions<'_>, dialect: &StegoProfile)
        -> Result<EmbedOutput, StrHideError>;

    fn extract(&self, carrier: &[u8], opts: &ExtractOptions<'_>, dialect: &StegoProfile)
        -> Result<Payload<'static>, StrHideError>;

    /// 只读特征头（成本极低：JPEG 718 个超块槽位 / PNG 512 个置换槽位），供双域 inspect 用
    fn inspect(&self, carrier: &[u8], opts: &InspectOptions<'_>, dialect: &StegoProfile)
        -> Result<StegoHeaderInfo, StrHideError>;

    /// 三级校验：容器语法 → 特征头/超块 → 矩阵解码 + AEAD Tag
    fn verify(&self, carrier: &[u8], opts: &VerifyOptions<'_>, dialect: &StegoProfile)
        -> Result<Vec<VerifyLevel>, StrHideError>;
}

pub struct EmbedOutput {
    pub bytes: Vec<u8>,
    pub capacity: Option<CapacityInfo>,   // PNG/JPEG 允许 None，不强制编造统计
    pub quality: Option<QualityStats>,
}
```

相对 v1 的四处修正：

1. **无 `detect()`**：分派一律走 `formats::sniff`，不造第二个格式真值源。
2. **无 I/O 参数**：`output_path` / `overwrite` 不在 `ExtractOptions` 里（v1 的 `ExtractOptions` 带 `output_path`，却喂给只返回 `Vec<u8>` 的 trait 方法，职责冲突）。
3. **补 `inspect` / `verify`**：v1 的阶段三和 v1 §4.2 都依赖 `content::inspect_header` 和三级校验，trait 里却没有这两个方法。
4. **`capacity` 可为 `None`**：v1 强制返回 `StegoCapacityInfo`，会逼 PNG/JPEG 造假数据。

### 3.4 参数强类型化

```rust
pub struct EmbedOptions<'a>   { password, domain, safety: SafetyPolicy, tuning: StegoTuning, freshness, exact,
                                control: Control<'a>, pool: Option<Arc<rayon::ThreadPool>> }
pub struct ProbeOptions<'a>   { password, domain, safety: SafetyPolicy, tuning: StegoTuning, exact,
                                control: Control<'a>, pool: Option<Arc<rayon::ThreadPool>> }
pub struct ExtractOptions<'a> { password, domain, limits: ExtractParams, control: Control<'a> }
pub struct InspectOptions<'a> { password, domain, limits: ExtractParams }
pub struct VerifyOptions<'a>  { password, domain, limits: ExtractParams, control: Control<'a> }

pub enum StegoTuning {
    #[default] Auto,
    Png  { algorithm: SpatialAlgorithm, params: PngParams },
    Jpeg { algorithm: JpegAlgorithm,    params: JpegParams },
    Hevc { mode: HevcMode,              params: HevcParams },
}

pub enum SpatialAlgorithm { Hill, Suniward, Custom(Arc<dyn PngCostModel>) }
pub enum JpegAlgorithm    { Uerd, Juniward, Custom(Arc<dyn JpegCostModel>) }
```

- 废除 `StegoOptions`（弱类型大泥球）。提取端不再被迫传写侧调优参数，`extract_carrier` 头部那句 `options.png_params.validate()?` 的误拦消失。
- `Custom(Arc<dyn …>)` 顺带补上 `ARCHITECTURE.md §8.2` 的"自定义代价模型无法注入"缺口。
- `HevcParams` 补齐（今天内容域根本没有 HEVC 参数结构），并修掉 **B1**：`safety: SafetyPolicy` 整体传入，`enforcement` 生效。
- `control` / `pool` 进 options 而非方法签名：GUI 的进度、取消、线程池注入因此不需要改 trait（见 §5.2 / §5.5）。结构域的 `WriteOptions` 同步加 `control`。

### 3.5 方言拆分（`Profile` → `Dialect`）

现状 `params::Profile`（`params.rs:408`）内嵌 `stego: StegoProfile`，而 `StegoProfile` 会返回 `Jpeg/Png/HevcFormatProfile`（`stego/format.rs`）——**它本身就是跨域大泥球**，也是 v1 把 `core/params.rs` 写成"零格式耦合"却做不到的根因。拆开：

```rust
// core/params.rs —— 只有基元
pub struct LocalParams { compression, rejection, chunk_size }

// structure/params.rs
pub struct StructureProfile { default_secret, stealth_domain, magic: Option<MagicPair> }

// stego/params.rs
pub struct StegoProfile { default_secret, domain, png: PngFormatProfile, jpeg: JpegFormatProfile, hevc: HevcFormatProfile }

// facade.rs —— 组合
pub struct Dialect { pub structure: StructureProfile, pub stego: StegoProfile }
impl Dialect { pub const fn with_default_secret(self, s: &'static str) -> Self } // 同时设置两半
```

`SafetyPolicy`（今天在 `stego/params.rs:208`）留在内容域，**不进 core**。

---

## 四、CLI 改造

### 4.1 双域诊断（保留 v1 方案，这是 CLI 侧最高价值项）

- `inspect <file> [-p pwd]`：先流式查结构域信封；未命中且格式支持内容域时，调 `stego::inspect` 只读特征头，命中则输出 `"content-domain payload found (JPEG V3, STC h=8 u=2, ciphertext 4,120 B)"`。
- `verify <file>`：按域走各自的校验链（结构域三级 / 内容域三级）。
- `read` / `extract` 未命中时探测另一域并给精确指引，另加 `--auto` 直接跨域提取。
- 聚合发生在 `cli/cmd_diag.rs`，**不是** `facade`：`facade` 只提供两个独立入口，避免把诊断策略下沉到库。

> 影响：`InspectResult.content_stego_capacity`（`engine.rs:437-439`）从结构域公开 API 移除，并入 CLI 侧聚合结构。`--json` 输出字段会发生一次变化（项目未发布，可接受，但需在 CHANGES 里写明）。

### 4.2 内容域微头（解决 `extracted.bin`）

在 `stego/envelope.rs` 的明文压缩前加微头：文本 `0x00`；文件 `0x01 | u8 name_len | name`；`--no-filename` 关闭。约 1–2 字节开销。

这是**线格式变更**，不是 CLI 功能，必须同 `docs/api/WIRE_SPEC.md` 一起改，并加互操作测试（有微头 / 无微头 / 空文件名三种）。

### 4.3 帮助分组与批量

- `--help` 按 `Container / Media Stego / Diagnostics` 三组展示（clap `help_heading`）。
- `--p1-window` 等归入 `PNG Spatial Tuning`；`--neighbor-weight` 等归入 `JPEG DCT Tuning`。
- `read` / `extract` 补多载体批量（`CARRIER...` + `-o <DIR>`），与其余 8 个命令对齐。
- `strhide.toml` 增 `[stego]` 段：`safety` / `enforce_safety` / `algorithm`。
- `list` 改为从 `CAPABILITIES` 渲染，删除手写表格文案。

### 4.4 交付形态：单 bin（决策记录）

维持单个 `strhide` 可执行文件，**不按域拆 bin**。三条硬证据：

1. 同一 package 内多 bin 的 feature 是**并集统一**的，`required-features` 只决定编不编，不产生依赖隔离；要隔离只能分 package（workspace）。
2. `cargo install strhide` 会把包内所有 bin 都装进 PATH。
3. 4.1 的双域诊断要求两个域在同一进程内；拆 bin 后只能子进程探测，密码要重复经 argv 传递（会漏进 `ps`），`--json` 聚合与退出码语义都要重定义。

若将来确有"只要容器域的精简产物"需求，两条路：workspace 拆包（library 包不带 h265），或 argv[0] 多调用名（同一二进制，`ln -s`/`cp`）。都不影响本版结构。

---

## 五、前端就绪层（CLI / GUI / 服务端共用）

**目标**：GUI 不是"再写一套 CLI"，而是 `cli/` 的兄弟消费者——共用同一套控制、结果、错误、配置与批量编排。本节为 v2 自查新增，起因是核对 GUI 需求时发现 v2 自身有一处层级错误。

### 5.1 归属修正（v2 自查）

`errors.rs:136` 的 `category()` 返回 `crate::i18n::Msg`，而 v2 原先把 i18n 放在 `cli/i18n`，由此产生两个后果：

1. `core → cli` 反向依赖，违反 §2.1 第 6 条；
2. `cargo build --no-default-features --features structure-base` 时 `cli` 被关掉，`errors.rs` 找不到 `i18n`——**直接编译失败**，与 §十 第 1 条同类。

所以 i18n、config、批量编排、控制信号一律下沉到 `core/`，`cli/` 只保留"参数绑定 + 渲染"。这也是 GUI 能复用它们的前提。

| 能力 | v2 原归属 | 本版归属 | GUI 为什么要 |
|---|---|---|---|
| i18n 文案与 `Msg` | `cli/i18n` | `core/i18n` | 错误与结果本地化 |
| 配置模型 `FileConfig` | `cli/config.rs` | `core/config.rs`（`Settings`）；`cli` 只留路径发现与 TOML 解析 | 同一份配置语义 |
| 批量编排（6 个函数） | `cli.rs:2253-2433` | `core/pipeline.rs` | 任务队列不重写，`.bak` 命名与默认输出目录不漂移 |
| 进度与取消 | 无 | `core/control.rs` | 进度条与取消按钮 |
| 结果结构 | `WriteResult`（字符串字段） | 结构化 + serde | 列表排序、分组、图表 |

### 5.2 进度与取消（`core/control.rs`）

现状：全库 0 处 progress/cancel。HEVC 一个 13.6 s 1080p60 载体要跑约 116 s、峰值 12 GB，GUI 无进度只能转圈，用户会当卡死强杀。

```rust
pub enum Stage { Read, Decode, CostMap, Solve, Encode, Write, Verify }
pub struct Event { pub stage: Stage, pub done: u64, pub total: Option<u64> }

pub trait Progress: Send + Sync { fn report(&self, ev: Event); }
pub struct NoProgress;
impl Progress for NoProgress { fn report(&self, _: Event) {} }

pub struct CancelToken(Arc<AtomicBool>);   // 可克隆，跨线程置位
pub struct Control<'a> { pub progress: &'a dyn Progress, pub cancel: Option<&'a CancelToken> }
impl Control<'_> { pub const fn none() -> Self; pub fn cancelled(&self) -> bool; }
```

约束：

- **放进 options，不做方法参数**：`EmbedOptions { control: Control<'a>, .. }`、`WriteOptions` 同。否则每加一个控制项就要改 6 个 trait 方法签名。
- **粒度到阶段**：引擎只需在阶段边界上报；取消检查点埋在"解码后 / 代价图后 / 编码前 / 每 N 个 block"。不强求进度条精确到字节——HEVC 一轮 CABAC 可能几十秒，阶段级上报已足够让用户判断"在动"。
- **取消不得 `process::exit`**：返回 `StrHideError::Cancelled`（新增变体），由 `TmpGuard` 的 drop 清理临时文件，保证不留半成品。
- 默认 `Control::none()`，CLI 的 `--quiet` 直接用默认值，行为不变。

### 5.3 结果与错误结构化

`WriteResult`（`engine.rs:343`）现在是"给人看的字符串"：`status`（恒 `"success"`）、`format`、`strategy`、`carrier` 全是 `String`，`media_info: Option<String>`（`"4032x3024"`）。GUI 要分组/排序/画图只能解析字符串。改为：

```rust
pub struct WriteResult {
    pub carrier: PathBuf,
    pub format: FileFormat,            // 原 String
    pub strategy: StrategyId,          // 原 String，对应 STRATEGY_REGISTRY 的数字 ID
    pub raw_size: u64, pub ube_size: u64,
    pub is_encrypted: bool, pub is_stealth: bool,
    pub backup_file: Option<PathBuf>,
    pub warning: Option<Warning>,      // 原 Option<String>，改枚举 + 参数
    // status 删除：返回 Ok 即成功
}

pub struct MediaInfo {
    pub width: u32, pub height: u32,
    pub fps: Option<f32>, pub duration_ms: Option<u64>, pub bitrate_bps: Option<u64>,
}
```

错误侧：`category()`（`errors.rs:136`）已返回 `Msg`，这点很好；但 `detail()`（`:154`）是预渲染英文。补一个结构化出口，保留 `Display` 给 CLI：

```rust
pub struct ErrorDetail { pub msg: Msg, pub args: Vec<(&'static str, String)> }
impl StrHideError { pub fn detail_i18n(&self) -> ErrorDetail; }   // GUI 用它 + Lang 查表
```

`--json` 输出按新结构体 serde 序列化，字段名一次定死（阶段 4 之后不再改）。

### 5.4 语言不再是 thread_local

`i18n/mod.rs:49` 是 `thread_local! { static CURRENT: Cell<Lang> }`，`set_lang` 只影响当前线程。GUI 在 UI 线程设中文，worker 线程渲染仍是英文。改成显式参数：`RenderCtx { lang: Lang }` 传进渲染函数；CLI 在 `run_cli_with` 里构造一次，GUI 各线程自带。不再保留进程级可变语言。

### 5.5 线程池与预览

- `EmbedOptions.pool: Option<Arc<rayon::ThreadPool>>`：内容域默认用全局池；GUI 想给 UI 留 CPU 时注入私有池（`rayon` 全局池只能设置一次，不可中途改）。
- `jpeg-decoder` 从 `analysis` 提到 `content-jpeg`（或独立 `preview` feature）：GUI 显示缩略图要解码，不该为此打开整个 analysis。

### 5.6 接入形态

| 形态 | 做法 | 约束 |
|---|---|---|
| Tauri / Electron | `cli/` 旁加 `ipc/`（或独立 bin），命令映射到 facade，进度走事件通道 | 不把 GUI 框架引入库 |
| 纯 Rust GUI（iced / egui） | 直接调 facade，长任务丢 `std::thread` + `Control` | `Send + Sync` 已满足 |
| HTTP 服务 | 直接用 `core::pipeline` + `Control` | 无需 `cli` feature |

**硬约束**：GUI 不得依赖 `cli` feature（否则要拖 clap / rpassword / toml）。这也是 §2.4 把 `cli` 与库能力分开的原因。

---

## 六、落地路线（阶段 0–4）

每阶段结束都必须满足 §七 全部护栏。工期为人日估算，含测试与文档。

### 阶段 0：基线冻结 + 三个独立缺陷（0.5–1 人日）

1. `scripts/baseline_hash.py --write`：对 `tests/fixtures` 与 `temp/testhevc` 每类载体跑 `write/read/restore` 与 `embed/extract`，把载体 sha256 + 载荷 sha256 写入 `temp/baseline/*.json`。**这是后续所有重构的唯一硬验收。**
2. 修 **B1**（HEVC `enforcement`）、**B2**（删 `CarrierFormat`）、**B3**（`facade` 补 `overwrite`）。三个独立 PR，互不依赖。
3. CI 加最小构建，先标 `continue-on-error: true`。阶段 0 只能用现存的 `--no-default-features --features engine` / `--features stego`（`structure-base` / `content-png` 到阶段 1 才存在），阶段 1 换成新 feature 名并转硬性。

> **状态（2026-10-27 12:23，已完成）**：基线 58 例冻结、684 项测试全绿、B1/B2/B3 已修，详见 `docs/CHANGES-20261027.md`。三条实测修正：① 两个最小构建当前**都能编过**（`engine`-only 有 3 条未使用告警：`MAX_CONTENT_STEGO_BYTES`、`OsString`、`PathBuf`），不是"红状态"；② CI 原先缺 `clippy -D warnings` 门禁（与 `AGENTS.md` 的声明不符），已一并补上；③ 内容域可比字节——`Freshness::Seeded` 早已存在但 CLI 未暴露，阶段 0 补了 `--seed`，基线据此对内容域产物做 sha256 比对（结构域信封 nonce 无种子开关，仍只比大小）。

### 阶段 1：formats 底盘 + 能力表 + feature 图 + core 下沉（3–4 人日）

1. 三处嗅探合并到 `formats/sniff.rs`，`FileFormat` 成为唯一枚举；`structure::registry` 与 `stego` 的分派逻辑统一改查 `CAPABILITIES`。
2. 建 `formats/capability.rs`；`HostAdapter` / `supports_*` / `list` / 错误提示改为派生。
3. 修 feature 图（§2.4 全表），验证最小构建独立可编。
4. **i18n 与配置模型下沉**：`cli/i18n` → `core/i18n`（`errors.rs:136` 依赖它，否则 `structure-base` 单独编不过）；`FileConfig` 的模型与合并规则 → `core/config.rs::Settings`，`cli/cfg_paths.rs` 只留路径发现与 TOML 解析。语言从 thread_local 改为显式 `RenderCtx { lang }`（§5.4）。
5. 只抽 `formats/isobmff/`（三份 3,585 行合一）。`png_chunks` / `riff` / `ebml` **暂不动**；仅把 `dqt.rs` 从顶层 `src/jpeg/` 迁入 `formats/jpeg_segments.rs`（它本来就是公共依赖）。
6. 验收：`baseline_hash.py --check` 全等；`analysis` 的 PE 扫描不回归；五个最小构建全绿。

> **阶段 1 收尾结论（2026-10-27 13:28）**
>
> **已完成**（三个提交，每个都以 `baseline_hash.py --check` 58/58 字节一致收口）：
> 1. `formats` 层：`FileFormat` + `sniff_bytes`/`sniff_stream` + `annexb` + `CAPABILITIES`；内容域 15 处手写魔数比较收成 3 次嗅探；删除 `HostAdapter::supports_content_stego`；`tests/test_lifecycle/sniff.rs` 把格式层 / 路由器 / 能力表钉在一起。
> 2. 结构域物理归位 `src/structure/`（`router`→`registry`、`adapters` 下移），i18n 与配置模型下沉 `src/core/`，`errors::category()` 去掉 cli 门控，`locale::detect` 与 config 解耦。
> 3. Feature 图重排：`engine`→`structure`、`stego`→`content`、新增 `core-io`/`config`；`default` 收窄为 `["structure","content","analysis"]`（不再拖 clap/toml/rpassword）；CI 测试带 `--all-features`，四条最小构建转硬性。
> 4. `dqt.rs` 迁入 `formats/jpeg_segments.rs`（原第 4 项的一部分）。
>
> **后移 / 明确不做**：
> - **按格式细分 feature 后移**。2026-10-27 实测发现它编不过：① `Profile` 无条件提供 `stego_secret()`/`png_format()`/`jpeg_format()`，任何单一内容格式都会连带需要整个内容域（需先做 §3.5 的 `Dialect` 拆分）；② `stego/format.rs` 直接从 `stego::jpeg::header_v3` 取 `SUPERBLOCK_BYTES`；`structure-base`（无 PE）同样卡在按 `feature = "structure"` 门控的 `Profile::locator_magic()` 等方法上。结论：**feature 细分必须排在阶段 2 的 `StegoEngine` 注册表与 `Dialect` 拆分之后**，否则只会放出"声明了但打不开"的开关。
> - **ISOBMFF 三份合一另开批次**。3,585 行、两域写语义不同，是全项目风险最高的一处；现有基线覆盖结构域 HEIF/MP4 共 44 例，但内容域 HEVC 路径需要额外语料回归（`--include-content-hevc`，单条 1080p60 约 100 s / 12 GB），不适合与目录改名混在同一批。


> **进度（2026-10-27 13:02）**：第 1、2 项**已完成**（`rust/src/formats/{sniff,annexb,capability,mod}.rs`，内容域三处瀑布改为单次 `sniff_bytes` 分派，删除 `HostAdapter::supports_content_stego` 及其 4 处覆写；新增 `tests/test_lifecycle/sniff.rs` 5 项一致性测试把"格式层 / 路由器 / 能力表"钉在一起）。698 项测试全绿、基线 58/58 不变。**未做**：第 3 项（feature 图 + `engine`→`structure` 改名 + i18n/config 下沉 `core`）、第 4 项（ISOBMFF 三份合一）——两者各自是一个独立提交，避免与本次结构改动混在一起。

### 阶段 2：内容域 trait 化 + 参数强类型 + 进度取消（4–5 人日）

1. `StegoEngine` trait（含 `inspect` / `verify`）+ 注册表，删掉 `stego/mod.rs` 三处 if-else。
2. `EmbedOptions` / `ProbeOptions` / `ExtractOptions` / `InspectOptions` / `VerifyOptions` / `StegoTuning`；删 `StegoOptions`，同步 13 个 example 与相关测试。
3. `Payload` 落地（`&[u8]` → `&Payload`），`name/kind` 暂不写线格式。
4. **进度与取消**：新建 `core/control.rs`（§5.2）；options 增加 `control` 与 `pool`；在三个引擎的"解码后 / 代价图后 / 编码前 / 每 N 个 block"埋 `cancelled()` 检查点，取消返回 `StrHideError::Cancelled`。
5. `registry.rs` 拆成 `png/registry.rs` + `jpeg/registry.rs`，切断 `content-hevc` 对 png/jpeg 的隐藏边；HEIF 桥接移入 `content-heif-bridge` 门控。
6. 验收：`cargo test --all-targets` 668 全绿；`cargo test local_ -- --ignored` 通过；基线全等（默认参数不变，字节不变）；取消测试（在 50% 处置位 → 返回 `Cancelled` 且不留临时文件）。

> **阶段 2 验收与收尾（2026-10-27 15:12）**
>
> **已完成（批次 1–4 提交）**：
> - 批次 1 (`33ba05c`)：`core/control.rs`（`Control`/`CancelToken`/`Stage`/`Event`）+ 统一 `core/payload.rs`（`Payload`/`PayloadKind`）；
> - 批次 2 (`d98797c`)：强类型 options（`EmbedOptions`/`ProbeOptions`/`ExtractOptions`/`StegoTuning`）+ `StegoEngine` trait + 引擎注册表 `engine_for`；彻底删除 `StegoOptions`；
> - 批次 3 (`1927689`)：PNG、JPEG、HEVC（Scheme C 与 HEIF 桥接）三个引擎全面埋入取消检查点与阶段上报（`Event::progress`）；新增 5 项取消与确定性单测；
> - 批次 4 (`8fa291f`)：`CostModelRegistry` 按域拆分为 `png/registry.rs` 与 `jpeg/registry.rs`，顶层改薄聚合。
> - **硬性验收全绿**：
>   1. `python scripts/baseline_hash.py --check`：**58/58 例与基线完全一致**（结构域还原逐字节一致，内容域哈希一致）；
>   2. `cargo test --all-features local_ -- --ignored`：**23 项重型语料测试全绿**（耗时 201 s，包含长视频 HEVC、真实 HEIF 照片、V3 JPEG 语料、STC 矩阵求解与 FFmpeg PSNR 校验）；
>   3. 取消与确定性测试全部通过。
>
> **批次 5（per-format feature 门控）实施落地完成（2026-10-27）**：
> - 抽离纯 std 的 `structure/adapters/pe_layout.rs`，解除 `pe_slack` 和 `analysis` 对 `iced-x86` 的硬依赖；
> - `stego/format.rs` 内收 `JPEG_SUPERBLOCK_BYTES = 44`，解除穿透引用；
> - `stego/options.rs`、`stego/registry.rs`、`stego/params.rs`、`stego/traits.rs`、`stego/header.rs`、`stego/engine.rs` 全面适配按格式 feature 条件编译；
> - `Cargo.toml` 开放细分 features 并将 H.265 相关重依赖标为 optional；
> - 5 条独立最小构建（`structure-base`, `content-png`, `content-jpeg`, `content-hevc`, `analysis`）全部零警告零错误通过；全量测试 293+87+18 项全绿；基线 58/58 例一致。

> **批次 5 实施清单（已全部落地）**：
> 1. [x] `Cargo.toml`：开放细分 features（`structure-base`、`structure-pe`、`content-base`、`content-png`、`content-jpeg`、`content-hevc`、`content-heif-bridge`）。
> 2. [x] 结构域 PE 拆分：抽离 `structure/adapters/pe_layout.rs`（纯 PE 节区与 slack 扫描，不引入 `iced-x86`），供 `pe_slack` 与 `analysis` 使用；`pe_codebits.rs` 仅留机器码反汇编并加 `#[cfg(feature = "structure-pe")]`；`structure/registry.rs` 相应门控。
> 3. [x] 内容域格式解耦：
>    - `stego/format.rs` 内收 `SUPERBLOCK_BYTES` 常量定义，切断对 `stego::jpeg` 内部常量的反向读取；
>    - `stego/heif/thumb_bridge.rs` 整体加 `#[cfg(feature = "content-heif-bridge")]`；`HeifEngine` 在无该 feature 时仅走 Scheme C；
> 4. [x] `options.rs` / `ResolvedTuning` 门控：
>    - `ResolvedTuning` 字段与 `resolve()` 填充按 `content-png`/`content-jpeg`/`content-hevc` 条件编译；
>    - `stego/registry.rs` 的 `list_algorithms()` 按启用 feature 聚合；
> 5. [x] `Profile` / `StegoProfile` 门控：
>    - `StegoProfile` 的 `jpeg`/`png`/`hevc` 字段与 `Profile` 上对应格式方法打上细分 feature 门控；
> 6. [x] `stego/engine.rs` 注册表动态切片：
>    - `ENGINES` 切片条目按 feature 门控，支持 0~5 个引擎组合；
> 7. [x] CI 验证：
>    - 验证 5 条最小构建独立可编：`structure-base`、`content-png`、`content-jpeg`、`content-hevc`、`analysis`。

### 阶段 3：微头 + 双域诊断（2–3 人日）

1. 微头（§4.2）+ `WIRE_SPEC.md` 更新 + 三种形态的互操作测试。
2. `inspect` / `verify` 双域、`read`/`extract` 互助提示与 `--auto`；`InspectResult` 移除 `content_stego_capacity`。
3. 验收：新增 CLI 集成测试 4 类载体 × 双域 ×（正确密码 / 错误密码 / 无密码）。

> **阶段 3 验收与收尾（2026-10-27 19:23）**
>
> **已完成（批次 1–4 提交）**：
> - 批次 1 (`6c67340`)：微头线格式（`MICRO_TAG_TEXT_OR_RAW = 0x00` 与 `MICRO_TAG_FILE = 0x01`）+ 原文件名安全净化与保留 + `Payload` 全链路打通 + HEVC/JPEG/PNG/HEIF-Bridge 统一支持微头；
> - 批次 2 (`e246e97`)：`structure/engine.rs` 彻底清除内容域反向探查代码与 `InspectResult.content_stego_capacity` / `media_info`，结构域纯正化；
> - 批次 3 (`51e5bac`)：`StegoEngine` trait 补齐 `inspect` 与 `verify`，5 个内容引擎（PNG、JPEG、HEIF、MP4、AnnexB）及缩略图桥接全量实现三级诊断校验；暴露顶层门面函数；
> - 批次 4 (`6a3d2b7`)：CLI 双域诊断聚合（`DualInspectResult` / `DualVerifyResult`）、跨域互助提示（结构域/内容域交叉误用指导）与 `--auto` 智能提取；
> - **硬性验收全绿**：
>   1. `python scripts/baseline_hash.py --check`：**58/58 例与基线完全一致**（结构域还原逐字节一致，内容域哈希一致）；
>   2. `cargo test --all-features local_ -- --ignored`：**23 项重型语料测试全绿**（耗时 193 s，包含长视频 HEVC、真实 HEIF 照片、V3 JPEG 语料、STC 矩阵求解与 FFmpeg PSNR 校验）；
>   3. `cargo test --all-features --all-targets` 全部通过；
>   4. 4 条独立最小构建（`--no-default-features`、`structure`、`content`、`analysis`）全部编译通过；
>   5. `cargo fmt --check` 与 `cargo clippy --all-targets --all-features -- -D warnings` 零告警通过。

### 阶段 4：门面 + 结果结构化 + CLI 收尾（4–5 人日）

1. `facade` 去门控、`.structure()` / `.stego()`；**新建 `ReadOptions` / `RestoreOptions`**；`Profile` → `Dialect`。
2. **结果与错误结构化**（§5.3）：`WriteResult` 的 `format`/`strategy`/`backup_file` 改强类型、删 `status`、`media_info` 改 `MediaInfo`；补 `StrHideError::detail_i18n()`；`--json` 按新结构定版。
3. **批量编排下沉**：`cli.rs:2253-2433` 的 6 个函数移入 `core/pipeline.rs`，CLI 只做参数绑定；GUI 与 HTTP 服务直接复用。
4. `cli.rs` 按 §2.2 拆模块；`[stego]` 配置段；批量读取；帮助分组；`jpeg-decoder` 提到 `content-jpeg`（§5.5）。
5. 文档同步：`lib.rs` 根导出修正（`embed`/`extract` 实际未导出、`PngParams`/`StegoOptions` 缺失）、`ARCHITECTURE.md`、`STEGO-API.md`、`WIRE_SPEC.md`、README 双份。
6. 验收：`cargo doc --no-deps --all-features` 无 warning；rustdoc 示例全部可编译；最小构建转硬性；GUI 冒烟（`Control` 上报进度 + 中途取消 + 中文错误渲染）。

---

## 七、验收与护栏（不靠自觉）

```bash
# 1. 基础三件套（CI 硬性）
cargo fmt --check
cargo clippy --all-targets --all-features -D warnings
cargo test --all-targets

# 2. 依赖隔离（阶段 1 起硬性）：每个 feature 独立可编
cargo build --no-default-features --features structure-base
cargo build --no-default-features --features content-png
cargo build --no-default-features --features content-jpeg
cargo build --no-default-features --features content-hevc
cargo build --no-default-features --features analysis

# 3. 边界 lint（新增 scripts/import_lint.py）
#    structure/** 不得 use crate::stego::*
#    stego/**     不得 use crate::structure::*
#    core/**      不得 use crate::{formats,structure,stego,cli}::*

# 4. 字节级回归
python scripts/baseline_hash.py --check
```

`local_` 批测沿用 `cargo test local_ -- --ignored`；注意内存峰值约 12 GB（见 `AGENTS.md`），跑批时不要并行其它重任务。

---

## 八、不做清单（Non-goals）

1. **不拆多 bin**（理由见 §4.4）。
2. **不做 `stego` → `content` 改名**：`stego` 是领域标准词，改名要动 2.3 万行测试面，收益是审美。只改无语义的 `engine` → `structure`。
3. **不把非重复解析搬进 `formats`**：`png_chunks` / `riff` / `ebml` / `jpeg_segments` 目前各只有一个消费者，等第二个消费者出现再抽（YAGNI）。
4. **不承诺 crates.io 发布**：crates.io 的 manifest 校验不接受 git 依赖，`optional = true` 不豁免；把 `oxideav-h265` / `rusty_h265` 挂到 feature 后面仍然 publish 失败，"vendor 到 workspace 子目录"也不行（path 依赖无版本被拒、带版本则要求该 crate 已发布）。可行路径只有：把两个 h265 包发布到 crates.io，或把 CLI 放进**不发布的** package。这两件事都不在本方案范围内。
5. **不改既有 wire format 字段**：除阶段 3 明确新增的微头外，信封字节布局不动。

---

## 九、风险

| 风险 | 影响 | 处置 |
|---|---|---|
| ISOBMFF 三份合一（3,585 行，两域写语义不同） | 静默改变注入偏移，产出不可还原的载体 | 阶段 1 单独做，基线 sha256 全等才算通过；`temp/testhevc` 语料全覆盖 |
| 删 `StegoOptions` 波及 668 个测试 + 13 个 example | 编译大面积红，掩盖真实回归 | 阶段 2 一次性完成，不跨阶段混改；先基线后改签名 |
| 微头改变内容域线格式 | 旧样本不可读（未发布，可接受） | `WIRE_SPEC.md` 同步；三形态互操作测试 |
| `--json` 字段变化（`content_stego_capacity` 移出） | 脚本解析失败 | CHANGES 明写；阶段 3 输出一次样例对比 |
| HEVC 批测内存 12 GB | 被 swap 拖住，像死锁 | 沿用 `AGENTS.md` 的跑测方式：日志重定向 + 轮询 |

---

## 十、勘误表（v1 → v2）

| # | v1 内容 | 问题（有源码证据） | v2 修正 |
|---|---|---|---|
| 1 | `structure-base = ["dep:filetime"]` | `engine.rs:431` 的 `InspectResult.metadata: Option<serde_json::Value>` 是结构域公开 API，缺 `serde_json` 编译失败 | 补 `dep:serde_json`（§2.4） |
| 2 | `analysis = ["structure-base", "dep:jpeg-decoder"]` | `analysis.rs` 用 `adapters::pe_codebits`（iced-x86）**且** `analysis/calibration.rs` 直接用 `dct-io`；只升到 `structure-base` 仍编不过 | 改依赖 `structure` + `dep:dct-io`（§2.4，2026-10-27 实测确认） |
| 3 | "隔离到 `content-hevc` 后主库即可满足 crates.io 发布校验" | optional 不豁免 git 依赖；path vendor 同样受阻 | 明确不承诺发布，列出两条可行路径（§八-4） |
| 4 | `analysis` 在 DAG 里只依赖 `formats`/`core` | `analysis.rs:43-44` 依赖 `adapters::pe_*` 与 `envelope` 常量 | DAG 允许 `analysis → structure`，写明理由（§2.1） |
| 5 | `core/params.rs` 装 `Profile`、`SafetyPolicy` | `params.rs:408-437` 的 `Profile` 内嵌 `StegoProfile`（→ `stego/format.rs`）；`SafetyPolicy` 在 `stego/params.rs:208` | `Profile` 拆成 `StructureProfile` + `StegoProfile` + `Dialect`；`SafetyPolicy` 留内容域（§3.5） |
| 6 | `ExtractOptions` 含 `output_path`/`overwrite`，又喂给返回 `Vec<u8>` 的 trait | 格式引擎不该管落盘策略 | I/O 只留 facade/CLI，trait 只收凭据与上限（§3.3） |
| 7 | trait `embed(payload: &[u8])`，阶段三再加微头 | 与 §2.1 痛点 3（载荷不统一）冲突，签名要改两次 | 阶段 2 即收 `&Payload`，微头只改线格式（§3.2） |
| 8 | trait 无 `inspect` / `verify` | v1 §4.2 与阶段三都依赖 `content::inspect_header` 和三级校验 | trait 补 `inspect` / `verify`（§3.3） |
| 9 | trait 有 `detect()` + `format()` + `Formats::sniff` | 又造三个格式真值源 | 删 `detect`，分派统一走 `sniff`（§3.3、§2.3） |
| 10 | `content-hevc = [.. "content-jpeg", "content-png"]` | 边只来自 `heif/thumb_bridge.rs:13-16` 与 `registry.rs:21-22` | 新增 `content-heif-bridge`，`content-hevc` 独立可编（§2.4） |
| 11 | `default = ["structure","content","analysis","cli"]` | `cargo add strhide` 仍拖 clap/iced-x86/两个 h265 仓库——正是 v1 批判的问题 | `default = ["structure","content-png","content-jpeg"]`（§2.4） |
| 12 | 目标树缺 `stego/format.rs`、`io.rs`、`registry.rs`；`header.rs` 放进 `png/` | 这四者有实际内容（722/105/270/430 行），且 `header.rs` 被 JPEG V3 共用 | 逐一落位（§2.2） |
| 13 | 阶段一/二各"1~2 天" | 含 3,585 行 ISOBMFF 合一 + 2.3 万行测试面改动 | 重估为 14–18 人日（§六） |
| 14 | 验收仅"测试全绿" | 无字节级基线、无边界强制手段 | 加 `baseline_hash.py` + 最小构建 + import lint（§七） |
| 15 | 行数表：`hevc/engine.rs` 1,644、`mp4_boxes.rs` 859 | 实测 1,899 / 867，基线已漂移 | 更新表格，并提示动手前重新 baseline（§1.3） |
| 16 | CLI 方案未表态交付形态 | 双域诊断与多 bin 互斥 | 明确单 bin + 决策记录（§4.4） |
| 17 | i18n 放在 `cli/i18n` | `errors.rs:136` 的 `category()` 返回 `crate::i18n::Msg` → `core → cli` 反向依赖；关掉 `cli` 后 `structure-base` 编译失败 | i18n / config / pipeline / control 一并下沉 `core/`（§5.1、§2.1 第 6 条） |
| 18 | 无进度与取消、结果为字符串、语言为 thread_local | GUI 无法显示进度/取消；`WriteResult` 字段全是 `String`；`i18n/mod.rs:49` 的 `set_lang` 只影响当前线程 | 新增 §五：`core/control`、结构化结果与错误、`RenderCtx`、线程池注入（§5.2–5.5） |

> 第 17–18 条是 v2 自查发现的**自身**缺陷（v1 没有这两处提法），正文已按此修订。
