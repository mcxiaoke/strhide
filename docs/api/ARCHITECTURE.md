# strhide 架构与公开 API 说明

> 适用版本：crate `strhide` 0.6.x（Rust 实现，`rust/`）。
> 本文描述模块职责、分层关系、公开 API 与内部数据流转，所有结论均按当前源码核对。
> 配套文档：
> - [WIRE_SPEC.md](./WIRE_SPEC.md) — UBE v2.2 二进制线格式规范；
> - 上层背景：`docs/strhide_facade_api_evaluation_and_industry_standards_20261022.md`（Facade 方案评估与业界标准）、`docs/library_extensibility_and_public_api_audit_20261020.md`、`docs/library_api_practical_plan_20261020.md`。

---

## 目录

1. [设计支柱](#1-设计支柱)
2. [分层架构](#2-分层架构)
3. [Crate 模块拓扑](#3-crate-模块拓扑)
4. [公开 API 全景](#4-公开-api-全景)
5. [核心数据流转](#5-核心数据流转)
6. [参数分级模型：L class 与 P class](#6-参数分级模型l-class-与-p-class)
7. [适配器与策略体系](#7-适配器与策略体系)
8. [扩展点与当前边界](#8-扩展点与当前边界)
9. [稳定性约定](#9-稳定性约定)

---

## 1. 设计支柱

strhide 的全部架构决策围绕四条支柱，理解它们比记住单个函数更重要：

1. **格式保持（Format-preserving）**：隐写载体的可见格式、渲染结果与程序行为不变。载体如何被修改由对应格式的 `HostAdapter` 决定，引擎本身不解析任何容器格式。
2. **无损可还原（Lossless / restorable）**：写入时在信封内记录原始载体的尺寸与 SHA-256；剥离（remove/restore）时重算并逐项比对，**任何不一致都拒绝提交**，不会产出半还原的文件。
3. **统一加密（Uniformly encrypted）**：载荷与元数据始终经 AES-256-GCM 密封。即使调用方不提供密码，也使用一个内置公开密钥加密，hex 视图中不出现明文。`FLAG_ENCRYPTED` 的含义是"需要用户密码"，而非"是否加密"。
4. **拒绝优先（Rejection-first）**：写入前先做安全检查——带签名的 PE/PDF/JAR、只读目标、不支持的 APK、不可写目录，在任何字节落盘之前拒绝。

---

## 2. 分层架构

```text
┌──────────────────────────────────────────────────────────────────┐
│  调用方：CLI（main.rs → cli.rs）  /  外部库使用者（your crate）   │
└───────────────┬──────────────────────────────────────────────────┘
                ▼
┌──────────────────────────────────────────────────────────────────┐
│  facade：StrHide（推荐入口，绑定一个 Profile + LocalParams）       │
│  普通方法转发到 engine / stego；run_cli_from 驱动私有 CLI          │
└───────────────┬──────────────────────────────────┬───────────────┘
                │ 结构域（structure domain）         │ 内容域（content domain）
                ▼                                   ▼
┌───────────────────────────────┐       ┌───────────────────────────┐
│  engine（高层编排，公开 API）   │       │  stego（内容自适应隐写）    │
│  write / read / remove /       │       │  embed / extract / probe  │
│  inspect / verify              │       │  StegoOptions / Params    │
└───────┬──────────────┬────────┘       └───────────┬───────────────┘
        │              │                            │
        ▼              ▼                            ▼
┌──────────────┐ ┌─────────────┐        ┌───────────────────────────┐
│  router      │ │  rejection  │        │  stego 子模块：            │
│  格式嗅探     │ │  预写安全检查 │        │  spatial / jpeg / hevc    │
│  策略名↔ID    │ └─────────────┘        │  heif / coding / traits   │
└──────┬───────┘                        │  registry / envelope /    │
       ▼                                │  header / prng            │
┌──────────────────────────────┐        └───────────┬───────────────┘
│  adapters（HostAdapter）      │                     │
│  PNG/JPEG/WEBP/HEIF/MP4/WAV/  │                     │
│  ZIP/PDF/PE/MKV + eof 等      │                     │
└───────┬──────────────────────┘                     │
        │                                            │ 共用底层原语
        ▼                                            ▼
┌──────────────────────────────┐        ┌───────────────────────────┐
│  envelope（UBE v2.2 结构）    │        │  crypto（AEAD/KDF/压缩）    │
└───────┬──────────────────────┘        │  params（Local/Profile）   │
        │                               │  errors（StrHideError）    │
        └──────────────────────────────▶└───────────────────────────┘
```

两个域彼此独立：

- **结构域**把一个完整的 UBE 信封（有头、有尾、有魔数）放进容器的结构性空隙（私有 chunk、段、盒子、目录前间隙等），入口在 [`engine`]。
- **内容域**把数据嵌入图像像素（PNG）、DCT 系数（JPEG）或 H.265/HEVC 变换系数旁路符号位（HEIF/HEIC 与 HEVC Annex-B），没有结构化信封，入口在 [`stego`]。

两域共用底层 [`crypto`]、[`errors`]、[`params`]，但**密钥派生域相互隔离，且信封格式本身就是两套不同结构**（结构域 UBE 有头/尾/元数据，内容域是极简伪随机微信封），互不可读。差异清单见 [WIRE_SPEC §1.1](./WIRE_SPEC.md#11-两种信封格式对比重要)，内容域机制见 [§7.3](#73-内容域隐写)。

**Facade（[`facade`]）是推荐入口，位于调用方与 engine/stego 之间。** 一个 `StrHide` 实例在构造时绑定一个方言 [`Profile`] 和一个写侧基线 [`LocalParams`]，然后把每个动词（write/read/restore/inspect/verify、embed/extract/probe）作为普通方法转发到现有自由函数，每个方法 1–3 行。它不引入新的协议、不持有可变状态，且 `StrHide` 是 `Copy`。这与业界成熟库的形态一致（OpenStego 构造时绑定 config 后调用普通 `embedData`/`extractData`；reqwest 构造持有配置的 `Client` 后调用方法）。需要直接使用自由函数的调用方仍可绕过 facade，两套入口长期共存。

---

## 3. Crate 模块拓扑

`src/lib.rs` 公开导出以下模块。按"是否属于稳定公开契约"分为两类：

### 3.1 公开 API 模块（库使用者主要接触）

| 模块 | 职责 | 关键类型 / 入口 |
|---|---|---|
| [`facade`] | 推荐入口：绑定一个方言 + 写侧基线，动词作为普通方法 | `StrHide`、`new`/`with_profile`/`with_local_params`、`run_cli_from` |
| [`engine`] | 结构域高层编排：写入、读取、剥离、检查、验证 | `write_carrier*`、`read_carrier*`、`remove_carrier*`、`inspect_carrier*`、`verify_carrier*`、`PayloadSource`、`WriteOptions`、各 `*Result` |
| [`stego`] | 内容域自适应隐写：嵌入、提取、容量探测（PNG/JPEG/HEIF/HEVC） | `embed_carrier*`、`extract_carrier*`、`probe_carrier_capacity`、`StegoOptions`、`PngParams`、`JpegParams`、`StegoCapacityInfo` |
| [`params`] | 调参旋钮与私有方言 | `LocalParams`、`Profile`、`StegoProfile`、`MagicPair`、`CompressionStrategy`、`RejectionPolicy` |
| [`adapters`] | `HostAdapter` trait 与各格式实现；容器 I/O 辅助 | `HostAdapter`、`StrategyCapacity`、`SeekRead`、`SeekWrite`、`SegmentedSubStream` |
| [`envelope`] | UBE v2.2 二进制结构与序列化 | `EnvelopeHeader`、`EnvelopeTrailer`、各尺寸/标志常量 |
| [`crypto`] | 加密、KDF、压缩、哈希原语 | `derive_keys`、`encrypt_stream_to_chunks`、`decrypt_stream_from_chunks`、`compress_stream`、`decompress_stream`、`derive_stealth_magics` |
| [`router`] | 格式嗅探与策略名 ↔ ID 路由 | `find_adapter*`、`ADAPTERS`、`STRATEGY_REGISTRY`、`strategy_to_id`、`id_to_strategy` |
| [`rejection`] | 预写安全检查 | `run_rejection_checks`、`check_content`、`check_pe_authenticode`、`check_pdf_signature`、`check_jar_signature` |
| [`errors`] | 全 crate 唯一错误类型 | `StrHideError` |

### 3.2 内部管线模块（主要服务二进制，不建议外部依赖其内部细节）

| 模块 | 职责 |
|---|---|
| [`cli`] | clap 命令定义、子命令分发、输出渲染（库使用者无需调用） |
| [`config`] | TOML 配置文件读写（`strhide.toml`） |
| [`analysis`] | 载体分析/扫描的内部实现 |
| [`i18n`] / [`cli_i18n`] | 消息国际化（中英文）与 CLI 文案 |
| [`jpeg`] | JPEG 量化表（DQT）解析辅助 |

> 注意：当前所有模块均以 `pub mod` 导出，内部模块**可见但不代表稳定 API**。需要稳定承诺的面应以 [§9](#9-稳定性约定) 为准；`StrHideError` 与各 `*` 类型的演进见各自文档。

---

## 4. 公开 API 全景

所有 fallible 函数返回 `Result<T, StrHideError>`。每个操作都提供三种 I/O 形态：

- **plain**：历史默认签名（官方方言、默认本地参数），最简洁；
- **`_with` / `_with_profile`**：文件路径 + 完整配置（`LocalParams` + `Profile`）；
- **`_bytes`**：内存字节（`&[u8]` → `Vec<u8>`），服务 Web/微服务场景。

### 4.0 推荐入口：StrHide（facade）

新接入的库使用者应优先使用 `StrHide`：构造一次（整个方言可在编译期声明为 `const`），然后在实例上调用动词。它把绑定的 `Profile`/`LocalParams` 自动转发给底层自由函数，无需在每个调用点重复传参。

```rust
use strhide::engine::{PayloadSource, WriteOptions};
use strhide::facade::StrHide;
use strhide::params::Profile;

// 整个私有方言在编译期声明，零运行时开销。
const ENGINE: StrHide = StrHide::new()
    .with_profile(Profile::new().with_default_secret("my-deployment-key"));

// 结构域（bytes 形态）：
let (stego, _) = ENGINE.write_bytes(
    &cover,
    PayloadSource::Bytes(b"secret"),
    &WriteOptions::default(),
)?;
let read = ENGINE.read_bytes(&stego, None)?;
assert_eq!(read.data, b"secret");

// 内容域（bytes 形态）：
let stego = ENGINE.embed(&jpeg, b"secret", &Default::default())?;
let payload = ENGINE.extract(&stego, &Default::default())?;
assert_eq!(payload, b"secret");
```

`StrHide` 还提供 `run_cli_from(argv)`，用绑定的方言驱动一套私有命令行，返回退出码而不调用 `std::process::exit`（见 [§4.4](#44-命令行入口run_cli_from)）。下表 §4.1–§4.2 列出 facade 转发的全部自由函数，需要绕开 facade 直接调用时可参考。

### 4.1 结构域（engine）

| 操作 | 入口 | 说明 |
|---|---|---|
| 写入 | `write_carrier(path, source, options)` | 官方方言、默认本地参数 |
|  | `write_carrier_with(path, source, options, local, profile)` | 完整配置；temp 文件 + 原子 rename |
|  | `write_carrier_bytes(carrier, source, options, local, profile)` | 内存写入，返回 `(Vec<u8>, WriteResult)` |
| 读取 | `read_carrier(path, out, password)` | 提取载荷（out 为 None 时在内存返回 ReadResult.data，为 Some 时写入文件） |
|  | `read_carrier_with(path, out, password, overwrite)` | 允许覆盖已存在输出文件 |
|  | `read_carrier_with_profile(path, out, password, overwrite, profile)` | 指定方言 |
|  | `read_carrier_bytes(carrier, password, profile)` | 内存读取，返回 ReadResult |
| 剥离 | `remove_carrier(path, out, password, backup)` | 剥离信封并还原载体 |
|  | `remove_carrier_with(path, out, password, backup, profile)` | 指定方言 |
|  | `remove_carrier_bytes(carrier, password, profile)` | 内存剥离，返回 `(Vec<u8>, RemoveResult)` |
| 检查 | `inspect_carrier(path, password)` | 只读：格式、信封、元数据、各策略容量 |
|  | `inspect_carrier_with(path, password, profile)` | 指定方言 |
| 验证 | `verify_carrier(path, password)` | 三级独立校验 |
|  | `verify_carrier_with(path, password, profile)` | 指定方言 |

### 4.2 内容域（stego）

| 操作 | 入口 |
|---|---|
| 嵌入 | `embed_carrier(carrier_bytes, payload, options)` |
|  | `embed_carrier_with_profile(carrier_bytes, payload, options, profile)` |
| 提取 | `extract_carrier(carrier_bytes, options)` |
|  | `extract_carrier_with_profile(carrier_bytes, options, profile)` |
| 容量 | `probe_carrier_capacity(carrier_bytes, options)` |
|  | `probe_carrier_capacity_with_profile(carrier_bytes, options, profile)` |

### 4.3 核心配置类型

```rust
// 载荷来源（engine）
pub enum PayloadSource<'a> {
    Bytes(&'a [u8]),          // 原始字节，文件名 payload.bin
    File(&'a Path),           // 文件，basename 作为存储文件名
    Text(&'a str),            // 文本，写入前做 NFC 归一化
    Stdin,                    // 从 stdin 读到 EOF（仅第一次读取有数据）
    Buffered { data: &'a [u8], filename: &'a str, is_file: bool },
}

// 写入选项（engine）；Default 与 CLI 默认一致
pub struct WriteOptions<'a> {
    pub output_path: Option<&'a Path>, // 不原地覆盖，写到指定路径
    pub password: Option<&'a str>,
    pub password_hint: Option<&'a str>, // 与 stealth 互斥，最长 1024
    pub strategy: &'a str,             // 策略名或 "auto"
    pub stealth: bool,                  // 密码派生魔数，需 password
    pub preserve_time: bool,           // 克隆原载体时间戳
    pub backup: bool,                  // 原地写入保留 <carrier>.bak
}

// 内容域选项（stego）
pub struct StegoOptions {
    pub algorithm: Option<String>,         // "hill" / "suniward" / "uerd" / "juniward" / "hevc" / "cabac" / "auto"
    pub password: Option<String>,
    pub domain: Option<String>,            // 派生隔离域标签（与 Profile::stego_domain 级联）
    pub safety: SafetyPolicy,             // 容量安全策略（level + enforcement，单一事实源）
    pub freshness: Freshness,              // 随机新鲜度（Random [默认] / Seeded([u8; 32]) 可复现运行）
    pub png_params: PngParams,             // PNG 调优（codec/stc_h/stc_u/exclusion_rate/滤波窗口）
    pub jpeg_params: JpegParams,           // JPEG DCT 调优（stc_h/slot_budget/cipher_suite/polarize_weight）
    pub extract_params: ExtractParams,     // 提取策略（allowed_suites/max_pbkdf2_iterations）
}
```

返回类型：`WriteResult`、`ReadResult`、`InspectResult`、`VerifyResult`（含三级 `LevelStatus`）、`RemoveResult`、`StegoCapacityInfo`。各字段含义见源码 doc 注释与 [WIRE_SPEC.md](./WIRE_SPEC.md)。

### 4.4 命令行入口（run_cli_from）

`StrHide::run_cli_from(argv)` 让一个嵌入式宿主用绑定的方言驱动完整的 strhide 命令行：

- 接收任意可迭代的参数（元素可转为 `OsString`），**第一个元素必须是程序名**（与 `std::env::args_os()` 一致，clap 用它生成帮助与错误输出）；
- 返回进程退出码（`i32`），**不调用 `std::process::exit`**，宿主自行决定如何处理退出码；
- 绑在 engine 上的 `Profile`/`LocalParams` 替换 CLI 内部原本硬编码的官方默认；显式 CLI 参数仍优先于绑定配置。

```rust
use strhide::facade::StrHide;

const ENGINE: StrHide = StrHide::new(); // 或绑定私有方言

// 宿主自己的 main：
let exit_code = ENGINE.run_cli_from(std::env::args_os());
std::process::exit(exit_code);
```

官方二进制的 `main.rs` 正是这样委托：`cli::run_cli()` 内部等价于 `StrHide::new().run_cli_from(std::env::args_os())`。

---

## 5. 核心数据流转

### 5.1 写入流程

文件路径的外层职责（`write_carrier_with`）与协议本身（`write_core`）被刻意分开，使 `write_carrier_bytes` 能复用同一协议。

**`write_carrier_with`（文件层）：**

```text
1. 存在性检查
2. run_rejection_checks(carrier, target, local.rejection)   ← 安全检查
3. 记录原权限 / atime / mtime
4. 创建 <target>.strhide.tmp（TmpGuard 负责异常时清理）
5. write_core(host, out_file, ...)                          ← 协议
6. （原地写入且 backup）复制 <carrier>.bak
7. rename(tmp → target)（原子提交）
8. 还原权限；preserve_time 时还原时间戳
```

**`write_core`（协议层，I/O 无关）：**

```text
 1. local.validate()；校验 hint/stealth 互斥、stealth 必须有密码
 2. 采集载体事实：orig_host_size、orig_host_sha256（流式哈希）
 3. find_adapter_or_reject → adapter；多重 locate 扫描确认载体未被占用
    （本方言魔数；私有方言再扫官方魔数；有密码再扫 stealth 魔数）
    suspicious_structures 产出结构告警（不拒绝）
 4. source.into_buffered() → (payload bytes, filename, is_file)
 5. raw deflate 压缩；按 local.compression 决定保留压缩还是原文
 6. 生成 salt / base_nonce；derive_keys(effective_password, salt)
    按 stealth 与否决定魔数：derive_stealth_magics 或 profile.*_magic
 7. 构造 CarrierMetadata → encode_metadata（compact 布局），置 FLAG_COMPACT_META
 8. 精确预算 UBE 尺寸（含每 chunk 20B 开销）；auto 时 choose_auto_strategy
 9. 构造 EnvelopeHeader；encrypt_metadata；encrypt_stream_to_chunks
    组装完整 UBE（header + hint + meta + payload + 占位 trailer）
10. adapter.inject(...) → (inject_offset, inject_size, patch_offset, orig_patch_val)
    envelope_offset_delta 修正实际 UBE 起点
11. 非散落策略：回写最终 header、trailer；adapter.finalize（如重算 CRC）
    返回 WriteCoreResult
```

关键事实：

- UBE 尺寸在注入前**精确预算**，并在加密后与实际字节数交叉核对，不一致即报 `Internal envelope size mismatch`。
- **散落策略**（scattered，目前仅 `pe_codebits`）在 `inject` 时已写入最终信封字节，没有连续文件偏移，引擎不再按偏移回写 header/trailer。

### 5.2 读取流程（read_core）

```text
1. find_adapter_or_reject → adapter
2. locate_envelope：
   - 有密码：先用 derive_stealth_magics(pwd, domain) 的 trailer 魔数 locate
   - 再用 profile 本方言魔数 locate（官方方言还接受历史魔数）
3. adapter.open_ube_reader(...) → 虚拟 UBE 流（散落/多段策略在此透明拼接）
4. 读 112B header → EnvelopeHeader::unpack_with_password/profile（含去掩码）
5. validate_against(ube_total_size)
6. 有 hint 则读取
7. 派生密钥：
   - FLAG_ENCRYPTED：必须有密码，derive_keys(password, salt)
   - 否则：derive_keys(profile.secret(), salt)
8. 读 meta 块 → decrypt_metadata → decode_metadata（compact）
9. 由 ube_total_size 与各长度字段算出 payload 区域字节数
10. decrypt_stream_from_chunks（按长度前缀自定界，不假设 chunk 大小）
11. FLAG_COMPRESSED 则 decompress_stream（以 meta.raw_size 为硬膨胀上限）
12. 重算载荷 SHA-256，必须与 meta.raw_sha256 一致
```

### 5.3 剥离流程（remove_core）

```text
1. find_adapter_or_reject → adapter
2. locate_envelope（同读取）
3. open_ube_reader → 读 header → unpack_with_profile → validate_against
4. adapter.strip(host, out, &header)
   默认实现：复制 inject_offset 前的字节 → 跳过注入区 → 复制剩余字节
   → 回滚 patch_offset 处的原始值（坐标按注入尺寸平移）
5. （外层）verify_restored：重算还原载体的 size / SHA-256，
   与 header.orig_host_size / orig_host_sha256 比对
```

- 还原载体与记录不一致时丢弃结果并返回 `RestoreMismatch`。常见原因：载体上叠了第二个信封，必须按注入的**逆序**（最近写入的先剥离）逐层移除；错误信息会附带该诊断。
- 非 stealth 信封无论是否提供密码都可剥离；stealth 信封需要写入时的密码才能定位。

### 5.4 检查与验证

- **inspect**（只读，不修改载体）：报告格式、是否找到信封、策略、偏移、标志、密码提示、原始尺寸/哈希、解密后的元数据，以及**每个策略在当前载体上的容量**（字段 `strategies: Vec<StrategyCapacity>`）；PNG/JPEG 还附内容域容量 `content_stego_capacity`。没有信封时返回 `has_hidden_data = false`，不视为错误。
- **verify**（三级相互独立）：
  - Level 1 宿主结构完整性（如 PNG CRC、ZIP 中央目录、PE 头），与方言无关；
  - Level 2 信封头/尾定位与内部一致性（版本、长度、CRC、偏移）；
  - Level 3 载荷可解密且 SHA-256 与元数据一致。

### 5.5 内容域嵌入 / 提取

```text
embed（PNG→spatial，JPEG→jpeg）：
 1. validate png/jpeg params
 2. 解析载体 → 候选元素（像素 / DCT 系数）
 3. StegoOptions.secret(profile)：显式密码优先，否则 profile 的 stego 私钥
 4. pack_envelope_ext(payload, secret)
    → 微信封字节（salt/nonce/密文）+ perm_seed
 5. 候选集合做 keyed permutation：前 256 个槽位承载 32B header
    （避免"最便宜的 256 槽位"成为公开指纹）；body 按代价顺序取剩余槽位
 6. header 直接 LSB 匹配；body 经矩阵编码（Hamming 或 STC），
    空间域用 ternary ±1 匹配（八值类约束，保持代价排序可复现）

extract：
 重建 keyed permutation → 定位 256 个 header 槽位 → 读 32B header
 → 解码 header word（长度/codec/h/u）→ 重建 body 槽位 → 矩阵解码 → 微信封解封
```

---

## 6. 参数分级模型：L class 与 P class

`params.rs` 按**"谁必须知道这个参数"**（而非读/写方向）划分两类，从类型层面消除"写时设置、读时忘记"的失败模式。

### 6.1 L class — LocalParams（仅写侧行为）

只影响本次调用怎么做，**不进入信封、不影响互读性**。读取方永远不需要，随意变化不会导致载体不可读。

```rust
pub struct LocalParams {
    pub chunk_size: usize,                 // 明文/AEAD 分块，默认 2 MiB，上限 64 MiB
    pub compression: CompressionStrategy,  // 压缩决策
    pub rejection: RejectionPolicy,        // 预写检查粒度
}
```

- `CompressionStrategy`：`Auto`（默认，节省 ≥2% 才保留，level 6）、`Never`、`Always { level }`（0..=9）。
- `RejectionPolicy`：`Strict`（默认，全部检查）、`ContentOnly`（只做结构/签名检查，跳过文件系统检查——内存载体所需）、`Skip`（全部跳过，调用方自负其责）。
- 读取侧不依赖 `chunk_size`：分块由 4 字节长度前缀自定界，尾块由字节预算识别。

### 6.2 P class — Profile（读写必须一致的方言）

定义信封属于**哪种私有方言**，不随线格式传输；读写必须给同一个 `Profile`，不匹配则按设计不可读（stealth 下甚至不可见）。`Profile::default()` 是官方方言，与所有版本字节兼容。

```rust
pub struct Profile {
    pub default_secret: Option<&'static str>,       // 无密码时的结构域信封密钥
    pub stealth_domain: Option<&'static [u8]>,      // stealth 魔数派生域
    pub magic: Option<MagicPair>,                    // 自定义头/尾魔数
    pub stego: StegoProfile,                         // 内容域（见下）
}

pub struct StegoProfile {
    pub default_secret: Option<&'static str>,        // 无密码时的图像隐写私钥
    pub stego_domain: Option<&'static str>,          // 图像隐写 HKDF 域标签
    pub format: Option<JpegFormatProfile>,               // 私有 JPEG V3 线格式身份（None=官方）
}
```

**所有字段都是 `'static` 借用或 `Copy` 值，因此整个方言可以在编译期用 `const fn` 链式构造，零运行时开销：**

```rust
const MY_DIALECT: Profile = Profile::new()
    .with_default_secret("my-structure-secret")
    .with_stealth_domain(b"my-stealth-domain")
    .with_stego_secret("my-stego-secret")
    .with_stego_domain("my-stego-domain");
```

之所以用 `&'static` 而非 `Cow<'static, _>`，是因为 `const fn` 中对 `Cow` 字段做 `mut self` 赋值会触发 E0493（`Cow` 析构无法在编译期求值，跟踪 rust-lang/rust#133214）；`&'static` 是 `Copy`，链式赋值可在编译期完成。代价是方言不能在运行时用 `String`/`Vec` 动态构造——运行时凭据（CLI/env/config）应通过 `WriteOptions`/`StegoOptions` 传入，不进 Profile。

- **`default_secret` 与 `stego_domain` 是对库使用者价值最高的旋钮**：
  - 使用公开内置常量时，任何人持任何 strhide 都能读无密码信封；替换为私钥后，线格式一个字节都不变，但没有私钥读不出来。显式密码始终优先于此值。
  - `stego_domain` 实现 HKDF 子密钥化域隔离（NFC 规范化 + 长度前缀防拼接），不同团队或系统即使密码相同也无法互读，杜绝开源共享指纹暴露。
- 自定义 `magic` 在 stealth 下被忽略（stealth 的魔数由密码派生，固定魔数会破坏可否认性）。
- 私有 `JpegFormatProfile`（`stego.jpeg`）决定超块/扩展几何与槽位网格，设置后官方二进制无法读取，与私钥等效；`jpeg_format()` 在未设置时回退 `DEFAULT_JPEG_FORMAT`。
- `Profile::is_official()` 同时检查两个域：结构域字段（`default_secret`/`stealth_domain`/`magic`）与内容域的私钥、`stego_domain`、`format`，任一设置即非官方。

### 6.3 内容域密钥与域解析

- `StegoOptions::secret(profile)`：显式密码（非空）优先，否则取 `profile.stego_secret()`，都没有则在微信封层回落到公开常量。空字符串密码被视为"未提供"，不会掩盖 profile 私钥。
- `StegoOptions::domain(profile)`：显式 `stego_domain` 优先，否则取 `profile.stego_domain()`，未配置则走官方默认派生分支。
- `SafetyLevel`：容量安全三档（`High` 默认 $\le 0.10$ bpp / $r \ge 6.9$；`Balanced` $\le 0.15$ bpp / $r \ge 4.6$；`Paranoid` $\le 0.06$ bpp / $r \ge 11.5$）。
- `SafetyEnforcement`：默认 `Advisory`（超限报警不阻断）；指定 `Enforced` 时若载荷超标则安全拒绝。

---

## 7. 适配器与策略体系

### 7.1 结构域适配器与策略

引擎不解析容器，全部委托给 `HostAdapter`。当前内置 10 种格式适配器（`router::ADAPTERS`，顺序即检测优先级）：

| 适配器 | `format_name` | 支持策略（按优先级） |
|---|---|---|
| `PngAdapter` | `PNG` | `chunk`、`eof` |
| `JpegAdapter` | `JPEG` | `app_segment`、`eof` |
| `WebpAdapter` | `WEBP` | `riff_chunk`、`eof` |
| `HeifAdapter` | `HEIF` | `item_hidden`、`free_box`、`box_uuid`、`eof` |
| `Mp4Adapter` | `MP4` | `box_uuid`、`eof` |
| `WavAdapter` | `WAV` | `riff_chunk`、`eof` |
| `ZipAdapter` | `ZIP` | `pre_cd_inject`、`eof` |
| `PdfAdapter` | `PDF` | `incremental`、`eof` |
| `PeAdapter` | `PE` | `pe_codebits`、`pe_slack`、`pe_overlay`、`eof` |
| `MkvAdapter` | `MKV` | `ebml_void`、`eof` |

- `strategy = "auto"`（默认）由 `choose_auto_strategy` 按 UBE 尺寸选主策略，放不下时透明回退 `eof`；回退会在 `strategy_note` 中说明。
- `EofAdapter` 是各载体共用的兜底策略（在 EOF 后追加），**不在** `ADAPTERS` 中作为格式捕获器；无法识别的文件会被拒绝，而不是被静默追加。

### 7.2 HostAdapter 能力面

`HostAdapter` trait 要求/提供：

- `format_name` / `detect` / `supported_strategies` / `choose_auto_strategy`；
- `strategy_capacities(reader)`：各策略容量（按推荐优先级）；`reader=None` 回答"该格式支持什么"，`Some` 回答"此载体能装多少"；
- `inject`：把 UBE 注入载体，返回注入偏移/尺寸与补丁信息；
- `locate`：在载体中定位信封（可指定期望的 trailer 魔数）；
- `strip`：剥离信封并还原（默认实现通用，格式可覆盖）；
- `verify_structure` / `suspicious_structures`；
- `open_ube_reader`：在 UBE 上打开虚拟 `SeekRead`（多段链/散落策略在此透明拼接）；
- `envelope_offset_delta` / `trailer_offset` / `finalize` / `is_scattered_strategy` / `strategy_note`。

### 7.3 内容域隐写

内容域当前支持三大体系架构与可复现工程保障：

1. **空间域（PNG，Scheme A）**：
   - **算法支持**：由 `CostModelRegistry` 解析：默认/`hill` → `HillCostModel`（wire id 1）；`suniward` → `SuniwardCostModel`（wire id 2，自适应连续访存与 SIMD FMA 加速）。未知名**明确拒绝**。
   - **参数自描述同步**：提取端自动从 `FeatureWord.algorithm_id` 与 `FeatureWord.exclusion_permille` 提取算法 ID 与排除分位数，原生支持自定义 `--exclusion-rate`。
   - **矩阵编码 `StegoCodec`**：`Hamming`（(7,3)，每块至多动 1 槽）或 `Stc`（全局 Viterbi 网格，最小化代价加权失真，支持分组 u）；`Auto`（默认）按容量/载荷自适应选择 STC 分组或回退。
   - **数值与边界约束**：像素值限制在 `[8, 247]`，采用 ternary ±1 匹配与八值类（`val & 0xF8`）约束，保证提取侧代价排序完全复现。
   - **并行 Deflate 重编码**：利用纯 Rust SIMD（`zlib-rs`）结合 Rayon 按扫描线整行切分并发压缩，大图（14.8 MP）重编码耗时由 4 秒降低至 380 毫秒（提速 10.5 倍）。

2. **DCT 频域（JPEG，Scheme B）**：
   - **算法支持**：默认/`uerd` → `UerdCostModel`；`juniward` → `JuniwardCostModel`（多线程并行化与 Wiener 降噪两趟方差防溢出）。
   - **固定网格真三元 STC（V3 协议）**：对全图所有 AC 位置（`k = 1..63`）计价并构建几何网格，提取无需代价图与重排序。
   - **校准与分析加速**：`analysis/calibration` 盲校准采用单趟直方图重构，大幅缩减分析耗时并杜绝数值溢出。
   - **44 字节超块**与套件 KDF 分层密钥派生，支持可选 TLV 扩展区与三种密码套件。

3. **HEIF 容器桥接与 CABAC 旁路域（Scheme B / Scheme C）**：
   - **载体识别与自动路由**：统一入口 `embed_carrier` / `extract_carrier` / `probe_carrier_capacity` 自动探测 ISOBMFF 结构中的 HEVC 图像项与原始 Annex-B 裸码流。HEIF 上三者同序：**先方案 C，失败再落方案 B**（桥接是早期方案，保留为兜底通道），因此"某个载体里读到的载荷"恒等于"写入端会产出的那份"。
   - **方案 C（CABAC 旁路符号位原位隐写）**：HEIF/HEIC 的默认路径，也是不支持桥接的纯 HEVC 码流唯一路径。
     - **旁路符号位编码（Bypass Coding）**：针对 H.265 变换系数的符号位（`coeff_sign_flag`，等概率 Bypass 模式，不影响上下文概率状态机更新），改变残差正负极性而不破坏宏块语法，感知失真极低。
     - **零尺寸膨胀（$\Delta = 0$）与 EPB 避让**：直接在压缩比特流内部就地修改。通过至多 24 轮迭代检验，将破坏 `0x000000..=03` 防竞争窗口的冲突槽位置为无穷大代价（Cost = $\infty$）重新求解，确保文件尺寸 100% 绝对守恒。
     - **空间均衡抽样（Weyl 离散置换）**：通过确定性互质步长离散抽样，避免载荷全量压在连拍首图导致局部画质失衡。
     - **外部解耦与 Observer**：通过 `rust_h265` 的 `CabacObserver` 截获 bin 流与系数，通过 `oxideav-h265` 进行精确重编。
   - **方案 B（内嵌缩略图桥接 `thumb_bridge`，兜底通道）**：当方案 C 不可用（无 HEVC 项、slice 语法不受支持）而容器包含独立 JPEG Item、未压缩像素项或 Exif TIFF IFD1 缩略图时，自动切片并桥接至 JPEG/空间域引擎，修补 Exif 与 `iloc`/`mdat` 偏移，**主图 100% bit-exact 零失真**。该性质是桥接自身的契约，只能在桥接 API 上验证（路由层会先走方案 C 并改动主图）。

4. **可复现嵌入机制（Freshness）**：
   - 支持 `Freshness::Random`（默认）与 `Freshness::Seeded([u8; 32])`。
   - 在 Seeded 模式下，salt、nonce 与 payload 均由主种子经 HKDF-SHA256 派生；同时强制浮点代价图走标量内核（避免 AVX2 FMA 舍入差异导致 slot 抖动），实现跨机器/跨 CI 的逐字节确定性可复现。

---

## 8. 扩展点与当前边界

### 8.1 已支持的定制

| 能力 | 入口 | 类别 |
|---|---|---|
| 调整分块大小 | `LocalParams::with_chunk_size` | L |
| 压缩开关 / 等级 | `LocalParams::with_compression` | L |
| 安全检查粒度 | `LocalParams::with_rejection` | L |
| 无密码信封私钥 | `Profile::with_default_secret` | P |
| stealth 派生域 | `Profile::with_stealth_domain` | P |
| 自定义头/尾魔数 | `Profile::with_magic` | P |
| 内容域无密码私钥 | `Profile::with_stego_secret` | P |
| 内容域 HKDF 域标签 | `Profile::with_stego_domain` | P |
| 私有图像线格式身份 | `Profile::with_jpeg_format` | P |
| 可复现随机源 / 确定性测试 | `StegoOptions.freshness = Freshness::Seeded` | Stego |
| 空间域成本模型选择 | `StegoOptions.algorithm = "hill"` / `"suniward"` | Stego |
| JPEG 频域成本模型选择 | `StegoOptions.algorithm = "uerd"` / `"juniward"` | Stego |
| HEIF 结构域隐藏策略 | `-s item_hidden` / `-s free_box` | 结构域 |
| 统一门面（绑定方言 + 基线） | `StrHide::new` / `with_profile` / `with_local_params` | Facade |
| 私有命令行 | `StrHide::run_cli_from` | Facade |
| 内存（免落盘）处理 | `*_carrier_bytes` | I/O |
| 实现代价模型 trait | `PngCostModel` / `JpegCostModel` | 扩展 |

### 8.2 当前边界（按设计不做或暂缓）

- **HostAdapter 动态注册**：`router::ADAPTERS` 与 `find_adapter` 目前是静态切片，自定义格式适配器无法在运行时注册进引擎。
- **代价模型经统一入口注入**：`StegoOptions` 目前通过 `algorithm` 名称匹配，没有 trait 对象直接注入字段；外部实现的 `PngCostModel/JpegCostModel` 可直接传给 `png/jpeg` 子模块的内部函数，但无法仅通过 `embed_carrier` 名称入口生效。
- **策略 ID 段**：`STRATEGY_REGISTRY` 中 1–13 为官方保留（`MAX_KNOWN_STRATEGY_ID = 13`）；解掩码启发式会把未知 ID 当噪声。
- **协议级参数不可配**：加密套件（仅 AES-256-GCM）、PBKDF2 轮数（100 000）、压缩算法（仅 raw deflate）、自定义元数据字段均为线格式常量，本期不开放（详见审计文档 §3.1 / §4.5）。

> 上述边界随版本演进可能调整；以最新源码与审计/计划文档为准。

---

## 9. 稳定性约定

- 所有 fallible 入口统一返回 `StrHideError`，变体按失败类别粗粒度划分，便于按判别式分支而非字符串匹配。
- 错误信息与国际化：`StrHideError::detail()` 与 `Display` 始终提供稳定的英文底层诊断；CLI 层通过 `StrHideError::category()`（返回 `Option<crate::i18n::Msg>`）挂接中/英双语本地化前缀。库调用者无需关心 i18n 内部机制。
- 多个公开枚举/结构体（`LocalParams`、`Profile`、`CompressionStrategy`、`RejectionPolicy` 等）标注 `#[non_exhaustive]`：下游应使用 `default()` + setter 构建，避免结构体字面量；未来新增字段/变体不构成破坏性变更。
- 线格式（UBE v2.2）的稳定性与读写兼容关系见 [WIRE_SPEC.md](./WIRE_SPEC.md) 的兼容矩阵。
- 可运行示例：`rust/examples/`（`in_memory`、`private_profile`、`codec_bench`）；公共 API 文档中的代码块由 `cargo test --doc` 守护，示例由 `cargo build --examples` 守护。
- **推荐入口是 `StrHide`（facade）**：新接入的库使用者应构造 `StrHide` 并调用其方法，而非直接调用多个自由函数；facade 是薄转发层，底层自由函数仍公开并长期维护，二者不构成两套互斥的 API。
- 方言字段使用 `'static` 借用以支持 `const fn` 编译期构造；不提供运行时 `String`/`Vec` 构造方言的能力，运行时凭据走 `WriteOptions`/`StegoOptions`。

---

[`engine`]: ../../rust/src/engine.rs
[`facade`]: ../../rust/src/facade.rs
[`stego`]: ../../rust/src/stego/mod.rs
[`params`]: ../../rust/src/params.rs
[`adapters`]: ../../rust/src/adapters/mod.rs
[`envelope`]: ../../rust/src/envelope.rs
[`crypto`]: ../../rust/src/crypto.rs
[`router`]: ../../rust/src/router.rs
[`rejection`]: ../../rust/src/rejection.rs
[`errors`]: ../../rust/src/errors.rs
[`cli`]: ../../rust/src/cli.rs
[`config`]: ../../rust/src/config.rs
[`analysis`]: ../../rust/src/analysis.rs
[`i18n`]: ../../rust/src/i18n/mod.rs
[`cli_i18n`]: ../../rust/src/cli_i18n.rs
[`jpeg`]: ../../rust/src/jpeg/mod.rs
[`hevc`]: ../../rust/src/stego/hevc/mod.rs
[`heif`]: ../../rust/src/stego/heif.rs
