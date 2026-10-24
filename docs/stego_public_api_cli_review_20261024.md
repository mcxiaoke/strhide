# stego 模块库接口 / CLI 参数 / 文档全面梳理与改进方案

> **编制时间**：2026-10-24 20:46（本机时间）；**20:57 补充复核**：新增 HEVC（Scheme C）专项缺失（A11–A17、H 批方案）——该路径未接入 Profile/Params 定制体系，且存在免密码存在性预言机。
> **范围**：`rust/src/stego/**` 公共接口、`rust/src/cli.rs` 中 embed/extract 相关参数、`rust/src/config.rs` 配置键、`docs/api/*`、README（中英）、`strhide.sample.toml`，以及第三方消费方 `C:\Home\Projects\CarrotHash`（`src/stego/*`）的实际用法。
> **方法**：逐文件读码 + 与 CarrotHash 调用点对照 + git 历史核对文档漂移。本文只做梳理与方案，未改任何代码。

---

## 0. 结论先行

stego 的**功能实现与质量（测试/clippy/批测）是全仓库最扎实的部分**，但它的**对外形状**已经明显落后于功能增长，问题集中在四类：

| 类别 | 数量 | 代表问题 |
|---|---|---|
| **混乱**（多个入口/多份事实源，调用方无法判断该用哪个） | 6 处 | 根级 `strhide::embed` 其实是 JPEG 专用；`safety_level` 三处重复存储；clap help 与 i18n 双份文案 |
| **应统一**（同一概念多条路径，优先级隐式） | 4 处 | `StegoOptions` 顶层值静默覆盖 `spatial/jpeg_params` 同名字段；`stego_domain` 运行时/Profile 双路径 |
| **应规范**（公开面没有分层，内部件外泄） | 3 处 | ~361 个 pub 项中大部分是内部原语（prng/wavelet/coding/hevc slot）；`pub use rust_h265 as h265` 把整个 git 依赖暴露进 strhide 命名空间 |
| **应精简**（CLI 把库的专家级旋钮全部公开） | 2 处 | embed 7 个 tuning flag 无分层；`--codec`/`--stc-u` 已删但 README 仍在宣传 |
| **缺失（20:57 补充）** | **7 处** | **HEVC（Scheme C）整条路径没有 Profile/Params 定制**：私有方言密钥被统一入口静默丢弃；静态魔数 `SH25` + 免密码 header 定位构成存在性预言机；第三份公开默认密钥常量；WIRE_SPEC §13.11 与代码三处漂移 |

**一句话方案**：库收敛为「稳定面（6 个入口 + 6 个配置类型）/ 专家面（domain engine + traits，支持第三方编译期与运行期定制）/ 内部面（doc(hidden)）」三层；CLI 收敛为「日常 / 专家 / 隐藏」三层并把 tuning  flag 压缩到 4 个以内进日常层；文档以 `docs/api/STEGO-API.md` 为单一事实源，README 与 sample.toml 的漂移项本轮修掉。**HEVC 需按 H 批专项补齐定制轴（格式 Profile 等价物 + secret/domain 接入 + 魔数派生化），否则"私有编译期定制"对 HEIC/HEVC 载体完全落空。**

---

## 1. 现状全景

### 1.1 库公开面盘点（`strhide::stego`，约 361 个 pub 项）

按职责分六组：

| 组 | 内容 | 评价 |
|---|---|---|
| **统一入口**（`stego/mod.rs`） | `embed_carrier` / `embed_carrier_with_profile` / `extract_carrier` / `extract_carrier_with_profile` / `probe_carrier_capacity` / `probe_carrier_capacity_with_profile` + `StegoCapacityInfo` | 形状正确，格式嗅探 + Profile 方言 + safety 注入都在这里。**应作为唯一推荐面** |
| **域引擎入口**（`stego/spatial`、`stego/jpeg`、`stego/heif`、`stego/hevc`） | spatial 7 个（`embed_spatial` → `_with_profile` → `_with_profile_and_freshness` 三层委托 + extract/probe 同构）、jpeg 5 个、heif 3 个（bridge，正确接收 `options`+`profile`）、hevc 3 个（`embed_hevc`/`extract_hevc` **只收 `password: Option<&str>`**，`probe_hevc_capacity` 只收 carrier）；另有 `decode_png`/`encode_png`/`RawImage`/`PngChunk` | 层层委托的"无 profile 变体"是历史遗留；`spatial/mod.rs` 的 `pub use` 把它们提到与统一入口同一命名空间，**该调哪个无法自明**。**HEVC 是唯一不接收 Profile/StegoOptions 的域**（见 A11–A17） |
| **配置类型**（`stego/params.rs`） | `StegoOptions`（9 字段）、`SpatialParams`（11）、`JpegParams`（11）、`ExtractParams`（2）、`StegoCodec`、`SafetyLevel`、`SafetyEnforcement`、`Freshness`、4 个预算常量 + 2 个函数 | 字段多且**同名概念跨 3 个结构体重复**（见 A1）；**没有任何 HEVC 参数结构体**（h/u/魔数/salt/标签全是 `hevc/engine.rs` 内的模块常量，见 A14） |
| **格式身份**（`stego/format.rs`） | `FormatProfile`（14 字段）、`SpatialFormatProfile`、`GridRule`、`CipherSuite`/`Kdf`/`Aead`、`SUITES`、`DEFAULT_FORMAT`、`OFFICIAL_SPATIAL` | **私有编译期定制的核心**，CarrotHash 用的就是这批。设计正确，应保持公开。**但没有 HEVC 等价物**——Scheme C 的派生标签/魔数/STC 参数无处安放（见 A11/A14） |
| **注册表与 trait**（`registry.rs`、`traits.rs`） | `CostModelRegistry`（6 方法 + 2 wire id 常量）、`SpatialCostModel`、`JpegCostModel`、`JpegGeometry` | trait 公开 = 邀请第三方实现，**但统一入口不接受 trait 对象**（见 A9） |
| **内部原语**（`coding`、`envelope`、`header`、`prng`、`wavelet`、`jpeg/{dht,header_v3,v3_layout,geometry}`、`hevc/{slot,bitstream,heif_boxes,sniff}`、`hevc::h265`） | StcTrellis、ChaCha12Stream、fisher_yates_*、HPDF/TAPS、derive_* 密钥原语、Superblock/Tlv、CabacRecorder/BinOp、`pub use rust_h265 as h265` | **全部应降级为非稳定面**：对库使用者无价值，且 `h265` re-export 把不受 strhide 控制的 git 依赖 API 暴露进公开命名空间 |

根级 `lib.rs` 另有：`pub use stego::jpeg::engine::{embed_jpeg as embed, extract_jpeg as extract}`（**名字极具误导性，见 A2**）、`UerdCostModel`、`JpegCostModel`、`ExtractParams`、`JpegParams`、format 五件套。

### 1.2 CLI 参数盘点（embed / extract）

| 参数 | embed | extract | 备注 |
|---|---|---|---|
| `-a/--algorithm` | ✅ | ✅ | 取值 `auto\|hill\|suniward\|uerd\|juniward\|hevc\|cabac`；**extract 侧对 PNG/JPEG 实际无效**（见 B3） |
| `--stego-secret` / `--stego-secret` env / config | ✅ | ✅ | 与结构域 `--password` 平行的 P 类凭据 |
| `--stego-domain` / env / config | ✅ | ✅ | 同上 |
| `--safety` / `--enforce-safety` | ✅ | ❌ | 合理（容量概念只属于 embed/probe） |
| `--exclusion-rate` | ✅（有 help） | ✅（**无 help 文案**） | 见 B5 |
| `--neighbor-weight` | ✅ | ✅（无 help） | 同上 |
| `--p1-window` / `--p2-window` | ✅ | ✅（无 help） | 同上 |
| `--stc-h` | ✅ | ❌ | 实际不需要（feature word 自描述），但 embed 帮助未说明 |
| `--slot-budget` | ✅ | ❌ | 帮助文本 4 行，专家级 |
| `--cipher-suite` | ✅ | ❌ | 协议套件选择，专家级 |
| `--capacity` | ✅ | — | 探测后退出 |
| `--codec` / `--stc-u` | **已删除**（commit `8e5ac34`） | — | **README 仍在宣传**（见 C1） |

配置键（`config.rs`）：仅 `stego_secret` / `stego_domain`；**`strhide.sample.toml` 完全未提 `stego_domain`/`STRHIDE_STEGO_DOMAIN`**（见 C4）。

### 1.3 CarrotHash（第三方编译期定制）实际用法

`CarrotHash/src/stego/` 用到的公开面：`params::Profile`（`with_stego_secret` / `with_stego_domain` / `with_format_profile` / `with_spatial_profile`）、`stego::format::{FormatProfile, GridRule, SpatialFormatProfile, SUITES}`、`stego::{embed_carrier_with_profile, extract_carrier_with_profile, probe_carrier_capacity_with_profile}`、`stego::{StegoOptions, SafetyLevel, SafetyEnforcement}`。

**被迫自建的部分**（说明库面向第三方宿主还缺什么）：

1. `SafetyLevel` 的数字别名解析（`"0"/"1"/"2"`）——库的 `SafetyLevel::parse` 只认英文单词（A6）；
2. **4 处手工同步 safety**（`options` + `spatial_params` + `jpeg_params`，见 A1）；
3. 整套文件 I/O：临时文件 + rename 原子提交、`.bak.N` 递增备份、时间戳克隆、输出命名——`facade::StrHide::embed_file` 已提供其中大部分，但**备份命名/输出命名不可定制**，宿主只能绕回裸 `embed_carrier_with_profile` 自建（A10）。

---

## 2. 问题清单

> 分级：**P0 = 已产生错误行为或文档说谎**；**P1 = 调用方脚枪/明显混乱**；**P2 = 规范性与体验**。

### A. 库接口

#### A1【P1】`safety_level` / `safety_enforcement` 三处存储，顶层静默覆盖 params

`StegoOptions`、`SpatialParams`、`JpegParams` 各有一对 `safety_level` / `safety_enforcement`。`stego/mod.rs:72-78` 在统一入口里用顶层值**无条件覆盖**两个 params 的值：

```rust
let mut spatial_params = options.spatial_params.clone();
spatial_params.safety_level = options.safety_level;      // 顶层赢
spatial_params.safety_enforcement = options.safety_enforcement;
```

后果：
- 经统一入口时 `SpatialParams::safety_level` 是**只写字段**（设了也被覆盖），只有直接调 `embed_spatial_with_profile_and_freshness` 才生效（`spatial/engine.rs:1165` 直读 params）；
- CarrotHash 设了 4 个地方（`options.rs:49-52`），其中 3 处是无效功；
- 反向脚枪：库用户只设 `spatial_params.safety_level = Enforced` 以为启用了强制，实际被顶层默认 `Advisory` 静默覆盖——**安全策略静默失效**。

#### A2【P0】根级 `strhide::embed` / `strhide::extract` 是 JPEG 专用，名字像通用入口

`lib.rs:170`：`pub use stego::jpeg::engine::{embed_jpeg as embed, extract_jpeg as extract};`。`strhide::embed(carrier, payload, password, domain, format, params, cost_model)` 七参、只吃 JPEG，却占据 crate 根最通用的名字；而真正的通用入口叫 `stego::embed_carrier_with_profile`。`lib.rs` 文档虽注明 "the JPEG entry points a private build calls with its own profile"，但**新用户按名字选错入口的概率极高**，且两个入口的签名/语义完全不一致（一个吃 `FormatProfile`+`&dyn 模型`，一个吃 `StegoOptions`）。

#### A3【P1】domain engine 的"无 profile 变体"是历史遗留，与统一入口命名空间冲突

`embed_spatial` / `embed_jpeg` / `extract_spatial` / `extract_jpeg` / `probe_spatial_capacity` / `probe_jpeg_capacity` 六个函数只是委托 `OFFICIAL_*` / `DEFAULT_FORMAT` 的薄壳。项目未发布，无兼容负担；它们与 `embed_carrier*` 同处 `stego::` 命名空间（经 `spatial/mod.rs`、`jpeg/mod.rs` 的 `pub use` 提升），造成"统一入口 vs 域入口"该选谁的困惑。

#### A4【P1】`-a/--algorithm` 在 extract 侧对 PNG/JPEG 是死参数，且能产生误导性错误

`extract_carrier_with_profile` 对 PNG 仍走 `CostModelRegistry::get_spatial_model(options.algorithm)`：传 `-a uerd` 提 PNG → 报 `Unknown or incompatible spatial stego algorithm`；传 `-a hill` 提取 juniward 载体 → **不报错但不生效**（`spatial/engine.rs:1494-1501`：carrier 的 feature word 权威，调用方模型只是 hint，只写 trace）。JPEG 提取则完全不看 algorithm（几何槽位）。唯一真实用途是 `-a hevc|cabac` 强制 Scheme C、跳过 HEIF bridge。**一个 90% 情况是死参数的 flag 挂在最显眼的位置。**

#### A5【P1】`stego_domain` 双路径（StegoOptions 运行时 vs Profile 静态），优先级靠文档维持

`StegoOptions::domain(profile)`：显式 `stego_domain` 赢 → profile 的 `stego_domain` → None。CLI 把 flag/env/config 的值塞进 `options.stego_domain`（`cli.rs:2040`），而 CarrotHash 走 profile。两条路径本身合理（运行时凭据 vs 编译期方言），但**文档没有一张"谁赢"的表**，且 `--stego-domain` 与 `Profile::stego.stego_domain` 同名不同源，和 2026-10-20 已经修掉的 `StegoOptions::default_secret` / `Profile::default_secret` 双源是同一类问题的一半。

#### A6【P2】`SafetyLevel::parse` 不接受数字别名，第三方各自实现

CarrotHash `options.rs:24-33` 自己 match 了 `"0"/"1"/"2"`。库侧 `parse` 只认 `paranoid/high/balanced`。要么库扩 `FromStr`（含数字），要么在文档给出推荐 match 范式。

#### A7【P2】`ExtractParams` 只被 JPEG 解码器消费，但无文档明示

`allowed_suites` / `max_pbkdf2_iterations` 仅 `jpeg::extract_jpeg` 使用；spatial extract 忽略。挂在 `StegoOptions` 上对所有格式可见，易误解为全局生效。

#### A8【P2】`JpegParams::deterministic` 与 safety 一样是"库自动覆写用户值"的隐藏字段

`#[serde(skip)] #[doc(hidden)]` + 统一入口 `jpeg_params.deterministic = options.freshness.is_seeded()`（`mod.rs:82`）。模式本身对（seeded 必须禁 FMA），但 `StegoOptions` 文档未列出"哪些字段会被入口自动改写"，用户手动构造 params 时无法预期。

#### A9【P1】trait 公开但统一入口不接受自定义模型——"可插拔"对第三方是半成品

`SpatialCostModel` / `JpegCostModel` / `JpegGeometry` 公开，`CostModelRegistry` 却是静态 `match`（无运行时注册）。2026-10-20 蓝图 §4.3 提过 `StegoOptions { custom_spatial_model, custom_jpeg_model }`，**至今未落地**（grep 无匹配）。第三方想带自己的代价模型（如私有 HILL 变体）只能绕过统一入口直接调 domain engine 并传 `&dyn`——于是**失去格式嗅探、HEIF/HEVC 路由、safety 强制、credential 解析**，要在自己的代码里重抄 `stego/mod.rs` 的分发逻辑。examples/stego_profile.rs 演示的正是这条羊肠小道。

#### A10【P2】facade 文件层不可定制，高级宿主被迫自建 I/O

`facade::StrHide::embed_file/extract_file` 提供原子提交/备份/时间戳，但备份命名固定 `.bak`、输出命名固定，CarrotHash 需要 `.bak.N` 递增与 `-h.<ext>` 命名，只能回到裸 bytes API 自建 ~150 行 I/O（含 TmpFileGuard RAII）。`engine::commit_carrier_bytes` 已是 `pub`，但 facade 没把它参数化暴露。

---

### A'. HEVC（Scheme C）专项——未接入 Profile/Params 定制体系（20:57 补充复核）

> 背景：Scheme C 是最近新增的第三套内容域引擎（HEIF/HEIC 与 Annex-B）。PNG/JPEG 有完整的 `Profile::stego`（secret/domain/format）+ `SpatialParams`/`JpegParams` + `SafetyLevel` + `Freshness` 定制轴；**HEVC 一条都没有**，且由此产生一个安全级缺陷。

#### A11【P0】统一入口向 HEVC 传的是裸 `password`，私有方言密钥被静默丢弃

`stego/mod.rs` 的 HEVC 分支（三处：`-a hevc/cabac` 显式路径、bridge 失败回退、Annex-B 路径）全部调用：

```rust
hevc::embed_hevc(carrier_bytes, payload, options.password.as_deref())   // 不是 options.secret(profile)!
```

而 `heif::embed_heif_bridge` 在同一文件里正确使用 `options.secret(profile)` / `options.domain(profile)` / `profile.format_profile()`。后果：**CarrotHash 式私有构建（`Profile::with_stego_secret(...)`）嵌入 .heic/.hevc 载体时，只要没带 `--password`，密钥回落到 HEVC 自己的公开默认常量**——装了官方 strhide 的人就能读。这正是 2026-10-20 M1b 为 PNG/JPEG 修掉的"私有密钥被静默降级"类 bug，在 HEVC 上原样复发。提取侧（`hevc::extract_hevc(carrier, options.password.as_deref())`）同样。

#### A12【P0】静态魔数 `SH25` + 免密码 header 定位 = 存在性检测预言机

- `hevc/engine.rs:28`：`const HEVC_STEGO_MAGIC: &[u8; 4] = b"SH25"`，明文写在 40 字节微信封头部，随消息一起嵌入。
- header 槽位由 `slot_positions(total_slots, needed)`（Weyl 置换，仅依赖槽总数）+ `seed_from_digest(cover_digest)` 决定，**cover_digest 只哈希参数集（VPS/SPS/PPS），与密码无关**（`derive_carrier_digest`/`engine.rs:839`）。
- 即：分析者无需任何凭据，解析参数集 → 算 digest → 推置换 → 读前 40 字节 → 比对 `SH25`，即可判定"此 HEVC 文件藏过数据"。

这与 PNG/JPEG 微信封"无静态魔数、整体高熵、与空载体不可区分"的设计原则直接相悖；结构域至少还有 stealth 模式用密码派生魔数兜底，HEVC 连这个机制都没有。WIRE_SPEC §13.11.2 声称"彻底切断口令暴力枚举预言机"——那只覆盖了暴力枚举，**没覆盖存在性 oracle**。

#### A13【P1】代码里出现第三份公开默认密钥常量

`derive_hevc_key`（`engine.rs:870-873`）：`password.unwrap_or("strhide-hevc-default-key-2026")`。全项目现有三份互不相干的公开默认密钥：`crypto::BUILTIN_DEFAULT_KEY`（结构域）、`stego::envelope::PUBLIC_DEFAULT_SECRET`（PNG/JPEG）、`"strhide-hevc-default-key-2026"`（HEVC）。同一"私有默认密钥"概念有三个事实源，正是 2026-10-20 文档反复要求收敛的模式。

#### A14【P1】HEVC 没有 FormatProfile 等价物，私有编译期定制完全落空

JPEG V3 的 `FormatProfile` 把 5 个 HKDF 派生标签 + superblock 几何 + grid rule + suites 收成一个可 const 构造的值；HEVC 的对应物全是模块内硬编码：`HEVC_STEGO_MAGIC`、`DEFAULT_HEVC_SALT = b"strhide-hevc-salt-2026"`、HKDF info `b"strhide-hevc-aes256-key"`、STC `from_seed_grouped(seed, 7, 2)`（probe 还用另一个硬编码 seed `0x5465_676f`）、header 定长 40 字节。第三方想消除开源指纹只能 fork——恰好是 `format.rs` 模块文档（"If those constants are `const` items scattered across modules, that means forking the crate"）要消除的场景。

#### A15【P1】WIRE_SPEC §13.11 与代码三处漂移（文档在描述一个不存在的格式）

| 项 | WIRE_SPEC §13.11.2 写的 | 代码实际 |
|---|---|---|
| cover digest 前缀 | `SHA-256("strhide-hevc-cover-v1" ‖ …)` | `hasher.update(DEFAULT_HEVC_SALT)`，即 `b"strhide-hevc-salt-2026"`（`engine.rs:851`） |
| HKDF info | `"strhide-hevc-aes-key"` | `b"strhide-hevc-aes256-key"`（`engine.rs:879`） |
| 无密码回退 | "默认使用 `DEFAULT_HEVC_SALT`（`b"strhide-hevc-salt-2026"`）" | 用独立的 `"strhide-hevc-default-key-2026"`，与 salt 不是同一个字符串（`engine.rs:872`） |

线格式文档是私有构建复现 carrier 的唯一依据，这三处漂移会让按文档实现的第三方生成互不兼容的载体。

#### A16【P2】SafetyLevel / Freshness 对 HEVC 全部无效，且无任何提示

- `probe_carrier_capacity` 的 HEVC 分支（`mod.rs:350-382`）直接 `recommended_max_bytes = cap`，**不套用 `safety_level` 的 bpp/ratio 限制**——`--safety paranoid` 对 HEIC 容量数字零影响；
- `Freshness::Seeded` 对 HEVC 无效：nonce 走 `rand::rng().fill()`（`engine.rs:123`），repro_* 示例与可复现回归不覆盖 HEVC；
- 口令未过 `normalize_nfc`（PNG/JPEG 口径），组合字符口令在 HEVC 路径按原始字节派生。

#### A17【P2】`--algorithm hevc|cabac` 与 bridge 的优先级只在 mod.rs 的 if/else 里表达

`-a hevc` 强制 Scheme C、否则先试 bridge 失败再回退 HEVC——这条路由规则没有文档化（README/ARCHITECTURE 均未写"什么时候走 bridge、什么时候走 Scheme C"），用户无法预期 .heic 到底走了哪条路径，`--capacity` 报告也因此不可解释。


### B. CLI

#### B1【P1】专家级 tuning flag 全部平铺进日常层

embed 一次公开 7 个 tuning flag，其中 `--slot-budget`（帮助 4 行）、`--cipher-suite`（协议套件选择）是"改了会显著改变性能/安全画像"的专家项，与 `-t/-p/-o` 日常项同权重出现。用户原话原则"cli 不需要把库暴露的全部作为参数公开"——当前恰好反例。对照：`--codec/--stc-u` 在 2026-10-22 已因"认知负担"被删（CHANGES-20261022 §3.4），但同类 flag 仍在。

#### B2【P0】extract 的 4 个 tuning flag 完全没有 help 文案

`cli.rs:483-494`：`#[arg(long = "exclusion-rate", value_name = "FLOAT")]` 等四个参数**没有 `help` 属性**，`strhide extract --help` 里显示为空列。embed 侧同组参数却有完整帮助。

#### B3【P0】README（中英）宣传已删除的 `--codec` / `--stc-u`，且默认 codec 描述与代码相反

- commit `8e5ac34`（早于 README 最后一次同步 `15998b9`）删除了两个 flag，README 两语言仍在 `--codec stc` / `--stc-u 1..3`（README.md:218-223、README.zh.md:207-209）；
- README 称空间域"**by default** `(7,3)` Hamming"，而代码默认是 `StegoCodec::Auto`，且 `auto_select_codec`（`coding.rs:95-110`）**永远返回 Stc**（u=3/2/1）——Hamming 目前库外不可达（CLI 无 flag，库需手写 `StegoCodec::Hamming`）。README 的描述在两个意义上都是错的。

#### B4【P1】clap help 与 i18n 双份事实源，已出现数值漂移

`cli.rs` 的 `#[arg(help=...)]` 硬编码英文 + `cli_i18n.rs` 在运行时用 `Msg` 覆盖。两处必须手工同步。已发现漂移：`HelpEmbedExclusionRate` 写 "default: 0.20"（messages.rs:516），实际默认 **0.30**（`params.rs:213`，cli.rs:373 也写 0.30）。另：`cli_i18n.rs` 用 `(_, "exclusion-rate")` 通配匹配，**extract 子命令会显示"排除在**嵌入**之外…"的 embed 语境文案**。

#### B5【P2】`--stc-h` 只在 embed 出现且帮助未说明"提取端不需要"

`--stc-h` 记入 feature word / superblock，提取自描述。embed 帮助应明示，否则用户会在 extract 时找对应 flag 而困惑。

#### B6【P2】config 只有 2 个 stego 键，与 CLI 的 7 个 tuning flag 不对称；sample.toml 缺 `stego_domain`

`FileConfig` 支持 `stego_domain` 且有 `STRHIDE_STEGO_DOMAIN` env，但 `strhide.sample.toml` §10 只字未提（只写了 stego_secret）。tuning 参数不走 config 是合理设计（一次性调参），但应在 sample.toml 明示"调参项仅 CLI"，避免用户寻找不存在的键。

### C. 文档

#### C1【P0】README 两语言宣传不存在 flag + 默认 codec 错误（同 B3）
#### C2【P1】`docs/api/ARCHITECTURE.md` §4.3 的 `StegoOptions` 清单缺 `extract_params`；`JpegParams` 注释声称"含 codec/stc_h/stc_u"——`JpegParams` 没有 `codec`/`stc_u` 字段（那是 `SpatialParams` 的）
#### C3【P1】无"稳定/专家/内部"分层的权威文档。361 个 pub 项里哪些可以依赖、哪些随时可变，没有任何一份文档说过。对第三方（CarrotHash 类）这是最大的接入成本
#### C4【P2】sample.toml 缺 `stego_domain` / `STRHIDE_STEGO_DOMAIN`（同 B6）

---

## 3. 改进方案

### 3.1 库：三层公开面模型

| 层 | 内容 | 稳定性承诺 |
|---|---|---|
| **稳定面 Stable** | `stego::{embed_carrier, embed_carrier_with_profile, extract_carrier, extract_carrier_with_profile, probe_carrier_capacity, probe_carrier_capacity_with_profile}`；`StegoOptions`/`SpatialParams`/`JpegParams`/`ExtractParams`/`StegoCodec`/`SafetyLevel`/`SafetyEnforcement`/`Freshness`/`StegoCapacityInfo`；`format::{FormatProfile, SpatialFormatProfile, GridRule, CipherSuite, Kdf, Aead, SUITES, DEFAULT_FORMAT, OFFICIAL_SPATIAL, ...}`；`registry::CostModelRegistry`；`traits::{SpatialCostModel, JpegCostModel, JpegGeometry}`；`facade::StrHide` | 破坏性变更只随 major |
| **专家面 Expert** | domain engine 入口（`spatial::engine::*`、`jpeg::engine::*`、`heif::*`、`hevc::{embed_hevc, extract_hevc, probe_hevc_capacity}`）、`spatial::{decode_png, encode_png, RawImage}`、`jpeg::cost::*`、`spatial::cost::*`、`params` 的预算常量/函数（`grouped_body_budget` 等） | 小版本可演进，CHANGES 公告 |
| **内部面 Internal** | `coding`、`envelope`、`header`、`prng`、`wavelet`、`jpeg::{dht, header_v3, v3_layout, geometry}`、`hevc::{slot, bitstream, heif_boxes, sniff, error, h265}` | 无承诺；标 `#[doc(hidden)]`，docs.rs 不展示 |

落地手段：内部面统一加 `#[doc(hidden)]`（保持 `pub` 以不破坏 examples/tests 的 crate 外引用），在新文档中明示三层；`hevc::h265` re-export 直接删除或 `#[doc(hidden)]`。

### 3.2 库：逐项改动

| # | 事项 | 改动点 | 理由/影响 |
|---|---|---|---|
| L1 | **删除根级 `embed`/`extract` re-export** | `lib.rs:168-174` 只保留 `UerdCostModel`/`JpegCostModel`/params/format 五件套；`embed_jpeg`/`extract_jpeg` 经 `stego::jpeg::engine` 可达 | 消除最误导的入口（A2）。项目未发布，零兼容成本 |
| L2 | **删除 6 个"无 profile"域入口薄壳** | `spatial/engine.rs`、`jpeg/engine.rs` 的 `embed_spatial`/`embed_jpeg`/`extract_*`/`probe_*`（无 profile 版）；`spatial/mod.rs`、`jpeg/mod.rs` 的 `pub use` 只保留 `_with_profile*` 全量版 | 统一入口即默认路径（A3）；examples/测试内调用点同批改 |
| L3 | **safety 单一事实源** | 二选一：(a) 从 `SpatialParams`/`JpegParams` 删除 `safety_level`/`safety_enforcement`，domain engine 改为显式参数（`embed_spatial_with_profile_and_freshness` 已可加）；(b) 保留字段但统一入口改为"params 未显式设置才注入"——不可行，无法区分显式与默认。**推荐 (a)**，同时给 `StegoOptions` 加 `const fn with_safety(level, enforcement)` builder | 消灭静默覆盖与 4 处赋值（A1）；CarrotHash 改后一行搞定 |
| L4 | **自定义代价模型注入** | `StegoOptions` 增加 `spatial_model: Option<Arc<dyn SpatialCostModel>>` / `jpeg_model: Option<Arc<dyn JpegCostModel>>`，统一入口优先于 registry 名称匹配；文档写明约束：**自定义 spatial 模型没有 wire id，载体不自描述算法，提取必须传同一个模型**（与 JPEG 几何槽位不同） | 让 traits 的公开名副其实（A9）；这正是 2026-10-20 蓝图未落地项 |
| L5 | **统一入口自动改写字段清单化** | `StegoOptions` 文档增加"自动覆写"小节：safety 注入（L3 后删除 params 字段即自然消失）、`jpeg_params.deterministic = freshness.is_seeded()`；`ExtractParams` 文档注明"当前仅 JPEG V3 解码器消费" | 消除隐藏行为意外（A7/A8） |
| L6 | **`stego_domain` 优先级成表** | `StegoOptions::domain()` 文档加优先级表（显式 > profile > 官方），`Profile::stego_domain` 文档交叉引用；评估是否重演 2026-10-20 的 `default_secret` 合并（建议：**不合并字符串，但文档明确"运行时凭据走 Options，编译期方言走 Profile"的分工）** | A5 |
| L7 | **`SafetyLevel` 增加 `FromStr`** | 实现 `FromStr`（委托 `parse`），文档示例给出含数字别名的 match 范式或直接支持 `"0"/"1"/"2"` | A6，顺带让 CLI `--safety` 解析复用 |
| L8 | **facade 文件层参数化** | `embed_file`/`extract_file` 增加备份策略与输出命名选项（或暴露 `commit_carrier_bytes` 的薄包装 + 文档羊肠小道说明） | A10，让 CarrotHash 类宿主不必自建 150 行 I/O |
| L9 | **内部面 doc(hidden)** | 按 3.1 清单批量加 `#[doc(hidden)]`；删除 `pub use rust_h265 as h265` | 规范公开面 |

### 3.2b HEVC（Scheme C）专项补齐（对应 A11–A17）

设计原则：**HEVC 必须获得与 PNG/JPEG 对等的定制轴，且线格式文档（WIRE_SPEC）与代码严格一致**。因项目未发布，`embed_hevc`/`extract_hevc` 的签名可以直接扩展，无兼容负担。

| # | 事项 | 改动点 | 理由/影响 |
|---|---|---|---|
| H1 | **新增 `HevcFormatProfile`（`stego/format.rs`）** | 一个可 `const` 构造的值：`magic_label`（派生 4 字节魔数的 HKDF info）、`cover_salt`、`kdf_info`、`stc_h`、`stc_u`、`header_bytes`；`DEFAULT_HEVC` 为官方常量；`StegoProfile` 增加 `hevc: Option<HevcFormatProfile>` + `with_hevc()` builder；`Profile::hevc_profile()` 回退默认 | 消灭 A14：第三方改标签重建即消除开源指纹，不必 fork；同时给 A12 的魔数一个派生化出口 |
| H2 | **HEVC 入口签名对齐 Profile** | `embed_hevc(carrier, payload, secret, domain, format, params, freshness)` / `extract_hevc(carrier, secret, domain, format)` / `probe_hevc_capacity(carrier, format)`；`stego/mod.rs` 三处调用改传 `options.secret(profile)` / `options.domain(profile)` / `profile.hevc_profile()`（**修 A11 静默降级**） | HEVC 与其他域同一解析链；CarrotHash 的私有密钥对 .heic 生效 |
| H3 | **默认密钥归一** | 删除 `"strhide-hevc-default-key-2026"`；无密码回退统一走 `secret`（显式密码 > profile 私钥 > `PUBLIC_DEFAULT_SECRET`），与 `StegoOptions::secret()` 语义一致 | 消灭 A13 第三份常量 |
| H4 | **魔数派生化 + 威胁模型成文** | `SH25` 改为从 `magic_label` 派生的 4 字节（官方格式保持现值以兼容既有测试载体，或直接重算并同步测试）；WIRE_SPEC 明示"header 定位免密码"这一事实及存在性 oracle 的边界（隐私方：载体内容绑定参数集；抗检方：静态魔数可被搜索，私有格式须改标签） | 修 A12；文档不再夸大"彻底切断" |
| H5 | **新增 `HevcParams`** | `stc_h`/`stc_u` + 预留 `algorithm_options`；probe 的硬编码 seed `0x5465_676f` 收敛为与 embed/extract 同一 `seed_from_digest` 口径（probe 容量与 h/u 绑定，需同参） | A14/A16；h/u 从模块常量变为可调 |
| H6 | **Safety/Freshness 接入或显式声明不适用** | probe 的 HEVC 分支：`recommended_max_bytes` 按 `safety_level` 的 bpp 上限折算（帧尺寸已知时可算；不可算时文档明示"HEVC 容量不参与安全档位"）；`Freshness::Seeded` 支持：nonce/salt 改走 `freshness.nonce(0)` 派生，repro 示例扩到 HEVC | A16；`--safety`/seeded 回归对 HEVC 生效 |
| H7 | **口令 NFC 规范化** | `derive_hevc_key` 入口对 password 过 `crypto::normalize_nfc`，与另两个域一致 | A16 末条 |
| H8 | **修 WIRE_SPEC §13.11 三处漂移** | 按代码实际改写 digest 前缀/info/无密码回退三段，并加一条"文档与实现的一致性测试"（把规范里的字面量写进 `rust/tests` 断言，防再次漂移） | A15 |
| H9 | **bridge vs Scheme C 路由文档化** | README/ARCHITECTURE 增一段：`-a hevc/cabac` 强制 Scheme C；默认先试 thumbnail/aux bridge（JPEG/unci 子载体），失败回退 Scheme C；`--capacity` 按同一路由报告 | A17 |


### 3.3 CLI：三层参数模型

| 层 | 参数 | 处置 |
|---|---|---|
| **日常** | `-t/-d/--stdin`、`-p`、`-o`、`--in-place`、`--overwrite`、`--no-backup`、`-a`、`--safety`、`--enforce-safety`、`--capacity` | 保持；`-a` 帮助补"按载体格式域生效" |
| **专家** | `--exclusion-rate`、`--p1-window`、`--p2-window`、`--stc-h`、`--neighbor-weight` | 保留可见，帮助压缩为一行；补 extract 侧缺失的 help（B2） |
| **隐藏** | `--slot-budget`、`--cipher-suite` | clap `hide = true`，仅 `--help` 长格式/文档可见；功能不变 | 
| **删除/收窄** | extract 的 `-a` | 收窄为 `--force-hevc`（或保留 `-a` 但帮助明示"仅 hevc/cabac 有效；PNG/JPEG 由载体自描述"） | B3/A4 |

配套：
- **B4 单一事实源**：删 cli.rs 各 `help=` 英文字符串，全部改由 `cli_i18n.rs` 的 Msg 注入（clap 允许省略 help）；加测试遍历命令树断言"每个 arg 在 zh/en 下都有非空 help"。
- **B5**：`--stc-h` 帮助补"记录于载体头部，提取端无需指定"。
- **B6**：sample.toml 补 `stego_domain` 段，并加注"调参项（--exclusion-rate 等）仅 CLI，不进 config"。

### 3.4 文档

| # | 事项 |
|---|---|
| D1 | **修 README（中英）**：删 `--codec`/`--stc-u` 两节，改写为"矩阵编码层由库自适应选择（STC u=3/2/1），Hamming 仅库可设"；容量实测数字保留但改口径 |
| D2 | **修 `docs/api/ARCHITECTURE.md` §4.3**：`StegoOptions` 补 `extract_params`、`spatial_model`/`jpeg_model`（L4 后）；`JpegParams` 注释删掉不存在的 codec/stc_u |
| D3 | **新建 `docs/api/STEGO-API.md`**（单一事实源）：三层公开面清单 + 每项的稳定性 + "谁覆盖谁"表（safety/domain/secret 优先级）+ 第三方编译期定制全流程（以 CarrotHash 为范本：const Profile + FormatProfile 字面量 + `cargo build`）+ 自定义模型接入路径（L4 后） |
| D4 | **修 `HelpEmbedExclusionRate` 默认值 0.20 → 0.30**，并把所有 help 文案默认值与代码常量对齐（可加单测断言） |
| D5 | `strhide.sample.toml` 补 `stego_domain`（B6） |

### 3.5 CarrotHash 改造后目标形态（验证方案可行性）

```rust
// dialect.rs 不变：const Profile + FormatProfile 字面量（编译期定制，零运行时成本）
pub const DIALECT: Profile = Profile::new()
    .with_stego_secret(STEGO_SECRET)
    .with_stego_domain(STEGO_DOMAIN)
    .with_format_profile(CARROT_JPEG_FORMAT)
    .with_spatial_profile(CARROT_SPATIAL)
    .with_hevc_profile(CARROT_HEVC_FORMAT);   // H1 新增：.heic/.hevc 也进入私有方言

// options.rs 改造后：safety 一处设置（L3 + builder），数字别名走库 FromStr（L7）
let opts = StegoOptions {
    password: resolved_pwd,
    ..Default::default()
}
.with_safety(level, enforcement);          // 原来 4 处赋值 → 1 处

// ops.rs 改造后：I/O 委托 facade（L8），删除 ~150 行自建原子提交/备份/时间戳
// H2 之后，同一份 DIALECT 对 PNG/JPEG/HEIC/HEVC 全部生效——包括无密码时的私钥回退
let stego = ENGINE.embed_file(carrier, target, &payload, &opts, backup_policy)?;
```

---

## 4. 实施顺序与风险

| 阶段 | 项 | 风险 |
|---|---|---|
| **第一批（纯删减/文档，零行为变更）** | B3/C1 README 修 flag；B4 help 默认值修正 + 单测；B2 extract help 补齐；C2 ARCHITECTURE 字段清单；D3 建 STEGO-API.md；D5 sample.toml | 无代码风险；README 修正需与 batch_stego 实测口径对齐 |
| **第二批（公开面收敛，项目未发布零兼容成本）** | L1 删根级 embed/extract；L2 删 6 个薄壳；L9 doc(hidden) + 删 h265 re-export | examples/测试调用点同批编译修复；`cargo test --all-targets` + batch 双跑 |
| **第三批（行为统一）** | L3 safety 单一源（动 domain engine 签名，影响面 = spatial/jpeg engine + 全部调用方）；L4 自定义模型注入；L5/L6 文档优先级表 | 最大一批；L3 需全量回归（safety 三档 × enforce × 格式矩阵）；L4 只需新增字段 + 入口分支，旧路径不变 |
| **第四阶段（CLI 分层 + facade 参数化）** | B1 hide=true；B3 extract `-a` 收窄；L7 FromStr；L8 facade 备份/输出选项 | CLI 帮助快照测试需更新；`-a` 收窄要评估 HEIF bridge 用户脚本 |
| **第五批（HEVC 专项，H1–H9）** | H8 先修 WIRE_SPEC 漂移（纯文档）；H2+H3 修统一入口静默降级 + 删第三份默认密钥（**安全相关，建议最先落码**）；H1+H5 加 `HevcFormatProfile`/`HevcParams`；H4 魔数派生化；H6/H7 safety/freshness/NFC；H9 路由文档 | H2 改动小但行为变化大：私有 profile 下的 .heic 载体将从"任何人可读"变为"仅同方言可读"，需在 CHANGES 明示；H1 涉及 `embed_hevc`/`extract_hevc`/`probe_hevc_capacity` 签名与 mod.rs 全部调用点 + hevc 单测/批测（batch_stego 覆盖 HEIC/HEVC 语料，须全绿）；H4 若重算魔数，既有测试载体需重新生成 |

**明确不做**：HostAdapter 运行时注册（2026-10-20 已裁定）；协议级套件动态注册（W 类，`docs/library_api_practical_plan_20261020.md` §7 结论仍成立）；把 tuning flag 加进 config 文件（一次性调参走 CLI 即可）。

---

## 5. 附：本梳理发现的一处文档漂移实证（修复 D1/D4 时直接可用）

| 事实 | 证据 |
|---|---|
| `--codec`/`--stc-u` 已从 CLI 删除 | `git log -S '"codec"' -- rust/src/cli.rs` → `8e5ac34` "prune CLI"；当前 cli.rs grep 无 `codec`/`stc_u` |
| README 最后一次同步晚于删除仍在宣传 | `15998b9`（docs sync）晚于 `8e5ac34`；`git show 15998b9:README.md \| grep codec` 命中 218-223 行 |
| 默认 codec 是 Auto→STC 而非 Hamming | `params.rs:34` `#[default] Auto`；`coding.rs:95-110` `auto_select_codec` 仅返回 `(Stc, 3/2/1)` |
| i18n 默认值漂移 0.20 vs 0.30 | `messages.rs:516` vs `params.rs:213`（`exclusion_percentile: 0.30`）与 `cli.rs:373` |
| HEVC 静态魔数 + 免密码 header 定位 | `hevc/engine.rs:28`（`b"SH25"`）；`engine.rs:839-868`（digest 只吃参数集，无密码）；`engine.rs:524-527`（Weyl 置换仅依赖 `total_slots`）；提取端 `engine.rs:577` 直接比对魔数 |
| HEVC 第三份公开默认密钥 | `hevc/engine.rs:870-873`：`password.unwrap_or("strhide-hevc-default-key-2026")`；另两份为 `crypto.rs` `BUILTIN_DEFAULT_KEY`、`stego/envelope.rs:59` `PUBLIC_DEFAULT_SECRET` |
| 统一入口 HEVC 分支丢 profile 密钥 | `stego/mod.rs` 三处 `hevc::embed_hevc(..., options.password.as_deref())`；同文件 bridge 路径用 `options.secret(profile)`（对照 `heif/thumb_bridge.rs:82-83`） |
| WIRE_SPEC §13.11 三处漂移 | 文档 `SHA-256("strhide-hevc-cover-v1"‖…)` vs 代码 `engine.rs:851` `hasher.update(DEFAULT_HEVC_SALT)`；文档 info `"strhide-hevc-aes-key"` vs 代码 `engine.rs:879` `b"strhide-hevc-aes256-key"`；文档"无密码用 `DEFAULT_HEVC_SALT`" vs 代码 `engine.rs:872` 独立常量 `"strhide-hevc-default-key-2026"` |
| HEVC probe 不套安全档位 | `stego/mod.rs:350-382`：`recommended_max_bytes: cap`，未过 `safety_level.bpp_limit()`；对照 JPEG/spatial 分支走 `options.safety_level` |
| HEVC 无 Freshness | `hevc/engine.rs:122-124`：`rand::rng().fill(&mut nonce_bytes)`，`Freshness::Seeded` 无入口 |
