# stego 参数一致性审查报告（JPG / PNG / HEVC）

- 日期：2026-10-25
- 范围：`rust/src/stego/**` 全部公开 API 与参数；对照 `rust/src/lib.rs`（crate 根导出）、`rust/src/cli.rs`（CLI 参数）、`rust/examples/*`。
- 方法：逐文件通读公开项（`pub fn` / `pub struct` / `pub const`）及其文档注释，与实现交叉核对；对三个格式引擎（PNG 空间域、JPEG DCT 域、HEVC Scheme C）的参数集合、校验规则、命名、默认值、行为做横向比对。
- 结论：接口总体设计良好（validate-first、载体自描述、无 oracle 错误），但存在 **5 处文档与实现不符（P1）**、**13 处跨格式不一致或易误用（P2）**、**6 处低优先级问题（P3）**。未发现会导致数据损坏或安全漏洞的错误；最需要优先处理的是 P2-1（HEVC 无 safety 强制）与 P1-1/P1-2（PngParams 默认值文档失实）。

问题编号规则：`P1-x` 文档与实现不符；`P2-x` 不一致/不规范/易误用；`P3-x` 建议。每条给出位置（`文件:行`，行号为 2026-10-25 工作区状态）。

---

## P1 文档与实现不符（应优先修正）

### P1-1 `PngParams::codec` 字段文档写 "default Hamming"，实际默认是 `Auto`

- 位置：`stego/params.rs:208`（字段注释 `/// Matrix-coding layer (default Hamming; STC is opt-in).`）vs `stego/params.rs:34`（`StegoCodec` 的 `#[default] Auto`）及 `stego/params.rs:280`（`Default for PngParams` 使用 `StegoCodec::Auto`）。
- 影响：使用者按文档会以为默认走 (7,3) Hamming 矩阵嵌入；实际默认是 STC 自适应（`auto_select_codec` 按 r 比率选 u=3/2/1）。两者的容量、改动率、探测输出（`probe_png_capacity` 按 `params.codec` 分支报告 `max_raw_payload_bytes` 与 `estimated_change_rate`，`stego/png/engine.rs:1671-1716`）都不同。
- 建议：字段注释改为 "(default Auto = STC-adaptive)"。

### P1-2 `PngParams::stc_u` 字段文档写 "(default 1)"，实际默认是 0（auto）

- 位置：`stego/params.rs:214`（`/// STC group size: how many elements share one syndrome row (default 1).`）vs `stego/params.rs:250-252`（`fn default_stc_u() -> u8 { 0 }`）。
- 影响：0 在本字段中是哨兵值"auto"（`slots_for_codec` 与引擎均按 `stc_u == 0` 走自动路径）。文档让使用者以为需要显式传 1。
- 建议：注释改为 "(0 = auto, the default)"。

### P1-3 `MAX_AUTO_BACKTRACK_BYTES` 文档说 "256 MiB allows 8.4M slots"，常量实际是 4 GiB

- 位置：`stego/params.rs:471-485`。doc 注释写 "*memory* -- one slot costs `2^h / 64` words …, so 256 MiB allows 8.4M slots at `h = 8`"，但 `pub const MAX_AUTO_BACKTRACK_BYTES: usize = 4 << 30; // 4 GiB`。
- 影响：按 4 GiB / 32 B（h=8 每 slot 回溯字节）实为约 134M 槽。文档描述的是旧值，容量换算和内存预估全部对不上。
- 建议：更新注释为 4 GiB 口径（或说明"从 256 MiB 提升到 4 GiB 的沿革"）。

### P1-4 crate 根文档声称 stego 的 `embed` / `extract` 在 crate 根 re-export，实际没有

- 位置：`lib.rs:118-123`（"Its public surface is re-exported at the crate root: [`JpegFormatProfile`] …, [`JpegParams`] / [`ExtractParams`] …, and [`embed`] / [`extract`] (the JPEG entry points …)"）；`lib.rs:169-178` 的实际 re-export 列表中**没有**任何 embed/extract 函数。
- 影响：`use strhide::{embed_carrier, extract_carrier};` 无法编译；统一入口在 `strhide::stego::embed_carrier`。且声称的 "the JPEG entry points"（`stego::jpeg::embed_jpeg`）同样未在根导出。
- 建议：要么补齐 re-export（见 P2-4），要么修正 lib.rs 文档为实际路径。

### P1-5 `probe_hevc_capacity_info` 的 `estimated_change_rate` 硬编码 0.25，与编码层速率表不符且不随 `fmt.stc_u` 变化

- 位置：`stego/hevc/engine.rs:271`（`estimated_change_rate: 0.25`）vs `stego/coding.rs:292-298`（`expected_stc_change_rate(u)`：u=0/1→0.50，u=2→0.265，其余→0.230）。默认 `DEFAULT_HEVC_FORMAT.stc_u = 2`（`stego/format.rs:222`），对应表值 0.265 而非 0.25。
- 影响：HEVC 的改动率估计既不是查表值，也不随私有 profile 的 `stc_u` 更新；与 JPEG（按布局实时算 u）、PNG（按 codec/u 计算）的口径不一致。
- 建议：改为 `crate::stego::coding::expected_stc_change_rate(fmt.stc_u)`（并为 u=2 补 0.265 的表值一致性），或在字段文档中注明 HEVC 为经验常数。

---

## P2 跨格式不一致 / 不规范 / 易误用

### P2-1 `SafetyEnforcement::Enforced` 对 HEVC/HEIF 载体完全无效

- 位置：`stego/hevc/engine.rs:284-291`（`embed_hevc` 签名无 `SafetyPolicy` 参数）；`stego/mod.rs:128-163`（统一入口 HEIF/AnnexB 分支直接调 `embed_hevc`，不做任何 enforced 检查）。对照 `stego/jpeg/engine.rs:766-776` 与 `stego/png/engine.rs:1141-1161`（两者都有 enforced 拒绝路径）。
- 影响：同一 `StegoOptions` + `SafetyPolicy { enforcement: Enforced }`，PNG/JPEG 载体超限时被拒绝，HEVC 载体**静默照嵌**。CLI `--enforce-safety` 同样只约束 PNG/JPEG。使用者在"强制安全"下对 HEVC 的安全预期落空。
- 建议：给 `embed_hevc` 增加 `safety: SafetyPolicy` 参数（`probe_hevc_capacity_info` 已实现 tier 折算，逻辑可复用），或在 `StegoOptions`/`SafetyEnforcement` 文档中显著声明 HEVC 不适用。

### P2-2 同一语义的凭据参数命名不一致：`password` vs `secret`

- 位置：`stego/jpeg/engine.rs:563`、`stego/png/engine.rs:1081` 参数名 `password: Option<&str>`；`stego/hevc/engine.rs:287`、`759-763` 参数名 `secret: Option<&str>`。
- 说明：三者的语义相同——统一入口 `StegoOptions::secret(&Profile)` 解析后的凭据（显式密码 > profile 私密 > None→官方常量），并非"HEVC 才收秘密"。命名差异纯属历史。
- 建议：统一为 `secret`（与 `StegoOptions::secret`、`embed_carrier_with_profile` 文档的用词一致）或统一为 `password`；改名成本低（纯参数名），收益是跨引擎代码可移植。

### P2-3 `embed_jpeg` 与 `embed_png` 的参数顺序在 `params` / `safety` / `cost_model` 上相反

- 位置：`stego/jpeg/engine.rs:560-569`：`(..., fmt, params, safety, cost_model, freshness)`；`stego/png/engine.rs:1078-1088`：`(..., spatial, cost_model, params, safety, freshness)`。
- 影响：两个签名类型不同不会误传，但从统一入口/示例移植调用代码时极易按记忆写错顺序（都是 `&dyn` + 两个值参数）。
- 建议：统一为 `(..., fmt, cost_model, params, safety, freshness)`（代价：一次性 breaking rename，项目未发布，现在改最便宜）。

### P2-4 crate 根 re-export 不对称，用户被迫混用两级路径

- 位置：`lib.rs:169-178` 只 re-export 了 `format::{CipherSuite, DEFAULT_HEVC_FORMAT, DEFAULT_JPEG_FORMAT, GridRule, HevcFormatProfile, JpegFormatProfile, OFFICIAL_PNG_FORMAT, PngFormatProfile}`、`jpeg::cost::UerdCostModel`、`params::{ExtractParams, JpegParams}`、`traits::JpegCostModel`；而 `PngParams`、`StegoOptions`、`SafetyLevel`、`SafetyPolicy`、`SafetyEnforcement`、`StegoCodec`、`Freshness`、`CostModelRegistry`、`StegoCapacityInfo`、`PngCostModel`、`HillCostModel`/`SuniwardCostModel`/`JuniwardCostModel` 只能从 `strhide::stego::*` 取。
- 影响：最常用的 `StegoOptions`/`PngParams` 反而要走长路径；`JpegParams` 在根、`PngParams` 不在根，同一个"参数家族"分居两处（一个真实使用样例：`examples/stego_profile.rs:16-22` 全部从 `strhide::stego::` 导入，根导出形同虚设）。
- 建议：把 stego 公共面（至少 `StegoOptions`、`PngParams`、`JpegParams`、`ExtractParams`、`Safety*`、`StegoCodec`、`Freshness`、`StegoCapacityInfo`、`embed_carrier`/`extract_carrier`/`probe_carrier_capacity`）整体 re-export 到 crate 根，与 lib.rs 文档（P1-4）一并修正。

### P2-5 probe 家族签名三种形态，返回类型与凭据要求各不相同

- 位置：
  - `stego/jpeg/engine.rs:1263-1269` `probe_jpeg_capacity(carrier, cost_model, params, safety_level, fmt)` —— 无凭据；
  - `stego/png/engine.rs:1623-1631` `probe_png_capacity(carrier, cost_model, params, safety_level, password, domain, spatial)` —— 凭据在 `safety_level` 之后；
  - `stego/hevc/engine.rs:135` `probe_hevc_capacity(carrier, fmt) -> usize` 与 `stego/hevc/engine.rs:209` `probe_hevc_capacity_info(carrier, fmt, safety_level) -> StegoCapacityInfo` —— 两个近似名函数、两种返回类型。
- 说明：JPEG 无凭据是正确的（容量与凭据无关），PNG 带凭据也是正确的（512 个 header/feature 槽由凭据置换决定并从 body 池扣除，`stego/png/engine.rs:835-857` 有明确说明）。问题在于：① HEVC 的两个 probe 名字仅差 `_info` 后缀，`usize` 版与其它格式返回 `StegoCapacityInfo` 的约定不一致；② 凭据参数在 embed（第 3-4 位）与 png probe（第 5-6 位）位置漂移。
- 建议：HEVC 保留 `probe_hevc_capacity_info` 为唯一公开 probe（`usize` 版降级为内部或改名 `max_raw_hevc_bytes`），并在指南/文档中用一句话说明"PNG 探测必须传 embed 同款凭据"。

### P2-6 `StegoCapacityInfo::total_elements` 与 bpp 口径跨格式不一致

- 位置：PNG `stego/png/engine.rs:1703`（`total_pixels = w*h`，全图每通道 1 份）；JPEG `stego/jpeg/engine.rs:1309、1332`（`total_coeffs = block_count * 64`，仅 luma 分量）；HEVC `stego/hevc/engine.rs:246-252`（像素数，无 SPS 时回退为槽位数）。
- 影响：`safety_bpp_limit` 字段名义是 bits/pixel，JPEG 实际按 bits/(luma 系数) 计。对 4:2:0 两者数值近似（luma 系数≈luma 像素），但 4:4:4 时 JPEG 的 total_elements≈luma 像素数而 PNG 的 total_pixels=全像素数，同一 tier 的"每像素预算"含义漂移；HEVC 无 SPS 时又变成"每槽预算"。`StegoCapacityInfo` 字段文档（`stego/mod.rs:262-291`）只写了 "pixels for PNG, coefficients for JPEG"，未提 HEVC 回退。
- 建议：字段文档补全三种口径；中期可增加 `total_pixels` 与 `total_elements` 两个字段分开报告。

### P2-7 `SafetyLevel::parse` 与 `FromStr` 行为不一致（数字别名只在一侧生效）

- 位置：`stego/params.rs:90-105`（`FromStr` 接受 `"0"/"1"/"2"` 数字别名）vs `stego/params.rs:127-135`（`parse()` 只接受名字，`parse("1")` 返回 `None`）。
- 影响：两个入口语义分叉；CLI 用 `SafetyLevel::parse`（`cli.rs:1819-1827`），因此 CLI 上 `--safety 1` 实际不可用（落到默认 High，静默接受错误输入前先检查 parse 失败即报错——`--safety 1` 会报 invalid），而库用户 `"1".parse()` 却合法。相反方向的不一致同样存在。
- 建议：`parse()` 内部委托 `FromStr`（或反之），只保留一处词表。

### P2-8 `PngParams::validate` 不校验 `exclusion_percentile`，引擎静默 clamp，违背 validate-first 原则

- 位置：`stego/params.rs:288-337`（`validate()` 检查窗口、epsilon、stc 参数、algorithm_options，唯独没有 `exclusion_percentile`）；字段文档 `stego/params.rs:206` 自述范围 "0.0 .. 0.9"；引擎在 `stego/png/engine.rs:938、1245、2840` 静默 `clamp(0.0, 0.9)`。
- 影响：传 `-0.5` 或 `1.5` 均不报错，被静默修正为 0.0/0.9。同一入口处其它参数（窗口、epsilon、stc_h/u）越界都是显式 `Err`，唯此参数静默改值——使用者拿不到"配置错了"的信号，且写入 feature word 的是 clamp 后的值，事后无法发现。
- 建议：`validate()` 增加 `exclusion_percentile` 的范围检查（0.0..=0.9），引擎的 clamp 保留为防御。

### P2-9 `epsilon` 的校验域（>0 任意）与线格式量化域（2^-1..2^-127）不一致，≥1.0 静默降为 0.5

- 位置：`stego/params.rs:317-322`（validate 只要求有限正数）；`stego/header.rs:195-198`（`quantize_epsilon`：`k = -log2(eps).round()` 后 `clamp(1.0, 127.0)`）；`stego/params.rs:262-270`（`wire_quantized` 以 `0.5^k` 回写）。
- 影响：`epsilon = 1.0`（log2=0）被 clamp 到 k=1，实际使用 0.5；`epsilon = 4.0` 同样变 0.5。validate 放行、量化静默改值，用户以为在用 1.0 实际是 0.5，且无任何警告。
- 建议：`validate()` 增加 `epsilon < 1.0`（或 `epsilon == 2^-k`）检查；`wire_quantized` 文档已说明量化，但 validate 是唯一能把错误拦在入口的地方。

### P2-10 公开字段类型 `Tlv` 藏在 `#[doc(hidden)]` 模块里

- 位置：`stego/params.rs:409-411`（`JpegParams.extensions: Vec<crate::stego::jpeg::header_v3::Tlv>`）；`stego/jpeg/mod.rs:7`（`#[doc(hidden)] pub mod header_v3;`）；`Tlv` 定义在 `stego/jpeg/header_v3.rs:229-241`（`pub struct Tlv { pub type_id: u8, pub value: Vec<u8> }`，`is_critical()`）。
- 影响：`JpegParams` 是完全公开的核心参数结构，其字段类型却只能通过 hidden 路径 `strhide::stego::jpeg::header_v3::Tlv` 构造——rustdoc 不会展示，语义上属于"公开类型躲在私有命名空间"。
- 建议：在 `stego::jpeg`（或 `stego::params`）re-export `Tlv`（`pub use header_v3::Tlv;`），或在 lib.rs 根导出。

### P2-11 `extract_png` 的 `cost_model` 参数形同虚设，但 API 强制要求

- 位置：`stego/png/engine.rs:1412-1425`（签名要求 `&dyn PngCostModel`）与 `1501-1514`（实现：真正的模型一律由 feature word 的 `algorithm_id` 解析，外部参数仅用于不一致时打一条 `trace` 日志）；统一入口为此每次 `CostModelRegistry::get_spatial_model(None).expect(...)`（`stego/mod.rs:214-215`）。
- 影响：调用者会误以为提取算法取决于该参数（比如传 HILL 提取 S-UNIWARD 载体会不会失败——不会）；签名把一个无行为影响的参数摆在了显著位置。
- 建议：接受现状但在参数文档写明"仅诊断提示"；或在未来版本改为 `Option<&dyn PngCostModel>` / 移除。

### P2-12 `probe_jpeg_capacity` 对 `algorithm` 名的校验是多余的（与 extract 阶段不对称）

- 位置：统一入口 `stego/mod.rs:370-377`（JPEG probe 分支先 `get_jpeg_model(options.algorithm)`，未知名报错）；而 `probe_jpeg_capacity` 内部（`stego/jpeg/engine.rs:1263-1341`）对 cost_model 的唯一使用是 `algorithm: cost_model.id().into()`（1331 行），**不计算任何 cost**（JPEG 槽集是几何的）。对照 extract 阶段完全不看算法名（`stego/mod.rs:197-207`）。
- 影响：一个只读容量、不嵌数据的调用会因 `--algorithm` 拼错而失败；同一载荷 extract 又不受影响。行为没有危害，但与"probe 是 embed 的预演"直觉相反（embed 确实需要合法模型）。
- 建议：统一入口的 JPEG probe 分支可容忍未知名（回落默认模型仅取名字），或在文档说明 probe 沿用 embed 的算法校验以保持报错一致。

### P2-13 HEVC 没有运行时调参结构，三个引擎的参数入口模式不统一

- 位置：PNG 从 `PngParams`（`codec`/`stc_h`/`stc_u`），JPEG 从 `JpegParams.stc_h`（u 由布局自动定），HEVC 的 `stc_h`/`stc_u` 固定在 `HevcFormatProfile`（`stego/format.rs:202-204`，默认 7/2），改它们=换格式=换 profile。
- 影响：三个格式的"trellis 几何"配置分散在三种对象里：PngParams（运行时）→ 载体 feature word 自描述；JpegParams（运行时）→ superblock 自描述；HevcFormatProfile（编译期）→ **不自描述**，读写两侧 profile 必须手工一致。使用者无法在运行时为 HEVC 选择 h/u（哪怕愿意自己保证两侧一致）。
- 建议：可接受（Scheme C 线上确实不带 h/u），但应在 `HevcFormatProfile` 文档与指南中把这三种模式并列说明（本报告配对的使用者指南 §11.3 已写）。

---

## P3 低优先级问题与改进建议

### P3-1 `StegoCodec::id()` 把 `Auto` 编码为 `Stc` 的 id，wire 层不存在 Auto

- 位置：`stego/params.rs:44-61`（`id(): Auto→1` 与 `Stc` 同值；`from_id(1)` 返回 `Stc`）。
- 说明：设计合理（Auto 是 embed 侧策略，实际选定的 u 写入载体），但 `from_id(1) == Stc` 而非 `Auto` 的往返不对称没有文档。建议在 `StegoCodec` 文档补一句"Auto 只存在于嵌入侧；线格式记录解析后的 (Stc, u)"。

### P3-2 `MAX_AUTO_BACKTRACK_BYTES` 与 `MAX_GROUPED_BACKTRACK_BYTES` 同值不同义

- 位置：`stego/params.rs:485、495`（均 4 GiB）。
- 说明：语义上一个管自动预算、一个管正确性驱动预算，当前数值相同纯属巧合。建议在常量文档互引，避免未来只改其一。

### P3-3 `JpegParams::deterministic` 是 pub 字段却 `#[doc(hidden)]`

- 位置：`stego/params.rs:429-433`。
- 说明：直接调用 `embed_jpeg` 的私有构建用户必须手动同步 `freshness.is_seeded()`（统一入口在 `stego/mod.rs:85` 自动做）。`#[doc(hidden)]` 让 rustdoc 不展示，但字段可写。建议字段文档直接写明与 `Freshness::Seeded` 的联动约定（`embed_jpeg` 的 doc 已提，字段本身未提）。

### P3-4 `algorithm` 值域文档分散；`"cabac"` 仅在 HEIF 分支有特殊语义

- 位置：值域唯一完整列表在 `StegoOptions::with_algorithm` 文档（`stego/params.rs:733`）；`"hevc"/"cabac"` 的分支行为在 `stego/mod.rs:130-133、229-233`（embed 强制 Scheme C / extract 失败时直接返回）；Annex-B 分支完全忽略 `algorithm`（`stego/mod.rs:154-163、251-253`）。
- 建议：把值域与分支语义集中到 `algorithm` 字段文档（使用者指南 §3.1 已替它完成，可回填到 rustdoc）。

### P3-5 HEIF 分支 embed 与 extract 的引擎优先顺序相反

- 位置：`stego/mod.rs:142-152`（embed：非 hevc/cabac 时先 bridge，失败回退 Scheme C）vs `stego/mod.rs:224-250`（extract：先 Scheme C，失败再 bridge；错误归因规则在 236-249 有细致处理）。
- 说明：方向正确（embed 按用户指定优先，extract 按"认证失败才定论"探测），但两侧顺序不同这一点没有任何文档。建议在 `embed_carrier`/`extract_carrier` 的 rustdoc 各加一行。另注意 extract 侧 `options.algorithm` 仅用于错误短路，不影响成功路径。

### P3-6 CLI 调参面与库参数面的覆盖差异未成文

- 位置：CLI 定义在 `src/cli.rs:256-323`（`StegoTuningArgs`）与 `src/cli.rs:1768-1775`（`apply_stc_h` 同时设置 png+jpeg 的 stc_h）。
- 现状：CLI 没有 `--stc-u`、`--codec`、`--epsilon`、`--wet-cost`、`--polarize-weight`、`--domain`（domain 只能编译期 Profile）；`--exclusion-rate` ↔ 库的 `exclusion_percentile` 名字不同；`--stc-h` 一杆双挑（png+jpeg 一起改）而库中两者独立。
- 建议：在 CLI `--help` 或文档中列一张"CLI↔库参数"对照（使用者指南 §14 已完成，可回填），并对 `--stc-h` 的双写行为加注。

---

## 附：核对过且确认无问题的点

以下易疑点已核对，**不是**问题：

1. `probe_jpeg_capacity` 不带凭据 / `probe_png_capacity` 带凭据：各自正确（JPEG 容量与凭据无关；PNG 的 512 header/feature 槽由凭据置换并从 body 池扣除，带不同凭据探测会得到不可达容量——PNG probe 的凭据是必需参数而非冗余）。
2. 统一入口 extract 的 PNG/JPEG 分支忽略 `algorithm`：正确（载体自描述，避免"拼错算法名导致可读载体被拒"）。
3. `PngParams::validate` 在 `codec == Hamming` 时不校验 `stc_h/stc_u`：正确（Hamming 不使用它们；Auto/Stc 才校验）。
4. `JpegParams::validate` 无条件校验 `stc_h`：正确（JPEG 恒为 ternary STC）。
5. `quantize_epsilon` 对极端 epsilon 不会 panic/溢出（clamp 到 1..=127，`stego/header.rs:195-198`）；`PngParams.validate` 拒绝非有限值。
6. `Freshness::Seeded` 的 (salt, nonce) 绑定 (cover, payload)（`stego/envelope.rs:191-242`），无 (key, nonce) 重用风险；JPEG 重试序列按 attempt 可复现。
7. JPEG over-optimised Huffman 的三重防御（grouped budget / wet cost / 复检重试）链路完整：`grouped_body_budget`（`stego/params.rs:523-538`）→ `embed_jpeg` 布局 → `layout_for_payload` 同口径报告。
8. `CostModelRegistry` 的名字表/wire id 表/清单三者有一致性测试兜底（`stego/registry.rs:157-240`），未知名字不静默别名（`registry.rs:131-138`）。
9. 错误面无 oracle：profile 不匹配、密码错误、无载荷统一为 `NoHiddenData`；HEIF 分支对 `Password` 判定优先采纳（`stego/mod.rs:236-249`）。
10. `embed_hevc` 对空 payload、`header_bytes < 24`、MP4 容器、容量不足均有显式前置检查（`stego/hevc/engine.rs:103-111、116-121、292-303、345-350`）。

## 修复优先级建议

| 优先级 | 条目 | 理由 |
|---|---|---|
| 1 | P2-1 | 安全语义缺口：Enforced 对 HEVC 无效，用户无法察觉 |
| 2 | P1-1, P1-2 | 默认值文档失实，直接误导参数选择 |
| 3 | P1-3, P1-4 | 文档失实，影响容量换算与首次上手 |
| 4 | P2-8, P2-9 | validate-first 缺口：静默 clamp/静默量化，越界配置无信号 |
| 5 | P2-2, P2-3, P2-5 | 专家入口签名统一（项目未发布，现在是 breaking 窗口期） |
| 6 | P2-4, P2-10, P2-6, P2-7, P2-11, P2-12 | API 卫生 |
| 7 | P2-13, P3-* | 文档补充类 |
