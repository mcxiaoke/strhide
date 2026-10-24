# stego 库接口 / CLI / 文档 整改 FixPlan（含实施总结）

> **编制时间**：2026-10-24 21:40（本机时间）
> **性质**：综合整改计划 →（全部批次完成后改写为实施总结报告）
> **综合来源**：
> 1. `docs/stego_public_api_cli_review_20261024.md`（本轮会话梳理，含 HEVC 补充复核 A11–A17）
> 2. `docs/stego_api_cli_full_audit_and_design_20261024_2120.md`（全面审计与设计，含缺失 API 清单 §3）
> 3. 代码实测补充：纯 `stego` 特性编译失败（4 处 `crate::adapters` 引用）；`FeatureWord.exclusion_permille` 自描述实证；提取端代价图重算实证。
>
> **用户裁定（2026-10-24 21:35）**：
> - **自定义代价模型注入（`custom_spatial_model`/`custom_jpeg_model`）去掉**，不进本期。traits 保留给专家面域引擎直接使用（`&dyn` 传参），统一入口只走注册表名称。
> - **format / params / profile 等类型与参数按主流习惯规范命名**（格式名优先：Jpeg/Png/Hevc）。
> - 原则：统一和规范接口、统一和规范命名、提高可靠性易用性、降低复杂度。
> - 分批实施、分批提交；完成后本文档改写为实施总结报告。

---

## 1. 目标命名规范（主流习惯：按载体格式命名，杜绝域/格式混用）

| 现名 | 新名 | 理由 |
|---|---|---|
| `stego::format::FormatProfile` | `JpegFormatProfile` | 现名过于通用，实际是 JPEG V3 专有；与 `PngFormatProfile`/`HevcFormatProfile` 对齐 |
| `stego::format::SpatialFormatProfile` | `PngFormatProfile` | 格式名优先，消除 spatial/jpeg 域与格式混用 |
| `DEFAULT_FORMAT` / `OFFICIAL_SPATIAL` | `DEFAULT_JPEG_FORMAT` / `OFFICIAL_PNG_FORMAT` | 同上 |
| `stego::params::SpatialParams` | `PngParams` | 与 `JpegParams` 对齐 |
| `stego::spatial` 模块（含 `spatial::cost`） | `stego::png`（`png::cost`） | 同上 |
| `stego::spatial::engine::{embed_spatial*, extract_spatial*, probe_spatial_*}` | `stego::png::engine::{embed_png*, extract_png*, probe_png_*}` | 同上 |
| `traits::SpatialCostModel` | `PngCostModel` | 与 `JpegCostModel` 对齐 |
| `StegoOptions.stego_domain` / `StegoProfile.stego_domain` | `domain` | 类型名已含 Stego，字段去冗余前缀 |
| `StegoOptions.spatial_params` | `png_params` | 同上 |
| `Profile::with_format_profile/with_spatial_profile/format_profile()/spatial_profile()` | `with_jpeg_format/with_png_format/jpeg_format()/png_format()`（新增 `with_hevc_format/hevc_format()`） | 与类型名对齐 |
| `StegoProfile.format/spatial` 字段 | `jpeg/png`（新增 `hevc`） | 同上 |
| 新增 `HevcFormatProfile`、`CarrierFormat`+`sniff_carrier()`、`SafetyPolicy` | — | 见 §3 |

保留不动的名：`StegoOptions`、`ExtractParams`、`StegoCodec`、`SafetyLevel`、`SafetyEnforcement`、`Freshness`、`StegoCapacityInfo`、`CostModelRegistry`、`JpegParams`、`JpegCostModel`、`JpegGeometry`、统一入口 `embed_carrier*`/`extract_carrier*`/`probe_carrier_capacity*`（carrier 为隐写界通用术语，与结构域 engine 一致）。

---

## 2. 批次总览（6 批，每批独立编译 + 测试 + 提交）

| 批 | 主题 | 关键项 | 风险 |
|---|---|---|---|
| 1 | CLI 死参数与文档漂移 | extract 删 `--neighbor-weight`/`--exclusion-rate`；补 help；i18n 0.20→0.30；README 删 `--codec`/`--stc-u`；sample.toml 补 `stego_domain` | 低（CLI 行为收缩，有测试守护） |
| 2 | 命名规范化 | §1 全表重命名，src/tests/examples/docs 同步 | 中（机械但面广，编译器驱动） |
| 3 | 公开面收敛 + 特性门修复 | 纯 stego 编译修复；删根级 `embed`/`extract`；删 6 个薄壳；内部原语 `doc(hidden)`；删 `h265` re-export；`with_*` 链式方法；`sniff_carrier`；`StegoCapacityInfo` 辅助；`SafetyLevel: FromStr`；新增 `stego::io` | 中高（公开面变化，examples/tests 同批修） |
| 4 | safety 单一源 | `SafetyPolicy`；`StegoOptions.safety` 单字段；params 删 safety；引擎显式接收 | 中（触引擎签名，全量回归） |
| 5 | HEVC 体系对齐 | `HevcFormatProfile`；入口签名扩展；魔数派生化；删第三份默认密钥；WIRE_SPEC 修正 + 一致性测试；NFC | 高（安全行为变化，CHANGES 明示） |
| 6 | CLI 分层 + 新能力 + 文档收官 | `hide=true`；`help_heading` 分组；`capacity` 子命令 + `--json`；`--dry-run`；stego help 单一事实源；`docs/api/STEGO-API.md`；ARCHITECTURE 同步；全量门禁；本文档→总结报告 | 中 |

---

## 3. 各批详细任务

### Batch 1 — CLI 死参数与文档漂移修正

1. `cli.rs` `ExtractArgs`：删除 `--neighbor-weight`、`--exclusion-rate`（提取端死参数：前者 JPEG 嵌入侧专有，后者已被 `FeatureWord.exclusion_permille` 自描述覆写）；`--p1-window`/`--p2-window` 保留并补 help（提取端重算 PNG 代价图必需）；`-a/--algorithm` 保留但 help 改为"仅 `hevc`/`cabac` 影响提取路由；PNG/JPEG 载体自描述算法"。
2. `warn_nondefault_stego_params`：警告清单去掉 exclusion（自描述），仅留 p1/p2。
3. `i18n/messages.rs`：`HelpEmbedExclusionRate` 默认值 0.20→0.30；新增 extract p1/p2 help 文案；`HelpStegoAlgorithm` 等与 cli.rs 对齐。
4. README（中英）：删除 `--codec`/`--stc-u` 两节，改写为"矩阵编码层由库自适应（STC u=3/2/1），Hamming 仅库可设"。
5. `strhide.sample.toml`：补 `stego_domain` 段（与 config.rs/README 一致）。
6. 测试：`tests/test_cli.rs` 同步；新增"help 默认值与代码常量一致"的守卫测试雏形（Batch 6 完善）。

### Batch 2 — 命名规范化

按 §1 表执行：`format.rs`、`stego/params.rs`、`params.rs`（Profile）、`traits.rs`、`spatial/→png/`（git mv + 函数重命名）、`lib.rs` 重导出、`facade.rs`、`cli.rs`、`analysis.rs`/`engine.rs` 引用点、`tests/**`、`examples/**`、`docs/api/ARCHITECTURE.md`、`docs/api/WIRE_SPEC.md`、README 代码样例。
- `SpatialFormatProfile.body: &'static JpegFormatProfile` 字段保留（PNG 体复用 JPEG V3 体派生是线格式事实），但文档写明耦合原因；不做字段级解耦（避免无收益的线格式折腾）。
- 验证：`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test --all-targets`。

### Batch 3 — 公开面收敛与特性门修复

1. **修复纯 stego 编译**：新增 `stego/sniff.rs`（`is_heif_bytes` + HEIF 品牌表 + `CarrierFormat{Png,Jpeg,Heif,HevcAnnexB,Unsupported}` + `pub fn sniff_carrier(&[u8]) -> CarrierFormat`）；`hevc/sniff.rs` 与 `stego/mod.rs` 改用它；验证 `cargo build --no-default-features --features stego`。
2. `lib.rs`：删除 `pub use stego::jpeg::engine::{embed_jpeg as embed, extract_jpeg as extract}`。
3. 删除 6 个无 profile 薄壳（`embed_png`/`embed_jpeg`/`extract_png`/`extract_jpeg`/`probe_png_capacity`/`probe_jpeg_capacity`），保留 `_with_format(_and_freshness)` 全量版。
4. 内部原语 `#[doc(hidden)]`：`prng`、`wavelet`、`coding`、`envelope`（`Freshness` 经 `stego::Freshness` 重导出保持可见）、`header`、`jpeg::{dht,header_v3,v3_layout,geometry}`、`hevc::{slot,bitstream,heif_boxes,sniff,error}`；删除 `pub use rust_h265 as h265`。
5. `StegoOptions` 链式方法：`with_password/with_algorithm/with_domain/with_safety/with_freshness/with_png_params/with_jpeg_params`（不做独立 Builder 类型，降复杂度；偏离审计 §3.1 缺失1 的 `builder()` 形态，理由：字段已 pub，`with_*` 已覆盖流式需求）。
6. `StegoCapacityInfo::fits_recommended/fits_max/summary_string`。
7. `SafetyLevel: FromStr`（大小写无关 + 数字别名 0/1/2）。
8. 新增 `stego::io`：`embed_carrier_file(carrier, target, payload, options, profile, backup) -> Result<Option<PathBuf>>`、`extract_carrier_file(carrier, options, profile) -> Result<Vec<u8>>`（自含原子提交 tmp+rename、`.bak`、时间戳保留；`filetime` 加入 `stego` 特性依赖）；`facade` 的 stego 文件方法改为委托 `stego::io`，消除双实现。

### Batch 4 — safety 单一源与凭据优先级

1. 新增 `SafetyPolicy { level, enforcement }`（`Default = High/Advisory`）；`StegoOptions.safety: SafetyPolicy` 单字段 + `with_safety(level, enforcement)`。
2. `PngParams`/`JpegParams` 删除 `safety_level`/`safety_enforcement`；`png/jpeg` 引擎 embed/probe 显式接收 `safety: SafetyPolicy`。
3. `stego/mod.rs` 统一入口单一注入（不再覆盖 params）；`heif` bridge 改用 `options.safety`。
4. `cli.rs` `--safety/--enforce-safety` 装配到 `SafetyPolicy`。
5. 全量回归：safety 三档 × enforce × PNG/JPEG/HEIC 矩阵（batch_stego 含安全拒绝用例）。

### Batch 5 — HEVC 体系对齐

1. `HevcFormatProfile { magic_label, cover_salt, kdf_info, stc_h, stc_u, header_bytes }` + `DEFAULT_HEVC_FORMAT`；`Profile::with_hevc_format()/hevc_format()`；`StegoProfile.hevc`。
   - h/u 放 FormatProfile 而非新开 `HevcParams`：HEVC 40 字节头部不自描述 h/u（ unlike JPEG superblock），属读写必须一致的方言级参数；偏离审计 §3.1 缺失5 的 `HevcParams`，理由：避免空壳类型与双事实源。
2. `embed_hevc(carrier, payload, secret, domain, &HevcFormatProfile, freshness)`、`extract_hevc(carrier, secret, domain, &HevcFormatProfile)`、`probe_hevc_capacity(carrier, &HevcFormatProfile)`；`stego/mod.rs` 传 `options.secret(profile)`/`options.domain(profile)`/`profile.hevc_format()`/`options.freshness`（修 A11 静默降级）。
3. 魔数派生化：`magic = SHA-256(magic_label ‖ secret)[..4]`，替换静态 `SH25`（修 A12 存在性预言机）；提取端用同一派生值校验。
4. 删除 `"strhide-hevc-default-key-2026"`，无密码回退 `PUBLIC_DEFAULT_SECRET`（与全库单一默认密钥体系一致）；cover digest 前缀改用 `cover_salt`；HKDF info 用 `kdf_info`；口令过 `normalize_nfc`；nonce 走 `freshness.nonce(0)`（支持 Seeded）。
5. WIRE_SPEC §13.11 按实现改写（魔数派生、标签常量、默认密钥回退、h/u 来源），新增一致性单测把规范字面量钉在代码上。
6. probe：`recommended_max_bytes` 维持物理容量并在文档明示"HEVC 容量不参与安全档位"（帧尺寸需解析 SPS，超出本期范围）。

### Batch 6 — CLI 分层、新能力与文档收官

1. `--slot-budget`/`--cipher-suite` 设 `hide = true`；专家参数归入 `help_heading = "Fine-Tuning Options"`；压缩帮助文案。
2. 新增 `capacity` 子命令（与 `embed --capacity` 同一实现）+ `--json`（输出 `StegoCapacityInfo` 序列化）。
3. `embed --dry-run`：内存中完整嵌入（容量/安全门/密码路径全走），输出容量与产物尺寸摘要，不落盘。
4. stego 参数 help 单一事实源：删除 `cli.rs` 中 stego 相关 `help=` 字符串，统一由 `cli_i18n` Msg 注入；新增测试断言 localize 后 en/zh help 均非空。
5. 新建 `docs/api/STEGO-API.md`（三层公开面 + 命名规范 + 凭据优先级表 + CarrotHash 接入配方 + HEVC 说明），ARCHITECTURE.md 同步新名。
6. 全量门禁：`cargo build --release`、`cargo test`、`cargo test --test batch_corpus -- --ignored`、`cargo test --test batch_stego -- --ignored`、`cargo fmt --check`、`cargo clippy --all-targets -D warnings`、`cargo build --no-default-features --features stego`。
7. 本文档改写为《实施总结报告》（每批实际改动、验证结果、偏离记录、遗留事项）。

---

## 4. 验收标准（继承审计 §5）

1. `cargo build --release` / `cargo fmt --check` / `cargo clippy --all-targets -D warnings` 全绿。
2. `cargo test --all-targets` + `batch_corpus` + `batch_stego`（ignored）全绿。
3. `cargo build --no-default-features --features stego` 通过（CarrotHash 特性组合）。
4. 纯 stego 消费者可用 `stego::io::embed_carrier_file` 完成文件级嵌入（CarrotHash ~150 行自建 I/O 可删除）——以文档化迁移样例替代实际改 CarrotHash（跨仓库，不在本期提交范围）。
5. HEVC：私有 profile 下无密码载体不可被官方默认密钥读取；静态魔数预言机消除（单测断言魔数随 secret 变化）。

---

## 5. 偏离记录（相对两份来源文档的裁定）

| # | 来源文档项 | 裁定 | 理由 |
|---|---|---|---|
| 1 | 审计 §3.1 缺失2 / 蓝图 L4：`custom_spatial_model`/`custom_jpeg_model` 注入 | **去掉** | 用户明确裁定；traits 保留于专家面 |
| 2 | 审计 §3.1 缺失1：`StegoOptions::builder()` 独立 Builder 类型 | 改为 `with_*` 链式方法 | 字段已 pub，减少一层类型，降低复杂度 |
| 3 | 审计 §3.1 缺失5：`HevcParams` | 取消，h/u 并入 `HevcFormatProfile` | HEVC 头部不自描述 h/u，属方言级；避免空壳与双事实源 |
| 4 | 审计 §3.2 缺失4：`--heif-mode` 新 flag | 不新增，`-a hevc/cabac` 语义文档化 | 少一个 flag，路由规则写进 README/STEGO-API |
| 5 | 审计 §3.2 缺失3：`--dry-run` 输出"真实失真度" | 收敛为"内存完整演练 + 容量/安全/尺寸摘要" | 嵌入引擎不返回失真统计，扩引擎超出本期 |
| 6 | 梳理文档 L3(b)：params 保留 safety 由入口条件注入 | 改为引擎显式接收 `SafetyPolicy` | 条件注入无法区分显式/默认，显式传参无歧义 |
| 7 | `SpatialFormatProfile.body` 字段级解耦 | 不做，仅重命名 + 文档说明 | 线格式事实耦合，解耦无收益 |
