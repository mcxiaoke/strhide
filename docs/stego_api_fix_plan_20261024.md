# stego 库接口 / CLI / 文档整改实施总结报告

> **原编制**：2026-10-24 21:40（整改计划）
> **本文档状态**：六批整改**全部完成**，原 FixPlan 改写为实施总结报告（2026-10-24 23:10 更新）。
> **综合来源**：`stego_public_api_cli_review_20261024.md`（接口梳理）+ `stego_api_cli_full_audit_and_design_20261024_2120.md`（全面审计）+ 代码实测补充。
> **用户裁定**：自定义代价模型注入去掉；format/params/profile 按主流习惯规范命名；统一规范接口与命名、提高可靠性易用性、降低复杂度；分批实施分批提交。

---

## 1. 实施结果总览

| 批次 | 主题 | 提交 | 状态 |
|---|---|---|---|
| Batch 1 | CLI 死参数清理与文档漂移修正 | `4d16567 refactor(cli): prune dead extract flags, fix help drift, document stego_domain` | ✅ |
| Batch 2 | 命名规范化（主流格式名优先） | `1b83a29 refactor(stego): rename public surface to mainstream format-based names` | ✅ |
| Batch 3 | 公开面收敛与特性门修复 | `59dafc3 refactor(stego): converge public surface, fix pure-stego build, add stego::io` | ✅ |
| Batch 4 | safety 单一源与凭据优先级 | `404e5fd refactor(stego): single source of truth for the capacity safety policy` | ✅ |
| Batch 5 | HEVC 体系对齐 | `68f92d0 feat(hevc): HevcFormatProfile dialect, derived magic, unified credentials` | ✅ |
| Batch 6 | CLI 分层、新能力与文档收官 | `cd92121 feat(cli): capacity subcommand, --dry-run, tiered help, API doc` | ✅ |

**最终验证（每批均独立跑过，收尾再全量复核）**：
- `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`：零告警。
- `cargo test --all-targets`：**592 通过 / 0 失败**（含新增守卫测试）。
- `cargo test --test batch_stego -- --ignored`（内容域真实载体批测）：通过。
- `cargo test --test batch_corpus -- --ignored`（结构域批测）：通过。
- `cargo test --test test_hevc_stego -- --ignored`（外部 HEIC 语料）：2 通过。
- `cargo build --no-default-features --features stego`（CarrotHash 特性组合）：**修复后通过**。
- 其余特性组合（engine-only / 无特性 / 默认）：全部通过。
- CLI 端到端冒烟：embed / extract / capacity / --json / --dry-run / help 分组全部实测。

---

## 2. 各批实际改动

### Batch 1 — CLI 死参数与文档漂移修正（commit `4d16567`）

- extract 删除死参数 `--exclusion-rate`（载体 `FeatureWord.exclusion_permille` 自描述）与
  `--neighbor-weight`（JPEG 嵌入侧专有）；**保留并补齐 help** 的 `--p1-window/--p2-window`
  是提取端活参数（重算 PNG 代价图必需）——实施中纠正了并行会话误删这两个 flag 的中间状态。
- `--algorithm`（extract）帮助改为"仅 hevc/cabac 影响路由；PNG/JPEG 载体自描述"。
- `warn_nondefault_stego_params` 去掉 exclusion（自描述），仅警告 p1/p2。
- i18n `HelpEmbedExclusionRate` 默认值 0.20 → 0.30（与代码常量对齐）；stego help 覆盖
  限定到 embed 命令作用域。
- README（中英）删除已不存在的 `--codec`/`--stc-u` 章节，改写为自适应 STC 描述并
  修正"默认 Hamming"的错误说法（实际默认 Auto→STC 自适应）。
- `config.rs` 模块文档与 `strhide.sample.toml` 补 `stego_domain`/`STRHIDE_STEGO_DOMAIN`。

### Batch 2 — 命名规范化（commit `1b83a29`）

按用户裁定执行主流格式名优先的整套重命名（36 文件）：

| 原名 | 新名 |
|---|---|
| `FormatProfile` / `DEFAULT_FORMAT` | `JpegFormatProfile` / `DEFAULT_JPEG_FORMAT` |
| `SpatialFormatProfile` / `OFFICIAL_SPATIAL` | `PngFormatProfile` / `OFFICIAL_PNG_FORMAT` |
| `SpatialParams` / `spatial_params` | `PngParams` / `png_params` |
| `SpatialCostModel`、`stego::spatial` 模块 | `PngCostModel`、`stego::png`（git mv） |
| `embed/extract/probe_spatial*` | `embed/extract/probe_png*` |
| `StegoOptions.spatial_params` / `.stego_domain` | `.png_params` / `.domain` |
| `StegoProfile.format/spatial` | `.jpeg/png` |
| `Profile::with_format_profile/with_spatial_profile/format_profile()/spatial_profile()` | `with_jpeg_format/with_png_format/jpeg_format()/png_format()` |

tests / examples / docs（README 中英、ARCHITECTURE.md、WIRE_SPEC.md）同批同步；
ARCHITECTURE.md 的 `StegoOptions` 字段清单修正（补 `extract_params`、JpegParams
真实字段）。

### Batch 3 — 公开面收敛与特性门修复（commit `59dafc3`）

- **修复纯 stego 编译**（本轮实测新发现的 P0）：新增非门控 `src/sniff.rs`
  （HEIF 品牌探测 + PNG/JPEG magic），`stego/mod.rs` 与 `hevc/sniff.rs` 不再引用
  engine 门控的 `adapters`；CarrotHash 的 `default-features=false, features=["stego"]`
  从编译失败恢复为可用。
- 新增 `stego::sniff::{CarrierFormat, sniff_carrier}` 公开嗅探。
- 删除根级误导性 `strhide::embed` / `strhide::extract`（实为 JPEG 专用）。
- 域引擎收敛为每动词一个完整入口：`png::engine::{embed_png, extract_png,
  probe_png_capacity}`、`jpeg::engine::{embed_jpeg, extract_jpeg,
  probe_jpeg_capacity}`（format/model/params/safety/freshness 全显式），删除 6 个
  层层委托的薄壳。
- 内部原语 `#[doc(hidden)]`：`coding`/`envelope`/`header`/`prng`/`wavelet`/
  `jpeg::{dht,geometry,header_v3,v3_layout}`/`hevc::{bitstream,error,heif_boxes,slot,sniff}`；
  hevc 仅重导出三个引擎入口；删除 `pub use rust_h265 as h265` 依赖外泄。
- `StegoOptions` 链式 builder（`with_password/with_algorithm/with_domain/
  with_safety/with_freshness/with_png_params/with_jpeg_params`）；
  `StegoCapacityInfo::{fits_recommended, fits_max, summary_string}`；
  `SafetyLevel: FromStr`（含数字别名 0/1/2，CarrotHash 不必自建解析）。
- 新增 `stego::io::{embed_carrier_file, extract_carrier_file}`：纯 stego 特性可用的
  文件级接口（原子提交 + `.bak` + 时间戳保留）；提交管线移入非门控 `src/commit.rs`
  与结构域共享（facade 改为委托，双实现归一）。
- 修复**存量**特性门漏洞：engine-only 与 no-features 编译从失败恢复为通过
  （engine/facade/params 的 stego 引用补 `#[cfg(feature = "stego")]`）。

### Batch 4 — safety 单一源（commit `404e5fd`）

- 新增 `SafetyPolicy { level, enforcement }`（Default = High/Advisory，
  `is_enforced()`）；`StegoOptions.safety` 单字段。
- 从 `PngParams`/`JpegParams` 删除 `safety_level`/`safety_enforcement`——原先统一入口
  会静默覆盖，调用方单独设置 params 的 Enforced 实际不生效（脚枪消除）。
- png/jpeg 引擎显式接收策略（jpeg 经 `EmbedContext`），probe 保留 level 参数；
  HEIF bridge 与 CLI `--safety/--enforce-safety` 装配到同一策略。
- 生命周期回归测试（Paranoid+Enforced 拒绝 / Advisory 放行）守护单一源行为。

### Batch 5 — HEVC 体系对齐（commit `68f92d0`）

- 新增 `HevcFormatProfile { magic_label, cover_salt, kdf_info, stc_h, stc_u,
  header_bytes }` + `DEFAULT_HEVC_FORMAT`；`Profile::with_hevc_format/hevc_format()`、
  `StegoProfile.hevc`——Scheme C 从"模块内硬编码常量"变为与 PNG/JPEG 对等的
  可定制方言（私有构建改标签重建即可，无需 fork）。
- **消灭存在性预言机**：固定魔数 `SH25` → `SHA-256(magic_label ‖ effective_secret)[..4]`
  派生。头部槽位仅由参数集决定（设计要求），固定魔数使任何无凭据者可判定
  "文件藏过数据"；派生化后无凭据视角下载体与空载体不可区分。
- **凭据统一**：`embed_hevc/extract_hevc/probe_hevc_capacity` 签名扩展为
  (secret, domain, fmt[, freshness])；统一入口改传 `options.secret(profile)`/
  `options.domain(profile)`——修复私有 stego_secret 对 HEIC/HEVC 静默失效
  （P0，复演 2026-10-20 M1b 已修 bug 的回归）。
- 删除第三份公开默认密钥常量 `"strhide-hevc-default-key-2026"`，无密码回退统一为
  `PUBLIC_DEFAULT_SECRET`；口令 NFC 规范化；`stego_domain` 经
  `derive_domain_subkey_with_label(b"strhide-hevc-domain-v1", …)` 子密钥化。
- `Freshness::Seeded` 对 HEVC 生效（nonce 走 seeded 派生）。
- WIRE_SPEC §13.11 按实现改写（派生魔数、精确标签、凭据链、威胁模型说明），
  常量速查表同步；新增 `dialect_tests`（规范字面量钉死、魔数随凭据变化、
  默认密钥唯一、域隔离生效）。

### Batch 6 — CLI 分层、新能力与文档收官（commit `cd92121`）

- 新增 `strhide capacity [CARRIERS]...` 只读探测子命令（与 `embed --capacity`
  共享 `run_capacity_probe`），支持 `--json`（`StegoCapacityInfo` 序列化），
  JSON 模式跳过 banner。
- `embed --dry-run`：内存完整演练（容量、安全门、凭据路径），报告产物尺寸，
  不落盘；跳过 overwrite 预检，与 `--capacity` 互斥。
- 调参/凭据 flag 抽为 `StegoTuningArgs`，embed 与 capacity flatten 共享——
  容量答案永远绑定其探测时的调参组合，且消除 flag 重复定义。
- 专家调参归入 `help_heading = "Fine-Tuning Options"` 分组；
  `--slot-budget/--cipher-suite` 维持隐藏。
- **help 单一事实源**：stego 范围参数（含 embed/extract/capacity 全部 15 处）的
  clap 内联英文 help 删除，统一由 i18n 消息表注入；extract 的 `--algorithm`
  （路由语义）与 `--p1/--p2`（embed-time 语义）有专属文案；新增守卫测试
  `tests/cli_help_guard.rs` 遍历 localize（en/zh）后全命令树断言 about/help 非空。
- 新建 `docs/api/STEGO-API.md`：公开面三层模型、命名规范、凭据优先级表、
  CarrotHash 私有方言配方（三域 const Profile）、自定义模型扩展点、CLI 映射表、
  守卫清单。

---

## 3. 偏离记录（相对来源文档的裁定，均已兑现）

| # | 来源文档项 | 裁定 | 结果 |
|---|---|---|---|
| 1 | 审计 §3.1 缺失2：`custom_spatial_model`/`custom_jpeg_model` 注入统一入口 | **去掉**（用户裁定）；traits 保留专家面 `&dyn` 直调 | ✅ 统一入口仍走注册表名称匹配，文档明示 |
| 2 | 审计 §3.1 缺失1：独立 `StegoOptionsBuilder` 类型 | `with_*` 链式方法替代 | ✅ 少一层类型 |
| 3 | 审计 §3.1 缺失5：`HevcParams` | 取消，h/u 并入 `HevcFormatProfile`（头部不自描述，属方言级参数） | ✅ 避免空壳与双事实源 |
| 4 | 审计 §3.2 缺失4：新增 `--heif-mode` | 不加 flag，`-a hevc/cabac` 路由语义文档化（STEGO-API.md §5） | ✅ |
| 5 | 审计 §3.2 缺失3：`--dry-run` 输出真实失真统计 | 收敛为内存演练 + 尺寸/增量摘要 | ✅ 不扩引擎返回面 |
| 6 | 梳理文档 L3：params 保留 safety 由入口注入 | 引擎显式接收 `SafetyPolicy` | ✅ 无歧义 |
| 7 | `PngFormatProfile.body` 字段级解耦 | 不做，仅重命名 + 文档说明（线格式事实耦合） | ✅ |

## 4. 计划外新增修复（实施中实测发现）

| # | 发现 | 修复 |
|---|---|---|
| 1 | 纯 `stego` 特性编译失败（4 处 `crate::adapters` 引用）——CarrotHash 特性组合不可用 | `src/sniff.rs` 共享探测 + 引用改道（Batch 3） |
| 2 | engine-only / no-features 编译失败（存量：engine/facade/params 无条件引用 stego） | 补 `#[cfg(feature = "stego")]` 门控，四种特性组合全绿（Batch 3） |
| 3 | 并行会话误删 extract 的 `--p1/--p2-window`（活参数） | 恢复并补 help 与端到端验证（Batch 1） |
| 4 | facade 的 `run_cli_from` 未门控 `crate::cli` | `#[cfg(feature = "cli")]`（Batch 3） |
| 5 | capacity 子命令默认输出路径触发 overwrite 预检误报（dry-run 不写文件） | dry-run 跳过预检（Batch 6） |

## 5. 遗留事项（超出本期范围，记录备查）

1. **CarrotHash 迁移**：strhide 侧 API 已就绪（`Profile::with_hevc_format`、
   `StegoOptions::with_safety`、`stego::io`、`SafetyLevel: FromStr`），CarrotHash
   约 150 行自建 I/O 与 4 处 safety 同步可删除；属另一仓库，未在本期提交范围。
   迁移配方见 `docs/api/STEGO-API.md` §3。
2. **HEVC 容量与安全档位**：`probe_hevc_capacity` 的 `recommended_max_bytes` 仍为
   物理容量，不随 `--safety` 折算（需解析 SPS 帧尺寸）；已在 STEGO-API.md 明示。
3. **非 stego 命令（write/read/restore…）的 help 双份维护**：本期单一事实源化仅覆盖
   stego 范围参数；其余参数沿用 clap 内联英文 + i18n 覆盖，模式与守卫测试已就绪，
   可按同法渐进收敛。
4. **HEVC 头部不自描述 h/u**：如需方言外可读，需线格式扩展位（v3 级变更），
   当前以 `HevcFormatProfile` 方言约束替代。
5. **conseal 数值预言机回归**（来源文档 G 项）：仍未做，独立事项。

## 6. 数据溯源

| 项 | 位置 |
|---|---|
| 整改计划（原 FixPlan） | 本文件前版（git 历史 `cd31fc3`） |
| 接口梳理报告 | `docs/stego_public_api_cli_review_20261024.md` |
| 全面审计与设计 | `docs/stego_api_cli_full_audit_and_design_20261024_2120.md` |
| 公开面权威规范 | `docs/api/STEGO-API.md` |
| 线格式规范 | `docs/api/WIRE_SPEC.md` §13.11（Scheme C） |
| 变更登记 | `docs/CHANGES-20261024.md` |
