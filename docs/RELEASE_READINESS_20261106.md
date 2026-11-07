# strhide 发布就绪度评估

> 评估时间：2026-11-06 18:16:03（本机时间）
> 评估对象：`HEAD = 0f91085`（`docs: record the disposition of every xhx review finding`），`rust/Cargo.toml` 版本 `0.9.1`
> 评估口径：**只记录本机实测结果**。未实测的项目在 §7 单独列出，不作推断性结论。
> 关联材料：`docs/CODE_REVIEW_20261106-xhx.md`、`docs/CODE_REVIEW_DISPOSITION_20261106_xhx.md`、`docs/api/{ARCHITECTURE,WIRE_SPEC,STEGO-API}.md`

> **2026-11-06 23:06 修订（口径变更，正文结论原样保留）**
>
> 本文 §2.4 / §4 P1-2 / §3 第 4 条把"规范能否支撑第三方独立实现"当作质量门禁。该口径不成立：
> strhide 是 CLI 工具，crate 是它的库形态，**项目不追求格式互操作**——规范文档的用途是指导本项目
> 开发（留住"为什么这样写"、防止误改），不是对外标准。
>
> 因此：
> - §2.4 的结论从"规范缺陷"降级为"已声明的效力边界"；
> - §3 第 4 条从 ❌ 改为 ➖（不适用），不再作为冻结前提；
> - §4 P1-2 视为已关闭（走"声明"路线，并已在 `WIRE_SPEC_CONTENT.md §13.0` 落地）。
>
> 其余各条（P0 打包、P1-1 格式静默期、P2 rustdoc、P2-3 tag 同步等）**结论不变**，仍是发布前要处理的事项。
> 本节之后正文按 18:16 的原样保留，便于对照。

---

## 0. 结论摘要

| 维度 | 判断 | 依据 |
|---|---|---|
| 工程架构 | **可公开发布** | 分层边界检查通过；分 feature 最小构建矩阵成立；字节级基线 28/28 |
| 代码质量 | **可公开发布** | 1080 用例 0 失败；clippy `-D warnings` 零警告；fmt 通过 |
| 公开接口 | **可公开发布，但缺少演进护栏** | facade 结构清晰；121 个公开 struct 未标 `non_exhaustive` |
| 线格式冻结前提 | **尚不成立** | 最近一次不兼容变更距今 1 天；crates.io 当前无法打包 |

**总体结论：工程质量已达到公开水准；"接口与格式冻结"的前提尚未成立。**

不建议现在按 `v1.0` / 稳定版发布。建议以 `0.9.x` 正式公开，将冻结推迟到 `1.0`。

关键前提：**crates.io 的 semver 语义下，`0.x` 系列允许破坏性变更**。"现在公开"与"承诺冻结"是两件独立的事，不必捆绑。存量用户接近零（crates.io 上 `strhide` 最高版本 `0.6.0`，累计下载 51 次），当前破坏性变更成本极低。

---

## 1. 实测门禁矩阵

全部在本机 `Windows 10 + Git Bash` 下执行，工作目录如命令所示。

| 门禁 | 命令 | 结果 |
|---|---|---|
| Release 构建 | `cargo build --release --all-features` | 通过，退出码 0 |
| 全量测试 | `cargo test --release --locked --all-features --all-targets` | **1053 passed / 0 failed / 27 ignored / 合计 1080** |
| 字节级基线 | `python scripts/baseline_hash.py --check` | **28/28 cases identical to baseline** |
| Clippy | `cargo clippy --all-targets --all-features -- -D warnings` | 通过，零警告 |
| 格式 | `cargo fmt --all --check` | 通过 |
| 架构边界 | `python scripts/import_lint.py` | `OK: all architectural boundaries intact` |
| 文档示例 | `cargo test --all-features --doc` | 8 passed / 0 failed |
| Rustdoc | `cargo doc --all-features --no-deps` | **9 个 warning**（见 §4 P2-1） |
| GUI 前端 | `cd gui && pnpm build` | 通过，1616 modules，无 TS 错误 |
| crates.io 打包 | `cargo package --no-verify --allow-dirty --all-features` | **失败**（见 §4 P0） |

测试用例分布（按测试二进制）：

| 测试目标 | passed | ignored |
|---|---|---|
| lib 单元测试 | 556 | 1 |
| `test_cli` | 140 | 0 |
| `test_lifecycle` | 156 | 1 |
| `test_media` | 15 | 1 |
| `test_pe` | 41 | 0 |
| `test_regression` | 118 | 0 |
| `test_security` | 25 | 0 |
| `local_tests` | 2 | 19 |
| `heavy_tests` | 0 | 5 |

> 说明：`ignored` 中的 19 个 `local_`（约 30–60 秒）与 5 个 `heavy_`（约 2 分钟）是本仓库约定的手动批量/矩阵测试，CI 不运行（`.github/workflows/ci.yml` 只跑默认的 `--all-targets`）。它们不计入 CI 门禁，但属于可复核项。

---

## 2. 维度评估

### 2.1 工程架构

**达标。** 以下机制是可复核的事实，不是主观判断：

- 两域互不引用的硬边界由 `scripts/import_lint.py` 每次 CI 校验：`structure !-> stego`、`stego !-> structure`、`core !-> {formats, structure, stego, cli, analysis}`、`formats !-> {structure, stego, cli, analysis}`、`analysis !-> cli`。
- CI 额外验证 8 种最小 feature 组合可独立编译（`--no-default-features` 起，逐个加 `structure-base` / `content-png` / `content-hevc` / `analysis` 等），确保下游可以裁剪依赖。
- 原子提交路径集中在 `core/commit.rs`：临时文件 + fsync + rename，只读目标提前拒绝，`TmpGuard` 与 `same_file` 校验。
- 字节级基线（`scripts/baseline_hash.py`）对 28 个真实语料做逐例 SHA-256 比对，覆盖 PNG/JPEG/WebP/MP4/MOV/MKV/HEIC/AVIF/PDF/ZIP/PE/WAV/FLAC。这是本项目最有分量的回归护栏。
- 多轮外部审查都有逐条处置台账（`docs/CODE_REVIEW_DISPOSITION_20261106*.md`），每条给出判定、证据行号、修复提交或搁置理由。

**架构文档与代码的一致性经抽查成立**：`docs/api/ARCHITECTURE.md` 中的模块分层、feature 依赖、公开 API 清单与 `rust/src/lib.rs`、`rust/Cargo.toml` 实际内容对应。

### 2.2 代码质量

**达标，边界清楚。**

| 指标 | 数值 |
|---|---|
| `rust/src` 总行数 | 76,812 |
| `unsafe` 出现次数 | 24（集中在 FFI / SIMD 路径） |
| TODO / FIXME / XXX / HACK | 1 |
| `unwrap()` / `expect()` 总数 | 820 |
| 其中测试模块内 | 583 |
| 非测试代码 | 237 |

对 237 处非测试 `unwrap/expect` 的抽样判断：绝大多数是"不可能失败"的断言，属于可接受用法：

- 定长切片转换：`stego/header.rs` 中的 `bytes[0..16].try_into().expect("16-byte salt slice")` 等，调用前已有长度校验；
- HKDF / PBKDF2 输出长度断言：`stego/envelope.rs`、`stego/format.rs`；
- 内置模型解析：`stego/options.rs` 中的 `expect("the built-in HILL model always resolves")`；
- 互斥锁中毒：`core/batch.rs` 的 `outcomes.lock().unwrap()`。

但需要如实记录两点边界：

1. `Cargo.toml` 的 release profile 配置了 `panic = "abort"`。作为**库**被下游链接时，任何 panic 都会终止宿主进程，无法被 `catch_unwind` 捕获。这一点应在 README 中如实声明。
2. 头部解析路径虽已校验长度，但 `expect` 分布在解析函数内部，若未来上游传入不满足前置条件的缓冲区（例如通过私有 API 直接调用），会触发 panic 而非返回 `StrHideError`。

### 2.3 公开接口

**设计合格，但缺少演进护栏。**

正面事实：

- 推荐入口统一为 `facade::StrHide`，双域通过 `engine.structure()` / `engine.stego()` 在类型上区分，避免了"两域动词同级"的歧义。
- 方言 `Dialect` 把跨读写的私有参数显式化，`Dialect::new()` 是官方方言，语义清楚。
- 所有 fallible 入口统一返回 `StrHideError`；`detail_i18n()` 返回结构化 `ErrorDetail`，GUI/服务端无需解析英文文本。
- 结果结构体字段名与 `--json` 输出已在阶段 4 定型（`strategy` 为 `{"id": N, "name": "..."}`，`warnings` 为带 `kind` 的对象数组）。

风险事实：

- **带 `pub` 字段的公开 struct 共 125 个，其中 121 个没有标注 `#[non_exhaustive]`，仅 4 个标注**（脚本按 `pub struct { pub 字段 }` 匹配统计；全仓库 `non_exhaustive` 共出现 14 次，其余作用在枚举与无字段 struct 上）。而 `docs/api/ARCHITECTURE.md:604` 声称"多个公开枚举/结构体（`LocalParams`、`StructureProfile`、`StegoProfile`、`Dialect`、`Warning`、`CompressionStrategy`、`RejectionPolicy` 等）标注 `#[non_exhaustive]`"。
- 后果：一经冻结，给这些类型新增字段即构成破坏性变更（对使用结构体字面量构造的下游）。典型受影响类型：`WriteOptions`、`ReadOptions`、`RestoreOptions`、`EmbedOptions`、`ExtractOptions`、`ProbeOptions`、`WriteResult`、`ReadResult`、`EmbedStats`、`EmbedOutput`、`StegoEmbedResult`、`DualInspect`、`DualVerify`、`ExtractOutcome`。
- `WriteOptions.strategy` 仍是 `&str`，拼写错误会被报成"适配器不支持"。`StrategyChoice` 已存在并提供 `with_strategy_choice`，但默认入口仍是字符串（`docs/CODE_REVIEW_DISPOSITION_20261106_xhx.md` XH-18 记录为可用性改进，未改）。

### 2.4 线格式与规范

**结构域接近"可独立实现"；内容域是"实现定义"，规范不支撑互操作。**

结构域（UBE v2.2）：

- `docs/api/WIRE_SPEC.md` §2–§12 给出了完整的字节布局：112 B header、24 B trailer、flags 位定义、AAD 范围、元数据块布局、分块载荷格式、KDF 标签、stealth 掩码规则、PE `ChannelHeader` 14 B 布局。
- 常量表齐备（§14），魔数、PBKDF2 轮数、HKDF 标签均明文给出。
- 结论：按规范可以独立写出读取器。这是真实的互操作价值。

内容域（V4 信封）：

- 规范给出了三套基础头（空间 64 B / JPEG 44 B / HEVC 32 B）的逐字段偏移、`body_len` 语义、AEAD AAD 组成、`CipherSuiteId` 枚举、TLV 规则、容量公式。
- **但未定义决定"payload 落在哪些槽位"的算法**：
  - 代价模型（HILL / S-UNIWARD / MiPOD / UERD / J-UNIWARD）的精确数值公式与边界处理；
  - `locate_seed` / `perm_seed` / `stc_seed` 到槽位序列的具体置换生成算法（`grep` 全文中"置换"仅以措辞出现，无算法定义）；
  - STC trellis 的网格生成方式与结束条件。
- 后果：第三方即使完全按规范实现，也无法从载体中提取出 payload。**冻结这份规范只能保证"本实现跨版本可读"，不能保证互操作。**
- 若对外称"公开格式规范"，需要在 `WIRE_SPEC.md` 首屏明确标注其定位为"布局规范（layout spec），互操作需同一实现"。

> **2026-11-06 23:06 修订**：上面这段是"如果把互操作当目标"的评估。按项目定位（CLI 工具，不做互操作），
> 它描述的是**已声明的效力边界**而不是缺陷：`docs/api/WIRE_SPEC_CONTENT.md` 已按域拆分，并在 §13.0
> 明确"不承诺第三方独立实现、不承诺跨平台逐位一致"，逐节标注 F/D/I 分级。
> 因此本条**不构成冻结阻塞**；内容域缺的那些算法，也已作为维护依据补进 §13.5–§13.11。

---

## 3. 冻结前提检查清单

若目标是 `v1.0` 并承诺"接口与格式不再变更"，以下条件必须全部满足。当前状态：

| # | 条件 | 当前状态 |
|---|---|---|
| 1 | crates.io 可成功 `cargo publish` | ⚠️ 阻塞已解除，待实际执行（§4 P0，`docs/CRATES_PUBLISH.md`） |
| 2 | 线格式在最近一段时间内无破坏性变更 | ❌ 最近一次 2026-11-05（§4 P1-1） |
| 3 | 公开 struct 全部具备演进护栏 | ❌ 121 / 125 未标 `non_exhaustive` |
| 4 | 规范足以支撑独立实现，或已明确声明为实现定义 | ➖ 不适用（已声明不做互操作，见 §2.4 修订） |
| 5 | rustdoc 无破损链接 | ❌ 9 个 warning |
| 6 | CI 覆盖 doctest | ❌ `.github/workflows/ci.yml` 不含 `--doc` |
| 7 | 版本号 / git tag / 发布产物三者同步 | ❌ tag 停在 `v0.6.0`，`release/` 已有 `v0.8.1`、`v0.8.2` |
| 8 | 存在 CHANGELOG 与 semver 政策文档 | ❌ 仅有 `docs/CHANGES-*.md` 工程日志，无面向用户的 CHANGELOG |
| 9 | 上游 vendor 库版本已冻结并发布 | ❌ 见 §4 P2-2 |

---

## 4. 发布阻塞项

### P0：crates.io 无法打包（硬阻塞）— **已关闭（2026-11-07 10:51）**

> **2026-11-07 10:51 修订**：已按「oxideav 用上游正式版 + rusty_h265 发布改名 fork」解决，详见
> `docs/CRATES_PUBLISH.md`。核心更正：下文的修复方向之二（`version` + `git` 双写）**不成立** ——
> 打包时 git 源会被剥离，依赖静默回落到 crates.io 同名上游版本，本地能编、线上丢补丁。
> 另外核查发现 `oxideav-h265` 的 fork 补丁（`encode_flush`）在 strhide 中 0 引用，锁定版本
> `db02660` 本身是纯上游代码，已直接改为依赖 crates.io `0.0.16`（字节基线 28/28 一致）。
> 以下原文保留作决策记录。

实测：

```text
$ cargo package --no-verify --allow-dirty --all-features
error: failed to verify manifest at `C:\Home\Projects\strhide\rust\Cargo.toml`
Caused by:
  all dependencies must have a version requirement specified when packaging.
  dependency `oxideav-h265` does not specify a version
```

根因：`rust/Cargo.toml:104` 与 `:107` 使用 git 依赖，且未同时给出 `version`：

```toml
oxideav-h265 = { git = "https://github.com/mcxiaoke/oxideav-h265.git", tag = "v1-20261024", optional = true }
rusty_h265   = { git = "https://github.com/mcxiaoke/rusty_h265.git",   tag = "v1-20261029", optional = true }
```

crates.io 规则要求所有依赖必须带版本号（打包时 git 来源会被剥离）。影响面：

- `cargo publish` 必然失败 → `.github/workflows/crates.yml` 在打 tag 时会红。
- `.github/workflows/release.yml` 与 `gui-release.yml` 的二进制构建不受影响（Cargo 允许 git 依赖参与构建）。
- 表现是"二进制能发，crate 发不出"，容易被误判为发布成功。

已发布状态对照：

| 项目 | crates.io 最高版本 | 本地 |
|---|---|---|
| `strhide` | `0.6.0`（2026-10-22，累计下载 51） | `0.9.1` |
| `oxideav-h265` | `0.0.16` | vendored tag `v1-20261024` |
| `rusty_h265` | `0.6.2` | vendored tag `v1-20261029` |

修复方向（二选一）：

- 把 vendor tag 上的代码发布成新的 patch 版本（如 `oxideav-h265 0.0.17`、`rusty_h265 0.6.3`），`Cargo.toml` 改为 `version` 依赖；
- 或使用 `version = "x.y.z", git = ...` 双写形式，让打包时回落到 crates.io 版本（需确认二者代码一致，否则线上构建与本地不同）。

### P1-1：线格式仍在震荡

最近三天的破坏性变更记录：

| 日期 | 变更 | 性质 |
|---|---|---|
| 2026-11-05 | `hvcC` 统一只保留 VPS/SPS/PPS，含 prefix SEI 的旧 MP4 隐写载体**无法被新版本读取**，按不兼容处理并重建基线 | 读侧不兼容（`docs/CHANGES-20261105.md:12`） |
| 2026-11-05 | STC 改动导致 55 处 `stego_sha256` / `stego_size` 差异，覆盖 JPEG/PNG/HEVC/FLAC/WAV/MOV/HEIC | 写侧字节变化（`docs/CHANGES-20261105.md:51`） |
| 2026-11-06 | Simple WebP 的 auto 策略由 `riff_chunk` 改为 `eof`，2 例基线字节变化 | 写侧字节变化（`docs/CHANGES-20261106.md` 批次 2） |
| 2026-11-06 | `eof` 信封位移后的读取路径（XH-01） | 读侧行为修正 |

判断：格式尚未进入静默期。**最近一次读侧不兼容变更距今 1 天。** 在这之前冻结，等于把"格式仍在调整"的成本一次性转为"永久兼容负担"。

需要区分：XH-01 这类是"修复原本就该工作的路径"，冻结后不会产生结构性问题；而 STC 参数调整、`hvcC` 解析口径收窄属于"改变既有产物的可读性/字节"，冻结后必须保留旧读路径。

### P1-2：内容域规范不足以支撑独立实现（**已关闭**）

> **2026-11-06 23:06 修订**：按"声明"路线关闭。`WIRE_SPEC_CONTENT.md §13.0` 已声明本项目不承诺
> 互操作，并给出 F/D/I 分级与写作约定；本条不再作为发布阻塞项。以下原文保留作决策记录。

见 §2.4。冻结前必须在以下两者中做出选择：

- **补齐**：在 `WIRE_SPEC.md` 中补入代价模型公式、置换算法、STC 网格定义（工作量大，且与实现强耦合，容易再次漂移）；
- **声明**：在规范首屏明确"这是布局规范而非互操作规范，读写需同一实现"，避免下游误判。

推荐后者。理由：私有方言（`StegoProfile`）本身就是设计目标之一，格式身份按编译期常量区分，本就不以跨实现互操作为目标。如实声明比虚假承诺更稳妥。

### P2-1：Rustdoc 破损链接

`cargo doc --all-features --no-deps` 产生 9 个 warning：

```text
warning: unresolved link to `CipherSuiteId`
warning: unresolved link to `Credential`
warning: public documentation for `MAX_ISOBMFF_META_SCAN` links to private item `read_meta_box_bytes`
warning: public documentation for `parse_channel_header` links to private item `CHANNEL_HEADER_BITS`
warning: public documentation for `mkv_boxes` links to private item `read_vint_size`
warning: unresolved link to `crate::stego::header::FeatureWord::sigma`
warning: unresolved link to `Domain::Stego`
warning: unresolved link to `Domain::Diagnostics`
warning: unresolved link to `Domain::All`
```

影响：docs.rs 上首屏即可见破损链接，直接影响"公开接口"的观感。修复成本低（补 `use` 或改为纯文本），应在发布前完成。

### P2-2：依赖链行为也是线格式的一部分

HEVC / HEIF 的字节输出依赖 vendored 上游库的 CABAC 重编码细节。`docs/CHANGES-20261106.md` 记录的 F-02 回退事件是直接证据：

> 删除 `stego/hevc/engine.rs` 中"重编码短 1–4 字节时补 0"的分支后，`IMG_5887.HEIC` 的 `content.algorithms.cabac` 从 `ok` 变为 `embed_failed`。该分支是真实 HEIC 载体正常路径所需。

即：冻结格式等于同时冻结 `oxideav-h265` / `rusty_h265` 的行为。发布说明中必须写明版本锁定策略，否则上游一次重构就会让旧载体不可读。

### P2-3：版本管理三方不同步

- git tag 停在 `v0.6.0`；
- `release/` 目录已有 `v0.8.1`、`v0.8.2` 产物；
- `Cargo.toml` 与 `gui/package.json` 均为 `0.9.1`。

发布流程实际执行过，但 tag 未同步打。建议在发布检查清单中加入"tag 与版本号一致性"校验。

### P3：已知搁置项（不阻塞，但应在文档声明）

来源：`docs/CODE_REVIEW_DISPOSITION_20261106_xhx.md` §11。

| 条目 | 内容 | 搁置理由 |
|---|---|---|
| A2 | 库层 8 处 `eprintln!` 直写 stderr | 仅在时间戳/权限还原失败时触发，不改变写入结果 |
| A3 | 全局 `AtomicU8` 语言 + 全局 rayon 池 | 影响同进程多租户/多语言嵌入；单进程 CLI 不受影响 |
| XH-04 | 大图内存准入无 `try_reserve` | 需数十 MP 图像 + 内存吃紧 |
| XH-05 | `verify` 固定 1 GiB 上限 vs `read` 按载体缩放 | 需伪造使用公开内置密钥的"已认证"deflate 炸弹 |
| XH-09 | stdin/文件载荷先全量读入再判上限 | 需数十 GB 输入 |
| XH-20 | 大载荷整体缓冲无 `try_reserve` | 需 ~1 GiB 载荷 + 内存压力 |
| R1/R2/R3 | Windows ACL 错误归类、补丁提交不复核源 mtime、Unix 目录 fsync 失败被吞 | 罕见环境/竞态，无数据丢失 |

这些项的共同特征：触发需要构造性条件或极端资源，且均无静默数据损坏。可作为已知边界写入 README 的 "Known limitations"。

---

## 5. 建议路径

### 路线 A（推荐）：现在发 `0.9.x`，冻结留到 `1.0`

理由：

1. `0.x` 语义下允许破坏性变更，**发放不消耗任何冻结额度**。
2. 存量用户接近零（`0.6.0` 下载 51 次），当前公开的破坏成本最低。
3. 格式仍在震荡，现在承诺冻结会把未定型的设计永久固化。

发布前最小工作量（按优先级）：

| 顺序 | 事项 | 预估 |
|---|---|---|
| 1 | 修 P0：上游发版 + `Cargo.toml` 改 version 依赖，`cargo package` 通过 | 半天 |
| 2 | 修 P2-1：9 个 rustdoc warning 清零 | 1 小时 |
| 3 | CI 增加 `cargo test --doc` 与 `cargo doc -D warnings` | 半小时 |
| 4 | README 增加 "Pre-1.0 notice"：API 与线格式在 1.0 前可能变更 | 半小时 |
| 5 | 补 CHANGELOG（面向用户，非工程日志） | 1–2 小时 |

### 路线 B：直接发 `1.0` 并冻结

不建议。必须先把 §3 的 9 项全部转为 ✅，其中第 2 项（格式静默期）无法靠工程手段加速，只能等待。建议至少观察 2–4 周无破坏性变更后再考虑。

### 无论哪条路线，都建议先做

**批量补 `#[non_exhaustive]`**。这是唯一一项"越晚做成本越高"的改动：现在加是零成本的编译期标注，冻结后再加就是对下游的破坏性变更。建议覆盖全部带 `pub` 字段的公开 struct，同步修正 `docs/api/ARCHITECTURE.md:604` 的描述。

---

## 6. 未验证项与残余风险

本次评估**未运行**以下项目，不作结论：

| 项目 | 原因 | 建议 |
|---|---|---|
| `local_` 批量测试（19 个 ignored） | 约 30–60 秒，本机未跑 | 发布前手动跑一次 |
| `heavy_` 矩阵测试（5 个 ignored） | 约 2 分钟，本机未跑 | 发布前手动跑一次 |
| 四个 stress 示例（`jpg/png/hevc/audio_stress`） | 耗时较长 | 发布前至少在目标平台各跑一轮 |
| GUI `test:unit` / `test:cross` / `test:e2e` / `test:e2e:real` | 需 Playwright 浏览器与 `StrHideStudio.exe` 产物 | 独立于本次 crate 评估，需单独验证 |
| macOS / Linux 实机运行 | 仅有 CI 覆盖 | 依赖 CI 矩阵（ubuntu + windows）结果 |

此外，`docs/CODE_REVIEW_DISPOSITION_20261106_xhx.md:125` 记录的 4 项"未复现、不作判定"的风险观察项（ISO-BMFF `item_hidden` 对称性、PDF 多 `%%EOF` 锚定、PE 跳转表误判、CLI `--auto` 批量上下文）仍未构建运行时夹具，属于**未闭环**的观察项，不等于已排除。

---

## 7. 复现命令

```bash
cd rust
cargo build --release --all-features
cargo test --release --locked --all-features --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo test --all-features --doc
cargo doc --all-features --no-deps
cargo package --no-verify --allow-dirty --all-features

cd ..
python scripts/import_lint.py
python scripts/baseline_hash.py --check

cd gui && pnpm build
```
