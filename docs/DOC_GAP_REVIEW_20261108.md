# 公开发布前的文档缺口梳理 (Documentation Gap Review)

> 记录时间：2026-11-08 16:17:09
> 范围：仓库根目录 + `docs/` + `gui/` + `.github/`，对照一个即将公开发布的开源项目的文档基线。
> 方法：逐目录清点 → 读 README/CHANGELOG/规范/工作流 → 用 `cargo metadata` 与代码抽查核对事实 → 与"公开发布需要什么"逐项比对。
> 结论先行：**技术规范类文档成熟度很高（线格式 19 篇可支撑第三方实现）；缺的全是对外发布配套文档——用户上手、法律合规、安全披露、贡献流程。**

---

## 1. 梳理时的存量

| 类别 | 存量 | 评价 |
| :--- | :--- | :--- |
| 总览 | `README.md` / `README.zh.md` / `rust/README.md` | 完整，中英双语 |
| 线格式规范 | `docs/api/spec/` 19 篇（CRYPTO / CAPACITY / DETMATH / 两域信封 / 9 个结构适配器 / 4 个内容载体 / CORRECTIONS） | **最强的一块**，含稳定性分级、自检向量、第三方实现路线 |
| 架构与 API | `docs/api/ARCHITECTURE.md`（53 KB）、`docs/api/STEGO-API.md` | 完整，含三层公开面与守卫声明 |
| 操作指南 | `docs/CLI_GUIDE.md`、`docs/PRIVATE_BUILD.md`、`docs/CRATES_PUBLISH.md` | 完整，但 `README.md` 未收录后三篇中的 CLI 指南 |
| 性能 | `BENCHMARK.md` + `docs/BENCH_*_20261107.md`（含 SVG） | 完整，含方法论与原始样本 |
| 变更 | `CHANGELOG.md`（Keep a Changelog，0.9.3） | 规范 |

## 2. 缺口清单与处理状态

### P0 — 没有就不能公开发布

| 缺口 | 为什么 | 状态 |
| :--- | :--- | :--- |
| 安全披露政策 | 加密 + 隐写工具必然被审；无渠道等于放弃漏洞管理 | ✅ `SECURITY.md`（含"已知设计边界"表，防止把设计当漏洞报） |
| 法律与合规 | 全仓库此前 grep 不到 `patent`/`disclaimer`/出口管制表述；HEVC 涉专利池，工具有双用途属性 | ✅ `LEGAL.md`（许可证/专利/出口管制）+ `DISCLAIMER.md` / `DISCLAIMER.zh.md`（使用风险与责任限制，两份 README 均已引用） |
| 第三方许可 | 依赖含 MIT/Apache-2.0/BSD/ISC/Zlib/MPL-2.0 多族；fork 需保留署名 | ✅ `THIRD_PARTY_LICENSES.md` + `NOTICE` + `docs/licenses/` 三份生成清单 + 生成脚本 |
| 安装与首跑 | README 只讲架构与命令示例，没有"下载哪个包、怎么验证、未签名怎么办" | ✅ `INSTALL.md` |
| 贡献流程 | `AGENTS.md` 面向 AI，`CLI_GUIDE` 面向用户，没有面向人贡献者的入口 | ✅ `CONTRIBUTING.md` + `CODE_OF_CONDUCT.md` |
| 威胁模型 | 安全边界此前散落在设计文档与规范里，用户会严重误判能力 | ✅ `docs/THREAT_MODEL.md` |

### P1 — 用户拿到手就能用起来

| 缺口 | 状态 |
| :--- | :--- |
| 桌面端使用指南（此前 `gui/` 下无任何 markdown） | ✅ `docs/GUI_GUIDE.md`（含 GUI↔CLI 术语交叉映射表）+ `gui/README.md` |
| FAQ / 排错 | ✅ `docs/FAQ.md`（26 问，全部有代码或规范出处） |
| 文档索引与阅读路径 | ✅ `docs/README.md` |
| 关键文档英文版 | ⏳ 仅确认缺口，未动手：`docs/api/spec/` 仍为中文，第三方实现者读不到（见 §5） |

### P2 — 工程可信度

| 缺口 | 状态 |
| :--- | :--- |
| 开发环境（含 vendor/fork 机制） | ✅ `docs/DEVELOPMENT.md` |
| 测试策略 | ✅ `docs/TESTING.md` |
| 发布流程 | ✅ `docs/RELEASE.md` |
| 算法选型指南 | ✅ `docs/ALGORITHM_GUIDE.md`（含三档位的真实数值：bpp 0.06/0.10/0.15、target_ratio 11.5/6.9/4.6、音频 0.5/1.5/3.0 %、HEVC 110/220/450） |
| 路线图与兼容承诺 | ✅ `ROADMAP.md` |
| 支持渠道 | ✅ `SUPPORT.md` |
| 学术引用 | ✅ `CITATION.cff` |
| GitHub 社区模板 | ✅ `ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml`、`PULL_REQUEST_TEMPLATE.md`、`CODEOWNERS`、`dependabot.yml` |

## 3. 三项一致性问题的处置决定（用户 2026-11-08 口述）

| 问题 | 决定 |
| :--- | :--- |
| `README.md` 目录树声明 `docs/CHANGES-*.md`，但这批文件已在 `01f0b2f` 清空 | **不冲突**：陈旧日志已清理，新的重要改动仍按 `docs/CHANGES-YYYYMMDD.md` 继续记录；`docs/README.md` §2.7 已按此表述 |
| `README.md` §6 未收录 `CLI_GUIDE.md` / `PRIVATE_BUILD.md` / `CRATES_PUBLISH.md` | **本次不改**：后续会加更多文档链接，届时一起更新 |
| 新旧两套 spec 并存（`docs/api/spec/` 与 90 KB 的 legacy `WIRE_SPEC_*.md`） | **暂不动**：等文档补齐后再决定是否归档到 `docs/archive/`；当前已在 `spec/README.md` 标注 legacy 非规范 |

## 4. 本次新增与修改的文件

新增（30 个）：

```text
SECURITY.md  LEGAL.md  THIRD_PARTY_LICENSES.md  NOTICE  INSTALL.md
CONTRIBUTING.md  CODE_OF_CONDUCT.md  SUPPORT.md  ROADMAP.md  CITATION.cff
docs/THREAT_MODEL.md  docs/FAQ.md  docs/GUI_GUIDE.md  docs/README.md
docs/DEVELOPMENT.md  docs/TESTING.md  docs/RELEASE.md  docs/ALGORITHM_GUIDE.md
docs/DOC_GAP_REVIEW_20261108.md（本文件）
docs/licenses/rust-core.md  docs/licenses/gui-backend.md  docs/licenses/gui-frontend.md
gui/README.md
scripts/gen_third_party_licenses.py
.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml
.github/PULL_REQUEST_TEMPLATE.md  .github/CODEOWNERS  .github/dependabot.yml
```

未修改：`README.md`、`README.zh.md`、`CHANGELOG.md`、`rust/README.md`、所有既有 `docs/*`、CI 工作流。按上面 §3 的决定，链接统一更新的事留给下一轮。

## 5. 本次梳理发现的实质问题（未修复，逐条可跟进）

| # | 问题 | 影响 | 建议 |
| :-: | :--- | :--- | :--- |
| 1 | **字节级基线不在版本库**：`scripts/baseline_hash.py` 读写 `temp/baseline/baseline.json`，而 `temp*` 在 `.gitignore` 中；`ci.yml` 也只跑 `import_lint` 与 `feature_matrix` | 公开后任何人都无法用基线证明"输出没变"，回归只能靠肉眼看测试 | 提交一份精简语料 + 基线 JSON，并把 `--check` 加进 CI |
| 2 | `rust/README.md` 的错误处理示例用了不存在的 `SignedBinaryRejected` 与 `CarrierTooSmall` | 真实枚举是 `Rejection(String)`（覆盖 PE Authenticode / PDF ByteRange / 签名 JAR / 只读 / 不可写目录）与 `PayloadTooLarge(String)`；示例会误导集成方 | ✅ 已改为真实变体（`Password` / `PasswordWithHint` / `PayloadTooLarge` / `SafetyThreshold` / `Rejection` / `NoHiddenData` / `RestoreMismatch` / `General`），并补 `kind()` 说明；示例经 `cargo build --example` 实际编译验证 |
| 3 | 发布产物不含 `LICENSE` / `NOTICE` / 许可清单 | Apache-2.0 §4(a) 要求随二进制提供许可证副本 | ✅ 已在 `release.yml` 增加 `Assemble license bundle` 步骤，自动产出 `strhide-<version>-licenses.zip` 并纳入校验和；桌面端安装包仍未内嵌（转入 ROADMAP） |
| 4 | 产物未签名、GUI 无 notarisation、无 updater 签名 | macOS Gatekeeper / Windows SmartScreen 拦截；也给了伪造同名二进制的空间 | 已在 `INSTALL.md`/`RELEASE.md` 写明现状；补证书后再改文案 |
| 5 | 无文档链接检查 | 后续重命名文档会留死链 | 加一个 CI 步骤（新文档已全部使用相对链接，便于校验） |
| 6 | `docs/api/spec/` 无英文版 | 第三方实现者（crates.io 国际受众）用不了规范 | 优先级：`README` → `CRYPTO` → 两域信封 |
| 7 | 旧 `WIRE_SPEC_*.md` 约 90 KB 与新规范并存 | 过期文本可能被误当权威 | 待文档补齐后归档，见 §3 |
| 8 | 依赖 `r-efi` 含 LGPL 可选分支、GUI 后端有 5 个 MPL-2.0（cssparser/selectors 系） | 前者只在 UEFI 目标；后者未修改源码即无源码公开义务，但需保留许可与获取方式 | 已在 `THIRD_PARTY_LICENSES.md` 逐项说明 |

## 6. 事实核对说明

本文档与新增文档里的每个具体数字都取自代码或既有规范，不来自推测。关键几处：

- PBKDF2：结构域 100 000 轮（`core/crypto.rs`），内容域 200 000 轮（`CONTENT_L1_PBKDF2_ITERATIONS`）；读侧拒绝低于 `max_pbkdf2_iterations`（默认 200 000）的声明。
- 档位参数：`core/params.rs` 的 `bpp_limit` / `target_ratio` / `video_budget`，音频见 `stego/audio/core.rs` 的 `CHANGE_PERCENT_*`。
- 算法 id 与默认项：`stego/registry.rs`（`hill`/`suniward`/`mipod`/`uerd`/`juniward`/`jmipod`/`hevc`/`wav_pcm`/`flac_residual`）。
- 发布产物名与平台矩阵：`.github/workflows/release.yml`；`SHA256SUMS.txt` 由发布 job 生成；GUI 无校验和。
- GUI 行为：`gui/src-tauri/tauri.conf.json`（CSP、capabilities 仅 dialog/opener）、`src/views/*.tsx`（嵌入页 `backup: false`、提取页两阶段与 `uniqueOutputPath`）、`src/lib/i18n.ts`（术语约定）。
- 依赖许可：`cargo metadata`（核心 87 个 crate、GUI 后端 503 个）+ `gui/node_modules`（前端 11 个包）。

## 7. 下一步建议

1. 修 §5 的 #1、#2、#3 —— 都属于"公开后第一周就会被问到"的问题，且改动量小。
2. 决定文档语言策略：目前根目录英文、`docs/` 中文。若打算面向国际发布，`spec/` 英文版是最高杠杆的一项。
3. `README.md` 的文档链接统一更新（用户已确认后续一起做）。
4. 把这些新文档挂进 `README.md` §6 与 `docs/README.md` 索引后，跑一次链接检查。
