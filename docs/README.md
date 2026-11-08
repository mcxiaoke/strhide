# 文档索引 (Documentation Index)

`strhide` 的文档分四层：**上手**（怎么用）、**规范**（怎么互操作）、**内部**（怎么改）、**治理**（怎么参与与合规）。按你的目的选一条路径，不要从文件列表硬读。

---

## 1. 阅读路径

### A. 我只要用它

0. [免责声明](../DISCLAIMER.zh.md) / [DISCLAIMER](../DISCLAIMER.md) — **先读**：研究用途、禁止用途、备份义务、无担保与责任限制
1. [INSTALL.md](../INSTALL.md) — 下载、校验、首次运行
2. [CLI_GUIDE.md](CLI_GUIDE.md) — 十个子命令与常用参数组合
3. [GUI_GUIDE.md](GUI_GUIDE.md) — 桌面端（先看术语映射表，"隐写"与"嵌入"是交叉的）
4. [FAQ.md](FAQ.md) — 提取失败、容量、性能、备份
5. [THREAT_MODEL.md](THREAT_MODEL.md) §4 — **它承诺什么、什么时候一定不成立**

### B. 我要在自己的程序里集成

1. [rust/README.md](../rust/README.md) — feature 矩阵与库用法
2. [api/STEGO-API.md](api/STEGO-API.md) — 内容域 API 与三层公开面
3. [api/ARCHITECTURE.md](api/ARCHITECTURE.md) — 分层、facade、参数模型
4. [api/spec/README.md](api/spec/README.md) — 线格式规范总览与稳定性分级
5. [PRIVATE_BUILD.md](PRIVATE_BUILD.md) — 私有方言（同口令隔离、断开归因）

### C. 我要实现一个可互操作的读写器

1. [api/spec/README.md](api/spec/README.md) — 术语、字节序、稳定性分级、实现路线
2. [api/spec/CRYPTO.md](api/spec/CRYPTO.md) — KDF/AEAD/AAD/nonce，含自检向量
3. 选一个域：[api/spec/CONTENT-ENVELOPE.md](api/spec/CONTENT-ENVELOPE.md) 或 [api/spec/STRUCTURE-ENVELOPE.md](api/spec/STRUCTURE-ENVELOPE.md)
4. 对应载体的分册（见 §2 表格）
5. [api/spec/CAPACITY.md](api/spec/CAPACITY.md) / [api/spec/DETMATH.md](api/spec/DETMATH.md)

### D. 我要改这个仓库

1. [DEVELOPMENT.md](DEVELOPMENT.md) — 环境、布局、feature 组合、vendor 源码
2. [TESTING.md](TESTING.md) — 测试分层与各类门禁
3. [../CONTRIBUTING.md](../CONTRIBUTING.md) — 提交与评审约定
4. [RELEASE.md](RELEASE.md) — 发布流程与产物
5. [api/spec/README.md](api/spec/README.md) §5 — 改线格式时必须同步改哪些文档

---

## 2. 文档地图

### 2.1 上手与治理

除 `THREAT_MODEL.md`（在 `docs/` 下）外，本表文件都在仓库根目录。

| 文档 | 内容 | 语言 |
| :--- | :--- | :--- |
| [README.md](../README.md) / [README.zh.md](../README.zh.md) | 项目总览、能力矩阵、CLI 速查 | EN / ZH |
| [INSTALL.md](../INSTALL.md) | 安装、校验、未签名产物的处理、排错 | EN |
| [SECURITY.md](../SECURITY.md) | 漏洞披露、支持版本、**已知设计边界**、安全属性 | EN |
| [THREAT_MODEL.md](THREAT_MODEL.md) | 对手模型、失效条件表、侧信道清单、威胁→对策 | ZH |
| [DISCLAIMER.md](../DISCLAIMER.md) / [DISCLAIMER.zh.md](../DISCLAIMER.zh.md) | **使用风险与责任限制**：研究用途、禁止用途、备份义务、无担保、责任限制、赔偿、条款变更 | EN / ZH |
| [LEGAL.md](../LEGAL.md) | 许可证、HEVC 专利、出口管制、商标、第三方组件 | EN |
| [THIRD_PARTY_LICENSES.md](../THIRD_PARTY_LICENSES.md) | 依赖许可汇总与再分发义务 | EN |
| [CONTRIBUTING.md](../CONTRIBUTING.md) / [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | 贡献流程、门禁、行为准则 | EN |
| [SUPPORT.md](../SUPPORT.md) | 提问渠道与"先看这里"清单 | EN |
| [ROADMAP.md](../ROADMAP.md) | 1.0 前后的方向与兼容性承诺 | EN |
| [CHANGELOG.md](../CHANGELOG.md) | 版本变更（Keep a Changelog） | EN |

### 2.2 使用指南

| 文档 | 内容 | 语言 |
| :--- | :--- | :--- |
| [CLI_GUIDE.md](CLI_GUIDE.md) | 命令体系、载荷/口令规范、三域实操、CI 最佳实践 | ZH |
| [GUI_GUIDE.md](GUI_GUIDE.md) | 桌面端界面、四页签、与 CLI 的能力差异 | ZH |
| [FAQ.md](FAQ.md) | 确定答案的高频问题 | ZH |

### 2.3 规范（规范性文档）

| 文档 | 主题 |
| :--- | :--- |
| [api/spec/README.md](api/spec/README.md) | 总览：两域对比、字节序、稳定性分级、术语 |
| [api/spec/CRYPTO.md](api/spec/CRYPTO.md) | 密钥派生、HKDF 标签、AEAD、AAD、stealth 掩码 |
| [api/spec/DETMATH.md](api/spec/DETMATH.md) | 确定性浮点数学（影响输出字节） |
| [api/spec/CAPACITY.md](api/spec/CAPACITY.md) | 容量公式、扩展槽、内存预算与限额 |
| [api/spec/CONTENT-ENVELOPE.md](api/spec/CONTENT-ENVELOPE.md) | V4 内容信封：微头、基础头、TLV、槽位、STC |
| [api/spec/CONTENT-PNG.md](api/spec/CONTENT-PNG.md) | PNG 像素槽位与 HILL / S-UNIWARD / MiPOD |
| [api/spec/CONTENT-JPEG.md](api/spec/CONTENT-JPEG.md) | JPEG DCT 网格与 UERD / J-UNIWARD / J-MiPOD |
| [api/spec/CONTENT-HEVC.md](api/spec/CONTENT-HEVC.md) | HEVC CABAC 符号位、分带、置换 |
| [api/spec/CONTENT-AUDIO.md](api/spec/CONTENT-AUDIO.md) | WAV PCM / FLAC 残差 |
| [api/spec/STRUCTURE-ENVELOPE.md](api/spec/STRUCTURE-ENVELOPE.md) | UBE v2 信封与 PE 信道头 |
| [api/spec/STRUCTURE-PNG.md](api/spec/STRUCTURE-PNG.md) · [-JPEG](api/spec/STRUCTURE-JPEG.md) · [-RIFF](api/spec/STRUCTURE-RIFF.md) · [-ISOBMFF](api/spec/STRUCTURE-ISOBMFF.md) · [-ZIP](api/spec/STRUCTURE-ZIP.md) · [-PDF](api/spec/STRUCTURE-PDF.md) · [-PE](api/spec/STRUCTURE-PE.md) · [-MKV](api/spec/STRUCTURE-MKV.md) | 各容器适配器 |
| [api/spec/CORRECTIONS.md](api/spec/CORRECTIONS.md) | 旧 WIRE_SPEC 的勘误与差异汇总 |

历史文档 [api/WIRE_SPEC_CONTENT.md](api/WIRE_SPEC_CONTENT.md) 与 [api/WIRE_SPEC_STRUCTURE.md](api/WIRE_SPEC_STRUCTURE.md) 保留链接但**非规范**；与 `spec/` 冲突时以 `spec/` 为准。

### 2.4 实现与运维

| 文档 | 内容 | 语言 |
| :--- | :--- | :--- |
| [api/ARCHITECTURE.md](api/ARCHITECTURE.md) | 分层、模块拓扑、公开面、数据流、稳定性约定 | ZH |
| [api/STEGO-API.md](api/STEGO-API.md) | 内容域 API、凭据优先级、CLI 映射、守卫 | ZH |
| [smart_file_data_hiding_design.md](smart_file_data_hiding_design.md) | 总体设计规范（双域模型、UBE 布局、适配器） | ZH |
| [PRIVATE_BUILD.md](PRIVATE_BUILD.md) | 私有构建配方（消除来源指纹）与边界 | ZH |
| [CRATES_PUBLISH.md](CRATES_PUBLISH.md) | crates.io 发布约束、fork 策略、包名机制 | ZH |
| [DEVELOPMENT.md](DEVELOPMENT.md) | 开发环境、布局、feature、vendor、常见坑 | ZH |
| [TESTING.md](TESTING.md) | 测试分层、门禁、基线、压力测试 | ZH |
| [RELEASE.md](RELEASE.md) | 打 tag、产物矩阵、校验和、发布顺序 | ZH |
| [ALGORITHM_GUIDE.md](ALGORITHM_GUIDE.md) | 算法/档位选型与容量-隐蔽性权衡 | ZH |

### 2.5 性能与统计

| 文档 | 内容 |
| :--- | :--- |
| [../BENCHMARK.md](../BENCHMARK.md) | 两域汇总表与主导因素 |
| [BENCH_STRUCTURE_20261107.md](BENCH_STRUCTURE_20261107.md) | 结构域完整方法论、逐格方差、原始样本（含 SVG） |
| [BENCH_CONTENT_20261107.md](BENCH_CONTENT_20261107.md) | 内容域同上 |

### 2.6 自动生成（勿手改）

| 文件 | 生成者 |
| :--- | :--- |
| [licenses/rust-core.md](licenses/rust-core.md) · [licenses/gui-backend.md](licenses/gui-backend.md) · [licenses/gui-frontend.md](licenses/gui-frontend.md) | `python scripts/gen_third_party_licenses.py` |

### 2.7 工程日志

`docs/CHANGES-YYYYMMDD.md` 按天记录重要代码变动（格式：时间精确到秒 + 简洁要点）。历史日志已按需清理，新变动继续追加；面向用户的版本变更仍以 [CHANGELOG.md](../CHANGELOG.md) 为准。

---

## 3. 语言策略

- **仓库根目录的对外文件用英文**（README、INSTALL、SECURITY、LEGAL、CONTRIBUTING、SUPPORT、ROADMAP、CHANGELOG），因为它们是国际读者与 GitHub 社区界面的入口。
- **`docs/` 下的技术文档以中文为主**，与现有规范保持一致；代码注释、commit message、日志输出一律英文。
- 中文总览见 [README.zh.md](../README.zh.md)。

已知缺口：`docs/api/spec/` 是面向第三方实现者的规范，目前只有中文。英文版尚未提供，见 §5。

---

## 4. 文档维护规则

1. **改线格式必须同步改规范。** 新增 `format_id`、`strategy_id`、TLV、派生标签、槽位规则或代价模型时，同步更新对应分册与 [api/spec/CORRECTIONS.md](api/spec/CORRECTIONS.md)。
2. **F 级（冻结）改动**属于线格式变更：必须同时更新字节级基线（`python scripts/baseline_hash.py --check`）与 [CHANGELOG.md](../CHANGELOG.md)。
3. **生成文件不许手改**：`docs/licenses/*` 由脚本产出；依赖变动后重新生成并一起提交。
4. **代码与文档冲突时以代码为准**，然后修文档，并在 `CORRECTIONS.md` 记录。规范里的 `文件:行` 是证据、不是规范，行号会漂移。
5. **不要新增"计划中"的文档链接**：文档没写就不要先挂链接，避免死链。

---

## 5. 已知文档缺口

| 缺口 | 影响 | 状态 |
| :--- | :--- | :--- |
| `docs/api/spec/` 无英文版 | 第三方实现者（crates.io 国际受众）只能读中文 | 待补，优先级：`README` / `CRYPTO` / 两域信封 |
| 旧 `WIRE_SPEC_*.md`（约 90 KB）与 `spec/` 并存 | 有过期文本被误当权威的风险 | 已在文首标注非规范；是否归档到 `docs/archive/` 待定 |
| 无自动化链接检查 | 重命名文档后可能出现死链 | 待补 CI 步骤 |
| `rust/README.md` 的错误处理示例出现过已不存在的 `SignedBinaryRejected` | 示例与真实错误枚举（`Rejection`）不符 | 待修 |
