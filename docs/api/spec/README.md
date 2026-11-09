# strhide 线格式规范（总览与索引）

> 适用范围：`strhide` 0.9.x（线格式：结构域 **UBE v2**，内容域 **V4 内容信封**）。
> 本目录是**规范性文档**，目标是让第三方在不阅读 Rust 源码的情况下实现可互操作的读写器。
> 参考实现：`rust/src`；模块职责见 [../ARCHITECTURE.md](../ARCHITECTURE.md)，公开 API 见 [../STEGO-API.md](../STEGO-API.md)。

---

## 0. 文档地图

### 公共层

| 文档 | 主题 |
|---|---|
| [CRYPTO.md](./CRYPTO.md) | 两域密钥派生、HKDF 标签、AEAD、AAD、stealth 掩码、PE 信道头掩码 |
| [DETMATH.md](./DETMATH.md) | 确定性浮点数学库（`exp`/`ln`/`ln_1p`/`cos`/`log2`）的规范性定义 |
| [CAPACITY.md](./CAPACITY.md) | 两域容量公式、扩展槽、工作内存预算与全部限额 |

### 内容域（`embed` / `extract`）

| 文档 | 主题 |
|---|---|
| [CONTENT-ENVELOPE.md](./CONTENT-ENVELOPE.md) | 微头、三套基础头、flags/TLV、槽位模型、ChaCha12/置换、STC、失败语义 |
| [CONTENT-PNG.md](./CONTENT-PNG.md) | PNG 像素槽位、HILL / S-UNIWARD / MiPOD 代价模型、候选排序 |
| [CONTENT-JPEG.md](./CONTENT-JPEG.md) | JPEG DCT 网格、超块、UERD / J-UNIWARD / J-MiPOD、三元 STC |
| [CONTENT-HEVC.md](./CONTENT-HEVC.md) | HEVC/HEIF CABAC 符号位槽位、分带、线性置换、窗口与防竞争 |
| [CONTENT-AUDIO.md](./CONTENT-AUDIO.md) | WAV PCM 采样域、FLAC 残差域、Feistel 置换、thin_pick、重试 |

### 结构域（`write` / `restore`）

| 文档 | 主题 |
|---|---|
| [STRUCTURE-ENVELOPE.md](./STRUCTURE-ENVELOPE.md) | UBE v2：112B header、hint、meta、分块载荷、24B trailer、stealth、PE ChannelHeader |
| [STRUCTURE-PNG.md](./STRUCTURE-PNG.md) | PNG `prIv` 块注入 |
| [STRUCTURE-JPEG.md](./STRUCTURE-JPEG.md) | JPEG APP 段注入 |
| [STRUCTURE-RIFF.md](./STRUCTURE-RIFF.md) | WAV / WebP 的 RIFF chunk 注入 |
| [STRUCTURE-ISOBMFF.md](./STRUCTURE-ISOBMFF.md) | MP4/MOV 与 HEIF/HEIC 的 box / item 注入 |
| [STRUCTURE-ZIP.md](./STRUCTURE-ZIP.md) | ZIP 中央目录前注入 |
| [STRUCTURE-PDF.md](./STRUCTURE-PDF.md) | PDF 增量更新注入 |
| [STRUCTURE-PE.md](./STRUCTURE-PE.md) | PE overlay / codebits / slack |
| [STRUCTURE-MKV.md](./STRUCTURE-MKV.md) | Matroska/WebM 的 EBML Void 注入 |

历史文档（**非规范**，仅保留链接与旧编号）：[../WIRE_SPEC_CONTENT.md](../WIRE_SPEC_CONTENT.md)、
[../WIRE_SPEC_STRUCTURE.md](../WIRE_SPEC_STRUCTURE.md)。规范与旧文冲突时**以本目录为准**；
已知差异汇总见 [CORRECTIONS.md](./CORRECTIONS.md)。

---

## 1. 两个隐写域

strhide 有**两套互不兼容的信封**，派生域隔离，不能交叉读取。

| 维度 | 结构域（`write` / `restore`） | 内容域（`embed` / `extract`） |
|---|---|---|
| 信封 | UBE v2：`112B header` + hint + meta + 分块载荷 + `24B trailer` | 密钥化基础头（空间 64B / JPEG 44B / HEVC 32B）+ 可选 TLV + 单个 AEAD 正文 |
| 静态特征 | 有 8B 头魔数 + 4B 尾魔数（stealth 模式为密码派生） | 无固定魔数；`magic4` 由 L2 派生 |
| 字节序 | **小端** | 多字节字段**大端**（`sigma` 例外：f32 小端） |
| 载荷 | 分块 AEAD，每块 `u32 LE` 长度前缀，chunk AAD 含 index/is_last | 一次性 AEAD，无分块 |
| 元数据 | 文件名、原始大小、SHA-256、创建时间（独立 AEAD 块） | 密文内微头：4B 原始长度 + 1B flags + 文件名 |
| 宿主还原 | 支持 bit-for-bit `restore`（记录宿主 size + SHA-256） | **不可逆**，像素/系数被改即不可恢复 |
| 无密码默认密钥 | `BUILTIN_DEFAULT_KEY` | `PUBLIC_DEFAULT_SECRET` |
| 压缩 | raw deflate；`Auto` 需节省 ≥2% | raw deflate；压缩后严格小于原文才保留 |

两域不得混用派生标签、AAD 或默认密钥；任何交叉读取都应返回“无隐藏数据”。

---

## 2. 规范性约定

### 2.1 语言

- **必须 / 禁止**：实现为通过一致性所需的最低要求；**应当**：推荐但可偏离，偏离需在实现说明中注明。
- 所有常量、字段偏移、公式都尽量给出参考实现的位置（`rust/src/...:行`）。这些位置是**证据**，不是规范的一部分；行号随代码演进可能漂移。
- “当前实现的事实标准”会显式标注 **I 级**（见 §2.3）：它描述参考实现如何写出字节，但读侧不依赖它。

### 2.2 字节序与位序

- 结构域：除特别注明外一律**小端**（header/trailer/meta/chunk 长度）。
- 内容域：基础头与 HKDF info 中的多字节字段一律**大端**；`sigma` 字段是 **f32 小端**。
- 位打包：字节内 **MSB-first**（bit 7 是第一个槽/消息位），除非某个结构显式说明按低位优先。
- CRC：两域均用 **CRC32-IEEE**（反射多项式 `0xEDB88320`，初值 `0xFFFFFFFF`，结果取反）。

### 2.3 稳定性分级

| 级别 | 含义 | 改动后果 |
|---|---|---|
| **F 冻结** | 已写出的载体依赖它 | 改动使旧载体不可读；1.0 前仍可能变更，但必须记录为不兼容变更 |
| **D 方言** | 可通过编译期 Profile/标签替换 | 不破坏官方载体，但产生独立方言；官方实现读不回 |
| **I 实现自由** | 只影响“写成什么样”，不影响“能否读出” | 读侧不依赖；可随实现优化，需由字节级基线守住本仓库的输出 |

**1.0 之前，任何 F 级内容仍可能变动。** 版本策略：

- `CipherSuiteId`、`strategy_id`、`format_id`、`algorithm_id`、TLV `type_id` 均为 **append-only**：只能新增值，不能改变既有值的语义。
- 版本字段（`version`、`CURRENT_VERSION`、`compact meta version`、`CHANNEL_VERSION`）只升不降；未知版本 fail-closed。
- 不提供旧版本读路径（项目尚未发布）。读到旧版本应返回明确的“不支持版本”或无数据，而不是猜测布局。

### 2.4 参考实现的边界

- `analysis` 域的检测/估计仍使用宿主 `libm`，**不参与字节输出**；所有影响输出的浮点运算必须遵循 [DETMATH.md](./DETMATH.md)。
- 参考实现中的 SIMD、并行、压缩级别、重试轮数属于 I 级；读侧不得依赖其具体选择。
- 本规范不承诺“与参考实现逐位一致”即可互操作；互操作的判据是**能读取对方写出的合法载体**。字节级基线仅用于守护本仓库自身输出。

---

## 3. 第三方实现路线（建议顺序）

1. 读 [CRYPTO.md](./CRYPTO.md)，实现 NFC、PBKDF2、HKDF、AES-256-GCM / ChaCha20-Poly1305。
2. 选择目标域：
   - 内容域：读 [CONTENT-ENVELOPE.md](./CONTENT-ENVELOPE.md) → 对应载体文档 → [DETMATH.md](./DETMATH.md) → [CAPACITY.md](./CAPACITY.md)；
   - 结构域：读 [STRUCTURE-ENVELOPE.md](./STRUCTURE-ENVELOPE.md) → 对应适配器文档 → [CAPACITY.md](./CAPACITY.md)。
3. 先实现**提取**（只需重建密钥、槽位与 syndrome），再实现写入。
4. 用文档给出的已知答案自检：ChaCha12 参考向量、detmath 五个摘要、各载体槽位/代价向量（若有）。

---

## 4. 术语

| 术语 | 含义 |
|---|---|
| UBE | Unified Binary Envelope，结构域信封 |
| 基础头 / superblock | 内容域随载体变化的头部（空间 64B、JPEG 44B、HEVC 32B） |
| 槽位 / slot | 载体中一个可翻转的奇偶位（字节 bit、DCT 系数奇偶、PCM LSB、CABAC 符号位等） |
| 候选池 | 满足载体规则、可承载槽位的位置集合 |
| 置换 | 由密钥种子确定的槽位重排；不是加密，但无密钥不可预测 |
| STC | Syndrome Trellis Coding，矩阵编码；读侧只需计算 syndrome |
| 预盐 / `pre_salt` | 只用嵌入前后不变元数据构造的 KDF salt |
| 方言 / profile | 编译期替换标签、盐或参数后产生的独立线格式 |
| L1 / L2 / L3 | 内容域三层密钥：定位主密钥、定位密钥、会话密钥 |

---

## 5. 文档维护规则

- 新增 `format_id`、`strategy_id`、TLV、派生标签、槽位规则或代价模型时，必须同步更新对应专题文档与 [CORRECTIONS.md](./CORRECTIONS.md) 的勘误状态。
- 任何 F 级算法改动都属于线格式变更，必须同步更新字节级基线与变更记录。
- 文档中的 `文件:行` 以参考实现为准；若代码与文档冲突，先按代码修正文档，并在 [CORRECTIONS.md](./CORRECTIONS.md) 记录。
