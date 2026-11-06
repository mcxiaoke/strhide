# strhide 线格式参考（索引）

> 适用版本：crate `strhide` 0.9.1（Rust 实现，`rust/Cargo.toml`）。
> 配套文档：[ARCHITECTURE.md](./ARCHITECTURE.md)（模块职责与数据流转）、
> [STEGO-API.md](./STEGO-API.md)（内容域公开 API）。

strhide 有**两个相互独立的隐写域**，各自有不同的信封格式、密钥派生域与读取器。所以拆成两份文档，
不是因为要对外提供两个标准，而是因为两者的改动后果互不相干：结构域的字节布局与内容域的
槽位/置换/代价排序，改错任何一个的表现、影响面和验证方式都不同。

> **这两份文档的读者是本项目的开发者，不是外部实现者。** 它们的作用按重要性排序：留住"为什么
> 这样写"、标出"改了会静默坏什么"、说明哪些旋钮可换（私有方言）。strhide 的主体是 CLI，
> crate 是它的库形态，文档**不承诺**"别人照着写一个能互通的 strhide"。分级与写作约定见
> [WIRE_SPEC_CONTENT.md §13.0](./WIRE_SPEC_CONTENT.md#130-稳定性分级与改动后果)。

| 域 | 承载内容 | 规范 | 入口 |
|---|---|---|---|
| **结构域（structure）** | 自包含的 **UBE**（连续，或经散落信道编码），有头、有尾、有魔数 | [WIRE_SPEC_STRUCTURE.md](./WIRE_SPEC_STRUCTURE.md)（§2–§12） | `write` / `restore` / `engine` |
| **内容域（content）** | 嵌入图像像素 / DCT 系数 / 音频采样 / H.265 旁路符号位的**微信封**，无静态魔数 | [WIRE_SPEC_CONTENT.md](./WIRE_SPEC_CONTENT.md)（§13） | `embed` / `extract` / `stego` |

> **章节编号**：两域原先合并在一个文件中，章节号已被其他文档与源码注释引用。拆分后保留原编号空间
> （结构域 §2–§12，内容域 §13），因此两份文档都不重新编号；内容域 §13 内部重排过一次，
> 新旧对应关系见其文首表格。

---

## 1.1 两种信封格式对比（重要）

`write` 与 `embed` 产出的是**两套不同的信封**，不是同一信封的不同封装。它们的派生域相互隔离，
互不兼容，也不能互相读取。差异如下：

| 维度 | 结构域信封（`write`，UBE） | 内容域微信封（`embed`） |
|---|---|---|
| 代码 | `envelope.rs` + `engine.rs` + `pe_codebits.rs` | `stego/envelope.rs` + `stego/header.rs` + `stego/format.rs` |
| 总体结构 | `112B header` + 可选 hint + 元数据块 + 分块载荷 + `24B trailer`（散落策略外包 `14B ChannelHeader`） | 密钥化基础头（空间 64B / JPEG 44B / HEVC 32B）+ 可选 TLV 扩展区 + 单个 AEAD 密文正文（见内容域 §13） |
| 静态魔数 | 有：8B 头魔数 + 4B 尾魔数 | **无固定魔数**：`magic4` 由 L2 派生，整体呈高熵随机数据 |
| 定位尾标（trailer） | 有 24B（offset/size/CRC/magic） | 无 |
| 元数据 | 文件名、原始大小、原始 SHA-256、创建时间（独立 AEAD 块） | 无时间戳；密文内微头为 4B 原始长度 + 1B flags + 1B 类型（文件另带 ≤255B 文件名） |
| 载荷密封 | 分块：每块 `u32 LE` 长度前缀 + 密文，chunk AAD 含 index/is_last | 一次性整体密封，无分块 |
| 字节序 | 小端 | 基础头多字节字段为**大端** |
| AEAD AAD | header 前 80B + `meta_len`/`hint_len` + hint 正文；分块再追加 `chunk_index/is_last` | `"strhide-content-envelope-v4\0" ‖ format_id ‖ base_header ‖ extension` |
| 无密码默认密钥 | `BUILTIN_DEFAULT_KEY` | `PUBLIC_DEFAULT_SECRET` |
| HKDF 子密钥标签 | `strhide-payload`、`strhide-metadata`（掩码：`strhide-header-mask-v1`、`strhide-pe-channel-mask-v2`） | L1 `strhide-stego-domain-v1`；L2 `hpos`/`magic` 标签随格式不同；L3 的 enc/perm/stc 标签随格式方言不同 |
| 额外派生 | stealth 魔数与 76B/10B 字段掩码 | header 槽位置换种子（无 salt）、STC 网格种子 |
| 宿主还原 | 记录宿主 size + SHA-256，支持 bit-for-bit 还原（散落策略依赖 slack diff） | **无宿主还原**：像素/系数被改即不可逆，只能重嵌或覆盖 |
| 最终承载 | 注入容器结构空隙（chunk/段/box/overlay 等）或指令编码散落 | 矩阵编码分散到像素 / DCT 系数 / PCM 采样 / H.265 变换系数符号位 |
| 压缩 | raw deflate；`Auto` 需节省 ≥2% 才保留（>1 MiB 先按 256 KiB 分层样本判定） | raw deflate；`compressed.len() < raw.len()` 才保留 |
| 密码 NFC 归一化 | 统一做 Unicode NFC 归一化 | 统一做 Unicode NFC 归一化 |

> 旧设计文档 §1.2 曾把"像素域 LSB"列为非目标；内容域是在该边界调整后新增的，因此其信封格式没有
> 沿用 UBE，而是独立设计的极简伪随机结构。

---

## 两份文档的用法

| 你想做的事 | 看哪里 |
|---|---|
| 知道一个字节/字段是什么、由谁派生 | 对应文档的布局与派生章节 |
| 想知道某段代码为什么这么写、能不能改 | 对应章节的说明与内容域 §13.0 的分级 |
| 判断"改这里会不会让旧载体读不回" | 内容域 §13.0 的分级表（F 冻结 / D 方言 / I 自由） |
| 定义私有方言（换标签、换 `hpos_salt`、换 STC 参数） | 内容域 §13.15 + 结构域 §15.2 |
| 改格式到官方构建读不回的程度 | 直接 fork，别在官方构建里加兼容分支 |

**没有"互操作"这一档。** 两域都不承诺第三方独立实现能读写本工具的产物，也不承诺跨平台/跨版本
逐位一致；官方只保证同一构建读得回自己写的载体，由 `python scripts/baseline_hash.py --check`
（28 例字节级基线）与全量测试守住。想要开放标准的话，正确做法是 fork 后自建，
而不是让本项目长期背兼容负担。
