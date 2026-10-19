# PE 节填充直接隐写（pe_slack）方案设计与可行性分析

> 文档编号：STRHIDE-DOC-20261019-02  
> 状态：独立方案论证 / 留存评估  
> 涉及模块：PE 适配器（`pe.rs` / `pe_slack.rs`）、策略路由（`router.rs`）  
> 关联文档：`pe_codebits_plugin_design.md`、`pe_codebits_chunked_diff_design.md`、`smart_file_data_hiding_design.md`

---

## 1. 核心洞察与背景

### 1.1 问题的提出

在针对 `pe_codebits`（指令编码隐写）的容量瓶颈与分块优化（方案 B）讨论中，出现了一个根本性的技术反思：

> **“PE 的 Section Slack Space（节对齐填充区）本来就全零，为什么不直接拿来存数据，而一定要经过极其复杂的指令转换？”**

### 1.2 可逆隐写与单向隐写的“逻辑悖论”

`pe_codebits` 移植自 `steg86`（通过替换 x86/x64 的 ModR/M 语义对指令编码隐藏信息）。在两者的设计目标对比中，暴露出一个深刻的矛盾：

1. **单向隐写（steg86 的逻辑自洽）**：
   - 目标仅为单向投递秘密数据，**不承诺也不需要将载体可逆还原**。
   - 秘密数据藏在 `.text` 内部，**完全不碰 Section Slack**（节填充区依然保持全零）。
   - 静态分析工具扫描节尾 padding 没有任何异常，隐蔽性极高。

2. **可逆数据隐藏（strhide 的约束碰撞）**：
   - strhide 的首要核心承诺是 **100% 逐比特无损还原（Remove 后 SHA-256 绝对一致）**。
   - 要把 `.text` 中被改写的指令翻回原状，必须记录一个“还原 diff 位图”。
   - 为了保证**文件尺寸零增长**，`pe_codebits` 将这个长达 $(14 + N)$ 字节的 diff 塞入了 **Section Slack**。
   - **荒谬之处由此产生**：
     - 为了隐藏 $N$ 字节的 UBE 载荷，在 `.text` 里翻转了成百上千条可执行指令；
     - 却在 Section Slack 里写入了 $(14 + N)$ 字节的非零 diff 数据；
     - **既然 Section Slack 无论如何都会被非零数据污染，那为何不直接把这 $N$ 字节的数据写入 Section Slack？**

---

## 2. 方案对比：pe_slack vs pe_codebits vs pe_overlay

| 评估维度 | 直接节填充隐写 (`pe_slack`) | 指令编码信道 (`pe_codebits`) | 追加覆盖区 (`pe_overlay`) |
|---|---|---|---|
| **文件体积变化** | **0 字节（尺寸严格不变）** | **0 字节（尺寸严格不变）** | 增大（增加信封大小） |
| **100% 无损还原** | **极简**（将填充区重写为 0 即可） | **复杂**（依赖 diff 翻转指令 + 清零） | **极简**（截断至原文件长度） |
| **可用容量** | **大（取决于各节对齐空隙，可达数 KB）** | **双重受限**：$\min(\text{text}/8, \text{slack})$ | **无限**（仅受磁盘空间限制） |
| **宿主架构支持** | **全架构原生通用**（x86, x64, ARM, .NET） | **仅限 x86 / x64** | **全架构原生通用** |
| **指令安全性** | **零风险**（绝对不碰 executable 代码） | **低风险**（改动指令编码，存在 edge-case 隐患） | **零风险**（不改动原始文件任何字节） |
| **外部库依赖** | **零依赖**（仅需原生 PE 头解析） | **重度依赖** `iced-x86` 解码/编码器 | **零依赖** |
| **性能开销** | **微秒级**（流式定位与 I/O） | **数百毫秒**（需反汇编扫描整段 `.text`） | **微秒级** |
| **静态特征检测** | 暴露为非零 Padding / Code Cave 特征 | 同时暴露为指令统计异常 + 非零 Padding | 暴露为 ImageEnd 后的 Overlay 数据 |

---

## 3. 实测数据：对 Text-bound 瓶颈的降维打击

在 `temp/testapps` 实测中，原本因 `.text` 指令稀少而在 `pe_codebits` 下失败的样本，在 `pe_slack` 视角下表现出完全不同的容量面貌：

```
[实测真实零值 Slack 容量]
CarroNote.exe:              7 个零 run, 总量 1,603 B, 最大单段 392 B
WindTerm/.../sz.exe:        3 个零 run, 总量 7,161 B, 最大单段 3,512 B
WindTerm/.../rz.exe:        3 个零 run, 总量 6,969 B, 最大单段 3,496 B
MPC-BE/mpc-be64.exe:       18 个零 run, 总量 5,912 B, 最大单段 492 B
```

- **`sz.exe` / `rz.exe`**：此前在 `pe_codebits` 下可用空间仅 229 ~ 232 B（装不下 219 B 加密信封）；直接利用 Slack 后，**单段最大即有 3.5 KB，总容量高达 7 KB**！
- **`CarroNote.exe`**：此前仅 269 B；直接利用 Slack 可达 **1.6 KB**。
- **结论**：直接使用 Section Slack，可以瞬间**彻底消灭**困扰已久的 4 个临界 text-bound 样本问题，连小型工具、小图片都能直接嵌入。

---

## 4. `pe_slack` 技术实现方案

若落地 `pe_slack` 策略（建议 `strategy_id = 9`），其技术架构极其简洁优雅：

### 4.1 候选区间定义

仅使用合法的 PE 内部对齐填充区（绝不触碰文件末尾 overlay）：
1. **节表头部 padding**：`[节表结束偏移, 首个节 PointerToRawData)`；
2. **各节尾部 padding**：针对每个节的 `[PointerToRawData + min(VirtualSize, SizeOfRawData), PointerToRawData + SizeOfRawData)`。

### 4.2 存储模式

支持两种模式（自动切换）：
- **Mode 1（单段存入，单 run 足够时）**：
  - 寻找满足长度 $\ge \text{UBE\_LEN}$ 的最短零 run；
  - 直接写入 UBE 信封（含 standard 或 stealth trailer magic）；
  - 不需要任何外部描述表，完全自包含。
- **Mode 2（分块打散存入，单 run 不足但总和足够时）**：
  - 复用分块描述表（类似 `DiffTable` 结构，称为 `SlackChunkTable`）；
  - 将 UBE 分块放入多个零 run；
  - 主锚点记录分块偏移。

### 4.3 定位（Locate）机制

定位效率比 `pe_codebits` 提升两个数量级：
1. 解析 PE 头，列举候选 Slack 区间；
2. 扫描这些区间的有效载荷：
   - 检查尾部（或头部）是否存在目标 trailer magic（标准 `STH!` 或口令派生魔数）；
3. 命中即成功定位，耗时 $< 1$ 毫秒，无需任何指令解码。

### 4.4 还原（Strip）机制

- 读取 UBE 信封后；
- 将信封所占据的区间（或分块区间）**全部重写为 `0x00`**；
- 原始文件毫发无损，SHA-256 必然 100% 匹配。

---

## 5. 安全性与隐蔽性客观评估

采用 `pe_slack` 时，需要如实向用户声明其对抗特征：

1. **执行层绝对安全**：
   - Section Slack 处于节的逻辑末尾（超过 `VirtualSize`），操作系统在加载运行 PE 时，CPU 的指令指针（EIP/RIP）绝不会跨入此区域。
   - 零崩溃风险，零副作用。

2. **静态取证与特征扫描**：
   - **特征表现**：PE 分析工具（如 `pefile`、`PE-bear`）或某些反病毒引擎的启发式扫描器会关注“Non-zero Padding”或“High Entropy Slack”，这是历史上检测 Code Cave（代码空洞木马）的常见启发式规则。
   - **防御策略**：在开启密码（`-p` / `-e`）的隐身（stealth）模式下，全信封为 AES-GCM 密文（均匀伪随机），魔数随密码派生，无静态明文特征，检测工具仅能判定为“包含未知非零数据”，无法提取内容。

---

## 6. 总结与演进建议

1. **`pe_codebits` 的归宿**：
   - 适合作为**面向逆向分析员的高级混淆策略**（对指令结构感兴趣、代码段超大的大型 PE）。
2. **`pe_slack` 的价值**：
   - 是解决 PE **零尺寸增长 + 高容量 + 全架构通用**的“大道至简”的最佳工程实践。
   - 建议在后续版本中独立立项为 `strategy_id = 9`（`pe_slack`），作为 PE 格式在 `pe_overlay`（大容量增长）和 `pe_codebits`（极客指令隐藏）之间的主力平衡点。
