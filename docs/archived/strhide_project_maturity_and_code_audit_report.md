# `strhide` 项目成熟度评估与全栈代码深度审查报告

**审查对象**：`strhide` (v1.0.0) —— 双域（容器结构域 + 内容自适应域）隐写与隐写分析系统（Rust 核心库 + CLI + Tauri v2 / React 19 桌面端）  
**代码规模**：Rust 源码 84 个模块文件（约 5.2 万行代码，含 465+ 单元与集成测试）、TypeScript/React 前端 34 个文件  
**审查维度**：项目成熟度、已实现功能完备性、代码错误、数据错误、逻辑错误、算法实现与可靠性、低效代码与算法、脆弱逻辑、系统健壮性与安全性、性能与内存瓶颈、可落地代码级修复方案

---

## 一、执行摘要与项目成熟度全景评估 (Executive Summary)

### 1.1 总体评价

`strhide` 是一个工程完成度极高、架构边界清晰、算法底座扎实的**准生产级（Pre-Production / Late RC 阶段）**现代全栈隐写与容器分析工具。项目最突出的工程亮点在于：

1. **纯 Rust 零外部 C/C++ 二进制依赖**：从 PNG 流式块解析、JPEG Baseline Huffman/DCT 系数的无损读写、H.265/HEVC CABAC 算术编码旁路位（`coeff_sign_flag` / `abs_remainder`）原地翻转、Matroska EBML / ISO-BMFF 容器盒解析，到 WAV/FLAC 子帧 LPC/Fixed Rice 残差流直接重编码与 x86/x64 指令语义等价变形（`pe_codebits`），全部在进程内以安全 Rust 实现，彻底消除了对 `ffmpeg`、`libjpeg`、`libflac` 或 `ImageMagick` 的外部运行时依赖。
2. **双域正交架构与统一外观（Facade）设计**：将**结构域（Structure Domain，100% 比特级可逆还原）**与**内容域（Content Domain，载体尺寸零增长或微扰、抗统计分析）**解耦，并通过 `StrHide` 统一门面（`facade.rs`）、流式取消/进度控制（`core/control.rs`）和原子文件提交守卫（`core/commit.rs`）向 CLI 与 Tauri v2 GUI 提供一致的能力支撑。
3. **现代学术级隐写编码与失真模型落地**：内容域完整实现了速率 1/2 ($K=7$) 卷积码 + 软判决 Viterbi 译码、二元/三元多层综合格码（Multi-layered Syndrome-Trellis Codes, MLS/STC, $h=7\dots 10$）、基于局部方差引导（Variance-Guided）的水塘抽样候选池，以及六大经典/前沿失真模型（空域 **HILL / S-UNIWARD / MiPOD**，频域 **UERD / J-UNIWARD / J-MiPOD**），并配套了基于 216 张真实图像语料库校准的盲隐写分析器（`analysis/`）。

尽管整体架构历经多轮迭代打磨（见 `docs/CHANGES-20261030.md` 至 `20261102.md`），本次针对全量 Rust 与 TypeScript 源码的逐行深度审查仍发现了 **22 项真实存在的技术问题**，其中包括 **4 项 P0 级（阻断性错误/容器损坏/必现解密拒绝）**、**7 项 P1 级（严重逻辑不一致/隐私泄漏/极端性能退化/算法统计失真）**、**7 项 P2 级（API 契约绕过/内存峰值膨胀/多线程缺失/解析脆弱性）** 以及 **4 项 P3 级（冗余死代码/前端功能闭环缺失）**。

### 1.2 子系统成熟度量化评分卡

| 子系统模块 | 关键源码路径 | 成熟度评分 (满分 10) | 成熟度等级 | 核心优势与现存短板概述 |
| :--- | :--- | :---: | :---: | :--- |
| **核心基础设施与密码学** | `rust/src/core/` (`crypto.rs`, `commit.rs`, `batch.rs`, `pipeline.rs`) | **9.0 / 10** | 生产就绪 (Production-Ready) | Argon2id + HKDF-SHA256 + AES-256-GCM 流式分块与 `TmpGuard` 原子提交非常稳健；但 `decrypt_stream_from_chunks` 存在漏加 `AEAD_TAG_LEN` (16B) 的边界拦截 Bug（**Issue #1**）。 |
| **结构域引擎与 11 容器适配器** | `rust/src/structure/` (`engine.rs`, `envelope.rs`, `adapters/*`, `rejection.rs`) | **9.1 / 10** | 生产就绪 (Production-Ready) | UBE v1 信封、Stealth 魔数盲化、ZIP/PDF/ISO-BMFF/RIFF/PE 适配器及 100% 比特级还原设计极佳；短板在于 PDF 签名与 XRef 流字典字符串匹配的脆弱性（**Issue #17**）。 |
| **内容域编码层 (Conv + STC/MLS)** | `rust/src/stego/coding.rs`, `coding/stc.rs`, `cost_calibration.rs` | **9.2 / 10** | 生产就绪 (Production-Ready) | 二元/三元多层 STC 格码、预计算奇偶校验表与软判决 Viterbi 实现扎实；仅 `cost_calibration.rs` 单调裁剪后少一次跨度复核（**Issue #21**）。 |
| **内容域图像引擎 (PNG & JPEG)** | `rust/src/stego/png/`, `rust/src/stego/jpeg/`, `spatial_variance.rs` | **8.6 / 10** | 准生产级 (Late RC) | MiPOD / J-MiPOD 经近期重构已实现 Rayon 并行与内存复用；但默认 PNG 模型 `HILL` 与 `S-UNIWARD` 仍为单线程且 `HILL` 峰值驻留 6 个 `f64` 全图平面（**Issue #14**），`JpegEngine::embed` 丢弃了 `capacity` 返回值（**Issue #13**）。 |
| **内容域视频引擎 (HEVC / MP4 / MKV)** | `rust/src/stego/hevc/` (`engine.rs`, `bitstream.rs`, `mp4_boxes.rs`, `mkv_boxes.rs`) | **7.8 / 10** | 候选发布级 (Beta / RC) | H.265 帧内 CABAC 旁路符号翻转与 MP4 局部补丁提交极具创新性；但 **MKV 容器存在嵌套 CRC-32 更新顺序错误（Issue #3）、未知大小 Cluster 吞噬后续帧（Issue #4）、缺失快速探测与局部补丁提交且单次嵌入全文件扫描 3 次（Issue #15）**。 |
| **内容域音频引擎 (WAV & FLAC)** | `rust/src/stego/audio/` (`mod.rs`, `core.rs`, `wav.rs`, `flac/*`) | **7.2 / 10** | 需重点修复 (Beta) | FLAC 残差直接重编码与因果卷积补偿确保了 PCM 零失真；但存在 **`embed_flac` 双重扣减 512 槽位导致临界容量嵌入失败（Issue #2）、全文件重复解码 3~7 次（Issue #6）、补偿脉冲改动漏计 5~8 倍（Issue #9）、`probe_flac` 漏检 >24-bit（Issue #10）**。 |
| **盲隐写分析模块 (`analysis`)** | `rust/src/analysis.rs`, `analysis/calibration.rs` | **8.3 / 10** | 准生产级 (Late RC) | 64 MiB 窗口化头尾扫描与语料库阈值校准非常务实；但在多通道/多分块非线性估计量聚合与 4:2:0 JPEG 色度合成灰度校准上存在统计偏差（**Issue #16**）。 |
| **CLI 与 Tauri v2 桌面端 (`gui`)** | `rust/src/cli/`, `gui/src-tauri/`, `gui/src/` | **7.6 / 10** | 候选发布级 (Beta / RC) | 60fps 进度节流与双源日志面板体验优秀；但存在 **诊断日志明文记录提取出的机密文本载荷（Issue #5）、GUI 提取文件载荷重复执行两遍完整解密解码（Issue #7）、前端用未压缩尺寸误杀高压缩率载荷（Issue #8）、6 个后端命令未暴露至前端 UI（Issue #22）**。 |

---

### 1.3 审查发现问题总览矩阵（22 项）

| 编号 | 严重度 | 问题类别 | 所属模块 / 精确位置 | 问题核心简述 |
| :---: | :---: | :--- | :--- | :--- |
| **#1** | **P0** | 代码错误 / 逻辑边界错误 | `rust/src/core/crypto.rs:472` | `decrypt_stream_from_chunks` 将密文块上限设为 `MAX_CHUNK_SIZE` 而漏加 `AEAD_TAG_LEN` (16B)，导致满 64 MiB 分块写入的数据无法解密与校验。 |
| **#2** | **P0** | 逻辑错误 / 算法容量失配 | `rust/src/stego/audio/mod.rs:85, 98, 207`<br>`audio/flac/mod.rs:577` | `embed_flac` 对已不含 Header 的 `analysis.usable` 再次减去 512 槽位，与 `core::embed` 规划不一致，引发临界负载下分组因子 $u$ 失配报错，且未校验 `tails >= 512`。 |
| **#3** | **P0** | 逻辑错误 / 容器校验损坏 | `rust/src/stego/hevc/mkv_boxes.rs:401, 464` | MKV `refresh_crcs` 按外层 `Segment` 到内层 `Cluster` 的顺序刷新 CRC-32，导致外层 CRC 覆盖旧的 Cluster CRC 而自检失败；且漏解析 `BlockGroup` 内的 `ID_CRC32`。 |
| **#4** | **P0** | 脆弱代码与逻辑 / 解析错误 | `rust/src/stego/hevc/mkv_boxes.rs:193, 391` | MKV `read_element` 将未知大小（流式 `size == None`）的 `Cluster` 钳制到 `segment.end()`，使首个 `Cluster` 吞掉后续所有 `Cluster` 并丢弃后续视频帧。 |
| **#5** | **P1** | 安全与隐私泄漏 / 逻辑错误 | `gui/src-tauri/src/commands/stego.rs:391`<br>`commands/structure.rs:131` | GUI 后端在 `smart_extract` 与 `read_structure` 日志中将完整 `ReadSummary`（含 `text_preview` 64 KiB 明文机密载荷）写入全局环形日志并广播至前端。 |
| **#6** | **P1** | 低效代码 / 严重性能问题 | `rust/src/stego/audio/mod.rs:78-238`<br>`audio/flac/mod.rs:288, 456` | FLAC 引擎全文件重复解码风暴：`probe_flac` 解码 3 次，`extract`/`inspect` 解码 4 次，`verify` 解码 6 次，`embed_flac` 单次嵌入解码全文件达 **7 次**。 |
| **#7** | **P1** | 低效代码 / 严重性能问题 | `gui/src/views/ExtractView.tsx:60-103` | GUI 提取文件载荷时先以 `outputPath = undefined` 完整提取一次（丢弃内存数据），再以目标路径完整提取第二次，双倍消耗 Argon2id 与全文件解码开销。 |
| **#8** | **P1** | 逻辑错误 / 契约不一致 | `gui/src/views/StegoEmbedView.tsx:106-159` | GUI 嵌入前用**未压缩**字节数比对压缩后容量上限与安全预算，误拒可压缩载荷；且每次嵌入前串行调用一次完整 `probeStegoCapacity` 造成双倍解码。 |
| **#9** | **P1** | 算法可靠性 / 数据统计错误 | `rust/src/stego/audio/flac/mod.rs:423, 643`<br>`audio/mod.rs:151` | FLAC 因果补偿脉冲 (`slot.comp`) 每个槽位连带改写多达 12 个相邻残差，但 `modified` 仅加 1，使统计修改率与安全评估被低估 5~8 倍；且每次补偿写触发冗余回读。 |
| **#10** | **P1** | 代码错误 / API 契约不一致 | `rust/src/stego/audio/mod.rs:200-222` | `embed_flac` 明确拒绝 `bits_per_sample > 24`，但 `probe_flac` 未做该检查，对 32-bit FLAC 虚报可用容量。 |
| **#11** | **P1** | 数据错误 / 逻辑错误 | `rust/src/stego/io.rs:163-175`<br>`rust/src/cli/cmd_stego.rs:302-312` | WAV/FLAC 触发安全预算超限警告时，错误调用了图像 `bpp_limit()` (`0.02/0.05/0.10`) 与 `payload_bits / total_elements`，而非音频专属 `safety_bpp_limit`。 |
| **#12** | **P2** | 逻辑错误 / 参数校验绕过 | `rust/src/stego/io.rs:59-89` | `embed_carrier_file` 对 MP4 与 Annex-B 走局部补丁快径时绕过了 `options.tuning.applicable_to(format)?`，传入图像算法参数不报错。 |
| **#13** | **P2** | 数据缺失 / 性能与 CLI 缺陷 | `rust/src/stego/jpeg/engine.rs:623, 1474`<br>`rust/src/cli/cmd_stego.rs:348` | `JpegEngine::embed` 返回 `capacity: None`，导致文件嵌入后被迫重跑一次 `probe_carrier_capacity`（重复计算代价），且 `--dry-run` 缺失容量报告；`inspect` 漏标 `J-MiPOD`。 |
| **#14** | **P2** | 性能与内存问题 / 低效算法 | `rust/src/stego/png/cost/hill.rs:59-158`<br>`png/cost/suniward.rs:148-233` | PNG 默认模型 `HILL` 与 `S-UNIWARD` 完全单线程；`HILL` 阶段二使用非分离 2D 均值滤波（慢 7.5 倍）且同时驻留 6 个 `f64` 全图平面（48 B/px）。 |
| **#15** | **P2** | 性能问题 / 低效代码 | `rust/src/stego/hevc/engine.rs:356, 450, 866`<br>`rust/src/stego/io.rs:59` | MKV 缺失 20% 采样快速探测、流式 `inspect` 与 `commit_carrier_patches` 局部写回，且单次嵌入重复执行 3 次 `parse_mkv_targets` 全文件扫描与 CRC 计算。 |
| **#16** | **P2** | 算法可靠性 / 统计学偏差 | `rust/src/analysis.rs:1555, 1959, 1993`<br>`analysis/calibration.rs:130` | 空域 RS/SPA/WS 跨通道取最大值放大假阳性、跨分块对非线性方程根直接求平均；JPEG 校准用解码 RGB 合成灰度引入 4:2:0 色度上采样伪影。 |
| **#17** | **P2** | 脆弱代码与逻辑 | `rust/src/structure/rejection.rs:158-216`<br>`structure/adapters/pdf.rs:161-169` | PDF 签名检测跨全文件独立匹配 `"/ByteRange"` 与 `"/Sig"` 易被普通正文误触发；`read_xref_stream_dict` 用 `split("stream")` 易被含 `stream` 子串的键名截断。 |
| **#18** | **P2** | 健壮性 / 线程调度与状态不一致 | `gui/src-tauri/src/commands/diag.rs:18-228`<br>`gui/src/views/ScanView.tsx:48` | `inspect`/`verify`/`scan` 命令未接入 `GuiState.pool` 与 `run_cancellable_task`；`ScanView` 与 `smart_extract` 对内容域载体的 `is_encrypted` 状态判定失真。 |
| **#19** | **P3** | 无效冗余代码 | `rust/src/stego/audio/mod.rs:114-143` | 音频嵌入的 `MAX_EMBED_ATTEMPTS (8)` 重试循环在过滤 `Move::None` 后永不触发，且更改 `salt` 在数学上无法改变 STC 网格状态可达性。 |
| **#20** | **P3** | 低效代码 | `rust/src/stego/png/engine.rs:1321-1410` | `embed_png_with_stats` 在 `build_png_capacity_info` 统计完绿通道/RGB 槽位数后，又冗余遍历两次 `plan.candidates` 计算相同数值。 |
| **#21** | **P3** | 算法健壮性 | `rust/src/stego/cost_calibration.rs:136-184` | `enforce_monotonic_anchors` 裁剪锚点后未复核总跨度 `MIN_CALIBRATION_SPAN`，极端退化分布下可能产生零斜率/零跨度插值。 |
| **#22** | **P3** | 前端功能闭环缺失 | `gui/src/api/commands.ts`<br>`gui/src/views/ScanView.tsx` | 后端已实现的 `scan_carrier_cmd`、`verify_carrier_cmd`、`restore_structure_file_cmd`、`run_batch_job_cmd` 等 6 个命令未在 GUI 前端暴露，`ScanView` 缺密码输入。 |


---

## 二、已实现功能全景盘点与成熟度深度评估

### 2.1 核心基础设施层 (`rust/src/core/`)

1. **密码学与流式分块帧 (`core/crypto.rs`)**
   - **已实现能力**：
     - 采用 **Argon2id**（默认 `m_cost = 64 MiB`, `t_cost = 3`, `p_cost = 4`）从用户密码与 16 字节随机盐派生主密钥种子，再经 **HKDF-SHA256** 域分离派生出 32 字节 `payload_key` 与 32 字节 `meta_key`。
     - 针对无密码（标准公开模式）载体，使用内置常量密钥进行确定性混淆（Obfuscation），统一了加密与非加密信封的底层二进制结构，避免明文特征裸露。
     - 载荷采用 **AES-256-GCM** 分块流式认证加密（默认分块 1 MiB，最大支持 64 MiB），每块 Nonce 由 `base_nonce ^ chunk_index` 构造，AAD 绑定 96 字节信封头、`chunk_index` 及 `is_last` 尾块标志，严格防御分块重排、截断与拼接攻击。
     - 内置 `VerifySha256Writer` 流式校验器，支持在不将 1 GiB 载荷载入内存的前提下完成流式解密、Deflate 解压与 SHA-256 完整性比对。
   - **成熟度评估**：密码学原语选型与 AAD 绑定设计符合现代密码学工程规范，唯独 `decrypt_stream_from_chunks` 在校验密文块长度上限时遗漏了 16 字节 GCM Tag（见 **Issue #1**）。

2. **崩溃安全原子提交与局部补丁写回 (`core/commit.rs`)**
   - **已实现能力**：
     - 所有文件写入均通过同目录带 PID 与随机盐的临时文件（`<target>.strhide.<pid>.<rand>.tmp`）配合 `TmpGuard` RAII 守卫执行，`fsync` 落盘后再通过带指数退避重试的 `rename_with_retry`（应对 Windows Error 32/33 文件占用）原子替换目标文件，并在 Unix 下同步父目录项（`sync_parent_dir`）。
     - 原地修改（In-place）支持持久化 `.bak` 备份（`copy_file_durable` 含 `sync_all`）与碰撞后缀递增，支持保留原文件权限与 `atime`/`mtime` 时间戳。
     - 针对大型视频载体（MP4 / Annex-B），提供 `commit_carrier_patches`：先执行内核级 `std::fs::copy`，再仅对修改过的字节区间执行 `seek + write_all`，避免将数百 MB 的视频克隆到用户态堆内存。
   - **成熟度评估**：文件系统事务安全性极高，达到了工业级存储工具水准。

---

### 2.2 结构域隐写引擎 (`rust/src/structure/`)

1. **通用二进制信封协议 (`structure/envelope.rs`)**
   - **已实现能力**：定义了 `UBE v1`（112 字节头部 + 变长分块密文流 + AEAD 保护的 JSON 元数据 + 24 字节尾部）。支持 `--stealth` 隐蔽模式（通过 HMAC-SHA256 由密码派生头部与尾部魔数，并用密钥流盲化尾部偏移量与长度字段），使未持有密码的扫描器无法通过固定字节签名识别信封。
2. **11 种宿主容器适配器 (`structure/adapters/`)**
   - **PNG (`png.rs`)**：支持在 `IEND` 块前注入合规私有辅助块 `prIv`（带标准 CRC-32）或 `eof` 尾部追加。
   - **JPEG (`jpeg.rs`)**：支持注入合规 `APP11` (`0xFFEB`, 64 KiB 上限) / `COM` 注释段或自动回退 `eof`。
   - **WebP & WAV (`webp.rs`, `wav.rs`, `riff.rs`)**：支持注入 RIFF 私有块 `SHRD`（自动维护偶数字节对齐填充与 RIFF 总长度字段修补）或 `eof`。
   - **MP4 & HEIF (`mp4.rs`, `heif.rs`, `isobmff.rs`)**：支持 32/64-bit `uuid` 扩展盒、`free` 填充盒，以及针对 HEIF/HEIC 图像的深度结构隐藏策略 **`item_hidden`**（在 `meta` 盒的 `iinf`/`iloc` 中注册一个不被主图 `pitm`/`iref` 引用的隐藏 `mime` Item，并将数据存入第二个 `mdat` 盒，实现零可疑 Box 与主图比特级无损）。
   - **MKV (`mkv.rs`, `ebml.rs`)**：支持注入合规 `EBML Void` (`0xEC`) 填充元素（VINT 编码长度）或 `eof`。
   - **ZIP (`zip.rs`)**：支持 `pre_cd_inject`（在中央目录 Central Directory 之前插入信封，自动平移并修补 EOCD 中的 `cd_offset` 字段，自动识别并规避空包与 ZIP64 定位器冲突）或 `eof`。
   - **PDF (`pdf.rs`)**：支持 `incremental`（符合 PDF 规范的增量更新：追加 `/Type /Metadata` 对象流、增量 `xref` 表、携带 `/Root`/`/Info`/`/Prev` 的新 `trailer` 与 `%%EOF`，并保留原文件尾部脏数据以保证 100% 比特级还原）或 `eof`。
   - **Windows PE (`pe.rs`, `pe_slack.rs`, `pe_codebits.rs`, `pe_layout.rs`)**：
     - `pe_overlay`：PE 节表末尾追加覆盖层；
     - `pe_slack`：扫描并验证节对齐全零填充区（Section Alignment Padding），原位覆写信封，文件大小零增长，还原时精确归零；
     - `pe_codebits`：基于 `iced-x86` 反汇编/重编码器，利用 `.text` 代码段中 x86/x64 寄存器间算术逻辑指令（`ADD/ADC/AND/OR/XOR/SUB/SBB/MOV/CMP` 的 `r/m, r` 与 `r, r/m` 对偶编码，以及交换律指令 `TEST` 的寄存器顺序）嵌入通道头与 UBE 比特流，并将还原差分位图（Diff Bitmap）存入全零 Slack 区，实现**代码段等价指令变形 + 100% 比特级原样恢复**。
   - **数字签名保护 (`rejection.rs`)**：写入前自动检测 PE Authenticode 证书表、PDF `/ByteRange + /Sig` 数字签名、ZIP/JAR `META-INF/*.SF|.RSA|.DSA` 签名及独立签名文件，防止静默破坏数字签名。

---

### 2.3 内容域自适应隐写引擎 (`rust/src/stego/`)

| 载体格式 | 核心引擎模块 | 嵌入域与修改原语 | 失真代价模型 | 纠错与格码方案 | 还原与保真特性 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PNG** | `stego/png/engine.rs` | 空域像素（绿通道单层池 + RB 双通道复合池），保留全部 PNG 辅助块 | **HILL** (默认)<br>**S-UNIWARD**<br>**MiPOD** (2D-Wiener + Fisher 信息) | Header: Rate-1/2 Conv + Binary STC<br>Body: **Ternary `±1` MLS** | 像素最大改动 $\pm 1$，自适应纹理区优先 |
| **JPEG** | `stego/jpeg/engine.rs` | 量化非零 AC DCT 系数（无损重编码 Baseline Huffman 流） | **UERD** (默认)<br>**J-UNIWARD**<br>**J-MiPOD** (块平滑先验) | Header: Rate-1/2 Conv + Binary STC<br>Body: **Ternary `±1` MLS** | 零 IDCT 重压缩世代损失，DQT/DHT/Exif 完整保留 |
| **HEVC (MP4 / MKV / HEIF / Annex-B)** | `stego/hevc/engine.rs` | H.265 帧内 Slice CABAC 旁路位 `coeff_sign_flag` 原地翻转（受 `abs_remainder` 存在性与每 4×4 块 $\le 2$ 符号预算约束） | **QP + $\log_2(\text{level})$ + 帧内块密度** 自适应失真模型 | Header: Rate-1/2 Conv (无 STC)<br>Body: **Binary STC** ($h=7\dots 10$) | **文件字节长度 100% 不变**，CABAC 状态机零漂移 |
| **WAV** | `stego/audio/wav.rs`<br>`audio/core.rs` | 16/24-bit PCM 采样点（避开静音段与削波边界） | **二阶线性预测残差** $\hat{x}_n = 2x_{n-1}-x_{n-2}$ 局部能量自适应代价 | Header: v2 512B 双层固定步长<br>Body: **Ternary `±1` MLS** | 采样点最大改动 $\pm 1$ LSB，RIFF 非音频块完整保留 |
| **FLAC** | `stego/audio/flac/` (`mod.rs`, `frame.rs`, `bits.rs`) | 原生无损子帧 Rice 编码残差流（直接修改残差商/余数，并在后续 $p$ 个采样施加 $-\text{sgn}\cdot a_k$ **因果反向补偿脉冲**） | 预测残差局部包络 + Rice 参数 $k$ 码长惩罚（零字节膨胀约束） | Header: 512 个子帧尾部残差<br>Body: **Binary STC** (映射到 $\pm 1$ 有效方向) | **解码后 PCM 采样与 MD5 100% 比特级不变**，仅改变 LPC 预测器与残差间的内部表征 |


---

## 三、深度问题审查与可靠代码级解决方案 (In-Depth Audit & Solutions)

本章节对审查发现的 **22 项核心技术问题**按严重度（P0 $\to$ P3）逐一展开深度剖析，提供精确到行号的根因推导与可直接合入的修复代码。

---

### Issue #1 [P0 | 代码错误 / 逻辑边界错误] `decrypt_stream_from_chunks` 漏加 `AEAD_TAG_LEN` (16B) 导致满 `MAX_CHUNK_SIZE` 分块密文无法解密与校验

- **问题类别**：代码错误、逻辑错误、数据边界错误
- **严重等级**：**P0（阻断性数据恢复失败）**
- **精确位置**：
  - `rust/src/core/crypto.rs:330` (`encrypt_stream_to_chunks`)
  - `rust/src/core/crypto.rs:472-478` (`decrypt_stream_from_chunks`)
- **根因深度剖析**：
  在 `rust/src/params.rs` 与 `rust/src/core/crypto.rs:19` 中，`MAX_CHUNK_SIZE` 被定义为 `64 * 1024 * 1024`（`67,108,864` 字节），代表**明文分块（Plaintext Chunk）**的最大允许字节数。
  在写入路径 `encrypt_stream_to_chunks` (`crypto.rs:330`) 中：
  ```rust
  if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
      return Err(StrHideError::General(...));
  }
  let mut buf = vec![0u8; chunk_size];
  ```
  当调用方配置 `chunk_size = MAX_CHUNK_SIZE`（或处于 `(MAX_CHUNK_SIZE - 15)..=MAX_CHUNK_SIZE` 区间内）且待加密数据长度 $\ge \text{chunk\_size}$ 时，AES-256-GCM 加密器会在明文块后附加 16 字节认证标签（`AEAD_TAG_LEN = 16`），因此写入流的单块密文长度前缀 `chunk_len` 为：
  $$\text{chunk\_len} = \text{MAX\_CHUNK\_SIZE} + \text{AEAD\_TAG\_LEN} = 67,108,864 + 16 = 67,108,880 \text{ bytes}$$
  然而在读取与校验路径 `decrypt_stream_from_chunks` (`crypto.rs:471-478`) 中：
  ```rust
  let remaining = total_payload_bytes - bytes_consumed;
  let max_chunk = remaining.min(MAX_CHUNK_SIZE as u64) as usize;
  if chunk_len > max_chunk {
      return Err(StrHideError::CorruptedData(format!(
          "Chunk length {chunk_len} exceeds maximum {max_chunk}"
      )));
  }
  ```
  此处将密文块长度 `chunk_len` 与**未加 `AEAD_TAG_LEN` 的 `MAX_CHUNK_SIZE`** 进行比较！只要明文分块大小落在 `(MAX_CHUNK_SIZE - 15)..=MAX_CHUNK_SIZE`，写入完全成功，但后续所有 `read`、`extract` 和 `verify` 操作都会必现报错：
  `CorruptedData("Chunk length 67108880 exceeds maximum 67108864")`。
- **可靠修复方案**：
  在 `decrypt_stream_from_chunks` 中将单块密文长度上限修正为 `(MAX_CHUNK_SIZE + AEAD_TAG_LEN) as u64`，并补充针对 `MAX_CHUNK_SIZE` 边界的回归测试。

```rust
// 文件: rust/src/core/crypto.rs (第 470-480 行修复)
        // Bound the allocation by the bytes still expected in the envelope AND
        // the protocol-level maximum ciphertext chunk size (MAX_CHUNK_SIZE + AEAD_TAG_LEN).
        let remaining = total_payload_bytes - bytes_consumed;
        let max_cipher_chunk = (MAX_CHUNK_SIZE + AEAD_TAG_LEN) as u64;
        let max_chunk = remaining.min(max_cipher_chunk) as usize;
        if chunk_len > max_chunk {
            return Err(StrHideError::CorruptedData(format!(
                "Chunk length {chunk_len} exceeds maximum {max_chunk}"
            )));
        }
```

---

### Issue #2 [P0 | 逻辑错误 / 算法容量失配] FLAC 引擎 `embed_flac` 双重扣减 512 个 Header 槽位且缺失 `tails < 512` 前置检查，导致临界容量下嵌入失败

- **问题类别**：逻辑错误、算法错误、数据不一致
- **严重等级**：**P0（功能阻断与容量失配）**
- **精确位置**：
  - `rust/src/stego/audio/mod.rs:85-106` (`embed_flac`)
  - `rust/src/stego/audio/mod.rs:207-220` (`probe_flac`)
  - `rust/src/stego/audio/flac/mod.rs:574-580` (`FlacCarrier::capacity_slots`)
  - `rust/src/stego/audio/core.rs:539-568` (`core::probe` / `core::embed`)
- **根因深度剖析**：
  1. **FLAC 双池物理隔离机制**：在 FLAC 引擎中，512 个 v2 Header 槽位存储在每个子帧的**最后一个残差**（`analysis.tails` 池，因为尾部残差无需因果补偿，可在不知道 `payload_len` 的情况下原位提取 Header）；而载荷 Body 槽位存储在子帧内部支持因果补偿的位置（`analysis.usable` 池）。因此，`analysis.usable` **本身就是已经排除了所有尾部 Header 槽位之后的纯 Body 可用槽位数**。
  2. **`FlacCarrier` 与 `core::embed` 的约定**：为了适配 `core.rs` 通用接口中 `let available = carrier.capacity_slots() - V2_TOTAL_HEADER_SLOTS;` 的统一公式，`FlacCarrier::capacity_slots()` (`flac/mod.rs:577`) 特意返回了：
     ```rust
     fn capacity_slots(&self) -> usize {
         self.total_usable + V2_TOTAL_HEADER_SLOTS
     }
     ```
     因此在 `core::probe` 和 `core::embed` 内部，计算出的 Body 可用槽位数 `available` 恰好还原为 `self.total_usable`（即 `analysis.usable`）。
  3. **`embed_flac` 的双重扣减 Bug (`audio/mod.rs:98-100`)**：
     在 `embed_flac` 中，预规划 Body 槽位数量以构造 `FlacCarrier::new` 时，代码却写成了：
     ```rust
     let available = analysis.usable.saturating_sub(V2_TOTAL_HEADER_SLOTS);
     let (u, body_slots) =
         core::plan_body(raw_frame.len() * 8, available, V2_STC_H, FlacCarrier::MLS)?;
     ```
     这里从 `analysis.usable` 中**错误地又减去了 512 (`V2_TOTAL_HEADER_SLOTS`)**！这导致两个严重后果：
     - **后果 A（容量边界拒绝）**：当载荷所需 Body 槽位数处于 `(analysis.usable - 512, analysis.usable]` 区间时，`probe_flac`（通过 `core::probe` 使用 `analysis.usable`）报告容量充足，但 `embed_flac` 在 `line 99` 直接报错 `CapacityTooSmall`！
     - **后果 B（分组因子 $u$ 阈值跳变导致 `core::embed` 崩溃）**：在 `core::plan_body` (`audio/core.rs:230-264`) 中，分组大小 $u \in \{3, 4, 6, 8\}$ 由负载率 $r = \text{available} / \text{code\_len}$ 决定（例如 $r \ge 4.5$ 时选 $u=3$，否则退回 $u=4$ 或更大）。因为 `embed_flac` 传入的是 `analysis.usable - 512`（较小的 `available`），当负载率恰好跨越 $4.5\times$（或 $6\times / 8\times$）阈值时，**`embed_flac` 选出较小的 $u_1$（分配较少的 `body_slots`），而随后 `core::embed` (`audio/core.rs:568`) 使用未减 512 的 `analysis.usable` 重新调用 `plan_body` 选出较大的 $u_2$（需要更多的 `body_slots`）**！此时 `carrier.body_len()` 小于 `core::embed` 期望的 `body_slots`，直接在 `audio/core.rs:574` 抛出错误：`Audio carrier capacity is too small: it exposes ... slots but the payload needs ...`！
  4. **缺失 `analysis.tails < V2_TOTAL_HEADER_SLOTS` 前置校验 (`audio/mod.rs:85, 207`)**：
     `embed_flac` 和 `probe_flac` 仅检查了 `analysis.usable < V2_TOTAL_HEADER_SLOTS + 8`，却没有检查 `analysis.tails < V2_TOTAL_HEADER_SLOTS`。对于块极长（如 `blocksize = 16384`）但总采样数较少、子帧总数不足 512 个的 FLAC 文件，`analysis.usable` 可能高达数万（通过检查），但 `analysis.tails < 512`！此时 `probe_flac` 虚报支持大容量嵌入，而 `embed_flac` 在 `FlacCarrier::new` 阶段才因 `tails` 不足报错。
- **可靠修复方案**：
  1. 在 `embed_flac` 与 `probe_flac` 中同时校验 `analysis.tails < V2_TOTAL_HEADER_SLOTS`；
  2. 在 `embed_flac` 中直接使用 `let available = analysis.usable;` 调用 `core::plan_body`，消除与 `core::embed` 的不一致。

```rust
// 文件: rust/src/stego/audio/mod.rs (修复 embed_flac 与 probe_flac)
pub fn embed_flac(
    carrier: &[u8],
    payload: &[u8],
    password: &str,
    domain: &str,
    options: &EmbedOptions<'_>,
    dialect: &StegoDialect,
) -> Result<EmbedOutput, StrHideError> {
    let info = flac::parse_stream_info(carrier)?;
    if info.bits_per_sample > 24 {
        return Err(StrHideError::UnsupportedFormat(format!(
            "FLAC bits_per_sample={} exceeds 24-bit integer pipeline",
            info.bits_per_sample
        )));
    }
    let analysis = flac::analyse(carrier)?;
    if analysis.tails < V2_TOTAL_HEADER_SLOTS || analysis.usable < 8 {
        return Err(StrHideError::CapacityTooSmall {
            needed: V2_TOTAL_HEADER_SLOTS,
            available: analysis.tails.min(analysis.usable),
        });
    }

    let raw_frame = envelope::compress_and_encrypt(
        payload,
        password,
        domain,
        options.payload_kind,
        options.payload_name.as_deref(),
        dialect,
    )?;

    // 修复: analysis.usable 已经是排除了 512 个尾部 Header 槽位后的纯 Body 可用槽位数，
    // 必须与 core::embed 中 (capacity_slots() - V2_TOTAL_HEADER_SLOTS == analysis.usable) 保持严格一致。
    let available = analysis.usable;
    let (_u, body_slots) =
        core::plan_body(raw_frame.len() * 8, available, V2_STC_H, FlacCarrier::MLS)?;
```

```rust
// 文件: rust/src/stego/audio/mod.rs (probe_flac 同步修复)
pub fn probe_flac(
    carrier: &[u8],
    safety: SafetyLevel,
    dialect: &StegoDialect,
) -> Result<StegoCapacityInfo, StrHideError> {
    let info = flac::parse_stream_info(carrier)?;
    if info.bits_per_sample > 24 {
        return Err(StrHideError::UnsupportedFormat(format!(
            "FLAC bits_per_sample={} exceeds 24-bit integer pipeline",
            info.bits_per_sample
        )));
    }
    let analysis = flac::analyse(carrier)?;
    if analysis.tails < V2_TOTAL_HEADER_SLOTS || analysis.usable < 8 {
        return Err(StrHideError::CapacityTooSmall {
            needed: V2_TOTAL_HEADER_SLOTS,
            available: analysis.tails.min(analysis.usable),
        });
    }
    let total_samples = (info.total_samples as usize).saturating_mul(info.channels as usize);
    let view = flac::FlacCarrier::metadata_only(analysis.usable, total_samples);
    Ok(core::probe(&view, "FLAC", safety, dialect))
}
```

---

### Issue #3 [P0 | 逻辑错误 / 容器校验损坏] Matroska (MKV) 嵌套 `CRC-32` 刷新顺序错误及遗漏 `BlockGroup` 级 `CRC-32`

- **问题类别**：逻辑错误、数据损坏、容器兼容性错误
- **严重等级**：**P0（导致含 Segment CRC 或 BlockGroup CRC 的 MKV 嵌入报错或文件损坏）**
- **精确位置**：
  - `rust/src/stego/hevc/mkv_boxes.rs:368-445` (`parse_mkv_targets`)
  - `rust/src/stego/hevc/mkv_boxes.rs:464-486` (`refresh_crcs`)
- **根因深度剖析**：
  1. **嵌套 CRC-32 更新顺序倒置 (`mkv_boxes.rs:384-410` vs `464-486`)**：
     在 `parse_mkv_targets` 遍历 Matroska `Segment` 子元素时：
     - 若 `Segment` 顶层包含 `ID_CRC32` (`0xBF`)，它在第 384 行被**最先 push** 进 `crcs` 向量，其覆盖区间 `covers` 为整个 `Segment` 的剩余字节（包含所有 `Cluster` 及其内部的 `ID_CRC32` 元素）；
     - 随后遍历到各个 `ID_CLUSTER` 时，每个 `Cluster` 内部的 `ID_CRC32` 在第 401 行被**依次 push** 进 `crcs` 向量。
     接着在 `refresh_crcs` (`mkv_boxes.rs:464-472`) 中：
     ```rust
     pub fn refresh_crcs(out: &mut [u8], crcs: &[CrcSpan]) -> Result<(), &'static str> {
         for c in crcs {
             let Some(body) = out.get(c.covers.clone()) else { ... };
             let crc = crc32_ieee(body);
             out[c.crc_At..c.crc_at + 4].copy_from_slice(&crc.to_le_bytes());
         }
         ...
     ```
     由于按 `crcs` 正序遍历，**外层 `Segment` 的 CRC-32 在内层 `Cluster` 的 CRC-32 被更新之前就已经计算完毕**！随后内层 `Cluster` 的 4 字节 CRC 值被写入 `out`（位于 `Segment` 的 `covers` 区间内），导致外层 `Segment` 的 CRC-32 立即失效！紧接着第 478 行的自检调用 `parse_mkv_targets(out)` 验证 `Segment` CRC 时就会触发 CRC 不匹配，直接抛出 `"Matroska CRC-32 could not be refreshed"`！
  2. **遗漏 `ID_BLOCK_GROUP` (`0xA0`) 内部的 `ID_CRC32` (`mkv_boxes.rs:401-411`)**：
     根据 Matroska (RFC 9559) 规范，`BlockGroup` (`0xA0`) 作为 Master Element 同样允许携带 `CRC-32` (`0xBF`) 子元素。而 `parse_mkv_targets` 在第 401–411 行处理 `ID_BLOCK_GROUP` 时只匹配了 `ID_BLOCK`，完全忽略了 `BlockGroup` 内部的 `ID_CRC32`。一旦修改了 `BlockGroup` 内的 HEVC 视频帧，`BlockGroup` 的 CRC-32 将保持旧值，导致严格校验 CRC 的播放器（如 `ffmpeg -err_detect +crccheck`、`mkvinfo`）报数据损坏。
- **可靠修复方案**：
  1. 在 `ID_BLOCK_GROUP` 子循环中同样收集 `ID_CRC32`（并验证初始 CRC）；
  2. 在 `refresh_crcs` 中按照 `c.covers.len()` **从小到大（自内向外：先 `BlockGroup` $\to$ 再 `Cluster` $\to$ 最后 `Segment`）** 排序后再计算并回填 CRC-32。

```rust
// 文件: rust/src/stego/hevc/mkv_boxes.rs (修复 ID_BLOCK_GROUP CRC 收集与 refresh_crcs 顺序)
                        ID_BLOCK_GROUP => {
                            let bg_body = &data[ce.body.clone()];
                            let mut bg_crc: Option<CrcSpan> = None;
                            for bge in (Children {
                                data,
                                pos: ce.body.start,
                                end: ce.body.end,
                            }) {
                                let bge = bge?;
                                match bge.id {
                                    ID_CRC32 => {
                                        if bge.body.len() != 4 || bge.header_at != ce.body.start {
                                            return Err("Malformed Matroska BlockGroup CRC-32 element");
                                        }
                                        let stored = u32::from_le_bytes(
                                            data[bge.body.clone()].try_into().unwrap(),
                                        );
                                        let actual = crc32_ieee(&bg_body[bge.body.end - ce.body.start..]);
                                        if stored != actual {
                                            return Err("Matroska BlockGroup CRC-32 mismatch in input carrier");
                                        }
                                        bg_crc = Some(CrcSpan {
                                            crc_at: bge.body.start,
                                            covers: bge.body.end..ce.body.end,
                                        });
                                    }
                                    ID_BLOCK => {
                                        parse_block_payload(
                                            data,
                                            bge.body,
                                            false,
                                            video_track_num,
                                            &mut units,
                                        )?;
                                    }
                                    _ => {}
                                }
                            }
                            if let Some(c) = bg_crc {
                                crcs.push(c);
                            }
                        }
```

```rust
// 文件: rust/src/stego/hevc/mkv_boxes.rs (修复 refresh_crcs 自内向外更新)
pub fn refresh_crcs(out: &mut [u8], crcs: &[CrcSpan]) -> Result<(), &'static str> {
    // 按覆盖区间长度从小到大排序（innermost-first: BlockGroup -> Cluster -> Segment），
    // 确保内层更新后的 CRC 字节能够被外层 Master Element 的 CRC 正确纳入计算。
    let mut ordered: Vec<&CrcSpan> = crcs.iter().collect();
    ordered.sort_by_key(|c| c.covers.len());

    for c in ordered {
        let Some(body) = out.get(c.covers.clone()) else {
            return Err("Matroska CRC-32 span out of bounds");
        };
        let crc = crc32_ieee(body);
        let Some(slot) = out.get_mut(c.crc_at..c.crc_at + 4) else {
            return Err("Matroska CRC-32 field out of bounds");
        };
        slot.copy_from_slice(&crc.to_le_bytes());
    }
    Ok(())
}
```


---

### Issue #4 [P0 | 脆弱代码与逻辑 / 解析器错误] Matroska 未知长度 (`size == None`) `Cluster` 吞噬后续所有 `Cluster` 导致全片视频帧丢失

- **问题类别**：脆弱代码与逻辑、容器解析错误
- **严重等级**：**P0（流式生成的 MKV 视频帧丢失）**
- **精确位置**：`rust/src/stego/hevc/mkv_boxes.rs:178-206` (`read_element`), `378-438` (`parse_mkv_targets`)
- **根因深度剖析**：
  在 Matroska 规范（RFC 9559 §5.1.1）中，实时录制或流式封包器（如 `ffmpeg -f matroska` 流式输出、OBS Studio 录制、GStreamer `matroskamux streamable=true`）生成的 MKV 文件不仅 `Segment` 使用未知大小 VINT（`0x01FFFFFFFFFFFFFF`），每个 `Cluster` (`0x1F43B675`) 也常被写为未知大小（`size == None`），并以遇到下一个 `Cluster`（或下一个顶层 Level 1 元素）作为当前 `Cluster` 的隐式结束边界。
  然而在 `read_element` (`mkv_boxes.rs:193-196`) 中：
  ```rust
  let body_end = match size {
      Some(n) => body_start.checked_add(n as usize).ok_or("EBML element size overflow")?,
      None => parent_end,
  };
  ```
  当 `Segment` 下的第一个 `Cluster` 具有 `size == None` 时，`read_element` 将其 `body_end` 直接设为 `parent_end`（即整个文件末尾 `segment.end()`）！随后在遍历该 `Cluster` 的子元素循环（`mkv_boxes.rs:391-434`）中：
  - 第一个 `Cluster` 内部的 `SimpleBlock` / `BlockGroup` 被正常解析；
  - 紧接着文件流到达**第二个 `Cluster` 的 Element ID (`0x1F43B675`)**，此时内层 `Children` 迭代器仍在运行（因为 `end == segment.end()`），它将第二个 `Cluster` 当成第一个 `Cluster` 的子元素读取，并在第 432 行落入 `_ => {}` 分支直接跳过！
  - 结果：**除第一个 `Cluster`（通常仅几秒视频）外，后续所有 `Cluster` 中的视频帧全部被静默丢弃**！
- **可靠修复方案**：
  当 `Cluster` 的 `size == None` 时，禁止将其 `body_end` 设为 `segment.end()`，而在内层 `Children` 迭代遇到下一个 Level 1 元素（如 `ID_CLUSTER`、`ID_CUES`、`ID_TAGS`、`ID_ATTACHMENTS`、`ID_CHAPTERS`、`ID_SEEK_HEAD`、`ID_INFO`、`ID_TRACKS`）之前停止，并将外层 `Segment` 游标回退到该新元素的 `header_at` 起始偏移。

```rust
// 文件: rust/src/stego/hevc/mkv_boxes.rs (在 ID_CLUSTER 分支支持未知长度 Cluster 边界识别)
                ID_CLUSTER => {
                    let cluster_unknown_len = data[elem.header_at..elem.body.start]
                        .get(4..)
                        .and_then(|s| read_vint_size(s, 0).ok())
                        .is_some_and(|(sz, _)| sz.is_none());
                    let cluster_body = &data[elem.body.clone()];
                    let mut cluster_crc: Option<CrcSpan> = None;
                    let mut sub_iter = Children {
                        data,
                        pos: elem.body.start,
                        end: elem.body.end,
                    };
                    while let Some(ce) = sub_iter.next() {
                        let ce = ce?;
                        // 若当前 Cluster 为未知大小 (size == None)，遇到下一个 Level-1 元素即终止当前 Cluster
                        if cluster_unknown_len
                            && matches!(
                                ce.id,
                                ID_CLUSTER | ID_INFO | ID_TRACKS | 0x114D9B74 /* SeekHead */
                                | 0x1C53BB6B /* Cues */ | 0x1043A770 /* Chapters */ | 0x1254C367 /* Tags */
                            )
                        {
                            // 将外层迭代器游标回退到下一个 Level-1 元素起始处
                            seg_children.pos = ce.header_at;
                            break;
                        }
                        // ... 原有 ID_CRC32 / ID_SIMPLE_BLOCK / ID_BLOCK_GROUP 处理逻辑 ...
                    }
                }
```

---

### Issue #5 [P1 | 安全与隐私泄漏 / 逻辑错误] Tauri GUI 后端在 `smart_extract` 与 `read_structure` 中将解密后的完整明文载荷记录进全局诊断日志

- **问题类别**：安全与隐私泄漏、逻辑错误（违反项目自身安全规范）
- **严重等级**：**P1（机密明文载荷泄漏）**
- **精确位置**：
  - `gui/src-tauri/src/commands/stego.rs:382-392` (`smart_extract_impl`)
  - `gui/src-tauri/src/commands/structure.rs:124-133` (`read_structure_file_impl`)
- **根因深度剖析**：
  在 `docs/gui_log_panel_and_diagnostics_plan_20261102.md` §7 中明确规定：
  > **密码与密钥脱敏**：严禁在任何日志（无论是 `info!` 还是 `debug!`）中记录明文密码、派生密钥或**完整的隐写载荷明文内容（仅记录字节长度 `payload_bytes` / `raw_size`）**。
  然而在 `gui/src-tauri/src/commands/stego.rs:382-392` 中：
  ```rust
  crate::logger::record_custom_log(
      "info",
      "ipc::smart_extract",
      &format!(
          "Smart extract succeeded from {:?}: is_file={}, size={}",
          res.source, res.summary.is_file, res.summary.raw_size
      ),
      serde_json::to_value(&res).ok(),
  );
  ```
  以及 `gui/src-tauri/src/commands/structure.rs:124-133` 中：
  ```rust
  crate::logger::record_custom_log(
      "info",
      "ipc::read_structure",
      &format!(...),
      serde_json::to_value(&summary).ok(),
  );
  ```
  当用户提取一段文本隐写载荷（`output_path == None`）时，`ReadSummary.text_preview` 字段中存储着**完整的解密后机密明文字符串（最高 64 KiB）**！调用 `serde_json::to_value(&res)` 会将 `text_preview` 完整序列化进 `LogEntryDto.data`：
  1. 驻留在全局静态内存 `LOGGER_STATE.buffer` 中；
  2. 在 Debug 模式下直接打印或通过 `app.emit("app:log", &entry)` 广播至前端 `useLogStore`；
  3. 当用户因排查问题点击日志面板的 **「复制全部 (Copy All)」** 导出诊断日志发给他人或提交 Issue 时，`copyFormatted` (`gui/src/store/logStore.ts:140-146`) 会将 `e.data` 中的完整机密明文一并导出到剪贴板！
- **可靠修复方案**：
  在向诊断日志记录 `ReadSummary` 或 `SmartExtractSummaryDto` 时，构造脱敏 JSON 对象（移除或掩码 `text_preview` 字段，仅保留 `has_text_preview: summary.text_preview.is_some()` 及字节长度 `raw_size`）。

```rust
// 文件: gui/src-tauri/src/commands/stego.rs (第 382-393 行修复)
        crate::logger::record_custom_log(
            "info",
            "ipc::smart_extract",
            &format!(
                "Smart extract succeeded from {:?}: is_file={}, size={}",
                res.source,
                res.summary.is_file,
                res.summary.raw_size
            ),
            Some(serde_json::json!({
                "source": res.source,
                "also_present": res.also_present,
                "carrier": res.summary.carrier,
                "is_file": res.summary.is_file,
                "is_encrypted": res.summary.is_encrypted,
                "filename": res.summary.filename,
                "raw_size": res.summary.raw_size,
                "written_file": res.summary.written_file,
                "has_text_preview": res.summary.text_preview.is_some(),
            })),
        );
```

```rust
// 文件: gui/src-tauri/src/commands/structure.rs (第 124-134 行修复)
        crate::logger::record_custom_log(
            "info",
            "ipc::read_structure",
            &format!(
                "Read structure: is_file={}, raw_size={}, filename={}",
                summary.is_file, summary.raw_size, summary.filename
            ),
            Some(serde_json::json!({
                "carrier": summary.carrier,
                "is_file": summary.is_file,
                "is_encrypted": summary.is_encrypted,
                "filename": summary.filename,
                "raw_size": summary.raw_size,
                "written_file": summary.written_file,
                "has_text_preview": summary.text_preview.is_some(),
            })),
        );
```


---

### Issue #6 [P1 | 低效代码 / 严重性能问题] FLAC 引擎全文件重复解码风暴（单次 `embed` 全量解码 7 次、`probe` 3 次、`extract`/`inspect` 4 次、`verify` 6 次）

- **问题类别**：低效代码与算法、严重性能问题
- **严重等级**：**P1（在大体积无损音频上造成 4~7 倍的 CPU 与内存带宽浪费）**
- **精确位置**：
  - `rust/src/stego/audio/mod.rs:78-238` (`embed_flac`, `extract_flac`, `inspect_flac`, `verify_flac`, `probe_flac`)
  - `rust/src/stego/audio/flac/mod.rs:288-375` (`FlacCarrier::new`), `456-560` (`refresh_checksums`, `max_sample_drift`)
- **根因深度剖析**：
  追踪 FLAC 各操作对全文件比特流（`walk_frames` + 全子帧 Rice 残差解码 + LPC 采样重建 + MD5 计算）的完整遍历次数：
  1. **`probe_flac`（全文件解码 3 次 + 整文件 `to_vec()` 克隆）**：
     - 第 1 次：`audio/mod.rs:206` 调用 `flac::analyse(carrier)`；
     - 第 2 次：`audio/mod.rs:215` 调用 `FlacCarrier::new(carrier, 0)`，其内部 Pass 1 (`flac/mod.rs:297`) 再次调用 `analyse(bytes)`；
     - 第 3 次：`FlacCarrier::new` 的 Pass 2 (`flac/mod.rs:321`) 再次调用 `walk_frames` 解码全文件并执行 `bytes.to_vec()` 克隆整个 FLAC 文件！
     - **荒谬之处**：紧接着调用的 `core::probe(&view, ...)` (`audio/core.rs:536`) **只读取了 `view.capacity_slots()` 和 `view.total_samples()` 两个整数**，根本不访问任何槽位或文件字节！
  2. **`embed_flac`（单次嵌入全文件解码 7 次）**：
     - 第 1 次：`embed_flac` (`audio/mod.rs:84`) 调用 `flac::analyse(carrier)`；
     - 第 2 次：`FlacCarrier::new` (`flac/mod.rs:297`) Pass 1 再次调用 `analyse(carrier)`；
     - 第 3 次：`FlacCarrier::new` (`flac/mod.rs:321`) Pass 2 调用 `walk_frames` 抽样槽位；
     - 第 4 次：`carrier_view.into_bytes()` 调用 `refresh_checksums` (`flac/mod.rs:475`)，执行 `walk_frames` 重算每帧 CRC-8/CRC-16 并计算全文件解码 PCM 的 MD5；
     - 第 5 次：`refresh_checksums` 第 513 行紧接着又调用了一次 `let recheck = analyse(&out)?;` 并检查 `recheck.pcm_md5 != md5`——而第 4 步刚刚在**完全相同的 `out` 缓冲区**上解码完所有帧并算出了 `md5`！第 5 次解码纯粹是用相同的函数对相同的切片重算了一遍完全相同的 MD5！
     - 第 6 & 7 次：`embed_flac` 第 145 行调用 `flac::max_sample_drift(carrier, &stego)`，其内部 (`flac/mod.rs:532-558`) **再次从头完整解码一遍原始 `carrier`（第 6 次）和一遍 `stego`（第 7 次）**！而第 4 步 `refresh_checksums` 已经算出了 `stego` 的 `pcm_md5` 并可与第 1 步 `analysis.pcm_md5` 直接比对（128-bit MD5 相等即证明 PCM 零漂移，`max_drift == 0`）！
  3. **`extract_flac` / `inspect_flac`（各解码 4 次 + 2 次整文件克隆）与 `verify_flac`（解码 6 次 + 3 次整文件克隆）**：
     - `extract_flac` 先调用 `FlacCarrier::new(carrier, 0)`（内部解码 2 次 + 克隆整文件）仅为了读 512 个 `tails` 槽位解析 Header；得到 `payload_len` 后，又调用 `FlacCarrier::new(carrier, body_slots)`（内部再次解码 2 次 + 克隆整文件）！
     - 只读路径（`extract`/`inspect`/`verify`）根本不需要修改文件，却在每次构造 `FlacCarrier` 时都执行 `bytes.to_vec()` 克隆数以十兆计的 FLAC 字节流！
- **可靠修复方案**：
  1. 为 `FlacCarrier` 增加轻量只读构造器 `FlacCarrier::metadata_only(usable, total_samples)` 供 `probe_flac` 使用，将 `probe_flac` 从 **3 次全量解码 + 1 次整文件克隆** 降至 **仅 1 次无 MD5 帧扫描**；
  2. 将 `Analysis` 作为参数传入 `FlacCarrier::with_analysis(carrier, body_slots, &analysis)`，消除 Pass 1 的重复 `analyse`；且当 `body_slots == 0`（仅读 Header）时，Pass 2 只收集前 512 个 `tails` 即可提前终止，无需遍历后续残差；
  3. 在 `refresh_checksums` 中直接传入原始 `analysis.pcm_md5` 与重算帧 CRC 期间同步得到的 `md5` 比对，删除第 513 行的冗余 `analyse(&out)` 和 `embed_flac` 中的 `max_sample_drift(carrier, &stego)`，将 `embed_flac` 从 **7 次全量解码** 降至 **2 次遍历**（提速 **3.5 倍以上**）。

```rust
// 文件: rust/src/stego/audio/flac/mod.rs (新增 metadata_only 与 with_analysis，精简 refresh_checksums)
impl FlacCarrier {
    /// 仅供 probe_flac 容量估算使用的零拷贝、零二次解码视图
    pub fn metadata_only(total_usable: usize, total_samples: usize) -> Self {
        Self {
            bytes: Vec::new(),
            slots: Vec::new(),
            total_usable,
            total_samples,
            modified: 0,
        }
    }

    /// 复用调用方已计算的 Analysis，避免重复执行 Pass 1 全文件解码
    pub fn with_analysis(
        bytes: &[u8],
        body_slots: usize,
        analysis: &Analysis,
    ) -> Result<Self, StrHideError> {
        if analysis.tails < V2_TOTAL_HEADER_SLOTS {
            return Err(StrHideError::CapacityTooSmall {
                needed: V2_TOTAL_HEADER_SLOTS,
                available: analysis.tails,
            });
        }
        if body_slots > analysis.usable {
            return Err(StrHideError::CapacityTooSmall {
                needed: body_slots,
                available: analysis.usable,
            });
        }
        // Pass 2: 抽取前 512 个 tails 与均匀水塘抽样的 body_slots
        // ... (保留原 Pass 2 逻辑，直接复用 analysis.info) ...
```

---

### Issue #7 [P1 | 低效代码 / 严重性能问题] GUI 提取视图 (`ExtractView.tsx`) 对所有文件载荷执行两次完整的 `smartExtract` 解密与解码

- **问题类别**：低效代码、前后端交互逻辑缺陷、严重性能问题
- **严重等级**：**P1（文件载荷提取耗时翻倍，大型视频/图像载体尤为明显）**
- **精确位置**：
  - `gui/src/views/ExtractView.tsx:60-103`
  - `gui/src-tauri/src/commands/stego.rs:303-397` (`smart_extract_impl`)
- **根因深度剖析**：
  在 `ExtractView.tsx` 中，点击「开始提取」后对每个载体的处理流程如下：
  1. 第 60–70 行：首先调用 `smartExtract(taskId, item.path, undefined, password || undefined, ...)`（`outputPath` 传 `undefined`）。
  2. 在后端 `smart_extract_impl` (`commands/stego.rs:329`) 中，`engine.smart_extract(&path, &smart_opts)` 会**完整执行一次隐写提取**（包括全文件读取、PNG/JPEG/HEVC/WAV/FLAC 全量解码、STC/Viterbi 译码、Argon2id 64 MiB 密钥派生、AES-256-GCM 解密、Deflate 解压，将完整载荷字节生成在 `outcome.payload.data` 中）。
  3. 随后在 `commands/stego.rs:357-374` 中，因为 `output_path` 是 `None`，后端检查若 `payload.data.len() <= 64 * 1024` 且为 UTF-8 则构造 `text_preview`，**然后直接丢弃了 `outcome.payload.data` 内存缓冲区**！
  4. 回到前端 `ExtractView.tsx` 第 77–102 行：只要提取出的是文件载荷（`summary.is_file == true`）或超过 64 KiB 的文本载荷，前端计算出保存路径 `target = await uniqueOutputPath(...)` 后，**再次调用 `smartExtract(taskId, item.path, target, ...)`**！后端不得不从头再跑一遍完整的载体解码、Argon2id 密钥派生和解密解压！
- **可靠修复方案**：
  让 `smart_extract_cmd` 接收可选的 `output_dir: Option<PathBuf>`（或默认回退到载体所在目录 `path.parent()`）。当提取出的载荷是文件类型（`is_file == true`）或文本超过预览阈值（`> 64 KiB`）时，**直接在后端单次提取流程中生成唯一文件名并调用 `write_bytes_atomic` 落盘**，将落盘路径填入 `ReadSummary.written_file` 返回给前端，彻底消除第二次 `smartExtract` 调用！

```rust
// 文件: gui/src-tauri/src/commands/stego.rs (在单次 smart_extract_impl 内完成文件自动命名与原子落盘)
        let summary = if let Some(ref dest) = output_path {
            // 若前端传入的是输出目录，或需要自动去重文件名的目标路径，直接一次写入
            let final_dest = if dest.is_dir() {
                unique_file_in_dir(dest, &filename)
            } else {
                dest.clone()
            };
            if is_file || payload.data.len() > 64 * 1024 {
                write_bytes_atomic(&final_dest, &payload.data)?;
                ReadSummary {
                    carrier: path,
                    is_file,
                    is_encrypted,
                    filename,
                    raw_size,
                    written_file: Some(final_dest),
                    text_preview: None,
                }
            } else if let Ok(s) = std::str::from_utf8(&payload.data) {
                ReadSummary {
                    carrier: path,
                    is_file: false,
                    is_encrypted,
                    filename,
                    raw_size,
                    written_file: None,
                    text_preview: Some(s.to_string()),
                }
            } else {
                write_bytes_atomic(&final_dest, &payload.data)?;
                ReadSummary {
                    carrier: path,
                    is_file,
                    is_encrypted,
                    filename,
                    raw_size,
                    written_file: Some(final_dest),
                    text_preview: None,
                }
            }
        } else { ... };
```

---

### Issue #8 [P1 | 逻辑错误 / 契约不一致] GUI 内容隐写视图 (`StegoEmbedView.tsx`) 使用未压缩载荷尺寸提前拦截并跳过可压缩载荷，且每次嵌入前重复执行完整 `probe`

- **问题类别**：逻辑错误、前后端契约不一致、低效代码
- **严重等级**：**P1（导致 CLI 可正常嵌入的文本/文件在 GUI 中被误判跳过，且嵌入耗时翻倍）**
- **精确位置**：`gui/src/views/StegoEmbedView.tsx:61-62, 99-160`
- **根因深度剖析**：
  1. **未压缩大小 vs 压缩后大小的契约冲突 (`StegoEmbedView.tsx:125-141`)**：
     在后端 Rust 引擎中，无论是物理容量上限检查还是安全预算检查（`StegoEngine::check_budget`, `rust/src/stego/engine.rs:845-875`），比对的都是 **经过 Raw Deflate (Level 9) 压缩后的载荷大小 `compressed_payload_bytes`**（见 `engine.rs:846` 注释：*"`compressed_payload_bytes` is the deflate-compressed payload size (before encryption framing), so highly compressible inputs are not rejected based on their raw uncompressed size"*）。
     然而在前端 `StegoEmbedView.tsx` 第 61–62 行与 125–141 行：
     ```tsx
     const payloadBytes =
       payloadKind === "text" ? new TextEncoder().encode(text).length : payloadSize ?? 0;
     ...
     if (payloadBytes > capacity.max_raw_payload_bytes) {
       queue.update(item.path, { status: "skip", message: ... });
       continue;
     }
     if (enforce && payloadBytes > limit) {
       queue.update(item.path, { status: "skip", message: ... });
       continue;
     }
     ```
     前端直接用**未压缩的 `payloadBytes`** 与 `capacity.max_raw_payload_bytes` 及 `limit` 比较！如果用户选择了一个 50 KB 的 JSON/日志/源码文件或长文本（Deflate 压缩后仅 6 KB），在安全上限 `limit = 15 KB` 的图像上，CLI (`strhide embed`) 能轻松嵌入，而 GUI 却直接在前端将其拦截并标记为 `skip`（过大跳过）！
  2. **嵌入前串行执行完整 `probeStegoCapacity` 造成双倍耗时 (`StegoEmbedView.tsx:106-116, 145-160`)**：
     点击「开始隐写」时，对队列中的每个文件，前端先调用一次 `probeStegoCapacity`（读取并解码载体计算代价与容量），紧接着在第 145 行又调用 `embedStegoFile`（后端 `embed_carrier_file` 再次从磁盘读取载体、完整解码并重新计算一遍失真代价与 `StegoCapacityInfo`，且在 `StegoEmbedResult.capacity` 中返回了该容量信息！）。
- **可靠修复方案**：
  移除 `StegoEmbedView.tsx` `run()` 循环中前置阻塞的 `probeStegoCapacity` 调用及基于未压缩 `payloadBytes` 的前端硬拦截，直接调用后端 `embedStegoFile`（后端 `embed_carrier_file` 内部会在 Deflate 压缩后精确执行 `check_budget` 和物理容量检查），并从 `embedStegoFile` 返回的 `res.capacity`（或在捕获 `SafetyBudgetExceeded` / `CapacityTooSmall` 错误时）更新队列项的 `capacityBytes` 与 `skip` 状态。

```tsx
// 文件: gui/src/views/StegoEmbedView.tsx (简化 run() 循环，交由后端在 Deflate 压缩后精确执行容量与安全预算判定)
        try {
          const target = await uniqueOutputPath(outputDir || item.dir, withSuffix(item.name, "_stego"));
          const res = await embedStegoFile(
            taskId,
            {
              carrier: item.path,
              payload,
              output_path: target,
              password: password || undefined,
              domain: undefined,
              safety_level: safety,
              enforce_safety: enforce,
              algorithm: algorithm !== "auto" ? algorithm : undefined,
              backup: false,
              overwrite: false,
            },
            updateProgress,
          );
          queue.update(item.path, {
            status: "ok",
            capacityBytes: res.capacity.recommended_max_bytes,
            message: undefined,
            outputPath: res.written_to,
          });
        } catch (err) {
          const parsed = parseStrHideError(err, c);
          const isBudgetOrCap =
            parsed.code === "SafetyBudgetExceeded" || parsed.code === "CapacityTooSmall";
          queue.update(item.path, {
            status: isBudgetOrCap ? "skip" : "error",
            message: parsed.message,
          });
        }
```


---

### Issue #9 [P1 | 算法可靠性 / 数据统计错误] FLAC 因果补偿脉冲 (`slot.comp`) 级联修改未计入 `modified_elements`，且每次补偿写入执行冗余全码字回读

- **问题类别**：算法可靠性、数据错误、低效代码
- **严重等级**：**P1（实际残差修改率被低估 5~8 倍，掩盖高负载下的统计异常）**
- **精确位置**：
  - `rust/src/stego/audio/flac/mod.rs:423-453` (`write_remainder`), `643-670` (`FlacCarrier::apply_slot`)
  - `rust/src/stego/audio/mod.rs:151` (`embed_flac` 统计汇报)
  - 参考内部评审文档：`docs/flac_residual_engine_review_20261102.md` §3.1
- **根因深度剖析**：
  1. **补偿级联修改漏计 (`flac/mod.rs:643-670`)**：
     在 FLAC 子帧中，将位置 $i$ 的残差 $r_i$ 修改 $\Delta \in \{-1, +1\}$ 时，为了保证解码器通过 $p$ 阶 LPC 滤波器重建的采样点 $s_i$ 之后的后续采样点 $s_{i+1}, \dots, s_{i+p}$ 不发生级联漂移，`apply_slot` 必须同步改写后续 $p$ 个采样点的残差（最多 $p=12$，常见 `flac -5` 为 $p=5\dots 8$）：
     $$r_{i+k}' = r_{i+k} - \Delta \cdot \text{round}\left(\frac{a_k}{2^{\text{shift}}}\right), \quad k = 1, \dots, p$$
     然而在 `apply_slot` 第 669 行：
     ```rust
     for c in &slot.comp {
         let new_r = c.orig - sign * c.impulse;
         let new_q = zigzag_encode(new_r) >> c.k;
         debug_assert_eq!(new_q, c.orig_q);
         write_remainder(&mut self.bytes, c, new_r)?;
     }
     self.modified += 1;
     ```
     无论 `slot.comp` 中实际改写了多少个非零脉冲位置（通常 5~8 个），`self.modified` 只加 `1`！正如项目自身的 `docs/flac_residual_engine_review_20261102.md` 实测指出的：在 Balanced 档位下，表面报告的槽位修改率仅 ~11%，但**全文件实际被改写的残差比例高达 62.0%**，导致一阶残差直方图与相邻残差互相关系数明显偏移，而 `EmbedStats.modified_elements` 与 `actual_bpp` 却向用户和上层调用方报告了被低估 5~8 倍的虚假修改量。
  2. **`write_remainder` 每次写入执行冗余全码字回读 (`flac/mod.rs:437-452`)**：
     `write_remainder` 在通过 `Bw::patch_bits` 原位覆写 $k$ 个余数比特后，第 439 行每次都调用 `read_codeword(bytes, slot.bit_offset, slot.k, slot.utf8_coded)` 从字节流重新解析一遍一元商 + 余数。由于 `patch_bits` 仅修改 `[rem_bit_offset .. rem_bit_offset + k)` 的余数位且商 $q$ 已被不变量证明不变，在 Release 构建中对每个槽位的 1+8 次写入全部执行比特流回读纯属多余开销。
- **可靠修复方案**：
  1. 在 `apply_slot` 中跳过 `c.impulse == 0` 的空操作，并将实际发生值改变的补偿残差一并计入 `self.modified`（或新增 `modified_residuals` 字段如实反映物理残差改动总数）；
  2. 将 `write_remainder` 中的 `read_codeword` 回读校验移入 `#[cfg(debug_assertions)]`。

```rust
// 文件: rust/src/stego/audio/flac/mod.rs (修复 apply_slot 跳过零脉冲并诚实统计物理残差修改数)
        write_remainder(&mut self.bytes, &slot.target, target_r)?;
        let mut comp_modified = 0usize;
        for c in &slot.comp {
            if c.impulse == 0 {
                continue;
            }
            let new_r = c.orig - sign * c.impulse;
            let new_q = zigzag_encode(new_r) >> c.k;
            debug_assert_eq!(new_q, c.orig_q);
            write_remainder(&mut self.bytes, c, new_r)?;
            comp_modified += 1;
        }
        self.modified += 1 + comp_modified;
        Ok(())
```

---

### Issue #10 [P1 | 代码错误 / API 契约不一致] `probe_flac` 缺失 `bits_per_sample > 24` 格式门控，对 32-bit FLAC 虚报可用容量

- **问题类别**：代码错误、API 契约不一致
- **严重等级**：**P1（探测成功但嵌入必败）**
- **精确位置**：`rust/src/stego/audio/mod.rs:81-84` vs `200-222`
- **根因深度剖析**：
  `flac::frame::parse_stream_info` (`rust/src/stego/audio/flac/frame.rs:73`) 允许 `bits_per_sample` 在 `4..=32` 范围内通过解析。
  在 `embed_flac` (`audio/mod.rs:81-84`) 中，因为内部残差与 LPC 补偿管线基于 24-bit 整数设计，显式拦截了 `> 24` 位采样深度：
  ```rust
  if info.bits_per_sample > 24 {
      return Err(StrHideError::UnsupportedFormat(...));
  }
  ```
  但 `probe_flac` (`audio/mod.rs:200-222`) 完全漏掉了这一检查！当用户或 GUI 对一个 32-bit FLAC 文件调用 `probe` 时，`probe_flac` 返回正的可用容量，而随后执行 `embed` 时立即抛出 `UnsupportedFormat` 错误。
- **可靠修复方案**：
  已在 **Issue #2** 的 `probe_flac` 修复补丁中一并加入 `if info.bits_per_sample > 24` 检查。

---

### Issue #11 [P1 | 数据错误 / 逻辑错误] 音频载体 (WAV/FLAC) 超安全预算警告错误使用图像 `bpp_limit` (`0.02/0.05/0.10`) 而非音频 `safety_bpp_limit`

- **问题类别**：数据错误、逻辑错误
- **严重等级**：**P1（Advisory 模式下向用户和 JSON API 输出错误的预算上限与比率）**
- **精确位置**：
  - `rust/src/stego/io.rs:163-175` (`embed_carrier_file`)
  - `rust/src/cli/cmd_stego.rs:302-312` (`handle_embed`)
- **根因深度剖析**：
  在 `rust/src/stego/audio/core.rs:29-38` 中，音频载体的安全预算上限与图像截然不同：
  - 图像 (`SafetyLevel::bpp_limit`)：`Paranoid = 0.02`, `High = 0.05`, `Balanced = 0.10`；
  - 音频 (`audio::core::tier_fraction`)：`Paranoid = 0.005`, `High = 0.015`, `Balanced = 0.030`，且该真实上限已被保存在 `StegoCapacityInfo.safety_bpp_limit` 字段中！
  在 Enforced（强制拦截）模式下，`StegoEngine::check_budget` (`stego/engine.rs:861-867`) 正确读取了 `cap.safety_bpp_limit`。
  然而在 Advisory（默认告警不拦截）模式下，`stego/io.rs:165-172` 和 `cli/cmd_stego.rs:302-310` 构造 `StegoWarning::SafetyBudgetExceeded` 时却写成了：
  ```rust
  let actual_bpp = (payload_bytes as f64 * 8.0) / (cap_ref.total_elements.max(1) as f64);
  warnings.push(StegoWarning::SafetyBudgetExceeded {
      payload_bytes,
      recommended_max_bytes: cap_ref.recommended_max_bytes,
      actual_bpp,
      limit_bpp: options.safety.level.bpp_limit(), // <-- 错误！硬编码调用了图像 bpp_limit()
      safety_level: options.safety.level,
  });
  ```
  这导致在 WAV/FLAC 载体上触发超预算警告时，警告信息中显示的 `limit_bpp` 是图像的 `0.050`，甚至出现 `actual_bpp (0.018) < limit_bpp (0.050)` 却提示“超出上限”的自相矛盾现象！
- **可靠修复方案**：
  统一使用 `cap_ref.safety_bpp_limit` 替代 `options.safety.level.bpp_limit()`，并复用 `StegoEngine::check_budget` 的计算逻辑。

```rust
// 文件: rust/src/stego/io.rs (第 163-175 行修复) & rust/src/cli/cmd_stego.rs (第 302-312 行修复)
    if payload_bytes > cap_ref.recommended_max_bytes {
        let actual_bpp =
            (payload_bytes as f64 * 8.0) / (cap_ref.usable_elements.max(1) as f64);
        warnings.push(StegoWarning::SafetyBudgetExceeded {
            payload_bytes,
            recommended_max_bytes: cap_ref.recommended_max_bytes,
            actual_bpp,
            limit_bpp: cap_ref.safety_bpp_limit,
            safety_level: options.safety.level,
        });
    }
```

---

### Issue #12 [P2 | 逻辑错误 / 参数校验绕过] `embed_carrier_file` 对 MP4 与 Annex-B 走局部补丁快径时绕过了 `options.tuning.applicable_to(format)?` 校验

- **问题类别**：逻辑错误、API 契约不一致
- **严重等级**：**P2（接口行为不一致，非法算法参数静默生效）**
- **精确位置**：`rust/src/stego/io.rs:59-89` (`embed_carrier_file`)
- **根因深度剖析**：
  在内存接口 `StegoEngine::embed_with_dialect` (`rust/src/stego/engine.rs:300`) 中，第一行即执行：
  ```rust
  options.tuning.applicable_to(format)?;
  ```
  当用户对 MP4 或 HEVC-AnnexB 载体指定 `--algorithm hill`（PNG 专属）或 `--algorithm jmipod`（JPEG 专属）时，`StegoEngine::embed` 会立即返回 `UnsupportedFormat` 错误。
  但在文件级接口 `embed_carrier_file` (`rust/src/stego/io.rs:59-89`) 中，为了对 `FileFormat::Mp4 | FileFormat::HevcAnnexB` 使用 `commit_carrier_patches` 局部补丁优化，代码直接调用了 `crate::stego::hevc::engine::embed_hevc_patches(...)`，**完全绕过了 `StegoEngine::embed` 及其中的 `options.tuning.applicable_to(format)?` 检查**！导致在 CLI 或库文件接口中对 MP4/Annex-B 传入 `--algorithm hill` 不会报错，而是静默忽略。
- **可靠修复方案**：
  在 `embed_carrier_file` 识别出 `carrier_format` 后立即执行 `options.tuning.applicable_to(carrier_format)?`。

```rust
// 文件: rust/src/stego/io.rs (第 58-65 行修复)
    let carrier_format = sniff_bytes(&carrier_bytes).ok_or_else(|| {
        StrHideError::UnsupportedFormat(format!(
            "Unrecognized carrier format for '{}'",
            carrier_path.display()
        ))
    })?;
    options.tuning.applicable_to(carrier_format)?;
```


---

### Issue #13 [P2 | 数据缺失 / 性能与 CLI 缺陷] `JpegEngine::embed` 丢弃已计算的 `StegoCapacityInfo`，导致文件嵌入被迫二次重跑代价模型且 CLI `--dry-run` 缺失容量报告

- **问题类别**：数据缺失、低效代码、CLI 行为缺陷
- **严重等级**：**P2（JPEG 文件嵌入多算一次全图代价模型，`--dry-run` 输出残缺）**
- **精确位置**：
  - `rust/src/stego/jpeg/engine.rs:556-624` (`embed_jpeg_with_stats`), `1474` (`inspect_jpeg_from`)
  - `rust/src/stego/engine.rs:327-342` (`JpegEngine::embed`)
  - `rust/src/stego/io.rs:139-145` (`embed_carrier_file`)
  - `rust/src/cli/cmd_stego.rs:348-360` (`handle_embed`)
- **根因深度剖析**：
  1. 在 `StegoEngine::embed_with_dialect` 中，PNG、HEVC、WAV、FLAC 四个引擎均返回 `EmbedOutput::with_capacity_and_stats(bytes, cap, stats)`（其中 `capacity: Some(cap)`）。唯独 `JpegEngine::embed` (`stego/engine.rs:339`) 返回的是 `EmbedOutput::with_stats(bytes, stats)`（`capacity: None`）！
  2. 而在 `embed_jpeg_with_stats` (`jpeg/engine.rs:556-565`) 内部，其实**已经完整计算了 `usable_slots`、`total_ac` 并校验了容量**，只需几行算术即可构造 `StegoCapacityInfo`（调用同文件第 777 行的 `build_jpeg_capacity_info`）。
  3. 因为 `JpegEngine::embed` 返回了 `capacity: None`：
     - 在 `embed_carrier_file` (`stego/io.rs:139-145`) 中，命中 `None` 分支，被迫调用 `probe_carrier_capacity_with_dialect(&carrier_bytes, ...)`——**把整张 JPEG 的 Huffman 解码和 UERD/J-UNIWARD/J-MiPOD 失真代价模型从头又重算了一遍**！
     - 在 CLI `handle_embed` (`cli/cmd_stego.rs:348`) 中，执行 `strhide embed cover.jpg -m "secret" --dry-run` 时，由于 `out.capacity` 为 `None`，`if let Some(ref cap) = out.capacity` 分支被跳过，**JPEG 的 `--dry-run` 不会打印 `Msg::EmbedCapacityReport` 容量报告**，与其他所有格式不一致！
  4. 此外，在 `inspect_jpeg_from` (`jpeg/engine.rs:1474`) 中，返回的 `algorithm` 字段被硬编码为 `Some("UERD/J-UNIWARD".into())`，遗漏了已实现的 `J-MiPOD`。
- **可靠修复方案**：
  在 `embed_jpeg_with_stats` 中调用 `build_jpeg_capacity_info` 一并返回 `(Vec<u8>, StegoCapacityInfo, EmbedStats)`，并在 `JpegEngine::embed` 中使用 `EmbedOutput::with_capacity_and_stats`；同时将 `inspect_jpeg_from` 的算法描述更新为 `"UERD/J-UNIWARD/J-MiPOD"`。

```rust
// 文件: rust/src/stego/jpeg/engine.rs (第 615-624 行修复)
    let cap = build_jpeg_capacity_info(total_ac, usable_slots, options.safety.level, dialect);
    let stats = EmbedStats {
        algorithm: format!("JPEG-{}", model.name()),
        total_elements: total_ac,
        usable_elements: usable_slots,
        modified_elements,
        actual_bpp: (raw_frame.len() as f64 * 8.0) / (total_ac.max(1) as f64),
    };

    Ok((out, cap, stats))
```

---

### Issue #14 [P2 | 性能与内存瓶颈 / 低效算法] PNG 默认模型 `HILL` 与 `S-UNIWARD` 单线程执行，且 `HILL` 使用非分离 2D 滤波并同时驻留 6 个全图 `f64` 平面

- **问题类别**：低效算法、多线程缺失、内存峰值过高
- **严重等级**：**P2（高分辨率 PNG 嵌入延迟高、内存占用达 48 Bytes/Pixel）**
- **精确位置**：
  - `rust/src/stego/png/cost/hill.rs:59-158` (`HillCostModel::compute_cost`)
  - `rust/src/stego/png/cost/suniward.rs:62-233` (`SuniwardCostModel::compute_cost`)
- **根因深度剖析**：
  项目近期在 `mipod.rs` 与 `jmipod.rs` 中引入了 Rayon 并行化与条带化内存优化，但作为 **PNG 默认算法**的 `HILL` (`hill.rs`) 以及 `S-UNIWARD` (`suniward.rs`) 却仍停留在早期的朴素实现：
  1. **完全单线程运行**：`hill.rs` 和 `suniward.rs` 均未引入 `rayon::prelude::*`，在多核 CPU 上处理 12 MP ~ 64 MP 无损 PNG 时仅能利用单核。
  2. **`HillCostModel` 阶段二使用非分离 2D 窗口遍历 (`hill.rs:102-120`)**：
     Stage 3 (`15×15` 均值滤波) 正确使用了行列可分离（Separable 1D Horizontal + Vertical）滑动窗口，每像素仅需 4 次加减法（$O(1)$）；而 Stage 2（同样是 `15×15` 均匀盒式均值滤波，$p_1 = 15, \text{half}_1 = 7$）却写了四层嵌套循环，对每个像素遍历 $15 \times 15 = 225$ 个邻居，计算量比可分离滤波高出 **50 倍以上**！
  3. **6 个全图 `f64` 缓冲区同时驻留 (`hill.rs:73-158`)**：
     在 `HillCostModel::compute_cost` 中，依次分配了 `gray` ($N$)、`x_pad` ($(H+2)(W+2)$)、`i1` ($N$)、`i2` ($N$)、`tmp` ($N$)、`cost` ($N$) 共 **6 个全图 `f64` `Vec`**，且全部保持存活直到函数末尾才释放！对于一张 $8000 \times 8000$（64 MP）的 PNG，仅 `HILL` 代价计算就会瞬间分配 $6 \times 64\text{M} \times 8\text{B} \approx 3.07\text{ GiB}$ 堆内存，而在 Stage 1 结束后即可 `drop(gray); drop(x_pad);`，在 Stage 2 结束后即可复用 `i1` 作为 `cost` 输出，将峰值内存从 **6 个平面（48 B/px）直接降至 2 个平面（16 B/px，节省 67% 内存）**。
- **可靠修复方案**：
  将 `HillCostModel` 的 Stage 2 同样改为行列可分离的 `par_chunks_mut(w)` 并行滑动窗口，及时 `drop` 阶段性缓冲区并复用 `i1` 作为最终 `cost` 向量；同时为 `SuniwardCostModel` 的 `residual_pass` 与 `suitability_pass` 加上 `par_chunks_mut(w)`。

```rust
// 文件: rust/src/stego/png/cost/hill.rs (可分离并行滤波 + 2 平面内存复用核心改造)
use rayon::prelude::*;

// Stage 1 完成后立即释放 gray 与 x_pad:
drop(gray);
drop(x_pad);

// Stage 2 (15x15 low-pass l1 -> l2) 与 Stage 3 (15x15 low-pass 1/l2 -> cost)
// 统一复用 separable_box_filter_15x15(input: &[f64], tmp: &mut [f64], out: &mut [f64], w: usize, h: usize)
fn separable_box_filter_15x15(input: &[f64], tmp: &mut [f64], out: &mut [f64], w: usize, h: usize) {
    let half = 7usize;
    let inv_area = 1.0 / 225.0;
    // 1. 水平方向 1D 滑动窗口 (Rayon 按行并行)
    tmp.par_chunks_mut(w).enumerate().for_each(|(r, dst_row)| {
        let src_row = &input[r * w..(r + 1) * w];
        let mut sum: f64 = (0..=half).map(|k| src_row[k.min(w - 1)]).sum::<f64>()
            + (1..=half).map(|k| src_row[k.min(w - 1)]).sum::<f64>();
        dst_row[0] = sum;
        for c in 1..w {
            let add_c = sym_pad(c as isize + half as isize, w);
            let rem_c = sym_pad(c as isize - half as isize - 1, w);
            sum += src_row[add_c] - src_row[rem_c];
            dst_row[c] = sum;
        }
    });
    // 2. 垂直方向 1D 聚集 (Rayon 按行并行)
    out.par_chunks_mut(w).enumerate().for_each(|(r, dst_row)| {
        for c in 0..w {
            let mut s = 0.0f64;
            for dr in -(half as isize)..=(half as isize) {
                let rr = sym_pad(r as isize + dr, h);
                s += tmp[rr * w + c];
            }
            dst_row[c] = s * inv_area;
        }
    });
}
```

---

### Issue #15 [P2 | 性能问题 / 低效代码] MKV 载体缺失快速采样探测、流式 `inspect` 与局部补丁写回，且单次嵌入全文件扫描并计算 CRC 达 3 次

- **问题类别**：低效代码、性能瓶颈
- **严重等级**：**P2（大型 MKV 视频探测、检查与嵌入速度显著慢于同尺寸 MP4）**
- **精确位置**：
  - `rust/src/stego/hevc/engine.rs:356-383` (`extract_hevc_dimensions`), `450` (`probe_hevc_pool`), `866-876` (`record_carrier_state`)
  - `rust/src/stego/engine.rs:907-924` (`inspect_file_with_dialect`)
  - `rust/src/stego/io.rs:59-62` (`embed_carrier_file`)
- **根因深度剖析**：
  对比 MP4 与 MKV 在 HEVC 引擎中的待遇，存在四处明显的性能不对等：
  1. **`probe_hevc_pool` 未对 `MkvContainer` 启用 20% 采样快速探测 (`hevc/engine.rs:450`)**：
     ```rust
     let fast_sample = !exact && matches!(kind, HevcCarrierKind::Mp4Container) && units.len() >= 100;
     ```
     当 `exact == false`（默认快速探测）时，MP4 仅抽样解码 20% 的帧并乘以 5，而 `MkvContainer` 被迫 100% 解码全片所有帧！将 `matches!(kind, HevcCarrierKind::Mp4Container | HevcCarrierKind::MkvContainer)` 对齐即可使 MKV 探测提速 **4~5 倍**。
  2. **单次 MKV 嵌入重复调用 `parse_mkv_targets` 达 3 次**：
     在 `embed_hevc_core` 中：
     - 第 1 次：`record_carrier_state` (`hevc/engine.rs:869`) 调用 `parse_mkv_targets(carrier)`（遍历全文件所有 Cluster 并计算全文件 CRC-32）；
     - 第 2 次：`extract_hevc_dimensions` (`hevc/engine.rs:372`) 为了从 `CodecPrivate` 读宽高，竟然又调用了一次完整的 `parse_mkv_targets(carrier)`（遍历所有 Cluster 和视频帧）！
     - 第 3 次：`refresh_mkv_crcs` (`mkv_boxes.rs:478`) 在更新 CRC 后又调用了一次 `parse_mkv_targets(out)`！
  3. **`embed_carrier_file` (`stego/io.rs:59-62`) 未将 `FileFormat::Mkv` 纳入 `embed_hevc_patches` + `commit_carrier_patches`**：
     注：由于 MKV 的 `refresh_mkv_crcs` 也只是原位覆写 4 字节 `crc_at` 偏移，只需将更新后的 `CrcSpan`（4 字节区间）一并追加到 `patches` 列表中，`FileFormat::Mkv` 即可完美复用 `commit_carrier_patches` 内核拷贝 + 局部覆写快径！
- **可靠修复方案**：
  1. 在 `probe_hevc_pool` 中将 `MkvContainer` 纳入 `fast_sample`；
  2. 在 `mkv_boxes.rs` 中提供仅解析 `Tracks`（遇到第一个 `ID_CLUSTER` 即返回）的轻量函数 `parse_mkv_codec_private(data)` 供 `extract_hevc_dimensions` 调用；
  3. 将 `MkvContainer` 纳入 `embed_hevc_patches`（将重算后的 4 字节 CRC 槽位作为 patch 输出）。

```rust
// 文件: rust/src/stego/hevc/engine.rs (第 450 行修复: MKV 同样启用 20% 快速采样探测)
    let fast_sample = !exact
        && matches!(
            kind,
            HevcCarrierKind::Mp4Container | HevcCarrierKind::MkvContainer
        )
        && units.len() >= 100;
```


---

### Issue #16 [P2 | 算法可靠性 / 统计学偏差] 盲隐写分析模块 (`analysis`) 跨通道/跨分块统计聚合偏差与 4:2:0 JPEG 色度校准失真

- **问题类别**：算法可靠性、统计学偏差
- **严重等级**：**P2（影响盲隐写检测器的信噪比与估计准确度）**
- **精确位置**：
  - `rust/src/analysis.rs:1408-1459` (`ws_analysis`), `1555-1577` (`track_spatial_domain`), `1959-2042` (`rs_analysis`, `spa_estimate_dww`)
  - `rust/src/analysis/calibration.rs:130-140, 210-236` (`luma_at`, `estimate_with_coefficients`)
- **根因深度剖析**：
  1. **多通道 `max` 选择偏差 + 跨分块非线性根平均 (`analysis.rs:1453, 1558-1576, 1969, 2038`)**：
     - 在 `ws_analysis`、`rs_analysis` 和 `spa_estimate_dww` 中，对 RGB 三通道分别计算估计率后均取了最大值（`best = best.max(score)`）。在自然图像中，蓝色通道（B）传感器散粒噪声常显著高于绿色通道（G），取三通道最大值会使单通道高方差直接主导输出（这也是代码不得不将 `SPATIAL_RATE_THRESHOLD` 推高到 `0.70` 的原因之一）。
     - 在 `track_spatial_domain` (`analysis.rs:1555-1576`) 中，大图被切分为顶、中、底 3 个 512 行的 `spatial_slabs`。对 `chi2_suspicion`，代码正确地将 3 个分块的直方图累加池化（Pooled Histogram）后再计算一次统计量；但对 RS、SPA 和 WS，代码却分别在 3 个分块上独立求解二次方程根（如 SPA 的 $2k\beta^2 + 2(2x-N)\beta + (y-x)=0$），再对截断到 $[0, 1]$ 后的根取算术平均！当图像顶部是纯色天空（$k$ 或判别式奇异，估计值为 0）而中部是纹理区时，分块求解再平均会严重扭曲全局最小二乘/矩估计的无偏性。正确做法是**先跨分块累加充分统计量**（WS 的 `numerator`/`denominator`、SPA 的 `(x, y, k, pair_count)`、RS 的 `(r_count, s_count, n)`），最后求解一次方程。
  2. **JPEG 校准分析在 4:2:0 色度子采样下使用 RGB 合成 BT.601 灰度 (`analysis/calibration.rs:130-140`)**：
     Fridrich (2002) 校准分析对比的是原图亮度通道（Y component）的量化 DCT 直方图 `actual.components[0]` 与裁剪 4 像素后的参考亮度 DCT 直方图。然而 `calibration.rs` 通过 `decode_jpeg_pixels` 解码得到的是经 `YCbCr -> RGB` 转换（且对 4:2:0 图像经历了 Cb/Cr 色度上采样与 [0, 255] 截断）后的 RGB 像素，随后 `luma_at` 又通过 `0.299 R + 0.587 G + 0.114 B` 逆向合成 Y！对于 4:2:0 彩色 JPEG，色度 2×2 块边界恰好与 4 像素裁剪后的 8×8 校准网格中心重合，色度量化与 RGB 截断误差会直接混入校准参考直方图。直接对 `actual.components[0]`（纯 Y 分量 DCT 块）执行反量化 + 8×8 IDCT 还原纯 Y 平面，既无需解码 Cb/Cr 通道（省去 2/3 计算与内存），又能彻底消除 `YCbCr -> RGB -> Y` 往返失真！
- **可靠修复方案**：
  1. 将 `ws_analysis`、`spa_estimate_dww`、`rs_analysis` 改为先跨所有 `spatial_slabs` 累加每個通道的充分统计量（分子/分母或轨迹计数），再在池化统计量上求解一次估计率；
  2. 在 `calibration.rs` 中直接由 `actual.components[0]`（Y 通道系数）乘以 `qt` 并执行 8×8 IDCT 重建纯亮度平面（仅需转换采样的校准窗口周围的块），彻底规避 `jpeg_decoder` 全图 RGB 解码与色度污染。

---

### Issue #17 [P2 | 脆弱代码与逻辑] PDF 签名检测跨全文件独立匹配字面量易误报，且 `read_xref_stream_dict` 使用 `split("stream")` 易被截断

- **问题类别**：脆弱代码与逻辑
- **严重等级**：**P2（特定正常 PDF 被误判为已签名拒绝写入，或 XRef 流解析失败）**
- **精确位置**：
  - `rust/src/structure/rejection.rs:158-216` (`check_pdf_signature`)
  - `rust/src/structure/adapters/pdf.rs:161-169` (`read_xref_stream_dict`)
- **根因深度剖析**：
  1. **`check_pdf_signature` 跨全文件独立布尔标志累积 (`rejection.rs:175-203`)**：
     `check_pdf_signature` 以 64 KiB 分块扫描整个 PDF。只要在文件第 1 页（例如一篇讨论 PDF 格式或密码学的文档、甚至包含代码片段的电子书）出现字面量 `"/ByteRange"`（`has_byterange = true`），而在第 100 页出现任何以 `"/Sig"` 开头的词（如 `"/Signal"`、注释或正文字符串，`find_subsequence(&window, b"/Sig")` 也会匹配 `"/Signal"` 的前缀！），两个布尔变量同时变为 `true`，立即报错拒绝写入！
     真正的 PDF 签名字典（ISO 32000-1 §12.8）中，`/ByteRange` 与 `/Type /Sig`（或 `/FT /Sig` / `/Filter /Adobe.PPKLite`）必定出现在**同一个签名对象字典内**（相距通常不超过 2 KiB），且 `/Sig` 之后必须紧跟 PDF 分隔符（空白、`/`、`[`、`<`、`>`、`(`），绝不能匹配 `"/Signal"`。
  2. **`read_xref_stream_dict` 使用 `text.split("stream").next()` (`pdf.rs:163`)**：
     在解析 PDF 1.5+ XRef 流对象字典时，代码使用 `text.split("stream").next()` 寻找字典末尾的 `stream` 关键字。如果字典在 `/Size` 或 `/Root` 之前包含任何带有小写 `"stream"` 子串的自定义键或注释（例如 `/UpstreamRef`），`split("stream")` 会在该键处提前截断字典文本，导致后面的 `/Size` 和 `/Root` 丢失！PDF 规范要求 `stream` 关键字前后必须紧跟行尾符（`\n` 或 `\r\n`）且位于字典结束符 `>>` 之后。
- **可靠修复方案**：
  1. 在 `check_pdf_signature` 中要求 `/ByteRange` 与带边界检查的 `/Sig` Token 出现在同一个 64 KiB 滑动窗口内，且校验 `/Sig` 后的字节为合法 PDF 分隔符；
  2. 在 `read_xref_stream_dict` 中先定位字典闭合符 `">>"`（或匹配 `\nstream` / `\rstream` / `>>stream`），再提取字典内容。

```rust
// 文件: rust/src/structure/rejection.rs (修复 check_pdf_signature: 要求同窗口共现且检查 /Sig 词边界)
fn has_pdf_name_token(haystack: &[u8], token: &[u8]) -> bool {
    haystack.windows(token.len() + 1).any(|w| {
        &w[..token.len()] == token
            && matches!(
                w[token.len()],
                b' ' | b'\t' | b'\r' | b'\n' | 0x0C | b'/' | b'[' | b']' | b'<' | b'>' | b'(' | b')'
            )
    })
}
// 在 check_pdf_signature 循环内 (同一 64KiB + 1KiB overlap 窗口内共现):
let window_has_byterange = has_pdf_name_token(&window, b"/ByteRange");
let window_has_sig = has_pdf_name_token(&window, b"/Sig");
if window_has_byterange && window_has_sig {
    reader.seek(SeekFrom::Start(start_pos))?;
    return Ok(Some(
        "PDF document contains a cryptographic digital signature. Modifying it will invalidate the signature.".into(),
    ));
}
```

```rust
// 文件: rust/src/structure/adapters/pdf.rs (第 161-168 行修复: 基于 ">>" 与行边界截断 XRef 流字典)
    let text = String::from_utf8_lossy(&buf);
    let dict_text = text
        .find(">>")
        .map(|idx| &text[..idx + 2])
        .unwrap_or_else(|| text.split("\nstream").next().unwrap_or(&text));
    if !dict_text.contains("/XRef") {
        return None;
    }
```

---

### Issue #18 [P2 | 健壮性 / 线程调度与状态不一致] Tauri GUI 后端 `diag.rs` 命令未接入受控线程池与取消机制，且 `ScanView` / `smart_extract` 加密状态判定失真

- **问题类别**：健壮性、并发调度缺陷、数据状态不一致
- **严重等级**：**P2（高负载扫描阻塞 UI 渲染，且内容域加密状态显示错误）**
- **精确位置**：
  - `gui/src-tauri/src/commands/diag.rs:18-228` (`inspect_carrier_impl`, `verify_carrier_cmd`, `scan_carrier_cmd`)
  - `gui/src-tauri/src/commands/stego.rs:257, 335` (`extract_stego_file_cmd`, `smart_extract_impl`)
  - `gui/src/views/ScanView.tsx:26-51` (`toRow`)
- **根因深度剖析**：
  1. **绕过 `GuiState.pool` 与 `catch_unwind` (`diag.rs:36, 156, 188`)**：
     `GuiState` (`state.rs:27-32`) 专门创建了一个保留 1 个核心给 OS/WebView UI 的受控 Rayon 线程池 `state.pool`。`stego.rs`、`structure.rs` 和 `batch.rs` 中的所有命令都通过 `run_cancellable_task` 运行（具备 `CancelToken` 注册、`catch_unwind` Panic 隔离和 `state.pool` 绑定）。
     唯独 `diag.rs` 中的 `inspect_carrier_impl`、`verify_carrier_cmd` 和 `scan_carrier_cmd` 直接裸调 `tauri::async_runtime::spawn_blocking` 且**未使用 `state.pool.install(|| ...)`**！当其中触发 Rayon 并行计算时，会直接唤醒全局默认 Rayon 线程池（占满 100% CPU 核心），且无 `catch_unwind` 保护。
  2. **`is_encrypted` 在双域间的语义失真 (`commands/stego.rs:257, 335` & `ScanView.tsx:48`)**：
     - 在 `smart_extract_impl` (`commands/stego.rs:335`) 中，代码直接写死 `let is_encrypted = password.is_some();`。如果载体实际存的是**未加密的结构域信封**，但用户在 GUI 的密码框里填了密码，`smart_extract` 提取成功后会错误地报告 `is_encrypted: true`！反之，`SmartExtractOutcome` 应当从底层实际提取结果中携带真实的 `is_encrypted` 布尔值。
     - 在 `ScanView.tsx:48` 中，`encrypted: !!info.is_encrypted` 只读取了结构域的 `info.is_encrypted`。对于内容域隐写载体（`info.content_stego?.has_hidden_data == true`），`info.is_encrypted` 恒为 `false`，导致 `ScanView` 表格中「加密」列始终显示为「否」，即便该载体使用了 AES-256-GCM 加密！
- **可靠修复方案**：
  1. 在 `diag.rs` 的 `spawn_blocking` 闭包中通过 `let pool = Arc::clone(&state.pool); pool.install(|| ...)` 绑定受控线程池并加上 `catch_unwind`；
  2. 在 `facade::SmartExtractOutcome` 中增加 `pub is_encrypted: bool` 字段，从结构域 `ReadResult.is_encrypted` 或内容域 `password.is_some_and(|p| !p.is_empty())` 传递真实加密状态。


---

### Issue #19 [P3 | 无效冗余代码] `audio/mod.rs` 中的 `MAX_EMBED_ATTEMPTS (8)` 重试循环在过滤 `Move::None` 后成为不可达死代码

- **问题类别**：冗余代码、算法理解偏差
- **严重等级**：**P3（代码整洁度与维护性）**
- **精确位置**：`rust/src/stego/audio/mod.rs:114-143` (`embed_flac`) 与 `34-52` (`embed_wav`)
- **根因深度剖析**：
  在 `embed_wav` 与 `embed_flac` 中，保留了一个最多 8 次的重试循环：
  ```rust
  for attempt in 0..MAX_EMBED_ATTEMPTS {
      let mut carrier_view = flac::FlacCarrier::new(carrier, body_slots)?;
      match core::embed(&mut carrier_view, &raw_frame, &seed, V2_STC_H) {
          Ok(bits) => { ... break; }
          Err(StrHideError::TrellisInfeasible) if attempt + 1 < MAX_EMBED_ATTEMPTS => {
              envelope::reseed_frame(&mut raw_frame)?;
          }
          Err(e) => return Err(e),
      }
  }
  ```
  这段代码存在两层逻辑问题：
  1. **触发条件已永不可达**：在 S1 修复后，WAV 和 FLAC 在抽取候选槽位前均已过滤掉所有 `Move::None`（不可移动槽位），进入 STC 的所有槽位均为有效槽位且每组大小 $u \ge 3$，在 $h \in [7, 10]$ 下奇偶校验矩阵满秩，因此 `TrellisInfeasible` 在数学上已不可能发生。
  2. **重试手段在数学上无效**：即使某个载体因为过多槽位代价为 $+\infty$ 而导致 STC 网格状态无法到达目标伴随式（Syndrome），`envelope::reseed_frame(&mut raw_frame)` 仅仅改变了帧头中的随机 `salt`（从而改变消息比特序列），**完全没有改变载体槽位的代价分布或 `FlacCarrier::new` 的抽样种子 `PERM_SEED`**（注意 `FlacCarrier::new` 使用的是固定常量 `PERM_SEED`，每次重试抽出的槽位完全相同）！
- **可靠修复方案**：
  直接移除 `MAX_EMBED_ATTEMPTS` 循环，单次调用 `FlacCarrier::with_analysis` 与 `core::embed`，使音频嵌入控制流清晰直接。

---

### Issue #20 [P3 | 低效代码] `embed_png_with_stats` 重复遍历两次 `plan.candidates` 统计已算过的 `pool_green` 与 `pool_rgb`

- **问题类别**：低效代码
- **严重等级**：**P3（轻微 CPU 冗余遍历）**
- **精确位置**：`rust/src/stego/png/engine.rs:1321-1410`
- **根因深度剖析**：
  在 `embed_png_with_stats` (`png/engine.rs:1321-1327`) 中：
  ```rust
  let cap_info = build_png_capacity_info(
      &plan,
      raw.width as usize * raw.height as usize,
      options.safety.level,
      dialect,
  );
  ```
  `build_png_capacity_info` (`png/engine.rs:1244-1245`) 内部已经调用了：
  ```rust
  let pool_green = plan.count_body_slots(PngChannelLayout::GreenOnly);
  let pool_rgb = plan.count_body_slots(PngChannelLayout::Rgb);
  ```
  每次 `count_body_slots` 都会遍历整个 `plan.candidates` 数组（对于 24 MP RGB 图像，长度为 $7.2 \times 10^7$ 个元素）。然而仅仅 70 行之后，在 `embed_png_with_stats` 的第 1397 和 1409 行：
  ```rust
  let avail_g = plan.count_body_slots(PngChannelLayout::GreenOnly);
  ...
  let avail_rgb = plan.count_body_slots(PngChannelLayout::Rgb);
  ```
  又把这几千万个候选槽位重复遍历了两遍！
- **可靠修复方案**：
  让 `build_png_capacity_info` 返回 `(StegoCapacityInfo, usize, usize)`（即同时返回 `(cap_info, pool_green, pool_rgb)`），在 `embed_png_with_stats` 中直接解构复用。

---

### Issue #21 [P3 | 算法健壮性] `cost_calibration.rs` 中 `enforce_monotonic_anchors` 裁剪后未复核总跨度 `MIN_CALIBRATION_SPAN`

- **问题类别**：算法健壮性
- **严重等级**：**P3（极端退化分布下的防御性完备度）**
- **精确位置**：`rust/src/stego/cost_calibration.rs:136-184`
- **根因深度剖析**：
  在 `calibrate_costs_inplace` (`cost_calibration.rs:163-173`) 中：
  ```rust
  if (raw_max - raw_min) < MIN_CALIBRATION_SPAN {
      return CalibrationStats::skipped_flat(finite_vals.len(), raw_min, raw_max);
  }
  let mut anchor_x = [0.0f64; NUM_ANCHORS];
  for (i, &q) in ANCHOR_QUANTILES.iter().enumerate() {
      anchor_x[i] = interpolate_sorted_quantile(&finite_vals, q);
  }
  enforce_monotonic_anchors(&mut anchor_x, raw_min, raw_max);
  ```
  虽然在裁剪前检查了 `raw_max - raw_min >= MIN_CALIBRATION_SPAN (1e-6)`，但在 `enforce_monotonic_anchors` (`lines 252-270`) 中，前向递增推挤（每个节点 $+10^{-9}$）后再以 `raw_max` 进行反向截断（`anchors[i] = anchors[i].min(anchors[i + 1])`）。当 `raw_max - raw_min` 非常接近 `1e-6` 且高分位点聚集在 `raw_max` 时，反向截断会使末端多个相邻锚点完全相等（`x1 == x0`）。虽然 `piecewise_linear_map` 中有 `if (x1 - x0).abs() < 1e-12 { return y0; }` 保护不会产生 `NaN`，但会导致末端区间的代价排序分辨率完全丧失（被压平为同一个常数 `y0`）。
- **可靠修复方案**：
  在 `enforce_monotonic_anchors` 反向修正时保持严格递减步长 `anchors[i] = anchors[i].min(anchors[i + 1] - EPS)`，若空间不足以容纳 `NUM_ANCHORS * EPS` 则回退为线性映射。

---

### Issue #22 [P3 | 前端功能闭环缺失] Tauri GUI 后端已实现的 6 个核心命令未在前端暴露，且 `ScanView` 缺少盲分析与密码输入

- **问题类别**：功能闭环缺失、前后端集成不完整
- **严重等级**：**P3（功能完备性与用户体验）**
- **精确位置**：
  - `gui/src-tauri/src/lib.rs:19-37` vs `gui/src/api/commands.ts:1-132`
  - `gui/src/views/ScanView.tsx:1-191`
- **根因深度剖析**：
  通过在 `gui/` 目录检索 Tauri IPC 命令绑定发现，`gui/src-tauri/src/lib.rs` 注册的 14 个后端命令中，有 **6 个完整实现的命令在前端 `gui/src/api/commands.ts` 中完全未定义、未被任何视图调用**：
  1. `scan_carrier_cmd`（盲隐写统计分析：RS / SPA / WS / Chi-Square / Fridrich JPEG 校准 / 尾部高熵扫描 / 已知工具签名检测）；
  2. `verify_carrier_cmd`（双域容器结构与隐写载荷 SHA-256 完整性校验）；
  3. `restore_structure_file_cmd`（结构域 100% 比特级无损剥离与还原）；
  4. `run_batch_job_cmd`（Rust 端多线程并发批处理引擎 `run_batch`）；
  5. `read_structure_file_cmd` 与 `extract_stego_file_cmd`（前端统一使用了 `smart_extract_cmd`）。
  尤其值得注意的是：前端的 `ScanView.tsx`（导航栏「检测 / Scan」标签页）只调用了 `inspectCarrier`（只能识别 `strhide` 自身未盲化的信封头），既没有调用 `scan_carrier_cmd` 展示风险评分（`risk_score`）与检测器指标（`DetectorMetric`），也没有提供 `PasswordRow` 密码输入框（导致所有 `--stealth` 结构隐写载体和设置了自定义密码的内容隐写载体在 `ScanView` 中一律显示为「未发现隐藏内容」）。
- **可靠修复方案**：
  1. 在 `gui/src/api/commands.ts` 中补全 `scanCarrier`、`verifyCarrier`、`restoreStructureFile`、`runBatchJob` 四个 IPC 封装函数；
  2. 在 `ScanView.tsx` 中增加可选的 `PasswordRow`（使 `inspectCarrier(item.path, password || undefined)` 能检测加密内容域与 Stealth 结构域载体），并集成 `scanCarrier` 盲分析结果展示与一键「无损还原 (`restoreStructureFile`)」操作按钮。


---

## 四、分阶段修复路线图与工程演进建议 (Remediation Roadmap)

为确保修复过程安全可控、零回归，建议按以下四个阶段推进代码整改：

### 第一阶段：P0 阻断性 Bug 与容器完整性修复（预计耗时：0.5 天）

1. **修复流式解密分块上限 (`rust/src/core/crypto.rs:472`)**：将 `MAX_CHUNK_SIZE` 修正为 `MAX_CHUNK_SIZE + AEAD_TAG_LEN`，并新增 `chunk_size = MAX_CHUNK_SIZE` 的往返加密解密单元测试。
2. **修复 FLAC 容量规划与前置门控 (`rust/src/stego/audio/mod.rs:85, 98, 207`)**：移除 `embed_flac` 中对 `analysis.usable` 的重复 `- V2_TOTAL_HEADER_SLOTS` 扣减，补齐 `analysis.tails < V2_TOTAL_HEADER_SLOTS` 与 `probe_flac` 的 `bits_per_sample > 24` 校验。
3. **修复 MKV 嵌套 CRC-32 与未知长度 Cluster (`rust/src/stego/hevc/mkv_boxes.rs`)**：在 `refresh_crcs` 中按 `covers.len()` 升序自内向外计算 CRC，补齐 `ID_BLOCK_GROUP` 内的 `ID_CRC32` 解析，并在 `ID_CLUSTER` 未知大小模式下遇到下一个 Level-1 元素时正确截断。

### 第二阶段：P1 隐私安全、算法统计准确性与核心性能去重（预计耗时：1~1.5 天）

1. **GUI 诊断日志明文脱敏 (`gui/src-tauri/src/commands/stego.rs`, `structure.rs`)**：移除日志 `data` 负载中的 `text_preview` 明文字段，改为布尔标记 `has_text_preview`。
2. **消除 FLAC 3~7 倍重复全文件解码 (`rust/src/stego/audio/flac/mod.rs`, `audio/mod.rs`)**：引入 `FlacCarrier::metadata_only` 与 `FlacCarrier::with_analysis`，删除 `refresh_checksums` 末尾的冗余 `analyse(&out)` 与 `embed_flac` 中的冗余 `max_sample_drift`。
3. **消除 GUI 提取与嵌入的双倍 I/O 解码 (`gui/src/views/ExtractView.tsx`, `StegoEmbedView.tsx`)**：在 `smart_extract_cmd` 后端单次完成文件落盘，移除 `StegoEmbedView.tsx` 中基于未压缩大小的预拦截和冗余前置 `probeStegoCapacity` 调用。
4. **修正 FLAC 补偿统计与音频安全告警 (`flac/mod.rs:669`, `stego/io.rs:169`, `cli/cmd_stego.rs:306`)**：将非零补偿脉冲计入修改统计，并在音频安全告警中使用 `cap_ref.safety_bpp_limit`。

### 第三阶段：P2 算法加速、内存瘦身与解析器加固（预计耗时：1.5~2 天）

1. **PNG `HILL` 与 `S-UNIWARD` 并行化与内存减半 (`png/cost/hill.rs`, `suniward.rs`)**：将 `HILL` Stage 2 改为行列可分离 Rayon 并行滑动窗口，及时释放中间平面，将峰值内存从 48 B/px 降至 16 B/px。
2. **JPEG `embed` 容量直出与 MKV 快速探测/补丁写回 (`jpeg/engine.rs`, `hevc/engine.rs`, `stego/io.rs`)**：让 `JpegEngine::embed` 直接返回 `StegoCapacityInfo`，为 MKV 开启 20% 采样探测与 `commit_carrier_patches` 局部写回，并在 `embed_carrier_file` 入口补齐 `options.tuning.applicable_to(carrier_format)?`。
3. **盲隐写分析统计池化与 PDF 边界加固 (`analysis.rs`, `calibration.rs`, `rejection.rs`, `pdf.rs`)**：跨分块累加 RS/SPA/WS 充分统计量后再求解，修复 PDF `/Sig` 词边界与 XRef 流 `>>` 截断逻辑。

### 第四阶段：P3 桌面端功能闭环与代码清理（预计耗时：1 天）

1. **打通 GUI 剩余 6 个后端命令 (`gui/src/api/commands.ts`, `ScanView.tsx`)**：在 `ScanView` 中加入密码输入框、盲隐写分析报告展示卡片、完整性校验与一键无损还原按钮，并将 `diag.rs` 命令统一接入 `run_cancellable_task` 与 `GuiState.pool`。
2. **清理死代码与冗余扫描 (`audio/mod.rs`, `png/engine.rs`, `cost_calibration.rs`)**：移除音频嵌入中不可达的 `MAX_EMBED_ATTEMPTS` 循环，复用 `build_png_capacity_info` 的槽位计数结果。
