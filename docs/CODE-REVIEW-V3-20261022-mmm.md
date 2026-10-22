# V3 分支代码审查报告（stego-v3-dev）

> 审查对象：分支 `stego-v3-dev` 相对 `master` 的全部改动（16 个提交，+6574 / −1287 行）
> 审查时间：2026-10-22
> 审查重点：JPEG V3（STC 三元码 + 44 字节超块 + 固定几何槽位网格）、空间域 PNG 头改造、标定检测器再校准、CLI 参数变更
> 方法：读代码 + 跑测试 + 实测（`cargo test --all-targets` 全绿；`batch_stego --ignored` 19/19；24 MP 载体内存/耗时实测；用仓库自带的 7 模型 CUDA 神经评侧栈做 A/B）

---

## What this change does:

V3 把 JPEG 隐写从"按代价挑候选槽位 + Hamming/可选 STC"改成"**全图 AC 位置的固定几何网格**"：槽位集合只由块数和密钥决定，不再看系数值，因此提取端不需要代价图、不需要重排序；写入改成**真三元 `±1`**（`0 ↔ ±1` 也允许），头部换成 **44 字节超块**（版本/盐/nonce/长度/套件 id/`h`/`u`/扩展长度），超块与扩展区作为 AEAD 的 AAD；组宽 `u` 由 `--slot-budget`（默认 1,200,000）按载荷大小自动推导（1..64），并写进超块，提取端只信超块。同时空间域 PNG 的头部改成"32 字节头 + 32 字节 FeatureWord"整体做 AAD，v1 回退被删除；标定检测器把 `(0,1)` 配对纳入统计、阈值从 0.09 降到 0.05。

**假定的负载**：单个用户把照片当载体（PNG/JPEG），偶尔批量跑；一个进程一次处理一个载体；典型载体 2.4 MP（1920×1280），上限到 24 MP（6000×4000）；载荷从几十字节到满容量（3.4 MB）；提取端要能扛"错误口令"和"不是本工具写的文件"两种输入。

---

## Must fix

### 1. 满容量嵌入的内存随载荷线性暴涨，24 MP 载体实测峰值 2.0 GB

- **是什么**：`coding/stc.rs:386` 的回溯位图按"槽位数 × 状态数 / 4 字节"分配。`u = 1` 时槽位数 ≈ 载荷比特数，于是**每 1 字节载荷要吃约 256 字节内存**。`--slot-budget` 只能把 `u` 往下压，压不动 `u = 1` 这条底线。
- **问题**（实测，`temp/teststego/pexels-nguy-n-nguyen-689620639-18533460.jpg`，24 MP / 27,965,206 槽）：
  - 3.4 MB 载荷（满容量 98%）→ 峰值常驻内存 **2046 MB**，耗时 10.1 s；
  - 69 KB 载荷（推荐档位）→ 峰值 **800 MB**（其中代价图 28.4 M × f64 = 227 MB，三份槽位表 3 × 112 MB）。
  - `params.rs:305-312` 写的是 `slot_budget * 2^h / 4` 字节，但这只在预算真正生效（即 `u > 1`）时才成立；`u = 1` 时是 `载荷字节数 × 256`。批量脚本 8 线程并发跑满容量时是 8 × 2 GB。
- **修法**（最小改动）：在 `embed_once` 算出 `body_n` 之后，用 `body_n * 2^h / 4` 估出位图字节数，超过阈值（比如 512 MB）就返回一条可执行的错误（"载荷过大，trellis 需要约 X MB；请减小载荷或换更大的载体"），而不是让进程被 OOM 杀掉；或者让 `h` 随载荷下调（`h` 在超块里，可以逐载体变），`h=8→4` 时位图降到 1/16。
- **不修的后果**：用户在自己电脑上嵌入一张 24 MP 原片就可能把进程推到 2 GB；CI/服务器上批量跑会被 OOM killer 直接杀掉，错误信息是"内存不足"这种没法自查的。

### 2. 真实照片上，V3 在 128 KB–2 MB 载荷带大面积失败，而且错误信息甩锅给用户的文件

- **是什么**：V3 的三元写回会**造出新的系数**（`0 → ±1`），这些新系数需要 cover 自己那张 Huffman 表里**没有定义**的 `(run, category)` 符号。`jpeg/engine.rs:203-208` 只对"不跨零"的方向做符号检查，跨零方向按 wet cost 计价放行（`:228-241`）→ 写回后重放符号序列（`:545-552`）发现缺符号 → 换盐重试 ≤ 3 次 → 仍然失败 → 报 `dht.rs:298` 那句"请用标准 Annex K 表重新保存载体"。
- **问题**（实测）：
  - **语料有偏**：`temp/images/jpg` 那 81 张相机照片 **100% 是完整表**（162/162，走快速路径，完全不触发这条路径）；而 `temp/teststego` 的 13 张 JPEG 里 **8 张是过度优化表**（62–67/162，Pexels / DSC 这类图都被 web 优化器重编过），`temp/testfiles` 2/4，`temp/real_samples` 1/2。README 和 phase3 报告里所有实测表都建在"全是完整表"的相机语料上。
  - **在这 8 张过度优化表载体上**：64 KB 载荷失败 3 张（38%），128 KB 载荷失败 5 张（63%）。
  - **24 MP 的 `pexels-nguy`（推荐档位 355 KB 正好在这个带里）**：64 KB OK、128/256/355/512/1024/2048 KB **全部失败**、3.4 MB 又 OK；355 KB 连试 15 次失败 14 次。
  - **同一张图，V2（`temp/strhide_baseline.exe`）64 KB 和 100 KB 都成功**——V2 从不造新系数，所以不会缺符号；V2 在这张图上的上限是 114 KB（报"capacity exceeded"）。也就是说：**V3 新增的那段容量，恰好就是 V3 开始报错的那一段**，而报错说的是"你的文件有问题"。
  - 唯一的实际出路是"重存成 Annex K 表"，那会掉画质、丢 EXIF；V2 在同样载荷下报的是"容量不够"（清晰、可预期）。
- **修法**（最小，且仓库里已经有零件）：在 `plan_slots` 里给**跨零方向**补一次符号检查——`0 → ±1` 会让**下一个**系数的零游程减 1，`1 → 0` 会让它加 1，检查那个**新**符号在不在表里；不在就关掉这个方向。`dht::zero_runs` + 现有 `direction_encodable` 够用，`dht::symbol_for_value`（目前是死代码）正是干这个的形状。改完就造不出缺符号的结构，重放永远不会失败。次选：至少把错误信息改成"V3 会在稀疏块里新建系数，而这张图的 Huffman 表没有对应符号"，并给出"降到 X KB 以下可嵌"的具体建议。
- **不修的后果**：真实用户拿一张普通网络照片（大概率被优化过）按推荐档位嵌入，拿到一个"你的文件坏了"式的拒绝，而且没有降级路径；同时所有语料回归都测不到这条路径（相机语料 100% 走快速路径，`batch_stego.rs:409` 又把这种错误降级成 note 跳过检测断言）。

---

## Should fix

### 3. 组宽 `u` 被绝对预算钉死：同一个 bpp，载体越大越容易被检测（已实测）

- **是什么**：`jpeg/v3_layout.rs:105-106` 的 `u = min(u_capacity, u_budget, 64)`，其中 `u_budget = slot_budget / (bits + h - 1)`。`slot_budget` 是**绝对值**，载荷随图像尺寸增长，所以窗口一大预算先耗尽，`u` 被压回 1。
- **问题**（同一批载体、同一份载荷，只改 `--slot-budget`；1920×1280 × 12 张，16 KiB 载荷）：

  | 变体 | `u` | 改动系数 | 改动/比特 | 体积增幅 | 7 模型 DL 均值 | DL 中位 | DL ≥0.5 | `strhide scan` 风险均值 |
  | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
  | 默认预算 1.2 M | 9 | 34,649–39,994 | 0.264–0.305 | +0.00%…+5.43%（12 张里 10 张 < +0.5%） | **0.456** | 0.41 | **5/12** | 20.8 |
  | `--slot-budget 8` | 1 | 65,567–65,989 | 0.500–0.503 | **+2.50%…+45.03%** | **0.748** | 0.82 | **9/12** | 31.2 |
  | 干净载体 | - | - | - | - | 0.276 | - | - | 20.8 |

  - 同样的图、同样的载荷、同样的密码，**只因为 `u` 从 9 掉到 1，神经网络检出率从 42% 变成 75%**，相对干净载体的 DL 概率增量从 +0.179 变成 +0.471（0002.jpg 从 0.00 变 1.00，0006.jpg 从 0.18 变 0.95）。改动系数多了 1.9 倍，体积增幅从"几乎不变"变成 +45%。
  - 而 24 MP 载体在**推荐档位**上默认就被预算钉成 `u = 1`（载荷 355,102 字节 → 窗口 2,840,991 → 预算只剩 0 → clamp 成 1），也就是"推荐安全档位"在大图上实际跑的是上表最右那一列。
  - 复现：`temp/eval_u_effect.py`（DL A/B）+ `temp/u_effect_rs/`（改动系数计数）。
- **修法**：`u` 应该由**槽位/比特比**决定（跟空间域 `coding.rs:112 auto_select_codec` 一样按比值选 `u`），`slot_budget` 只当硬内存上限；或者让预算随载荷等比放大（现在是固定 1.2 M）。改之前，README 那张实测表要补一行"24 MP 载体"。
- **不修的后果**："推荐档位"这个承诺在大图上不成立，而大图恰恰是最需要藏东西的场景；用户按推荐值嵌完，被检出的概率高出一大截。

### 4. 提取端把"确实是我们的载体、但用了不支持的压缩算法"降级成"没有隐藏数据"

- **是什么**：`jpeg/engine.rs:744-753`，`unpack_envelope_parts` 的错误只对 `CorruptedData` 特判返回，`UnsupportedVersion` 落进 `Err(_) => continue`，试完所有套件后统一报 `NoHiddenData`。
- **问题**：走到这一步时 **AEAD 已经通过**，载体百分之百是本工具写的（代码注释自己写明了）。此时 `UnsupportedVersion("Envelope uses unsupported compression algorithm N")` 是一条**可执行**的诊断，却被吞掉，用户只看到"没有找到隐藏数据"，会以为是自己密码错了或文件被清洗了。
- **修法**：`Err(StrHideError::UnsupportedVersion(m)) => return Err(StrHideError::UnsupportedVersion(m))`（两行）。
- **不修的后果**：格式向前兼容（以后换压缩算法）时，老版本给出的是误导性错误，排查成本很高。

### 5. 标定检测阈值下调 + 纳入 `(0,1)` 配对，但唯一的相关测试在 CI 里是空跑

- **是什么**：`analysis/calibration.rs:248-256` 把配对统计从 `|c| >= 2` 扩到 `(0,1)`，`analysis.rs:63` 把阈值从 0.09 降到 0.05。检测器对**所有用户的 `scan` 输出**生效，不只是 V3 载体。
- **问题**：唯一断言"干净 JPEG 不被标记"的测试 `test_jpeg_calibration_detector_clean_vs_loaded`（`tests/test_lifecycle/stego.rs:856-866`）这次被从内置 fixture 换成了语料文件 `temp/images/jpg/0003.jpg`，找不到语料就 `return`——**CI 里没有 `temp/`，所以这个测试在 CI 上等于没跑**。而被换掉的那个内置 fixture 恰恰是"合成渐变图、量化表让参考被 IDCT 舍入主导"这种**非相机照片**，正是新统计量最可能误报的一类。80 张相机照片上零误报，不能外推到图形/截图/重压缩的 JPEG。
- **修法**：把 fixture 版测试加回来（断言干净 fixture 的 `dct:calibration` 分数低于 0.05），或者让语料缺失时在 CI 里 `panic` 而不是 `return`；再补一个"非相机来源的干净 JPEG"样本。
- **不修的后果**：`scan` 的误报率变化没有回归护栏，阈值/统计量的下一次调整会直接打到用户脸上。

### 6. PNG 的 v1 头回退被删掉，但 CHANGES / README 都没记

- **是什么**：`spatial/engine.rs:818-823`，提取端现在要求 `raw_stc_h == 15`（v2 逃逸标记），否则一律 `NoHiddenData`；旧版写的 v1 头 PNG 载体（`h = 8`）读不出来了。
- **问题**：`docs/CHANGES-20261021.md` 的 V3 条目第 6 点列了一串删除项（`dct_move` 桶语义、`embed_dct_lsb`、JPEG 的 512 槽头分支、`min_abs_coeff`…），**唯独没写"PNG 的 v1 回退"**。README 也只声明了结构域 UBE 的兼容情况，没提内容域 PNG 载体。
- **修法**：在 CHANGES 的 V3 条目里补一句"PNG 内容域 v1 头载体不再可读（项目未发布，不做兼容）"，README 的兼容矩阵加一行。
- **不修的后果**：已经用 0.3.x 嵌过 PNG 载荷的用户升级后数据"凭空消失"，而 changelog 里查不到原因。（按 `AGENTS.md`，不兼容本身是被允许的决策；这里缺的是**记录**。）

### 7. 两个新 CLI 参数没有 i18n 条目，中文界面里是英文

- **是什么**：`cli.rs:381-397` 新增 `--slot-budget`、`--cipher-suite`，但 `cli_i18n.rs:92-105` 的参数映射表里没有这两个 id，`messages.rs` 里也没有对应消息。`localize()` 找不到映射就保留 clap 原文。
- **问题**：`strhide embed --help`（中文）里，这两个 V3 的主力参数是**唯一**两个没有中文说明的选项，而它们恰恰是本次 V3 唯一新增的用户可见开关。
- **修法**：`messages.rs` 加 `HelpEmbedSlotBudget` / `HelpEmbedCipherSuite`（中英各一条），`cli_i18n.rs` 加两行映射。
- **不修的后果**：中文用户看不懂这两个参数的含义与影响（预算越大越慢越耗内存、套件 2 更慢更强），只能去翻英文文档。

---

## Nice to have

### 8. `--codec` / `--stc-u` 对 JPEG 被静默忽略

- **是什么**：`cli.rs:1898-1941` 的 `apply_codec_options` 只把 `codec` / `stc_u` 写进 `spatial_params`，JPEG 侧只取 `stc_h`。
- **问题**：`strhide embed cover.jpg --codec hamming` 会被接受，然后**默默**用三元 STC。`cli.rs:412-418` 的 clap 帮助还写着"PNG and JPEG alike"（虽然实际显示的是 i18n 那份"PNG payload bits"，但两份文案互相矛盾，clap 那份已成死文案）。
- **修法**：载体嗅探出是 JPEG 且用户显式传了 `--codec`/`--stc-u` 时打一行 stderr 提示"JPEG V3 固定使用三元 STC，该参数已忽略"；顺手把 `cli.rs` 里那两段过时的 help 文本删掉（i18n 表已覆盖）。
- **不修的后果**：用户以为自己换了编码层，实际没有。

### 9. 稀疏 Huffman 表路径上，每个槽位都重算一次整块的零游程

- **是什么**：`jpeg/engine.rs:196-201`，`plan_slots` 用 `last_block != bi` 缓存 `zero_runs`，但槽位顺序是随机置换的，相邻槽位几乎总在不同块 → 缓存基本不命中。
- **问题**：`dht::zero_runs` 每次 63 次迭代，1.19 M 槽位（4 KiB 载荷 / 1920×1280）就是 7500 万次重复计算，只在"表不完整"的载体上触发（真实世界里占相当比例，见 Must fix 2）。
- **修法**：用 `Vec<Option<[u8;64]>>` 按块号缓存一次（38 K 块 × 64 B = 2.4 MB），每块只算一遍。
- **不修的后果**：稀疏表载体上嵌入慢一截；功能无碍。

### 10. 一批死代码和过时文案

- **是什么**（都在本次改动范围内新增或遗留，且已无生产调用方）：
  - `stego/jpeg/dht.rs:237` `symbol_for_value` 与 `:194` `zero_run_before`：只有自己的单测在用（`zero_run_before` 只被 `symbol_for_value` 调用）；
  - `stego/jpeg/dht.rs:92` `AcSymbolSet::is_empty`：无调用方；
  - `stego/coding.rs:90,101` `RECOMMENDED_CAPACITY_SLOT_RATIO` / `recommended_payload_bytes`：无调用方（空间域探测自己算）；
  - `stego/params.rs:383` `JpegParams::slot_budget_is_narrow`：无调用方，注释写着"调用方决定是否打印"；
  - `stego/jpeg/header_v3.rs:43` `CODEC_HAMMING`：解码端接受 `codec_id = 1`，但提取端紧接着 `if superblock.codec_id != CODEC_TERNARY_STC { continue; }` 把它全部拒掉；
  - `i18n/messages.rs:539-541` `HelpStegoMinAbsCoeff` + `cli_i18n.rs:100` 的映射：`--min-abs-coeff` 这个开关已被删除。
- **问题**：留着的代价是"看起来还能用"的假象；`CODEC_HAMMING` 尤其危险——它让人以为 JPEG 端支持 Hamming。反过来说，`symbol_for_value` 恰好是 Must fix 2 需要的形状（只是没人用）。
- **修法**：删掉（`symbol_for_value` 要么删，要么按 Must fix 2 改造成真正在用的检查）。
- **不修的后果**：读者会照着注释去找不存在的功能。

### 11. 注释 / 文档与代码不一致

- **是什么**：
  - `analysis/calibration.rs:236-238` 的块注释仍写"LSB replacement moves counts inside an even/odd magnitude pair（`|c| >= 2`）"，而代码已经从 `value = 2` 改成 `value = 0`（纳入 `(0,1)`）——紧跟其后的行内注释说的才是新的行为；
  - `docs/api/WIRE_SPEC.md` §13.3 写 `body_stc_seed = HKDF(perm_seed, salt, info = "stc-trellis" ‖ domain)`，但 `format.rs:455` 的 `stc_seed` 根本不收 `domain`（域隔离是通过 `perm_seed` 间接实现的，隔离效果一样，公式不准）；
  - `i18n/messages.rs:699-701` 的容量输出写 "Payload slots: {val} **bits**"，而 `available_slots` 是**槽位数**（JPEG V3 下 = 网格 − 头部槽位，24 MP 载体上是 27,965,206 个槽位，不是比特）。
- **问题**：文档是这条分支的主要交付物（`WIRE_SPEC.md` 整章重写、README 整节重写），公式对不上会让后来的实现者照着错的公式写代码。
- **修法**：三处各改一行文字。
- **不修的后果**：读者按 WIRE_SPEC 实现私有格式时，算出来的 trellis 种子和本实现不一致（虽然域隔离仍然成立）。

### 12. 容量输出里的单位是错的（槽位写成了比特）

- **是什么**：`strhide embed --capacity` 输出 `Payload slots: 2418454 bits`，实际是槽位数。
- **问题**：V3 之后这个数字的量纲彻底变了（以前是"候选槽位"，现在是"整张图的 AC 位置数减去头部"），比特/槽位之比正是 `u` 的来源，写错单位会让人以为容量少了 8 倍。
- **修法**：`messages.rs:700-701` 把 "bits/比特" 改成 "slots/个槽位"。
- **不修的后果**：读 `--capacity` 输出的人会算错可用容量。

---

## Verdict

**先修 1（内存）和 2（真实照片的失败带）再发布。** 其余是"用户会困惑"级别的小修。

V3 的核心设计（几何槽位网格 + 真三元写回 + 超块做 AAD + `u` 写进超块）我逐行核对过，两端一致性没问题：`cover_digest` 只吃 DC 系数（DC 全程不写）、`body_grid` 用 bool 位图按升序构造（没有 `HashSet` 的跨进程顺序坑）、STC 内核的 `u > 1` 状态机（多一个"组内累积行"状态位）和回溯反演我按公式重推了一遍，`h`/`u`/槽位数在嵌入端和提取端对得上。测试也是实的：`cargo test --all-targets` 全绿，`batch_stego --ignored` 19/19 通过，20 图 × 4/16/64 KiB 矩阵门禁存在（`#[ignore]`）。

问题不在**正确性**，在**规模**和**语料代表性**：

1. trellis 的内存和 `u` 都随"绝对槽位数"走，而载荷随图像尺寸走 → 大图上同时踩到 2 GB 内存和 `u` 被压回 1；
2. 全部实测都建在"100% 完整 Huffman 表"的相机语料上，而真实照片里过度优化表占相当比例，V3 的三元写回在那里会撞上 63–93% 的失败带（Must fix 2）；
3. `u` 这个被实测证明的决定性参数（`u=9` → DL 检出 42%，`u=1` → 75%），却被一个绝对预算间接决定，用户没有任何手段在推荐档位上把它调高。

---

## Lean: -55 lines possible

删死代码即可（`symbol_for_value` + `zero_run_before` + `AcSymbolSet::is_empty` + `recommended_payload_bytes` + `RECOMMENDED_CAPACITY_SLOT_RATIO` + `slot_budget_is_narrow` + `CODEC_HAMMING` + `HelpStegoMinAbsCoeff` 及其映射 + 两段过时的 clap help 文本）。

---

## Not checked

- **DCTR-8000**：仓库里确实没有。`temp/github/` 是 40+ 个第三方隐写/隐写分析仓库的**源码参考**（Adversarial-Embedding、pySTC、Deep-Steganalysis、steganalysis-detector…），不是可跑的评测工具。
- **神经评侧栈已可用并已使用**：`scripts/stego_eval/`（4 个 JPEG 频域模型 + 3 个空域模型，EfficientNet-B0 ×5 + SRNet ×2，权重在 `scripts/stego_eval/models/*.pt`；CUDA 推理通过 `F:\ai\torch\venv` 的透明桥接，`.venv` 里没有 torch）。Should fix 3 的 A/B（12 张 1920×1280 × 16 KiB，`temp/eval_u_effect.py` + `temp/u_effect_rs/`）就是用它测的；改动系数与体积增幅用 `temp/u_effect_rs` 数。
- **仍未核查**：SRNet / Aletheia 权重的来源与许可（只用于评测，不进产品）；`dct-io` 内部的 ZRL/EOB 约定（我是按 `dht::first_missing_symbol` 的镜像实现反推的，若约定不同，稀疏表路径会误报"过度优化 Huffman 表"而不是坏文件——这也意味着 Must fix 2 的修复要在 dct-io 侧复核一次）；跨进程/跨平台字节级一致性（契约测试有，没在第二个进程上跑过同一批载体）；`scripts/stego_eval` 评分栈里是否另有硬编码阈值（本次只改了 `analysis/calibration.rs` 一处）。
