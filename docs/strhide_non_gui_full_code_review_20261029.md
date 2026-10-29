# strhide 非 GUI 代码全面审查报告

- **审查日期**：2026-10-29 08:34（本机时间）
- **审查范围**：`strhide/rust/` 全部非 GUI 代码（不含 `gui/` 目录）
  - `rust/src` — 89 个 `.rs` 文件，**53 524 行**
  - `rust/tests` — **22 862 行**
  - `rust/examples` — **3 456 行**
- **审查维度**：代码质量、算法逻辑、业务逻辑、性能与内存、安全与健壮性
- **代码基线**：git `8042ba2`，工作区干净
- **质量门禁实测**：`cargo fmt --check` 通过 / `cargo clippy --all-targets --all-features -- -D warnings` **0 警告** / `cargo test --all-features --all-targets` **759 通过、0 失败**（21 个 `local_` 语料测试被 ignored）

> **方法与可信度说明**
> 本报告所有条目均来自对源码的逐段通读，**已在源码中定位到具体行**。凡涉及"攻击者能否利用""触发概率多高"等需要运行验证的结论，均标注为**待确认**，未做实测的部分不会写成既成事实。为避免误报，报告末尾单列一节"已核实为无问题的重点项"。

---

## 一、总体评价

strhide 的**工程质量明显高于同类开源隐写项目**：双域（structure 容器 / content 隐写）分层清晰、`facade` 单一入口设计合理、UBE 信封协议有明确的线格式常量与自校验（写入后反向 locate 自检）、还原路径有 SHA-256 兜底、feature 分层（默认不含 CLI）避免了依赖膨胀。`cargo clippy -D warnings` 零警告且 759 个测试全绿，说明团队对 lint 与回归有真实投入。

核心算法经逐行核对**未发现破坏往返（round-trip）的对称性缺陷**：STC 编解码、置换生成、PNG/JPEG/HEVC 三路的 embed↔extract 遍历顺序、代价图重算均一致。这是隐写库最容易出错的地方，能做到这一点说明主体设计是可靠的。

**主要风险集中在三条线上**：

1. **不可信输入的资源耗尽**（Bloker B1/B3）：`read` 路径的解压上限自引用、PNG 提取路径不校验 wire 超参——项目在 `verify` 路径做了 1 GiB 限制却在 `read` 路径漏掉，属"同一威胁两套标准"。
2. **PE codebits 的语义安全**（Blocker B2）：x86 指令等价替换不区分代码与数据，可能改写 `.text` 内的跳转表/内联常量。这是唯一一个"改完载体就废了"的高风险功能，而目前的过滤只有 `Code::INVALID` 一道。
3. **analysis（隐写分析）的统计有效性**（Major M20/M21）：卡方统计量未做样本量归一化、检测器无法运行时仍渲染成 PASS、"尾部高熵"对 ZIP/MP4/PDF 系统性误报。这些问题不会让程序崩溃，但会让"隐写分析"这一 headline 能力给出的结论不可信——对安全工具来说，误报与漏报同样是缺陷。

此外还有一类**系统性议题**：`engine.rs`（structure 2540 行 / PNG 3360 行 / HEVC 3193 行 / analysis 2366 行）构成四个"上帝文件"，以及若干常量在两处独立定义、注释与实现相悖的情况。这些是维护性的慢性成本，应在功能修复之外排期处理。

---

## 二、严重问题（Blocker）

### B1. `structure` 域 `read` 路径解压上限自引用 —— 解压炸弹 OOM

**位置**：`rust/src/structure/engine.rs:1557-1563`（`read_core`）；对比 `engine.rs:1592-1611`（`verify_l3_stream`）

```rust
// read_core — limit 就是 raw_size 自己
let mut decomp = Vec::new();
decompress_stream(&mut Cursor::new(&decrypted_payload), &mut decomp, env.meta_obj.raw_size)?;

// verify_l3_stream — 反而有硬上限
crate::crypto::verify_payload_stream(..., crate::crypto::MAX_VERIFY_PAYLOAD_SIZE)  // 1 GiB
```

- **问题**：`decompress_stream` 的 `limit` 参数是唯一的防膨胀水位线，但 `read` 传入的正是被攻击者控制的 `raw_size` 本身——**自引用等于没有限制**。
- **可达性**：`crypto.rs:97-98` 的 `BUILTIN_DEFAULT_KEY` 是**硬编码公开常量**，无密码信封一律用它加封。因此任何人都能构造一个合法 AEAD 元数据、把 `raw_size` 写成 `u64::MAX` 的载体。几十 KB 的恶意 PNG 即可让 `read` 分配 GB 级内存。
- **影响**：GUI / 服务端批量处理不可信上传时是远程 DoS。且 `verify` 与 `read` 对同一威胁用了两套标准（1 GiB vs 无限制），说明这是遗漏而非有意设计。
- **建议**：`read_core` 增加 `limit` 参数，取 `min(raw_size, MAX_VERIFY_PAYLOAD_SIZE)`；并交叉校验"解压后大小不超过压缩前 N 倍"。同时 `decomp` 用 `with_capacity` 预分配。

### B2. `pe_codebits` 不区分代码与数据 —— 可改写跳转表，PE 静默崩溃

**位置**：`rust/src/structure/adapters/pe_codebits.rs:192-282`（`profile()`）

```rust
for insn in &mut decoder {
    let code = insn.code();
    // F0: skip data embedded in .text (jump tables, constants, ...).
    if code == Code::INVALID { continue; }        // ← 唯一的数据过滤
    ...
    // F2: both operands must be bare registers (mod = 11)
    if insn.op0_kind() != OpKind::Register || insn.op1_kind() != OpKind::Register { continue; }
```

- **问题**：唯一的数据过滤是"解码失败"。跳转表、内联常量、字符串表、对齐填充只要**恰好**能解码成 `Add/Mov/Cmp/Test` 的**寄存器-寄存器**形式，就会通过 F2/F4/F5 全部关卡并被改写。
- **未做的检查**（逐项核对）：无 `.reloc` 反向查询、无 `.pdata`/异常表排除、无 section `Characteristics`（`IMAGE_SCN_CNT_CODE|MEM_EXECUTE`）校验——`pe_layout.rs:235-241` 仅按名字 `.text` 匹配。
- **已规避的**：特权指令/栈操作/控制转移天然不在 `dual_and_bit` 表内；等长替换不影响跳转目标与后续偏移。
- **影响**：改写 4/8 字节 RVA 跳转表条目 → 运行时跳到错误地址，PE 静默崩溃。**不破坏"逐字节可逆"**（profile 对同一字节序列稳定，`strip` 仍能还原），但破坏"载体仍可运行"这一隐含承诺——而后者才是用户真正在意的。
- **建议**：(1) `pe_geometry` 增加 `.text` 的 characteristics 校验；(2) 解析 Base Relocation Table，把落在 `.text` 内的重定位点所在指令区间标黑；(3) 至少在 `strategy_note` 与 README 中明示该风险，并提供注入后自校验。
- **待确认**：实际触发概率取决于编译器布局（MSVC 常把跳转表放 `.rdata`，但 MinGW / 手工汇编 / 加壳样本会在 `.text` 内联数据）。建议构造 MinGW 编译的大 switch-case 样本实测一次，再决定是否默认关闭该策略。

### B3. PNG 提取路径不校验 wire 超参 —— 计算型 DoS

**位置**：`rust/src/stego/png/engine.rs:1597-1606`（`extract_png`）

```rust
let mut effective_params = params.clone();
effective_params.p1_window = fw.p1_window as usize;   // wire 允许 1..=1023
effective_params.p2_window = fw.p2_window as usize;
// ← 之后没有再调用 params.validate()
```

- **问题**：`FeatureWord::decode`（`header.rs:283-292`）只校验"奇数且 ≤1023"，而写入侧的 `PngParams::validate`（`params.rs:254`）限制 ≤63——**读写两侧上限不一致**，提取侧直接信任 wire 值。
- **放大路径**：`hill.rs:122-131` 的 stage-2 是 `O(h2·w2·p1²)`。p1=p2=1023 时每输出像素约 1.05e6 次乘加，512×512 图约 2.5e12 次运算；外加 `pad_symmetric` 的 (h+2046)×(w+2046) f64 填充（≈52 MB）。`extract` / `verify` 就此挂死。
- **可达性**：官方 profile 的 `fallback_secret` 是公开常量（`png/engine.rs:1163`），攻击者可用它自行写入 header 槽位伪造特征字。
- **建议**：`extract_png` 在覆盖后调用 `effective_params.validate()?`；把 wire 上限与 `validate` 统一（都取 63）；`compute_cost` 内对 pad 做 `checked` 保护。

### B4. CLI 隐式加载当前目录 `./strhide.toml`，且可注入凭据 —— 仅告警不拒绝

**位置**：`rust/src/core/config.rs:93-101`（`default_candidates`）、`:137-142`

```rust
fn default_candidates() -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from("strhide.toml")];   // 无需 --config，自动加载
    ...
}
...
if is_cwd_implicit && (cfg.password.is_some() || cfg.password_file.is_some()) {
    warnings.push(format!("[WARNING] Loaded sensitive password/secret keys from local CWD config ..."));
}
```

- **问题**：在任意目录执行 `strhide read secret.png`，会静默采用该目录下的 `strhide.toml`，其中 `password` / `password_file` / `strategy` / `backup=false` 全部生效。代码只在 `parse_config:137` 打一条 warning，**不拒绝、不降级**。
- **影响**：攻击者在共享/下载目录放一个 `strhide.toml`（`password_file = "//attacker/share/pwd"`）即可把用户口令外泄；或关掉 `.bak` 备份（配合 M19 的写入路径无覆盖保护，就是原始文件不可逆覆盖）。
- **建议**：`password` / `password_file` 在 CWD 隐式配置中直接忽略（仅 `--config` 显式指定时允许）；`./strhide.toml` 需显式 `--config` 或环境变量才加载。

---

## 三、重要问题（Major）

### 3.1 HEVC / HEIF 引擎

| # | 位置 | 问题 / 影响 / 建议 |
|---|---|---|
| **M1** | `hevc/engine.rs:925-929`、`964-968` vs `hevc/slot.rs:249-254` | **被禁槽位用 `f64::INFINITY`，与代码自身的契约注释直接矛盾**。`slot.rs:249` 明确写着"`f64::INFINITY` 会让 u=2 的 trellis 组整体塌缩成 `DeadGroup`，因此刻意用有限的 `HIGH_DISPLACEMENT_PENALTY = 1e6`"，而 embed 端却把 `forbidden` 槽位设成 INFINITY。**影响**：真实载体触发 EPB 冲突后，`MAX_EMBED_ROUNDS=24` 的自愈循环可能在 `embed_with_deltas` 处直接返回 `Err`（`stc.rs:730-739` `best_state == usize::MAX` → `DeadGroup`），嵌入失败。**建议**：改用有限大惩罚值；或在 trellis 报 `DeadGroup` 时当作"继续下一轮"而非终止。*待确认*：触发概率取决于 `forbidden` 是否非空且同组内两个槽位同时被禁——建议构造含 EPB 的真实码流实测一次，若复现频繁则应按 Blocker 处理。 |
| **M2** | `hevc/engine.rs:888` | `window_slices: slice_contexts.len() as u16` —— 记录片数 >65535 时静默截断，提取端（`engine.rs:1539-1550`）用它做 `StopCondition::TargetSlices(w0)`，导致 `body_positions` 与 embed 不一致 → CRC/认证失败且无提示。建议改 `u32`（Superblock 有 2 字节 reserved 可挪用），或超限时报错。触发门槛高但属**静默数据损坏**。 |
| **M3** | `hevc/engine.rs:1885` vs `:2454` | `has_inter` 判定不一致：inspect 只取样前 64 个 sample（`take(64)`），embed/extract 用全量 `any(\|c\| !is_irap(...))`。`has_inter` 决定 `picture_band()` → 池布局 → 命中槽位。对长 IDR 前缀的 MP4，`inspect`/`verify` 会**误报"无隐藏数据"**。建议复用 `record_carrier_state` 的同一推导。 |
| **M4** | `hevc/engine.rs:2271/2283/2300` 写、`:2558-2565` 丢弃 | `SlotSink::band_slots` **只写不读**，全工程无读取点。17M 槽位 ≈ 272 MB 纯浪费，约占已知 1.31 GB 峰值的 20%。建议删除该字段（band 归属已由 `counts` + `bands` 表达）。 |
| **M5** | `hevc/engine.rs:589`、`:619` vs `record_carrier_state` | 容量/维度计算**重复解析容器 2~3 次**（`extract_hevc_dimensions` → `parse_heif_targets`/`parse_mp4_targets`，又各调一次）。建议把 dimensions / picture_count / fps / duration 放进 `CarrierRecord`，与 digest 一样只解析一次。 |
| **M6** | `hevc/engine.rs:779-781` vs `:806-811` | **安全闸门比对的是明文长度，不是实际嵌入字节**：实际写入 `encode_micro_header(payload)`（压缩后、可能含文件名）+ 16 字节 tag，却用 `payload.len()` 与 `recommended_max_bytes` 比较。同时 `_max_raw_payload_bytes` 形参完全未使用。建议改用 `uncompressed.len() + HEVC_TAG_BYTES`，删掉死参数。 |
| **M7** | `hevc/heif_boxes.rs:694-714` | `parse_iloc_extents` 对**非目标** item 的 extent 循环无上限：`MAX_TARGET_EXTENTS`（:702）只在 `is_target` 分支生效。item_count(u16)×extent_count(u16) ≈ 4.29e9 次迭代，`read_uint` 一律返回 0 但循环照跑 → DoS。注释声称已堵住该形状（:573-576），实际只堵了目标 item。建议加 `if pos >= iloc.len() { break }` 与总迭代上限。 |
| **M8** | `hevc/engine.rs:373-398` vs `:2735-2762` | EPB 排除逻辑**被复制两份**（`count_absorbed_slots` 服务 20% 抽样估算，`absorb_recorder` 服务真实入池）。任一侧修改都会让**估算容量与实际容量悄悄偏离**。建议抽成 `fn excluded_substreams(...)` 共用。 |
| **M9** | `hevc/engine.rs:794-804` | `embed` 返回的 `StegoCapacityInfo` 只反映**早停窗口**（`TargetSlots(2048+desired+128)`），不是载体容量，但 `is_estimated` 仍为 `false`。CLI/GUI 拿到的"载体容量"被系统性低估且标为精确值。建议容量报告走独立全量 `Capture::Count` 扫描，或显式标注"窗口容量"。 |

### 3.2 PNG 引擎

| # | 位置 | 问题 / 影响 / 建议 |
|---|---|---|
| **M10** | `png/engine.rs:1636/1648` vs `header.rs:277` | `class_rule` **未校验**：wire 直接取 2 bit（允许 0/1/2/3），写入侧硬编码 `1`（`engine.rs:1295`），提取侧却信任 wire 值重建 body 池。`class_rule != 1` 会跳过 `r∈[1,6]` 过滤 → 池与写入时不同 → **AEAD 静默失败**（不报"参数不支持"，而是报"无隐藏数据"）。建议 `FeatureWord::decode` 拒绝 `class_rule != 1`。 |
| **M11** | `coding.rs:405` vs `png/engine.rs:17-22`、`coding.rs:356-358` | header 用 `spatial_move`、body 用 `spatial_move_safe`——**与 P0-B 不变量文档冲突**。`spatial_move` 对 `r=1/6` 返回 `Both`，故 header 像素 9→8（落到 r=0）、246→247（落到 r=7）是可能的，而文档明确承诺"modified pixel 永不落在 {0,7}，delta 直方图在 r=0/7 恒为零"。**影响**：不破坏往返，但 512 个 header 槽破坏了自己声明的抗检测不变量。建议 `write_bit_ternary` 增加 `safe` 参数，或 header pool 也过滤 `r∈[1,6]`。 |
| **M12** | `png/engine.rs:948-954`、`:886-894` | `ranked`（24MP 时 384 MB）与 `header_pool`（192 MB）都用 `filter().collect()`——`Filter` 的 `size_hint` 下界为 0，导致约 25 次倍增重分配。叠加 HILL 的 6 张 f64 平面，峰值可达 1.5 GB+。建议 `Vec::with_capacity(total_pixels)`（候选集上界已知）。 |
| **M13** | `png/engine.rs:453`（唯一 `into_par_iter`） | **代价计算 100% 串行**，rayon 只用于 deflate。HILL 的 stage1/2/3-horizontal 与 S-UNIWARD 的两次 16-tap 一维 pass 都按行可分；3 个 band 间只做 `cost` 累加。建议按行 `par_chunks_mut`，band 间 `map(独立缓冲).reduce(逐点相加)`（需保证浮点累加顺序确定以维持可复现性）。 |
| **M14** | `png/engine.rs:1076-1082` | `body_slots_upto` 无提前退出：`visit` 闭包返回 `()`，`taken >= limit` 后仍走完全部候选（24MP×3 通道 ≈ 5000 万次）。且 `count_body_slots` 已在 `:1198`、`:1244` 各走一遍全量 → **最多 3 次全量遍历**。建议 `visit` 返回 `ControlFlow`。 |
| **M15** | `png/engine.rs:1517` vs `:1615` | `header_layout` 算了两遍（`SlotPlan::build` 内部又调一次，全图 O(n) 过滤 + ChaCha shuffle）。`:1616-1620` 的 `debug_assert_eq!` 在 release 下消失但双倍开销保留。建议把已算好的 layout 传进去。 |
| **M16** | `png/engine.rs:730-735`、`:533-540` | `fn trace(_msg: &str) {}` 是**空函数**，注释却称"enabled with `STRHIDE_STEGO_TRACE=1`"（全仓库无该环境变量读取）。`choose_deflate_level` 返回的 `probe[0]/probe[1]` 只喂给 `trace` → 每次编码白做两次压缩投影且结果无处可用。建议用 `std::env::var_os` 实现，或删掉 `probe` 返回值。 |

### 3.3 JPEG 引擎

| # | 位置 | 问题 / 影响 / 建议 |
|---|---|---|
| **M17** | `jpeg/engine.rs:1414`、`:1457`、`:1482` | `verify_jpeg` 对同一文件做 **3 次完整解码 + 3 次 KDF**，且 level-1 解出的系数立刻丢弃（`:1453 let _ = (info, coeffs);`）。verify 耗时约为单次 extract 的 3 倍。建议把已有 `coeffs` 传给 `inspect_jpeg`/`extract_jpeg`（加 `from_coefficients` 内部入口）。 |
| **M18** | `geometry.rs:47` → `jpeg_segments.rs:107` | **量化表按 `Tq=0` 硬取**，忽略 SOF 的组件→Tq 映射。而嵌入目标固定是 `coeffs.components[0]`。若文件第一个分量的 `Tq != 0`（CMYK/RGB 排列、自定义编码器），UERD 的 `Q[k]` 权重与 J-UNIWARD 的 `q[k]` 全表取错 → **代价排序错误，安全性下降**（非功能失败，更难发现）。建议从 SOF 读 component[0] 的 `Tq`。 |
| **M19** | `jpeg/engine.rs:1528-1530` vs `:198` | `probe_jpeg_capacity` 用**推算**的 block 数（`component_geometry` → `grid_w*grid_h`），embed/extract 用**实际**解码值（`coeffs.components[0].blocks.len()`）。若 `dct-io` 对非 16 倍数尺寸按可视网格分配（而非补齐网格），probe 报告的容量会**高于真实值**，用户按推荐容量写入失败。`geometry.rs:176-179` 的测试声称两者一致——*待确认*：建议 probe 里直接调用 `read_coefficients` 取真值，或加断言测试锁死该不变式。 |
| **M20** | `precover.rs:140-180`、`:257-269` | `decompress_luma` 用了 rayon，但下游 `wiener3`（三趟 w×h 各 9 抽样）与 `estimate` 的逐块 FDCT（每块 1024 次乘加）**全串行**。24 MP 载波约 3 亿次浮点运算落在单核；J-UNIWARD 侧已并行，唯独极化路径没有。建议 `wiener3` 按行并行、`estimate` 用 `par_iter` 分块。 |
| **M21** | `jpeg/engine.rs:99-100` vs `juniward.rs:204/442/459` | `MAX_PIPELINE_BYTES` 预算只统计 coefficients/costs/slot grid/work copy（1020 B/block），**未计入 J-UNIWARD 的 plane**（weights 4 B/px + horizontal 8 B/px + residual 8 B/px ≈ 20 B/px ≈ 2.4 GB @100 MP）。注释声称"8 GiB 容纳 100 MP 的 5.4 GiB"，加上这 2.4 GB 已达 7.8 GB，再叠加 `directions` 与 `sparse_overrides` 即**越界**。建议并入预算或按像素数二次校验。 |
| **M22** | `jpeg/engine.rs:675` vs `:1045` | `let mut work = coeffs.clone();` 克隆**全部**分量，但 `apply_deltas` 只写 `components[0].blocks`。4:2:0 下约 1/3 的克隆是无用功（100 MP 约 100 MB）。建议只克隆 component 0。 |

### 3.4 STC / 参数 / 信封（content 域公共基础）

| # | 位置 | 问题 / 影响 / 建议 |
|---|---|---|
| **M23** | `stego/params.rs:432/442` | `MAX_AUTO_BACKTRACK_BYTES / MAX_GROUPED_BACKTRACK_BYTES = 4 << 30` —— **4 GiB 的"上限"形同虚设**。`stc.rs:627` `vec![0u64; n * words_per_col]`，h=8 时 32 B/槽 ⇒ 1.34 亿槽；100 MP 载体可达 25M 槽 ⇒ 单次分配约 800 MB。大载体嵌入 OOM。**建议**：默认降到 256–512 MiB 并允许显式覆盖；分配前 `try_reserve`，失败返回 `StrHideError` 而非 abort。 |
| **M24** | `stego/envelope.rs:144-165` + `png/engine.rs:908-910` | **PNG 头部置换种子绕过 PBKDF2**：`effective_ikm` 就是 NFC 口令本身（无 salt/cover 绑定），只做一次 HKDF-Expand。而 `format.rs:477-479` 明确宣称"这是口令 KDF 唯一运行的地方……不付代价就无法验证猜测"，PNG 侧违背该不变式。**影响**：① 头部位置种子与载体无关，同口令+同尺寸图 ⇒ 头部像素位置完全相同，**可跨载体关联**；② 无 salt，弱口令可预计算彩虹表。建议改为 `HKDF(master, hpos_label)`，master 来自 `derive_master(suite, pw, cover_digest)`；至少混入 cover 摘要。 |
| **M25** | `stego/params.rs:432` / `stego/format.rs` | `PngFormatProfile` / `HevcFormatProfile` **无 `validate()`**（`JpegFormatProfile::validate()` 有）。`fallback_secret`、`hpos_salt`、`hpos_label`、`stc_h`、`stc_u`、`header_bytes` 全无校验，私有构建传入空标签或 `stc_h=0` 不会被拦。建议补上并在所有入口调用。 |
| **M26** | `stego/envelope.rs:60` vs `format.rs:450` | **公开默认密钥字符串两处独立定义**（`"strhide-default-content-stego-key-2026"`）。PNG 走 `spatial.fallback_secret`，JPEG/HEVC 走 `PUBLIC_DEFAULT_SECRET`。改一处不改另一处 ⇒ **PNG 与 JPEG 无密码载体互相解不开**。建议单点 `pub const` 定义。 |
| **M27** | `stego/envelope.rs:87` vs `header.rs:35` | `MAX_PLAINTEXT_LEN = 1 << 26`（67 108 864）vs `HEADER_LEN_MAX = 2^26 - 1`。恰好 64 MiB 的载荷能通过 `build_plaintext`（:384）却在 `encode_header_word` 的 `debug_assert` 下被静默截断为长度 0。写入侧用 `HEADER_LEN_MAX` 检查（`png/engine.rs:1273`），**两侧上限不一致**。建议统一。 |
| **M28** | `stego/params.rs:244-280` | `PngParams::validate()` **未校验 `exclusion_percentile`**（文档声明 0.0..0.9），实际靠 `png/engine.rs:960` 与 `:1301` 两处 `clamp` 静默兜底。当前对称（写侧 clamp 后写 wire、读侧从 wire 还原），但分散且未校验，是易碎点。另 `inspect_png`（:1697）**根本没调用 `validate()`**。 |
| **M29** | `stego/coding/stc.rs:559` vs `:687-699`、`:291-318` | `u == 1` 早退使其后约 90 行 trellis 代码成为**永不单态化的死代码**，`parity_bit` 实为死参数。这段"u=1 通用实现"从未被测试覆盖——若日后有人删除 u=1 快路径，会启用一段**未经任何测试验证**的分支。建议删除死分支，或加 `#[cfg(test)]` 断言两路径一致。 |

### 3.5 structure 域引擎与信封

| # | 位置 | 问题 / 影响 / 建议 |
|---|---|---|
| **M30** | `structure/envelope.rs:86` vs `engine.rs:1014-1023` | **`MIN_UBE_PLAIN = 178` 小于写入器真实最小信封 214 B，常量永不可达 → 容量虚报**。已核实：`engine.rs:1015-1018` 中元数据**无条件** AEAD 封装、载荷**无条件** chunk 分帧（`exact_meta_len = meta_raw.len() + 16`、`framed_len(...)`），与 `FLAG_ENCRYPTED` 无关——且 lib.rs 文档确认"无密码时也一律加密"。故真实最小 = 214 = `MIN_UBE_ENCRYPTED`。**影响**：`pe.rs:259/311/571` 用它判定 `available`，178–213 B 区间的 PE 载体被 `inspect` 报为可用，随后 `write` 被拒绝或静默退化到 `eof`，与 `strategy_note` 声明矛盾。建议删除该常量或令其 = 214，并加测试断言"最短真实信封 = 常量值"。 |
| **M31** | `structure/engine.rs:1235-1238`、`options.rs:55-72` | **`write` 路径缺少覆盖写保护**，`WriteOptions` 无 `overwrite` 字段。`remove`（:1881-1883）与 `read`（:1638）都有 `check_overwrite`，唯独 `write` 没有。CLI 在 `cmd_structure.rs:143/166` 自行检查，但**库调用者拿不到这层保护**：`write_carrier_with(..., output_path: Some(existing.png))` 会直接 `rename` 覆盖用户文件。建议 `WriteOptions` 增加 `overwrite: bool`。 |
| **M32** | `structure/envelope.rs:402-407` | **隐身 magic 推导失败被当作"匹配成功"（`is_none_or` 语义用反）**：`Option::is_none_or` 在值为 `None` 时返回 `true`，故 KDF 出错 → `magic_matches = true`。随后仍执行 `derive_header_mask(pwd, &salt)?`，把一次确定性失败伪装成"命中隐身分支"。建议改 `is_some_and(...)`。*注*：HKDF-Expand 对 8 字节输出实际不会失败，故当前不可达，属**潜在缺陷**而非活跃 bug。 |
| **M33** | `structure/envelope.rs:189-211` vs `adapters/mod.rs:230-243` | `validate_against` **不校验偏移/长度字段**：只校验 version / hint_len / meta_len 与总长的一致性，`inject_offset` / `inject_size` / `orig_host_size` / `patch_offset` 均未纳入。而 `mod.rs:231` 直接把 `inject_offset` 用作拷贝长度。**目前靠 `verify_restored` 的 SHA-256 兜底才没变成破坏性缺陷**，但那是事后发现而非事前拒绝。建议补边界校验：注入区间须落在 `[0, 载体长度)` 内且不与 `patch_offset` 冲突。 |
| **M34** | `structure/rejection.rs:259-311` | `check_jar_signature` 的 EOCD 候选回退循环**最坏 O(n²)**：唯一约束是 `cd_offset + cd_size > file_size`。攻击者可在尾部 64 KiB 内塞入数万个 `PK\x05\x06`，每个都指向 `cd_offset=0, cd_size=file_size` → 每次迭代完整读一遍文件。建议候选数上限（如 8）+ 累计字节预算（如 16 MiB）。 |
| **M35** | `structure/engine.rs:1547-1567` | `read_core` 非流式且 `Vec` 未预分配 → 密文 + `decrypted_payload` + `decomp` **三份缓冲同时存活**，峰值约 3× 载荷。对比 `verify_l3_stream` 已是流式（约 4 MiB）。建议 `with_capacity(min(raw_size, cap))`，或 `output_path` 存在时走流式落盘。 |
| **M36** | `structure/engine.rs:1760/1782/1821` | `remove` 路径**未复用 `UnpackSecrets`，每趟多跑 2–3 次 PBKDF2**。`read` 路径已通过 `Located` + `UnpackSecrets` 降到 1–2 次，但 `remove` 仍在三处独立推导（`locate_envelope`、`unpack_with_profile`、`verify_restored`），每次 100k 次 HMAC-SHA256。建议改用 `locate_envelope_with_magic` + `unpack_with_secrets`。 |

### 3.6 容器适配器（PDF / PE / ZIP）

| # | 位置 | 问题 / 影响 / 建议 |
|---|---|---|
| **M37** | `structure/adapters/pe.rs:651-723` | **未处理 Optional Header `CheckSum`**：注入改写 `.text` 后 PE 校验和失效。`pe.rs:236` 已有 `parse_pe_headers`（含 `has_authenticode`）却未读写 `CheckSum`。对驱动 / 开启完整性校验的加载器会导致"不可加载"。建议注入时重算并落盘（strip 会自然还原），或明确拒绝并提示改用 `pe_overlay`。 |
| **M38** | `structure/adapters/pe.rs:677-687` | **"已存在 channel"检测漏判，注释与实现不符**：注释写"header parse alone decides"，实现却额外要求 diff 前 64 字节非全零。若首个 channel 的 diff 恰好全零，第二次注入覆盖 header，首个 diff 永久遗留在 slack 且再无可逆路径 → **破坏 100% 还原**。建议按注释语义改为 header 命中即拒绝，或在 diff 头部写入可校验 sentinel。 |
| **M39** | `structure/adapters/pe.rs:189/243/513` | 单次写入内**重复全量 profile** `.text`（`choose_auto_strategy` → `read_text_range` + `embed` → `strategy_capacities`）。`read_text_range` 把整个 `.text` 读成 `Vec`，`profile` 为每个位置分配 `CodePosition`（约 40 B）。大 PE 上内存约 2~3× `.text`、CPU 2~3 遍。建议在同一 write 流程内缓存 profile 结果。 |
| **M40** | `structure/adapters/pdf.rs:682-701` | locate **扫描窗口可增长到整个文件大小**：`scan_len` 每轮 `saturating_mul(4)`，2 GB PDF 的最终迭代分配 2 GB，且每轮对整窗重跑 `rposition` 全文扫描。建议改为与 `find_last_eof`（:97）一致的 64 KB 尾部滑窗 + 重叠。 |
| **M41** | `structure/adapters/pdf.rs:622-625` | xref 条目宽度依赖 `{:010}`：规范要求每条 xref 恰好 20 字节，`actual_obj_offset ≥ 10^10` 时变 21 字节 → **产出损坏 PDF**。建议比照 `:63` 的 `new_obj_num` 检查，超限时拒绝增量更新并回退 `eof`。 |
| **M42** | `structure/adapters/zip.rs:322` | **硬编码策略 ID 魔法数字** `if header.strategy_id == 1`。`registry.rs:91` 为 `("eof", 1)`，属巧合耦合；同项目 `pe.rs:511` 用的是 `registry::id_to_strategy(...)`。注册表一变即静默走错分支。建议统一。 |
| **M43** | `structure/adapters/riff.rs:66-100`、`:346-366` | 写 RIFF 头前**不校验 magic**：只 `read_exact` 就直接 `out.write_all(&header[0..4])` 并改写 offset 4。目前仅靠 `detect()` 门禁。建议显式校验 `b"RIFF"` + form type，避免上层直连时静默损坏任意文件的第 5~8 字节。 |

### 3.7 CLI / analysis / core

| # | 位置 | 问题 / 影响 / 建议 |
|---|---|---|
| **M44** | `analysis.rs:1666-1681` | **卡方统计量未做样本量归一化**。公式为 `((df - chi2) / df).clamp(0.0, 1.0)`（注释"Clean: chi2 ≈ df；Fully embedded: chi2 → 0"）。但卡方值随样本量**线性增长**：真实照片里 `(0,1)` 这一对如 8000 vs 200，单项 chi2 就 ≈3710，全局上万而 `df ≤ 128` → 强负 → clamp 到 **0.0**。即该检测器在真实图片上恒为 0，只在接近满嵌入时才抬起，**对低嵌入率几乎没有分辨力**；而单元测试只用全偶数和均匀随机数这两种人造分布，测不出该缺陷。建议改用卡方分布 CDF 求 p 值，或对 chi2 除以总样本数 N 归一化后再定阈值。 |
| **M45** | `analysis.rs:1602-1611`、`:1436-1440` | **检测器"无法运行"被渲染成 PASS**（`metric: "n/a"`、`status: "PASS"`）。`rs_analysis` 返回 `None` 时 `rs_p = 0.0` 也走 PASS 分支。这会让"clean"看起来通过了全部检测，而实际是检测未执行——正是文档自称要避免的"clean ≠ 无隐藏数据"。建议增加 `status: "SKIPPED"` 且不计入 PASS。 |
| **M46** | `analysis.rs:1084-1098` | **`overlay:high-entropy` 对 ZIP/MP4/PDF 系统性误报**：`match format { Some("PNG")=>false, Some("JPEG")=>false, _ => entropy >= 7.5 }`。任何 >4 KiB 的 ZIP 尾部都是 deflate 数据（熵 7.9~8.0）→ 必报 `Suspicious`（25 分）。而 `MP4`、`PDF` 在 `scan_view_internal` 里根本没有其他检测器，`notes` 也只给 JPEG 出免责说明。目录里全是 `.zip`/`.mp4`/`.pdf` 时全部判定 `low`/`suspicious`。建议排除已识别的压缩容器，或改为"容器末尾之后仍有数据"才判定。 |
| **M47** | `analysis.rs:1181-1199` | **PNG 解压上界由攻击者可控的 IHDR 决定**：`expected = stride * height` 来自 IHDR width/height，声明 20000×20000 RGB 时 `expected ≈ 1.2 GB`，几百 KB 的 PNG 可迫使 GB 级 `raw` + `out` 双份分配。`MAX_FULL_SCAN` 只限文件体积，不限解压后体积。建议对 `expected` 设绝对上限（如 256 MB）并与文件大小挂钩（放大倍率上限）。 |
| **M48** | `analysis.rs:1276-1345` | **WS 实现与注释（Ker 2007）不符**：模块头声称"algorithms follow the published papers"，但 WS 是自造的协方差估计量（`w = 1/(1+var)²`，分子 `residual·d`、分母只累加权重），不是 Ker 的加权最小二乘。且 `ws/spa/rs` 都在 **3 通道 × 3 slab = 9 次机会里取 max**，再与单一阈值 0.70 比，等价把误报率放大约 9 倍。建议改注释为"inspired by"，并把跨通道/跨 slab 的合并改为均值 + Bonferroni 校正。 |
| **M49** | `analysis/calibration.rs:234` vs `:243-251` | **实际与校准直方图的块集合不同源**：实际用 `luma_blocks.iter().step_by(stride)`（含 MCU 边缘填充块），校准只含 `(w-4)/8 × (h-4)/8` 网格。注释明确警告"两组必须在同一尺度上，否则 beta 会爆炸"，但前者数量恒 ≥ 后者（1024×768 例：12288 vs 12065，比例 ≈1.018）→ `rate = 1 - ratio` 带系统性负偏。建议按同一网格索引取实际块，或归一化后再求比值。 |
| **M50** | `core/commit.rs:240-242`、`:198-200` | **临时文件名为固定 `.strhide.tmp`，无唯一化**：两个进程（或 GUI 批处理 + CLI）写同一目标时会互相截断对方的临时文件，`rename` 可能把半成品提交成目标文件。建议加入 pid + 随机数（如 `.strhide.<pid>.<rand>.tmp`），并用 `O_EXCL` 创建。 |
| **M51** | `cli/helpers.rs:53-58` + `cli/args.rs:126-132` | **口令暴露面**：`-p` 出现在命令行 → `ps` / `/proc/<pid>/cmdline` 对所有本地用户可见；`STRHIDE_PASSWORD` 在 `/proc/<pid>/environ`。口令以 `String` 全程传递，**无 zeroize**（Cargo.toml 无 `zeroize`/`secrecy` 依赖），进程内存/核心转储中长期驻留。建议在 help 中明确提示 `-p` 可见、优先 `--password-file`；至少对 `resolve_password` 的返回值做 drop 清零。 |
| **M52** | `cli/cmd_stego.rs:238-254` | **`embed` 跳过 `preflight_batch`**，缺目标冲突与格式预检。`write`/`restore` 都走 `preflight_batch`（重复载体、目标碰撞、格式校验），`embed` 没有 → `embed a/x.png b/x.png -o out --overwrite` 会静默后写覆盖先写。建议复用。 |
| **M53** | `cli/cmd_stego.rs:602-605` | `let dest = PathBuf::from(name);` **直接采用载荷名**。`stego/envelope.rs:367` 已在解码端 `sanitize_filename`，但 CLI 侧无纵深防御（结构域 `cmd_structure.rs:383` 就显式再消毒了一次）。建议统一走 `core::fs::sanitize_filename`。 |
| **M54** | `formats/annexb.rs:38-72` | 只校验起始码 + NAL type 白名单，**H.264 Annex-B（NAL 1/5/7/8 均在白名单内）会被判成 `HevcAnnexB`**。*待确认*：下游 `stego::hevc` 是否二次校验；若此为唯一判据则为误判。 |

---

## 四、一般问题（Minor）

### 4.1 常量漂移与魔法数字

- `structure/engine.rs:829` 硬编码 `1024` 校验 hint 长度，未复用 `envelope.rs:77` 的 `MAX_HINT_LEN`。
- `structure/engine.rs:117` `patch_offset: u32` —— ZIP 的 `eocd_pos + 16 + ube_size` 在 >4 GiB 容器上会截断。
- `structure/engine.rs:1135` `inject_offset + delta` 未用 `checked_add`。
- `structure/envelope.rs:202` `let fixed = HEADER_SIZE as u64 + 24;` 魔法数字 24（应为 `TRAILER_SIZE`）。
- `stego/header.rs:270` 与 `format.rs:315/321` 硬编码 STC `h` 范围 `4..=10`，与 `MIN_STC_H/MAX_STC_H`（`stc.rs:82-83`）脱钩。
- `stego/stc.rs:396`、`format.rs:285/290`：`h as usize - 1` 在 `pub const fn` 入口未校验，`h = 0` ⇒ debug panic / release 回绕。
- `hevc/engine.rs:88` `MAX_EMBED_ROUNDS = 24`、`:545` `SLOTS_PER_REF_FLIP = 4`、`:94-96` `POOL_SLOTS=2048/MIN_SLOTS=524` 缺少推导来源标注。
- `hevc/engine.rs:262-263` `saturating_sub(HEVC_TAG_BYTES)` 后又 `.saturating_sub(1)`，该 `-1` 无注释无测试约束。
- `jpeg/engine.rs:335` 魔数 `slots.len() >= 4096` 决定 dense/sparse bitset 路径。
- `pe_codebits.rs:660-661` 注释 `// test eax, ebx ; 85 C3` 与编码不符——`85 C3` 的 ModRM `11 000 011` 实为 `TEST EBX, EAX`，方向写反，会误导对 bit 编码方向的维护判断。

### 4.2 注释与实现不符

- `jpeg/engine.rs:71-72`："repeating it here was a dead branch"，描述的是已删除的代码。
- `jpeg/engine.rs:184` / `png/engine.rs:730-735`：`fn trace(_msg: &str) {}` 恒为空，注释称由环境变量开启（全仓库无读取点）。
- `structure/rejection.rs:321-322` vs `:229-231`：注释称"`filename` 被透传，因为 JAR 签名检测按文件名报告违规条目"，但 `check_jar_signature` 的形参是 `_filename`（未使用）。
- `structure/engine.rs:1748-1751`：文档引用 `[remove_carrier_with]`，实际公开函数名为 `remove_carrier_with_dialect` → rustdoc 断链。
- `stego/traits.rs:58` 文档称 `channel` 是 "byte offset"，实际引擎传的是通道索引 0..2。
- `stego/coding.rs:113-127` `auto_select_codec` 三个分支全部返回 `StegoCodec::Stc`，`Hamming` 分支不可达 —— 函数名与实现不符。
- `hevc/bitstream.rs:142` `is_epb_safe_flip` 全工程仅被测试引用，是死代码，且语义与新引擎的"重编码后比较"方案完全不同，容易误导。

### 4.3 死代码与重复代码

- `structure/envelope.rs:455-457`：第三级兜底 `Self::unpack(data)` 对任意 112 字节都返回 `Ok`，不校验 magic/version；`unpack` 是 `pub`，外部误用会得到垃圾字段。建议降为 `pub(crate)`。
- `hevc/engine.rs:1619` `extract_hevc_record` 标 `#[allow(dead_code)]`，且函数体内把整个 `CarrierRecord` 逐字段 clone 一遍，是明显的死重代码。
- `jpeg/v3_layout.rs:149-164` `body_grid` 是死代码，仅被 `:322` 的测试使用，生产路径全走 `fill_body_grid`。两份实现并存有漂移风险。
- `jpeg/engine.rs:1108-1165` vs `:1352-1372`：`extract_jpeg` 与 `inspect_jpeg` 的 superblock 定位流程几乎逐行重复。
- `jpeg/engine.rs:410-414` vs `:1026-1030`：极化代价计算两处逐字重复，一旦只改一处，Dense 与 Sparse 路径的代价会静默发散。
- `analysis.rs:519-539` `sniff_format` 是与 `formats::sniff.rs` 重复的**第二套嗅探器**（MP4 判据仅 `data[4..8]=="ftyp"`、PE 仅 `MZ`），能力更弱且已分叉。
- `analysis.rs:1642-1646` `track_content_domain` 标 `#[allow(dead_code)]` 且无调用者。
- `cli/cmd_stego.rs:579-605`：`out_path.is_dir()` 分支不可达（`batch_output_dir` 已转换），为死代码；`std::fs::write` 非原子、不 fsync。
- `core/params.rs:237-252`：`SafetyLevel::FromStr`（接受 `"0"/"1"/"2"`）与 `SafetyLevel::parse`（不接受数字）语义不一致，且 `FromStr` 全仓无调用者。
- `pe_layout.rs:96/254`：`pe_code_layout`、`find_slack_run` 为 `pub` 但生产代码无调用方；`pe_codebits.rs:28` 又 `pub use super::pe_layout::*` 二次 re-export，扩大可见面。

### 4.4 错误处理与健壮性

- `structure/rejection.rs:60-76`：`find_adapter_or_reject` 中 `unwrap_or(0)` 与两处 `let _ = seek(...)` 静默吞错，magic 探测失败后位置可能未恢复。
- `structure/engine.rs:2245-2341` vs `:2349`：L2 失败（如 header 校验失败）后仍无条件运行 L3，产生无关的 crypto 报错**掩盖真实原因**。建议 `l3` 增加 `l2_ok &&` 前置条件。
- `structure/options.rs:35-45`：`StrategyChoice::from(&str)` 对未知策略名**静默退化为 `Auto`**，用户拼错策略名会静默用错策略。
- `jpeg/engine.rs:1338-1341`：`inspect_jpeg` **静默吞掉解码失败** —— `read_coefficients` 出错就 `return Ok(empty_info)`，把"文件损坏"报成"无隐藏数据"。与 `extract_jpeg`（会传播错误）行为不一致。
- `pe.rs:600-644` `copy_with_patches`：`sorted` 后若 `start < cursor` 会静默跳过 copy 直接写 replacement，产出比 host 更短的文件且**不报错**。作为承载"无损"承诺的核心 helper 缺断言。
- `png.rs:365`：`carrier.seek(SeekFrom::Start(ctx.ube_offset - 4))` 对载体派生数据做裸减法。
- `core/batch.rs:176-179`：`continue_on_error=false` 时并发分支下其他线程仍会继续取索引，最多多跑 `max_concurrency` 个任务；`outcomes.lock().unwrap()` 在互斥量中毒时会 panic（应 `unwrap_or_else(\|e\| e.into_inner())`）。
- `cli/cmd_diag.rs:424`：`note.contains("Carrier is larger")` 硬编码英文子串匹配渲染逻辑。
- `hevc/engine.rs:184-193` `superblock_positions` 是 `pub` 函数却用 `assert!` 做参数校验 → 外部调用即 panic。
- `stego/envelope.rs:123/163/181/292/586` 与 `format.rs:519/541/552/586`：大量 `.expect("HKDF expand ...")`。输出均 ≤32 B 远低于上限不会失败，但属 panic 路径。

### 4.5 性能细节

- `png/engine.rs:524` / `:298`：PNG 滤波/反滤波**每行一次堆分配**（`vec![0u8; stride]`），4000 行图 = 8000 次 alloc + 复制。建议改为 `filter_row_into(&mut out[..])` + 双缓冲。
- `png/hill.rs:122-156`：HILL **无滑动窗口**，stage-2 每点 `p1²` 次、stage-3 每点 `2·p2` 次；均可降为 O(1)/点（默认 p1=3,p2=15 时约 30 次 → 2 次）。另 `hill.rs:138` 的 `tmp` 分配 `h*w2`（含 p2-1 冗余列）。
- `png/engine.rs:1807/1837/1865`：`verify_png` **解码整图 3 次**。
- `hevc/engine.rs:2507`：每个 slice 都无条件做一次 RBSP 全拷贝（`nal_rbsp` → `unescape()` 新分配），但 `absorb_recorder:2736` 仅在 `substreams.len() > 1` 时才用；容量探测（`Capture::Count`，全量扫描）也白做一遍。
- `hevc/engine.rs:1308-1318`：用 `substreams.iter().position(...)` 对每个翻转做线性查找 → O(翻转数 × substream 数)；`encode_substream:1231` 的 `flip_cursor` 每条 substream 都从 0 重扫（WPP 68 行 × 数千翻转时明显）。建议二分查找 + 游标跨 substream 复用。
- `hevc/engine.rs:1026-1039` vs `:1062-1072`：保真校验对每个 touched substream 完整重编码一遍（空翻转集），随后真实重编码再来一遍 → **2× 编码开销**。
- `analysis.rs`：`rs_analysis` 对 512 行 × 4000 宽 × 3 通道 × 3 slab × 4 次 `rs_difference`，约 10⁹ 量级窗口运算；`handle_scan`（:369）逐文件纯串行。单图可达数十秒。建议目录扫描并行化。
- `formats/sniff.rs:301-320`：`sniff_stream` 每次额外预分配并丢弃一个 64 KiB `Vec`。
- `analysis.rs:1199-1224` `decode_png_pixels` 每行 `vec![0u8; stride]` 重新分配。

---

## 五、架构与代码质量（系统性议题）

### 5.1 四个"上帝文件"

| 文件 | 行数 | 承载职责 |
|---|---|---|
| `stego/png/engine.rs` | 3 360 | PNG 容器编解码 + deflate 并行/层级选择 + slot 规划 + embed + extract + probe + inspect + verify |
| `stego/hevc/engine.rs` | 3 193 | Annex-B/MP4/HEIF 解析 + 槽位录制 + 两阶段 STC + 重编码 + EPB 自愈 + 容量 + inspect + verify |
| `structure/engine.rs` | 2 540 | 协议组装 + write/read/remove/inspect/verify 五条命令编排 + 元数据 varint 编解码 |
| `analysis.rs` | 2 366 | 格式嗅探（第二套）+ 四个检测器 + 报告生成 + CLI 渲染辅助 |

这四个文件占 `src` 总行数的 **21%**，且每个都混合了 5~8 个正交职责。建议的拆分方向：

- `png/engine.rs` → `png/{container,deflate,slots,embed,extract}.rs`
- `structure/engine.rs` → `structure/engine/{write,read,remove,inspect,verify}.rs` + `envelope/meta.rs`
- `analysis.rs` → `analysis/{sniff,chi2,rs,spa,ws,report}.rs`（并删除重复的第二套嗅探器）

### 5.2 其他结构性问题

- **超大函数与参数爆炸**：`jpeg/engine.rs:720-957` `embed_once` 238 行且混合布局计算、安全策略、三次 STC、写回；`plan_slots` 145 行 8 参数；`embed_slots` 11 参数；`stc.rs:213` `transfer_column` 11 参数。建议用 `HeaderPlan`/`BodyPlan`/`SlotPlan` 结构体收敛参数（PNG 侧已有 `SlotPlan`，是好例子）。
- **可见性泄漏**：`jpeg/mod.rs` 把 `dht`/`geometry`/`header_v3`/`v3_layout` 标 `#[doc(hidden)]` 但仍 `pub`；`dht::ZZ_POS`、`dht::ZIGZAG`、`v3_layout::body_grid`、`precover::dct_basis` 全部对外可访问。建议收窄为 `pub(crate)`。
- **i18n 覆盖不全**：`cli_i18n.rs:75-175` 中 `read/extract --auto`、`embed --no-filename`、`embed/capacity --seed` 无对应 `Msg`，中文模式下仍是英文 help；`("write","no-encrypt")` 映射在 `args.rs` 中不存在对应参数（死分支）；`render.rs`/`cmd_diag.rs` 中 `"Content Steganography Domain:"`、`OK/FAIL`、`Risk/verdict/ALERT` 等均未 i18n。
- **测试盲区**：759 个测试覆盖了往返、参数校验、畸形输入不 panic（如 `truncated_boxes_are_errors_not_panics`、`fully_illegal_cover_is_an_error_not_a_silent_noop` 等写得很好）。但**缺少**这几类：(a) 恶意 wire 超参的 DoS 用例（B3/M44 正是这类）；(b) chi2/RS/SPA 在**真实自然图像**上的判别力用例（现有人造分布测不出 M44）；(c) PE codebits 在含内联跳转表的 `.text` 上的行为用例（B2）。

---

## 六、已核实为无问题的重点项（避免误报）

以下各项经逐行核对**确认正确**，列出以免后续重复排查：

- **STC 核心算法**：`u=1` 快路径状态机推导正确（`want = state_0 ^ col_0·parity`，`col_0` 恒为 1 由 `from_seed_grouped` 强制）；`extract` 的 `row = b + (h-1)` 与 embed 的 `row = g - (h-1)` 互逆，行窗口 `[(r-h+1)u, (r+1)u)` 边界安全（即使 n 非 u 倍数也不越界）；`row_syndrome`、`transfer_column` 索引、`back` 位图回溯均不越界；AVX2 gather 的 `(i^block)+(j^lane_xor) == (i+j)^d` 等价性成立。
- **PNG embed/extract 对称性**：`slots_for_codec` → `body_slots_upto` → `permute_indices` 两端一致；`extract` 只用 LSB 重算 `Hx`，不依赖代价图（代价图在 stego 上重算也是 bit-identical，因为 header/feature 像素永不离开其八值类）。±1 在 0/255 的回绕被 `[8,247]` + 八值类规则**结构性排除**。
- **JPEG 对称性**：`permute_prefix` ≡ `fisher_yates_prefix_from(0,k)` + 续接（`prng.rs:471` 有等价性契约测试）；`parity_carrier` 2/3 与 `read_bits` 的 `&1` 等价；`fill_body_grid → permute_prefix → truncate` 顺序两侧逐行一致。DC 不进网格（`format.rs:340` 校验 `k_min>=1`）。
- **HEVC CABAC 状态污染**：引擎只翻转 `BinOp::is_stego()` 的 bypass bin，HEVC 的 `DecodeBypass` 不改变 `ivlRange`，故后续 decision bin 状态不受影响，码流仍可解。设计成立。
- **HEVC sign data hiding**：已核对 fork（`residual.rs:522-523/577/597`）—— `nsigns = nsig - 1` 时只为 `k < nsigns` 上报 `record_stego_sign`，隐藏符号不在 bin 流里、不进池；且隐藏符号由 `sum_abs` 奇偶决定，**不依赖**其他符号位。无问题。
- **structure 域无损还原**：`write_core` 在注入前记录 `orig_host_size` / `orig_host_sha256`（覆盖全文件含尾部与 overlay）；`remove` 的两条公开入口都在 rename 前调用 `verify_restored` 并用 `?` 传播，mismatch 时不提交、不改原文件；`write_core` 还有写入后自检（反向 locate 定位不到即中止）。**三条路径的对称性成立**。
- **PE codebits 注入失败不留损坏 PE**：`embed`（`pe_codebits.rs:545-575`）中途 `Err` 时只修改了内存中的 `text` 副本，`copy_with_patches` 尚未执行。
- **PDF 增量更新 dirty tail 可逆**：`inject` 把 `%%EOF` 之后的原始字节原样追加，`inject_size` 恰好等于新写入字节数，默认 `strip` 的 `[0,inject_offset) + [inject_offset+inject_size,EOF)` 可完整还原。
- **ZIP/PNG/RIFF/WAV/WebP 的 `patch_offset` ↔ stripped 坐标转换**：均用 `checked_*`，无溢出/回绕。
- **加密分层**：`make_chunk_nonce` 用 XOR 注入 chunk index（XOR 是单射，故 nonce 互不重复）；`make_meta_nonce` XOR `0xFFFF_FFFF` 与 chunk 0 不冲突（需 i = 4294967295 才碰撞，2 MB 块下对应 8 PB）；chunk AAD 含 `chunk_index` 与 `is_last`，故重排/截断均被 AEAD 拒绝。
- **ChaCha12 KAT（Strombergson TC1）、Fisher-Yates 无偏拒绝采样**（`2^32 % b` / `2^64 % b`）实现正确。

---

## 七、修复优先级建议

### P0 — 应立即修复（安全 / 数据损坏）

1. **B1** `read` 路径解压上限自引用 → 加 `min(raw_size, MAX_VERIFY_PAYLOAD_SIZE)`
2. **B2** `pe_codebits` 代码/数据不分 → 先加 section characteristics 校验 + `.reloc` 排除；在危害确认前考虑默认关闭该策略
3. **B3** PNG 提取不校验 wire 超参 → 覆盖后调用 `validate()`，统一 wire 上限为 63
4. **B4** CWD 隐式配置可注入凭据 → 隐式配置中忽略 `password`/`password_file`

### P1 — 本迭代修复（正确性 / 静默失败）

5. **M30** `MIN_UBE_PLAIN` 常量与实现脱钩（容量虚报）
6. **M31** `write` 路径缺覆盖写保护
7. **M10** `class_rule` 未校验（静默 AEAD 失败）
8. **M2 / M3** HEVC `window_slices` u16 截断、`has_inter` 取样不一致（静默误报）
9. **M38** PE 重复注入检测漏判（破坏 100% 还原）
10. **M44 / M45** analysis 卡方归一化 + 检测器未运行应报 SKIPPED 而非 PASS
11. **M18** JPEG 量化表按 `Tq=0` 硬取（安全性下降）
12. **M46** `overlay:high-entropy` 对压缩容器系统性误报

### P2 — 排期修复（性能 / 内存）

13. **M23** STC 回溯位图上限从 4 GiB 降到 256–512 MiB + `try_reserve`
14. **M4 / M5** HEVC `band_slots` 只写不读（省 272 MB）、容器重复解析
15. **M12 / M14 / M15** PNG `Vec` 预分配、提前退出、layout 复用
16. **M13 / M20** PNG 代价、JPEG precover 并行化
17. **M17 / M21 / M22** JPEG verify 三次解码、预算漏算、无用 clone
18. **M35 / M36** `read_core` 流式化、`remove` 复用 `UnpackSecrets`
19. **M34 / M40 / M47** 三处无界/放大 DoS（JAR EOCD、PDF scan window、PNG IHDR）

### P3 — 技术债（架构）

20. 四个上帝文件拆分（见 §5.1）
21. 死代码清理（`is_epb_safe_flip`、`body_grid`、`extract_hevc_record`、`track_content_domain`、`trace`）
22. 重复实现合并（EPB 排除逻辑、极化代价、第二套 sniff、默认密钥常量）
23. 注释与实现不符的逐项订正（§4.2）
24. i18n 补齐（§5.2）
25. 补充 §5.2 列出的三类测试盲区用例

---

## 八、附：审查执行记录

- **编译与门禁**（2026-10-29 实测，工作区干净、git `8042ba2`）：
  - `cargo fmt --check` → 通过（exit 0）
  - `cargo clippy --all-targets --all-features -- -D warnings` → **0 警告**（exit 0，耗时 31 s）
  - `cargo test --all-features --all-targets` → **759 通过 / 0 失败 / 21 ignored**（耗时约 31 s；`local_` 语料测试按 AGENTS.md 约定以 `--ignored` 单独运行，本次未跑，因依赖 gitignored 的本地语料）
- **已人工复核的关键行**（非仅凭子代理报告）：`structure/engine.rs:1557-1563 & 1592-1611`、`structure/envelope.rs:402-407`、`:86`、`:189-211`、`engine.rs:1014-1023`、`stego/png/engine.rs:1597-1606`、`stego/hevc/engine.rs:915-975`、`hevc/slot.rs:249-254`、`stego/coding/stc.rs:242/580/722-736`、`stego/params.rs:432/442`、`stego/envelope.rs:87` vs `header.rs:35`、`analysis.rs:1666-1681`、`core/config.rs:93-101 & 137-142`、`pe_codebits.rs:192-240`
- **未做实测而标注为"待确认"的项**：B2 触发概率、M1 触发概率、M19 `dct-io` 网格分配、M54 H.264 误判、M43 SPA 取根规则
