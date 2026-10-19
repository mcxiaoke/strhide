# strhide Rust 实现深度代码审查报告

- **审查日期**：2026-10-19
- **审查基线**：`rust/` 当前工作树（最近提交 `b09d240`，含后续未提交改动）
- **审查范围**：`rust/src` 全部 8,972 行源码（19 个文件）+ `rust/tests` 7,289 行（20 个测试目标、188 个用例）+ 构建/静态检查 + 定向黑盒复现
- **审查方法**：逐文件通读 → 构建与静态检查（`cargo test` / `clippy --all-targets` / `fmt --check`）→ 针对可疑路径用 release 二进制做最小复现实验 → 结论分级
- **python/ 目录按项目约定冻结，不在本次审查范围**

---

## 0. 质量基线（先说结论）

| 检查项 | 结果 |
|---|---|
| `cargo test` | **188 / 188 通过**（20 个测试目标全部 ok） |
| `cargo clippy --all-targets` | **0 警告** |
| `cargo fmt --check` | **通过** |
| release 二进制 | 1,143,296 B（静态单文件，`target/release/strhide.exe`） |
| 测试样本 | 26 个真实文件（mp4/png/jpg/pdf/zip/apk/exe），覆盖 7 种载体 |

**总体评价**：这是一个工程成熟度明显高于同类隐写工具的代码库。分层清晰（`cli → engine → adapter/envelope/crypto`）、错误处理统一（`StrHideError` 单一错误类型 + 退出码约定）、可逆性承诺有端到端验证（写入后自检、剥离后 SHA-256 比对）。测试数量充足且全部通过。

但通读 + 实测仍然发现了 **2 个可复现的 P1 级缺陷、4 个 P2 级健壮性问题**，以及若干安全边界/设计层面值得改进的点。核心缺陷集中在**"stealth（口令掩码）与结构校验的交互"**和**"适配器解析器的窗口假设"**两条主线上。

---

## 1. 缺陷清单（按严重度）

### P1-1 ｜ MP4 `verify` 对 `stealth + eof` 合法载体误报 Level 1 结构损坏

- **位置**：`adapters/mp4.rs:27-52`（`trailing_envelope_len`），影响 `verify_structure`
- **现象（已复现）**：对一个 MP4 执行 `write -s eof --stealth -p pw` 后，`verify -p pw` 报告：

```
Level 1 (Host Format):      [FAIL] Box ?r at offset 1008404 extends past end of file
Level 2 (Envelope Boundary): [PASS] Envelope valid at offset 1008404, size 220B (CRC32 OK)
Level 3 (Crypto & Payload):  [PASS] Decryption and SHA-256 verified successfully
```
退出码 1；但 `read` 完全正常、`remove` 后 SHA-256 与原文件 100% 一致。**文件本身完全合法，verify 误报。**

- **根因**：stealth 模式会对信封 trailer 的 CRC32 做口令掩码（`trailer_crc32 = raw_crc ^ mask`）。而 `trailing_envelope_len` 用 `crc32fast::hash(&tail[0..16])` 与明文 CRC 比对来判断"文件尾部是否恰好是一个 strhide 信封"。掩码后比对必然失败 → box 树遍历把信封开头的 8 字节口令派生 magic 当作 box 头（size 字段为垃圾大数）→ 判定"box 越过文件末尾"。
- **影响范围**：这是 **MP4 独有**的问题——只有 MP4 的 `verify_structure` 会主动走到文件末尾并尝试判定尾部附加区。PNG/JPEG/PDF/ZIP/PE 的 Level 1 校验都不触及 EOF 附加区。`stealth + box_uuid`（MP4 的 auto 路径）不受影响（已验证 3 级全 PASS）。
- **修复建议**（两选一）：
  1. **架构级**：`Adapters::verify_structure` 增加密码/期望 trailer magic 上下文（引擎侧本来就有密码），让 CRC 校验改用掩码后的期望值——这也是最干净的做法；
  2. **降级容忍**：当"尾部 24 字节解析出 `ube_offset + ube_total_size == 文件大小` 且 `ube_offset == 当前遍历位置`"但 CRC 不匹配时，不直接报损坏，而是报告"疑似口令保护的附加信封，L2 将用密码校验"。这样 L1 不误杀、也不放行任意垃圾尾。

### P1-2 ｜ PNG `chunk`/`auto` 策略无法处理超过 64KB 的"脏尾"

- **位置**：`adapters/png.rs:18`（`let scan_len = std::cmp::min(total_size, 64 * 1024);`）
- **现象（已复现）**：在 IEND 之后追加 128KB 任意字节（合法 PNG + 脏尾），`write -s chunk` 与 `write`（auto，小载荷自动选 chunk）均失败：

```
[ERROR] Corrupted data: Valid PNG IEND chunk not found within tail scan window
```
同一文件用 `-s eof` 可正常写入。这说明"脏尾容忍"的宣称只在 ≤64KB 尾部数据下成立。

- **影响**：真实世界的 PNG 常携带大于 64KB 的尾部数据（水印、ICC 大块、第三方元数据、反爬垃圾尾）。此类文件的默认写入路径（auto）直接失败，用户只能手动指定 eof 或裁掉尾部。
- **修复建议**：扫描窗口自适应增长——先扫尾部 64KB，未命中则翻倍并前移窗口，直至全文件；或对 PNG 直接全文件扫描（PNG 体积通常可接受）。成本是定位 IEND 的复杂度从 O(64KB) 升到 O(n)，但换来行为与宣称一致。

### P2-1 ｜ PE `-s eof` 写入后 `locate` 恒归类为 `pe_overlay`（策略归因失真）

- **位置**：`adapters/pe.rs:365-372`
- **机制**：`locate` 的分支条件是 `trailer.ube_offset >= pe_info.pe_image_end` → `pe_overlay`。而 PE 的 eof 注入位置是 `host_len`（文件末尾），恒有 `host_len >= pe_image_end`，因此 **`eof` 分支永远不可达**。实测：`write -s eof` 后 `inspect` 报告 `Strategy: pe_overlay`。
- **影响**：无功能影响——两种策略的注入与剥离实现逐字节相同（保留前 `inject_offset` 字节），strip 分支对二者一致。但 `inspect`/审计输出与用户指定的策略不一致，属于元数据失真；`verify` 输出同样如此。
- **修复建议**：要么按信封头的 `strategy_id` 归因（注入时写的就是 eof），要么接受现状并文档化"PE 上 eof 与 pe_overlay 等价"。推荐前者，一行改动。

### P2-2 ｜ ZIP `strip` 在 debug 构建下可触发 u64 下溢 panic

- **位置**：`adapters/zip.rs:323-324`
- **机制**：`bytes_before_patch = (header.patch_offset as u64) - (header.inject_offset + header.inject_size)`。`patch_offset` 是 u32，损坏或被篡改的信封头若使 `patch_offset < inject 区末尾`，debug 构建（`cargo test`、`RUST_BACKTRACE` 场景）会 **panic**；release 构建下回绕成巨数，循环会吞掉剩余全部流再补写 4 字节补丁值，产出错误文件——该文件随后会被载荷 SHA-256 校验拦截并报失败，因此不会静默产生错误还原，但行为不可预期。
- **触发面**：信封头字段无 AEAD 保护（见 §3.3），因此任何能篡改载体文件的攻击者（或部分损坏）都能构造这个输入。ZIP 定位器对 EOCD 有 CRC 校验，但 strip 阶段直接信任 header 字段。
- **修复建议**：`checked_sub` 并在失败时返回 `StrHideError::CorruptedData`（与其他损坏输入处理一致）。同时建议把这类算术约束检查纳入 fuzz 输入生成（见 §4.7）。

### P2-3 ｜ `read` 提取会静默覆盖已存在的同名文件

- **位置**：`cli.rs:513`（`File::create(&fn_to_use)`）
- **机制**：`read` 在三种情况下落盘：未给 `-o` 且载荷为文件（写到当前目录）、`-o <目录>`、`-o <文件路径>`。前两种使用 `sanitize_filename`（防目录穿越，已正确），但**不防与现有文件同名**——直接截断覆盖。
- **影响**：从多个载体批量提取同名载荷（如多个包里的 `index.html`）或当前目录已有同名文件时，用户文件会被静默替换。这是数据丢失类问题，与整个工具"无损、可还原"的定位相悖。
- **修复建议**：落盘前检查存在性——已存在则报错并提示 `-o` 指定路径，或自动追加序号（与 `next_backup_path` 的 `.bak-<ts>` 风格一致），或提供显式 `--force`。

### P2-4 ｜ 给无加密信封传错密码时"静默成功"，无任何提示

- **现象（已复现）**：对无密码写入的信封执行 `read -p 任意错误密码`，正常返回明文、退出码 0。
- **机制**：这是设计内的——无密码模式的信封头用公开的内置密钥掩码，`unpack_with_password` 先试用户密码、失败后回退内置密钥解掩码，所以"传错密码也能读"。**行为正确，但 CLI 不提示用户"该信封未加密，密码未生效"**，容易让用户误以为 `-p` 提供了保护。
- **修复建议**：CLI 在"提供了密码但信封未加密"时输出一条 stderr 警告（与既有 warning 风格一致）。这是低成本高收益的防误导改进。

### P3-1 ｜ `--text-base64` 强制要求 UTF-8，无法承载二进制

- **位置**：`cli.rs`（`--text-base64` 分支，base64 解码后 `String::from_utf8`）
- **影响**：base64 是表达二进制的最自然途径，但该选项解码后强制 UTF-8，隐藏任意二进制数据时只能用 `-d` 文件路径。语义上自相矛盾（"base64 文本"→ 却只收 UTF-8 文本）。
- **建议**：解码后若非法 UTF-8，回退为原始字节存储（base64 本来就是字节编码）；或增加 `--text-file` 对应二进制的等价入口。注意与 `-t`（UTF-8 语义）的区分要写清楚。

### P3-2 ｜ 若干性能小项（非缺陷）

1. `config.rs` 对同一 TOML 文件解析两次（先 `Table` 校验 KNOWN_KEYS，再类型化解析）——可一次解析。
2. `preflight_batch` 打开每个载体跑适配器探测，引擎 `write_carrier` 再重复一次（打开 + 探测 + 读头）。批量场景下开销翻倍。
3. `verify` 的 L3 完整重跑 `read_carrier`（再次 PBKDF2 + 全部解密 + 解压），与 L2 的解密工作重叠。大文件 + 高迭代 KDF 下可感知。

### P3-3 ｜ `unpack_with_password` 内置密钥回退的启发式判据

- **位置**：`envelope.rs:308-309`：回退解掩码成功条件是 `version==2 && ENCRYPTED 位清空 && strategy_id<=10 && reserved==0`。
- **分析**：这是"去掩码结果是否可信"的概率性判据。对随机/损坏数据，误判概率约 2^-24 量级，且后续 `validate_against`（meta_len/hint_len/总长一致性）会兜底拒绝。**当前无实际风险**，但值得记录：判据本质上是脆弱假设，若未来信封格式扩展（如新增 flag 位、strategy_id >10），此处需同步更新。建议将"字段语义合法性"集中到 validate 阶段，解包阶段只做结构拷贝。

### P3-4 ｜ 符号链接载体行为

- 对符号链接路径执行 in-place `write`：`std::fs::absolute` 是纯词法解析，`target_path == carrier_path` 判定为 in-place → 临时文件 rename **替换链接本体**为普通文件；备份文件（`std::fs::copy` 跟随链接）保存的是目标内容。
- **结果**：链接被静默破坏，目标文件未动。行为可用但反直觉。建议文档化，或在 preflight 阶段 `canonicalize` 并显式提示。

### P3-5 ｜ 32 位 nonce 计数器的理论边界

- `make_chunk_nonce` 用 `base_nonce[8..12] ^ (chunk_index as u32)` 生成每块 nonce；元数据 nonce 用 `base_nonce[8..12] ^ 0xFFFFFFFF`。
- 数学上，当 `chunk_index == 0xFFFFFFFF` 时元数据 nonce 与块 nonce 同值。对应 2MB 块 × 4.29B = **8.6 EB** 载荷，且 `chunk_index as u32` 在更大的流上会静默回绕。现实不可达（载荷全程内存缓冲），但计数器空间只有 32 位这件事值得在代码里留注释或显式保护（如块数超限直接报错）。

---

## 2. 安全边界与设计观察

### 2.1 无密码模式的真实安全边界（文档需明示）

无密码写入时，信封元数据/载荷仍会加密，但密钥是源码中的**公开常量** `BUILTIN_DEFAULT_KEY`，头部字段用同一常量掩码。这意味着：

- 对**不懂 strhide 的第三方**：无密码模式提供的是"不可见 + 不可读"的观感（无明文痕迹、高熵密文）；
- 对**懂 strhide 的攻击者**：无密码信封可被完整解密、篡改并重算 CRC/元数据——没有任何真实性保证。

README 中"100% reversible / SHA-256 guaranteed"的表述对**意外损坏**完全成立，但对**恶意篡改**仅在加密模式下成立。建议文档明确区分这两个威胁模型，避免用户误把无密码模式当作防篡改手段。

### 2.2 KDF 强度与跨语言演进约束

`PBKDF2-HMAC-SHA256`、100,000 次迭代、随机 16B salt + 12B nonce。作为隐写工具的口令 KDF 属"可用但偏弱"：2026 年 OWASP 对 PBKDF2-SHA256 的建议迭代数已达 600,000+，且 Argon2id 是更优选择。

**约束**：python/ 已冻结为 0.2.0，跨语言信封格式必须兼容。演进路径建议：**版本化信封头**（`version` 字段已有 2 字节空间）——新写入可用 Argon2id 派生（或更高迭代数），读取侧按版本分发 KDF；旧文件保持可读。这是 P2 级改进，不破坏现有文件。

### 2.3 AEAD AAD 覆盖面（认证缺口）

`envelope::get_aad` 认证了 magic/version/flags/strategy/salt/nonce/host 大小/host SHA-256，但**不含** `inject_offset / inject_size / patch_offset / orig_patch_val / meta_len / hint_len`。这些字段被篡改时，解密层不会察觉，只能靠后续的 host SHA-256 比对或 strip 失败兜底。

对加密信封，把这些边界字段纳入 AAD 的成本为零（AAD 由本文件写入时生成），收益是**解密前**即可拒绝篡改，而不是等到剥离后才发现文件不一致。建议纳入。对无密码信封无意义（密钥公开，AAD 不防懂行攻击者）。

### 2.4 内存模型

write/read 全链路内存缓冲：原始载荷 + 压缩缓冲 + 密文缓冲 + 完整信封 + 解密缓冲 + 解压结果，峰值约为载荷大小的 **3–6 倍**。文档已承认（"R7 partial"）。对几百 MB 级载荷可接受，GB 级会有压力。**read 路径最值得先流式化**：`解密 → 解压 → SHA-256` 可以设计成单通道管道（chunk 边界与压缩块边界都是流式的，改动集中在 `decrypt_stream_from_chunks` 与 `DecompressStream` 的接线）；write 路径至少把压缩缓冲改成真流式（`DeflateEncoder::new(Vec::new(), …)` 目前先整体收集再写出）。

### 2.5 解析器健壮性（fuzz 缺口）

7 类格式解析器（PNG chunk 扫描、ZIP EOCD 两遍扫描、MP4 box 树遍历、JPEG marker 扫描 + 多段链追踪、PDF trailer 窗口扫描、PE 头解析、信封 unpack/去掩码）全部是手写容错解析。当前 188 个测试覆盖了正常路径与常见损坏，但**没有任何 fuzz / property 测试**。

结合 P2-2（ZIP strip 下溢）可见：这类手写解析器在"畸形但不致命的输入"下最容易暴露算术越界/panic。建议：
- 接 `cargo-fuzz`（至少覆盖 `envelope::unpack` / `unpack_with_password` / `compact_meta`、ZIP EOCD 解析、MP4 遍历、PNG 定位、JPEG 定位、PDF trailer 扫描）；
- 或先用 `proptest` 对"随机字节 → 各适配器 locate/verify 不 panic"做快速覆盖。

### 2.6 `verify` 三层语义的强度不均衡

- L1 在各适配器间差异大：PNG 全 chunk CRC 最强、MP4 全 box 树其次、PDF/JPEG/PE 只查关键标记、ZIP 只查 EOCD。对"诊断型"工具可接受，但文档对 L1 的承诺宜措辞为"关键结构标记检查"而非"结构完整性"。
- L3 失败不改变退出码（与 Python 一致）是有意的，但脚本使用者容易忽略——CLI 已有明确 stderr 提示，建议 README 再强调一次。
- P1-1 暴露的问题说明：**L1 需要密码上下文**才能正确判定 stealth 附加区，这是 `verify_structure` trait 签名层面的欠账。

---

## 3. 更优方案与演进建议

### 3.1 策略路由（`choose_auto_strategy`）增强

现状是按 ube_size 粗略决策（PNG >2GB→eof、JPEG >64MB→eof、MP4 恒 box_uuid、ZIP 按 4GB 补丁头）。建议注入**结构感知**：

- PNG：脏尾 >64KB 时直接选 eof（规避 P1-2）；
- JPEG：检测到已有多个 APP15/APP 段且剩余空间不足时明确报错或回退 eof；
- MP4：box 树完整则 box_uuid，存在可疑尾部则提示。

不需要引入"最优策略搜索"，在 `capacity/available` 信息之外加两个布尔结构信号即可。

### 3.2 批量操作的事务化

`write/remove -c a b c` 目前"任一失败即停"，前面已处理的载体保持修改状态。建议两段式：
1. **预检阶段**：全部载体的格式/信封占用/容量/输出路径冲突检查（复用 `preflight_batch`，已经做了一半）；
2. **提交阶段**：通过预检后再逐个写入。

这样容量不足、已含信封、目标不可写等"可预知失败"不会造成半批生效。`--continue-on-error` 可作为可选项。注意 `read`/`inspect` 已有 per-carrier 汇总输出，语义上对齐即可。

### 3.3 提取覆盖保护（与 P2-3 配套）

统一落盘策略：默认拒绝覆盖 → 提供 `--overwrite` 或自动加序号。命名规则与备份后缀（`.bak-<ts>`）保持一致，降低用户心智负担。

### 3.4 ZIP64 与 4GB 上限

`patch_offset`/`orig_patch_val`/各 offset 的 u32 字段将 ZIP 策略限制在 4GB 内（`eof` 不受限）。这是协议级演进点：若目标场景需要大 ZIP，应在 v2.x 版本化信封头中引入 64 位字段变体，且**必须双语言同步**（python 解冻或接受 rust 先行的跨版本只读兼容）。

### 3.5 熵整形 / 反取证（文档已列为后续，补充方案选项）

密文高熵断层对统计检测是当前最可感知的暴露面。可选方案：
- **4b/5b 或类 Base32 编码**嵌入：把载荷扩张 25%，换统计上与宿主噪声接近的字节分布；
- **伪随机填充混合**：载荷按比例与宿主无关的 PRNG 流混合，破坏"均匀随机"指纹；
- **分段注入 + 分散**：把载荷切块分散到多个允许区（JPEG 多段、PE 多 slack 区）。

三者都不影响无损还原（信封自描述），但都会改变文件大小/布局，需与"格式保持"的目标权衡；建议先做 4b/5b 的容量-安全折中评估。

### 3.6 工程基建

- **CI 门禁**：当前三个 workflow（crates.yml/pypi.yml/release.yml）都没有 `test + clippy + fmt` 门禁。建议给 release.yml 增加 pre-built 前的质量关卡（cargo test、clippy -D warnings、fmt --check），否则"release 二进制"与"仓库测试状态"可能脱节。
- **依赖漏洞**：建议 `cargo audit` 或 `cargo deny` 入 CI；当前依赖集（aes-gcm/pbkdf2/hmac/sha2/flate2/crc32fast 等）较稳，但门禁应自动化。
- **测试缺口补全**：P1-1、P1-2、P2-1、P2-2 目前**均无回归测试**（这正是它们活到现在的部分原因）。另补：MP4 64-bit box 分支、ZIP >4GB 边界、PNG 脏尾 >64KB、JPEG 多段链、PE codebits 的极小/极大 slack。

---

## 4. 逐模块简评

| 模块 | 行数 | 评价 |
|---|---|---|
| `engine.rs` | 1,707 | 核心编排扎实；exact size 预计算 + 写入后自检是好设计。偏大，建议按 write/read/remove/verify 拆文件 |
| `cli.rs` | 984 | 参数语义清晰、批量汇总输出好；覆盖保护（P2-3）与 base64 语义（P3-1）待修 |
| `pe_codebits.rs` | 1,407 | 复杂度最高的适配器；masked channel header + legacy magic 兼容做得很细 |
| `envelope.rs` | 444 | 掩码/去掩码与 AAD 设计成熟；启发式判据（P3-3）与 AAD 覆盖面（§2.3）可改进 |
| `crypto.rs` | 535 | 分块 AEAD + 流式解压正确；计数器 32 位边界（P3-5）与压缩缓冲可优化 |
| `adapters/*` | 144–1,407 | 解析器总体严谨；P1-1（mp4 394）、P1-2（png 360）、P2-1（pe 628）、P2-2（zip 367）集中于此 |
| `rejection.rs` / `config.rs` / `router.rs` / `errors.rs` | — | 拒绝检查覆盖面好（含签名 PE 探测、写探针）；无大问题 |

---

## 5. 优先级路线图

| 优先级 | 事项 | 理由 |
|---|---|---|
| **P0（立即）** | 修复 P1-1（MP4 stealth+eof verify 误报）、P1-2（PNG 脏尾窗口），并为二者补回归测试 | 两个都是"合法输入被拒绝/误判"的确定性缺陷，影响脚本化使用 |
| **P1（近期）** | P2-1 策略归因、P2-2 ZIP checked_sub、P2-3 提取覆盖保护、P2-4 未加密警告；CI 加 test/clippy/fmt 门禁；接入 fuzz/proptest 骨架 | 低成本高收益，补齐可信度与健壮性 |
| **P2（中期）** | AAD 纳入边界字段；KDF 升级（版本化信封 + Argon2id 或更高迭代）；read 路径流式化；批量两段式提交 | 安全与体验的实质提升，需双语言协调 |
| **P3（长期）** | ZIP64；熵整形/反取证；策略路由结构感知；engine.rs 拆分 | 面向更大规模与更强对抗场景 |

---

## 附录 A：复现实验记录

环境：Windows 11 + `target/release/strhide.exe`（1.1 MB，当前工作树构建）。

**A1｜P1-1 MP4 stealth+eof verify**（`temp/review/m1.mp4`，源自 `file-00.mp4`）
```
write -c m1.mp4 -t secret1 --stealth -p pw123 -s eof   → OK
verify -c m1.mp4 -p pw123                              → Level1 FAIL（见 §P1-1），exit 1
read -c m1.mp4 -p pw123 --stdout                       → secret1（正常）
remove -c m1.mp4 -p pw123                              → SHA-256 100% 还原，exit 0
对照组：write -s box_uuid（auto）+ stealth 的 verify 三级全 PASS。
```

**A2｜P1-2 PNG 脏尾 >64KB**（`temp/review/p1.png` / `p2.png`，源自 `file-02.png`，IEND 后追加 128KB）
```
write -s chunk → [ERROR] Corrupted data: Valid PNG IEND chunk not found within tail scan window（exit 1）
write（auto）   → 同上（小载荷 auto 选 chunk）
write -s eof    → OK
```

**A3｜P2-1 PE 策略归因**（`temp/review/e1.exe`，源自 `caffeine64.exe`）
```
write -s eof → inspect 显示 Strategy: pe_overlay（eof 分支不可达）
```

**A4｜P2-4 无密码信封 + 错密码**（`temp/review/q1.mp4`）
```
write（无密码）→ read -p wrongpass --stdout → 正常输出明文，exit 0
```

**A5｜测试与静态检查**
```
cargo test        → 20 目标 / 188 用例全部 ok，exit 0
cargo clippy --all-targets → 0 警告
cargo fmt --check  → 通过
```

---

## 附录 B：验证环境

- 样本：`temp/testfiles/` 26 个文件（mp4/png/jpg/pdf/zip/apk/exe），含真实签名 PE（`cc-switch.exe` 等）
- 复现产物：`temp/review/`（可删除）
- 本次审查不修改任何源码；所有结论均可在当前工作树复现
