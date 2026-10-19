# 两份审查报告的核实结果与修复优先级

- **核实时间**：2026-10-19 21:31（本机时间）
- **核实基线**：`HEAD = 7c73704` + 工作树未提交改动（只有 `list-strategies → list` 重命名与 README 文案，与两份报告结论无关）
- **核实方法**：逐条定位源码 → 用当前工作树构建的 `strhide 0.3.0`（1,333,248 B）做定向复现 → `cargo test --release` 全量跑一遍
- **测试基线**：`cargo test --release` → **219 passed / 23 个测试目标 / 0 失败**（两份报告写的 188/188 是旧基线，之后新增了 `pe_slack`、`batch_corpus` 等用例；这不影响结论有效性）
- **被核实的文档**：`docs/DEEP-CODE-REVIEW-20261019.md`、`docs/CODE-REVIEW-20261019-150434.md`

---

## 1. 总体结论

**两份报告的可信度很高：没有发现凭空编造或严重失实的结论。**

| 类别 | 数量 | 说明 |
|---|---|---|
| 属实且已实机复现 | 17 | 输出的错误/行为与报告描述逐字一致 |
| 属实（代码确证，未实机复现） | 19 | 依赖 ACL、非 UTF-8 路径、debug 构建、控制台代码页等条件 |
| 表述不准确 / 严重度偏差 | 6 | 见 §3，均不影响"要不要修"的判断（其中 5 条主体仍然成立） |
| 完全不成立 | 0 | — |
| 两份报告均未覆盖的新问题 | 1 | PE padding 非零告警在正常 PE 上误报（见 §2.3） |

两点需要强调：

1. **没有发现会导致"静默错误还原"的缺陷。** 最接近的是 ZIP `strip` 的 u64 下溢（P2-2），release 下会产出错误文件，但随后被载荷 SHA-256 拦下并报失败——报告对此的判断是准确的。
2. **两份 P1 都是真缺陷，但不是"数据损坏"，而是"合法输入被误判/误拒"**：MP4 `stealth + eof` 的 L1 假阳性、PNG >64KB 脏尾导致 chunk 策略硬失败。

---

## 2. 逐条核实

### 2.1 报告一（DEEP-CODE-REVIEW）

| 编号 | 结论 | 核实证据 |
|---|---|---|
| P1-1 MP4 `stealth+eof` verify L1 误报 | **属实，已复现** | `write --stealth -p pw123 -s eof` 后 `verify` 输出 `[FAIL] Box ?r at offset 1008404 extends past end of file`，L2/L3 PASS，exit 1；`read` 正常输出明文。根因双重：`mp4.rs:52` 用裸 `crc32fast` 比对，而 stealth 的 trailer CRC 被口令掩码（`envelope.rs:357-370`），且 trailer magic 本身也由口令派生（`engine.rs:617-619`），`verify_structure` 无口令 → 必然识不出。对照组：`box_uuid + stealth` 三级全 PASS；`eof` 不带 stealth 也全 PASS。 |
| P1-2 PNG >64KB 脏尾 | **属实，已复现** | IEND 后追加 128KB 后 `write -s chunk` 与 `write`（auto）均报 `Valid PNG IEND chunk not found within tail scan window`；`png.rs:18` 写死 `min(total_size, 64*1024)`。 |
| P2-1 PE `-s eof` 归因成 pe_overlay | **属实，已复现** | `inspect` 输出 `Strategy: pe_overlay`；`pe.rs:432-441` 的 `ube_offset >= pe_image_end` 分支在 `eof` 分支（455 行）之前，而 `eof` 的注入点就是 `host_len`，恒满足前者 → `eof` 分支不可达。 |
| P2-2 ZIP u64 下溢 | **属实（代码确证）** | `zip.rs:323-324` 直接 `(patch_offset as u64) - (inject_offset + inject_size)`，无 `checked_*`。信封头字段不在 AAD 内（`envelope.rs:148-160` 只有 80 字节），篡改可达。 |
| P2-3 提取静默覆盖同名文件 | **属实，已复现** | 预先放好 `target/important.txt`（内容 `KEEP-ME-ORIGINAL`），`read -o target` 后被替换为载荷内容，无任何提示（`engine.rs:1134`、`cli.rs:547` 均为裸 `File::create`）。 |
| P2-4 无密码信封传错密码静默成功 | **属实，已复现** | 无密码写入后 `read -p totallywrong --stdout` 输出明文、exit 0。属设计内行为（`envelope.rs:303-326` 内置密钥回退），缺的只是提示。 |
| P3-1 `--text-base64` 拒绝二进制 | **属实，已复现** | `AP8B/g==`（字节 00 FF 01 FE）报 `Base64 content is not valid UTF-8`。**注意**：`tests/cli_sources.rs:147-162` 有测试锁定该行为，改动需同步改测试与文档。 |
| P3-2.1 配置解析两次 | 属实 | `config.rs:65-72` 先 `toml::Table` 再反序列化。 |
| P3-2.2 批量预检重复探测 | 属实 | `cli.rs:919-922` 打开并 `find_adapter_or_reject`，`write_carrier` 内再探测一次。 |
| P3-2.3 verify L3 "重跑 read_carrier" | **不准确** | L3 走 `open_ube_reader` + 解密（`engine.rs:1480+`），并没有再调 `read_carrier`；L2 本身不含 KDF，因此也不存在"与 L2 重叠的 PBKDF2"。它是"与一次 read 等价"的工作量，属必要成本。 |
| P3-3 内置密钥回退判据脆弱 | 属实 | `envelope.rs:318-322` 的 `version/flags/strategy_id/reserved` 概率判据，表述准确。 |
| P3-4 符号链接 in-place 行为 | 属实 | `engine.rs:881`、`1268` 用 `std::path::absolute` 做词法比较，链接路径与目标路径字符串相等 → 判为 in-place → rename 替换链接本体。 |
| P3-5 32 位 nonce 计数器 | 属实 | `crypto.rs:105-121`，`chunk_index as u32` 与元数据 `^ 0xFFFFFFFF`；8.6 EB 不可达，属注释/防御级别。 |
| §2.1 无密码模式安全边界 | 属实 | `crypto.rs:21` 常量 `BUILTIN_DEFAULT_KEY` 为公开字符串，文档确实需要区分威胁模型。 |
| §2.2 KDF 100k 迭代 | 属实 | `crypto.rs:16` `PBKDF2_ITERATIONS = 100_000`。 |
| §2.3 AAD 缺边界字段 | 属实 | `envelope.rs:148-160` 的 80 字节 AAD 不含 `inject_offset/inject_size/patch_offset/orig_patch_val/meta_len/hint_len`（`pack()` 把它们放在 80..112）。 |
| §2.5 无 fuzz/property 测试 | 属实 | `rust/` 下无 `fuzz/`、无 `proptest/arbitrary` 依赖。 |
| §2.6 L1 强度不均衡 | 属实 | JPEG 只查 SOS（`jpeg.rs:531-544`）、ZIP 只查 EOCD、PNG 全 chunk CRC——差异与报告描述一致。 |

### 2.2 报告二（CODE-REVIEW-150434）

| 编号 | 结论 | 核实证据 |
|---|---|---|
| A-1 CI 无质量门禁 | **属实，已核实** | `rg -n "cargo (test\|clippy\|fmt\|audit)" .github` 零命中；三个 workflow 只有构建/发布。 |
| A-2 写探针查的是载体目录 | 属实（代码确证） | `engine.rs:521` 传 `carrier_path`，`rejection.rs:296` 在 `path.parent()` 建探针；真实临时文件建在 `target_path` 旁（`engine.rs:761`）。ACL 实验因 `icacls` 参数失败未能实机复现，但代码路径唯一、结论确定。 |
| A-3 配置 `hint` 阻断 `--stealth` | **属实，已复现** | `strhide.toml: hint="my usual one"` + `--stealth -p pw123` → `[ERROR] Password hint is not supported in --stealth mode`；去掉 `--config` 即成功（`cli.rs:467`）。 |
| A-4 `remove` 忽略 `backup` 配置 | **属实，已复现** | `write` 在 `backup=false` 下不产 `.bak`，`remove` 仍产出 `b1.jpg.bak`（`cli.rs:572` 漏了 `cfg.backup`）。 |
| A-5 提示含单引号被截断 | **属实，已复现** | `-H "Bob's usual one"` → `read` 打印 `[INFO] Password hint: s usual one`（`cli.rs:512`）。 |
| A-6 控制台非 ASCII 乱码 | 属实（环境相关） | `png.rs:75` 的 `≤`、`cli.rs:647/749` 的 `—`、`rejection.rs:99` 整条中文消息。在 936 代码页的 conhost 下会乱码；Windows Terminal(UTF-8) 正常。严重度应为 P3 而非 P2。 |
| A-7 MP4 首 box 白名单 | **属实，已复现** | `styp`/`moof` 开头的合法 BMFF 均报 `Unsupported format`（`mp4.rs:80`）。 |
| A-8 `-o` 目录/不存在父目录裸错误 | **属实，已复现** | `-o 'nope\o3.mp4'` → `I/O error: 系统找不到指定的路径。(os error 3)`；单载体 `-o outdir` → `拒绝访问。(os error 5)`。`batch_output_dir` 在 `!multi` 时直接 `return Ok(None)`（`cli.rs:868-870`）。 |
| A-9 解压无上限 | **属实，已复现** | 8 MiB 全零载荷 → UBE 仅 8,381 B（1000:1）；`crypto.rs:364-383` 无 limit，`engine.rs:1106` 解到 `Vec`。 |
| A-10a PE 重复 profile | 属实 | `parse_channel_header` 内部已 `profile()`（`pe_codebits.rs:537`），调用方再算一次（551/570/682）。 |
| A-10b 探针残留 | 属实 | 探针名仅含 PID（`rejection.rs:296`），被强杀时残留。 |
| A-11 `patch_offset + 4` u32 溢出 | 属实 | `zip.rs:339`；与 P2-2 是不同表达式，修一处不覆盖另一处——此判断正确。 |
| A-12 `display()` 构造备份路径 | 属实 | `engine.rs:444/455/457/463`。 |
| A-13 PDF/ZIP 无 `suspicious_structures` | **属实，已复现** | 两次 stealth 写入 PDF/ZIP 均无 WARNING；PNG/JPEG/MP4 有。默认实现返回空（`adapters/mod.rs:196-198`）。 |
| A-14 `MIN_UBE_*` 硬编码 | 属实（影响偏小） | `envelope.rs:47-49`；但 `tests/compact_meta.rs:51` 已断言真实最小尺寸 219，能兜住大部分漂移（余量 10 字节，仍不严密）。 |
| A-15 解元数据失败全映射为 Password | 属实 | `crypto.rs:156`。 |
| A-16 膨胀告警文案自相矛盾 | **属实，已复现** | 67 B 载体输出 `exceeds 50.0% ... (67 bytes, 319.4%)`（`engine.rs:727`）。 |
| A-17 两点已核查无问题 | 属实 | `strip_codebits` 的 `validate_header` 约束成立；`read_at` 越界被 `read_exact` 拦住。 |
| D-1 "或任意文件" | 属实 | `README.md:3`、`README.zh.md:3`、`lib.rs:4` 与 `router.rs:9-16` 的显式拒绝冲突。 |
| D-2 跨语言互操作表述 | 属实 | `README.md:12` 仍宣称双向可读；`:102` 只说 `pe_codebits` 例外，与实际格式分叉不符。 |

### 2.3 两份报告都未覆盖的新问题（N-1）

**PE "非零 padding" 告警/检测在正常 PE 上误报。**

- **现象**：对语料中**未经修改**的 `caffeine64.exe` 写入时提示 `[WARNING] Carrier shows structures that only a hidden envelope would produce (224 non-zero bytes in PE section padding ...)`；`scan` 同文件报 `[LOW] risk 25/100` 与 `pe:nonzero-padding`。`UnRAR.exe` 同样命中（392 B）。语料中 6 个可写入的 PE 里 2 个误报（`DontSleep.exe`、`LiveUpdate.exe` 因带签名被拒绝，未计入）。
- **根因**：`pe.rs:558-569` / `analysis.rs:529-543` 假定"链接器会把 section padding 填零"。实测 `caffeine64.exe` 在 `[433440, 433664)` 有 **224 字节连续非零块**（正好是 slack 区间尾部），违反该前提。`pe_slack` 的真实信封也确实写在这类区间（实测写入偏移 370424），因此"非零字节数 ≥ 178"这个判据无法区分二者。
- **影响**：不损坏数据，但对一个主打隐蔽性的工具，在普通 exe 上给出"只有隐藏信封才会产生此结构"的断言会持续误导用户，并污染 `scan` 的风险评分。

---

## 3. 需要修正的报告表述（不影响修复清单）

1. **P3-2.3**：verify L3 并未"完整重跑 `read_carrier`"，也未与 L2 重复 KDF；它只是完成了一次必要的解密+解压。
2. **P3-1 的建议**："或增加 `--text-file`"——`--text-file` 已存在（文本语义），有效建议只剩"让 base64 允许非 UTF-8"；且现有测试锁定了拒绝行为，属设计取舍而非纯缺陷。
3. **P2-1 的"一行改动"**：`locate` 拿不到信封头，而 `strategy_id` 只有写入方向的 `strategy_to_id`（`engine.rs:679`），没有反向映射。要按 strategy_id 归因，需要新增 id→名字映射并在 inspect/verify 层覆盖，约 20-30 行，不是一行。
4. **A-7 的第二个建议**："只要 box size 自洽且 type 是 4CC 就认为 ISO-BMFF" 会把大量普通二进制识别成 MP4，与 `router.rs` 的"未识别一律拒绝"原则冲突。应只做白名单扩展。
5. **A-14 的"只会静默失准"**：`tests/compact_meta.rs:51` 已断言真实最小信封 = 219 B，能拦住大部分布局漂移，表述过强。
6. **A-6 的严重度**：受控制台代码页影响，属显示层问题，P3 更合适。

---

## 4. 修复方案与优先级

排序标准：**改动小 × 收益大 ÷ 风险低**。P0 全部是"单点、几行、不改协议、不改 CLI 契约"的修复。

### P0｜当天可合并（每项 ≤ 10 行，几乎零风险）

| # | 问题 | 改法 | 规模 | 风险 | 验证 |
|---|---|---|---|---|---|
| 1 | P1-1 MP4 `stealth+eof` L1 误报 | 删掉 `mp4.rs:52-54` 的裸 CRC 早退，改为"CRC 命中即接受，否则回落到边界判定"（`ube_offset == offset && ube_offset + total == file_size`）。这与同文件 `suspicious_structures`（`mp4.rs:376-379`）**已有的做法完全一致**，不是新判据 | ~5 行 | 极低：边界等式随机满足的概率可忽略，L2/L3 仍会兜底；L1 本来只负责宿主格式 | 回归测试：`stealth+eof → verify` 三级全 PASS；再补一条"普通 eof 尾部垃圾仍报 L1 FAIL" |
| 2 | P2-2 + A-11 ZIP 算术 | `zip.rs:323` 改 `checked_sub().ok_or(CorruptedData)`；`zip.rs:339` 改 `patch_offset.checked_add(4)` | ~8 行 | 极低 | 单测：篡改 `patch_offset` 后返回 `CorruptedData` 而非 panic |
| 3 | A-4 `remove` 忽略 `backup` | `cli.rs:572` → `!args.no_backup && cfg.backup.unwrap_or(true)` | 1 行 | 极低 | 现有 `config_cli` 加一条用例 |
| 4 | A-5 提示被单引号截断 | `cli.rs:510-514` 改 `msg.split_once("Hint: '")` + `rsplit_once("'.")`（引擎文案固定以 `'.` 结尾） | 2 行 | 极低 | 用 `Bob's usual one` 做用例 |
| 5 | A-3 配置 hint 阻断 stealth | `cli.rs:467`：`stealth && args.hint.is_none()` 时不再取 `cfg.hint`；显式 `-H` + `--stealth` 才报错 | 3 行 | 低：只影响配置默认值路径 | 两条用例（配置来源静默忽略 / 显式给出仍报错） |
| 6 | A-16 膨胀告警文案 | `engine.rs:727` 去掉"exceeds 50.0%"的硬编码断言，改为"占比 X%，超过 50% 告警阈值" | 2 行 | 极低 | 已有 `size_inflation_warning_*` 两条测试顺带覆盖 |
| 7 | A-7 MP4 首 box 白名单 | `mp4.rs:80` 扩到 `{ftyp, styp, moov, moof, mdat, free, skip, wide, uuid, pdin, sidx, emsg}` | 1 行 | 极低（纯放宽，`verify_structure` 仍做全树校验） | 用 `styp`/`moof` 最小 BMFF 做用例 |
| 8 | A-12 备份路径用 `display()` | `engine.rs:444-466` 改用 `OsString::push(".bak")` / `".bak-<ts>"` | ~8 行 | 极低 | 现有备份用例 + 一条非 UTF-8 路径用例（Linux CI） |
| 9 | A-6 非 ASCII 输出 | `≤` → `<=`、`—` → `-`（`png.rs/pe.rs/mod.rs/jpeg.rs/zip.rs/cli.rs`），`rejection.rs:99` 中文改英文 | 6 处字符串 | 低：无测试断言这些字符 | 跑一遍 `cargo test` |

**建议一次提交（或按 1–3、4–9 两次），全部带回归测试。** P0 修完，用户可见的"误判 + panic + 静默覆盖邻近风险"就清零了。

### P1｜本轮迭代（小改，高收益）

| # | 问题 | 改法要点 | 规模 | 风险 | 收益 |
|---|---|---|---|---|---|
| 10 | P2-3 提取覆盖同名文件 | 落盘前 `if path.exists() → Err(Rejection(...))`，提示用 `-o` 或新增 `--overwrite`；引擎与 CLI 兜底分支都要加 | ~15 行 | 低：默认变"拒绝"是行为变更，脚本需知会；用 `--overwrite` 保平滑 | 消除唯一一类**数据丢失**风险 |
| 11 | P1-2 PNG IEND 64KB 窗口 | `find_iend_offset` 改为**分块流式**扫描全文件（64KB 缓冲 + 11 字节重叠，记录最后一次命中）。12 字节 `IEND_FULL` 模式随机误命中概率可忽略；内存恒定 | ~20 行 | 低：语义与现在"取最后一次命中"等价，只是去掉窗口上限 | 让"脏尾容忍"名副其实；auto 策略不再直接失败 |
| 12 | A-9 解压无上限 | `decompress_stream(reader, writer, limit)`，`read_carrier` 传 `meta.raw_size`，超限返回 `CorruptedData` | ~10 行 | 低：额外读一次上限参数；注意 `raw_size` 本身来自元数据，仅作资源保护不作信任判据（SHA-256 仍校验） | 堵住压缩炸弹，对不可信载体是必要防御 |
| 13 | A-8 `-o` 语义不一致 | `batch_output_dir`：`!multi` 且 `path.is_dir()` 时返回 `Some(path)`（与 batch/read 对齐）；`File::create(tmp)` 失败包装成 `Rejection("No write permission on target directory ...")` | ~15 行 | 低 | 消除裸 OS 错误与本地化中文泄漏 |
| 14 | A-2 + A-10b 探针 | 探针建在 `target.parent()`（给 `run_all_rejection_checks` 加 `target` 参数），文件名带 PID+随机数，失败也 `remove_file` | ~10 行 | 低 | 同时解决误拒、错误目录、残留三个问题 |
| 15 | P2-4 未加密却传了密码 | `ReadResult` 加 `is_encrypted`（唯一构造点 `engine.rs:1145`，加字段安全）；`handle_read` 在 `password.is_some() && !is_encrypted` 时 `eprintln!` 警告 | ~12 行 | 低 | 去掉"以为加了密"的误导 |
| 16 | A-1 CI 门禁 | 新增 `.github/workflows/ci.yml`：`fmt --check` / `clippy -D warnings` / `test --locked` / `audit`；`crates.yml`、`release.yml` 加 `needs` | 新文件 ~30 行 | 低（只影响流水线；首次跑 `clippy -D warnings` 可能暴露存量告警） | 让 P0/P1 的修复不再被下次打 tag 绕过 |
| 17 | N-1 PE padding 误报 | 判据从"非零字节总数"改为"能对上信封特征"：先用 `STANDARD_HEADER_MAGIC`/`LEGACY_HEADER_MAGIC` 命中做高置信；未命中时降级为措辞保守的"possible"，不再断言"only a hidden envelope would produce" | ~20 行 | 中低：需保留 stealth 场景的兜底提示 | 消除 6 个语料 PE 中 2 个的误报与 `scan` 假阳性 |

### P2｜下一迭代（中等改动，需要设计决策或更多测试）

| # | 问题 | 要点 | 风险 |
|---|---|---|---|
| 18 | A-13 PDF/ZIP 叠加无告警 | ZIP：用"最后一个 local entry 结束位置 → CD 起始位置之间出现 ≥178 B 空洞"作为结构信号；PDF：在最后一次 `%%EOF` 之后的增量更新里找 `/Length` ≥ 178 的 stream，并用其尾部 24 字节做边界等式校验（不依赖口令） | 中：两个判据都要用真实语料压测，避免重蹈 N-1 的误报 |
| 19 | A-15 错误分类 | `decrypt_metadata` 返回 `CorruptedData`，由调用方在"确实提供了密码"时映射为 `Password`；注意 `inspect_carrier` 的 `Invalid password` 分支要同步 | 中：会动到错误断言型测试 |
| 20 | A-10a PE 重复 profile | 合并 `parse_channel_header` 与紧随其后的 `profile`（同参数同结果） | 低：纯性能，先用现有 32MB PE 做基线 |
| 21 | P2-1 PE 归因 | 新增 `id_to_strategy` 反向映射，inspect/verify 用信封头的 `strategy_id` 覆盖显示；或直接文档化"PE 上 eof 与 pe_overlay 等价" | 低；收益仅为元数据准确性，可延后 |
| 22 | P3-1 base64 语义 | 二选一：允许非 UTF-8 原始字节（同步删改 `cli_text_base64_non_utf8_is_rejected`），或维持现状并在文档写清"二进制请用 `-d`" | 低，但要先定契约 |
| 23 | D-1 / D-2 / D-3 / D-4 / D-5 | 删"或任意文件"；把跨语言表述收敛为"Python 为历史留存，仅保证 Rust 读旧载体单向兼容"；补 `.bak` 与配置口令的说明 | 极低 |

### P3｜结构性，按版本推进

- 边界字段（`inject_offset/inject_size/patch_offset/orig_patch_val/meta_len/hint_len`）纳入 AEAD AAD —— 解密前即可拒绝篡改，但要双语言/版本化考虑。
- KDF 升级：版本化信封头 + Argon2id 或 ≥600k 迭代 PBKDF2。
- `read` 路径流式化（解密 → 解压 → SHA-256 单管道），`write` 侧压缩缓冲改真流式。
- fuzz/proptest 骨架（先覆盖 `envelope::unpack*`、ZIP EOCD、MP4 遍历、PNG/JPEG/PDF 定位）。
- `engine.rs`（1.7k 行）按 write/read/remove/verify 拆分。
- ZIP64、熵整形/反取证、`choose_auto_strategy` 结构感知、nonce 计数器上限保护。

---

## 5. 建议的提交切分

1. `fix(mp4,png,zip): correct stealth EOF verification, IEND window, and strip arithmetic` —— P0 的 1/2/11（同属"结构判定"簇，便于一起回归）。
2. `fix(cli): honor config backup/hint, harden hint parsing, ASCII-only output` —— P0 的 3/4/5/6/9。
3. `fix(engine): OsString backup paths, single-carrier -o dir, probe in target dir` —— P0 的 8 + P1 的 13/14。
4. `feat(extract): refuse to overwrite existing files by default` —— P1 的 10（行为变更，单独提交）。
5. `fix(crypto): bound decompression by raw_size` + `fix(read): warn when password is unused` —— P1 的 12/15。
6. `ci: add fmt/clippy/test/audit gate` —— P1 的 16。
7. `fix(pe): make padding heuristic evidence-based` —— P1 的 17（需语料回归）。

每批都建议附一条可复现的回归测试——两份报告都指出：P1-1、P1-2、P2-1、P2-2 至今没有回归测试，这正是它们存活下来的原因。

---

## 附录：本次核实用到的复现命令

环境：Windows 10 + `rust/target/release/strhide.exe`（0.3.0，当前工作树构建），样本来自 `temp/testfiles/`，产物在 `temp/verifyreview/`（可删）。

```bash
# P1-1 MP4 stealth + eof 的 L1 假阳性
strhide write -c m1.mp4 -t secret1 --stealth -p pw123 -s eof
strhide verify -c m1.mp4 -p pw123        # Level 1 FAIL, exit 1
strhide read  -c m1.mp4 -p pw123 --stdout

# P1-2 PNG >64KB 脏尾
python -c "d=open('p1.png','rb').read(); open('p2.png','wb').write(d+b'\0'*131072)"
strhide write -c p2.png -t x -s chunk    # IEND not found within tail scan window

# P2-1 PE 归因
strhide write -c e1.exe -t x -s eof
strhide inspect -c e1.exe                # Strategy: pe_overlay

# P2-3 提取覆盖
strhide write -c c.png -d important.txt
strhide read  -c c.png -o target         # target/important.txt 被静默替换

# P2-4 无密码信封 + 错密码
strhide write -c n1.png -t plaintext
strhide read  -c n1.png -p totallywrong --stdout   # 输出明文，exit 0

# A-3 / A-4 / A-5 / A-7 / A-8 / A-16
strhide write -c c1.png -t x --stealth -p pw123 --config hint.toml   # 被配置 hint 阻断
strhide remove -c b1.jpg --config nobak.toml                          # 仍产出 .bak
strhide write -c h1.png -t secret -p pw123 -H "Bob's usual one"
strhide read  -c h1.png                                               # hint: s usual one
strhide inspect -c frag.mp4                                           # styp 开头被判不支持
strhide write -c o3.mp4 -t x -o 'nope\o3.mp4'                         # os error 3（本地化）
strhide write -c tiny.png -t x                                        # exceeds 50.0% ... 319.4%

# A-9 压缩比
python -c "open('zeros.bin','wb').write(b'\0'*8388608)"
strhide write -c z1.png -d zeros.bin -p pw     # 8 MiB -> UBE 8,381 B

# A-13 PDF/ZIP 叠加无告警
strhide write -c s.pdf -t one --stealth -p pw1 && strhide write -c s.pdf -t two --stealth -p pw2

# N-1 正常 PE 误报
strhide scan -c caffeine64.exe     # [LOW] pe:nonzero-padding，文件未做任何修改

# 基线
cargo test --release               # 219 passed / 23 targets / 0 failed
```
