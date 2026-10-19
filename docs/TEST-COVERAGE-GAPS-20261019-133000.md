# strhide (Rust) 测试覆盖缺口分析报告

- 生成时间：2026-10-19 13:29:58
- 分析范围：`rust/src/`（engine / cli / config / envelope / crypto / rejection / adapters）对照 `rust/tests/` 与 `rust/src/**` 内置单元测试
- 现状基线：`cargo test` 实测 **138 项全部 PASS，0 失败**（16 个测试目标：库单测 + 15 个集成测试文件）
- 方法：逐文件阅读源码与测试，对每个候选缺口用源码引用（`文件:行`）与测试引用双向核对；未运行动态覆盖率工具（如 llvm-cov），结论均为静态核对结果

> 说明：本报告只做“缺口定位与分析”，未改动任何代码。缺口按影响面与可测性分级：P0 为数据安全/正确性相关，P1 为对外接口行为，P2 为内部/边缘分支。

---

## 一、结论速览

整体覆盖度较高：核心 `write → read → inspect → verify → remove` 全链路、加密/隐身去指纹化、批量载体、驳回检查、真实样本生命周期、PE codebits 信道等均有端到端测试。

仍存在以下**关键未覆盖点**（共 12 组，按优先级排序）：

| # | 优先级 | 未覆盖功能点 | 位置 |
|---|--------|--------------|------|
| 1 | P0 | 载荷来源 `--text-file` / `--text-base64` / `STRHIDE_TEXT` 环境变量 | `rust/src/cli.rs:379-407` |
| 2 | P0 | 口令来源 `--password-file`（CLI 与 config 两处） | `rust/src/cli.rs:212-238` |
| 3 | P1 | `verify` 的“无信封”“L3 需口令跳过”分支 | `rust/src/engine.rs:1457-1475,1585-1590` |
| 4 | P1 | 写入“体积膨胀 >50%”告警文案 | `rust/src/engine.rs:722-737` |
| 5 | P1 | config 键 `stealth/backup/unescape/preserve_time/hint/password_file` 与 `~/.strhide/config.toml` 发现路径 | `rust/src/config.rs:31-67` |
| 6 | P1 | CLI `inspect --json` / `verify --json` 输出路径 | `rust/src/cli.rs:552-554,627-629` |
| 7 | P1 | `--strategy ask` 单载体交互选择路径 | `rust/src/cli.rs`（ask 分支） |
| 8 | P1 | MP4 64 位 large-size（`size==1`）box 定位分支 | `rust/src/adapters/mp4.rs:170-250` |
| 9 | P1 | ZIP 补丁偏移 >4GB 溢出保护 | `rust/src/adapters/zip.rs:196` |
| 10 | P2 | PNG 写入侧无 IEND 报错、2GB 容量上限报错 | `rust/src/adapters/png.rs:112-116` |
| 11 | P2 | JPEG 多段链超容量报错、PDF `calc_prefix_len` 与多次增量更新 | `jpeg.rs:275-277`、`pdf.rs:245` |
| 12 | P2 | 写入侧结构可疑告警仅覆盖 PNG（jpeg/pe/mp4 未覆盖） | `adapters/{jpeg,pe,mp4}.rs` |

---

## 二、详细分析

### 1. 载荷来源分支（P0）

`rust/src/cli.rs:375-413` 定义了 6 种载荷来源，测试覆盖不对称：

```text
--stdin           → 测试覆盖（batch_cli.rs:116 多载体 stdin 只读一次）
-d/--data         → 测试覆盖（batch_cli.rs:154）
-t/--text         → 大量覆盖
--text-file       → 未覆盖（测试中无任何引用）
--text-base64     → 未覆盖（含非法 base64、非 UTF-8 解码失败两个错误分支）
STRHIDE_TEXT 环境  → 未覆盖（测试只做 .env_remove("STRHIDE_TEXT")）
```

- 证据：`grep --text-file|--text-base64|STRHIDE_TEXT rust/tests` 仅命中 `batch_cli.rs` 的 `env_remove`，无正向用例。
- 风险：`--text-base64` 的 base64 解码与 UTF-8 校验错误分支一旦回归，用户拿到的是静默失败或错误信息不准。
- 建议用例：
  - `--text-file` 读取含中文/Emoji 的文件并往返；
  - `--text-base64` 合法（含 UTF-8 中文）与非法（坏 base64、非 UTF-8 字节）两组；
  - `STRHIDE_TEXT` 环境变量作为唯一载荷来源，以及与 `-t` 同时存在时的优先级。

### 2. 口令来源 `--password-file`（P0）

`resolve_password`（`rust/src/cli.rs:202-254`）的优先级为：
`-p` → `--password-file` → `STRHIDE_PASSWORD` → `config.password` → `config.password_file`。

- 已覆盖：`-p`、`STRHIDE_PASSWORD`、`config.password`（`config_cli.rs:98-192`）。
- 未覆盖：`--password-file`（CLI）与 `config.password_file` 两条分支，包括文件尾部 `\r\n` 修剪（`:215`、`:236`）与读文件失败错误（`:214`、`:230`）。
- 建议用例：写一个 `pwd.txt`，用 `--password-file` 写入并读取；文件带尾随换行验证被 trim；`config.password_file` 生效；文件不存在时报错且不崩溃。

### 3. `verify` 的非正常分支（P1）

`verify_carrier`（`rust/src/engine.rs:1428-1608`）有若干早退分支，测试目前只覆盖“正常信封 + 篡改头/CRC/版本/元数据长度”。

- **无信封分支**（`:1457-1475`）：`level2 = "No envelope found"`、`level3 = "Skipped (no envelope)"`，且 `level1` 结果原样返回。未覆盖。
- **L3 跳过分支**（`:1574-1590`）：加密信封但无口令时 `l3 = false`，文案 `"Password required for cryptographic verification"`。测试中所有 `level3_crypto` 断言均为 `ok == true`，从未断言该跳过路径（`grep cryptographic rust/tests` 无命中）。
- 建议用例：对一个干净 PNG 调用 `verify_carrier`，断言 L1 ok、L2 false、L3 "Skipped"；对加密信封不带口令 verify，断言 L3 detail 含 `Password required` 且退出码为 0（仅报告，见 `p2_cli.rs` #15 语义）。

### 4. 体积膨胀告警（P1）

`rust/src/engine.rs:722-737`：当信封体积 > 载体体积 50% 时生成 `"...exceeds 50.0% of carrier file size..."` 警告，并与结构告警合并。

- `grep inflation|50.0% rust/tests` 无命中，完全未覆盖。
- 现有唯一告警测试是 PNG 的“疑似已有信封”结构告警（`fixes_regression.rs:399`），未触及比例告警，也未验证两条告警的**合并文案**（`:737` 的 `join("; ")`）。
- 建议用例：用极小 PNG + 较大载荷触发 >50%，断言 `WriteResult.warning` 含 `50.0%`；再构造“既有旧信封又膨胀”的场景验证两条信息合并。

### 5. 配置文件的键与发现路径（P1）

`rust/src/config.rs` 有 9 个键，`config_cli.rs` 仅覆盖 `strategy`、`encrypt`、`password` 与未知键告警。

- 未覆盖键：`stealth`、`password_file`、`hint`、`preserve_time`、`backup`、`unescape`（对应 `cli.rs:392`、`:426-428` 的取值逻辑）。
- 未覆盖路径：`~/.strhide/config.toml` 发现分支（`config.rs:60-67`）。测试虽设置了 `USERPROFILE/HOME`，但只在当前目录写 `strhide.toml`，从未在该 home 下建 `.strhide/config.toml`。
- 未覆盖：隐式候选文件“存在但不可读”时的硬错误分支（`config.rs:104-109`，与 NotFound 跳过逻辑相区分）。
- 建议用例：
  - 分别注入 `stealth=true` / `backup=false` / `unescape=true` / `preserve_time=false` / `hint=...`，断言实际行为变化；
  - 写 `<USERPROFILE>/.strhide/config.toml` 验证 home 发现；
  - 造一个目录冒充 config 文件，验证报 `Failed to read config file`。

### 6. CLI JSON 输出（P1）

`rust/src/cli.rs:552-554`（inspect）、`:627-629`（verify）通过 `serde_json::to_string_pretty` 打印。

- 测试中 `pe_codebits.rs:615-629` 是对 `InspectResult` 结构体做 serde（库层），**没有**通过二进制用 `inspect --json` / `verify --json` 断言 stdout 是合法 JSON 且字段完整。
- 建议用例：CLI 加 `--json` 后 `serde_json::from_str(stdout)` 成功，并断言关键字段（`format`、`strategies`、`level1_host` 等）。

### 7. `--strategy ask` 单载体交互（P1）

- 已覆盖：**多载体**时拒绝 `ask`（`batch_cli.rs:237`，报 `multiple carriers`）。
- 未覆盖：**单载体** `--strategy ask` 的交互式选择流程（读 stdin 序号，`cli.rs:359` 附近）与非法输入重试。
- 说明：非 TTY 环境下可部分测试（通过管道喂入序号 / 非法值），属于可测但未测。

### 8. MP4 64 位 large-size box（P1）

`mp4.rs:170-250` 的定位逻辑分别处理 32 位 header 与 `size == 1` 的 64 位 large header（32 字节头，读 `largesize`）。

- p2_fixes 的 MP4 测试（`:339-422`）全部使用普通 32 位 box；真实样本 `sample.mp4` 走的是常规路径。
- 64 位分支（写入 `mp4.rs:114` 与定位 `:235-241`，含 `Truncated 64-bit size` 错误）未覆盖。
- 建议用例：手工合成带 `size==1 + largesize` 的 uuid box 载体，验证 `locate`/`open_ube_reader` 正确；以及截断的 64 位头报错。

### 9. ZIP >4GB 溢出保护（P1）

`zip.rs:196`：补丁偏移超出 u32 时报 `"...(>4GB) ... Please specify --strategy eof."`。

- 测试中 ZIP 只覆盖常规与 eof 回退（`fixes_regression.rs:651`），无溢出消息断言。因需 >4GB 载体，实际可用“区间构造/单元级调用”验证。

### 10. PNG 写入侧错误分支（P2）

`png.rs:112-116`：`Payload size ... exceeds PNG chunk maximum capacity (2GB)` 与 `find_iend_offset` 失败（无 IEND）。

- 已覆盖：**verify** 侧缺 IEND（`p2_fixes.rs:301`）。
- 未覆盖：**write** 侧缺 IEND 的错误、以及 2GB 容量上限报错。

### 11. JPEG / PDF 内部路径（P2）

- `jpeg.rs:275-277`：多段链超 `JPEG_MAX_TOTAL_CAPACITY` 的报错未覆盖（`fixes_regression.rs:747` 的 `exceeds maximum` 属于其它格式）。另 `partition_jpeg_payload_lengths`（`jpeg.rs:79`）中“剩余 <24 字节”的特殊分支未单独覆盖。
- `pdf.rs:245` `calc_prefix_len` 无直接单测；PDF 仅覆盖单次增量更新（`real_samples.rs:296` 与 rejection 用例），**多次连续增量更新**后的读取/还原未覆盖。
- 已覆盖的反而是较难的路径：JPEG legacy COM 兼容（`jpeg_multisegment.rs:150`）、PDF 脏尾（`fixes_regression`）。

### 12. 写入侧结构可疑告警的格式覆盖（P2）

`suspicious_structures` 在 png/jpeg/pe/mp4 四个适配器均实现，但测试只覆盖 **PNG**（`fixes_regression.rs:399`）。jpeg/pe/mp4 的“疑似已有信封”告警未覆盖。虽触发条件（注入的未知魔数信封）构造成本较高，仍建议各补一个。

---

## 三、已确认“无需补测/不可测”的项（避免重复投入）

- **交互式口令提示** `prompt_password`（`cli.rs:185-200`）：依赖 TTY，非 TTY 路径已由“no interactive terminal”错误覆盖（`fixes_regression.rs:236-259`）。`IsTerminal` 双真分支不做自动化测试属合理取舍。
- **备份冲突带时间戳**：已覆盖（`p2_cli.rs:493-525`，`.bak` → `.bak-<stamp>`）。
- **临时文件清理**：已覆盖（`fixes_regression.rs:776`，`*.strhide.tmp` 残留断言）。
- **权限/时间保留**：`permissions_preserved_on_write` 已覆盖（`fixes_regression.rs:754`）；`--no-preserve-time` 仅断“标志被接受”（`:263`），实际时间戳未保留这一**副作用**未断言，可作为低优先补充项。
- **历史魔数兼容**：`\x89STRHIDE`/`STH!` 未加密兼容（`stealth_defingerprinting.rs:314`）、未掩码 stealth 兼容（`:133`）、PE `STHC`/`STH!` 兼容（`pe_codebits.rs:810`）均已覆盖。
- **真实样本生命周期**：样本目录 `temp/real_samples/` 实际存在（apk/jpg/mp4/pdf/png/zip + 两个签名 EXE），因此 `real_samples.rs` 的 7 项**会真实执行**而非跳过；其中已含签名 APK/PE 驳回与五种格式全链路逐比特还原。
- **PE codebits**：信道掩码、legacy STHC、容量上报、PE32/PE64、降级 pe_overlay、双写拒绝、损坏拒绝等已覆盖（`pe_codebits.rs` 23 个用例），覆盖度是全部适配器中最高的。

---

## 四、建议的补测优先级与工作量

1. **第一批（P0，必补）**：#1 载荷来源三分支、#2 `--password-file`/`config.password_file`。
2. **第二批（P1，建议补）**：#3 verify 两个跳过分支、#4 膨胀告警、#5 config 键与 home 发现、#6 CLI `--json`。
3. **第三批（P1/P2，按需）**：#7 `ask` 单载体、#8 MP4 64 位 box、#9 ZIP >4GB、#10/#11 适配器报错分支、#12 其它格式结构告警。
4. **低优先**：`--no-preserve-time` 的实际时间戳断言。

预计第一批 6~8 个用例、第二批 8~10 个用例即可将上述关键缺口基本补齐；均可复用现有 `scratch()` + `env!("CARGO_BIN_EXE_strhide")` 的测试范式，无需改动生产代码。

---

## 五、附：核对证据索引

| 缺口 | 源码位置 | 交叉核对（测试中缺失） |
|------|----------|------------------------|
| `--text-file`/`--text-base64`/`STRHIDE_TEXT` | `cli.rs:379-407` | `grep` 无正向用例 |
| `--password-file`/`config.password_file` | `cli.rs:212-238` | `config_cli.rs` 全读无该分支 |
| verify 跳过分支 | `engine.rs:1457-1475,1585-1590` | `grep cryptographic rust/tests` 无命中 |
| 膨胀告警 | `engine.rs:722-737` | `grep inflation\|50.0%` 无命中 |
| config 键/home 发现 | `config.rs:31-67` | `config_cli.rs` 仅 3 键 |
| CLI `--json` | `cli.rs:552-554,627-629` | 测试均走结构体 serde |
| MP4 64 位 box | `mp4.rs:170-250` | MP4 测试均 32 位 box |
| ZIP >4GB | `zip.rs:196` | 无溢出断言 |
| PNG write 无 IEND / 2GB | `png.rs:112-116` | 仅有 verify 侧缺 IEND |

---

# 追加分析：口令 × 隐身 × 策略 × 文件类型 矩阵覆盖

- 追加时间：2026-10-19 13:29:58 之后的同一轮分析
- 触发问题：“现有的各种 password / stealth / strategies / filetype 矩阵组合都有测试覆盖吗？”
- 结论：**没有**。每个格式的“默认 auto 策略 + 完整生命周期”基本都有，但四个维度的笛卡尔组合存在成片缺口。

## 六、矩阵维度定义（均来自源码核对）

| 维度 | 取值 | 源码位置 |
|------|------|----------|
| 文件类型 | PNG / JPEG / MP4 / ZIP / PDF / PE | `router.rs` `ADAPTERS` |
| 策略 | `chunk` / `app_segment` / `box_uuid` / `pre_cd_inject` / `incremental` / `pe_codebits` / `pe_overlay` / `eof` | 各 adapter `supported_strategies()` |
| 口令 | `Some(pwd)` 显式加密 / `None` 走 `BUILTIN_DEFAULT_KEY` 默认密钥 | `engine.rs:97-99`、`cli.rs:319-325` |
| 隐身 | `stealth=false` / `true`（true 隐含需要口令） | `cli.rs:314-325` |

说明：`eof` 是全部 6 种格式都支持（`supported_strategies` 均含 `eof`）的兜底策略，因此单独作为一列统计。

## 七、覆盖矩阵

图例：✅ 已覆盖；⚠️ 弱覆盖（仅单测 `inject`、或 `let _ = write` 不校验、或仅 write+verify 半链路）；❌ 缺失。

| 格式 | auto 默认策略 | 显式非-eof 策略 | 显式 eof | pwd=Some | pwd=None | stealth=true |
|------|---------------|------------------|----------|----------|----------|--------------|
| PNG | `chunk` ✅ | `chunk` ⚠️仅 `p2_fixes.rs:241` 单测 inject | ✅ `p2_protocol.rs:65`、`pe_codebits.rs:515` | ✅ | ✅ `stealth_defingerprinting.rs:257,409` | ✅ |
| JPEG | `app_segment` ✅ | `app_segment` ⚠️仅 `fixes_regression.rs:785` 且丢弃结果 | ❌ | ✅ | ❌ | ❌ |
| MP4 | `box_uuid` ✅ | `box_uuid` ❌ | ❌ | ✅ | ⚠️仅 write+verify `p2_fixes.rs:401` | ❌ |
| ZIP | `pre_cd_inject` ✅ | `pre_cd_inject` ❌ | ✅ `fixes_regression.rs:660` | ✅ | ✅ | ✅ `unicode_and_binary.rs:353` |
| PDF | `incremental` ✅；eof 回退 ✅ | `incremental` ✅ `p2_protocol.rs:164` | ❌（仅 auto 回退 `p2_protocol.rs:136`） | ✅ | ✅ `p2_protocol.rs:105` | ❌ |
| PE | `pe_codebits` ✅ / `pe_overlay` ✅ 回退 | `pe_codebits` ✅；`pe_overlay` ❌ | ❌ | ✅ | ✅ `pe_codebits.rs:269` | ⚠️仅 codebits `pe_codebits.rs:209` |

## 八、缺口明细（追加，编号接续前文）

### 13. `eof` 策略仅覆盖 3/6 格式（P1）

- 覆盖：PNG（`p2_protocol.rs:56`、`pe_codebits.rs:505`）、ZIP（`fixes_regression.rs:651`）、PDF 仅作为 `incremental` 失败后的 auto 回退（`p2_protocol.rs:136`）。
- 缺失：**JPEG + eof、MP4 + eof、PE + eof** 无任何用例。`eof` 是每格式的兜底分支，却只测了一半。

### 14. 显式指定策略的端到端用例不足（P1）

- 有显式 `strategy:"..."` 且跑完 write→read→remove 的仅：`pe_codebits`、`incremental`、`eof`。
- 缺失/弱覆盖的显式策略：`chunk`（仅单测 inject）、`app_segment`（`fixes_regression.rs:785` 处 `let _ = write_carrier(...)` 丢弃返回值、不断言）、`box_uuid`、`pre_cd_inject`、`pe_overlay`（仅作为 auto 回退命中，`pe_codebits.rs:265`）。
- 影响：除 PE 外，各格式基本只验证了 auto 选中的那一条策略；`engine.rs:669` 的策略能力校验、`strategy_note` 生成、显式策略传参等路径缺少回归。

### 15. `stealth=true` 仅覆盖 3/6 格式（P1）

- 覆盖：PNG（`stealth_defingerprinting.rs`、`p2_cli.rs:217`、`password_hint.rs:107`、`fixes_regression.rs:368`）、ZIP（`unicode_and_binary.rs:353`）、PE（`pe_codebits.rs:209`）。
- 缺失：**JPEG、MP4、PDF 的 stealth 全生命周期**。这三类恰好是真实业务中最可能使用的载体，且去指纹化在不同 adapter 的 `locate()` / 尾标魔数路径上实现不同，风险最高。

### 16. 无口令默认密钥路径（pwd=None）分布不均（P1/P2）

- 覆盖：PNG、ZIP、PDF、PE。
- 缺失：**JPEG 无口令完全无用例**；**MP4 无口令只测了 write+verify**（`p2_fixes.rs:401`），无 read/remove 还原验证。

### 17. 维度交叉项全缺（P2）

- `stealth + eof`、`stealth + 非 auto 策略`、`stealth + pwd=None`（应被拒绝，拒绝逻辑目前只在 PNG 验证，`fixes_regression.rs:217`）。
- `password_hint` 只在 PNG 上测过（`password_hint.rs`），其余 5 种格式未覆盖。
- `inspect_carrier` 的字段级断言只在 PNG/PE（`real_samples.rs:124`、`pe_codebits.rs:615`），JPEG/MP4/ZIP/PDF 无直接断言。

## 九、覆盖较好的部分（避免重复投入）

- 6 种格式**都至少有一条** auto 策略的 write→(inspect/)verify→read→remove 逐比特还原路径（`real_samples.rs` + 各专项）。
- PE 是策略维度覆盖最高的适配器：`pe_codebits`/`pe_overlay`、32/64 位、stealth、密文、容量边界、降级回退均有（`pe_codebits.rs` 23 用例）。
- 去指纹化、历史魔数兼容、驳回、批量载体、错误分支均有专门测试。

## 十、矩阵补测优先级（追加）

1. **P1**：`stealth × {JPEG, MP4, PDF}` 各一条全生命周期。
2. **P1**：`eof × {JPEG, MP4, PE}` 各一条。
3. **P1**：显式非默认策略 `chunk` / `box_uuid` / `pre_cd_inject` / `pe_overlay` 各一条 write→read→remove。
4. **P2**：`pwd=None × JPEG` 全链路、`pwd=None × MP4` 的 read/remove。
5. **P2**：交叉项 `stealth+eof`、`stealth` 下 `pwd=None` 的多格式拒绝、非 PNG 格式的 `password_hint`。

建议将现有各格式 lifecycle 测试改造为表驱动（遍历 `(format, strategy, password, stealth)`），比逐条堆用例更省维护成本。

## 十一、矩阵分析证据索引（追加）

| 缺口 | 交叉核对（测试中缺失/弱覆盖） |
|------|------------------------------|
| JPEG/MP4/PE 的 `eof` | `grep strategy: "eof"` 仅命中 PNG/ZIP 用例 |
| 显式 `chunk`/`box_uuid`/`pre_cd_inject`/`pe_overlay` | 测试中无对应 `strategy:"..."` 正向断言（`pe_overlay` 仅 auto 回退命中） |
| JPEG/MP4/PDF 的 `stealth=true` | `grep stealth: true` 仅命中 PNG/ZIP/PE 用例 |
| JPEG 的 `pwd=None` | JPEG 相关用例全部为 `password: Some(...)` |
| MP4 的 `pwd=None` read/remove | 仅 `p2_fixes.rs:401` write+verify |

---

# 实施结果（2026-10-19 14:23:44）

按本报告优先级补测完毕，测试总数 **138 → 190（+52）**，全绿；期间修复 3 处真实缺陷。

## 十二、新增测试文件与覆盖的缺口

| 文件 | 项数 | 覆盖的缺口编号 |
|------|------|----------------|
| `rust/tests/cli_sources.rs` | 20 | #1（`--text-file`/`--text-base64`/`STRHIDE_TEXT`，含非法 base64、非 UTF-8、`-t` 优先级、空环境变量）、#2（`--password-file` 与 `config.password_file`，含换行修剪、文件缺失、CLI 覆盖 config）、#5（config 键 `unescape`/`backup`/`hint`/`password_file`、`<home>/.strhide/config.toml` 发现、cwd 优先、不可读 config 硬报错） |
| `rust/tests/verify_and_cli_output.rs` | 16 | #3（verify "无信封"与"L3 需口令跳过"两分支，及 L3 失败不改变退出码）、#4（>50% 膨胀告警及其与结构告警的合并）、#6（`inspect --json`/`verify --json` schema、`[auto preference]` 标记）、#7（`--strategy ask` 单载体交互，越界/非数字/空输入回退） |
| `rust/tests/matrix_lifecycle.rs` | 14 | #13（`eof` 全 6 格式）、#14（显式 `chunk`/`app_segment`/`box_uuid`/`pre_cd_inject`/`incremental`/`pe_overlay`/`pe_codebits`）、#15（stealth 全 6 格式）、#16（`pwd=None` 全 6 格式的完整 read/remove）、#17（`stealth+eof`、非 PNG 格式 hint、stealth/hint 守卫的六格式遍历、二次写入拒绝、各格式容量表与纯净宿主 L1） |

矩阵文件为表驱动：每格统一执行 write → inspect → verify(L1/L2/L3) → read → remove → 逐比特还原，因此任一操作在该组合下的缺口都会被捕获。

## 十三、由新测试暴露并已修复的真实缺陷

1. **MP4 `verify_structure` 对 `eof` 策略必然判失败**（`adapters/mp4.rs`）
   - MP4 是唯一遍历完整 box 树的适配器；`eof` 按定义在最后一个 box 之后追加原始 UBE 流，前导字节不是 box 头，L1 恒报 `"extends past end of file"`。而 `eof` 是该适配器 `supported_strategies()` 声明支持、CLI 会列出且允许显式指定的策略——即"写得出、校验必挂"。
   - 修复：新增 `Mp4Adapter::trailing_envelope_len`，当剩余区域**恰好是一个信封**（尾标边界自洽 + CRC32 通过，无需口令）时停止遍历并判为合法，对齐 PNG 在 IEND 处的行为；真正损坏的 box 仍照常报出（`p2_fixes.rs` 4 个 MP4 检测用例保持通过）。
   - 过程中纠正了一个自身疏漏：helper 内 `seek` 改变流位置，必须复位游标。

2. **MP4 `suspicious_structures` 对 stealth 信封永远失效**（`adapters/mp4.rs`）
   - 注释宣称"不检查魔数，未知密码的 stealth 信封也能被结构检出"，但代码先做裸 CRC32 早退判断；stealth 用密码派生掩码异或了尾标 CRC（`envelope.rs:create_stealth`），该校验必然失败并提前返回，注释承诺的能力实际失效。
   - 修复：移除该 CRC 校验，只保留边界校验 + strhide uuid 命名空间判定。

3. **`--password-file` 读文件失败时错误信息不含路径**（`cli.rs`）
   - `resolve_password` 的 CLI 分支只给裸 OS 消息，而 config 分支已带路径，多命令共用该参数时用户无从判断是哪个文件。修复后与 config 分支措辞对齐。

## 十四、发现但未修改的既有设计行为（非缺陷）

- **PE 的 `eof` 与 `pe_overlay` 写入结果字节相同**，均追加在 PE 镜像之后，`PeAdapter::locate` 按 `offset >= pe_image_end` 一律报告为 `pe_overlay`。数据无损，仅策略名与写入时不同。测试改为断言数据完整性并注明该歧义。
- **ZIP / PDF 未实现 `suspicious_structures`**（用 trait 默认空实现）；**PE 的实现只识别尾部 overlay**，而 stealth `pe_codebits` 写在 `.text` 内不产生 overlay。因此这些组合下 stealth 无密码读取不会附带引导信息，属设计默认，测试按各适配器实际能力分别断言。

## 十五、仍未覆盖（需更大代价，本次未做）

- MP4 64 位 large-size（`size==1`）分支：需构造 >4GB 载体或直接单测 `locate`，未做。
- ZIP >4GB 溢出保护（`zip.rs:196`）：需 >4GB 载体。
- PNG 写入侧 2GB 容量报错、JPEG 多段链超容量报错：需构造 GB 级载荷。
- `pdf.rs:calc_prefix_len` 直接单测、PDF 多次连续增量更新。
