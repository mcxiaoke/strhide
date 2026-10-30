# strhide `rust/` 代码审查报告（第二轮）

- 审查时间：2026-10-30 19:59（本机时间）
- 基线：`HEAD 031c4bb`，`strhide v0.8.1`
- 对照：`docs/CODE-REVIEW-dsf-20261029.md`、`docs/comprehensive_code_review_g4.md`、`docs/FIXPLAN-20261029.md`
- 构建状态：`cargo clippy --all-targets --all-features -D warnings` **零警告**
- 审查方式：分模块静态通读 + 逐条回源码复核。**本报告只收录我亲自读过源码并确认的条目**；无法静态闭环的标「待实测」。未改动任何代码。

## 0. 结论摘要

> **处理状态（2026-10-30 21:12 更新）**：本报告 29 条已修复 23 条，6 条主动搁置（理由见文末「7. 处理状态」）。提交：`caeafa2`、`1ae290a`、`d63a20b`、`0bac4c1`、`fb2991e`、`623fbbd`、`7df1bf5`、`770bf6b`、`1cefc77`、`aa7d9b2`（wire format：`offset_delta` + verify 三级校验）、`634a773`（分析侧 JPEG 上限、`[stego]` 嵌套键告警、PDF xref 位数保护）。`fmt`/`clippy -D warnings`/全量测试/`local_ --ignored`/`baseline_hash --check`（58 例）/`import_lint.py` 全绿，另有 24 组跨策略 `write→verify→read→restore` 端到端脚本。

上一轮 P0/P1 大部分已落地（C-1~C-4、H-1/H-2、M-1/M-2/M-4、M-23、M-26 等已确认修复）。本轮在**新代码路径与遗留 Medium** 上共确认 **7 项 P0、10 项 P1、12 项 P2**。

最要紧的三条：

1. **`thumb_bridge` 的 64 位 box size 未做上界校验**，一个几十字节的构造 HEIC 就能让 `extract` 走进 `&data[a..a+b]` panic；而 `[profile.release] panic = "abort"`，等于**直接 abort 进程**（不是可捕获错误）。
2. **`--strategy ask` 与 `--stdin` 抢同一个 stdin**，被吃掉的正是载荷第一行，且退出码为 0 —— 静默写入截断的载荷。
3. **ZIP 的 `find_eocd_offset` 采纳“形状像 EOCD”的伪记录**（从不校验 `cd_offset` 处是不是 `PK\x01\x02`），会写出损坏归档但 `verify` 三级全绿；同一个判据缺陷让 `check_jar_signature` 的签名保护可被绕过。

---

## 1. P0：必修（panic / 静默损坏 / 校验绕过）

### P0-1 【新】`thumb_bridge` 64 位 largesize 未校验，任何 HEIC 提取都可能 abort

- 位置：`src/stego/heif/thumb_bridge.rs:1195`（`read_box_header`）、`:904`、`:932`
- 证据：

  ```rust
  // :1195  size32 == 1 分支，直接 as usize，不校验下界也不校验上界
  let size_64 = u64::from_be_bytes(bytes[pos + 8..pos + 16].try_into().unwrap()) as usize;
  Ok((size_64, 16))
  // :904
  if bsize == 0 || pos + bsize > data.len() { break; }   // pos + bsize 未 checked
  // :932
  if sb_sz == 0 || mpos + sb_sz > meta_end { break; }
  ```
- 触发：HEIF 顶层或 `meta` 内的子 box 写 `size32 == 1` + `largesize` 取 `0xFFFF…FF`。`mpos + sb_sz` 在 release 下回绕成小值，绕过 `break`，随后 `&data[iinf_off..iinf_off + iinf_sz]`（`:957`）切片前后界倒置 → `slice index starts at N but ends at M` panic。
- 后果：`[profile.release] panic = "abort"`（`Cargo.toml:148-152`），**进程直接中止**，无 `Result` 可返回；GUI 侧（Tauri）后端随之退出。
- 路径可达性：`stego/engine.rs:478-490` 对任何 HEIF 载体在 HEVC 直读失败后无条件回落 `thumb_bridge::extract_heif_bridge → find_bridge_target → parse_isobmff`。即**默认 feature、普通 `extract` 命令、不可信载体**。
- 修法：`read_box_header` 返回前 `usize::try_from(size_64).ok()` + `size >= header`；调用处统一 `pos.checked_add(bsize).filter(|e| *e <= limit)`。

### P0-2 【新】`--strategy ask` 与 `--stdin` 争抢 stdin，静默丢掉载荷首行

- 位置：`src/cli/cmd_structure.rs:82`（`read_line` 选策略）→ `:115`（`into_buffered()` 读 stdin）
- 证据：

  ```rust
  std::io::stdin().read_line(&mut input)?;   // :82 先把载荷第一行当选项吃掉
  ...
  let (payload, payload_name, payload_is_file) = payload_source.into_buffered()?;  // :115
  ```
- 触发：`cat secret.zip | sth write photo.png --stdin --strategy ask`。
- 后果：单行载荷被整条吞掉，信封里写入空/截断载荷，**退出码 0**，无任何提示；非 TTY 下 `read_line` 读到 EOF 更隐蔽。
- 修法：`strategy == "ask"` 且载荷来源为 `Stdin` 时直接拒绝；或从 `CONIN$`/`/dev/tty` 读选择，并在非 TTY 时报错而不是默认 `strats[0]`。

### P0-3 【新】ZIP 伪 EOCD 被采纳 → 写出损坏归档但 `verify` 全绿

- 位置：`src/structure/adapters/zip.rs:31-63`（`find_eocd_offset`）、`:261-290`（`inject`）
- 证据：

  ```rust
  if fits {
      let cd_size   = ...; let cd_offset = ...;
      if cd_offset + cd_size <= eocd_pos || (cd_offset == 0 && cd_size == 0) {
          return Ok((eocd_pos, cd_offset, cd_size));   // 从不读 cd_offset 处 4 字节
  ```
- 触发：ZIP 注释区/尾部垃圾中放一条 22 字节 EOCD 形状记录，`comment_len` 使其 `record_end == file_size`，`cd_offset` 指向任意更早位置。反向 `rposition` 先命中它。
- 后果：UBE 被插到伪 `cd_offset`（可能落在某条目的压缩数据中间），只改伪记录的 `cd_offset`，**真 EOCD 的 `cd_offset` 仍是旧值**而中央目录已后移 → 标准工具找不到中央目录。写入自检只做 `locate`，`verify_structure`（`zip.rs:385-407`）复用同一个 `find_eocd_offset`，于是 `verify` 报通过。
- 修法：采纳候选前读 `cd_offset` 处 4 字节必须为 `PK\x01\x02`（空归档要求 `cd_offset == eocd_pos`），否则 `continue`。

### P0-4 【新】`check_jar_signature` 同源缺陷 → 签名 JAR 保护可绕过

- 位置：`src/structure/rejection.rs:265-296`
- 证据：

  ```rust
  while offset + 46 <= cd_buf.len() {
      if &cd_buf[offset..offset + 4] != b"PK\x01\x02" { break; }   // 解析失败 = 当作“没有签名”
      ...
  }
  ...
  Ok(None)   // :311 返回“未签名”，拒绝检查放行
  ```
- 触发：在签名 JAR 尾部追加垃圾，内含 `PK\x05\x06` 且 `cd_offset` 指向非中央目录区域。
- 后果：`META-INF/*.SF` 检查被跳过，`write` 放行，产出归档签名失效（`jarsigner`/JVM 校验失败）。这是**安全校验的反向绕过**，不属于“无法解析”。
- 修法：候选必须解析出完整 `entry_count` 条 `PK\x01\x02` 记录才算有效 EOCD；解析失配就 `continue` 而不是 `break`，全候选失败时**保守判为“疑似签名”**（拒绝）而非放行。

### P0-5 【遗 M-14】`isobmff::read_box_size` 同类未 checked 运算（写入/剥离路径）

- 位置：`src/structure/adapters/isobmff.rs:528`、调用点 `:463`、`:651-661`、`:1239`
- 证据：

  ```rust
  let size64 = u64::from_be_bytes(bytes[pos + 8..pos + 16].try_into().unwrap()) as usize;
  ...
  if s_size < s_hlen || bpos + s_size > m_end { return Err(...); }   // 回绕后条件为假
  subboxes.push((tag, host_bytes[bpos..bpos + s_size].to_vec()));    // 切片 panic
  ```
- 后果：与 P0-1 同类 panic，但发生在 `write --strategy item_hidden` 与 `remove` 路径；`isobmff_can_item_hidden`（`:463`）在 debug 构建报 `attempt to add with overflow`。
- 修法：`read_box_size` 返回 `u64`，调用处 `bpos.checked_add(s).filter(|e| *e <= m_end)` 一次判定。

### P0-6 【遗 M-3】`commit_carrier_patches` 不校验 patch span 与目标文件长度

- 位置：`src/core/commit.rs:215-219`（调用点 `src/stego/io.rs:92`）
- 证据：

  ```rust
  let mut file = OpenOptions::new().read(true).write(true).open(&tmp_path)?;
  for (span, patch) in patches {
      file.seek(SeekFrom::Start(span.start as u64))?;
      file.write_all(patch)?;      // 越界 = 静默延长文件 / 稀疏零洞
  }
  ```
- 后果：`span.start + patch.len() > len` 时 `write_all` **不报错**，产物被拉长并带零洞，随后 `rename` 覆盖原文件、返回 `Ok`。正常情况下 patch 由同一份字节算出，但读入（`io.rs:53`）到写入之间文件可被替换，属 TOCTOU 放大器。
- 修法：进入循环前 `let len = file.metadata()?.len();` 并逐个断言 `span.end <= len`，否则 `Err(CorruptedData)`。

### P0-7 【新】CLI 提取落盘非原子，且跟随符号链接

- 位置：`src/cli/cmd_structure.rs:344`、`src/cli/cmd_stego.rs:602/621/642`、`src/structure/engine.rs:1688-1706`
- 证据：CLI 三处 `std::fs::write(&dest, ...)` / `File::create(&final_dest)`；而库路径 `facade.rs:880` 用的是 `commit::write_bytes_atomic`（temp + fsync + rename）。
- 后果：磁盘满/进程被杀时目标名上留下半截文件；`File::create` 跟随符号链接，可覆盖信任边界外文件（`sanitize_filename` 只挡路径穿越，挡不住预先存在的 symlink）。
- 修法：CLI 落盘统一走 `write_bytes_atomic`，rename 前 `symlink_metadata` 检查。

---

## 2. P1：正确性与语义

### P1-1 【遗 H-4】HEVC 提取先判 version 后判 magic → 干净 MP4 报“文件损坏”

- 位置：`src/stego/hevc/engine.rs:148-152`（`HevcSuperblock::decode`）vs `:1552-1557`（magic 校验）
- 证据：`decode` 第一条判断就是 `version != 2 → CorruptedData("Unsupported HEVC stego version")`，而 `magic` 校验在其之后。
- 后果：对无隐写数据的 MP4/MOV，覆盖比特随机，15/16 概率报“版本不支持/数据损坏”，用户以为文件坏了，而不是“没有隐藏数据”。HEIC 因有 bridge 兜底被掩盖，`--auto` 也救不了（结构域先失败）。
- 修法：`decode` 只做结构解码；调用侧先验 `magic`，不匹配直接 `NoHiddenData`/`Password`，再验版本与 `reserved`。

### P1-2 【新】`read --auto` 丢弃刚提示输入的密码

- 位置：`src/cli/cmd_structure.rs:287`（`*password = Some(prompt_password(false)?)`）→ `:311-318`（`passwords: args.passwords.clone()`）
- 后果：结构域无信封、内容域加密时，用户按提示输入的密码被丢弃，`handle_extract` 用 `args.passwords`（仍为 `None`）重新解析 → 报口令错误。`--auto` 的核心场景失效且错误信息误导。
- 修法：把已解析的 `password` 回填进 `ExtractArgs`，或直接把 `password` 传给 `extract_one`。

### P1-3 【遗 M-31】分析器对 PNG 16-bit/Adam7/超限时零检测器且无提示

- 位置：`src/analysis.rs:466-474`（`if let Some(...) && ...` 无 `else`）、`decode_png_pixels` 在 `bit_depth != 8`/`body[12] != 0`/`expected > 256 MiB` 时 `return None`（`:1197-1220`）
- 后果：这类 PNG 的 WS/RS/SPA/chi2 一条 `DetectorMetric` 都没有，`notes` 也不提示（notes 只在 JPEG 与窗口模式分支 push），人类输出显示 `clean`。与 JPEG 侧至少输出 `dct:calibration SKIPPED` 不一致。
- 修法：`decode_png_pixels` 返回 `Result<_, SkipReason>`，失败时 push 一条 `SKIPPED` metric + note。

### P1-4 【遗 M-32】`dct:chi2` 为 `None` 整行消失；SKIPPED 文案写死 "q100"

- 位置：`src/analysis.rs:1668-1697`（`if let Some(...)` 无 `else`）、`:1663`（`"carrier quantization not suitable for calibration (e.g. q100)"`）
- 后果：AC 样本不足（`df < 3`）时该检测器无声消失，漏报不可察觉；真实门槛是 `mean_step < 2.0`，质量≈95 的平均步长 1.5 也会命中，文案误导排障。
- 修法：`None` 时输出 `SKIPPED` metric，并把 detail 改为实际原因（缺 DQT / 渐进 / 图太小 / 平均步长 < 2）。

### P1-5 【遗 M-33】RS 把“测得 0”映射成 `None`，SPA 失败返回 `0.0` 却计入均值

- 位置：`src/analysis.rs:1849`、`:1859-1861`、`:1464`
- 后果：真实测得 0 被报成 `SKIPPED`（理由却是“几何不适合”）；SPA 失败样本以 0.0 进入 `spa_sum / slabs.len()`，系统性拉低估计 → 假阴性方向。
- 修法：统一 `Option<f64>`，只用有效 slab 求均值。

### P1-6 【遗 M-30】尾窗内“最后一个 `FF D9`”当 EOI，密文载荷下系统性少报

- 位置：`src/analysis.rs:849-865`
- 后果：追加的是随机/密文载荷时，尾窗里最后两个 `FF D9` 多半落在载荷内部 → trailing 字节严重少报（`Likely` 降级为 `Suspicious`）；载荷恰好以 `FF D9` 结尾（约 1/65536）时直接 `return`，完全不报。
- 修法：只在“解码成功且该位置之后字节数 == 0”时认 EOI，或改用 JPEG 结构解析得到的真实 EOI 偏移。

### P1-7 【新】分析路径不复用 JPEG 预检预算

- 位置：`src/analysis.rs:1289-1305`（`decode_jpeg_pixels` 直接 `decoder.decode()`）
- 对照常量：`src/stego/jpeg/engine.rs:96-100` 已有 `MAX_JPEG_MCU_COUNT` / `MAX_JPEG_TOTAL_BLOCKS` / `MAX_PIPELINE_BYTES`
- 后果：`scan` 一个头声明 20000×20000 的平坦 JPEG（压缩后仅几十 KB，低于 64 MiB 全量扫描阈值）会让 `jpeg_decoder` 按声明尺寸分配，随后校准再复制一份 `f64` 平面 → 数 GB。嵌入式侧有预算，分析侧没有，同一“不可信输入”两种口径。
- 修法：`decode_jpeg_pixels` 前用 `dct_io::inspect` 复用 `preflight_jpeg` 的三条上限，超限记 `SKIPPED`。

### P1-8 【遗 M-6】配置：嵌套未知键静默忽略、不合并、首候选坏掉即整体失败

- 位置：`src/core/config.rs:185-196`（只遍历 `table.keys()` 顶层）、`:212-233`（首个命中即 `return`）、`:106-111`（`exe_dir` 优先级最高）
- 后果：`[stego] algoritm = "hill"` 这类拼写错误无任何提示；用户配置只写 `lang` 会整份丢弃系统级 `backup/safety`；便携目录内的 `strhide.toml` 可覆盖用户/系统策略。CWD 已按上轮修复移出候选。
- 修法：`StegoConfig`/`StructureConfig` 加 `deny_unknown_fields`；候选按优先级合并（后者补缺）；解析失败给 warning 并继续下一个候选。

### P1-9 【新】`verify` Level 2 的信封边界校验是套套逻辑

- 位置：`src/structure/engine.rs:2346-2357`
- 证据：比较的 `ube_offset`/`ube_total_size` 直接来自 `locate()`，而 ZIP/PDF/PE/RIFF/MKV/ISO-BMFF 的 `locate` 返回的正是 `trailer.ube_offset/ube_total_size`（例：`zip.rs:295-322`）→ 永远相等。
- 后果：篡改 `header.inject_offset/inject_size/patch_offset`（既不在 AAD 内，非 stealth 也不掩码）后，`verify` 仍报 `Envelope valid … (CRC32 OK)`，但随后的 `remove` 会写坏中间文件并以 `RestoreMismatch` 失败。作为准入闸门的 `verify_passed` 结论不可信。
- 修法：Level 2 增加 `header.inject_offset + inject_size` 与 `trailer.ube_offset + ube_total_size` 的交叉校验，以及 `inject_end <= 文件长`。

### P1-10 【新】`scan`/`inspect` 在干净结果上吞掉“结论不可靠”的提示

- 位置：`src/cli/cmd_diag.rs:421-425`
- 证据：`if !r.findings.is_empty() || note.contains("Carrier is larger")` —— JPEG 无 finding 时那条“clean/low 不等于安全”的 caveat 恰好被过滤掉。
- 后果：文本模式给出干干净净的 `clean` 且没有任何保留说明（JSON 输出反而正常），正是最需要提示的场景缺失。
- 修法：按 note 类型过滤，不按 findings 是否为空过滤。

---

## 3. P2：资源上限、一致性与体验

| ID | 位置 | 问题 | 修法 |
|---|---|---|---|
| P2-1 | `stego/hevc/slot.rs:481-506` | `with_slice_capacity` 按 `slice_len*18` 预分配（`BinOp` 2 B → 36 B/输入字节 + 16 B/字节槽位），`slice_len` 直接来自载体且无上限；`StopCondition::MinSlots(2048)` 的界被完全绕过 | `with_capacity(slice_len.min(CAP))`，让 `Vec` 自然增长 |
| P2-2 | `structure/adapters/isobmff.rs:437-449`、`:607` | 只为布尔判断读 1 GiB（`MAX_ISOBMFF_META_SCAN` + `read_to_end`）；`item_hidden` 又把整宿主读进内存 | 按 box 头逐跳 seek 只读 `meta`，上限降到 4–16 MiB |
| P2-3 | `structure/adapters/pe_layout.rs:396` | `.text` 整段 `vec![0u8; text_scan_len as usize]`，`inspect/write/remove` 各读一遍 | `usize::try_from` + 64 MiB 上限，超限判 `pe_codebits` 不可用 |
| P2-4 | `cli/cmd_stego.rs:44`、`:209`、`:279` | `capacity`/`extract`/`--dry-run` 全量 `fs::read` 载体；`--stdin` 无上限 | 容量探测走流式；stdin 加可配置上限 |
| P2-5 | `cli/helpers.rs:62-77` | `--password-file` 为取首行读整个文件（且必须 UTF-8） | `BufReader::read_line` + 4 KiB 上限 |
| P2-6 | `cli/cmd_diag.rs:131-145`、`:50-78` | 批量 `inspect` 失败只写 stderr：`--json` 数组无失败项、退出码 0、`content_error` 从不渲染；摘要 `total = reports.len()` 与 `failed` 口径不同（3 个文件说“Inspected 2 … 1 failed”） | 失败项进 JSON；文本打印 `content_error`；`total = files.len()` |
| P2-7 | `core/i18n/mod.rs:175-184` | `format_msg` 丢弃 `{key:.2}` 说明符，按 `Display` 输出 → `12.345678901234567%`；`debug_assert!` 却只校验 key 不看说明符 | 识别 `:.N` 做定点格式化，或模板里改传已格式化字符串 |
| P2-8 | `cli/cmd_diag.rs:57-68`、`cli/cmd_stego.rs:81-108` | 硬编码英文段落（`Content Steganography Domain:` 等）、`capacity` 自带第三套 `is_zh` 分支；`capacity --json` 是 NDJSON 而 `inspect/verify/scan --json` 是数组，`print_json` 还给每个数组元素塞 `banner` | 文案进 `messages.rs`；JSON 形状统一 |
| P2-9 | `core/crypto.rs:245-263` | `make_chunk_nonce` 把 `usize` 截成 `u32`，注释断言“每个 nonce 都不同”并不成立；`make_meta_nonce` 与第 `0xFFFFFFFF` 块相撞（chunk 最小 1 B 时可构造，CLI 不暴露） | 注释写清上界，或计数器不够时改用 12 字节全 XOR |
| P2-10 | `stego/hevc/engine.rs:157-172` | `reserved` 读了但从不校验 `== 0`；`total_windows` 读了从不使用；bit0 多窗口标志未检查 → 多窗口布局被静默按单窗口解（最终表现为 AEAD 失败） | `decode` 里三条判断返回 `UnsupportedVersion` |
| P2-11 | `stego/hevc/slot.rs:137`、`:230` | 注释写 “32 bytes here”，`assert!` 是 16 字节；`[`StegoSlot::band`]` 是悬空 intra-doc link（无该字段） | 注释改 16 B，删掉悬空链接 |
| P2-12 | `structure/adapters/isobmff.rs:468`、`:1244` | `isobmff_can_item_hidden`/`has_iloc_item` 用 `pos + 12` 硬编码 8 字节头，忽略 `hlen`（64 位 `meta` 时错 8 字节） | 改用 `pos + hlen + 4` |

其余已确认仍存在但影响较小（不单列修法）：PDF xref `{:010}` 固定 10 位（>10 GB 写坏却 verify 通过，`pdf.rs:617-626`）；`check_jar_signature` 不支持 ZIP64（`rejection.rs:247-281`，ZIP64 签名归档一律漏检）；`zip.rs:333`/`isobmff.rs:498` strip 硬编码 `strategy_id` 数字（PE 侧已改 `id_to_strategy`）；MKV/RIFF `verify` 硬编码标准 trailer magic（`riff.rs:236-243`、`mkv.rs:160-167`，stealth/私有 dialect 载体被判损坏）；`sniff.rs:205-208` `is_jpeg_bytes` 只认 2 字节（`FF D8 00` 被送进 JPEG 适配器）；`sniff.rs:183` `is_heif_bytes` 要求首 box 为 `ftyp`（`free/uuid` 前置的 HEIC 被判 MP4）；`structure/engine.rs:1804-1838` restore 路径 stealth 约 3 次 PBKDF2；`core/payload.rs:11-14` 文档称“元数据不上线”与现状矛盾，且 `PayloadKind::Text` 不往返 → `extract -o dir` 把文本载荷写成 `<carrier>.bin`。

工程性小项：`src/stego/heif/thumb_bridge.rs` 测试字符串里有 4 个**裸 NUL 字节**（`:61333` 附近），导致 `grep`/`rg` 把整个文件当二进制（需 `-a`）；改成 `\x00` 转义即可。

---

## 4. 上一轮遗留问题现状

已复核确认**已修复**：M-1（batch 单/并行 ctx 一致，`batch.rs:117-120`/`:166-169`）、M-2（`DEFAULT_STC_H` 常量，`helpers.rs:658/666`）、M-4（`sanitize_filename` 保留名/末尾点空格，`fs.rs:44-56`）、M-6 的 CWD 部分、M-23（PNG 分块固定 8 块）、M-26（`PngParams::validate`）、C-1~C-4、H-1/H-2。

**部分修复**：M-9 / L-16（`name` 已上线，`kind` 未上线，`payload.rs` 文档过期）、M-11（`base_sz == 0` 已支持，`off_sz/len_sz == 0` 仍报 `UnsupportedFormat`）、M-16（已挡 `size_of_opt_header == 0`，未校验“安全目录落在 optional header 内”）、M-21（`pe.rs` 已流式，`pe_layout.rs` 仍 64 KiB 窗口）、M-35（系数解码已共享，分析侧仍无预检）、L-17（签名已参数化，调用点仍写死 1 GiB）。

**仍存在**（本报告已收录的）：M-3 → P0-6，M-5（`check_overwrite` 与写入之间 TOCTOU，`engine.rs:1279`、`stego/io.rs:46`），M-8（stealth 下同时接受原始 CRC 与掩码 CRC，属设计取舍），M-10 → P2-12，M-12（`auto` 失败无二次回退，`engine.rs:1067-1080`），M-13 → P2-2/P2-3，M-14 → P0-5，M-15/ZIP64、M-17、M-18（PDF 尾部扫描峰值 = 整文件）、M-19、M-20、M-22（PDF 要求 `%PDF-` 在 offset 0）、M-30~M-34 → P1-3~P1-6（M-34 阈值标定仍需实测语料），M-36/M-37 → P2-11/P2-10，L-1/L-2/L-3/L-5/L-7/L-8/L-13。

---

## 5. 建议修复批次

- **第 1 批（P0，改动小、可加回归测试）**：P0-1、P0-5（同一类 unchecked box 算术，一个 helper 解决）、P0-2、P0-6、P0-4、P0-3、P0-7。
- **第 2 批（P1 语义）**：P1-1、P1-2、P1-3、P1-4、P1-5、P1-9、P1-10（都是几行判断 + 文案）、P1-6、P1-7、P1-8。
- **第 3 批（P2 资源上限）**：P2-1~P2-6，P2-11/P2-12（顺带）。
- **第 4 批（输出与一致性）**：P2-7~P2-10 及第 3 节末尾的小项。

每批改完按 AGENTS.md 全流程验证：`cargo fmt && cargo clippy --all-targets --all-features -D warnings`、`cargo test --all-features --all-targets`、`cargo test local_ -- --ignored`、`python scripts/baseline_hash.py --check`。

**必须标「待实测」的两项**：M-34 的检测器阈值标定（需语料跑 FPR）、`jpeg-decoder 0.3` 是否自带尺寸上限（影响 P1-7 的最终严重度）。

---

## 7. 处理状态（2026-10-30 20:35）

### 已修复

| 条目 | 提交 | 一句话 |
|---|---|---|
| P0-1 thumb_bridge 64 位 box 尺寸溢出 | `caeafa2` | 拒绝装不进 `usize` 或小于 16 字节头的 `largesize`，全部改成 `size > limit - pos` 比较 |
| P0-5 isobmff 同类未 checked 运算 + P2-12 `pos + 12` | `caeafa2` | 同上；`meta` 子 box 用真实头长 |
| P0-3 ZIP 伪 EOCD 被采纳 | `1ae290a` | 采纳前要求 `cd_offset` 处为 `PK\x01\x02` |
| P0-4 JAR 签名检查可绕过 | `1ae290a` | CD 必须完整走完，失配换下一个候选而不是判"未签名" |
| P0-6 补丁跨度不校验 | `d63a20b` | 越界返回 `CorruptedData`，不再静默延长文件 |
| P0-2 `--strategy ask` 与 `--stdin` 抢 stdin | `d63a20b` | 直接拒绝该组合 |
| P1-1 HEVC 干净载体报"版本不支持" | `0bac4c1` | 先验 magic（口令派生）再判版本 |
| P2-10 Superblock `reserved`/`total_windows` 不校验 | `0bac4c1` | 非 0/非 1/多窗口标志 → `NoHiddenData` |
| P1-2 `read --auto` 丢密码 | `fb2991e` | 把已解析口令带进重定向参数 |
| P1-10 `scan` 干净报告吞提示 | `fb2991e` | notes 无条件打印 |
| P2-7 `{x:.2}` 说明符被丢弃 | `623fbbd` | 数值参数按精度重新定点渲染 |
| P2-11 slot 注释 32B / 悬空链接 / payload 文档 | `623fbbd` | 文档与实现对齐 |
| （工程项）源码裸 NUL 字节 | `623fbbd` | 改 `\0` 转义，`grep`/`rg` 不再当二进制 |
| P0-7 CLI 落盘非原子 + 跟随符号链接 | `7df1bf5` | 4 处统一走 `commit::write_bytes_atomic` |
| P2-1 HEVC 记录器预分配无上限 | `770bf6b` | 提示值上限 1 MiB（预留约 56 MiB） |
| P2-5 `--password-file` 整文件读 | `770bf6b` | `BufReader` + 4 KiB 上限读首行 |
| P1-3 PNG 16-bit/Adam7 零检测器无提示 | `1cefc77` | 补 note 说明空间域未运行 |
| P1-4 `dct:chi2` 整行消失 / 文案写死 q100 | `1cefc77` | 输出 `SKIPPED` 并给真实原因 |
| P2-6 inspect 内容域错误被吞 + 摘要计数口径 | `1cefc77` | 合并重复块并打印错误；`total` 改为处理总数 |
| （测试）5 例回归 | `d63a20b` | `tests/test_regression/review_20261030.rs` |
| P1-9 `verify` Level 2 套套逻辑 | `aa7d9b2` | header 第 11 字节改为 `offset_delta`（AAD 内、已认证），写入端在封装前算好；Level 2 改为 `inject_offset+delta == trailer.ube_offset`、`ube_total_size <= inject_size`、`inject+size <= 文件长` 三级校验 |
| P1-7 分析侧 JPEG 无内存预算 | `634a773` | `jpeg-decoder` 的 `set_max_decoding_buffer_size` 默认 `usize::MAX`，现设 1 GiB |
| P1-8 配置嵌套未知键静默忽略 | `634a773` | `[stego]` 段按同一告警机制报 `[stego].<key>`（仍只告警） |
| （第 3 节小项）PDF xref 固定 10 位 | `634a773` | >10 GB 直接拒绝并提示 `--strategy eof` |
| （测试）3 例坐标校验 | `aa7d9b2` | `envelope_coordinates` 子模块：位移与策略一致、未篡改通过、篡改 `inject_offset` 被拒 |
| （测试）1 例配置告警 | `634a773` | `tests/test_cli/config.rs` |

### 主动搁置（未改，附理由）

| 条目 | 搁置理由 |
|---|---|
| P1-5 RS/SPA 口径不一 | 会改变检测数值，进而影响 verdict；没有语料实测 FPR 前改口径等于盲调阈值 |
| P1-6 JPEG EOI 取尾窗最后一个 `FF D9` | 需要先决定"用结构解析的真实 EOI 还是尾窗启发式"，且会改变 `trailing-data` 判定与既有语料结论 |
| P1-8 配置**合并**与**回退**语义 | 嵌套键告警已补（`634a773`）；但"候选配置合并"与"首个候选解析失败回退下一个"仍会重定义优先级，属行为约定变更，需单独定方案 |
| P2-2 `isobmff_can_item_hidden` 读 1 GiB | 需要改成"按 box 头逐跳 seek + 只读 meta"，是函数重写而非数行修改；当前无正确性缺陷，只是内存浪费 |
| P2-3 PE `.text` 整段读入 | 上限取值（64 MiB？）会影响大 PE 的策略可用性，需先确认目标载体规模 |
| P2-4 CLI `capacity`/`dry-run` 全量读载体 | 要引入流式容量探测接口，属 API 设计；与 GUI 共用 |
| P2-8 硬编码英文段 / `capacity --json` NDJSON | 统一 JSON 形状会破坏现有机器消费方（含 GUI 侧封装），需要一次性约定版本 |

其余第 3 节末尾的小项（ZIP64 签名、strip 裸 `strategy_id`、MKV/RIFF magic、`sniff` 2 字节 JPEG、restore 重复 PBKDF2）均为"已知、影响窄"，留待各自模块专门处理；PDF xref 位数保护已随 `634a773` 落地。
