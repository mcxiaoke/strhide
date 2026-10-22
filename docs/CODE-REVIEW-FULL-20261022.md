# strhide 全项目代码审查报告（合并版，2026-10-22）

**审查范围**：`rust/` 全部源码（27,369 行 / 60+ 文件）+ 集成测试，不含已冻结的 `python/`。

**基线**：`cargo clippy --all-targets` 零告警、`cargo test` 全绿（含 doctest）、`cargo fmt` 通过。
本报告不含 lint 能查出的问题，只讨论 **缺陷、健壮性、性能、坏味道、过度防御、脆弱耦合**。

**合并说明**：本版合并了两份独立审查的结论——
`CODE-REVIEW-V3-20261022*.md`（STC-V3 专项，已整改项不复述）、
`CODE-REVIEW-FULL-20261022-gmf.md`（全量质量审查）以及本轮全项目通读。
gmf 的 10 条技术论断已**逐条回到源码核实**：8 条原样采纳、2 条修正（见 §10 核实表）。
下文标注 `[gmf#n]` 的条目来自该报告。

---

## 0. 总体评价

架构分层清晰（engine / adapters / envelope / crypto / stego 边界明确），wire format 有单一真源，
注释保留了“为什么这样做”的历史决策——这是本项目最大的资产。

问题集中在三处：

1. **重复逻辑已经分叉并产生实际口径不一致**（§1-B2、§4）。
2. **跨模块硬编码耦合**：engine 手算 crypto 帧开销、envelope 手抄 strategy id 上限、
   CLI 与 stego 引擎靠错误消息文本做控制流（§6）。
3. **防御写错了位置**：该防的（解压炸弹、>64 MiB 扫描、非 UTF-8 路径、UBE 重读）没防，
   不该防的（不可达参数、已校验的算术）防了两层（§5）。

---

## 1. P0 — 必须修（静默漏报 / 数据损坏 / 确定性浪费）

### B1 大于 64 MiB 的载体，结构扫描整体失效 `[gmf#2 核实采纳，严重度修正]`

`src/analysis.rs:127-140`

```rust
combined.extend_from_slice(b"\n..<truncated>..\n");   // 18 字节伪造标记
```

把“前 1 MiB + 伪造 ASCII 标记 + 尾部 64 KiB”拼成一个 `Vec<u8>` 交给 `sniff_format` /
`track_png_structure` / `track_jpeg_structure`。后果链：

1. 结构 walker 步进到拼接边界时，把 `"\n..<tru"` 当 chunk length/type 解码 → `checked_add` 越界 →
   `break`（`analysis.rs:348-351`）；
2. 真实尾部永远走不到，`png:trailing-data`（`:364-382`）与 JPEG 尾部检测不会触发；
3. `track_trailing_entropy` 对 PNG/JPEG 显式返回 `false`（`:660-663`，注释写 "covered precisely by
   png:trailing-data"）——而那条检查此刻已不可能触发；
4. 像素统计因 `file_size > MAX_FULL_SCAN` 被跳过（`:161`）。

**净效果**：>64 MiB 的 PNG/JPEG 在尾部追加任意载荷后，只剩 `track_tool_signatures` 的
**已知特征串**兜底（strhide trailer magic、OpenStego 等），未知工具/恶意附加数据 → 报 `clean`。
gmf 原文说“100% CLEAN”，实测仍会命中已知签名，故修正为
**“结构证据完全丢失，只剩已知签名一条路”**。

修法：`prefix` 与 `tail` 保持独立，用 `enum ScanView { Full(&[u8]), Windowed { prefix, tail } }`
供各检测器按需取；尾部结构标记（IEND/EOI）从 `tail` 逆向查找。

### B2 空间域容量探测与真实嵌入的槽位口径不一致

`src/stego/spatial/engine.rs:951`

```rust
let header_seed = crate::stego::envelope::derive_header_perm_seed(None, None);
```

`probe_spatial_capacity` 用“无密码 + 无 domain”派生 header 排列，`embed_spatial:549` 用真实
`password/domain`。header 槽位决定 `is_header[]`，进而决定 body 候选集（`:566-573`），
所以 **`inspect` / `--capacity` 报的容量与真实可写容量的候选集不同**。

`stego/mod.rs:212-217` 的文档也需更正：它写“容量答案对任何方言都相同”，这对 JPEG 成立
（几何网格 + 固定 superblock），对空间域**不成立**。

### B3 PNG 注入把 UBE 完整读两遍 `[gmf#4 核实采纳]`

`src/adapters/png.rs:154-180`

先整轮读 `ube_in` 喂 CRC32，`seek(0)` 后再整轮读一次写 `out`。
PNG 的 CRC 位于 chunk 数据**之后**，可在写出的同一个循环里 `hasher.update(&buf[..n])`，
末尾再写 `finalize()`。大 payload 白读一遍磁盘/内存。

（对照：`adapters/jpeg.rs` 的 UBE 只读一遍，说明这不是格式限制，只是实现顺序问题。）

### B4 解压无上限，扫描/嵌入路径可被解压炸弹打爆内存

- `src/analysis.rs:754-758`：`ZlibDecoder::read_to_end(&mut raw)`，无上限
- `src/stego/spatial/engine.rs:239-248`：同上，`expected` 是解压**之后**才算的

`MAX_FULL_SCAN = 64 MiB` 限的是**压缩后**大小；`scan` 的输入按设计就是不可信文件。
几百 KB 的 IDAT 可膨胀到几十 GB。应先由 IHDR 算出 `stride*height + height`，
用 `take(expected + 1)` 限定，超限即判损坏。

### B5 `remove_carrier` 的临时文件名走 `display()`

`src/engine.rs:1792`

```rust
let tmp_target = PathBuf::from(format!("{}.strhide.restoring.tmp", target_path.display()));
```

写路径（`:1195-1197`）刻意用 `OsString::push` 规避 `display()` 的有损转换并注明原因；
删除路径用了被否定的写法。非 UTF-8 文件名（Windows 孤立代理项 / Unix 任意字节）会得到
不存在的临时路径，把恢复结果写到“被打乱的文件名”下。

### B6 PDF“下一个可用对象号”靠尾部 64 KiB 猜，已解析的 startxref 被丢弃 `[gmf#3 核实采纳，描述修正]`

`src/adapters/pdf.rs:97-177`

- `prev_startxref`（`:127-133`）已拿到上一个 XRef 的绝对偏移，但 `PdfTailInfo` 里只存不用；
- 真正取对象号只有两条路：64 KiB 窗口里的 `trailer << /Size >>`（`:147-152`），
  或同一窗口扫 `N G obj` 取 max+1（`:156-158`）。

对 PDF 1.5+ 的 XRef 流：`/Size` 在 XRef **流字典**里，而该流的压缩数据很容易超过 64 KiB，
一旦超出（大型文档常见），窗口里只剩压缩字节 → 两条路都失败 →
`parse_pdf_trailer_info:38` 返回 `CorruptedData`。

修正 gmf 两点：① 错误变体是 `CorruptedData` 而非 `UnsupportedFormat`；
② `auto` 不会硬失败——`choose_auto_strategy` 在 `Err` 时回退 `eof`（`pdf.rs:399-403`），
用户拿到的是“文件增大 + 一条 note”。
但 gmf 指出的**危害成立且更隐蔽**：窗口里若恰好只含少量旧对象定义，
`max+1` 会小于文档真实最大对象号（压缩对象流里的对象永不以 `N G obj` 出现），
写入后与既有对象号冲突，破坏文档结构。

修法：`seek(prev_startxref)` → 解析 XRef 流字典 `/Size`（必要时解压流），该值即下一个可用号；
只在非 XRef 流时回退字符串扫描。

### B7 PE / JPEG 在大文件上同样跳过整文件级证据

与 B1 同源，独立列出以便验收：`track_pe_structure` 在大文件上直接跳过（`analysis.rs:151`），
`track_jpeg_structure` 在拼接边界即 `break`（`:411-413`）。
验收标准：**对 >64 MiB 的 PNG/JPEG，在 IEND/EOI 之后追加 4 KiB 随机数据，`scan` 必须给出
`png:trailing-data` 或等价的 Suspicious/Likely**。目前这条断言会失败。

---

## 2. P1 — 应修

### P1-1 PBKDF2 在单次操作里重复执行 3–5 次

`derive_keys` / `derive_stealth_magics` / `derive_header_mask`（`src/crypto.rs:81/103/125`）
各自独立跑 `PBKDF2(password, salt)`，其中 `derive_keys` 与 `derive_header_mask` 的
`(password, salt)` **完全相同** → IKM 相同，可只算一次再 HKDF-Expand 出两个子密钥。

stealth 读路径实测调用序列：

| 调用点 | PBKDF2 |
|---|---|
| `locate_envelope` → `derive_stealth_magics` | 1（domain） |
| `unpack_with_profile` → `derive_stealth_magics`（**重复**） | 1（domain） |
| `unpack_with_profile` → `derive_header_mask(pwd)` | 1（salt） |
| `unpack_with_profile` → `derive_header_mask(profile.secret())`（**必然失败**） | 1（salt） |
| `read_core` → `derive_keys` | 1（salt，**与第 3 行重复**） |

100k 次 HMAC-SHA256 ≈ 30–60 ms，每次读写白烧 100–250 ms。
修法：crypto 暴露 `derive_all(password, salt, domain)`，并让 `locate_envelope`
把已算出的 magics 传给 `unpack_with_profile`。

### P1-2 库层 `remove_carrier` 无覆盖保护，与 `read_carrier` 不对称

`src/engine.rs:1771-1836`：`read_carrier_with` 拒绝覆盖已有输出（`:1549`），
`remove_carrier_with(output_path)` 直接 rename 覆盖。CLI 用 `check_overwrite` 兜住了，
但作为公开 API 语义不一致，且会静默丢失用户文件。

### P1-3 `verify` 的退出码忽略 level3

`src/cli.rs:1540-1544`、`:1553`：只看 `level1_host.ok && level2_envelope.ok`。
payload 解密/SHA-256 失败时仍返回 0——人读输出打印 `L3 FAIL`，脚本却当成功。
至少应把 `CorruptedData` 类失败计入退出码。

### P1-4 拷贝循环静默截断，`copy_exact` 无人使用

`png.rs:141-149 / 189-195`、`zip.rs:205-213 / 231-239 / 251-257 / 311-319 / 345-353 / 368-374`、
`jpeg.rs:204-212 / 242-248`、`pe.rs:392-399 / 405-411` 共 10+ 处同构循环，全部写成
`if n == 0 { break; }`。在“已知范围内”遇到 EOF 意味着输入被截断，继续执行会产出
**少几百字节但看似成功**的输出，错误推迟到 `verify_written` 或 `restore` 才以“哈希不匹配”暴露。

`adapters/io.rs` 的 `copy_exact`（EOF → `CorruptedData`）语义正确，但除默认 `strip` 外无人使用。

### P1-5 目录遍历遇到单个异常条目就中止整批 `[gmf#7 核实采纳，修法修正]`

`src/cli.rs:1701-1729`

```rust
let entry = entry?;              // 一条 Err 就终止整批
if entry.file_type()?.is_file()  // 同上
```

`scan` / `inspect` / `verify` 的批量模式在系统目录、受限目录、破损条目上会整体夭折。
应改成“记录告警 + `continue`”，与 `expand_input_paths` 对不存在路径的处理（`:1747-1749`）一致。

**修正 gmf 的修法**：它建议加“已访问路径集合防软链接成环”。
`entry.file_type()` 返回**链接自身**类型（不 follow），符号链接的 `is_dir()` 为 false，
现有实现不会顺链接递归，成环风险不存在，无需引入 visited 集合。

### P1-6 错误处理依赖消息文本（两处，同源）

**a. CLI 从错误消息里抠 hint** — `src/cli.rs:1179-1184`

```rust
if let Some((_, rest)) = msg.split_once("Hint: '") { ... rest.strip_suffix("'.") ... }
```

`engine.rs:1437` 改一个引号或加个句号，功能即静默失效。

**b. STC/JPEG 引擎按子串判错误类型** `[gmf#8 核实采纳]` — `src/stego/jpeg/engine.rs`

- `:529` 与 `:573` 两处完全相同的 `e.to_string().contains("no legal element")`
- `map_dct_error` `:62` 已用 `err_str.contains("SOF2")` 拦过，`:69` 的 `match` 分支里又判一次（死分支）

修法：`StrHideError` 增加结构化变体（如 `TrellisInfeasible`），`read_carrier` 的错误带
`hint: Option<String>` 字段。禁止用格式化文本做控制流。

### P1-7 `is_inplace` 用 `std::path::absolute` 字符串比较

`src/engine.rs:1239`、`src/rejection.rs:365`：不解符号链接、不做大小写归一。
Windows 上 `-o PHOTO.PNG` 与 `photo.png` 指向同一文件却判为“非原地” → **静默跳过 `.bak`**。
建议用文件身份（dev/ino 或 Windows file index）比较，退而求其次在不同判定时给 warning。

### P1-8 灰度 JPEG 被按 3 通道统计

`src/analysis.rs:818`：`Some((pixels, width, 3))`，无视解码器 `PixelFormat`。
`rs_analysis` / `spa_estimate_dww` 按 `width * 3` 推算行宽 → 几何错位，输出无意义数值，
最终**静默给出 clean 结论**——而 `scan` 的定位恰恰是不能给假阴性。

---

## 3. P2 — 建议改进

| 编号 | 问题 | 位置 | 说明 |
|---|---|---|---|
| P2-1 | JPEG 头部 marker 状态机写了 3 份，且逐字节 `read_exact` `[gmf#5]` | `jpeg.rs:31-82`(find_jpeg_sos_offset)、`:265-325`(locate)、`:480-530`(suspicious_structures) | 三份逐行近似；宿主是未缓冲 `File`，单字节 syscall。抽 `scan_jpeg_markers(on_marker)` 回调迭代器，内部配 512B 缓冲 |
| P2-2 | CLI 载荷解析 40 行重复 `[gmf#6]` | `cli.rs:1050-1088`(write) vs `:1981-2015`(embed) | `--stdin / -d / -t(+unescape) / --text-file / --text-base64 / STRHIDE_TEXT` 分支与 base64/unescape 处理完全一致。抽 `resolve_payload(...)` |
| P2-3 | `handle_embed` 的参数装配两份（另一处重复） | `cli.rs:1889-1926`(capacity) vs `:2039-2080` | 已分叉：后者多了 `apply_stc_h` + `warn_nondefault_stego_params` |
| P2-4 | `extract_jpeg` 每个 trial suite 重建整张网格 `[gmf#10]` | `jpeg/engine.rs:726-733` | `slots_buf.clear()` + 双层循环重填同一份索引（`clear` 保留容量，故是 O(n) 重算而非重分配）。留只读模板 + `copy_from_slice` 即可 |
| P2-5 | `verify_carrier` 的 L3 把整条载荷重读进内存 | `engine.rs:2199` | L2 已解析 header/trailer，L3 又完整走一遍定位→解密→解压→sha256，payload 全量驻留 |
| P2-6 | `inspect` 为测内容隐写容量把整个文件读入内存 | `engine.rs:1914-1921` | `read_to_end` 无上限，且 `cf.rewind().ok()` 吞错 |
| P2-7 | 签名检测 fail-open（依赖当前流位置） | `rejection.rs:31-39`(PE)、`:150-159`(PDF) | `pub fn` 却不 `seek(0)`；内部调用方目前在 0 位，复用方停在中间就判“未签名” |
| P2-8 | 空间域两个魔法数字 | `spatial/engine.rs:812`(49)、`:862`(28) | 应改用 `MIN_ENVELOPE_LEN` / `HEADER_OVERHEAD`；`envelope.rs` 已有常量 |
| P2-9 | 空口令文件产出 `Some("")` | `cli.rs:668` | `trim_end_matches` 后不校验非空；`StegoOptions::secret` 已过滤空串（`stego/params.rs:472`），UBE 侧没有 |
| P2-10 | 配置文件解析两次 | `config.rs:88` 与 `:106` | 两条错误消息还不一致；用一次 `toml::Value` + `try_into()` |
| P2-11 | `effective_slot_budget` 用等值判断“是否显式设置” | `stego/params.rs:383` | 显式传 `--slot-budget 1200000`（=默认）会被当成未设置而动态缩放，与文档矛盾。用 `Option<usize>` |
| P2-12 | 备份路径兜底可能覆盖旧备份 | `engine.rs:576-606` + `:1243` | 1000 次尝试后回退 `.bak-<stamp>-<pid>` 却不检查存在性，`fs::copy` 直接覆盖 |
| P2-13 | `embed` 落盘语义与 `write` 不一致 | `cli.rs:2110 / 2133` | 直接 `fs::write`：无 temp+rename、无 `TmpGuard`、无权限/时间戳保留 |
| P2-14 | `MAX_KNOWN_STRATEGY_ID` 与 `STRATEGY_REGISTRY` 手工同步 | `envelope.rs:55` vs `router.rs:90-102` | 新增 strategy 忘了改，会让未加密信封的 de-mask 闸门（`envelope.rs:418`）把新载体判成“不是信封” |
| P2-15 | 用格式名字符串做类型判断 | `engine.rs:1911`（`format_name() == "PNG"`） | 路由不该走展示名，建议加 trait 方法 `supports_content_stego()` |
| P2-16 | 测试夹具 `make_png` 的 PNG 自相矛盾 `[gmf#9 核实采纳，补充]` | `tests/common/mod.rs:37 / 46` | 见下方专条 |

**P2-16 专条（比 gmf 描述更严重）**：
`ihdr_data = [1,0,0,0, 1,0,0,0, ...]` 按 PNG 规定的大端序解读为
宽 = 高 = 0x0100_0000 = 16,777,216 像素，与 `1x1` 的注释不符。
但它在本仓库内不会 OOM——`decode_png` 的 `raw.len() < expected` 检查在分配**之前**，
直接返回 `Decompressed IDAT is truncated`。
真正的问题是**第二处**：IDAT 用 `flate2::write::DeflateEncoder`（raw deflate），
而 `ZlibDecoder` 要求 zlib 头 → 该夹具在任何像素解码路径上都不可能成功。
两个缺陷互相掩盖，所以一直没人发现。修 `IHDR` 时**必须同时**改成 `ZlibEncoder`，
否则修完尺寸会立刻暴露第二个问题。

---

## 4. 重复代码台账

| 编号 | 重复内容 | 份数 | 位置 | 风险 |
|---|---|---|---|---|
| D1 | 空间域“候选→排序→排除→置换→header/body 划分” | 3 | `spatial/engine.rs:506-573 / 748-786 / 925-971` | **已分叉，导致 B2** |
| D2 | `slots_for` 两个实现，其中一个零调用 | 2 | `coding.rs:263`（文档声称两引擎都调用）+ `spatial/engine.rs:77`（实际副本） | 文档失真 + 死代码 |
| D3 | PNG chunk 遍历 | 4 | `png.rs:212 / 266 / 340`（+ `find_iend_offset`） | 边界处理各不相同（`break` vs `?`） |
| D4 | header 掩码 XOR 循环 | 3 | `envelope.rs:270-275 / 387-392 / 411-415` | wire format 改一处漏两处 |
| D5 | CLI 往 JSON 塞 banner | 4 | `cli.rs:1406 / 1451 / 1584 / 1643`（`list` 另一形态） | 低 |
| D6 | stego“嗅探格式 + 取 cost model” | 4 | `stego/mod.rs`（embed×2 / extract / probe） | 低 |
| D7 | CLI 载荷解析 | 2 | `cli.rs:1050-1088` vs `1981-2015` | 见 P2-2 |
| D8 | 适配器 64 KiB 拷贝循环 | 10+ | 见 P1-4 | **静默截断** |
| D9 | JPEG marker 状态机 | 3 | 见 P2-1 | 见 P2-1 |
| D10 | 死代码：`has_hint`(envelope.rs:168)、`pack_with_stealth_mask`(:237)、`run_all_rejection_checks`(rejection.rs:327)、`validate_stc_u_wide`(coding.rs:32)、`slots_for_codec`(coding.rs:263) | 5 | — | 读取端一律用 `hint_len > 0`，`has_hint` 是死路径 |
| D11 | `#[allow(too_many_arguments)]` | 2 | `jpeg/engine.rs:345 / 616` | `fmt + params + cost_model` 总同行出现，可合成一个 ctx |

---

## 5. 过度防御

1. **为不可达状态写守卫** — `coding.rs:49 validate_k` 注释自认
   “unreachable while k is the compile-time constant”，而 `k` 目前无任何外部入口。
   留 `debug_assert` 即可，等真开放参数再加。
2. **已校验的不变量再算一遍** — `engine.rs:1467-1476` 在 `validate_against` 之后又套四层
   `checked_sub`，注释也承认。而两处都没覆盖真正能触发的情形：`meta_len >= 16`。
3. **通用 `strip` 为单一适配器妥协** — `adapters/mod.rs:239-253` 的 `patch_offset` 三分支，
   ZIP 已有 override（`zip.rs:296`），默认实现只需第一种情况 + 断言。
4. **超通用返回类型** — `InspectResult`（`engine.rs:347`）15 个 `Option` + `metadata: Value`，
   调用方（`cli.rs:1300`）只能逐字段 `if let`。`enum InspectState { Empty, Present(..) }`
   能把“该报错还是该沉默”的决策收敛一处（顺带解决 P1-3 这类退出码歧义）。
5. **拷贝循环的伪防御** — 见 P1-4：把“不该发生的 EOF”当正常结束，比不做防御更危险。

---

## 6. 脆弱耦合

| 编号 | 耦合 | 位置 | 断裂方式 |
|---|---|---|---|
| F1 | engine 手算 crypto 帧开销（`+16` / `+20` / `+24`） | `engine.rs:964-971` | crypto 改分帧 → `auto` 选错策略 → 靠运行期 `ube_total_size != exact_ube_size` 断言兜底。应暴露 `framed_len(plain, chunk_size)` |
| F2 | 错误文本当控制流 | 见 P1-6 | 改文案即断 |
| F3 | `absolute()` 比较判定原地写 | `engine.rs:1239`、`rejection.rs:365` | 大小写/符号链接 → 丢 `.bak` |
| F4 | 展示名当路由 | `engine.rs:1911` | 改名即断 |
| F5 | JPEG 多段链回推依赖“段间正好 4 字节” | `jpeg.rs:366` | 链中插入其它 APP 段 → 认不出信封 |
| F6 | 空间域 header 种子无 KDF 工作因子 | `stego/envelope.rs:118` | 见 §7 S1 |
| F7 | i18n 只翻外壳 | `errors.rs` + `engine.rs` 等几十处 `format!` | 中文界面下错误详情仍是英文 |
| F8 | `make_png` 夹具自相矛盾 | `tests/common/mod.rs:37/46` | 见 P2-16 |

---

## 7. 安全相关观察（权衡，非漏洞，建议显式记录）

### S1 空间域 header 位置种子没有 KDF 工作因子

`stego/envelope.rs:118` 的 `derive_header_perm_seed` 只做 HKDF，直接拿口令当 IKM。
攻击者可只付 HKDF 代价（微秒级）试口令：算 header 槽位 → 读 32 字节头 →
用 `total_len ∈ [49, MAX]`、`stc_h == 15`、`FeatureWord::decode` 三重校验过滤。
失败率极高，但确实比 AEAD 便宜。JPEG 侧刻意规避了（`envelope.rs:114-117` 有解释：
header 种子走 suite KDF + cover digest）。空间域是否对齐，建议写进 `docs/` 作为已知取舍，
而不是只留一句代码注释。

### S2 `BUILTIN_DEFAULT_KEY` 的语义边界

无密码信封用公开内置密钥（文档已说明，`read` 也会告警 `WarnEnvelopeNotEncrypted`，
`cli.rs:1206-1208`）。属可接受的默认值，但需要文档持续强调“无密码 ≠ 机密”。

---

## 8. 测试覆盖的薄弱面

测试总量可观（146 单元 + 110 集成 + 68 生命周期 + 15 安全），但下列路径无覆盖，
恰好是问题最密集处：

- **>64 MiB 载体**（B1/B7）——目前唯一“确定性漏报”
- **错误路径**：`CorruptedData` 各分支、截断文件、`strip` 的 `patch_offset` 分支
- **非 UTF-8 路径**（B5）——语料全是 ASCII 文件名
- **畸形/炸弹 PNG、超大 `cd_size` ZIP**（B4）
- **`probe` vs `embed` 容量一致性**（B2）——一条属性测试即可挡住：
  “probe 报 N 字节 → embed N 字节必须成功”
- **`remove_carrier` 输出到已有文件**（P1-2）、**`verify` 退出码**（P1-3）
- **测试夹具自身有效性**（P2-16）——建议加“夹具必须能被 `decode_png` 解出 1×1”的断言，
  这类自欺性夹具只能靠这种断言防住

---

## 9. 处理顺序建议

| 优先级 | 项 | 改动量 | 备注 |
|---|---|---|---|
| P0 | B1/B7 大文件扫描视图（gmf 提议的 `WindowedData`） | 中 | 唯一确定性漏报，先加失败用例 |
| P0 | B4 解压上限（analysis + spatial） | 小（~15 行） | |
| P0 | B3 PNG 单遍 CRC | 小（~10 行） | 纯收益 |
| P0 | B5 非 UTF-8 临时路径 | 小（3 行） | |
| P0 | B2 + D1 抽 `build_slot_plan` | 中（~80 行重构，行为不变） | 一次解决两个 |
| P1 | P1-1 PBKDF2 去重 | 中 | 每次读写省 100–250 ms |
| P1 | B6 PDF `/Size`（seek prev_startxref） | 中 | 需构造 XRef 流夹具 |
| P1 | P1-4 拷贝循环统一 `copy_exact` | 中（机械替换 10+ 处） | 消除静默截断 |
| P1 | P1-5 目录遍历容错、P1-7/P1-8 小修 | 小 | |
| P1 | P1-2/P1-3 语义对齐（覆盖保护、退出码） | 小 | 需先定语义 |
| P2 | P1-6 结构化错误（`StrHideError` 加变体 + `hint` 字段） | 中 | 跨模块，需同步改测试 |
| P2 | P2-1/P2-2/P2-3/P2-4 局部去重 | 中 | 净减约 145 行（gmf 估算） |
| P2 | P2-16 夹具修正（IHDR + Zlib） | 小 | 两处必须同时改 |
| P3 | D10 死代码、F1 `framed_len()`、P2-8/10/11/12/14 小修 | 小 | |

---

## 10. 对 gmf 报告的逐条核实

| gmf | 论断 | 核实结论 | 差异 |
|---|---|---|---|
| #1 | `api_bytes.rs:371 tempdir()` 并发碰撞 | **成立**：`as_nanos()` 拼 `pid`，`create_dir_all` 对已存在目录不报错，`cleanup` 的 `remove_dir_all` 会误删邻居；与 `common::scratch`（带 `rand::random`）不一致 | 碰撞粒度是时钟刻度而非“同一毫秒”；建议直接改用 `common::scratch` |
| #2 | >64MB 拼接伪 ASCII 导致 100% 漏报 | **核心成立**：拼接 + “PNG/JPEG 跳过熵检测”使结构证据全丢 | “100% CLEAN”过头，已知签名仍会命中。已改写为 B1 |
| #3 | PDF 尾部 64KB 猜对象号 | **成立**，忽略 `prev_startxref` 属设计缺陷 | 错误变体是 `CorruptedData` 非 `UnsupportedFormat`；`auto` 回退 `eof` 而非硬失败；真正危害是对象号偏小导致冲突。已改写为 B6 |
| #4 | PNG inject 把 UBE 读两遍 | **完全成立**（`png.rs:154-180`） | 采纳为 B3 |
| #5 | JPEG marker 扫描 3 份 + 单字节 I/O | **成立**：三处状态机逐行近似，宿主确为未缓冲 `File` | 无 |
| #6 | CLI 载荷解析 40 行重复 | **成立** | 补充：`handle_embed` 内部还有**另一处**参数装配重复（P2-3），两者都要改 |
| #7 | 目录遍历单条异常中止整批 | **成立** | 修法修正：`entry.file_type()` 不 follow 链接，无成环风险，不需要 visited 集合 |
| #8 | 错误处理靠字符串匹配 | **成立**：`engine.rs:62/69` 重复判断、`529/573` 两处 `contains("no legal element")` | 补充：CLI 解析 hint（`cli.rs:1179`）同类，应一并结构化 |
| #9 | `make_png` IHDR 尺寸 16M×16M | **成立**：`[1,0,0,0,...]` 按大端解读 | 补充：本仓库内不会 OOM（长度检查在分配前）；且 IDAT 用 raw deflate 而非 zlib，两缺陷互相掩盖。已合并进 P2-16 |
| #10 | `extract_jpeg` 每套件重建网格 | **成立** | `clear()` 保留容量，是 O(n) 重算而非“多次重分配” |

### gmf 未覆盖、本报告新增的主要项

B2（容量口径）、B4（解压炸弹）、B5（非 UTF-8 路径）、B7（PE/JPEG 大文件跳过）、
P1-1（PBKDF2 重复）、P1-2（remove 覆盖保护）、P1-3（verify 退出码）、P1-7（`is_inplace`）、
P1-8（灰度 JPEG 通道）、§5（过度防御）、§6（脆弱耦合）、S1（空间域 header 种子强度）。

---

## 11. 结论

代码质量在同类项目中属上游：格式解析有边界检查、加密参数有单一真源、注释解释“为什么”。
当前最值得投入的不是加功能，而是三件事：

1. **修掉大文件扫描盲区**（B1/B7）——唯一“确定性漏报”，也是两份报告唯一的汇合级严重项；
2. **把三份复制粘贴的选槽逻辑合并成一份**（B2/D1）——同时消灭一处口径分歧；
3. **消掉 PBKDF2 的重复计算**（P1-1）——每次读写实打实省 100–250 ms。

其余（重复代码、死代码、过度防御、字符串耦合）都是清理，可按 §9 的节奏逐步收。

---

## 12. 处理台账（2026-10-22 整改记录）

P0 / P1 全部完成；P2 完成绝大部分；§5（过度防御）与 §7（安全观察，属设计取舍）按原样保留。
详细变更见 `docs/CHANGES-20261022.md` 顶部条目。

| 编号 | 状态 | 落点 |
|---|---|---|
| B1 / B7 | ✅ 已修 | `analysis.rs` `ScanView`（prefix/tail 分离）+ `walk_png_chunks` + `report_jpeg_tail`；3 个回归测试 |
| B2 / D1 | ✅ 已修 | `stego/spatial/engine.rs` `SlotPlan`；probe 接收凭据；容量一致性测试 |
| B3 | ✅ 已修 | `adapters/png.rs::inject` 单遍 CRC |
| B4 | ✅ 已修 | `analysis.rs` / `spatial/engine.rs` / `stego/envelope.rs` inflate 上限 |
| B5 | ✅ 已修 | `engine.rs` `remove_carrier_with_options` OsString 临时路径 |
| B6 | ✅ 已修 | `adapters/pdf.rs` `read_xref_stream_dict` |
| P1-1 | ✅ 已修 | `crypto::derive_all` + `envelope::UnpackSecrets`；PBKDF2 次数 5→2/3 |
| P1-2 | ✅ 已修 | `engine::remove_carrier_with_options(overwrite)` |
| P1-3 | ✅ 已修 | `LevelStatus::skipped` + `engine::verify_passed` |
| P1-4 / D8 | ✅ 已修 | `io::copy_exact` / `io::copy_stream` 统一 10+ 处 |
| P1-5 | ✅ 已修 | `cli.rs` 目录遍历告警 + continue |
| P1-6 | ✅ 已修 | `StrHideError::PasswordWithHint` / `TrellisInfeasible` + `hint()` |
| P1-7 / F3 | ✅ 已修 | `engine::same_file` |
| P1-8 | ✅ 已修 | `decode_jpeg_pixels` 按 `PixelFormat` |
| P2-1 / D9 | ✅ 已修 | `adapters/jpeg.rs` `scan_jpeg_markers`（单一状态机 + BufReader） |
| P2-2 / D7 | ✅ 已修 | `cli.rs::resolve_payload` |
| P2-3 | ✅ 已修 | `cli.rs::embed_stego_options` |
| P2-4 | ✅ 已修 | `extract_jpeg` 网格模板 `extend_from_slice` |
| P2-6 | ✅ 已修 | `inspect` 内容容量读取上限 512 MiB + 显式 seek |
| P2-7 | ✅ 已修 | `check_pe_authenticode` / `check_pdf_signature` 统一 `seek(0)` |
| P2-8 | ✅ 已修 | `MIN_ENVELOPE_LEN` / `HEADER_OVERHEAD` 替换字面量 |
| P2-9 | ✅ 已修 | 空口令文件返回 `None` |
| P2-10 | ✅ 已修 | 配置单次 `toml::Table` + `try_into` |
| P2-11 | ✅ 已修 | `JpegParams::slot_budget: Option<usize>` |
| P2-12 | ✅ 已修 | 备份兜底继续探测存在性 |
| P2-14 | ✅ 已修 | `router::MAX_STRATEGY_ID` 由注册表推导 |
| P2-15 / F4 | ✅ 已修 | `HostAdapter::supports_content_stego()` |
| P2-16 / F8 | ✅ 已修 | `make_png` IHDR 大端 + zlib IDAT + 夹具自检测试 |
| F1 | ✅ 已修 | `crypto::framed_len` / `chunk_count` / `AEAD_TAG_LEN` + 一致性测试 |
| D2 | ✅ 已修 | `coding::slots_for_codec` 两引擎共用 |
| D10 | ✅ 已修 | 删除 `has_hint`、`pack_with_stealth_mask`、`validate_stc_u_wide` 别名 |
| P2-5 | ⏸ 未做 | `verify` L3 仍整条重读载荷（性能项，改动面涉读取主路径，留待单独评估） |
| P2-13 | ⏸ 未做 | CLI `embed` 落盘仍为直接 `fs::write`（无 temp+rename / 权限时间戳保留） |
| §5 过度防御 | ⏸ 未做 | 均为"多一层无害检查"，改动收益低于风险，保留 |
| §7 安全观察 | 📝 已记录 | S1/S2 属已知取舍，建议在 `docs/` 单独成文，未在代码层改动 |

### 验收口径

- `cargo fmt --check` / `cargo clippy --all-targets -D warnings` / `cargo test --all-targets` 全绿；
- `batch_corpus`（temp/testfiles 全语料，reject/明文/加密/stealth 四场景）240/240 100% 还原；
- `batch_stego`（temp/teststego 全量真实大图）自检结果与整改前基线一致。
