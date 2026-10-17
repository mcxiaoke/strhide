# strhide Rust 实现评审报告与改进方案

> 文档编号：STRHIDE-DOC-20261017-02
> 评审日期：2026-10-17 13:43:21
> 评审基线：`92e49c5 feat(rust): implement strhide in Rust with bidirectional cross-compatibility`
> 评审对象：`rust/src/**`（2024 edition，`cargo 1.96.0`）、`docs/smart_file_data_hiding_design.md`（UBE v2.2 规范）、`python/strhide/**`（作为行为基准）
> 评审方式：静态通读全部 Rust 源码 + 与 Python 实现逐点对照 + release 二进制实测复现（不复现不下结论）
> 结论：架构与密码学实现基本可信，但存在 **3 项高危语义/安全缺陷**、**6 项中危健壮性缺陷**、若干一致性缺陷，均未在当前测试矩阵中覆盖。

---

## 1. 评审范围与方法

| 项目 | 内容 |
| :--- | :--- |
| 静态审查 | `rust/src` 全部 17 个源文件（envelope / crypto / engine / rejection / router / cli / errors / main / lib + 7 个适配器） |
| 规范比对 | 与 `docs/smart_file_data_hiding_design.md` 的 UBE v2.2 字段定义、§3.5 流式写入声明、§8 原子与属性克隆要求、§9 CLI 规范逐条核对 |
| 行为基准 | 与 `python/strhide/**` 在信封布局、密钥派生、压缩取舍、提取落盘、CLI 参数上逐点对照 |
| 动态验证 | `cargo test`、`cargo clippy --all-targets`、release 二进制端到端复现（载体取 `temp/testfiles`，产物落 `temp/opt`） |
| 未执行项 | 未做性能基准、未做跨平台（Linux/macOS）实测、未做模糊测试 |

---

## 2. 结论摘要

| 编号 | 级别 | 问题 | 位置 | 已复现 |
| :--- | :--- | :--- | :--- | :--- |
| R1 | 高危 | `--stealth` 不带密码时静默降级为普通模式，且 `is_stealth` 回传值失真 | `engine.rs:262-283`、`engine.rs:525` | 是 |
| R2 | 高危 | 提取时未净化文件名，存在目录穿越写入 | `cli.rs:392-399`、`engine.rs:651-661` | 是 |
| R3 | 高危 | “载体已含隐藏数据”保护对 stealth 载体失效，允许二次注入且数据不可达；自检逻辑同时过弱 | `engine.rs:191-195`、`engine.rs:437-452` | 是 |
| R4 | 中危 | `auto` 策略容量估算漏算每块 4 字节长度前缀，导致本应自动回退的场景硬报错 | `engine.rs:299-313` | 是 |
| R5 | 中危 | 写入失败残留 `<carrier>.strhide.tmp` | `engine.rs:383-389` | 是 |
| R6 | 中危 | 头部字段无边界校验，`u64` 相减可下溢，存在内存放大 / 分配失败风险 | `envelope.rs:111-163`、`engine.rs:568-611`、`crypto.rs:227-244` | 是 |
| R7 | 中危 | 全内存缓冲，与规范 §3.5“流式读写不耗尽内存”声明相矛盾 | `engine.rs:199-237`、`342-380`、`613-635` | 代码确认 |
| R8 | 中危 | 未克隆文件权限，与规范 §8.4 不符 | `engine.rs:465-467`、`754` | 代码确认 |
| R9 | 中危 | CLI 参数与 Python / 文档三方不一致（`--preserve-time`） | `cli.rs:77-78` | 是 |
| R10 | 低危 | 压缩取舍判据与 Python 不等价（先截断 vs 浮点比较） | `crypto.rs:233` | 代码确认 |
| R11 | 低危 | ZIP `patch_offset` 以 u32 保存，容量检查未覆盖 `eocd_pos + 16 + ube_size` | `zip.rs:100-104`、`147-150` | 代码确认 |
| R12 | 低危 | 三处死代码 / 无效分支 | `png.rs:182`、`jpeg.rs:234`、`mod.rs:79-83`、`python/strhide/core/crypto.py:98-133` | 代码确认 |
| R13 | 低危 | 23 条 clippy 告警未清理 | 全仓 | 是 |
| R14 | 低危 | 文案与文档滞后（MP4 “64-bit uuid Box”、Rust 2021 vs edition 2024） | `engine.rs:496`、`Cargo.toml:4` | 代码确认 |
| R15 | 低危 | Rust 侧缺少适配器/引擎/损坏输入测试，仅 2 个 crypto 单测 | `rust/` 无 `tests/` | 是 |

---

## 3. 高危问题明细

### R1 `--stealth` 不带密码时静默降级为普通模式

* **现象**：`write --stealth` 在未提供密码时既不报错也不告警，按普通模式写出（`FLAG_STEALTH` 未置位、使用标准魔数 `\x89STRHIDE`/`STH!`），但返回结构 `WriteResult.is_stealth` 仍为 `true`。
* **代码**：`engine.rs:262` 的条件为 `if stealth && is_encrypted`，无密码时直接落入 `else` 分支；`engine.rs:525` 直接回传入参 `stealth`。
* **复现**：
  ```powershell
  $exe = "rust\target\release\strhide.exe"
  Copy-Item temp\testfiles\file-00.mp4 temp\opt\c.mp4 -Force
  & $exe write  -c temp\opt\c.mp4 -t "hello world" --stealth
  & $exe inspect -c temp\opt\c.mp4          # Stealth Mode: false
  & $exe read   -c temp\opt\c.mp4 --stdout  # hello world（无需密码）
  ```
  实测输出：`WriteResult.is_stealth = true`，但 `inspect` 报 `Stealth Mode: false`，`read` 无密码成功；二进制中 `\x89STRHIDE` 位于偏移 1008428（已用 Python 断言定位）。
* **影响**：用户以为获得“可否认性 + 去特征化”，实际得到最易被 `strings` / YARA / 杀软特征命中的标准模式。这属于安全承诺与实际行为不一致，是本工具语境下最严重的问题。
* **建议**：
  1. `password.is_none() && stealth` 时直接抛错（推荐），或让 `--stealth` 隐含要求 `-p`；
  2. 若保留宽容行为，则至少输出强告警，并让 `is_stealth` 返回 `header` 实际标志值；
  3. CLI 增加 `[STEALTH]` 提示行，明确写出实际生效的模式与魔数来源。

### R2 提取时未净化文件名，存在目录穿越写入

* **现象**：载体元数据中的 `filename` 被直接用于落盘路径，未做 basename 净化。
* **代码**：`cli.rs:392-399`（无 `-o` 时 `File::create(fn_to_use)`）、`engine.rs:651-661`（`-o <dir>` 时 `out_p.join(fn_to_use)`）。Python 侧有防护（`python/strhide/core/engine.py:522` `os.path.basename`），Rust 缺失。
* **复现**（普通模式 metadata 为明文，可将 `AAAAA.txt` 等长替换为 `../../x.b`）：
  ```powershell
  # 8 字节源文件名 -> 等长替换为 9 字节穿越名（脚本见附录 A）
  & $exe read -c temp\opt\c2.png
  # [OK] Extracted payload to '../../x.b' (16 bytes).
  # 实际落盘：C:\...\temp\opt\x.b（越过 CWD 两级）
  ```
* **影响**：接收方打开第三方提供的载体文件即可能被写入工作目录之外任意相对路径；`-o <dir>` 路径同样受影响。属于典型的“不可信输入 + 路径拼接”漏洞。
* **建议**：落盘前统一走 `Path::new(&meta_obj.filename).file_name()`，拒绝空名、绝对路径与含 `..` 的组件；对 `-o <dir>` 分支复用同一净化函数；行为与 Python 对齐。

### R3 二次注入保护失效 + 自检过弱

* **现象 A**：`write` 只在 `locate(cf, None)` 命中标准魔数时才拒绝“已含隐藏数据”。stealth 载体使用派生魔数，必然匹配失败，于是被判定为“干净”，允许二次写入。
* **现象 B**：自检（`engine.rs:437-452`）只验证“能定位到任意一个信封”，不验证“能定位到刚写入 `actual_ube_offset` 处的信封”，因此二次注入也能通过自检。
* **复现**：
  ```powershell
  Copy-Item temp\testfiles\file-02.png temp\opt\st.png -Force
  & $exe write -c temp\opt\st.png -t "topsecret" -p pw1 --stealth --no-backup   # 成功
  & $exe write -c temp\opt\st.png -t "second"    -p pw1 --stealth --no-backup   # 本应拒绝，实际成功
  & $exe read  -c temp\opt\st.png -p pw1 --stdout   # topsecret（第二次写入的数据不可达）
  ```
* **影响**：同一载体出现两个 `prIv` 信封，`locate` 恒定返回第一个，第二次写入的数据成为永久不可读的垃圾；载体体积与结构异常度叠加，隐蔽性反而下降。若发生在 in-place 场景且用户以为“覆盖”了旧数据，还会造成数据语义误解。
* **建议**：
  1. 写入前，若已获得密码，用 `derive_stealth_magics` 派生魔数再执行一次 `locate(Some(magic))`；
  2. 自检改为精确校验：读回 `actual_ube_offset` 处 header，核对 `inject_offset`/`inject_size`，并在 `actual_ube_offset + ube_total_size - 24` 处解出 trailer，核对 `ube_offset == actual_ube_offset && ube_total_size == ube_total_size`；
  3. 可考虑为 `locate` 增加“返回全部命中列表”的内部接口，便于诊断重复信封。

---

## 4. 中危问题明细

### R4 `auto` 策略容量估算漏算分块长度前缀

* **代码**：`engine.rs:299-308`
  ```rust
  let est_payload_len = to_encrypt_len
      + if is_encrypted { ((to_encrypt_len + 2097152 - 1) / 2097152) * 16 } else { 0 };
  ```
  加密路径实际每块写 `4B chunk_len + 密文 + 16B Tag`（`crypto.rs:195-198`），估算漏掉 `4 * ceil(len / 2MB)` 字节。
* **后果**：估值为 `est`、实际为 `est + 4`。当 `est ∈ [65530, 65533]`（JPEG）、或落在 PNG/ZIP 阈值同类窗口时，`choose_auto_strategy` 选出 `app_segment`，随后 `inject` 抛 `UnsupportedFormat`，与 `auto` 的“自动降级、不静默失败”承诺冲突（规范 §6.1）。
* **复现**（JPEG，加密载荷 65220 字节，文件名 `rand3.bin`，est=65533、actual=65537）：
  ```
  [ERROR] Unsupported format: Payload size (65537 bytes) exceeds JPEG single segment maximum capacity (65533 bytes). Please specify --strategy eof.
  ```
* **建议**：
  1. 估算公式补上 `4 * chunks`；
  2. 更稳妥的做法是在 `ube_total_size` 落定后（`engine.rs:356` 之后）对 `auto` 模式再执行一次策略判定与“是否需要回退”的检查，形成“估算用于预排布、实测用于最终决策”的双重保险；
  3. 为阈值附近增加参数化测试（`est = limit - 4 .. limit + 4`）。

### R5 写入失败残留临时文件

* **代码**：`engine.rs:383-389` 中 `adapter.inject(...)?` 使用 `?` 早退，未清理 `tmp_target`；只有自检失败分支（`engine.rs:447-452`）显式删除。
* **复现**：接 R4 的失败用例，失败后目录中留下 `c6.jpg.strhide.tmp`。
* **影响**：失败操作在载体同目录留下半成品文件，既是磁盘垃圾，也容易被误认为“已注入”的产物；Python 侧同样存在该问题（`engine.py:287-291`）。
* **建议**：将 `inject` 调用用 `match` 包裹，出错时删除 `tmp_target`；更推荐引入 RAII guard（结构体 `Drop` 中删除未被提交的临时文件），使提交路径 `std::mem::forget`/`commit()` 后不再删除。

### R6 头部字段无边界校验，存在下溢与内存放大

* **代码**：
  * `envelope.rs:111-163` `EnvelopeHeader::unpack` 只校验长度，不校验 `version == 0x02`、`hint_len <= 1024`、`strategy_id` 取值范围；`CURRENT_VERSION` 仅用于写入，读取路径从未比对（`version` 字段除 AAD 外无消费方）。
  * `engine.rs:569`、`821` 以 `header.hint_len as usize` 直接 `vec![0u8; n]`；`engine.rs:593`、`828` 同理使用 `header.meta_len`。
  * `crypto.rs:229-239` 以流内 `chunk_len` 直接 `vec![0u8; chunk_len]`，无上界（规范上界为 `CHUNK_SIZE + 16`）。
  * `engine.rs:607-611` `total_payload_bytes = ube_total_size - 112 - hint_len - meta_len - 24` 为无保护 `u64` 相减。
* **复现**：将 `temp\opt\c.mp4` 的 header `meta_len`（UBE 偏移 +104）改写为 `0xFFFFFFF0` / `0xFFFFFFFF`：
  ```
  [ERROR] I/O error: failed to fill whole buffer
  ```
  release 构建下 Windows 惰性提交未崩溃，但在此之前已发起数 GB 量级分配尝试；若为 debug 构建或 Linux overcommit 环境，将分别触发 `attempt to subtract with overflow` panic（`panic = "abort"`）或 OOM kill。
* **建议**：
  1. `unpack` 内或 `read/inspect/verify/remove` 入口统一校验：`version == CURRENT_VERSION`、`hint_len <= 1024`、`meta_len/hint_len` 之和不超过 `ube_total_size - 112 - 24`；
  2. `total_payload_bytes` 一律改用 `checked_sub`，失败即返回 `CorruptedDataError`；
  3. 解密循环校验 `chunk_len <= CHUNK_SIZE + 16`；
  4. 分配前先与实际剩余字节数比对，避免“先分配后读失败”。

### R7 全内存缓冲与规范声明矛盾

* **代码**：`engine.rs:199-237`（`read_to_end` / `to_vec` 载入完整载荷并压缩）、`342-380`（密文缓冲 + 完整 UBE `Vec`）、`613-635`（解密结果与解压结果各持一份完整缓冲）；`ReadResult.data` 恒为完整 `Vec<u8>`。
* **量化**：写路径峰值约为载荷的 3 倍（原始载荷 + 压缩缓冲 / 密文缓冲 + 完整 UBE），读路径约为 2–3 倍。
* **影响**：规范 §3.5 明确宣称“支持大文件流式读写而不耗尽内存”，实测实现与该声明不符；对大载体写入百 MB 级载荷时内存占用显著。Python 侧（`tmp_ube` 为 `BytesIO`）同样存在。
* **建议**（两种路径二选一）：
  * **改实现**：写路径先写占位 header → 流式压缩/加密并统计 `meta_len` 与 `payload_written` → 回填 header 与 trailer（适配器已具备回填能力，改动集中在 `engine.rs`）；读路径以 `take()` 精确界定载荷区间，流式解密/解压后直接写入目标文件，仅在 `--stdout` 时才考虑整块输出；
  * **改声明**：若短期不改实现，则把 §3.5 的流式声明改为“载荷在内存中处理，建议单次载荷不超过 X MB”，避免文档与实现长期背离。

### R8 未克隆文件权限

* **代码**：`engine.rs:465-467`（写）、`754`（还原）仅调用 `filetime::set_file_times`；全仓无 `set_permissions`。
* **影响**：临时文件经 `File::create` 后以 rename 替换目标，Unix 下会丢失原文件 mode（含可执行位、只读位），与规范 §8.4“克隆权限模式与时间戳”不符；Windows 下影响较小。另外 `write --preserve-time` 只作用于时间戳，权限问题与之独立。
* **建议**：写入前记录 `metadata.permissions()`，rename 后 `set_permissions`；还原路径同样处理；并补一条 Unix 下的集成测试断言 mode 一致。

### R9 CLI 参数与 Python / 文档三方不一致

* **代码**：`cli.rs:77-78` 使用
  ```rust
  #[arg(long = "preserve-time", default_value_t = true, action = clap::ArgAction::Set)]
  ```
* **实测**：
  ```
  --preserve-time        -> error: a value is required for '--preserve-time <PRESERVE_TIME>'
  --no-preserve-time     -> error: unexpected argument '--no-preserve-time' found
  ```
* **对照**：Python 为 `--no-preserve-time`（store_false，默认 True，`python/strhide/cli.py:264`）；规范 §9 列出的是 `--preserve-time`。三方互不相容。
* **建议**：统一为 `--no-preserve-time`（与 Python 一致，且不破坏“默认保留时间戳”的语义），同步更新 §9 文档；若需保留开关，改用 `ArgAction::SetTrue` 的反向语义或提供 `aliases = ["no-preserve-time"]`。

---

## 5. 低危问题明细

| 编号 | 问题 | 位置 | 说明与建议 |
| :--- | :--- | :--- | :--- |
| R10 | 压缩取舍判据不等价 | `crypto.rs:233` vs `python/strhide/core/crypto.py:164` | Rust 为 `comp_len < (raw_size as f64 * 0.98) as u64`（先截断），Python 为 `comp_len < raw_len * 0.98`（浮点比较）。例：`raw_size=102, comp_len=99`，Rust 判不压缩、Python 判压缩。因 `FLAG_COMPRESSED` 自描述，不影响互操作，但两实现行为不统一，建议统一为整数比较 `comp_len * 100 < raw_size * 98` |
| R11 | ZIP `patch_offset` u32 截断 | `zip.rs:100-104`、`147-150` | 容量检查只覆盖 `cd_offset + ube_size < 0xFFFFFFFF`，未覆盖 `eocd_pos + 16 + ube_size`。接近 4GB 的 ZIP（含 EOCD 注释时 `eocd_pos` 可远超 `cd_offset`）会截断 `patch_offset`，导致 `remove` 必然 `RestoreMismatch`——是安全失败（不会静默损坏），但该载体永远无法还原。建议把检查条件改为 `max(cd_offset, eocd_pos + 16) + ube_size < 0xFFFFFFFF`，或在超界时同样降级 `eof` |
| R12 | 死代码 / 无效分支 | `png.rs:182`、`jpeg.rs:234`、`mod.rs:79-83`、`python/strhide/core/crypto.py:98-133` | ①`png.rs:182`/`jpeg.rs:234` 的 `if expected_trailer_magic.is_none() && trailer.trailer_magic != STANDARD_TRAILER_MAGIC` 永不可达——`EnvelopeTrailer::unpack` 在 `expected_magic.is_none()` 时已按标准魔数校验并返回 `Err`；②`mod.rs:79-83` 通用 `strip` 的 `patch_offset` 分支无人触发（唯一使用 `patch_offset` 的 ZIP 自己重写了 `strip`），且以未回移的绝对偏移写回口径有误，属潜在陷阱；③Python `crypto.py:98-133` 的 `encrypt_stream_chunked` 是返回 `0` 的半成品桩函数。建议全部删除 |
| R13 | clippy 告警 | 全仓 | `cargo clippy --all-targets` 共 23 条：16×`collapsible_if`（`jpeg.rs:232`、`pdf.rs:247/262/60`、`pe.rs:209/77`、`png.rs:175/180`、`zip.rs:173/177/178` 等）、5×`unwrap` on `password` after `is_some`（`engine.rs:549/705/782/893/928`）、`manual_div_ceil`（`engine.rs:304`）、`too_many_arguments`（`engine.rs:124`）。建议清零并纳入 CI（`-D warnings`） |
| R14 | 文案与文档滞后 | `engine.rs:496`、`Cargo.toml:4` | ①MP4 的 `strategy_note` 仍写 “64-bit uuid Box”，实际 `< 4GB` 使用 24 字节 32 位头（`mp4.rs:88-94`）；②`png.rs` 回退提示 “exceeded PNG chunk limit (2GB)” 语序不顺；③规范 §10 写 “Rust 2021”，`Cargo.toml` 实为 `edition = "2024"`；④规范 §11 引用的 Rust 单测数量（2/2）与实际一致，但未说明测试覆盖范围极窄 |
| R15 | Rust 侧测试覆盖不足 | `rust/` 无 `tests/` | 目前仅 `crypto.rs:354-400` 两个单测（派生向量、deflate 往返）。适配器、引擎、损坏输入、路径穿越、stealth 语义均依赖 Python 侧 `python/tests/test_rust_cross_compat.py`（且其 `RUST_BIN` 指向 `rust/target/debug/strhide.exe`，需先编 debug 产物）。建议新增 `rust/tests/` 集成测试覆盖 R1–R6 与各适配器生命周期 |

补充（非问题，仅提示）：对 PE 使用 `--strategy eof` 时，`locate` 会把它报告为 `pe_overlay`（`pe.rs:209-217` 只要有 trailer 且 `ube_offset >= pe_image_end` 即返回该策略名）。功能无损，仅策略名不准，可在返回前增加“`ube_offset + ube_total_size == file_size` 则判定为 eof”的优先级调整。

---

## 6. 改进路线图

按“先堵安全与正确性、再补健壮性、最后清理”推进，每步均需保持 Python/Rust 跨语言套件全绿。

**阶段一（安全与正确性，必须）**
1. R1：`--stealth` 无密码直接报错；`is_stealth` 回传实际 header 标志。
2. R2：提取路径统一 `file_name()` 净化并拒绝 `..`/绝对路径。
3. R3：写入前用派生魔数补做“已存在信封”检测；自检改为精确校验刚写入的 `actual_ube_offset`。
4. R4：估算补 `4 * chunks`；`auto` 模式在实测尺寸落定后再判一次回退。
5. R5：失败路径清理 tmp（RAII guard 优先）。

**阶段二（健壮性与一致性，强烈建议）**
6. R6：`version` / `hint_len` / `meta_len` / `chunk_len` 全量边界校验，`checked_sub` 替换裸减法。
7. R7：真流式改造，或修正 §3.5 声明。
8. R8：克隆权限（写入与还原两处）。
9. R9：CLI 统一为 `--no-preserve-time` 并同步 §9。

**阶段三（质量清理，建议排期）**
10. R10–R12：统一压缩判据、修正 ZIP 容量检查、删除死代码。
11. R13：clippy 清零 + CI 门禁。
12. R14：文案与文档同步（MP4 头型描述、edition、§9 参数）。
13. R15：新增 `rust/tests/` 集成测试，把本次评审的复现用例固化为回归测试。

---

## 附录 A 复现脚本与证据

所有实测产物位于 `temp/opt/`（不属于源码变更，评审期间 `git status` 保持干净）。

**A.1 环境与编译**
```powershell
cd C:\Home\Projects\mytools\tools\strhide\rust
cargo test                       # 2 passed
cargo clippy --all-targets       # 23 warnings
cargo build --release            # rust\target\release\strhide.exe
```

**A.2 R1 stealth 静默降级**
```powershell
$exe = (Resolve-Path "rust\target\release\strhide.exe").Path
Copy-Item temp\testfiles\file-00.mp4 temp\opt\c.mp4 -Force
& $exe write   -c temp\opt\c.mp4 -t "hello world" --stealth
& $exe inspect -c temp\opt\c.mp4                      # Stealth Mode: false
& $exe read    -c temp\opt\c.mp4 --stdout             # hello world
python -c "d=open(r'temp/opt/c.mp4','rb').read(); print('magic at', d.rfind(b'\x89STRHIDE'))"
# magic at 1008428
```

**A.3 R2 目录穿越**
```powershell
python -c "
d=open(r'temp/opt/c2.png','rb').read()
assert d.count(b'AAAAA.txt')==1
open(r'temp/opt/c2.png','wb').write(d.replace(b'AAAAA.txt', b'../../x.b'))"
# 在 temp\opt\deep\dir 下执行 read -> 落盘到 temp\opt\x.b
```

**A.4 R3 二次注入**
```powershell
Copy-Item temp\testfiles\file-02.png temp\opt\st.png -Force
& $exe write -c temp\opt\st.png -t "topsecret" -p pw1 --stealth --no-backup
& $exe write -c temp\opt\st.png -t "second"    -p pw1 --stealth --no-backup   # 未被拒绝
& $exe read  -c temp\opt\st.png -p pw1 --stdout                               # topsecret
```

**A.5 R4 auto 边界失败 + R5 tmp 残留**
```powershell
python -c "import os; open(r'temp/opt/rand3.bin','wb').write(os.urandom(65220))"
Copy-Item temp\testfiles\file-06.jpg temp\opt\c6.jpg -Force
& $exe write -c temp\opt\c6.jpg -d temp\opt\rand3.bin -p pw123 --no-backup
# [ERROR] Unsupported format: Payload size (65537 bytes) exceeds JPEG single segment maximum capacity (65533 bytes)
Get-ChildItem temp\opt -Filter *.strhide.tmp      # c6.jpg.strhide.tmp 残留
```

**A.6 R6 篡改 header**
```powershell
python -c "
import struct
off=1008428; src=open(r'temp/opt/c.mp4','rb').read()
for name,val in [('huge',0xFFFFFFF0),('max',0xFFFFFFFF)]:
    b=bytearray(src); b[off+104:off+108]=struct.pack('<I',val)
    open(f'temp/opt/corrupt_{name}.mp4','wb').write(bytes(b))"
& $exe read -c temp\opt\corrupt_max_meta.mp4 --stdout
# [ERROR] I/O error: failed to fill whole buffer（分配数 GB 后失败）
```

**A.7 R9 CLI 参数**
```powershell
& $exe write -c temp\opt\pt.png -t x --preserve-time      # error: a value is required
& $exe write -c temp\opt\pt.png -t x --no-preserve-time   # error: unexpected argument
```

---

## 附录 B 评审中确认无问题的部分

为免误判，以下项经代码核对确认与规范/Python 一致，无需改动：

* 信封字节布局：112 字节头部 `<8sBBBB16s12sQ32sQQIIII`、80 字节不可变 AAD、24 字节尾标 `<QQI4s` 与 CRC32 覆盖范围，与 Python `envelope.py` 完全一致。
* 密码学：Unicode NFC → PBKDF2-HMAC-SHA256(100,000) → HKDF-SHA256 双域派生；stealth 魔数派生盐与 info 标签；meta nonce `^0xFFFFFFFF`；分块 nonce `^chunk_index`；分块 AAD `80B || idx(u64 LE) || is_last(u8)`；空载荷单空块处理——均有 `crypto.rs:358-386` 的跨语言向量断言兜底。
* 尾标定位与还原：各适配器 `locate` 的双向校验（CRC32 + 魔数 + 边界吻合）、`strip` 的逐比特回滚 + 全量 SHA-256 强校验，逻辑完整。
* MP4 32/64 位 Box 头自适应与中立 UUID、PNG `prIv` CRC 重算、JPEG COM 段前置 SOS、PDF 增量更新尾部 `endstream` 前 O(1) 反查、ZIP EOCD 偏移修正、PE 节区边界与 Authenticode 拦截——实现与规范一致，且已有真实样本批量验证记录。
* 安全预检：PE Authenticode、PDF 签名 64KB 重叠全盘扫描、APK/JAR/独立签名文件拦截，逻辑与 Python 对齐。
