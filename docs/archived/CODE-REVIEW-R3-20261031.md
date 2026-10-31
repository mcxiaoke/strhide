# strhide `rust/` 代码审查报告（第三轮 · 全面复审）

- 审查时间：2026-10-31 11:36–12:20（本机时间）
- 基线：`HEAD 2f2c110`，`strhide v0.8.1`，`rust/src` 共 104 文件 / 56 053 行，`tests/` 23 615 行
- 方式：静态通读（分 structure / stego-hevc / stego-png+jpeg / core / cli / analysis+facade 六块）+ **变异模糊测试实测** + 对关键结论逐条回源码复核并做最小复现
- 对照：`docs/CODE-REVIEW-R2-20261030.md`、`docs/CODE-REVIEW-dsf-20261029.md`、`docs/comprehensive_code_review_g4.md`
- 本次未改动任何代码

---

## 0. 结论摘要

**代码质量整体在这个项目的"可信度"上是够的，但还没到"可以随便交给陌生人对付任意文件"的程度。**

分项判断：

| 维度 | 评价 |
|---|---|
| 架构与模块边界 | 好。两域互不引用、feature 组合真实可选（4 种最小组合实测编译通过）、facade 是单一入口，`lib.rs` 的分层文档与实现一致 |
| 工程纪律 | 好。`fmt --check` / `clippy -D warnings` 零告警，**全仓无 TODO/FIXME**，无 `unsafe` 滥用（仅 2 处 SIMD + 1 处 Win32 调用，均有 feature 检测与边界推导） |
| 测试 | 中上。808 个测试（353 单元 + 455 集成）全绿；有回归目录（`review_20261019/1025/1030`）说明修 bug 会补测试；但**畸形输入/结构对抗覆盖薄**（本次仅凭一份 86 字节构造文件就打到 panic） |
| 错误模型 | 中上。`kind()` 稳定、`ErrorDetail` 可 i18n、口令不外泄；但 `CorruptedData` / `NoHiddenData` / `Password` 在 HEVC 与分析路径上互相越界，排障信息会被覆盖 |
| 不可信输入健壮性 | **弱**。这是本次的主要发现集中区：1 处已实测 panic、3 处 GB 级分配放大、2 处"删掉尾部标记即失明"的检测盲区 |
| 密码学 | 好。HKDF 域隔离清晰，`chunk_index`/`is_last` 进 AAD，截断/重排/删块均可检测；未发现密钥泄露或 nonce 复用可达路径 |
| 资源管理 | 弱且**不对称**：JPEG/HEVC 有预算框架，PNG 一个都没有；分析域的预算只加在解码器上，没跟着派生缓冲区走 |

结论：**再修掉下面 3 条 P0 + 6 条 P1 之后可以公开发布；以当前状态发，第一周就会收到"程序闪退/卡死/文件损坏"的 issue。**

---

## 1. 实测基线（本次亲自跑的命令）

| 项目 | 结果 |
|---|---|
| `cargo fmt --check` | 通过（exit 0） |
| `cargo clippy --all-targets --all-features -- -D warnings` | 通过，零告警 |
| `cargo test --all-features --all-targets` | **全绿**：353 单元 + 455 集成，0 failed |
| `cargo check --no-default-features` / `--features structure` / `content` / `analysis` | 4 种最小组合全部通过 |
| `cargo test local_ --all-features -- --ignored` | **21 passed / 0 failed，106.75 s**（含 HEVC/HEIF/PE/JPEG 真实语料） |
| 变异模糊测试（自建，1500 例 × 10 类载体 × 8 个入口） | **0 panic / 0 超时**——说明"随机噪声型"损坏已有基本盘 |
| 定向构造 | **1 例 panic**（见 P0-1），说明"结构对抗型"损坏没有被覆盖 |
| 非测试代码 panic 面统计 | 26 个文件、约 220 处 `try_into().unwrap()` 等，绝大多数有前置长度检查（抽查 4 个 adapter + 3 个 hevc box walker 均成立）；**1 处无保护（P0-1）** |

> 模糊测试说明：变异策略含截断、单字节/头尾改写、置零、插入垃圾、超大长度字段；语料含 PNG/JPEG/ZIP/PDF/MP4/MKV/HEIC/PE。0 panic 的结果主要来自这些格式的解析器确实做了边界检查，但也因为随机变异很难构造出"语义自洽的伪记录"——P0-1 就是只有定向构造才能命中的那一类。

---

## 2. P0：必修（panic / 资源耗尽 / 静默损坏）

### P0-1 【实测复现】JAR 签名检查对 `cd_size < 4` 直接切片 → 进程 abort

- 位置：`rust/src/structure/rejection.rs:283-291`
- 证据：

```rust
if cd_size == 0 { continue; }                 // :278 只挡了 0
let mut cd_buf = vec![0u8; cd_size as usize];
if reader.read_exact(&mut cd_buf).is_err() { continue; }
// :291
if &cd_buf[0..4] != b"PK\x01\x02" { continue; }
```

- 复现：86 字节文件 = `PK\x03\x04` + 60 字节 0 + EOCD（`cd_size=1, cd_offset=0`）：

```
$ sth write temp/jar_panic.zip --text hi -p test123
thread 'main' panicked at src\structure\rejection.rs:291:19:
range end index 4 out of range for slice of length 1
DEBUG EXIT=101
```

- 触发面：`run_rejection_checks` 是 `write` / `write_carrier_bytes` 的**前置路径**，`Strict` 与 `ContentOnly` 两种策略都会走；首 4 字节为 `PK\x03\x04` 即可进入（不要求是合法 ZIP）。
- 后果：`[profile.release] panic = "abort"`，release 下**进程直接终止**（Windows 上是 `STATUS_STACK_BUFFER_OVERRUN`），GUI/Tauri 后端一起退出，且发生在"还没开始写"的阶段，用户完全无法预期。
- 修法：`if !cd_buf.starts_with(b"PK\x01\x02") { continue; }`（一行）。
- 附带：`rejection.rs:272-273` 的 `cd_offset + cd_size > file_size` 是未 checked 的 u64 加法，同样应改 `checked_add`。

### P0-2 PNG 内容域没有任何工作集预算，按 `capacity` 建议值写入大图会 OOM abort

- 位置：`rust/src/stego/png/engine.rs:377`（只有像素数上限）、`rust/src/stego/coding/stc.rs:626-627`（回溯位图按 `n × states/8` 分配）
- 证据：

```rust
const MAX_PNG_PIXELS: usize = 64 * 1024 * 1024;      // png/engine.rs:377 唯一的闸门
...
let words_per_col = states.div_ceil(64);
let mut back = vec![0u64; n * words_per_col];        // stc.rs:626
```

`grep check_pipeline_budget|estimate_backtrack_bytes` 在 `src/stego/png/` 下**零命中**，而 JPEG 侧有 `MAX_PIPELINE_BYTES`(8 GiB) + `check_pipeline_budget`（`jpeg/engine.rs:96-100/177-187`）。

- 量化：24 MP RGB 载体 → body 池 ≈ 5000 万槽 → `h=8,u=3` 时 `back` ≈ **1.6 GB**（另加 HILL 的 5~6 个 f64 全图平面 ≈ 1.3 GB）；64 MP 上限下可到 4 GB 量级。分配失败即 `handle_alloc_error` → abort，无 `Result`。
- 触发面：用户按 `capacity` 报出的 `recommended_max_bytes` 写入大照片（这正是文档推荐的用法）。
- 修法：把 JPEG 的 `estimate_backtrack_bytes`/`check_pipeline_budget` 上提到 `stego::coding` 共用，PNG 在 `needed_body_slots` 确定后调一次；`body_slots_upto` 的 `with_capacity` 改为按真实可收集上限夹取（`png/engine.rs:1101-1105`）。

### P0-3 分析域 JPEG 标定把像素摊成 `f64` 全图平面，1 GiB 解码上限被放大到 3–8 GiB

- 位置：`rust/src/analysis.rs:1305-1307`、`rust/src/analysis/calibration.rs:123-127`
- 证据：

```rust
const MAX_DECODED_BYTES: usize = 1 << 30;
decoder.set_max_decoding_buffer_size(MAX_DECODED_BYTES);   // 只约束 u8 像素
...
if pixels.len() < width * height * channels { return None; }
let mut out = Vec::with_capacity(width * height);           // Vec<f64>：8 B/像素
```

- 量化：灰度 8-bit 载体在 1 GiB 上限内是 ~10.7 亿像素 → 平面 **8.6 GB**（同时还有 1 GiB 原图）；RGB 约 2.7 GB。`MAX_CALIBRATION_BLOCKS = 120_000` 只在平面建好之后按步长抽块，起不到保护作用。
- 触发面：`scan` 一个"声明 32768×32768、实际内容平坦、压缩后几十 KB"的 JPEG 即可。这是当前唯一能把**单文件扫描**变成进程级故障的路径。
- 修法：`luma_plane` 之前加像素数上限（如 6400 万）或按 8×8 块就地取 luma；同时把 `width * height * channels` 改成 `checked_mul`。

---

## 3. P1：正确性与语义

### P1-1 结构域 `verify` 在结构域通过时静默吞掉内容域失败，并返回 0

- 位置：`rust/src/cli/cmd_diag.rs:212-236`（单文件）、`:263-291`（批量）

```rust
content_stego: dual.content.filter(|c| c.is_all_ok()),   // 失败的 content 被丢掉
if struct_ok || !content_ok { print_verify_result(&dual.structure); }
if let Some(ref cs) = dual.content && cs.is_all_ok() { ... }
return Ok(if struct_ok || content_ok { 0 } else { 1 });
```

- 后果：一个结构信封完好、内容信封损坏的文件，`verify` 输出"L1/L2/L3 全 OK"、退出码 0，`--json` 里也看不到任何 FAIL。`verify` 作为准入闸门的结论不可信。
- 修法：内容域存在且未全 OK 时必须渲染 `print_content_verify_result` 并计入 `any_failed`。

### P1-2 分析域：删掉 IEND / EOI 就能让最重要的尾随数据检测整体消失，且报告会写出"clean termination at IEND"

- 位置：`rust/src/analysis.rs:707-712`（整文件无 IEND → "say nothing"）、`:1104-1119`（PNG/JPEG 被排除出熵规则）、`:383-399`（无条件写 PASS 文案）
- 证据：

```rust
None => {
    let Some((tail_offset, tail)) = view.tail else {
        // Whole file without a terminating IEND: a truncated PNG. Not
        // evidence of hidden data, so say nothing (as before).
        walk.emit(out); return;
    };
```

- 后果：把 PNG 末尾 12 字节 `IEND` 删掉再追加任意 payload → `png:trailing-data` 不产生任何 finding，熵检测器因 `Some(Png|Jpeg) => false` 不出场，`verdict = clean`，而 `detectors` 里仍写着 `PASS / "0 bytes" / "clean termination at IEND"`——文件里根本没有 IEND。零成本、零密钥的检测盲区。
- 修法：缺 end marker 时至少产出 `Suspicious`（或在 metric 里标 SKIPPED 并改写 detail），并让 `track_trailing_entropy` 在该情形下对 PNG/JPEG 生效。

### P1-3 `restore` 的"比特级还原"结论可被伪造：`remove` 从不解密 metadata，也从不校验 AAD

- 位置：`rust/src/structure/engine.rs:1867-1878`（remove 只 `unpack` + `validate_against`）、`:2319-2321`（`inject_size == 0` 短路）、`envelope.rs:337-343`（非 stealth 加密信封**不掩码** header）
- 依据：加密非 stealth 的 header 在盘上是**明文**（写入端注释写 "the AEAD authenticates it"，但 remove 路径根本不解密，等于从不认证）。攻击者改 `strategy_id=1`、`inject_size=0`、`orig_host_size/sha256` 为任意前缀的哈希，则 `remove` 走 EOF strip → `verify_restored` 用它自己伪造的哈希比对通过 → 返回 `verified_identical: true`；同一份 header 让 `verify` 在 Level 2 短路、Level 3 因无口令 skip → `verify_passed = true`。
- 后果：不需要口令即可让工具**背书**一份"这是原始载体"的假结论（provenance 伪造），并把一条明确有问题的载体报成 valid。
- 修法：`remove_core` 在有口令/有 metadata 时先解密 metadata（天然校验 AAD）再 strip；`envelope_coordinates_agree` 的短路条件改为"策略是 scattered（`pe_codebits`）"而不是"`inject_size == 0`"。

### P1-4 CLI `read` 的默认落盘绕开了原子提交，且跟随符号链接（R2 P0-7 的同类问题原地复活）

- 位置：`rust/src/cli/cmd_structure.rs:411-418`

```rust
let mut f = File::create(&fn_to_use).map_err(...)?;
f.write_all(&res.data)?;
```

- 对照：同一语义的库路径 `structure/engine.rs:1723-1728` 已改 `write_bytes_atomic`，并在注释里点名这是 R2 P0-7；`cmd_stego.rs:602/621/642` 也已统一。
- 后果：`--overwrite` 下先截断再写，磁盘满/被杀 → 目标名上留下半截载荷（用户原文件已毁）；CWD 存在同名 symlink 时写穿到链接目标。
- 修法：删掉该分支，统一 `commit::write_bytes_atomic`。

### P1-5 取消令牌选用了 std 唯一会自动重试的错误类别 → 写阶段取消后 100% CPU 死循环

- 位置：`rust/src/core/control.rs:284-291`；`write_all` 的重试语义见 `adapters/io.rs:26/44`
- 证据：

```rust
fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    if self.control.is_cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "strhide: cancelled"));
    }
```

`Write::write_all` 对 `ErrorKind::Interrupted` 的实现是 `continue` 重试，于是每次重试立即再返回 `Interrupted`，形成纯自旋；`map_io_cancel` 永远收不到错误。
- 后果：GUI 在大载体写入阶段点"取消"→ 线程死转、临时文件不清理、进度不再更新，只能杀进程（杀进程又绕过 `TmpGuard`，正好是模块头注释要避免的场景）。
- 修法：改用 `ErrorKind::Other`/`BrokenPipe` 或自定义 marker error。

### P1-6 HEVC：小载体 `extract` 报"文件损坏"，同一条码流 `inspect` 报"没有数据"

- 位置：`rust/src/stego/hevc/engine.rs:1537-1541` vs `:1729-1731`

```rust
// extract
if pool_size < HEVC_SUPERBLOCK_MIN_SLOTS {
    return Err(StrHideError::CorruptedData("Insufficient HEVC slots for Superblock".into()));
}
// inspect（同条件）
if pool_size < HEVC_SUPERBLOCK_MIN_SLOTS { return Ok(empty_info); }
```

- 后果：slot < 524 的合法 HEVC（小分辨率/极短片段）在 `extract` 下挂 `ErrCorrupted`，用户以为文件坏了。`CorruptedData` 与 `NoHiddenData` 的分类在这里明显用反了。
- 修法：改 `NoHiddenData`（容量不足天然意味着放不下 Superblock）。

### P1-7 HEVC：`capacity` 的推荐量与 `write` 的闸门是两套预算，纯 I+P 流会被"推荐能放、写入拒绝"

- 位置：`rust/src/stego/hevc/engine.rs:641-653`（推荐量 = `band0*f + ref_flips`）vs `:828-829`、`:867-885`（闸门要求 `total_slots ≥ 524 + body_needed*f⁻¹`，等价于容量 `(total-524)*f`）
- 依据：`--bframes 0` 的流里 band 0 极小/为空，推荐量几乎全部来自 `ref_flips_per_picture × band_pictures[1] × 4`，与池大小无关；而闸门按整池折算。举例 T=100 000 槽、high 档（f=0.2）：推荐 ~1.6 KB，闸门需要 129 420 槽 → 必然失败。加 `--enforce-safety` 时 `enforce_safety` 还会先放行，失败延后到写入阶段。
- 修法：影片分支返回前把推荐量再夹一次 `f*(total_slots-524)`，与闸门同源。

### P1-8 CLI：`--stdout` 时口令提示写进 stdout，污染载荷

- 位置：`rust/src/cli/cmd_structure.rs:285-288`（`println!`）对照同函数邻居 `:318/:357`（`eprintln!`）
- 后果：`sth read carrier.png --stdout | prog` 的第一行变成 `Password hint: ...`。`should_print_banner` 特意为 `--stdout` 关掉 banner，说明这条路径必须保持 stdout 纯净，此处是漏网。
- 修法：改 `eprintln!`。

### P1-9 PNG 带 `tRNS` 的灰度/真彩载体：±1 嵌入可把像素"移动成"透明键色，画面出现空洞而 `verify` 全绿

- 位置：`rust/src/stego/png/engine.rs:229-236`（`tRNS` 落兜底分支原样保留）、`:1073`（槽位只按 `[8,247]` + `val%8 ∈ 1..=6` 筛选，不排除键色）
- 依据：color type 0/2 的 `tRNS` 是"某颜色 = 全透明"的语义键。若键色通道值 `v` 满足 `v%8 ∈ 1..6`（如灰度背景 5、`tRNS=5`），槽位翻转 `v→v±1` 就让该像素由透明变不透明（或反之），AEAD 与三级 verify 都不受影响。
- 触发条件较窄（要求键色余数落在 1..6 且该颜色在图中成片出现），但一旦命中就是**不可事后检测**的视觉破坏。
- 修法：color type 0/2 带 `tRNS` 时直接 `UnsupportedFormat`（与 `PLTE`/`acTL` 同口径），或在槽位筛选里排除键色。

### P1-10 HEIF 缩略图桥接的 `patch_uint` 对字段宽度静默截断

- 位置：`rust/src/stego/heif/thumb_bridge.rs:573-592`（`4 => buf[pos..pos+4].copy_from_slice(&(val as u32).to_be_bytes())`，无范围检查），调用点 `:496-497`
- 后果：`iloc` 的 `length_size` 为 1/2（合法值）+ 缩略图被撑过 65535/255 → 写入截断后的长度，容器结构损坏但返回 `Ok`；顶层 box size 那条路径反而做了 `u32::try_from` 检查，说明是遗漏而非设计。
- 修法：`patch_uint` 内加 `val > MAX_FOR(size)` → `Err`；或在选目标时排除 `length_sz < 4` 的载体。

### P1-11 JAR 签名检查在所有候选都不是真 EOCD 时 fail-open

- 位置：`rust/src/structure/rejection.rs:325-337`
- 依据：`continue` 走完所有候选后落到函数尾 `Ok(None)`＝"未签名"，即放行。R2 P0-4 想要"全候选失败时保守判疑似签名"并没有实现（注释写了，代码没写）。ZIP64 签名归档（`cd_offset=0xFFFFFFFF`）也一律走这条 fail-open 分支。
- 修法：走完仍未命中 → 返回 `Some("cannot structurally validate … treat as signed")`；单独解析 ZIP64 EOCD。

### P1-12 facade：内容域错误被 `.ok()`/丢弃，最后统一报成"没有隐藏数据"

- 位置：`rust/src/facade.rs:468`（`verify_file(...).ok()`，`DualVerify` 没有 `content_error` 字段）、`:489-517`（`smart_extract` 不读 `diag.content_error` → `NoHiddenData("No hidden data found")`）
- 后果：HEIF 布局不支持、缩略图桥缺失、引擎未编入等原因，全部被渲染成"没有隐藏数据"，正是排查成本最高的一类误导。
- 修法：`DualVerify` 补 `content_error`；`smart_extract` 优先返回真实错误。

---

## 4. P2：一致性与资源（汇总）

| ID | 位置 | 问题 | 影响 |
|---|---|---|---|
| P2-1 | `structure/engine.rs:1362-1379` | 结构域写入 rename 前**没有 `sync_all`**，也不 fsync 父目录（`grep sync_all src/structure` 为空），而 `commit.rs:266-273` 的持久化契约只覆盖 stego 域 | 掉电/蓝屏后目标名上可能是空/半截文件，`.bak` 同样是裸 `copy` |
| P2-2 | `structure/engine.rs:1553-1558` + `cli/cmd_structure.rs:287` | 口令提示 `hint` 不在 AAD 内、非 stealth 无口令时用**公开常量**掩码，且原样 `println!` 到终端 | 可注入 ANSI/OSC 控制序列、伪造提示文本；与 `fs.rs` "控制字节不得进日志"的策略不一致 |
| P2-3 | `cli/cmd_structure.rs:390-391` | `print!` 在 EPIPE 时 panic（std 行为），同分支二进制路径是 `?` 返回 | `\|\| head` 流水线变 abort，`pipefail` 下 exit code 异常 |
| P2-4 | `core/fs.rs:79-90`、`cli/cmd_structure.rs:360-364`、`cmd_stego.rs:593-602` | 批量 `-o <DIR>` 不做同名去重 | `--overwrite` 下静默互相覆盖却打印两条成功；不加则半批失败留残 |
| P2-5 | `cli/cmd_structure.rs:93-104` | `--strategy ask` 读到 EOF/非法输入 → 静默取 `strats[0]` | CI 里配置 `ask` 会无声改变写入策略（R2 P0-2 的同类） |
| P2-6 | `core/config.rs:244-256` | 隐式配置候选"存在但不可读/解析失败"直接 `Err` | 一份坏掉的系统级 config 让所有命令（含 `inspect/verify`）启动即失败 |
| P2-7 | `core/commit.rs:280-314` | Windows `ERROR_ACCESS_DENIED(5)` 被当作"被占用"，重试 3 次后报 `TargetBusy` | 只读目标永远失败且提示误导（`ContentOnly/Skip` 策略下可达） |
| P2-8 | `core/crypto.rs:245-263` | chunk nonce 把 `usize` 截 `u32`，第 2³² 块与第 0 块 nonce 相同；无块数上限 | 需 ~88 GiB 密文，现实不可达；但"一旦触发就彻底失效"且无报错 |
| P2-9 | `core/fs.rs:19-72` | `sanitize_filename` 漏 `CONIN$`/`CONOUT$`；无长度上限（>255 字节 → ENAMETOOLONG/MAX_PATH） | 提取"成功"但磁盘上没有文件；批处理中断 |
| P2-10 | `cli/cmd_diag.rs:170`、`:136-137`、`:306-307` | 批量 `inspect` 全失败仍 exit 0；`--json` 有 object/array/NDJSON 三种形状且都不含失败项；`banner` 逐元素重复 | `--json` + 退出码目前不能作为 CI 判定面 |
| P2-11 | `stego/png/engine.rs:221-227` | 无 IEND 的 PNG，`tail` 从不回填 → 重编码静默丢掉尾部字节 | "格式保持"承诺被打破（`RawImage::tail` 文档承诺相反） |
| P2-12 | `stego/png/engine.rs:1702-1718` → `:1101-1105` | `body_slots_upto` 用**未认证**的 `total_len` 决定 `with_capacity`，且发生在 AEAD 校验之前 | 无口令即可让 `extract/inspect` 触发 ~1.5 GB 瞬时分配 |
| P2-13 | `stego/jpeg/engine.rs:64-79` | 渐进式/多 scan 的拒绝完全依赖 `dct-io` 错误**字符串匹配**（`contains("SOF2")`），仓库内无独立 SOF 检查 | 依赖补丁级措辞变化即退化；若上游接受 SOF2 则会"写成功但图被降级" |
| P2-14 | `stego/jpeg/engine.rs:679`、`dht.rs:120-147` | DHT 不可解析（`None`）被语义化为"表完整，无需防护" → `u>=3` 强制与 missing-symbol 预检全部失效 | 带 DAC/DNL 的 JPEG 会跑完整个 solve 才报 `CorruptEntropy` |
| P2-15 | `stego/hevc/slot.rs:499-518` + `engine.rs:2813-2833` | 单 recorder 上限 1 MiB 提示 ≈56 MiB，但 `par_iter` 并发 16~48 个 GOP | 4K/8K 内帧峰值 0.9~2.7 GB，与注释"per-run"不符 |
| P2-16 | `stego/hevc/engine.rs:1568-1571`/`:1641-1643` | magic 由口令派生，口令错 → magic 不匹配 → 恒为 `NoHiddenData`，`Password` 分支不可达 | 输错口令无法与"没有数据"区分 |
| P2-17 | `structure/adapters/isobmff.rs:140/164/182` | `24 + trailer.ube_total_size` 等三处未 checked 的 u64 加法 | debug 下 panic，release 下接受尺寸不符的伪 box（R2 P0-5 的残留路径） |
| P2-18 | `structure/engine.rs:1583`、`:2177`、`:2195` | `ube_total_size` 从不与文件长度比较，`meta_len` 按不可信值 `vec![0u8; n]` 分配 | 几百字节载体可让 inspect/read 预留 GB 级缓冲 |
| P2-19 | `structure/adapters/mkv.rs:17-37`、`formats/sniff.rs:230-233` | 只认 EBML 头，不校验 `DocType` | 任意 EBML 容器被判 MKV → 写入成功、`verify` 报"载体坏了" |
| P2-20 | `analysis.rs:1477-1488` | 空间 chi2 把 alpha 计入直方图，RS/WS/SPA 却显式排除 | RGBA 不透明图系统性低估 suspicion |
| P2-21 | `analysis.rs:1499-1504` + `:1964-1972` | WS 命中只给 `Severity::Info`（2 分）→ `verdict` 仍是 `clean`，而 RS/SPA 同级命中是 `Suspicious`（25 分） | `detectors` 报 ALERT、`verdict` 报干净，机器消费方被误导 |
| P2-22 | `stego/hevc/engine.rs:1351-1368` | `reencode_slice` 用 `orig_rbsp[start..end]` 切片无护栏，而吸收路径 `:3121` 有同类判断 | 当前 vendor 版本恰好安全，但升级上游即可能 abort（**待确认**） |
| P2-23 | `stego/hevc/heif_boxes.rs:199-234` + `engine.rs:733-737` | HEIC 的 NAL span 不去重/不查重叠，patch 后写覆盖先写 | 构造/异常 HEIC 可导致 `embed` 成功但永远读不出（**待复现**） |
| P2-24 | `analysis.rs:1182-1186`、`:1218`、`calibration.rs:124` | 32 位目标上的未 checked 加法/乘法 | 仅 wasm32/i686/armv7：切越界 panic 或"全 PASS 0.000" |
| P2-25 | `core/crypto.rs:63-65/326/402` | `pub` 的 `framed_len`/`encrypt_stream_to_chunks` 只靠 `debug_assert`，`chunk_size=0` 时 release 下静默产出空载荷；`chunk_len as u32` 无 try_from | 库调用方误用即静默丢数据 |
| P2-26 | `cli/cmd_structure.rs:396-400`、`core/fs.rs` | 提取默认文件名来自信封，未经长度限制；`--stdin` 载荷一律 `is_file=false` | 二进制载荷被写成 `.txt` 并直接打到终端 |

---

## 5. 已复核、确认没有问题的部分（避免下轮重复劳动）

- **`fmt`/`clippy`/测试基线**：全绿，零告警，808 测试通过。
- **SIMD `unsafe`**：`stc.rs:630`、`juniward.rs:147-152` 都先 `is_x86_feature_detected!("avx2"[, "fma"])` 再调用 `#[target_feature]` 函数；`get_unchecked`/`loadu` 的边距推导（`PAD=24`、`states` 为 2 的幂）成立；AVX2 与标量路径数值等价。**不存在"非 AVX2 机器上执行 AVX2"的路径。**
- **STC 编码器**：尺寸/无解/湿代价处理干净（`TrellisInfeasible`、`DeadElement` 都是显式错误），`u=1` 快路径与一般路径的窗口对齐正确。
- **PNG 可复现排名**：`select_nth_unstable` 的元素是 `(cost.to_bits(), idx)`，全序无并列 → 与全排序前缀逐位一致；header 池成员集合在 cover/stego 上不变。
- **JPEG 容量口径**：`probe` 与 `embed` 共用 `estimate_backtrack_bytes` 与同一 `max_bits` 推导；PNG 的 `probe`/`embed` 共用同一槽位谓词。
- **AAD 设计**：80 字节 AAD 与 `envelope.rs:273-285` 完全一致；chunk AAD 含 `chunk_index` 与 `is_last` → 截断/重排/删块可检测。
- **口令与密钥不外泄**：全仓没有把口令/`ikm`/派生密钥写进错误或日志；`--json` 与 `Debug` 均 redacted。
- **路径穿越**：`sanitize_filename` 的 `rsplit` + `..`/绝对路径/控制字节处理，配合三个落盘点，未找到 `..`/UNC/ADS 穿透面。
- **R2 修复抽查**：P0-3（ZIP EOCD `PK\x01\x02` 校验）、P0-5（isobmff `read_box_size` 收紧）、P0-6（patch span 越界）、P1-1（先 magic 后 version）、P2-10（superblock `reserved`/`total_windows` 硬拒绝）、P2-11、P2-1 单 recorder 上限——**均已闭合**；未闭合/残留见 P0-1、P1-11、P2-17、P2-22。

---

## 6. 与 R2 报告的关系

- R2 的 29 条里 23 条确认修好，本次不再重复。
- R2 主动搁置的 6 条（RS/SPA 口径、JPEG EOI 尾窗、配置合并语义、isobmff 1 GiB 读、PE `.text` 整段读、CLI 全量读载体、JSON 形状）**仍然成立**，其中"JPEG EOI 尾窗"与本次 P1-2 是同一族的检测盲区，建议合并处理。
- 本次新发现的性质与 R2 相似：**修复往往只覆盖被点名的那一条路径**（`check_jar_signature` 修了"采纳伪 EOCD"，但漏了 `cd_size<4`；`verify` Level 2 修了坐标比对，但留下 `inject_size==0` 后门；原子落盘修了 3 处 CLI，漏了第 4 处）。这提示**修复流程应该按"缺陷类别"扫描全仓，而不是按"报告条目"逐条打补丁**。

---

## 7. 建议修复顺序

1. **P0-1**（一行 + 回归测试）→ **P0-3**（加像素上限）→ **P0-2**（把 JPEG 预算抽到 `coding` 复用）。
2. **P1-4 / P1-5 / P1-8**（都是几行，且属"已修过的类别"）：统一 `write_bytes_atomic`、换 `ErrorKind`、`eprintln!`。
3. **P1-1 / P1-2 / P1-3**（语义与信任模型）：verify 内容域计入失败、缺 end marker 报 Suspicious、remove 解密 metadata。
4. **P1-6 / P1-7 / P1-11 / P1-12**（HEVC 与 facade 的错误分类、JAR fail-open）。
5. **P1-9 / P1-10**（tRNS、patch_uint 截断）——前者建议直接拒绝该载体类型，后者加范围检查。
6. P2 按模块各自批次收拾；**P2-2（hint 未转义）建议紧跟 P0**，因为它是唯一"攻击者能往用户终端写控制序列"的通道。

每批改完按 AGENTS.md 跑：`cargo fmt && cargo clippy --all-targets --all-features -D warnings`、`cargo test --all-features --all-targets`、`cargo test local_ -- --ignored`、`python scripts/baseline_hash.py --check`。

建议补的测试（按性价比排序）：
1. `rejection` 的 `cd_size` 取 1/2/3/0、`cd_offset` 越界/回绕的单元测试（P0-1）；
2. PNG `tRNS` + 灰度/RGB 的"嵌入后不出现新透明像素"断言（P1-9）；
3. 删除 IEND/EOI 后 `scan` 必须给出 `Suspicious`（P1-2）；
4. `remove` 在 header 坐标被篡改时必须失败（P1-3）；
5. 大图 `capacity → embed` 的内存预算测试（可用 `MAX_PIPELINE_BYTES` 的注入式上限）；
6. `verify` 在"结构 OK + 内容坏"下必须 exit 1（P1-1）。

---

## 8. 发布判断

**不建议以当前状态对外发布 1.0；修完 P0 三条 + P1 前六条后可以发 0.9.x 公测。**

理由：
- 代码本身的结构、命名、注释、错误模型都在"可维护"之上，明显不是堆出来的原型；808 个测试与三轮回归目录说明作者对正确性是认真的。
- 但"处理任意第三方文件"是这个工具的核心前提，而当前有 1 条 86 字节即可触发的 abort、2 条单文件打爆内存的路径、1 条零成本让检测失明的路径。公开之后，这类问题会以"闪退/杀进程/查不出"的形式出现在 issue 里，且很难被用户描述清楚。
- 另有 2 条属于"工具自己给出的结论不可信"（verify 吞内容域失败、restore 伪造 verified identical）。对安全类工具来说，**错误的肯定结论比错误地报错危险得多**，这两条应在发布前解决。
