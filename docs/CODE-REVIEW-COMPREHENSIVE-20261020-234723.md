# strhide 全面代码审查报告

> 审查日期：2026-10-20 23:47 (UTC+8)
> 审查范围：`rust/`（src 18k 行 + tests 13k 行，共 ~31k 行 Rust）
> 审查方式：本人直接通读核心层 + 2 个并行深度子代理（适配器层 / 隐写层）+ 实证运行验证
>
> **⚠️ 最终复核：报告结论已按 HEAD `41d91d0` 重新验证。**
> 审查期间仓库被同一作者的另两个提交推进（`cd177e4` 三元 ±1、`41d91d0` STC 接线），
> 所有【实证】级结论（尤其 P0-1 PDF panic）已在 `41d91d0` 上**重跑确认仍然成立**。
> 受影响的条目（P0-3、P1-6、§5.1）已在正文中更新为最新状态，并标注了变更。

---

## 0. 审查方法与重要前置说明

### 0.1 先说结论：这个项目的工程水准高于平均

在列问题之前，必须先给出正面结论，否则容易误导。本项目在以下方面做得相当扎实，**不应在"改进"中破坏**：

- **核心契约被真正验证了。** 全语料批量回归 **240/240 全绿**（详见 §1.1），覆盖 PNG/JPEG/MP4/ZIP/PDF/PE 六大族 × 明文/加密/隐身三模式 × 4 种载荷尺寸，逐项校验 100% 比特级还原。这是数据隐藏工具最重要的正确性保证，而且是自动化、可复现的。
- **密码学用法本身没有明显错误。** AES-256-GCM 用法正确、80 字节 AAD 绑定、nonce 由 base_nonce XOR chunk_index 派生无重用、元数据/载荷子密钥用不同 HKDF info 分离、压缩炸弹有 AEAD 保护的 `raw_size` 硬上界。这些都是容易写错且本项目写对了的地方。
- **失败导向安全。** `remove_carrier` 在提交前用信封内记录的 SHA-256 + size 二次校验，不匹配则不提交、不动原文件。临时文件用 `TmpGuard` + 原子 rename，异常路径自动清理。
- **文档与代码同频。** 大量 `//!` 模块级说明解释了"为什么这样做"，而不是复述代码。`Profile`/`LocalParams` 按"谁必须知道"而非"读/写方向"拆分（§6.2），是一个有洞察的 API 设计决策。
- **CI 门禁真实有效。** `cargo fmt --check`、`clippy -D warnings`、`test --all-targets` 三项本地实测全绿，`release` 工作流 `needs` 该质量任务。

**下面的问题清单应在这个基调上理解：这是"一个已经很好的项目还能改什么"，不是"这个项目有多少 bug"。**

### 0.2 ⚠️ 快照漂移警告（务必先读）

**审查期间工作区被持续修改**（同一时间另有会话/编辑器在改同一批文件）。证据：

| 时间 | 事件 |
|---|---|
| 23:35–23:39 | `stego/traits.rs`、`coding.rs`、`spatial/engine.rs`、`spatial/cost/hill.rs`、`tests/test_lifecycle/stego.rs` 连续被写 |
| 23:37 | 我首次运行 `cargo test --all-targets` → **1 个测试失败**（详见 §5.1） |
| 23:39 | 该失败测试被外部会话修复，重跑全绿 |
| 23:5x | 新增 `src/stego/coding/stc.rs`（555 行）—— 我当时判定为"未接线"（旧 P1-6） |
| 23:58 | 上述改动被提交推进到 HEAD `41d91d0`（`cd177e4` 三元 ±1、`41d91d0` STC 接线） |
| 复核时 | **我在 `41d91d0` 上重跑验证了所有【实证】级结论**；P0-1 已确认复现，P1-6 已按"已解决"改写 |

**因此：**

1. 本报告所有行号是某一时刻的快照，请以函数名/代码形状为准，**不要直接照抄行号**。
2. 报告中标注【实证】的条目是我亲自读到代码或实跑验证的；标注【待复核】的来自深度子代理，逻辑我已审阅且认为可信，但**行号可能已漂移，落地前需重新核对**。
3. 审查过程中观察到的"半成品并行推进"本身也是一个流程风险，见 §7。

---

## 1. 现状验证结果（实证）

### 1.1 质量门禁全绿 ✅

（下列为 HEAD `41d91d0` 上的最终复核结果）

```
cargo fmt --all --check                        → 通过
cargo clippy --all-targets -- -D warnings      → 通过，零警告
cargo test --all-targets                       → 341 passed, 0 failed
cargo test --release --test batch_corpus  -- --ignored  → 240/240 passed (100.0%)
cargo test --release --test batch_stego   -- --ignored  → 19/19 passed (15 normal + 4 safe-reject)
```

批量语料回归覆盖了 20 个真实宿主文件，逐项 `PASS` 包含：

- PNG `chunk` / JPEG `app_segment` / MP4、ZIP `pre_cd_inject` / PDF / PE `pe_codebits`+`pe_overlay`
- `plain` / `encrypt` / `stealth` 三种模式
- 101B / 603B / 4K / 128K 四种载荷
- **策略自动降级在真实数据上生效**：PE 上 603B 以上的载荷从 `pe_codebits` 自动退到 `pe_overlay`，PDF 上 `incremental` 自动退到 `eof` —— 说明 `exact_ube_size` 的精确预估修复确实起作用了

**内容自适应隐写批量测试（`batch_stego`）同样全绿**：

```
Total: 19 | Passed: 19 (15 normal, 4 rejected) | Failed: 0
```

4 个被正确拒绝的格式也印证了能力边界处理得当：**Progressive JPEG、APNG、Adam7 隔行 PNG、调色板 PNG** 都以 `safe-reject` 拒绝而非 produce 一个坏载体 —— 这是正确的失败导向。

### 1.1.1 ⚠️ 但批量报告缺少"嵌入前基线"，导致一个关键问题无法判断【实证】

`batch_stego` 的输出表格是：

```
File        Format   Capacity  Embed(ms) Ext(ms)  Scan(64B)      Scan(max)      Status
2015041322590395.jpg JPEG     105.0 KB   1917     1923      50/suspicious  100/likely-hidden PASS
DSC_20190505...      JPEG       0.7 KB     80       66       0/clean        60/likely-hidden PASS
IMG_20190121_130333.jpg JPEG  180.8 KB   1658     1527      100/likely-hidden 100/likely-hidden PASS
jiangsuviews.jpg     JPEG      52.4 KB    650      610       50/suspicious  50/suspicious    PASS
SSD20210218.png      PNG       36.0 KB    343      248       27/low         2/clean         PASS
```

注意几个只嵌了 **64 字节**（`Scan(64B)` 列）却拿到 `50/suspicious` 甚至 `100/likely-hidden` 的样本。

这**有两种互斥的解释**，而当前报表无法区分：

- **(a) 嵌入可检测**：64 字节就把画面推进"suspicious" ⇒ 隐蔽选择器/编码的抗分析性弱；
- **(b) 检测器假阳性**：天然高纹理照片本身就被 `analysis.rs` 打高分，与嵌入无关。

**这正是本报告 §4.1、P0-3、P1-6 关心的那个问题，而当前的 batch 报表给不出答案。** 建议在 `batch_stego` 里加一列 **`Scan(0)` = 空跑检测/on-carrier baseline**，生成 `Scan(0) → Scan(64B) → Scan(max)` 的增量。有了基线就能立刻分辨：

- 若 `Scan(0)` 已经 = 50 ⇒ 检测器假阳性问题（需要修 `analysis.rs` 的校准）；
- 若 `Scan(0)`=0 而 `Scan(64B)`=50 ⇒ 嵌入本身可检测（需要推进 STC 接线 / 密钥化槽位集合）。

**这是一个"先加一列 excel 就能省掉一周争论"的改动，建议优先做。**

### 1.2  codebase 规模

| 模块 | 行数 | 备注 |
|---|---|---|
| `src/cli.rs` | 2374 | 单文件最大，CLI 逻辑集中 |
| `src/engine.rs` | 2041 | 核心引擎 |
| `src/adapters/` | 7098 / 18 文件 | 格式适配器 |
| `src/stego/` | ~3200 / 16 文件 | 内容自适应隐写 |
| `src/analysis.rs` + `calibration.rs` | 1583 | 隐写检测扫描 |

---

## 2. 🔴 严重问题（P0 — 建议立即修复）

### P0-1. PDF 适配器可远程/本地触发 panic（`rfind` 未校验顺序）【实证：已复现】

**位置**：`src/adapters/pdf.rs`，`parse_pdf_tail_info()`，`trailer_idx..sx_idx` 切片处

**问题代码**：

```rust
let sx_idx = text_before_eof.rfind("startxref").ok_or_else(|| ...)?;   // 最后 startxref
...
if let Some(trailer_idx) = text_before_eof.rfind("trailer") {          // 最后 trailer
    let trailer_str = &text_before_eof[trailer_idx..sx_idx];           // ← 未校验 trailer_idx < sx_idx
```

`rfind` 返回的是**窗口内最后一次出现的位置**。只要 `%%EOF` 之前、最后一个 `startxref` **之后**再出现一次子串 `trailer`（PDF 允许 `startxref` 之后带 `%` 注释，影印/流式导出器常见），就有 `trailer_idx > sx_idx` ⇒ 切片起点大于终点 ⇒ panic。

**复现过程**（本人实际构造并运行，非推断）：

构造 `temp/review/probe.pdf`：

```
%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
trailer
<< /Size 4 /Root 1 0 R >>
startxref
9
% appended comment mentioning trailer written here     ← 关键
%%EOF
```

运行结果：

```
$ strhide inspect probe.pdf
thread 'main' panicked at src\adapters\pdf.rs:148:43:
byte range starts at 191 but ends at 149

$ strhide write probe.pdf -t "hi" -o out.pdf
thread 'main' panicked at src\adapters\pdf.rs:148:43:      (exit code 101)

$ strhide verify probe.pdf
thread 'main' panicked at src\adapters\pdf.rs:148:43:
```

对照组（去掉注释行的正常 PDF）完全正常输出，证实是特定输入触发而非普遍故障。

**影响面**：`inspect` / `write` / `verify` / `read` / `remove` 全部路径都会先 `detect` → `parse_pdf_tail_info`，**任何 PDF 子命令都会踩到**。且 `Cargo.toml` release profile 是 `panic = "abort"`，release 构建下不是优雅报错而是**进程直接 abort**。

**修复**（一行 + 建议加回归用例）：

```rust
if let Some(trailer_idx) = text_before_eof.rfind("trailer")
    && trailer_idx < sx_idx
{
    let trailer_str = &text_before_eof[trailer_idx..sx_idx];
    ...
}
```

同时在 `/Root`、`/Size` 的查找上做前向约束，并补一条针对"`startxref` 之后出现 trailer 注释"的回归测试。

---

### P0-2. 隐身模式（stealth）的 magic 未加盐 ⇒ 可离线爆破密码的预言机【实证：读码确认】

这是一个**安全设计缺陷**，不是编码 bug，但影响 stealth 模式的核心承诺（`README` 宣称 "plausible deniability"）。

**证据链**：

```rust
// src/params.rs:34 —— domain 是全仓库唯一的静态公开常量
pub const STEALTH_DOMAIN: &[u8] = b"strhide-stealth-v1";

// src/crypto.rs:103 —— derive_stealth_magics 的第二个参数名叫 salt ...
pub fn derive_stealth_magics(password: &str, salt: &[u8]) -> Result<([u8;8],[u8;4]), ...>
{
    let mut ikm = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(norm_pwd.as_bytes(), salt, PBKDF2_ITERATIONS, &mut ikm);
    ...
}

// 但所有调用点传的都是静态 domain，不是每信封随机 salt：
// src/engine.rs:81   let magics = derive_stealth_magics(pwd, profile.domain())?;
// src/engine.rs:838  let magics = derive_stealth_magics(effective_password, profile.domain())?;
// src/envelope.rs:380 crate::crypto::derive_stealth_magics(pwd, profile.domain())
```

而**这两个 magic 都以明文形式落在磁盘上**：

- header magic（8 字节）= UBE 偏移 0..8
- trailer magic（4 字节）= 文件最后 4 字节

**后果**：

1. **离线密码预言机**：攻击者拿到任一隐身载体，抽出 12 字节 magic，即可离线穷举口令（成本仅 PBKDF2-100k × 候选数）。这与"无口令无法判断是否隐写"的承诺直接冲突 —— 恰恰相反，它**证明**了这条 filenames 是抗抵赖的证据。
2. **彩虹表可预计算**：因为无盐，`password → magic` 全局固定，可预先构建口令到 magic 的彩虹表，一次命中即通杀全世界的隐身信封。
3. **跨文件关联**：同一口令写的所有载体共享同一个 magic，攻击者可把散布在不同文件里的隐写簇成一堆，而不需要解开任何内容。

**对比**：同一文件里 `derive_header_mask(pwd, &self.salt)` **确实用了每信封随机 salt**。两者不一致，说明这大概率是遗漏而非设计。

**修复建议**（二选一，都需要**破坏性升级**，因为改的是定位协议）：

- **方案 A（推荐，彻底）**：magic 由 `HKDF(ikm, info="magic", request_salt=<<strong>每信封随机并与 base_nonce 一同存储</strong>>)` 派生。问题是定位时需要先知道 salt —— 可行做法是让 magic 本身 = `H(derived_magic ‖ visible_salt)`，把 16 字节 salt 作为 UBE 头部前置。
- **方案 B（务实，显著缓解）**：至少把 PANIC group 分开：magic 派生改用**高成本** KDF（Argon2id 或 scrypt）并保留全局静态 domain。彩虹表成本上升到无法预计算，但仍保留跨文件关联。
- 无论选哪个，**必须同步提升 STRHIDE docs 的实际主张**：在文档里明确写"隐身模式的无关联性依赖于口令熵，且 magic 本身是口令派生的、可被爆破的"，不要再写"无法检测"。

---

### P0-3. stealth/image 隐写：32 字节头不受任何认证保护，1 bit 翻转 ⇒ 载荷永久不可提取【实证：读码确认】

**位置**：`src/stego/spatial/engine.rs`（`embed_spatial` 写头 / `extract_spatial` 读头）、`src/stego/envelope.rs`

**事实**：

- 头 256 槽用 **1:1 LSB（现在是 ±1）替换**写入 `[16B Salt][12B Nonce][4B BE total_len]`，共 32 字节 = 256 bit。
- AAD 只覆盖 `salt + nonce`（`envelope.rs:132-134`），**`total_len` 不在其中**。
- 读取时 `total_len` 只做范围检查 `49..=64MiB`，之后 `ciphertext_len = total_len - 28`。

**后果**：这 256 个槽位中任意 1 bit 翻转（JPEG 重压缩、截图重采样、社交平台转码、传输损坏、甚至宿主软件重写元数据的常见情形）：

```
total_len 变化 → ciphertext_len 变化 → GCM 解密必然失败 → 报 NoHiddenData
```

**没有冗余、没有重试、没有纠错、也没有任何"是长度字段坏了还是密码错了"的区分**。这是本子系统最脆弱的单点：它比 UBE 容器模式脆弱得多，因为容器模式的头部不在会因再编码而改变的像素里。

**复核最新提交（`41d91d0`）后的补充**：头部字现在被更紧地打包了：

```rust
fn encode_header_word(len: u32, codec: StegoCodec, stc_h: u8) -> u32 {
    (len & HEADER_LEN_MASK)                                    // 26 bit 长度
        | ((codec.id() & 0b11) << HEADER_CODEC_SHIFT)          // 2 bit codec id
        | (((stc_h as u32) & 0xF) << HEADER_STC_H_SHIFT)       // 4 bit stc h
}
```

**这反而让本风险略微放大**：同一个 32 位、同样无冗余无认证的字，现在要多承担 `codec` 和 `stc_h` 两个字段的正确性 —— corrupt 一位不仅会导致长度错（`ciphertext_len` 错 → GCM 失败），还可能导致 **codec 从 Hamming 被翻成 STC**（或 `stc_h` 被改）。这类失效比"长度错"更迷惑：症状看起来像
"提取算法坏了 / 编解码器不匹配"，而不是"数据坏了"，排障成本显著更高。
`decode_header_word` 的注释也承认了这点：

> The codec id is returned raw: validation against `StegoCodec::from_id` is the caller's job,
> because the extract path must fold an unknown id into the generic "no payload here" error.

**⇒ P0-3 的结论与修复建议不变，且优先级应提高**（参见下方原文）。
2. 次选：头部 3 副本多数表决 + 用格式内的前导同步字定位。
3. 或者：给头 32 字节单独加一个 4 字节 MAC（密钥同进 Transport Key），至少能明确报错原因。
4. 在正确性问题之外，头部 1:1 替换的改动率 ~0.5，是体内 Static 分析问题的最好下手点（正文 Hamming 为 0.2917，MVG/f5 类编码器 ~0.1）。建议头部改用 k=5 或 STC 编码降改动率。

---

## 3. 🟠 中等问题（P1）

### P1-1. `pe_codebits` 叠加注入会永久、不可逆地破坏宿主【待复核 · 高风险】

**来源**：适配器深度子代理Top-1，我复核了调用链认为逻辑成立，但未实跑验证。

`pe_codebits` 每次注入都在 PE 的"全零" slack 区写入一个 diff，用于 afterwards 还原被翻转的指令位。**第 1 次**写入零区 A；**第 2 次**写入时 A 已非零，必然另选零区 B，同时第 2 个位流覆盖了 `.text` 前 112 个位置 —— **channel#1 的 header（含它自己的 `slack_off`）被抹掉**。此后无论怎么 `remove`：

- 剥离 envelope#2 → 只还原第 2 层并零填区 B；
- 区 A 里 diff#1 的非零字节**永远无法被定位和清零**（定位信息已随 header#1 消失）；
- ⇒ `remove` 后文件 ≠ 原宿主，`orig_host_sha256` 永久失配。

触发条件：`engine.rs` 对"stealth + 未知口令"的既有信封只**警告不拒绝**（`suspicious_structures`），而 `pe.rs` 的启发式（nonzero≥178 且 distinct≥100）不能保证命中。

**建议**：在 `PeAdapter::inject` 进入 `pe_codebits` 前做硬门限：**若任一 slack range 存在非零字节且非本适配器可识别的 channel diff，直接拒绝**；或者让 diff 自描述（在固定的 padding range 头部写"已占用区列表"）。最小兜底：`strip_codebits` 归零时把**所有** padding range 内的非零字节一律清零（契约就是"slack 必须全零"）。

> 这条如果成立，直接冲击项目核心卖点"100% 还原"，建议**优先写一个两信封叠加的回归用例来证实或证伪**——这比改代码更重要。

---

### P1-2. `pe_codebits` 绕过 Authenticode 与宿主完整性校验【实证：读码确认】

```rust
// src/adapters/pe.rs, inject():
if strategy == "pe_codebits" {
    return inject_codebits(host_in, ube_in, out);     // ← 提前返回
}
if !matches!(strategy, "pe_slack" | "pe_overlay" | "eof") { ... }

let pe_info = parse_pe_headers(host_in)?;
if pe_info.has_authenticode {                        // ← codebits 永远到不了这里
    return Err(StrHideError::UnsupportedFormat("... Authenticode ...".into()));
}
if pe_info.host_size < pe_info.pe_image_end { ... }  // ← 同上
```

且该文件自己的注释（约 336 行）声称 "`run_all_rejection_checks` refuses Authenticode-signed PEs for **every** strategy"，`strategy_capacities` 也把所有策略标为 `available=false` —— **适配器自己的行为与自己的声明矛盾**。

**为什么现在没出事**：`engine.rs:724` 的 `run_rejection_checks` 在默认策略下兜住了。**降级 experientially 不安全**：

- 库调用方直接使用适配器；
- `RejectionPolicy::Skip` / `ContentOnly` 配置。

**修复**：把这两项检查提到 `inject` 最顶部，在所有 strategy 分派之前。

---

### P1-3. `inject_offset + inject_size` 缺 `checked_add`（9 个适配器共用的默认 `strip`）【实证：读码确认】

```rust
// src/adapters/mod.rs —— 被 PNG/JPEG/PDF/MP4/MKV/HEIF/RIFF/WAV/WEBP 共用
stego_in.seek(SeekFrom::Start(header.inject_offset + header.inject_size))?;
```

而 ZIP 自己实现了带防护的版本并留下注释说明原因：

```rust
// src/adapters/zip.rs
// Every offset below comes from the envelope header, which is NOT covered by
// the AEAD: a corrupted or tampered header must fail as CorruptedData, never
// panic in a debug build or wrap around into a bogus seek in release.
let inject_end = header.inject_offset.checked_add(header.inject_size).ok_or_else(|| ...)?;
```

我确认了 `envelope.rs:99-101` 的说法成立：`inject_offset/inject_size/patch_offset/orig_patch_val` **不在 80 字节 AAD 内**，仅被 XOR mask 保护。

**影响**：debug 构建 panic；release 回绕后 seek 到错误偏移（最终被 `remove` 的 SHA 校验拦下不提交，但**报错信息误导**）。

**同类问题还有 8 处** `trailer.ube_offset + trailer.ube_total_size == file_size`：出现在 `eof.rs`(2)、`png.rs`、`zip.rs`(2)、`riff.rs`、`mkv.rs`、`isobmff.rs`。同类 stood：仓库里已经有 3 处正确写法（`zip.rs:413`、`pdf.rs:628`、`pe_slack.rs:193` 都用 `checked_add(...) == Some(...)`），说明这是**遗漏而非设计**。

**修复**：把 ZIP 的 `checked_add` 版本上提到 `mod.rs` 默认实现，ZIP 改为复用；其余 8 处统一替换。

---

### P1-4. PBKDF2 迭代次数偏低（100k）【实证】

`crypto.rs:61`：`pub const PBKDF2_ITERATIONS: u32 = 100_000;`

OWASP 对 PBKDF2-HMAC-SHA256 的当前建议是 **600,000** 次。100k 在 GPU 上的爆破成本已经明显偏低 —— 这会放大 P0-2 的严重性（有了 magic 预言机 + 低成本 KDF = 弱口令基本等于明文）。

代码注释已说明"Raising this invalidates envelopes written with older versions"，所以**不能静默改**。建议：

1. 引入 envelope 格式版本位（顺带解决 P0-2、§4.1 的 STC 接线、§4.2 的 PRNG 可移植性 —— 这三个都需要版本位）；
2. 新版本信封用 Argon2id（推荐参数 ≥19 MiB memory, t=2）替代 PBKDF2，或至少 PBKDF2 ≥600k；
3. 过渡期给 CLI 加一个"弱 KDF"警告。

---

### P1-5. 当前工作目录的 `strhide.toml` 会被自动加载，且可含明文口令 ⇒ 目录投毒【实证：读码确认】

`config.rs` 的查找顺序是：显式 `--config` → **`./strhide.toml`** → `~/.strhide/config.toml`，且 `password` 是合法键。

**攻击场景**：受害者进入一个别人给/下载的目录（内含一个待"处理"的载体文件 + 一个 `strhide.toml`），执行 `strhide write photo.png -t "secret"` （未指定 `-p`）。此时：

- 攻击者预设的 `strhide.toml` 里写的 `password = "attacker-known"` 会被静默采用；
- 受害者写入的载荷用攻击者已知的口令加密；
- **且受害者完全无感知**（`-p` 未 given，config 作为 default）。

这与 `.npmrc` / `.env` 投毒是同类问题，对一个以"可否认性"为卖点的工具尤其不合适。

**建议**：

1. **至少**：从 CWD 自动加载 `strhide.toml` 时，若该文件中含 `password`/`password_file` 且户主 ≠ 当前用户（Unix）或来自非 gitignore 的路径，打印醒目的 `[WARNING]`；
2. **更好**：把 `password`/`password_file` 从"可自动加载的 CWD 配置"中排除，只允许 `~/.strhide/config.toml`（用户主目录）或显式 `--config` 提供；
3. Windows 上额外提醒：从网络/压缩包解压的目录在 Zone.Identifier 标记下应视为不可信。

---

### P1-6. ✅ 已解决 —— STC 在实现后已完成接线（`--codec stc`）

> **【状态更新】** 本条在审查初期记为"STC 已实现但未接入"，属半成品。
> 提交 `41d91d0 feat(stego): syndrome-trellis coding layer (--codec stc), weighted distortion 408x lower`
> 已将其完成接线。当前状态：

我复核后的结论是 STC **已经接入**：

```
src/stego/spatial/engine.rs:39    Move, StcTrellis, hamming_embed_ternary, ..., spatial_move, write_bit_ternary,
src/stego/spatial/engine.rs:127   StegoCodec::Stc => { let t = StcTrellis::from_seed(0, stc_h)?; Ok(t.slots_for(bits)) }
```

引入了 `StegoCodec` 枚举（Hamming / STC）与 CLI `--codec stc`，`slots_for` 按 codec 计算所需槽位，并且
`required_slots` 的注释明确写出了一个容易被误解的事实：

> STC needs `bits + h - 1` slots, i.e. roughly one slot per bit. Hamming k=3 needs 2.33.
> Using fewer slots is **not** a capacity gain: the encoder flips a much larger fraction of
> the slots it does use, so the change budget is the same.

—— **"STC 更省槽位"是错觉，真正的收益是失真下降（宣称 408x）**，文档写明了这点，很好。

**剩下的事**：接线刚落地，建议补两件事
1. **默认 codec 的选择**：当前默认应仍是 Hamming；既然失真差距达 408x，建议在下一破坏性升级里把 STC 转为默认（需配合版本位）。
2. 纠正 `tests/test_lifecycle.rs` 里仍在写"（HILL, UERD, STC）"的误导性注释 —— 现在是事实了，但应补充标注 Hamming 仍是默认。

---

### P1-7 ~ P1-12. 其余中等问题【待复核】

按网 Agent 深度审查选出，我已审阅逻辑并认为可信，但**未亲自重跑验证、行号可能漂移**：

| # | 位置 | 问题 | 影响 |
|---|---|---|---|
| P1-7 | `riff.rs` `inject` | **忽略"脏尾"**：`inject_offset = host_len`（追加到文件末尾），但 `new_riff_size` 把既有的容器外尾数据也算进 RIFF 容器，导致容器不再自洽。PNG（`find_iend_offset` 保留 IEND 后脏尾）和 PDF（"dirty tail"）都已处理，RIFF 是唯一遗漏 | 比特还原仍正确，但结构不自洽，第三方播放器兼容性存疑；`verify_structure` 会报假损坏 |
| P1-8 | `pe_codebits.rs` section 表 | 节表越界时 `break` **静默截断**，与调用方注释承诺的"clean NotPe rejection"相反。`slack_ranges` 的安全性建立在"每个 section 的文件区间都被减掉"之上 | 节 raw data 可能被误判为可写 padding ⇒ **覆写破坏宿主**，是整个适配器层唯一的写越界面 |
| P1-9 | `pdf.rs` `new_obj_num` | xref-stream PDF 的下一个对象号只扫 `%%EOF` 前 64 KiB 窗口，`max(N)+1` 可能低估 ⇒ 增量更新写出重号对象 | 文档语义被改坏（比特仍可 100% 还原） |
| P1-10 | `png.rs` `finalize` | 把整个 UBE 拉进 `Vec`（理论至多 2 GiB）算 CRC，而**同一个文件的 `inject` 是流式算的**并有注释解释为什么要流式 | 内存峰值翻倍；32 位平台 `as usize` 截断 |
| P1-11 | `jpeg/engine.rs` + `jpeg/dqt.rs` | 硬编码只用 `components[0]`、永远取 DQT `id==0` | 对 CMYK / RGB（非 YCbCr）JPEG 会拿错分量和量化表，代价排序失效 |
| P1-12 | `spatial/cost/hill.rs` + `engine.rs:451` | 用**三通道亮度**（`0.299R+0.587G+0.114B`）算代价，但只往**绿通道**嵌入 | 绿通道平坦而亮度残差大的像素被误判为"便宜"，实际失真与代价脱钩 |

---

## 4. 🟡 次要问题与改进建议（P2）

### 4.1 隐写子系统：基体槽位集合由公开代价图决定，密钥只保护"顺序"【实证：读码确认】

`prng.rs` 的模块文档称：

> ensuring that without the key, an attacker cannot determine **which slots** were modified or in what order.

我实读了 `spatial/engine.rs` 的选槽逻辑，**这个说法目前不成立**，而且代码里自己有一处注释解释了为什么选择这么做：

```rust
// Body slots must keep HILL's cost ordering. ...
// Selecting the body as permuted_candidates[256..] (as an earlier version did)
// was equivalent to a random subset of the candidate set, which threw away the
// minimal-distortion premise of HILL: measured at 50% load, the median HILL
// cost of modified pixels was ~4.3x the cost of the cheapest equivalent slots.
```

即：**正文槽位集合就是"代价最低的 N 个"，属于无密钥可复现的公开函数**；密钥只决定它们之间的**顺序**。头部 256 槽是真随机的（规避了"最便宜的前 256 个"这个指纹）。

**这不是实现 bug，是"文档 overclaim + 抗分析性 tradeoff"**。两个都值得处理：

1. **改文档**：把 claim 改成"AES key protects the bit→slot mapping (order); the slot *set* is determined by the cost model"，并把这个 tradeoff 写进 `docs/`；
2. **改实现（可选）**：代价最低的 `K·N`（K=2~4）个候选建池，密钥随机抽 N —— 集合也依赖密钥了，代价是失真上升。这是一个应该让用户/配置能选的旋钮。

### 4.2 PRNG 可移植性 + 无版本标签 ⇒ 升级 rand 会让历史载体永久变砖【实证：读码确认】

先把好消息说清楚，避免误读：

**PRNG 本身是密码学安全的 ✅**。我实读了 `src/stego/prng.rs` 并核对了上游：

```rust
pub fn permute_indices<T>(items: &mut [T], seed: &[u8; 32]) {
    let mut rng = StdRng::from_seed(*seed);
    items.shuffle(&mut rng);
}
```

`rand 0.10.3` 的 `StdRng` = `ChaCha12Rng`，上游显式实现了 `TryCryptoRng`；种子来自 PBKDF2-HMAC-SHA256(100k) → HKDF 展出的 256-bit。**不是自实现 LCG/XORShift，也不是弱 CSPRNG。这条不需要改。**

真正的问题是**可移植性**：

- 上游 `rand-0.10.3/src/rngs/std.rs` 明确标注 `Non-portable: any future library version may replace the algorithm and results may be platform-dependent.`
- 而这套 Python 语句的可移植性被**当成了持久化格式**：嵌入时的槽位顺序 = `shuffle` 的逐比特输出，提取端必须复现**完全相同**的输出。
- 该子系统的信封格式 `[16B Salt][12B Nonce][AEAD 密文]` 里**没有任何版本号/算法标识符**。

⇒ 只要升级 `rand`（0.10 → 0.11）或 `shuffle` 实现调整，**所有已嵌入的历史载体变成 `NoHiddenData`，且无法区分"密码错"与"格式变"**。release 还是 `panic="abort"`。

**修复**：加 1 字节 `format_version`；或脱离 `StdRng`，直接依赖 `chacha20::ChaCha12Rng` + 自实现 Fisher-Yates 把字节流锁死，并加"固定种子→固定置换"的值稳定性测试。

### 4.3 PBKDF2 每次 embed/extract 被完整计算两遍【实证：读码确认】

- `stego/envelope.rs:106`：`let (key_bytes, _) = derive_keys(p, &salt)` ← `perm_seed` 被丢弃
- `spatial/engine.rs:537`、`jpeg/engine.rs:149`：再调一次 `derive_keys(...)` 只为了拿 `perm_seed`

每次操作跑 **200,000 次 HMAC-SHA256**，其中一半纯浪费。建议 `pack_envelope` 一并返回 `perm_seed`。

### 4.4 为挑 256 个头槽，对百万级候选集做全量 shuffle【待复核】

`spatial/engine.rs:486`、`jpeg/engine.rs:117`：

```rust
let mut permuted_candidates = candidate_pixels.to_vec();   // 全量拷贝
permute_indices(&mut permuted_candidates, &header_seed);   // O(n) 次 ChaCha12
let header_slots = &permuted_candidates[..256];            // 只用前 256
```

改 `partial_shuffle(256)` 即 O(256)。注意会改变线格式，需与 §4.2 的版本号一起做。

### 4.5 `min_abs_coeff` 文档 / 校验 / 行为三者不一致【待复核】

`params.rs` 文档说 "default 1"、validate 只要求 `>= 0`；但 `jpeg/engine.rs` 三处（embed/extract/probe）全部 `.max(2)` ⇒ 用户设 0 或 1 被静默改成 2；而 `uerd.rs:146` 用的是**未 clamp** 的值，给 `|C|=1` 的系数赋了有限代价但引擎永远选不中它们。**代价图与候选集口径不一致**，后续维护者极易踩坑。建议 `validate` 下限定 2，并让 UERD 与引擎共用同一个 `min_abs`。

### 4.6 UERD 与论文的若干偏差【待复核】

已核实正确的部分先说：UERD **用了文件自身 DQT 而非硬编码 Annex K**（并有 `uses_file_quant_table_not_annex_k` 单测锁定），`geometry.rs` 对 MCU 交错和 4:2:0 二次采样建模正确并有 5 个单测覆盖。这是好的。

三处偏离：（a）邻域平滑时中心块能量不参与邻域均值、边界块用"有效邻居均值"等价于自动放大权重；（b）单一代价不区分 ±1；（c）能量用 `& !1` 掩码，把 2↔3 区间压平。（c）是为可逆性**必需且正确**的（已被表达式验证）。建议：补一条对作者 MATLAB 参考实现的对照测试，在模块文档里逐条列明偏离点。

### 4.7 性能：单字节 `read()` 循环【待复核】

`jpeg.rs:29-37` 的 `find_jpeg_sos_offset`（以及 `locate`、`suspicious_structures` 的同类循环）在遇到非 `FF` 时 `continue`，对 `File` 意味着**每字节一次 syscall**。正常 JPEG 很快遇到 SOS 退出；但没有 SOS / 被截断 / 非 JPEG 但以 `FF D8` 开头的文件会一路读到 EOF —— 10 MB 文件 = 1000 万次 syscall。这是**畸形输入上的性能放大**，在服务端扫描场景有实际 DoS 意义。建议加扫描上限（如 16 MiB）并改成带缓冲的批量扫描。

### 4.8 `config.rs` 把 TOML 解析了两遍

`parse_config` 先 `toml::from_str::<toml::Table>` 检查未知键，再 `toml::from_str::<FileConfig>` 正式解析。未知键检查的设计意图（防 `pasword` 拼写错静默失效）是好的，但可以用 `#[serde(deny_unknown_fields)]` + 自定义 `Deserialize` 或在 `FileConfig` 上加标记字段实现单遍解析。属 micro-optimization，优先级低。

### 4.9 `pe_codebits` 性能：全量载入 `.text` + 每条操作双次反汇编【待复核】

`read_text_range` 把整段 `.text` 一次性读进 `Vec`（100 MB `.text` 就是 100 MB 分配）；`profile` 对每条指令做 2 次 iced 编码。而 `locate_codebits` **只需要前 112 个位置**（`CHANNEL_HEADER_BITS`）却在判据之前无条件 profile 整个 `.text`。单次 `remove`/`read` 的静态可达路径上有 3~5 次全反汇编。建议给 `profile` 加 `stop_after: Option<usize>` 提前返回，并在 `PeCodeLayout` 上缓存剖析结果。

### 4.10 `pe_codebits` 依赖 `iced_x86::Register` 枚举序做持久化

`pe_codebits.rs` 用 `(r0 as usize) < (r1 as usize)` 决定 bit 值，**而该 bit 被写入宿主字节码**（持久化）。若 iced-x86 升级重排了 `Register` 枚举，旧写字将无法用新版读出。`Register` 是普通 C-like enum、`#[non_exhaustive]`，社区版有可能调整。建议用单测钉住若干 `(Bit, r0, r1)` 三元组的期望值，把第三方枚举序变成受控契约。

### 4.11 带前缀指令的排除依赖隐式推理（加固建议，非已观察错误）

`embed`/`apply_diff` 用 `Instruction::with2(code, r0, r1)` 构造对偶形式 —— 该构造器**不带原指令的任何前缀**（LOCK / 段 / 0x66 / 0x67 / REX 冗余）。当前正确性依赖 "`profile` 的 F5 用长度比较把这些过滤掉"这一隐式推导。我逐一核对了各类前缀：带任何前缀的指令其无前缀对偶必然至少短 1 字节，所以 F5 确实都能拦住。但一旦 `Instruction::with2` 未来被改成继承前缀，就会**产出丢失 LOCK 前缀的指令 ⇒ 原子性被悄悄削弱**。建议在过滤处加显式、带注释的判断，并补一条覆盖 "LOCK / 段前缀指令不被采纳" 的单测。

### 4.12 `derive_channel_header_mask` 只依赖公开 magic ⇒ "掩码"不提供任何保密性

`pe_codebits.rs` 的 `pack_masked` 用 `derive_channel_header_mask(&self.magic)` 掩码，而标准模式下 `CHANNEL_MAGIC == STANDARD_TRAILER_MAGIC`，是**源码级公开常量**。任何人都能算出掩码 ⇒ 通道头里的 `ube_len` 和 `slack_off`（diff 区的精确地址）可被无口令还原。

\Rightarrow arrows ⇒ 隐蔽性依赖"payload 总是加密"，但**元信息完全泄漏**（精确到字节的信封长度与位置，是很强的隐写检测特征）。如果设计上就是"仅混淆"，请在 `docs/pe_codebits_plugin_design.md` 里明确否定保密性，不要让人误用。

---

## 5. 测试与流程观察

### 5.1 审查开始瞬间 HEAD 是红的（已被外部会话修复）

23:37 首次运行 `cargo test --all-targets`：

```
failures:
    stego::spatial::engine::tests::embed_extract_roundtrip_preserves_container
thread panicked: only LSBs may change: 26 -> 25
test result: FAILED. 65 passed; 1 failed
```

**根因（我确证）**：当时正在进行一项 WIP 重构 —— 把空间域嵌入从 **LSB 替换**改成 **三元 ±1 匹配**（`git diff` 可见：文档、`embed_lsb → write_bit_ternary`、候选区间 `(2..=253) → SPATIAL_ELIGIBLE_MIN..MAX`、HILL 掩码 `0xF8` 全部同步改了），但**测试断言没有跟上**，仍写 `a ^ b <= 1`。

这不是代码 bug —— 26→25 是**设计的正确行为**（26 与 25 同属 `& 0xF8` 的 8 值类，`|Δ|=1`，HILL 用 `0xF8` 掩码故代价图不变，这正是 ±1 匹配的设计意图）。到 23:39 外部会话把断言改成了：

```rust
assert!(a.abs_diff(*b) <= 1, "a write moves a pixel by at most one");
assert_eq!(a & 0xF8, b & 0xF8, "a write must stay inside the eight-value class");
```

**这才是正确的断言形式**，比原来的更好（两个不变量都钉住了）。当前全绿。

**值得记下的两点**：

1. 这类"断言比不变量更弱/更强"的漂移，在重构涉及隐蔽嵌入语义时**特别容易漏**。建议给涉及嵌入语义的改动加一条约定：改嵌入规则时同步审视测试里的**形状断言**（不只是往返断言）。
2. 当时它表现为**孤立跑绿、全套跑红**（8 次单跑全 pass，全套 fail）—— 因为每个 embed 用随机 salt，不同 rng 序列选中不同像素。这种"看起来像 flaky test、其实是断言漂移"的情况很容易被误判为不稳定测试而忽略。

### 5.2 CI 覆盖不到的东西

CI 跑 `cargo test --release --locked --all-targets`，**不跑** `#[ignored]` 的 `batch_corpus` / `batch_stego`（它们需要外部语料）。这意味着：

- **核心正确性保证（240/240 全语料还原）不在 CI 里。** 一个破坏性的适配器改动可以在 CI 全绿的情况下上线。
- 建议：在 CI 里跑一个**最小的内置语料**（比如 `tests/assets/` 里的合成 PNG + 一个手工 PE），把"bitr-exact restore"这条不变量进 CI。`tests/assets` 目前只有 `minimal.png`。

### 5.3 JPEG 往返测试可以静默跳过【待复核】

`tests/test_lifecycle/stego.rs` 读 `temp/testfiles/file-08.jpg`，**文件缺失时只 `eprintln!("[SKIP]")` 后 return，不失败**。干净 checkout / CI 上 JPEG 路径等于未测。缺文件应该 `panic!` 或在 CI 里保证语料存在。

---

## 6. 架构与重复代码

### 6.1 `io.rs` 基本是死代码，而同样的循环被手写了 20+ 次【实证：grep 确认】

`src/adapters/io.rs` 定义了三个工具：`copy_exact` / `copy_stream` / `with_restored_position`。全仓检索结果：

```
$ grep -rn "copy_exact\|copy_stream\|with_restored_position" src/ tests/
src/adapters/pe_slack.rs:90:   copy_stream(ube_in, out)?;
src/adapters/pe_slack.rs:377: fn copy_stream<W: Write + ?Sized, R: Read + ?Sized>(   ← 本地重复定义
```

- `copy_exact`：**0 引用**
- `with_restored_position`：**0 引用**（而它的用途正是 `detect()` 的标准模式，被 12 个适配器各手写了一遍）
- `copy_stream`：**唯一"引用"指向 `pe_slack.rs` 自己定义的同名本地函数**，即 io.rs 版本也是死的

与此同时，同一模式的拷贝循环在适配器里被手写了至少 22 处（`mod.rs`/`eof.rs`/`png.rs`/`jpeg.rs`/`zip.rs`/`pdf.rs`/`pe.rs`/`pe_slack.rs`/`isobmff.rs`/`mkv.rs`/`riff.rs`）。

**这是全仓最大的重构收益点**：
1. 让所有 adapter 调用 `io::copy_exact` / `io::copy_stream`；
2. 新增 `io::detect_magic(reader, &[u8]) -> bool`，12 个 `detect` 收敛成一行；
3. `pe_slack` 的 3 个私有 helper 与 `io.rs` 合并。

### 6.2 三份近乎逐字相同的"带重叠尾部倒扫"

`png.rs::find_iend_offset`、`pdf.rs::find_last_eof`、`zip.rs::find_eocd_offset` 都是"64 KiB 倒退 + `len-1` 重叠 + `rposition` 找最后标记 + 返回绝对偏移"。抽 `fn scan_backwards<R>(reader, marker, overlap) -> Result<Option<u64>>` 复用。

### 6.3 六处相同的"读末 24 字节 → 解 UBE 偏移 → `checked_add == file_size`"

`isobmff.rs`(2)、`mkv.rs`、`zip.rs`、`pdf.rs`、`pe_slack.rs`。抽 `fn read_tail_fields_at_end() -> Option<(u64,u64)>` + `fn looks_like_envelope()`。

### 6.4 👍 值得肯定的架构决策（不要在重构中破坏）

- **`Profile` 按"谁必须知道"而非"读/写方向"拆分**（`docs/library_api_practical_plan_20261020.md`）。这从类型系统上消掉了"写时配了、读时忘了"这个失败模式 —— 只有**一个** `Profile` 要传。这是本项目最好的 API 设计决策。
- **`LocalParams` 与可解码性正交**。chunk 长度自描述、压缩有标志位，都不协商 ⇒ 换 `LocalParams` 永远不会让已有载体不可读。
- **`suspicious_structures` 的三层不一致容忍**（magic 不匹配时降级到结构性扫描并 warn 而非 refuse）。这体现了对不同失败模式的清醒认识。
- **`TmpGuard` + 原子 rename + 权限/timestamp 恢复**。异常路径的资源清理是 RAII 的，这点很多项目都做不对。
- **显式{,在 `router.rs` 里拒绝未知格式而不是"追加兜底"**：注释明确说原因是不支持的文件追加信封会破坏它。这个默认值选得很克制。

---

## 7. 流程建议

1. **`panic = "abort"` 与"处理不可信输入"的组合需要审视。** 本项目天然要处理用户从网上下的任意文件。任何一个像 P0-1 这样的切片 panic，在 release 下就是直接 abort。建议：要么把 `panic` 改回 `unwind` 并在 CLI 顶层 `catch_unwind` 转成友好错误，要么**显式承认**"我们 panic 即崩溃"，并在 ` heuristics` 路径（PDF/PE/ZIP 头部解析）上做一次专门的 panic 面审查。考虑到 P0-1 的真实存在，我倾向后者更现实。
2. **给涉及 wire format / 嵌入语义的改动加版本位**（P0-2、P1-6/STC 接线、§4.2/PRNG 可移植性、P1-4/KDF 强度 —— 这四件事都需要同一个东西：一个明确的 envelope format version byte）。建议先做这个再分头做那四件，否则会做成一个接一个的破坏性升级。
3. **把核心正确性保证放进 CI**（§5.2）。现在最有价值的测试（240/240 全语料）反而跑不到。
4. **审查期间工作区被并行修改**，导致：我首次跑测试时是红的、STC 文件在审查中新增、两个子代理的部分行号/结论在我复核时已漂移。建议在进行大范围重构时避免并行会话改同一批文件，或在开始前先 `git stash`/开分支隔离。

---

## 8. 优先级路线图

### 第一批（本周，正确性 + 崩溃）

| # | 事项 | 类型 | 代价 |
|---|---|---|---|
| 1 | **P0-1 PDF 切片 panic**：加 `trailer_idx < sx_idx` 守卫 + 回归用例 | 修 bug | ~10 行 |
| 2 | **P1-3 `checked_add`**：`mod.rs` 默认 `strip` 上提 + 其余 8 处统一 | 硬化 | ~20 行 |
| 3 | **P1-2 `pe_codebits` 绕过签名检查**：检查提到最顶部 | 硬化 | ~10 行 |
| 4 | **P1-1 叠加注入是否成立**：先写一个"两信封叠加 + remove"回归用例**证伪或证实** | 验证 | 测试优先 |
| 5 | **§5.2 把最小内置语料进 CI** | 流程 | 小 |
| 6 | **§1.1.1 给 `batch_stego` 加 `Scan(0)` 基线列**（一行 excel 级改动，解开"嵌入可检测 vs 检测器假阳性"的死结） | 诊断 | ~15 行 |

> **ADDED { item 6 } 的理由**：目前无法确定隐写的实际抗检测表现，而这是内容自适应子系统唯一重要的对外指标。加了基线列以后，§4.1 / P0-3 / STC 默认值三件事的优先级就能用数据排，而不是凭感觉争。

> 第 4 项刻意写成"先写测试"：如果 P1-1 成立，它是本次审查最严重的发现；如果不成立，用 10 分钟就排除了一个重大风险。两种情况都值得先做。

### 第二批（安全，需要与版本位一起做）

| # | 事项 |
|---|---|
| 6 | 引入 envelope **format version byte**（下面 7/8/9 的前置） |
| 7 | **P0-2** stealth magic 加盐 / 或改用 Argon2id + 同步修正文档承诺 |
| 8 | **P1-4** KDF 强度：新版本信封 Argon2id 或 PBKDF2 ≥600k |
| 9 | **§4.2** PRNG 脱离 `StdRng`（直接用 ChaCha12 + 自实现 Fisher-Yates）+ 值稳定性测试 |
| 10 | **P0-3** stego 32B 头：改为不存长度（由槽位几何反推）或 3 副本表决 |
| 11 | **P1-5** 限制 CWD 配置可提供 `password` |

### 第三批（质量与性能）

| # | 事项 |
|---|---|
| 12 | **P1-6（已完成于 `41d91d0`）** ✅ STC 已接线。剩余：把 STC 转为默认 codec（需配合版本位） |
| 13 | **§4.3** PBKDF2 只算一遍 |
| 14 | **§4.4** `partial_shuffle(256)` |
| 15 | **§4.7** JPEG 单字节 read 循环加缓冲 + 扫描上限 |
| 16 | **P1-10** `png::finalize` 改流式 CRC |
| 17 | **P1-11 / P1-12** JPEG 分量选择 / HILL 逐通道代价 |
| 18 | **§6.1–6.3** 抽取 `io` 工具与三处倒扫模版，收敛 22 处手写循环 |
| 19 | **§4.10–4.11** 用单测钉死 iced 枚举序 + 前缀过滤的显式断言 |

---

## 9. 附录：发现置信度说明

出于对自己结论负责，这里区分两类：

**【实证】= 我亲自执行/读到代码确认，可以直接照此修（但重排行号）**
- P0-1 PDF panic —— 亲手构造输入、运行三个子命令复现
- P0-2 stealth magic 无盐 —— 读完 crypto/params/envelope/engine 四处调用确认
- P0-3 stego 头无认证 —— 读完 embed/extract 头部路径确认，并复核了 `41d91d0` 新增的 `encode_header_word`（结论：风险不变且略放大）
- P1-2 pe_codebits 绕过校验 —— 读完 `pe.rs::inject` 确认
- P1-3 checked_add 不一致 —— 对照读完 `mod.rs` 与 `zip.rs` 确认
- P1-4 PBKDF2 100k —— 读常量确认
- P1-5 CWD 配置投毒 —— 读完 config 加载顺序确认
- P1-6 STC 状态 —— 初期判定"未接线"，在 `41d91d0` 后被作者完成接线，已复核改为"已解决"
- §1.1.1 batch_stego 缺基线列 —— 读实际输出表格确认无 `Scan(0)` 列
- §4.1 槽位集合公开 —— 读完选槽逻辑 + 代码内自述的 tradeoff 注释确认
- §4.2 PRNG 是 CSPRNG 但非可移植 —— 读完 prng.rs + 核对 rand 上游确认
- §4.3 PBKDF2 算两遍 —— 读完三处调用确认
- §6.1 io.rs 死代码 —— grep 确认
- §5.1 红色 HEAD 根因 —— 读 git diff 确认是"实现改了、测试断言没跟上"

**【待复核】= 深度子代理审查产出，逻辑我已审阅且认为可信，但落地前需重新核对**
- P1-1 pe_codebits 叠加破坏（**最高优先级验证项**）
- P1-7 ~ P1-12（RIFF 脏尾 / 节表截断 / PDF 对象号 / PNG 2GiB / JPEG 分量 / HILL 通道）
- §4.4 ~ §4.11（partial_shuffle / min_abs / UERD 偏差 / 单字节读 / 双向 pbkdf / 性能 / iced 枚举序 / channel mask）

---

*报告结束。审查范围限于 `rust/`；`python/` 按 AGENTS.md 已冻结，未纳入。*
