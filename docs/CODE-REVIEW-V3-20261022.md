# STC-V3 分支代码深度审查与缺陷分析报告

> **审查分支**：`stego-v3-dev`（相对 `master` 基线）  
> **审查时间**：2026-10-22  
> **审查范围**：JPEG STC-V3 固定几何网格三元隐写、44 字节超块与 TLV 扩展机制、密码套件分层派生、UERD 代价图与三元合法性、DHT 符号表解析、空域头部适配及 CLI/i18n 变更  
> **验证基准**：
> - `cargo test --all-targets`（全绿，145 单元测试 + 68 生命周期测试 + 15 安全测试全部通过）
> - `cargo clippy --all-targets -D warnings`（零警告）
> - `cargo fmt --check`（通过）
> - 忽略批测：`batch_stego`（全量 19 载体通过）、`v3_huffman_corpus_roundtrips`、`v3_payload_matrix_twenty_images`（20 图 × 3 档载荷 60 组 100% 还原）、`batch_corpus`（全部通过）

---

## 目录

1. [执行概要与架构评价](#一执行概要与架构评价)
2. [严重缺陷（Critical / Must Fix）](#二严重缺陷critical--must-fix)
3. [高优先级问题（High / Should Fix）](#三高优先级问题high--should-fix)
4. [中低优先级问题与代码异味（Medium / Low）](#四中低优先级问题与代码异味medium--low)
5. [文档、规范与国际化缺陷](#五文档规范与国际化缺陷)
6. [整改与行动项清单](#六整改与行动项清单)

---

## 一、执行概要与架构评价

### 1.1 核心架构演进评价

`stego-v3-dev` 分支成功兑现了 `docs/stc_v3_final_plan_20261021.md` 的地基重构目标，彻底摆脱了 V2 的致命缺陷：
1. **几何槽位解耦**：槽位集合仅依赖图像块数、网格规则与密钥置换，完全脱离系数值。提取端彻底移除了 UERD 代价图重算和浮点排序，根本消除了 V2 的池失步和单向门赤字。
2. **真三元双向合法性**：将合法性约束简化为仅在 $|c| = 1023$ 处单向限制，解除了 71% 的零/低频湿点锁定，格图窗口全湿率降至几乎为 0，消除了随机无解需要静默换种子的死穴。
3. **分层密钥与防爆破预言机**：移除了明文 `probe` 与特征字，将超块定位置换种子绑定至 `SuiteKDF(password, cover_digest)`。口令猜测成本被锁死在单次套件完整 KDF（200k/600k 次 PBKDF2），不存在微秒级结构旁路。
4. **超块 + TLV 扩展**：定稿 44 字节超块（718 槽精准填充），整个超块作为 AEAD 的 AAD，扩展区解析滞后于载荷解密认证。

### 1.2 审查发现汇总

在肯定架构重构成立的同时，经对全量代码逐行审查与边界推演，共发现 **13 处问题**，其中：
- **严重缺陷（可能引发 Panic / 崩溃）**：2 处
- **高风险缺陷（容量判定倒挂、协议错误降级、32位溢出）**：4 处
- **中低风险缺陷（大图规模伸缩性、保留位校验缺失、API 易用性）**：4 处
- **规范与文档问题（公式脱节、文案与单位笔误、i18n 缺失）**：3 处

---

## 二、严重缺陷（Critical / Must Fix）

### 1. `dht::luma_ac_symbols` 越界索引引发 Panic（拒绝服务 / 健壮性崩溃）

- **位置**：`rust/src/stego/jpeg/dht.rs:144-145`
- **代码片段**：
  ```rust
  0xDA => {
      // SOS: Ns at payload[0], then (Cs, Td/Ta) per component.
      if payload.len() < 4 {
          return None;
      }
      let ta = payload[2] & 0x0F;
      return ac_tables[ta as usize]; // ⚠️ 越界风险
  }
  ```
- **机理核实**：
  - `ac_tables` 定义为 `[Option<AcSymbolSet>; 4]`（固定 4 张表，对应 JPEG 标准允许的 0..3）。
  - 在 JPEG SOS 段（`0xDA`）中，每个分量的对应字节包含 `(Td << 4) | Ta`。
  - 代码取 `ta = payload[2] & 0x0F`，其数学取值范围为 `0..=15`。
  - 在遇到畸变、对抗构造或非法编码的 JPEG 时，若 `ta >= 4`，`ac_tables[ta as usize]` 会发生 **Rust slice index out of bounds panic**。
  - `luma_ac_symbols` 的模块文档承诺：`Parsing is read-only and never fails hard: an unparsable table simply yields None`，该 panic 严重违反了无硬失败的契约，在处理不可信载体时构成 DoS 漏洞。
- **修复方案**：
  ```rust
  let ta = (payload[2] & 0x0F) as usize;
  return ac_tables.get(ta).copied().flatten();
  ```

---

### 2. `layout_for_payload` 未校验分量空数组导致直接 Panic

- **位置**：`rust/src/stego/jpeg/engine.rs:916-917`
- **代码片段**：
  ```rust
  pub fn layout_for_payload(
      carrier_bytes: &[u8],
      payload_len: usize,
      params: &JpegParams,
      fmt: &FormatProfile,
  ) -> Result<Layout, StrHideError> {
      let coeffs = dct_io::read_coefficients(carrier_bytes).map_err(map_dct_error)?;
      let block_count = coeffs.components[0].blocks.len(); // ⚠️ 直接解引用索引 0
  ```
- **机理核实**：
  - 在 `embed_jpeg`（第 356 行）、`extract_jpeg`（第 649 行）、`probe_capacity_with_format`（第 855 行）中，均具备完备的防护：
    ```rust
    if coeffs.components.is_empty() {
        return Err(StrHideError::UnsupportedFormat("JPEG has no image components".into()));
    }
    ```
  - 但作为公开诊断与测试函数 `pub fn layout_for_payload`，遗漏了 `components.is_empty()` 校验，直接访问 `coeffs.components[0]`，在遇到无有效图像分量的 JPEG 数据时将引发 Panic。
  - 同时，该函数未对 `fmt` 和 `params` 进行入参 `validate()`，若传入非法几何结构可能导致下游除以 0。
- **修复方案**：
  补齐 `fmt.validate()?`、`params.validate()?` 以及 `coeffs.components.is_empty()` 防御判断。

---

## 三、高优先级问题（High / Should Fix）

### 3. `enforced_payload_limit` 与容量探测口径不一致（安全档位嵌入倒挂）

- **位置**：
  - 调用处：`rust/src/stego/jpeg/engine.rs:457`
  - 函数实现：`rust/src/stego/jpeg/engine.rs:630-634`
  - 容量探测：`rust/src/stego/jpeg/engine.rs:877-881`
- **机理核实**：
  - 在容量探测 `probe_capacity_with_format` 中，系数总数计算标准为：
    ```rust
    let total_coeffs = block_count * 64; // 全图所有 DCT 系数（含 DC）
    let bpp_bits = (total_coeffs as f64 * safety_level.bpp_limit()).floor() as usize;
    ```
  - 在 `embed_once` 校验报错打印中：
    ```rust
    let bpp = (payload.len() * 8) as f64 / (cover.block_count * 64) as f64;
    ```
  - **然而**在 `embed_once` 调用限额判定时（第 457 行）：
    ```rust
    let max = enforced_payload_limit(n_total, body_grid.len(), params);
    ```
    传入的第一参数是 `n_total = cover.n_total() = block_count * 63`（仅 AC 系数总数，排除了 DC）！
  - **直接后果**：
    `enforced_payload_limit` 内部计算的上限比 `probe` 报告的 `recommended_max_bytes` 少了约 $1.6\%$（即 $63/64$）。
    用户通过 `probe` 或 `inspect` 查询得到的推荐载荷，在使用 `--safety-tier enforced` 嵌入时，会被判定为超出安全阈值而报错拒绝！
- **修复方案**：
  `engine.rs:457` 调整为：
  ```rust
  let max = enforced_payload_limit(cover.block_count * 64, body_grid.len(), params);
  ```

---

### 4. `extract_jpeg` 协议错误吞没：`UnsupportedVersion` 与正文损坏被降级为口令错误

- **位置**：`rust/src/stego/jpeg/engine.rs:743-753` 配合 `rust/src/stego/envelope.rs:277, 285, 299, 301`
- **代码片段**：
  ```rust
  let payload =
      match unpack_envelope_parts(suite, &enc_key, &superblock.nonce, &aad, &ciphertext) {
          Ok(payload) => payload,
          Err(StrHideError::CorruptedData(message)) => {
              return Err(StrHideError::CorruptedData(message));
          }
          Err(_) => continue, // ⚠️ 吞掉了除 CorruptedData 以外的所有错误
      };
  ```
- **机理核实**：
  1. `unpack_envelope_parts` 执行解密时，**AEAD Tag（16 字节）已经认证成功**，说明密钥与 44 字节超块 AAD 完全匹配，载体必然是真实合法的，不存在口令猜测不准的情况。
  2. 若未来载体使用了演进的压缩算法（如预留的 Brotli / Zstandard），`unpack_envelope_parts` 会按协议返回：
     `Err(StrHideError::UnsupportedVersion("Envelope uses unsupported compression algorithm ..."))`
  3. 但 `extract_jpeg` 的 `match` 仅对 `CorruptedData` 向上透传，将 `UnsupportedVersion` 匹配进入 `Err(_) => continue`，尝试完所有套件后最终返回 `Err(NoHiddenData("No valid payload found"))`！
  4. 此外，在 `envelope.rs` 中，解密后的明文长度不符（第 277 行）、解压失败（第 299 行）、解压后长度不符（第 301 行）错误地返回了 `StrHideError::NoHiddenData`。一旦解压出错，同样会被当成"口令不对"吞没，未能给出"载荷损坏"的确切诊断。
- **修复方案**：
  1. `unpack_envelope_parts` 中在 AEAD 验证通过后的所有结构与解压失败一律返回 `StrHideError::CorruptedData`。
  2. `extract_jpeg` 中捕获 `UnsupportedVersion` 并即时向上抛出：
     ```rust
     Err(StrHideError::CorruptedData(message)) => return Err(StrHideError::CorruptedData(message)),
     Err(StrHideError::UnsupportedVersion(message)) => return Err(StrHideError::UnsupportedVersion(message)),
     Err(_) => continue,
     ```

---

### 5. `dht::zero_run_before` 反向零游程算法逻辑缺陷

- **位置**：`rust/src/stego/jpeg/dht.rs:194-209`
- **代码片段**：
  ```rust
  pub fn zero_run_before(block: &[i16; 64], zz: usize) -> u8 {
      let mut run = 0usize;
      let mut i = zz;
      while i > 1 {
          i -= 1;
          if block[ZIGZAG[i] as usize] == 0 {
              run += 1;
              if run == 16 {
                  return 0; // ⚠️ 致命截断：提前退出导致丢弃更前面的零
              }
          } else {
              break;
          }
      }
      run as u8
  }
  ```
- **机理核实**：
  - JPEG 熵编码中，零游程是以正向（zigzag 顺序）遇到非零系数后开始累计，每满 16 个连续零发射一个 `ZRL`（`0xF0`），后续系数所携带的 `run` 为剩余的 `zeros % 16`。
  - `zero_run_before` 从目标位置反向递减扫描，在遇到第 16 个零时执行了 `return 0;`。这导致任何 $\ge 16$ 个零的场景，函数均恒定返回 0，彻底丢失了超过 16 个零以后的实际游程模数。
  - 例如前置连续 17 个零时，实际在 1 个 ZRL 后应剩下 1 个零（`run = 1`），但该函数在倒数到第 16 个零处直接提前返回 0。
  - 所幸在主嵌入引擎 `plan_slots` 中使用的是正向扫描的 `dht::zero_runs`，未直接调用本函数；但作为 `pub fn` 以及被 `symbol_for_value` 依赖的函数，属于未被暴露的逻辑 Bug。
- **修复方案**：
  改用正向统计计算，或者将未使用的 `zero_run_before` 与 `symbol_for_value` 作为死代码整体剔除。

---

### 6. 32 位架构平台下的 `body_n` 整数溢出风险

- **位置**：`rust/src/stego/jpeg/engine.rs:719-720`
- **代码片段**：
  ```rust
  let window = bits + superblock.h as usize - 1;
  let body_n = superblock.u as usize * window; // ⚠️ 32位可能溢出
  if body_n > body_grid.len() {
      continue;
  }
  ```
- **机理核实**：
  - 超块中 `envelope_len` 为 26 位无符号数，最大支持约 $64\text{ MB}$（$2^{26}-1 = 67,108,863$ 字节）。
  - 对应 `bits` 约为 $5.36 \times 10^8$；超块中 `u` 最大支持 64。
  - 当 $u = 64$ 时，$window \times u \approx 3.43 \times 10^{10}$。
  - 在 64 位平台下 `usize` 为 64 位，该值安全；但在 **32 位目标平台**（如 x86 32-bit Windows / Linux 或 wasm32）下，`usize::MAX` 仅为 $4.29 \times 10^9$。
  - $3.43 \times 10^{10}$ 会发生无符号整数溢出：Debug 模式下直接 Panic，Release 模式下发生回绕（wrap-around），回绕后的极小数值会绕过 `body_n > body_grid.len()` 门禁，随后触发下溢或越界。
- **修复方案**：
  使用安全乘法判断：
  ```rust
  let Some(body_n) = window.checked_mul(superblock.u as usize) else {
      continue;
  };
  ```

---

## 四、中低优先级问题与代码异味（Medium / Low）

### 7. `Superblock::check_reserved` 遗漏 `components_mask` 保留位校验

- **位置**：`rust/src/stego/jpeg/header_v3.rs:181-185`
- **现存逻辑**：
  ```rust
  if self.components_mask & COMPONENT_Y == 0 {
      return Err(StrHideError::CorruptedData(
          "Superblock declares no luminance payload component".into(),
      ));
  }
  ```
- **问题分析**：
  - `WIRE_SPEC.md §13.4` 明确规定：`bit0 = Y；其余保留`，且"保留位/字节写 0，解码时校验为 0"。
  - 当前代码仅校验了 bit0 是否为 1，未校验 `bit1..7` 是否全为 0（即 `self.components_mask & !COMPONENT_Y != 0`）。
  - 若未来扩展 Cb/Cr 色度分量载荷（bit1/bit2），当前旧版本解码器会误认该头部有效，并在只读取 Y 槽位的情况下发起错误解密，破坏向前兼容防御机制。
- **修复建议**：
  增加保留位校验：
  ```rust
  if self.components_mask != COMPONENT_Y {
      return Err(StrHideError::UnsupportedVersion(format!(
          "Superblock components_mask {:#04x} uses unsupported channels",
          self.components_mask
      )));
  }
  ```

---

### 8. 满载超大载体（24 MP+）Trellis 状态回溯内存激增

- **位置**：`rust/src/stego/coding/stc.rs:432-436`
- **问题分析**：
  - STC Trellis 状态回溯位图占用内存公式为 $N_{\text{slots}} \times 2^{h-1} / 4$ 字节。
  - 当用户在 24 MP 大图（约 2800 万槽位）上尝试极限满载（$u = 1$，$h = 8$）时，回溯位图本身需分配约 **900 MB**，叠加 UERD 代价图与多份置换槽位表，常驻峰值内存突破 **2.0 GB**。
  - 现有的 `--slot-budget` 参数用于在小载荷时自适应抬高 $u$，但当载荷逼近极限容量时，$u$ 必然跌落至 1，预算控制失效。
- **优化建议**：
  在 `embed_once` 阶段，对 $body\_n \times 2^h$ 的内存开销设置防御性上限报警（如预估超过 1 GB 时报错并建议降低载荷或降低 $h$），避免无提示被 OOM Killer 杀掉。

---

### 9. 固定绝对值 `SlotBudget` 导致高分辨率图像抗检性劣于低分辨率图像

- **位置**：`rust/src/stego/jpeg/v3_layout.rs:105-106`
- **问题分析**：
  - 当前 `SlotBudget` 默认为固定绝对值 `1,200,000`。
  - 在 2.4 MP 图像上，推荐档位载荷（约 30 KB）下，推导出的 $u = 4$（改动率低至 $\approx 0.23$ 改动/比特）。
  - 在 24 MP 图像上，推荐档位载荷（按相同 0.10 bpp 换算约 350 KB）下，由于载荷比特数超出了固定预算，计算结果直接将 $u$ 压到最低的 **$u = 1$**（改动率激增至 $\approx 0.50$ 改动/比特）。
  - 这导致在相同单位面积载荷（bpp）下，大图的局部修改密度反而高于小图。
- **优化建议**：
  允许预算根据宿主图像总槽位数按比例浮动，或在推荐档位下优先基于目标改动率选定 $u$。

---

### 10. `embed_jpeg` / `extract_jpeg` 空字符串口令过滤不一致

- **位置**：`rust/src/stego/jpeg/engine.rs:385, 656`
- **问题分析**：
  - 顶层入口 `options.secret(profile)` 对口令进行了 `.filter(|s| !s.is_empty())` 规整（空字符串转为 `None`，回退至内置公共密钥）。
  - 但直接调用库公开函数 `embed_jpeg` / `extract_jpeg` 时，使用了 `password.unwrap_or(PUBLIC_DEFAULT_SECRET)`，未过滤 `Some("")`。若库调用方传入 `Some("")`，将使用空串直接计算 PBKDF2，导致与顶层统一接口行为不一致。
- **优化建议**：
  统一使用 `password.filter(|s| !s.is_empty()).unwrap_or(PUBLIC_DEFAULT_SECRET)`。

---

### 11. 根模块 `lib.rs` 缺少私有格式定制的关键类型重导出

- **位置**：`rust/src/lib.rs:148-150`
- **问题分析**：
  - `lib.rs` 导出了 `embed`（`embed_jpeg`）、`extract`（`extract_jpeg`）与 `FormatProfile`。
  - 但调用 `embed` 必须提供 `cost_model: &dyn JpegCostModel`，构造自定义 `FormatProfile` 必须引用 `CipherSuite`。
  - 目前 `JpegCostModel`、`UerdCostModel` 和 `CipherSuite` 均未在根导出，用户依照根 API 编写代码时仍需深入内部子模块进行引用。
- **修复建议**：
  在 `lib.rs` 补齐重导出：
  ```rust
  pub use stego::format::{CipherSuite, DEFAULT_FORMAT, FormatProfile, GridRule};
  pub use stego::jpeg::cost::UerdCostModel;
  pub use stego::traits::JpegCostModel;
  ```

---

## 五、文档、规范与国际化缺陷

### 12. `--slot-budget` 与 `--cipher-suite` 缺少双语国际化翻译

- **位置**：`rust/src/i18n/messages.rs` & `rust/src/cli_i18n.rs:92-105`
- **问题分析**：
  - `cli.rs` 中新增了 `--slot-budget` 和 `--cipher-suite` 参数，但在 `cli_i18n.rs` 的映射表和 `messages.rs` 中缺少对应翻译条目。
  - 在中文环境下运行 `strhide embed --help` 时，其他参数均为中文说明，唯独这两个 V3 核心参数显示英文，影响体验。

---

### 13. 线格式规范公式与代码实现轻微脱节

- **位置**：`docs/api/WIRE_SPEC.md §13.3`
- **问题分析**：
  - `WIRE_SPEC.md §13.3` 写道：
    `body_stc_seed = HKDF(perm_seed, salt, info = "stc-trellis" ‖ domain)`
  - 但实际代码 `format.rs:455` 中：
    `stc_seed` 仅使用 `fmt.stc_label`，未拼接 `domain`。
  - 代码实现是安全的，因为 `perm_seed` 在前置派生时已经融入了 `domain`，下层种子天然隔离；但线格式规范文档中的公式描述应当与真实代码保持严格一致。

---

## 六、整改与行动项清单

| 编号 | 类别 | 描述 | 涉及文件 | 推荐处理方案 |
| :---: | :---: | :--- | :--- | :--- |
| **1** | 严重缺陷 | `dht.rs` SOS 解析 `ta >= 4` 越界 Panic | `rust/src/stego/jpeg/dht.rs` | 使用 `ac_tables.get(ta).copied().flatten()` |
| **2** | 严重缺陷 | `layout_for_payload` 空分量解引用 Panic | `rust/src/stego/jpeg/engine.rs` | 补充 `components.is_empty()` 校验与参数合法性检查 |
| **3** | 高风险 | 安全档位限额计算传入了 AC 总数而非系数全量 | `rust/src/stego/jpeg/engine.rs` | `enforced_payload_limit` 传入 `block_count * 64` |
| **4** | 高风险 | AEAD 通过后协议版本与解压错误被降级为口令失败 | `rust/src/stego/jpeg/engine.rs`, `envelope.rs` | 抛出 `UnsupportedVersion` 与 `CorruptedData`，禁止静默 continue |
| **5** | 高风险 | `zero_run_before` 反向扫描 $\ge 16$ 零算法截断 | `rust/src/stego/jpeg/dht.rs` | 修正计算逻辑或清理该无引用函数 |
| **6** | 高风险 | 32 位平台解密网格计算乘法溢出 | `rust/src/stego/jpeg/engine.rs` | 使用 `checked_mul` 防御溢出 |
| **7** | 中风险 | `components_mask` 遗漏保留位检查 | `rust/src/stego/jpeg/header_v3.rs` | 增加非 Y 通道保留位拒绝校验 |
| **8** | 中风险 | 24 MP 极限满载 Trellis 内存达到 2.0 GB | `rust/src/stego/coding/stc.rs` | 增加内存软上限预警或说明 |
| **9** | 中风险 | 绝对值 `SlotBudget` 导致大图上 $u$ 坍塌为 1 | `rust/src/stego/jpeg/v3_layout.rs` | 优化推荐档位下的 $u$ 选择策略 |
| **10** | 低风险 | `embed_jpeg` / `extract_jpeg` 空口令过滤不严 | `rust/src/stego/jpeg/engine.rs` | 统一加入 `.filter(!s.is_empty())` |
| **11** | 低风险 | 根模块缺失 `UerdCostModel`/`CipherSuite` 导出 | `rust/src/lib.rs` | 补齐公开类型重导出 |
| **12** | 国际化 | 两个新 CLI 参数缺少中文消息 | `rust/src/i18n/messages.rs`, `cli_i18n.rs` | 补齐双语翻译条目 |
| **13** | 文档 | `WIRE_SPEC.md` 中 `stc_seed` 派生公式笔误 | `docs/api/WIRE_SPEC.md` | 纠正公式为代码实际派生逻辑 |

---

## 结论

`stego-v3-dev` 分支的基础算法与数学模型设计极其扎实，全量自动化回归与真实语料批测均已全绿。上述 13 项发现主要集中于**边界防御性（畸变格式与 32 位溢出）**、**错误语义透传（AEAD 后的精准报错）**以及**容量/安全门禁的一致性闭环**。完成上述修正后，V3 实现即可具备发布级（Production-Ready）的工业品质。
