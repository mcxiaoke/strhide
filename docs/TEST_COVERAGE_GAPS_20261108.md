# 关键路径测试空洞审计（2026-11-08）

> 范围：`rust/`（内容域 stego + 结构域 structure + CLI）与 `gui/`（Tauri 前端出口）。
> 方法：只读审计。全仓 `rg` 检索 + 调用链追踪 + 一次临时测试实证（`rust/tests/temp_coverage_audit.rs`，运行后已删除，工作区无残留；唯一未跟踪文件 `docs/V1.0_RELEASE_READINESS_AUDIT_20261108.md` 非本任务产物）。
> 排序依据：**缺这个测试会漏掉哪类真实缺陷**，不是覆盖率数字。
> 本轮不新增/修改任何测试与代码，不 commit、不 push。

---

## 摘要

| 级别 | 数量 | 含义 |
| --- | --- | --- |
| 关键 | 5 | 缺失时，用户可见的错误（容量虚报/少报、写读不一致、错误回退走错分支）可长期静默 |
| 重要 | 6 | 明确的分支/边界未测，缺陷可复现但影响面较窄或需要特定输入 |
| 次要 | 5 | 共享代码已间接覆盖，或当前不可达，补测收益有限 |
| 无法判定 | 3 | 受夹具/特性/平台限制，需额外条件才能判 |

### 实施落地记录（2026-11-08）

- **Batch 1（Commit `378db0c`）**：
  - [x] **K1 修复**：`stego/mod.rs` `filename_safe_capacity` 序关系不变量维护（`recommended_max_bytes` 与 `tier_limits` 同步 clamp 到 `max_raw_payload_bytes`），修复 HEIC 等小载体容量反常与 GUI 判定冲突。
- **Batch 2（Commit `9cc90f8`）**：
  - [x] **K2 补齐**：`tests/test_media/hevc_stego.rs` 增加不可压缩伪随机载荷边界双向断言（实证探针与写侧 100% 字节级一致，原报告 1600 字节为透明 Deflate 压缩干扰）。
  - [x] **K5 / I3 补齐**：WAV 与 JPEG `Enforced` 模式下 `rec` 成功而 `rec + 1` 拒绝单测；WAV 低 PBKDF2 上限拒绝单测。
  - [x] **I1 补齐**：`stego/detmath.rs` 极端值（NaN / ±0 / 溢出截断 / 次正规数 / 符号）单测覆盖。
  - [x] **I4 补齐**：`stego/audio/flac/mod.rs` FLAC 畸形元数据块（越过 EOF、零块大小、非法位深）拒绝与拦截单测。
  - [x] **I5 补齐**：`structure/envelope.rs` 信封结构 `validate_against` 9 个错误校验分支单测。
- **Batch 3**：
  - [x] **I6 补齐与重构**：`gui/src/lib/errorHandler.ts` 导出 `kind` 与 `isCapacityOrSafety` 判定；`gui/src/views/StegoEmbedView.tsx` 消除脆弱多语言模糊正则，改为结构化状态判定；新增 `gui/tests/unit/errorHandler.spec.ts`（24 GUI 用例全绿）；`rust/tests/test_cli/verify.rs` 补齐单文件 `--json` 缺失错误单测。


### 最该先补的五条

1. **K1 容量字段跨字段序关系（`filename_safe_capacity` 之后）**：`max_raw_payload_bytes` 被减去 256，但 `recommended_max_bytes` / `tier_limits` 保持不变。实测 `minimal.heic`：`max_raw=4`，`recommended=54`，`tiers=[24,54,93]`。GUI 容量卡读 `tierLimit()`（[StegoEmbedView.tsx:152](file:///c:/Home/Projects/strhide/gui/src/views/StegoEmbedView.tsx#L152)），批量预检却用 `max_raw_payload_bytes`（[:155](file:///c:/Home/Projects/strhide/gui/src/views/StegoEmbedView.tsx#L155)）——界面显示能放 54/93 字节，实际 5 字节就被跳过。现有单测 [mod.rs:502](file:///c:/Home/Projects/strhide/rust/src/stego/mod.rs#L502) 只断言"这两个字段不被 clamp"，选的样例恰好 `max_raw > recommended`，因此该序关系从未被任何测试约束。
2. **K2 HEVC/HEIF 探针容量与写侧可达容量不对等**：`minimal.heic` 探针报 raw 260 字节（filename-safe 后 4），但写侧在默认与 Cabac 调优下都能嵌入并成功提取 **1600 字节**。现有唯一可达性测试 [hevc_stego.rs:239](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L239) 只证明"advertised 能嵌入"，从不证明"advertised+1 被拒"或"写侧真实上限 = advertised"，所以少报/多报都绿。探针走 `scan_hevc_slot_count`（`Capture::Count`，[engine.rs:4235](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L4235)），写侧用的是 `record.all_slots`（[engine.rs:1290](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L1290)），两条记录路径没有横向对照测试。
3. **K3 PNG 容量推荐值随凭据变化，且 Enforced 在"广告值"上拒绝**：同一 `small.png`，无密码探针 `(max 10400, rec 690)`；带密码探针 `(max 10398, rec 689)`。带密码 Enforced 嵌 690 字节 → `SafetyThreshold { required 690, available 689 }`。对称性测试 [engine.rs:3992](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L3992) 对每个凭据都是"同凭据 probe + 同凭据 embed"，没有"探测用匿名、嵌入用密码"的交叉断言。
4. **K4 STC 不可行原因与 h 边界**：`DeadElement`（[stc.rs:584](file:///c:/Home/Projects/strhide/rust/src/stego/coding/stc.rs#L584)）与 `DeadGroup`（[:747](file:///c:/Home/Projects/strhide/rust/src/stego/coding/stc.rs#L747)）从未被断言 `cause`；`fully_illegal_cover_is_an_error_not_a_silent_noop`（[:1421](file:///c:/Home/Projects/strhide/rust/src/stego/coding/stc.rs#L1421)）只 `assert!(is_err())`。可 `cause` 决定了下游行为：JPEG 把两种 cause 合并映射为 over-optimised（[jpeg/engine.rs:966](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L966)），FLAC 重试仅认这两种（[audio/mod.rs:118](file:///c:/Home/Projects/strhide/rust/src/stego/audio/mod.rs#L118)）。cause 错 → 该重试的不重试，或该回退的不回退。另：单测 h 只到 `{4,5,6,8}`，公开入口支持的 9/10 无任何 `message_bits`/`slots_for`/`embed` 断言。
5. **K5 音频失败语义缺失**：`with_enforcement` 全仓测试命中只有 PNG、FLAC 与一处生命周期测试，**WAV 完全没有 Enforced 用例**；`max_pbkdf2_iterations` 拒绝分支有 PNG/JPEG 测试（[png/engine.rs:5005](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L5005)、[stego_jpeg_v4.rs:192](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego_jpeg_v4.rs#L192)），**WAV/FLAC 没有**（实现见 [audio/core.rs:1128](file:///c:/Home/Projects/strhide/rust/src/stego/audio/core.rs#L1128)）。FLAC 有 6 次重试循环与耗尽分支（[audio/mod.rs:208](file:///c:/Home/Projects/strhide/rust/src/stego/audio/mod.rs#L208)、[:261](file:///c:/Home/Projects/strhide/rust/src/stego/audio/mod.rs#L261)），但测试只断言 `flac_retryable` 谓词（[audio/tests.rs:571](file:///c:/Home/Projects/strhide/rust/src/stego/audio/tests.rs#L571)），循环本身与"exhausted its retry budget"从未执行。

---

## 一、逐项明细

### 关键

#### K1. `filename_safe_capacity` 破坏 `recommended ≤ max_raw`（容量口径）

- **模块/函数**：[stego/mod.rs:276](file:///c:/Home/Projects/strhide/rust/src/stego/mod.rs#L276) `filename_safe_capacity`；构造方在 [hevc/engine.rs:905](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L905)（`recommended_for` 用 `min(..., max_raw)`，但减去 256 发生在之后）。
- **现状**：0 个测试断言 facade 输出不变量 `recommended_max_bytes ≤ max_raw_payload_bytes` 与 `tier_limits[i] ≤ max_raw_payload_bytes`。唯一相关单测 [mod.rs:502](file:///c:/Home/Projects/strhide/rust/src/stego/mod.rs#L502) 明确断言"不 clamp"，样例为 `max_raw=300, recommended=280, tiers=[100,200,280]`，天然满足序关系。
- **实证**（临时测试，已删除）：
  - `png small.png: max_raw=10400 rec=690 tiers=[405,690,1046]`
  - `png minimal.png: max_raw=810 rec=34 tiers=[11,34,62]`
  - `jpeg minimal.jpg: max_raw=383 rec=54 tiers=[24,54,93]`
  - `wav small.wav: max_raw=595 rec=38 tiers=[0,38,100]`
  - `hevc minimal.heic: max_raw=4 rec=54 tiers=[24,54,93]` ← **4 < 54 < 93**
  - 对照组：所有引擎的 raw max 都 `≤ 260 + 256`，只有 HEIC 触发该矛盾；PNG/JPEG/WAV 夹具容量远大于 256，恰好掩盖问题。
- **缺失会导致什么**：宿主/GUI 若分别使用 `tier_limits` 与 `max_raw_payload_bytes`（当前 GUI 正是如此），容量展示与准入判断永久不一致；小载体（HEIC 缩略图、极小 PNG）上表现为"显示可嵌 54/93，实际 5 字节即跳过"。也会让 `fits_recommended()` 的语义与真实可嵌入性脱节。
- **补齐所需**：构造 `max_raw < 256 + tier` 的 `StegoCapacityInfo` 单测（无需真实载体），再补一条 HEIC 夹具端到端：probe → 断言三字段序关系 → `recommended` 可嵌、`max_raw` 可嵌。夹具已有 `tests/assets/minimal.heic`。
- **成本**：S（单测半小时；端到端半天）。修复本身另计。

#### K2. HEVC/HEIF 探针 vs 写侧容量口径（单边可达性测试）

- **模块/函数**：探针 [hevc/engine.rs:487](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L487) `hevc_max_raw_payload` + [:4235](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L4235) `scan_hevc_slot_count`；写侧 [:1290](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L1290) `all_slots`；桥接回退 [engine.rs:625](file:///c:/Home/Projects/strhide/rust/src/stego/engine.rs#L625)（探针只在 direct **报错** 时查桥，direct 成功返回小值）。
- **现状**：达标测试 [hevc_stego.rs:239](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L239) 仅 `assert cap >= 1` + "cap 字节能嵌入并读回"。无 `cap+1` 拒绝断言；无"探针值 = 写侧实际可达上限"断言；无探针/写侧槽位记录路径（`Capture::Count` vs `Capture::All`）的对照。
- **实证**：`minimal.heic` 探针 `available_slots=5061`、`total_elements=6144`（64×96），raw max 260；同一文件 Cabac 调优 `embed@54 -> Ok`、`embed@1600 -> Ok`，默认 Advisory 在 60/100/200/400/800/1600 全部嵌入+提取成功。即写侧实际可达 ≥1600，探针广告 260（filename-safe 后 4）。
- **缺失会导致什么**：容量少报（用户以为放不下、GUI 跳过）不会报警；反过来，若某次改动让探针走 `Capture::Count` 的粗算而写侧走 `all_slots`，多报（`PayloadTooLarge` 在用户操作时爆发）同样不会被现有测试发现。`test_hevc_capacity_is_reachable` 的文案（"广告值必须能嵌入"）只覆盖一个方向。
- **补齐所需**：在既有 `small.heic`/`minimal.heic` 夹具上加三条断言：(a) `cap+1` 必须 `PayloadTooLarge`（或明确的桥接接受）；(b) 探针与"先 embed 再 extract"的真实接受量一致；(c) 若允许桥接，探针容量必须是 CABAC 与桥接的 max，而不是"direct 成功就不查桥"。无需新夹具。
- **成本**：M（需先决定语义：HEIF 探针是否应计入桥接容量；测试与实现可能要一起定）。

#### K3. PNG 推荐容量的凭据敏感性未被双端断言

- **模块/函数**：[png/engine.rs:2634](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L2634) `probe_png_capacity`（`derive_locator_master(cred,...)` 决定 header 置换，进而决定 body 池）；Enforced 校验在 `embed_png`。
- **现状**：对称性测试 [engine.rs:3992](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L3992) 对 `None / "pw" / "a-completely-different-password"` 分别做"同凭据 probe + 同凭据 embed + cap+1 拒绝"，**没有跨凭据组合**。
- **实证**：`small.png` 无密码 `(10400, 690, [405,690,1046])`；带密码 `(10398, 689, [405,689,1045])`。带密码 Enforced 在 690 → `SafetyThreshold{required 690, available 689}`。
- **缺失会导致什么**：调用方先匿名探测、后用密码嵌入（或用不同密码/密钥）时，正好在广告值上被拒（1 字节差）；错误信息是"安全阈值不足"，容易被误判为用户设置问题。反过来也可能出现少 1 字节的假状态。
- **补齐所需**：在现有测试上加 `probe(None) → embed("pw")` 与 `probe("pw") → embed(None)` 两组，断言"按 advertise 值嵌入不应被 Enforced 拒绝"，或至少在 API 文档中约束"probe 与 embed 必须同凭据"并由测试钉住。夹具现成。
- **成本**：S。

#### K4. STC 不可行原因（DeadElement/DeadGroup）与 h 边界无断言

- **模块/函数**：[stc.rs:584](file:///c:/Home/Projects/strhide/rust/src/stego/coding/stc.rs#L584)、[:747](file:///c:/Home/Projects/strhide/rust/src/stego/coding/stc.rs#L747)；矩阵测试 [:1117](file:///c:/Home/Projects/strhide/rust/src/stego/coding/stc.rs#L1117) 只覆盖 `(h,u)∈{(4,1),(5,1),(4,2),(4,3)}`；形状测试 [1090](file:///c:/Home/Projects/strhide/rust/src/stego/coding/stc.rs#L1090) 覆盖 `(2,4),(3,4),(2,6),(3,8)`；`message_bits/slots_for` 只在 h≤8 上验证。
- **现状**：`rg 'DeadElement|DeadGroup'` 显示仅 [audio/tests.rs:571](file:///c:/Home/Projects/strhide/rust/src/stego/audio/tests.rs#L571) 构造了带 cause 的 error 喂给谓词，**没有测试从 `StcTrellis::embed` 真正产生这两种 cause**；`fully_illegal_cover...` 只用 `u=4/h=8`，且不检查 cause。
- **缺失会导致什么**：`cause` 是下游分派的输入（JPEG 的 over-optimised 提示、FLAC 的重试资格）。若 `u==1` 分支误报 `DeadGroup`（或反之），FLAC 会在不可恢复的载体上重试 6 次后给出误导性错误；JPEG 会把结构性失败说成"表过度优化"。h=9/10 若被私有 dialect/profile 使用，`u=1..3` 的公式与 embed/extract 无任何测试护住。
- **补齐所需**：构造两类 cover：(a) 单元素非法（u=1，Move::None + 非零 syndrome）断言 `DeadElement`；(b) 整组非法（u≥2，首组全 stuck）断言 `DeadGroup`；再加 `(h,u)∈{(7,1..3),(9,1..3),(10,1..3)}` 的 shape/roundtrip。纯内存夹具。
- **成本**：S–M。

#### K5. 音频引擎的安全策略/凭据/重试失败分支

- **模块/函数**：WAV `probe_wav`/`embed` 路径与 `core::pbkdf2_policy_blocks`（[audio/core.rs:1128](file:///c:/Home/Projects/strhide/rust/src/stego/audio/core.rs#L1128)）；FLAC 重试 [audio/mod.rs:208-261](file:///c:/Home/Projects/strhide/rust/src/stego/audio/mod.rs#L208-L261)。
- **现状**：
  - `rg 'with_enforcement'`：命中 PNG（[engine.rs:4187](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L4187) 等）、FLAC（[flac/e2e.rs:653](file:///c:/Home/Projects/strhide/rust/src/stego/audio/flac/e2e.rs#L653)）、HEVC 纯函数（[engine.rs:4803](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L4803)）、生命周期一条（[stego.rs:1281](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego.rs#L1281)）。**JPEG 与 WAV：0 命中**。
  - `rg 'max_pbkdf2_iterations'`：测试仅 PNG 与 JPEG；WAV/FLAC/HEVC 测试 0 命中。
  - FLAC 重试：仅 `flac_retryable` 谓词测试；`for attempt in 0..6` 循环、"exhausted its retry budget"、`flac_body_phase` 轮换均未在测试中执行。
- **缺失会导致什么**：`--enforce-safety` 在 WAV/JPEG 上若被静默丢弃（历史上 HEVC 就这么发生过一次，见 [hevc/engine.rs:958](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L958) 注释），没有测试能发现；低 KDF 上限在音频上可能变成"读了但不该读"或"直接 panic/绕过"；FLAC 重试耗尽时的错误类型与可重试语义无人验证。
- **补齐所需**：WAV 夹具（`tests/assets/small.wav`）加 Enforced 拒绝/Advisory 通过；WAV/FLAC 各加一条 `with_max_pbkdf2_iterations(1000)` → `NoHiddenData`/空 inspect；FLAC 用一个必然 `DeadGroup` 的合成载体（或注入失败谓词）走到耗尽分支。现有真实 FLAC 夹具过小，见第四节。
- **成本**：M（FLAC 耗尽分支可能需要可控的合成 carrier；现有真实 FLAC 夹具过小，见第四节）。

### 重要

#### I1. detmath 特殊值/溢出/次正规/归约边界零测试

- **文件**：[detmath.rs:158](file:///c:/Home/Projects/strhide/rust/src/stego/detmath.rs#L158)（`EXP_HI/EXP_LO`）、[:126](file:///c:/Home/Projects/strhide/rust/src/stego/detmath.rs#L126)（`frexp` 次正规提升）；测试仅 2 个（[:321](file:///c:/Home/Projects/strhide/rust/src/stego/detmath.rs#L321)、[:404](file:///c:/Home/Projects/strhide/rust/src/stego/detmath.rs#L404)），输入全是正常数量级。
- **现状**：`rg 'EXP_HI|EXP_LO|subnormal|INFINITY|NAN' src/stego/detmath.rs` 只命中实现与注释，测试 0 命中。`ln(0)`、`ln(负数)`、`ln(次正规)`、`exp(±745)`、`log2(0/负数/次正规)`、`cos` 大参数归约、`round_i32` 半值与饱和均无断言。
- **缺失会导致什么**：代价模型/概率在极端输入下产生 `inf/NaN` 并被静默吸收（排序稳定但值错），表现为"隐写后图像质量异常/容量异常"而非报错。若调用域可证明全为正常值，可降级为次要；需先确认调用链输入域。
- **补齐所需**：纯函数边界表驱动测试（NaN/inf/±0/负数/次正规/`EXP_HI±ε`/`EXP_LO±ε`/大角度归约）。无需夹具。
- **成本**：S。

#### I2. PNG 探针带非空 extension 无测试

- **现状**：`probe_png_capacity` 确实按 `extension.len()` 建 `SlotPlan`（[engine.rs:2649-2681](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L2649-L2681)），但所有测试调用都传 `&[]`（如 [:3999](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L3999)、[:4141](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L4141)）。PNG 只有 **embed** 侧扩展往返（[:4821](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L4821)）。
- **横向对照**：JPEG 有 `v4_probe_and_embed_agree_on_extensions`（[stego_jpeg_v4.rs:101](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego_jpeg_v4.rs#L101)）；HEVC 有 `probe_hevc_capacity_ext` 往返（[hevc_stego.rs:392](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L392)）；FLAC 有"扩展不得缩水"（[flac/e2e.rs:611](file:///c:/Home/Projects/strhide/rust/src/stego/audio/flac/e2e.rs#L611)）。**PNG 是唯一缺 probe-ext 对照的引擎。**
- **缺失会导致什么**：探针若漏算扩展 slots，广告值高于写侧，`PayloadTooLarge` 在用户操作时才出现；这类"探针不认扩展"正是 `probe_hevc_capacity_ext` 注释点名的历史缺陷形态。
- **补齐所需**：PNG 夹具 + `Tlv{type_id:0x02}`，probe(ext) → embed(ext) → extract；成本 S。

#### I3. JPEG 安全策略 Enforced 完全无测试

- **现状**：`rg 'with_enforcement' rust/src/stego/jpeg` 0 命中；JPEG 容量探针有推荐值公式（[jpeg/engine.rs:1820](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L1820) 附近）但无"Enforced 在推荐值接受、推荐值+1 拒绝"断言。
- **缺失会导致什么**：JPEG 的 `--enforce-safety` 若被吞掉（与 HEVC 历史缺陷同型），没有任何测试会发现；推荐值边界只能靠用户踩到。
- **补齐所需**：`small.jpg`/`minimal.jpg` 各一条 Enforced High：`recommended` 接受、`recommended+1` → `SafetyThreshold`。现有夹具即可。成本 S。

#### I4. FLAC 解析器负分支

- **文件**：[flac/mod.rs:123](file:///c:/Home/Projects/strhide/rust/src/stego/audio/flac/mod.rs#L123) `parse_stream_info`。分支：元数据链截断、块越过 EOF、STREAMINFO 非首块、长度≠34、STREAMINFO 切片截断、无 STREAMINFO；字段校验在 [:187](file:///c:/Home/Projects/strhide/rust/src/stego/audio/flac/mod.rs#L187) 之后。
- **现状**：测试只覆盖"缺 `fLaC` 标记"（[:1596](file:///c:/Home/Projects/strhide/rust/src/stego/audio/flac/mod.rs#L1596)）、"STREAMINFO 非首块"（[:1470](file:///c:/Home/Projects/strhide/rust/src/stego/audio/flac/mod.rs#L1470)）与大偏移合成（[:1602](file:///c:/Home/Projects/strhide/rust/src/stego/audio/flac/mod.rs#L1602)）。元数据链截断/越界/长度≠34/切片截断/非法块大小与通道数无断言。
- **缺失会导致什么**：恶意/损坏 FLAC 可能走到 panic（切片 panic）或被静默接受后在 `refresh_checksums` 写错 MD5 偏移（注释描述的真实缺陷）；错误类型不稳定会影响 CLI 退出码分类。
- **补齐所需**：字节级合成 FLAC 头（无音频帧），每种畸形一条断言。成本 S。

#### I5. 结构域 `validate_against` 分支矩阵 + strip 对伪造 envelope

- **文件**：[structure/envelope.rs:265](file:///c:/Home/Projects/strhide/rust/src/structure/envelope.rs#L265)。分支包括 version、hint_len、meta_len、hint+meta+fixed 总长、未知 strategy、inject_size/inject_offset 溢出、`offset_delta`、`patch_offset<4`、patch_end>host_len。
- **现状**：`rg 'validate_against' rust/tests` 只命中 hint 超限（[fixes.rs:687](file:///c:/Home/Projects/strhide/rust/tests/test_regression/fixes.rs#L687)）与 4 GiB 注入（[fixes.rs:1114](file:///c:/Home/Projects/strhide/rust/tests/test_regression/fixes.rs#L1114)）；meta 上限经 verify 间接覆盖（[forge.rs:208](file:///c:/Home/Projects/strhide/rust/tests/test_security/forge.rs#L208)）。version / 未知 strategy / inject 坐标 / offset_delta / patch 分支无单测。
- **strip/remove**：`assert_forged_envelope_is_inert`（[forge.rs:78](file:///c:/Home/Projects/strhide/rust/tests/test_security/forge.rs#L78)）只断言 read/inspect/verify，**不调用 remove/strip**；remove 侧另有伪造 host digest / ZIP 坐标测试（[fixes.rs:1066](file:///c:/Home/Projects/strhide/rust/tests/test_regression/fixes.rs#L1066)、[:1151](file:///c:/Home/Projects/strhide/rust/tests/test_regression/fixes.rs#L1151)），已覆盖"认证后拒绝"，但未覆盖"伪造 trailer 尺寸 + remove 不得裁剪"。
- **缺失会导致什么**：`patch_offset` 越界或 `offset_delta` 过大若漏校验，strip 会写到载体之外（实现注释明确说这是唯一防线）；未知 strategy 若进入 adapter 的 restore 分支，可能误删宿主字节。矩阵测试覆盖的是合法路径的 byte-exact 还原，不覆盖这些畸形头。
- **补齐所需**：直接构造 `EnvelopeHeader` 逐分支单测（无需载体），再加一条"伪造 ube_total_size + remove 后宿主不变"。成本 S–M。

#### I6. CLI/GUI 错误出口映射

- **CLI**：批量/缺失输入已覆盖（[verify.rs:603](file:///c:/Home/Projects/strhide/rust/tests/test_cli/verify.rs#L603)、[:637](file:///c:/Home/Projects/strhide/rust/tests/test_cli/verify.rs#L637)），`--auto` 回退覆盖良好（[cli_unification.rs:933](file:///c:/Home/Projects/strhide/rust/tests/test_cli/cli_unification.rs#L933)、[batch.rs:510](file:///c:/Home/Projects/strhide/rust/tests/test_cli/batch.rs#L510)），输出冲突/覆盖保护覆盖良好（[cli_unification.rs:242](file:///c:/Home/Projects/strhide/rust/tests/test_cli/cli_unification.rs#L242)、[:327](file:///c:/Home/Projects/strhide/rust/tests/test_cli/cli_unification.rs#L327)、[:1074](file:///c:/Home/Projects/strhide/rust/tests/test_cli/cli_unification.rs#L1074)）。**未覆盖**：单文件命令的 `--json` 硬错误形态（批量 item 的 `"error"` 形态已断言，单对象形态未断言）。
- **GUI**：`parseStrHideError`/`errorHandler`（[errorHandler.ts](file:///c:/Home/Projects/strhide/gui/src/lib/errorHandler.ts)）在 `gui/tests` 中 **0 引用**；e2e 只覆盖"能力加载失败"（[08-capabilities-failure.spec.ts:12](file:///c:/Home/Projects/strhide/gui/tests/e2e/specs/08-capabilities-failure.spec.ts#L12)）与真实进程的"错误密码显示失败"。批量跳过分类靠字符串匹配 `"capacity"`/`"safety"`/`"容量"`/`"预算"`（[StegoEmbedView.tsx:192](file:///c:/Home/Projects/strhide/gui/src/views/StegoEmbedView.tsx#L192)），无测试。
- **缺失会导致什么**：错误码（`already_exists`、`SafetyThreshold`、`PasswordWithHint`、`TrellisInfeasible`）到用户文案的映射一旦漂移，用户看到错误原因错位；批量把真正的错误误分类成"跳过"（或反之），造成"看起来成功"的部分失败。
- **补齐所需**：GUI 单测直接喂错误对象断言 `{title,message}` 与 skip/error 分类；CLI 一条 `extract --json` 失败形态断言。成本 S。

### 次要

#### M1. `with_exact(true)` 探针语义无测试
- 只出现在 [examples/*_stress.rs](file:///c:/Home/Projects/strhide/rust/examples/png_stress.rs)（不属 CI 测试套件）。估计 vs 全扫描的路径无断言；若 `exact` 影响 `is_estimated` 或容量，缺证据。成本 S，但需先确认该字段是否面向用户。

#### M2. `message_bits`/`slots_for` 全 h×u 公式覆盖不足
- 形状测试仅 `h≤8` 的部分组合；`validate_h/validate_u_wide` 上界（h=10）只有非法值测试。与 K4 同源，可合并修。成本 S。

#### M3. `hevc_max_raw_payload`/`hevc_extension_slots` 无直接单测
- 仅通过 `probe_hevc_capacity_ext` 间接（[hevc_stego.rs:392](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L392)）。扩展槽位算术（[engine.rs:426](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L426)）若错，probe-ext 测试可能因夹具余量充足而不失败。成本 S。

#### M4. unknown critical TLV 读侧拒绝的引擎覆盖不均
- PNG 有伪造 critical 读侧失败（[png/engine.rs:4888](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L4888)）；FLAC 有（[flac/e2e.rs:548](file:///c:/Home/Projects/strhide/rust/src/stego/audio/flac/e2e.rs#L548)）。JPEG/HEVC/WAV 依赖共享 `parse_extension`（[header.rs](file:///c:/Home/Projects/strhide/rust/src/stego/header.rs) 有单元测试）——属**间接覆盖**，不必逐引擎重复。仅在怀疑各引擎调用顺序不同（先认证再解析 vs 先解析）时补一条。

#### M5. 255 字节文件名在 `max_raw` 的端到端只在 PNG 覆盖
- [stego.rs:621](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego.rs#L621)。其他引擎的 `filename_safe_capacity` 同一口径但未端到端验证；结合 K1，建议在修 K1 时一并加 HEIC/WAV 各一条。

---

## 二、按缺陷类型横向归纳

### 1. 容量口径类（最危险）
- 缺 **跨字段不变量**：`recommended/tier ≤ max_raw`（K1）。
- 缺 **probe ↔ writer 双向断言**：只测"advertised 能嵌"，不测"advertised+1 拒绝"、不测"writer 实际可达 = advertised"（K2、I2、M3）。
- 缺 **凭据维度**：probe 与 embed 同凭据才测，交叉组合（K3）。
- 缺 **扩展维度**：PNG probe 不认扩展（I2）；JPEG/HEVC/FLAC 已有对照，可作为模板。
- 共同后果：容量虚高 → 运行时 `PayloadTooLarge`；容量少报 → GUI 误跳过；两者都没有测试报警。

### 2. 对称性类
- 已做得好的：`probe_capacity_is_reachable_by_embed`（PNG，同凭据）、`test_hevc_capacity_is_reachable`（单向）、FLAC probe/ext。
- 缺口集中在"两侧常量/口径相同但没有人同时断言"：凭据（K3）、扩展（I2）、探针记录模式 vs 写侧记录模式（K2）、`probe` 与 `embed` 对 `filename_safe_capacity` 的先后顺序（K1）。
- 建议统一模式：每引擎一条 `probe == embed` 的**双向**边界测试（`cap` 成功、`cap+1` 失败、`extract` 回读一致），并参数化 `{匿名, 密码}` × `{无扩展, 有扩展}`。

### 3. 失败语义类
- 音频最弱：WAV Enforced 与 WAV/FLAC 低 KDF 全无（K5），FLAC 重试循环未执行（K5）。
- STC cause 未被断言（K4），而 cause 是 JPEG/FLAC 回退分派的输入。
- 结构域 `validate_against` 的多数拒绝分支只有实现没有测试（I5）；strip/remove 对伪造 trailer 尺寸无断言（I5）。
- TLV critical 拒绝集中在一个引擎（M4），共享解析器已间接兜底。
- 各引擎 AEAD 失败/错误密码：HEVC、JPEG、FLAC、PNG 均有 `NoHiddenData` 不可区分断言；WAV 错误密码也已覆盖（[audio/tests.rs:117](file:///c:/Home/Projects/strhide/rust/src/stego/audio/tests.rs#L117)）。此维度不缺，缺口只在 Enforced 与低 KDF（K5）。

### 4. 边界数值类
- detmath 特殊值（I1）。
- STC h=9/10、u 全组合（K4/M2）。
- FLAC 头字段边界（I4）。
- `with_exact` 的等价性（M1）。
- `hevc_extension_slots` 算术（M3）。

---

## 三、本轮**不**建议补的项

1. **逐引擎重复 unknown critical TLV 测试**：`encode_extension_for_write`/`parse_extension` 是共享实现，[header.rs](file:///c:/Home/Projects/strhide/rust/src/stego/header.rs) 与 PNG/FLAC 已覆盖写/读两侧；再给 JPEG/HEVC/WAV 各写一遍属于复制，收益是"调用顺序差异"这一极小概率。等真出现顺序差异再加。
2. **结构域各 adapter 的 locate/verify/strip 单元测试**：`test_lifecycle/matrix.rs` 已做全格式 byte-exact 还原、伪造尾部、EOF overlay 位移（[:840](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/matrix.rs#L840) 附近），逐 adapter 重写会与矩阵重复。只有 `validate_against` 的畸形头分支值得补（I5）。
3. **代价模型数值漂移测试**：`scripts/baseline_hash.py --check` 逐例比对字节级基线，比断言具体浮点值更稳。不要在 `cargo test` 里复制一份浮点快照。
4. **压缩探针阈值测试**：`tests/test_lifecycle/profile.rs` 已覆盖可压/不可压、尾块检测、`orig_len+1` 边界；无需再加。
5. **detmath 全 NaN 交互矩阵**：若调用链输入域可证明不含 NaN/inf（需先确认），只补 `EXP_HI/EXP_LO` 与 `ln/ log2` 的 ±0/负数/次正规代表值即可（I1 的最小集）。
6. **GUI e2e 全量错误码**：成本高且脆弱；用 `errorHandler` 单元测试覆盖映射即可（I6）。

---

## 四、无法判定（缺条件）

1. **FLAC 容量/对称性端到端**：仓库夹具 `tests/assets/small.flac` 探针直接失败——`"FLAC carrier has 17 usable subframe tails; the V4 header needs 512"`。这不是代码缺陷，是夹具过小。需要一条 ≥512 个可用 tail 的真实/合成 FLAC 才能判定 FLAC 容量口径与 probe/embed 对称性。现有 `flac_carrier_custom` 合成器（[flac/e2e.rs:112](file:///c:/Home/Projects/strhide/rust/src/stego/audio/flac/e2e.rs#L112)）可扩出足够块数。
2. **HEVC 视频（MP4/MKV）容量语义**：默认 CI 只跑 HEIC；视频分支（drift ladder、`picture_count>1`、`band_slots`）主要在 heavy/ignored 测试中。需要 `cargo test heavy_ -- --ignored` 或真实视频语料才能判定覆盖率是否足够。
3. **HEIF 缩略图桥接容量语义**：`minimal.heic` 的 1600 字节成功是走 Scheme C 还是桥接，需要更细的插桩（inspect 目标 item / 桥接日志）才能判定；本报告只证明"探针 260 ≠ 写侧 ≥1600"，不判定根因。

---

## 五、附录：复核命令与测试位置

### 复核命令（PowerShell + ripgrep）
```powershell
# K1 容量字段序关系：唯一相关单测
rg -n "filename_safe_capacity_only_shrinks|recommended_max_bytes|tier_limits" rust/src/stego/mod.rs

# K2 HEVC 可达性测试（单边）
rg -n "test_hevc_capacity_is_reachable|probe_hevc_capacity_ext" rust/tests/test_media/hevc_stego.rs

# K2 探针/写侧槽位路径
rg -n "scan_hevc_slot_count|Capture::Count|all_slots" rust/src/stego/hevc/engine.rs

# K3 PNG 对称性测试与凭据维度
rg -n "probe_capacity_is_reachable_by_embed" rust/src/stego/png/engine.rs

# K4 STC cause 与 h 覆盖
rg -n "DeadElement|DeadGroup|fully_illegal_cover|for \(seed, h, u\)|for \(u, h\)" rust/src/stego/coding/stc.rs

# K5 音频安全/凭据/重试
rg -n "with_enforcement|max_pbkdf2_iterations|flac_retryable|exhausted" rust/src rust/tests

# I1 detmath 特殊值
rg -n "EXP_HI|EXP_LO|subnormal|NAN|INFINITY" rust/src/stego/detmath.rs

# I2 PNG probe 扩展
rg -n "probe_png_capacity\(" rust/src/stego/png/engine.rs

# I3 JPEG Enforced
rg -n "with_enforcement" rust/src/stego/jpeg rust/tests

# I4 FLAC 解析分支
rg -n "FLAC metadata chain is truncated|runs past the end|must be the first|expected 34" rust/src/stego/audio/flac/mod.rs

# I5 结构域校验/strip
rg -n "validate_against|assert_forged_envelope_is_inert|remove_carrier_bytes" rust/src/structure rust/tests

# I6 GUI 错误映射
rg -n "parseStrHideError|errorHandler" gui/src gui/tests

# 已覆盖（用于对照，不必补）
rg -n "--auto|with_overwrite|Refusing to overwrite" rust/tests/test_cli
```

### 关键测试位置索引
| 主题 | 位置 |
| --- | --- |
| PNG 同凭据可达性 | [png/engine.rs:3992](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L3992) |
| HEVC 单向可达性 | [test_media/hevc_stego.rs:239](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L239) |
| HEVC 带扩展探针 | [test_media/hevc_stego.rs:392](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L392) |
| FLAC 带扩展探针 | [flac/e2e.rs:611](file:///c:/Home/Projects/strhide/rust/src/stego/audio/flac/e2e.rs#L611) |
| JPEG 带扩展探针 | [test_lifecycle/stego_jpeg_v4.rs:101](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego_jpeg_v4.rs#L101) |
| 容量字段不 clamp 单测 | [stego/mod.rs:502](file:///c:/Home/Projects/strhide/rust/src/stego/mod.rs#L502) |
| 255 字节文件名端到端 | [test_lifecycle/stego.rs:621](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego.rs#L621) |
| 结构域伪造 envelope（read/inspect/verify） | [test_security/forge.rs:78](file:///c:/Home/Projects/strhide/rust/tests/test_security/forge.rs#L78) |
| remove 拒绝伪造 host digest | [test_regression/fixes.rs:1066](file:///c:/Home/Projects/strhide/rust/tests/test_regression/fixes.rs#L1066) |
| 批量/JSON 失败 item | [test_cli/verify.rs:603](file:///c:/Home/Projects/strhide/rust/tests/test_cli/verify.rs#L603) |
| `--auto` 回退 | [test_cli/cli_unification.rs:933](file:///c:/Home/Projects/strhide/rust/tests/test_cli/cli_unification.rs#L933) |
| 输出覆盖保护 | [test_cli/cli_unification.rs:242](file:///c:/Home/Projects/strhide/rust/tests/test_cli/cli_unification.rs#L242) |
| GUI 能力失败 | [gui/tests/e2e/specs/08-capabilities-failure.spec.ts:12](file:///c:/Home/Projects/strhide/gui/tests/e2e/specs/08-capabilities-failure.spec.ts#L12) |

### 临时实证说明
- 临时文件：`rust/tests/temp_coverage_audit.rs`（`temp*` 被 `.gitignore` 忽略）。
- 运行命令：`cargo test --all-features --test temp_coverage_audit -- --nocapture`（cwd `rust/`）。
- 覆盖：8 个夹具的 probe/Enforced 边界、PNG/JPEG/WAV 跨凭据、HEIC Cabac 与 Advisory 的 embed/extract、HEIC probe 明细。
- 结束后已删除该文件；`git status --short` 仅剩既有的未跟踪文档 `docs/V1.0_RELEASE_READINESS_AUDIT_20261108.md`（非本任务产生），无任何源码/测试改动。
