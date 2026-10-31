# strhide Rust 项目成熟度与发布就绪度深度审计报告

- **审计日期**：2026-10-31
- **审计基线**：`strhide v0.8.1`（含 `2026-10-31 13:03:49` 第三轮代码审查修复后的工作区快照）
- **覆盖范围**：核心库与 CLI（`rust/src/**` 共 96 个源文件）及 Tauri 桌面端后端（`gui/src-tauri/src/**` 共 8 个源文件）
- **审计重点**：纯代码质量、工程架构、核心密码学与隐写算法正确性、容器解析边界安全、跨端 API 接口一致性（忽略发布文档、CI 与安装包签名等非代码项）

## 1. 核心评估结论与分项成熟度矩阵

当前项目的**核心库与 CLI（`rust/`）已具备公开发布 `0.9.x` 或 `1.0-rc` 的工程成熟度**，模块分层、密码学协议与隐写算法实现扎实；但 **GUI 后端（`gui/src-tauri/`）存在 1 处因最新 API 变更漏同步导致的编译阻断**，且核心库仍残留 **5 处中高优先级的数据、算法与接口边界问题**。建议完成本报告列出的收口修复（预计工作量约半天）后再正式对外发布。

| 评估维度 | 成熟度评级 | 实证审计评价 |
| :--- | :--- | :--- |
| **工程架构与模块边界** | 成熟（可发布） | 严格遵循 `core` → `formats` → `structure` / `stego`（双域同级隔离、互不引用）→ `analysis` → `facade` → `cli`/`gui` 五层架构；`Cargo.toml` 的 Feature 组合切分合理，`structure-base`、`structure-pe`、`content-png`、`content-jpeg`、`content-hevc`、`content-heif-bridge`、`analysis`、`cli` 可独立按需编译 |
| **工程规范与 Unsafe 纪律** | 成熟（可发布） | 全仓零 `TODO`/`FIXME` 遗留；仅在 `stego/coding/stc.rs` 与 `stego/jpeg/cost/juniward.rs` 的 AVX2/FMA 热点路径使用受控 `unsafe`，且均具备运行期 `is_x86_feature_detected!` 守卫、对齐填充（`PAD = 24`）及标量等价性单测验证 |
| **密码学与信封协议** | 成熟（可发布） | PBKDF2-HMAC-SHA256（含 NFC 归一化与单次派生缓存 `UnpackSecrets`）+ HKDF-SHA256 域分离 + AES-256-GCM 流式分块加密；80B 固定头部、`chunk_index` 与 `is_last` 标志完整绑定进 AAD，具备防重排、防截断、防修改及防解压炸弹（`MAX_VERIFY_PAYLOAD_SIZE` 与 `raw_size` 硬限）能力 |
| **隐写算法与容器无损性** | 成熟（局部待收口） | STC 卷积网格编码、PNG 8 值等价类内 `±1` 嵌入（保证提取端 HILL / S-UNIWARD 成本图 100% 比特级复现）、JPEG V3 几何网格 + 过优化霍夫曼表（DHT）三级防护、HEVC CABAC 旁路符号原地重编码设计严谨；仅 HEVC 视频容量预算公式与 PNG `tRNS` 透明键色存在局部边界问题 |
| **不可信输入健壮性** | 中高（有残留缺口） | 第三轮修复已闭合 JAR 签名检查 `cd_size < 4` 切片 panic、取消令牌 `Interrupted` 自旋死循环、ISOBMFF `ube_total_size` 越界分配等关键缺陷；但 `calibration` 亮度平面内存放大、PNG 隐写回溯表预算缺失、JPEG 缺失 `EOI` 检测盲区仍需补齐 |
| **跨端接口一致性** | 存在脱节（阻断 GUI） | `rust/src/facade.rs` 演进后未与独立 Cargo 包 `gui/src-tauri` 同步编译验证，导致 GUI 后端存在编译错误，且 GUI 端重复硬编码了部分容量计算与文件写入逻辑 |

## 2. 第三轮审查修复（CHANGES-20261031）复核验证

针对工作区 `2026-10-31 13:03:49` 落地的 11 项修复，经逐一核对源码实现，确认核心库内已闭合项如下：

| 修复项 | 对应源码位置 | 复核状态 | 复核说明 |
| :--- | :--- | :--- | :--- |
| JAR 签名检查切片越界 | `rust/src/structure/rejection.rs:296` | 已闭合 | 已改为 `!cd_buf.starts_with(b"PK\x01\x02")`，消除了 `cd_size ∈ 1..=3` 时的进程 abort |
| 取消令牌写阶段自旋死循环 | `rust/src/core/control.rs:288-295, 324-333` | 已闭合 | `ProgressWriter::write` 取消时改为返回 `io::Error::other`，避免触发 `Write::write_all` 对 `Interrupted` 的无限重试；`map_io_cancel` 改为直接判定 `control.is_cancelled()` |
| `--stdout` 密码提示污染载荷 | `rust/src/cli/cmd_structure.rs:294-298` | 已闭合 | `--stdout` 模式下密码提示已改走 `eprintln!` |
| CLI 默认路径落盘原子化 | `rust/src/cli/cmd_structure.rs:427` | 已闭合 | `read` 无 `-o` 分支已改为 `commit::write_bytes_atomic` |
| HEVC 小载体错误码统一 | `rust/src/stego/hevc/engine.rs:1541` | 已闭合 | 槽位不足以放下 Superblock 时，`extract` 与 `inspect` 统一返回 `NoHiddenData` |
| `verify` 吞内容域失败修复 | `rust/src/facade.rs:161, 481-484` + `cmd_diag.rs` | 核心库已闭合 / GUI 未同步 | `DualVerify` 新增 `content_error` 并区分三态，但破坏了 `gui/src-tauri/src/commands/diag.rs:163` 的结构体初始化 |
| PNG 缺失 `IEND` 检测盲区修复 | `rust/src/analysis.rs:715-774` + `png/engine.rs:243` | PNG 已闭合 / JPEG 漏改 | PNG 扫描与解码已拒绝无 `IEND` 载体，但同文件的 `track_jpeg_structure` 仍保留了缺失 `EOI` 不报错的盲区 |
| ISOBMFF `ube_total_size` 上界 | `rust/src/structure/adapters/isobmff.rs:137-146` | 已闭合 | `isobmff_locate` 已增加 `min_envelope` 与 `ube_offset + ube_total_size <= file_size` 校验 |
| HEIF 桥接 `patch_uint` 截断保护 | `rust/src/stego/heif/thumb_bridge.rs:573-613` | 已闭合 | 已按字段字节宽度（1/2/4/8）检查 `val > max`，防止 `iloc` 长度静默截断 |
| 终端密码提示控制字符转义 | `rust/src/core/fs.rs:99-124` | 已闭合 | 新增 `escape_control_chars` 过滤控制字符与 Bidi 覆盖字符，防止终端 ANSI/OSC 注入 |
| WS 检测器状态对齐 | `rust/src/analysis.rs:1527-1545` | 已闭合 | `spatial:ws` 触发时的 metric status 已由 `"ALERT"` 改为 `"INFO"`，与 `Severity::Info` 对齐 |

## 3. 现存严重及中高优先级问题详解（按优先级排序）

### 3.1 【P0 · 编译阻断与接口脱节】GUI 后端（`gui/src-tauri`）与核心库失步

#### 问题 1：`gui/src-tauri/src/commands/diag.rs:163-184` 缺少 `content_error` 字段导致编译失败
* **源码证据**：
  `rust/src/facade.rs:144-162` 中 `DualVerify` 定义为：
  ```rust
  pub struct DualVerify {
      #[cfg(feature = "structure-base")]
      #[serde(flatten)]
      pub structure: crate::structure::VerifyResult,
      #[cfg(feature = "content-base")]
      #[serde(rename = "content_stego", skip_serializing_if = "Option::is_none")]
      pub content: Option<crate::stego::StegoVerifyResult>,
      #[cfg(feature = "content-base")]
      #[serde(skip_serializing_if = "Option::is_none")]
      pub content_error: Option<crate::core::errors::ErrorDetail>,
  }
  ```
  而 `gui/src-tauri/src/commands/diag.rs:155-185` 在处理 `is_annexb` 分支时手工构造 `DualVerify`：
  ```rust
  let content = engine.stego().verify_file(&path, &ver_opts).ok();
  Ok(DualVerify {
      structure: VerifyResult { ... },
      content,
      // 缺失 content_error 字段，直接触发 rustc E0063 编译错误
  })
  ```
* **深层架构原因**：`facade.rs` 中的 `engine.inspect_any`、`engine.verify_any` 与 `engine.smart_extract` 早已内置了对 `FileFormat::HevcAnnexB`（仅支持内容域、不支持结构域）的豁免分支（见 `facade.rs:390-392, 452-454`）。`gui/src-tauri/src/commands/diag.rs:32-72`、`diag.rs:152-185` 以及 `gui/src-tauri/src/commands/stego.rs:313-326` 中的 `if is_annexb` 分支完全是早期遗留的重复代码，不仅吞掉了 Annex-B 验证时的 `content_error`，还导致 `DualVerify` 字段变更时编译断裂。
* **修复方案**：直接删除 `diag.rs`（`inspect_carrier_cmd`、`verify_carrier_cmd`）和 `stego.rs`（`smart_extract_cmd`）中的 `if is_annexb` 手工分支，统一调用 `engine.inspect_any`、`engine.verify_any` 和 `engine.smart_extract`。

#### 问题 2：`gui/src-tauri/src/commands/stego.rs:258, 351` 绕过原子落盘
* **源码证据**：
  在 `extract_stego_file_cmd`（第 257–258 行）和 `smart_extract_cmd`（第 350–351 行）中：
  ```rust
  if let Some(ref dest) = output_path {
      std::fs::write(dest, &payload.data)?;
  ```
* **风险影响**：违背了全仓在 R2/R3 确立的“所有落盘必须走临时文件 + `fsync` + 原子重命名”的契约。若磁盘满或中途异常，会直接截断毁坏目标路径已有文件，且在目标为符号链接时会写穿到链接目标。
* **修复方案**：将 `core::commit::write_bytes_atomic` 设为 `pub`（或在 `core::fs` 暴露公共包装），并在 GUI 上述两处替换 `std::fs::write`。

#### 问题 3：`gui/src-tauri/src/commands/stego.rs:110-137` 硬编码容量推算公式与核心引擎不一致
* **源码证据**：
  ```rust
  let (paranoid_max_bytes, high_max_bytes, balanced_max_bytes) =
      if info.format.eq_ignore_ascii_case("hevc") || info.format.eq_ignore_ascii_case("mp4") {
          let base_high = match safety_level {
              SafetyLevel::High => info.recommended_max_bytes,
              SafetyLevel::Paranoid => info.recommended_max_bytes * 2,
              SafetyLevel::Balanced => info.recommended_max_bytes / 2,
          };
          (base_high / 2, base_high, base_high.saturating_mul(2).min(info.max_raw_payload_bytes))
      } else {
          let pixels = info.total_elements;
          let ratio_slots = if info.format.eq_ignore_ascii_case("png") {
              (info.available_slots / 3).max(1)
          } else {
              info.available_slots.max(1)
          };
          ...
      };
  ```
* **缺陷分析**：
  1. `build_hevc_capacity_info` 返回的 `info.format` 实际取值为 `"HEIF/HEVC"`、`"HEVC-AnnexB"` 或 `"MP4/HEVC"`（见 `hevc/engine.rs:606-610`），**永远不会等于 `"hevc"` 或 `"mp4"`**！导致所有 HEVC/MP4/HEIC 载体在 GUI 中全部误走入下方的 `else`（图像介质）分支。
  2. 即便修正了格式名匹配，HEVC 视频各档位预算包含 `ref_flips_per_picture`（Paranoid=10, High=25, Balanced=50，并不是 1:2:4 关系），且 JPEG V3 使用分组 STC 与 `grouped_body_budget`、开销为 `BODY_OVERHEAD (21B)` 而非硬编码的 `28B`。
* **修复方案**：在核心库 `StegoCapacityInfo` 中直接新增 `tier_limits: [usize; 3]`（或提供纯函数从已解码的池信息一次算出三档 `recommended_max_bytes`），彻底移除 GUI 层的手工公式复制。

### 3.2 【P1 · 数据与内存安全】大国标载体下的 GB 级瞬时分配（OOM Abort 风险）

#### 问题 4：分析域 JPEG 标定将整图摊平为 `Vec<f64>`，1 GiB 解码上限被放大至 3–8.6 GiB
* **源码证据**：
  `rust/src/analysis.rs:1333-1336` 与 `rust/src/analysis/calibration.rs:122-140, 200`：
  ```rust
  // analysis.rs:1333
  const MAX_DECODED_BYTES: usize = 1 << 30; // 1 GiB u8 像素缓冲上限
  decoder.set_max_decoding_buffer_size(MAX_DECODED_BYTES);
  ```
  ```rust
  // analysis/calibration.rs:122-128
  fn luma_plane(pixels: &[u8], width: usize, height: usize, channels: usize) -> Option<Vec<f64>> {
      if channels == 0 || width == 0 || height == 0 || pixels.len() < width * height * channels {
          return None;
      }
      let mut out = Vec::with_capacity(width * height); // 每个像素 8 字节 f64！
  ```
* **量化推导**：一张声明尺寸为 `32768 × 32768` 的纯色灰度 JPEG 文件大小仅几十 KB，其解码后 `u8` 像素刚好为 `1 GiB`，可通过 `jpeg-decoder` 门禁。但紧接着 `luma_plane` 会分配 `10.73 亿 × 8 B = 8.59 GiB` 的 `Vec<f64>`（加上原图共 **9.6 GiB**；若为 RGB 图则分配 `2.86 GiB` `f64` + `1 GiB` 原图 = **3.86 GiB**）。由于 `Cargo.toml` 配置了 `[profile.release] panic = "abort"`，单次 `scan` 即可引发进程级 OOM 崩溃。
* **修复方案**：`calibration.rs:208-234` 原本就通过步长 `stride = total_blocks.div_ceil(MAX_CALIBRATION_BLOCKS).max(1)` 最多抽样 `120_000` 个 8×8 块。完全无需预先生成全图 `luma_plane`，直接在 `calib` 循环内对命中的 `(bx, by)` 8×8 窗口从 `pixels` 计算 `block: [[f64; 8]; 8]`，即可将标定阶段额外内存从 **8.6 GiB 降至 < 15 MB**。

#### 问题 5：PNG 内容隐写引擎缺乏管线内存预算闸门
* **源码证据**：
  `rust/src/stego/png/engine.rs:390` 仅检查了 `MAX_PNG_PIXELS = 64 * 1024 * 1024`（64 MP），而全文件未对 STC 回溯位图 `back` 做内存预算检查（对比 `stego/jpeg/engine.rs:96-187` 实现了 `MAX_PIPELINE_BYTES = 8 GiB` 与 `check_pipeline_budget`）。
* **量化推导**：在 50–64 MP 的 RGB PNG 上，`SlotPlan` 的三通道候选池可达 $1.5 \times 10^8$ 槽位。当计算 `cost_model.compute_cost`（HILL 含 `gray`、`x_pad`、`i1`、`i2`、`tmp`、`cost` 共 6 个全图 `f64` 平面，在 64 MP 下峰值约 **3.0 GiB**）后，若用户嵌入较大载荷触发 `stc.rs:627` 的 `vec![0u64; n * words_per_col]`（`h=10, u=3` 时每槽位 128 字节，或 `h=8, u=3` 时每槽位 32 字节），会再瞬间请求 **1.5–4 GiB** 连续内存。
* **修复方案**：将 `estimate_backtrack_bytes` 与预算检查提升到 `stego::coding` 公共层，在 `png/engine.rs` 的 `probe_png_capacity` 与 `embed_png_with_stats` 中统一执行工作集预算核验，并在 `hill.rs` 中复用缓冲平面（`i1` 与 `tmp` 可复用已用完的 `gray`/`x_pad`）。

### 3.3 【P1 · 算法与容量模型矛盾】HEVC 视频推荐容量与嵌入硬闸门不一致

#### 问题 6：`build_hevc_capacity_info` 与 `embed_hevc_patches_with_factor` 使用两套不兼容的预算公式
* **源码证据**：
  1. 容量探测端（`rust/src/stego/hevc/engine.rs:636-645`）：
     ```rust
     let budget = safety_level.video_budget();
     let non_ref_slots = (pool.band_slots[0] as f64 * budget.non_ref_fraction).floor() as usize;
     let ref_slots = budget
         .ref_flips_per_picture
         .saturating_mul(pool.band_pictures[1])
         .saturating_mul(SLOTS_PER_REF_FLIP)
         .min(pool.band_slots[1]);
     trellis.message_bits(non_ref_slots.saturating_add(ref_slots))
     ```
  2. 嵌入执行端（`rust/src/stego/hevc/engine.rs:820-829, 867-885`）：
     ```rust
     let non_ref_fraction = safety.level.video_budget().non_ref_fraction;
     let factor = if window_factor > 1.0 {
         window_factor
     } else if kind == HevcCarrierKind::HeifContainer {
         1.0
     } else {
         (1.0 / non_ref_fraction).max(1.0)
     };
     let desired_body_slots = ((body_needed_slots as f64) * factor).ceil() as usize;
     ...
     if is_video && total_slots < HEVC_SUPERBLOCK_MIN_SLOTS + desired_body_slots {
         return Err(StrHideError::General(...));
     }
     ```
* **触发机制与后果**：
  在低延迟编码或不含 B 帧的 H.265 视频（全 I/P 帧，此时 `band_slots[0] == 0`，所有帧都在参考帧 `band 1`）或高帧率短片中：
  * 若总槽位 `total_slots = 20_000`、帧数 `band_pictures[1] = 120`，在默认 `High` 档（`non_ref_fraction = 0.2`，`ref_flips_per_picture = 25`）下，容量探测算出 `ref_slots = 25 * 120 * 4 = 12_000` 槽位（推荐可嵌入约 **740 B**）；
  * 但嵌入闸门 ignores `ref_slots`，硬性要求 `body_needed_slots <= (20_000 - 524) * 0.2 = 3_895` 槽位（仅允许约 **210 B**）。
  * 结果：用户严格按照 `capacity` 报告的 `recommended_max_bytes` 传入载荷，且通过了第 844 行的 `enforce_safety`，却在第 867 行被报 `HEVC capacity insufficient for tier 'high'` 拒绝。
* **修复方案**：在 `build_hevc_capacity_info`（第 644 行）计算视频 `target_bits` 前，将 `usable_slots = non_ref_slots.saturating_add(ref_slots)` 与 `((total_slots.saturating_sub(HEVC_SUPERBLOCK_MIN_SLOTS) as f64) * budget.non_ref_fraction).floor() as usize` 取 `min`（或者让嵌入端的 `desired_body_slots` 同样计入 `ref_slots` 额度），确保 `probe` 承诺的推荐容量 100% 能通过 `embed` 闸门。

### 3.4 【P1 · 检测与验证盲区】分析域 JPEG 尾随检测盲区与结构域坐标校验豁免过宽

#### 问题 7：删去 JPEG 末尾 2 字节 `EOI (FF D9)` 即可绕过尾随隐写检测并获 `PASS` 背书
* **源码证据**：
  `rust/src/analysis.rs:436-454, 865-878, 1144`：
  ```rust
  // analysis.rs:865-878
  fn track_jpeg_structure(view: &ScanView, out: &mut Vec<Finding>) {
      let walk = walk_jpeg_markers(view.prefix);
      match walk.eoi_end {
          Some(end) => report_trailing(view, end, "jpeg:trailing-data", "EOI", out),
          None => {
              if !view.is_whole() {
                  report_jpeg_tail(view, out);
              }
              // 整文件视图（<= SCAN_WINDOW）且无 EOI 时什么都不报！
          }
      }
      emit_jpeg_findings(walk, out);
  }
  ```
* **后果**：与第三轮刚修好的 PNG `IEND` 盲区完全同源。对于任何常见尺寸（`<= 16 MiB`）的 JPEG，若将末尾 2 字节 `FF D9` 抹除并追加任意密文：
  1. `walk_jpeg_markers` 找不到 `EOI`，返回 `eoi_end: None`；
  2. 因 `view.is_whole()` 为 `true`，不进入 `report_jpeg_tail`；
  3. `track_trailing_entropy`（第 1144 行）因 `Some(FileFormat::Png | FileFormat::Jpeg) => false` 跳过高熵尾随检测；
  4. 第 436–454 行的 `jpeg:trailing-data` 指标无条件输出 `status: "PASS"`, `metric: "0 bytes"`, `detail: "clean termination at EOI"`。
* **修复方案**：完全照搬今日 `track_png_structure`（第 715–774 行）的修法：让 `track_jpeg_structure` 返回 `terminated: bool`，当 `walk.eoi_end == None` 且 `view.tail == None` 时产出一条 `Severity::Suspicious` 的 `jpeg:trailing-data` finding，并在第 443–453 行区分 `!terminated` 的文案（`"no terminator"`）。

#### 问题 8：`envelope_coordinates_agree` 对 `inject_size == 0` 无条件放行
* **源码证据**：
  `rust/src/structure/engine.rs:2311-2321`：
  ```rust
  fn envelope_coordinates_agree(
      header: &EnvelopeHeader,
      ube_offset: u64,
      ube_total_size: u64,
      file_len: u64,
  ) -> Result<(), String> {
      // Scattered strategies (`pe_codebits`) record 0/0 by definition: there is
      // no contiguous injected region to check.
      if header.inject_size == 0 {
          return Ok(());
      }
  ```
* **后果**：注释本意是仅豁免离散策略 `pe_codebits`（`strategy_id == 9`），但代码写成了检查未受 AEAD AAD 保护的 `header.inject_size == 0`。任何连续策略（如 `eof`、`chunk`、`box_uuid`）若头部 `inject_size` 被篡改为 `0`，都会在 `verify` Level 2 中直接短路通过。
* **修复方案**：将判断条件收紧为 `if crate::structure::registry::id_to_strategy(header.strategy_id) == "pe_codebits" { return Ok(()); }`，并对所有非离散策略强制要求 `header.inject_size >= ube_total_size`。

### 3.5 【P2 · 边界条件与工程打磨】

| 编号 | 模块与源码位置 | 问题描述与触发条件 | 修复建议 |
| :--- | :--- | :--- | :--- |
| **P2-1** | `rust/src/stego/png/engine.rs:229-236, 1083-1088` | **PNG `tRNS` 透明键色碰撞**：Color Type 0（灰度）或 2（真彩 RGB）可携带 `tRNS` 块定义某个像素值为全透明键色。当前 `decode_png` 原样保留 `tRNS`，若键色值落在 `[8, 247]` 且 `val % 8 ∈ 1..=6`，`±1` 嵌入会将原本透明的背景像素翻转为不透明（或反之），造成肉眼可见的破损噪点 | 在 `decode_png` 遇到 `ty == b"tRNS"` 且 `color_type == 0 \|\| color_type == 2` 时返回 `UnsupportedFormat`（提示使用 RGBA 或结构域隐写），或解析键色并在槽位筛选时排除 |
| **P2-2** | `rust/src/structure/engine.rs:1362-1379, 1993-2017` | **结构域落盘缺少 `sync_all`**：内容域通过 `commit.rs` 写入时均执行了 `file.sync_all()` + `sync_parent_dir`，但结构域 `write_carrier_with` 和 `remove_carrier_with_dialect` 在 `rename_with_retry` 前未对 `out_file` 执行 `sync_all()` | 在 `write_core` / `remove_core` 作用域结束前补上 `out_file.sync_all()?`，并在 `rename_with_retry` 后调用 `sync_parent_dir` |
| **P2-3** | `rust/src/stego/hevc/heif_boxes.rs:198-235` | **HEIC 切片跨度未做去重与重叠校验**：`parse_heif_targets` 从 `iloc` 提取 `slice_spans` 时，未校验恶意构造的重复/重叠 extent，若两个 span 重叠会导致原地 patch 后写覆盖先写 | 在 `parse_heif_targets` 返回前校验 `slice_spans` 按文件偏移严格递增且互不重叠（`prev.end() <= next.start`） |
| **P2-4** | `rust/src/structure/rejection.rs:275, 340` | **JAR 签名检查未检查加法溢出与全候选失败分支**：第 275 行 `cd_offset + cd_size > file_size` 虽然操作数是 `u32 as u64`（在 64 位不会溢出），但改为 `checked_add` 更规范；此外当文件含 `PK\x05\x06` 候选却全部无法解析出合法 Central Directory（如 ZIP64 签名包 `cd_offset == 0xFFFFFFFF`）时，第 342 行会静默返回 `Ok(None)` 放行 | 当 `candidates` 非空但无一通过 `well_formed` 校验（或检测到 `0xFFFFFFFF` ZIP64 标记）时，保守返回 `Some` 拒绝直接修改或提示存在不可解析的中央目录 |
| **P2-5** | `rust/src/core/crypto.rs:64, 326` | **公共流式加密接口 `chunk_size == 0` 保护**：`chunk_count` 与 `encrypt_stream_to_chunks` 是 `pub fn`，当外部库调用方误传 `chunk_size == 0` 时，`chunk_count` 会除零 panic，而 `encrypt_stream_to_chunks` 仅靠 `debug_assert!` 在 release 下会死循环 | 在函数入口将 `debug_assert!` 升级为显式 `if chunk_size == 0 \|\| chunk_size > MAX_CHUNK_SIZE { return Err(...); }` |

## 4. 公开发布前最小收口清单（Action Plan）

按投入产出比排序，完成以下 3 步即可进入公开发布状态：

1. **修复 GUI 编译与跨端同步（约 30 分钟）**
   * 删除 `gui/src-tauri/src/commands/diag.rs` 与 `stego.rs` 中的 `is_annexb` 分支，直接委托给 `engine.inspect_any` / `verify_any` / `smart_extract`；
   * 将 `gui/src-tauri/src/commands/stego.rs` 中的两处 `std::fs::write` 替换为 `write_bytes_atomic`；
   * 修复 `probe_stego_capacity_cmd` 对 HEVC/HEIC 格式名的判断与三档容量计算，并在 `gui/src-tauri` 目录下执行 `cargo check --all-targets` 验证通过。
2. **闭合 2 处大图内存放大（约 1 小时）**
   * 修改 `rust/src/analysis/calibration.rs`，移除全图 `luma_plane` 分配，改为在抽样块循环内按需计算 `8×8` 亮度块；
   * 在 `rust/src/stego/png/engine.rs` 引入与 JPEG 引擎一致的 `check_pipeline_budget` 预检。
3. **补齐 3 处算法/检测边界（约 1 小时）**
   * 在 `rust/src/stego/hevc/engine.rs:650` 将视频推荐容量与 `(total_slots - 524) * non_ref_fraction` 对齐；
   * 在 `rust/src/analysis.rs:865` 同步 PNG 的 `terminated` 逻辑，对缺失 `EOI` 的整文件 JPEG 产出 `Suspicious` finding；
   * 在 `rust/src/structure/engine.rs:2319` 将 `inject_size == 0` 豁免限制为仅针对 `pe_codebits` 策略。
