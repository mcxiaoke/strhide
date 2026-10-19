# strhide 多格式扩展方案：HEIC / HEIF / WEBP / WAV / MKV

> 版本：v1.1　状态：**第 0 步实测已完成，方案三条主路径全部成立**　日期：2026-10-19
> 范围：Rust 实现（`rust/`）。`python/` 已冻结，不同步。
> 实测报告：`docs/compat_experiment_results_20261019.md`
> 前置阅读：`docs/smart_file_data_hiding_design.md`、`docs/pe_codebits_plugin_design.md`

---

## 1. 背景与目标

当前 strhide 支持 6 种载体（PNG / JPEG / MP4 / ZIP / PDF / Windows PE），8 个策略。目标是再接入
**HEIC、HEIF、WEBP、WAV、MKV**，并且保证：**后续再扩展新格式或新策略时，不需要修改
`engine.rs` 里的中心化分支**。

> 原定的第 6 个格式 **AAC 已被实测移出范围**（§5.5）：`eof` 方案会导致播放器显示的时长
> 按载荷大小线性失真（16 KB 载荷 → 时长 +85%），属用户可感知的元数据损坏。

本次工作的两条腿：

- **A. 架构整改**——把"新增一个格式"从"改 1 个文件 + 改 4 处 engine 中心分支 + 改 11 处测试数组"
  降为"改 1 个文件 + 1 处注册表"。
- **B. 格式接入**——按家族复用容器语法，新增 5 种载体。

**非目标**：不追求容量极限（不做像素级/采样级隐写）；不做无损视频再编码。

---

## 2. 结论摘要

> **实测已验证**（见 `docs/compat_experiment_results_20261019.md`，2026-10-19）。
> 下表"实测"列基于 ffmpeg / libheif 1.23.4 / libwebp 1.6.0 / mkvtoolnix v102 的真实结论。

| 项 | 结论 | 实测 |
| --- | --- | --- |
| HEIC / HEIF | **能力已存在**，只是被 MP4 适配器"误收"。核心工作是收窄检测 + 抽出 ISO-BMFF 共享模块 | ✅ 通过（libheif 完整解析 + ffmpeg 像素级 SHA-256 一致 + 还原逐比特） |
| WEBP / WAV | 同属 RIFF，一次开发两个。**被现有 `strip` 默认实现阻塞**，需各自 override `strip` | ✅ 通过（含 VP8X+ALPH 扩展格式；libwebp / ffprobe / Pillow / Python `wave` 四方验证） |
| MKV | EBML，比想象的简单。关键发现：**"加法型"补丁不需要在 header 里存原值**（见 §6.4） | ✅ 通过（ffprobe / mkvmerge 识别 / 重封装 / 完整解码 / Seek 抽帧全通过） |
| AAC | **移出本次范围**。原定的 `eof` 方案已被实测否决，见下方说明 | ❌ `eof` 否决 |
| 架构最大风险 | `engine.rs` 12 处 `format_name() == "XXX"` 字符串分派；`envelope.rs:308` 的 `strategy_id <= 10` 隐形地雷 | — |

### AAC 为什么被移出范围（实测否决，2026-10-19）

对裸 `.aac`（ADTS）尾部追加不透明字节，**解码出的 PCM 逐比特一致**，但
**ffprobe 报告的时长按载荷大小线性膨胀**：

| 追加字节 | 文件大小 | ffprobe duration | 相对真值(2.043s) |
| --- | --- | --- | --- |
| 0 | 18243 | 2.015467 | 基准 |
| 4000 | 22243 | 2.457383 | +20.2% |
| 16000 | 34243 | 3.783130 | **+85.1%** |

根因：ADTS 解复用器拿不到帧数时用 `文件大小 × 8 / 标称码率` 估算时长，不透明尾字节
被当成音频按码率折算成时长，**误差与载荷大小成正比**。这是用户可感知的元数据损坏，
违反"不改变宿主可见属性"的承诺。

替代方案（合成真实 ADTS 帧承载载荷）实测可行，误差变为解复用器固有偏差而非随载荷放大，
但成本从 1 人日升到 1.5~2 人日，且仍带检测启发式风险。**建议作为独立任务排期。**
| 总工期 | Phase 0（架构）1.5 人日 + Phase 1（格式）6～7.5 人日（AAC 实测否决后移出） |

---

## 3. 架构审查结论

### 3.1 P0 — 不修就会产出坏文件或静默错误

#### P0-1　`engine.rs` 用字符串分派格式逻辑（12 处）

```
engine.rs:777   format_name()=="PNG"  && strategy=="chunk"    → actual_ube_offset += 8
engine.rs:779   format_name()=="MP4"  && strategy=="box_uuid" → += calc_prefix_len()
engine.rs:781   format_name()=="JPEG" && strategy=="app_segment" → += 4
engine.rs:783   format_name()=="PDF"  && strategy=="incremental"  → += calc_prefix_len()
engine.rs:818   format_name()=="JPEG" && strategy=="app_segment" → trailer 定位特例
engine.rs:827   format_name()=="PNG"  && strategy=="chunk"    → 写回后重算 chunk CRC
engine.rs:900-950  6 段 format_name() if-else 生成 strategy_note
```

危害：这些是**编译期不可检的字符串比较**。新格式漏掉 `engine.rs:777` 那一支不会报错，只会算出
错误的 `ube_offset`，直到 `remove` 时才以 `RestoreMismatch` 暴露，而用户已经拿到一个坏掉的载体。

反例（现状）：`engine.rs:783` 为 PDF 做了偏移校正，ZIP 用的是另一种语义（`inject_offset` 直接就是
UBE 起点，`zip.rs:215`），所以 ZIP 没有对应分支。**同一个字段在不同 adapter 里含义不同，
靠 if-else 逐个补齐，这是不变量没有被类型表达的典型症状。**

#### P0-2　`inject_offset` 语义在 5 个 adapter 里各不相同

| adapter | `inject_offset` 实际含义 | 真正 UBE 起点 |
| --- | --- | --- |
| PNG (`png.rs:133`) | chunk 头起点 | `+8` |
| JPEG (`jpeg.rs:298`) | marker 起点 | `+4` |
| MP4 (`mp4.rs:144`) | box 头起点 | `+24/32` |
| ZIP (`zip.rs:215`) | **UBE 真实起点** | `+0` |
| pe_codebits (`pe.rs:566`) | 恒为 0（无文件位置） | — |

这个"前缀由 engine 负责算"的契约**只存在于 engine 的注释里**，`mod.rs:90-91` 的 trait 文档完全没写。

#### P0-3　`strip()` 默认实现无法处理"补丁点在注入点之前"

`mod.rs:168-172`：

```rust
debug_assert!(header.patch_offset as u64 >= header.inject_offset + header.inject_size);
let out_patch_pos = (header.patch_offset as u64).checked_sub(header.inject_size)...
```

补丁点被硬性要求位于注入区之后，且靠"恒定减去 `inject_size`"做坐标平移。而：

- **RIFF**：`RIFF` chunk 的 size 字段在**偏移 4**（u32 LE），注入点在文件尾。
  → debug 构建直接 panic；release 下 `checked_sub` 返回 `CorruptedData`，**remove 100% 失败**。
- **MKV**：`Segment` 的 size 在所有 Cluster 之前，同样在注入点之前。

这是 WEBP / WAV / MKV 的**硬阻塞**，无法通过"写一个新 adapter"绕过。

#### P0-4　`patch_offset: u32` + 单点补丁

`envelope.rs:64-65` 只有 `patch_offset: u32` / `orig_patch_val: u32`，各 4 字节，且 header
定长 112 字节（`envelope.rs:35`）无扩展区。ZIP 在 4 GiB 处被迫放弃策略（`zip.rs:194-198`），
根因就是这个 u32。

需要多点补丁的格式（未来）：ZIP64（EOCD64 + locator + EOCD 三处）、ISO-BMFF 改 `stco`/`co64`
（成百上千个条目）、PNG 的 chunk CRC（**现在靠 `engine.rs:827` 硬编码绕过**）。

#### P0-5　`envelope.rs:308` 的 `strategy_id <= 10` 是隐形地雷

```rust
if unmasked[8] == CURRENT_VERSION && (unmasked[9] & FLAG_ENCRYPTED) == 0
    && unmasked[10] <= 10 && unmasked[11] == 0
```

这个 10 是"排除随机字节被误解码"的启发式。当前只用 1..8，**安全余量只剩 2 个 ID**。
MKV 需要新增 `ebml_void`（ID 9），再用两个就到顶。届时未加密信封的默认密钥路径会静默失效，
退化成不解掩码的 `Self::unpack(data)`（`envelope.rs:316`），**读出错误字段且不报错**。
且没有任何测试守护。

#### P0-6　`router.rs` 两处 `_ =>` 静默降级

```rust
router.rs:87    "pe_codebits" => 8,  _ => 1,      // 未注册策略 → 编码成 eof
router.rs:101   8 => "pe_codebits",  _ => "eof",  // 未知 ID → 报告成 eof
```

`strategy_id` 参与 AEAD 的 AAD（`envelope.rs:153`），**映射错误会一路污染到解密**；
`zip.rs:302` 的 `header.strategy_id == 1` 判断也会走错分支。而这些降级**恰好掩盖了 P0-5**。

#### P0-7　HEIC / HEIF / AVIF / MOV 今天被静默当作 MP4

`mp4.rs:80` 的嗅探是 `tag == b"ftyp"`。HEIC 文件前 8 字节是 `00 00 00 18 66 74 79 70`，
**命中**。`router.rs:29-33` 是"第一个 detect 返回 true 就赢"，所以：

- 现状下 HEIC 实际上**能工作**（追加 uuid box 追加在末尾，解析器会忽略），
- 但 `inspect`/`write` 的输出把它报成 `Format: MP4`，
- `verify_structure`（`mp4.rs:338-340` 只要求存在 `ftyp`）判为"Valid ISO BMFF container"。

所以 HEIC 的接入本质是**修正检测与报告**，不是新增能力——这是好消息，意味着工作量远低于表面。

### 3.2 P1 — 增加维护成本，但不阻塞本次扩展

| 编号 | 位置 | 问题 |
| --- | --- | --- |
| P1-1 | `engine.rs:983-994` / `1180-1189` / `1311-1319` / `1445-1453` | "先试 stealth magic 再试 standard" 的 locate 逻辑**逐字复制 4 份** |
| P1-2 | `engine.rs:547,617,989,1184,1241,1314,1448,1517` | 派生域字面量 `b"strhide-stealth-v1"` 散落 8 处，改版本要全局搜索 |
| P1-3 | `engine.rs:1047-1071` vs `1359-1402` | metadata 解码两条路径**已经分叉**：read 有 legacy 明文回退分支，inspect 没有；错误处理也不同（inspect 返回 JSON error） |
| P1-4 | `engine.rs:1574-1575` | verify 的 Level 3 直接调 `read_carrier`，重开文件、重做 detect、重做 locate。开销约 2 倍，且 L1/L2/L3 之间存在 TOCTOU 窗口 |
| P1-5 | `mod.rs:229-279` `SubStream` vs `jpeg.rs:112-198` `JpegChainedSegmentReader` | 87 行 vs 51 行，同一个东西，只差一个 `Vec<(u64,u64)>`。WEBP/WAV/MKV 都会再抄一遍 |
| P1-6 | `eof` 分支被复制 7 份 | `png.rs:97`/`jpeg.rs:262`/`pdf.rs:327`/`zip.rs:176` 委托给 `EofAdapter`；**但 `mp4.rs:125-128,148-167` 和 `pe.rs:319-344` 自己内联重写了一遍** |
| P1-7 | `locate` 里的 eof 兜底复制 5 份 | `png.rs:230` / `jpeg.rs:489` / `zip.rs:286` / `pdf.rs:489` 逐字相同，`mp4.rs:237` 是第 5 份改写版 |
| P1-8 | `strategy_capacities` 模板 | 7 个 adapter 共 269 行，其中 `"eof"` 条目这个结构体字面量复制了 7 次（每次 7 行） |
| P1-9 | `detect` 的"存位置→seek(0)→读→恢复"模板 | 6 个 adapter 86 行纯样板；整个 crate 里 `SeekFrom::Start(start_pos\|start\|p)` 这个惯用法共 **38 处**（`rejection.rs` 18、`pe_codebits.rs` 9、其余 adapter 13） |
| P1-10 | `adapters/mod.rs:77-88` | `strategy_capacities` 的默认实现是**死代码**——7 个 adapter 全部 override |
| P1-11 | `eof.rs:122-143` | `EofAdapter::verify_structure` 是**死代码**——`EofAdapter` 已不在 `ADAPTERS` 里，但仍被强制实现 |
| P1-12 | `pe.rs:394-404` | 为了摆脱 `open_ube_reader` 的 `&mut` 借用约束，把**整个 `.text` 段读进内存**（真实 PE 可达数百 MB） |
| P1-13 | `jpeg.rs:43-46` vs `365-368` vs `566` | JPEG marker 扫描器写了 3 遍，其中 `suspicious_structures` 的 `0xFF` 填充失败处理是 `return found`，另两处是 `break`——**复制已经开始漂移** |

### 3.3 P2 — 测试与文档

| 编号 | 位置 | 问题 |
| --- | --- | --- |
| P2-1 | `tests/matrix_lifecycle.rs` | **11 处硬编码格式数组**（行 404/413/476/512/560/588/619/667/689/725/759），外加 3 个 `match` 表（`name()`/`ext()`/`carrier()`）和 3 个期望策略映射。加一个格式要改 8～15 处 |
| P2-2 | `tests/pe_codebits.rs:664` | `for expected in ["PNG","JPEG","MP4","ZIP","PDF","PE"]` 硬编码白名单 |
| P2-3 | `tests/real_samples.rs` + `.gitignore:105` (`temp*`) | 真实样本放在 `temp/` 被 gitignore，CI 上测试**静默 return 跳过**（`real_samples.rs:101-103`） |

### 3.4 值得肯定的部分（不要动）

- **read / remove / inspect / verify 四条路径没有任何格式字符串比较**。格式差异完全通过
  `locate` / `open_ube_reader` / `strip` / `verify_structure` 下沉到 trait。
  **所有耦合集中在 write 路径的 12 个 if-else 里**——这是整个架构最健康的部分，整改范围明确。
- `cli.rs` 完全通过 `ADAPTERS` 驱动（`cli.rs:677-679`），`list-strategies` 的表格不会与代码漂移。
- `rejection.rs` 对签名二进制的保护逻辑是独立层，没有和适配器耦合。

---

## 4. Phase 0：架构整改（1.5 人日）

设计原则：**只加带默认实现的方法，不改现有签名**，避免一次性重写 7 个 adapter 引入回归。

### 4.1 消掉 `engine.rs` 的格式分派

给 `HostAdapter` 增加三个**带默认实现**的方法：

| 新方法 | 默认值 | 取代 |
| --- | --- | --- |
| `fn envelope_offset_delta(&self, strategy: &str, ube_size: u64) -> u64` | `0` | `engine.rs:777-786` |
| `fn trailer_anchor(&self, strategy: &str) -> TrailerAnchor` | `EndOfEnvelope` | `engine.rs:818-822`（JPEG → `EndOfInjection`） |
| `fn finalize(&self, carrier: &mut dyn SeekWrite, ctx: &FinalizeCtx) -> Result<()>` | no-op | `engine.rs:827-834`（PNG CRC） |

配套新增：

```rust
pub enum TrailerAnchor { EndOfEnvelope, EndOfInjection }

pub struct FinalizeCtx<'a> {
    pub ube_offset: u64,
    pub ube_total_size: u64,
    pub inject_offset: u64,
    pub inject_size: u64,
    pub strategy: &'a str,
}
```

`strategy_note`（`engine.rs:899-950`）同样下沉为 `fn strategy_note(&self, strategy: &str, fallback: bool) -> Option<String>`，
默认 `None`，各 adapter 自行实现（文案本来就属于格式知识，不属于引擎）。

改完后 `engine.rs` 减少约 70 行，且**新增格式不再需要碰 engine**。

### 4.2 修掉三处静默降级

1. `envelope.rs` 新增 `pub const MAX_KNOWN_STRATEGY_ID: u8`，`envelope.rs:308` 的 `<= 10` 改为引用该常量；
   新增测试断言 `MAX_KNOWN_STRATEGY_ID == STRATEGY_REGISTRY 的最大 id`。
2. `router.rs` 新增单一真源：
   ```rust
   pub static STRATEGY_REGISTRY: &[(&str, u8)] = &[("eof",1),("chunk",2),("box_uuid",3),
       ("pre_cd_inject",4),("app_segment",5),("incremental",6),("pe_overlay",7),("pe_codebits",8)];
   ```
   `strategy_to_id` 改返回 `Result<u8, StrHideError>`，删掉 `_ => 1`；
   `id_to_strategy` 保留 `_ => "unknown"`，让上层能给出明确错误而不是假装是 eof。
3. 保留 `tests/pe_codebits.rs:405` 那条 ID 断言，并扩展成"注册表全表断言"。

**兼容性**：ID 只增不改、只追加到末尾，已写出的载体不受影响。

### 4.3 抽公共工具（消除 P1-9 / P1-5 / P1-6）

- `adapters/io.rs`：`copy_exact(r, w, n)`（流泵，替换 `adapters/` 下 23 处 `loop { read; write_all; break }`）、
  `with_restored_position(r, |r| ...)`（RAII 位置守卫，替换 38 处手工 save/restore）、
  `copy_stream(r, w)`。
- `adapters/mod.rs`：`SubStream` 升级为 `SegmentedSubStream { segments: Vec<(u64,u64)> }`，
  单段构造器保持兼容。`jpeg.rs` 的 `JpegChainedSegmentReader`（87 行）随之删除。
- `eof` 分支：让 `EofAdapter` 真正成为唯一的 eof 实现，`mp4.rs` / `pe.rs` 内联的那两份改为委托。
- `StrategyCapacity` 增加 `fn unbounded_growth(note: &str) -> Self` 构造器，消掉 7 份重复字面量。

### 4.4 收敛 locate 重复（P1-1/1-2/1-3）

在 `engine.rs` 内抽三个私有函数，五条流程统一调用：

```rust
fn locate_envelope(f: &mut dyn SeekRead, a: &dyn HostAdapter, pwd: Option<&str>)
    -> Result<Option<LocatedEnvelope>, StrHideError>;   // 消灭 P1-1 / P1-2
fn read_envelope_header(s: &mut dyn SeekRead, pwd: Option<&str>)
    -> Result<EnvelopeHeader, StrHideError>;
fn decode_metadata(...) -> Result<Value, StrHideError>; // 消灭 P1-3 的分叉
```

顺带把 verify 的 Level 3 从"重开文件调 `read_carrier`"改成"复用已定位的信封流"，去掉 TOCTOU 窗口。

### 4.5 测试表驱动（P2-1）

`matrix_lifecycle.rs` 建一张表：

```rust
struct FmtSpec { fmt: Fmt, name: &'static str, ext: &'static str,
                 build: fn(&Path) -> io::Result<()>,
                 auto_strategies: &'static [(&'static str, &'static str)] }

static FORMATS: &[FmtSpec] = &[ /* 现有 6 个 */ /* 新增的 6 个 */ ];
```

11 处数组改为遍历 `FORMATS`。加一个格式 = 1 条表项 + 1 个 `build` 函数。
同步修 `tests/pe_codebits.rs:664` 的硬编码白名单。

### 4.6 Phase 0 验收

- `cargo test` 190 项全绿；`cargo clippy --all-targets` 0 警告；`cargo fmt` 无 diff
- `engine.rs` 中 `format_name() == "` 出现次数 = **0**；`selected_strategy == "` = **0**
- `tests/matrix_lifecycle.rs` 中格式数组字面量 = **1 处**（`FORMATS` 表）

---

## 5. 各格式技术方案

### 5.1 ISO-BMFF 家族：抽出 `isobmff.rs`

把 `mp4.rs` 中与"MP4"无关、纯属 ISO-BMFF 语法的部分提到 `adapters/isobmff.rs`
（**当前全部是 `impl Mp4Adapter` 的私有方法/常量，约 150 行**）：

| 提取项 | 当前位置 | 说明 |
| --- | --- | --- |
| box 头解析（`size==1`→largesize / `size==0`→延伸到 EOF） | `mp4.rs:283-311` | 纯规范 |
| 顶层 box 树遍历 + `ftyp` 校验 | `mp4.rs:259-346` | 移为 `walk_top_level` |
| 尾部信封检测 `trailing_envelope_len` | `mp4.rs:27-61` | 私有 → 公共 |
| uuid box 头写入（32 位 / 64 位） | `mp4.rs:148-164` | 移为 `write_uuid_box_header` |
| uuid box 头回读（32 位 / 64 位） | `mp4.rs:191-235` | 移为 `read_uuid_box_header` |

保留在 `mp4.rs` 的只有品牌相关和策略相关部分。

### 5.2 HEIC / HEIF（1.5 人日）

**策略**：复用 `box_uuid`（strategy_id = 3）。**无协议变更。**

**检测（关键设计决策）**：**不要收窄 `Mp4Adapter::detect`**。收窄会让现有 MP4 载体（brand 五花八门：
`isom/iso2/iso5/iso6/mp41/mp42/avc1/M4V /M4A /dash/qt  /3gp4/...`）开始被拒，是回归风险。

改为**纯增量**方案：

```
ADAPTERS 顺序：[..., HeifAdapter, Mp4Adapter, ...]
```

- `HeifAdapter::detect` —— 读 `ftyp` 的 `major_brand` + `compatible_brands`，
  命中 HEIF/AVIF 品牌集才返回 true。
- `Mp4Adapter::detect` —— **保持现状不动**。

效果：HEIF 文件被 `HeifAdapter` 抢先认领并正确报告为 `HEIF`；
其它任何 BMFF 仍走 MP4（行为完全不变）。**零回归风险。**

HEIF 品牌集：`heic heix heim heis hevc hevx hevm hevs mif1 msf1 msf2 avif avis`

**特殊处理**：
1. **`mdat` 的 `size==0`**（表示延伸到 EOF）：追加的 uuid box 会被 `mdat` 声明吞掉
   —— 结构上不再是一个独立的顶层 box，`remove` 仍能正确还原（默认 strip 只按字节切片），
   但注入区不再是结构上可分辨的区域，暗藏性与 `inspect` 的结构描述都变差。
   → `strategy_capacities` 检测到这种情况时把 `box_uuid` 标为 `available: false`，
   `choose_auto_strategy` 回退到 `eof`，并在 `strategy_note` 里说明原因。
   （MP4 适配器目前**没有**这项容量报告，属于既有能力缺口，一并补上。）

   > 补充：`mp4.rs:306-308` 对 `size == 0` 一律当作"延伸到 EOF"处理。
   > 若未来要让 `verify_structure` 区分"末 box 声明到 EOF"与"末 box 恰好结束于 EOF"，
   > 这里需要额外记录注入点，当前不必。
2. **`verify_structure`**：box 树遍历 + 要求存在 `ftyp` **和** `meta` box。

**实测结论（2026-10-19，已完成）**：✅ 全部通过。
用**现有 strhide 二进制**（HEIC 当前被 MP4 适配器认领走 `box_uuid`）实测：
- libheif 1.23.4 `heif-info` 完整解析（640x480, YCbCr 4:2:0, bit depth 8, nclx 全在）
- ffmpeg 解码为 rawvideo，**像素级 SHA-256 与原文件完全一致**
- strhide `read` / `remove` 正确，**还原逐比特一致**
- 注入后 uuid box 是合法的第 4 个顶层 box（`@28786 size=269`）

另单独实测了 `mdat size==0` 边界：**不损坏文件**——`heif-info` 正常、ffmpeg 完整解码无错、
`remove` 逐比特还原、L1/L2/L3 全 PASS；真实影响仅是注入区结构上不可分辨
（`verify` 报"3 top-level boxes"而非 4）。故保留 §5.2 特殊处理第 1 条的处置建议，
但理由是**结构可分辨性与报告准确性**，而非"会损坏文件"。

> 唯一偏差：`verify` 输出的 `Format: MP4`，坐实了 §3.1 P0-7 的报告错误问题。
> 详见 `docs/compat_experiment_results_20261019.md` §1 与 §5。

---

### 5.3 RIFF 家族：`riff.rs`（1.0 人日）+ WEBP（0.5）+ WAV（0.5）

**共用骨架**：

```rust
pub struct RiffAdapter { pub format_name: &'static str, pub form_type: [u8;4] }
// WebpAdapter { "WEBP", *b"WEBP" },  WavAdapter { "WAV", *b"WAVE" }
```

**注入策略 `riff_chunk`**（新策略名 → **strategy_id = 9**，触发 §4.2 的常量修复）：
在文件末尾追加一个 chunk：

```
'SHRD' | payload_len(u32 LE) | UBE 字节流 | [1 字节 0x00 补齐]
```

**关键设计：不需要通用补丁机制。**
`inject` 的 `host_in` 是 `SeekRead`，可以先 `seek(End(0))` 拿到宿主长度，
**直接把正确的 RIFF size 一次写对**：

```
new_riff_size = host_len + 8 (chunk 头) + ube_size + pad - 8
```

于是 `patch_offset = 0`（无补丁），**完全绕开 P0-3 的阻塞**。

**`strip` override**（每个 RIFF adapter 约 40 行）：
默认实现会原样复制 `[0, inject_offset)`，其中包含**已被改大的** RIFF size。必须自己实现：

```
copy [0,4)
write (orig_host_size - 8) as u32 LE      // 从 EnvelopeHeader 派生，无需存原值
copy [4, inject_offset)
skip [inject_offset, inject_offset + inject_size)
copy 其余全部
```

`orig_host_size` 已在 header 里（`envelope.rs:60`），**不需要协议变更**。

**`envelope_offset_delta("riff_chunk", _) = 8`**（UBE 起点 = chunk 头之后 8 字节）。

**`locate`**：走 chunk 链，找到 fourcc == `SHRD` 且 payload 尾部 trailer 校验通过；
回退到 eof 尾部检查（复用 §4.3 的公共 helper）。

**`verify_structure`**：chunk 链从 offset 12 走到末尾，每步 size 自洽、奇数长度有补齐字节、
最终 `riff_size + 8 == 文件长度`。

**WEBP 特有**：
- 不修改 `VP8X` 的画布尺寸/动画标志位（追加 chunk 不影响画布语义）。
- WebP 规范的 chunk 读取器必须忽略未知 fourcc；`libwebp`（`webpinfo` / `dwebp`）行为待实测。
- 若宿主是 `VP8X` 扩展格式，仍只是在末尾追加，不动既有 chunk。

**WAV 特有**：
- `LIST` 子块（`INFO` / `adtl`）需要递归遍历来定位末尾，注入仍放在顶层 chunk 序列末尾。
- `data` chunk 长度为 u32，>4 GiB 的 WAV 走 **RF64**（`RF64` + `ds64` 64 位长度），
  此时 RIFF size 语义不同 → **RF64 文件直接拒绝 `riff_chunk`，回退 `eof`**（`eof` 不改任何 size 字段）。
- 部分 WAV 在最后一个 chunk 后有 1 字节补齐或尾部垃圾 → 注入点取"chunk 链真实末尾"而非"文件末尾"，
  垃圾字节保持在注入区之后。

**实测结论（2026-10-19，已完成）**：✅ 全部通过。4 个样本（VP8 / VP8L / **VP8X+ALPH** / WAVE）
注入 4028 B 的 `SHRD` chunk 后：

| 样本 | libwebp `dwebp` 1.6.0 | ffprobe | Pillow 12.3 | Python `wave` | 像素一致 | `strip` 逐比特 |
| --- | --- | --- | --- | --- | --- | --- |
| `sample.webp`（VP8） | ✅ | ✅ | — | — | ✅ | ✅ |
| `sample_ll.webp`（VP8L） | ✅ | — | — | — | ✅ | ✅ |
| `sample_ext.webp`（**VP8X+ALPH**） | ✅ 320x240 with alpha | ✅ `pix_fmt=yuva420p` | ✅ RGBA | — | ✅ | ✅ |
| `sample.wav`（fmt+LIST+data） | — | ✅ `pcm_s16le 44100 1ch 2.000000s` | — | ✅ 88200 frames | — | ✅ |

- **时长未受影响**（2.000000 == 2.000000）：WAV 时长来自 `data` chunk 显式长度。
- **`strip` 逐比特还原** ×4，`orig_riff_size = orig_host_size - 8` 的派生方案成立。
- 方案 §5.3 的三个关键假设全部验证：① RIFF size 一次写对（不用通用补丁机制）
  ② 未知 fourcc chunk 被所有解码器忽略 ③ strip 用 `orig_host_size - 8` 派生原值。

> ⚠️ **ImageMagick 不可用作验收工具**：`magick identify` 对**原始样本**同样报
> `RegistryKeyLookupFailed CoderModulesPath`，属本地安装问题（已用原文件做对照实验确认）。
> 若目标环境需要覆盖 ImageMagick，需先修复其安装再补测。

**范围外**：不做 WAV 采样 LSB 分散注入（需要 §7 的协议升级）。

---

### 5.4 MKV（2.5～3 人日）

**检测**：`1A 45 DF A3`（EBML Header 的 ID，4 字节）。同时要求紧随其后的 size VINT 能解析。
`router.rs` 里排在最后（最严格的 magic）。

**EBML 基础（新建 `adapters/ebml.rs`，约 180 行）**：

| 函数 | 说明 |
| --- | --- |
| `read_vint(r, keep_marker) -> u64` | 1～8 字节变长整数。前导 0 的个数决定宽度，marker 位要剥掉 |
| `write_vint(v, width) -> [u8]` | 固定宽度写回 |
| `read_id(r) -> u32` | ID 是**保留 marker** 的 VINT（1～4 字节） |
| `walk_segment(r) -> Vec<Element>` | 顶层遍历 + Segment 子元素遍历 |

**注入策略 `ebml_void`**（新策略名 → **strategy_id = 10**，用满 `MAX_KNOWN_STRATEGY_ID` 的余量，
再次印证 §4.2 那个常量必须先修）。

Segment 内部追加一个 **Void 元素**（ID `0xEC`）——Void 是 Matroska 规范里专门用于填充/保留的元素，
**所有合规解析器都会跳过它**，比在顶层追加未知元素干净得多：

```
0xEC | size_vint | UBE 字节流 | ...
```

**Segment size 处理（三种情况）**：

| 情况 | 处理 | `patch_offset` | `strip` |
| --- | --- | --- | --- |
| Segment size 是 **unknown**（VINT data 全 1，流式录制常见） | 无需改，Segment 本身声明"延伸到 EOF" | `0` | 用 trait 默认实现 |
| size **已知**且 VINT 宽度 ≥ 4 字节 | 原地改值：`new = old + inject_size` | 需要 | 覆盖：`orig = cur - inject_size` |
| size **已知**但 VINT 太窄、加完会溢出 | **拒绝 `ebml_void`**，回退 `eof` | — | — |

**加法型补丁的可逆性**：`new = old + Δ` ⟹ `old = new - Δ`，而 `Δ = inject_size` 就在 header 里
（`envelope.rs:62`）。**原值永远不需要存进 header**——这是 RIFF 和 MKV 能共用同一套 strip 逻辑的根本原因，
也让 P0-4（单点 u32 补丁）暂时不需要协议升级。

> ⚠️ **`inject_size` 必须是元素总长，含容器头。**
> 实测中原型第一版按"载荷长度"（4019）回算，Segment size 差 5 字节（`1` 字节 Void ID + `4` 字节 size VINT），
> **`remove` 结果不逐比特一致**。必须遵循 PNG（`png.rs:167`：`4 + 4 + ube_size + 4`）与
> JPEG（`jpeg.rs:308`：`4 + seg_payload_len`）已有的约定——**注入区的完整字节数**。
> RIFF 同理（`SHRD` 的 8 字节 chunk 头必须计入）。RIFF 与 MKV 的原型实测都因此
> 出现过 off-by-header 的还原失败，这是本次实验暴露的最隐蔽的一个坑。

**`strip` override**（MKV 版，约 45 行）：
copy 遍历 → 遇到 Segment size VINT 时写回 `(cur - inject_size)`（同宽度重编码）→ 跳过注入区 → copy 其余。

**为什么在文件末尾注入不会破坏其它结构**：
- Segment 之前的一切（EBML Header、Segment 头）字节位置不变。
- `SeekHead` / `Cues` 里存的是**绝对偏移**，指向的都是追加点**之前**的元素 → 全部保持有效。
- 唯一需要改的就是 Segment 自身的 size。

**实测结论（2026-10-19，已完成）**：✅ 全部通过。4 个变体（ffmpeg / mkvmerge /
ffmpeg `-live 1` / mkvmerge 加轨道元数据）注入 4024 B 的 Void 元素后：

| 变体 | Segment size 变更 | ffprobe | mkvmerge 识别/重封装 | 完整解码 | Seek 抽帧 |
| --- | --- | --- | --- | --- | --- |
| `v_a_ffmpeg` | 110200 → 114224 | ✅ | ✅ | ✅ | ✅ |
| `v_b_mkvmerge` | 115167 → 119191 | ✅ | ✅ | ✅ | ✅ |
| `v_c_live`（流式，**unknown**） | 无需补丁 | ✅ | ✅ | ✅ | ✅ |
| `v_d_rich` | 115179 → 119203 | ✅ | ✅ | ✅ | ✅ |

- **时长未受影响**（3.023000 == 3.023000）：MKV 时长来自 `Info/Duration` 显式元素。
- **Seek/Cues 完好**：注入后 `-ss 2.0` 抽帧与原始文件同位置抽帧 PNG 字节完全一致。
- **`strip` 逐比特还原** ×3（含修正 `inject_size` 语义后）。

**VINT 宽度实测分布**（4/4 变体均为 **8 字节**）：

| 变体 | 工具 | Segment size VINT 宽度 |
| --- | --- | --- |
| `v_a_ffmpeg.mkv` | ffmpeg matroska | 8 |
| `v_b_mkvmerge.mkv` | mkvtoolnix v102 | 8 |
| `v_c_live.mkv` | ffmpeg `-live 1` | 8（值为 **unknown**） |
| `v_d_rich.mkv` | mkvmerge + 轨道名/语言 | 8 |

两个对实现有直接影响的发现：
1. **ffmpeg 与 mkvmerge 都固定用 8 字节宽度** → 上表第 3 行"VINT 太窄需回退 `eof`"
   是**防御性分支而非常规分支**，保留但不需投入测试资源。
2. **流式录制会产生 unknown-size Segment**（真实常见场景）→
   上表第 1 行"无补丁"分支**必须实现且必须有测试覆盖**。

附带发现：**4 个变体在 Segment 内部本来就有 `Void` 元素**（ffmpeg 1 个、mkvmerge 2 个）。
Void 是 muxers 自己就在用的合法填充元素，方案选择零风险。

**范围外**：不做 track/cluster 级的分散注入（那才需要 §7 的协议升级）。

---

### 5.5 AAC / ADTS（**移出本次范围**，实测否决，详见本节）

**核心问题：ADTS 没有魔数。** 帧头是：

```
syncword(12)=0xFFF | ID(1) | layer(2)=00 | protection_absent(1) | profile(2) |
sampling_frequency_index(4) | private(1) | channel_config(3) | ...
```

`sampling_frequency_index` 落在保留值（`0b1111`）或 `0b1101/0b1110` 时可直接排除。
但仅靠首帧的启发式检测**存在误判风险**，而本项目的原则是
"只修改明确支持的格式，追加到任意文件可能损坏它"（`router.rs:11-16` 的注释）。

**建议方案**：
- `detect` 必须**连续校验 N 帧（建议 N ≥ 16）**的头部，且所有帧的
  `sampling_frequency_index` / `channel_config` / 帧长链条自洽，把误判率压到可忽略。
- 若实测仍有误判，**改为不自动识别**，要求用户显式 `--format aac` 或 `--force`，否则放弃该格式。

### ❌ 实测否决：`eof` 方案（2026-10-19）

原计划是"只有 `eof`：追加到文件末尾，ADTS 解码器顺序扫描会忽略尾随字节"。**实测证伪。**

对裸 `.aac`（18243 B，88 帧）尾部追加不透明字节：

| 追加字节 | 文件大小 | ffprobe duration | 相对真值(2.043s) | 解码 PCM |
| --- | --- | --- | --- | --- |
| 0 | 18243 | 2.015467 | 基准 | 一致 |
| 1000 | 19243 | 2.125946 | +4.1% | 一致 |
| 4000 | 22243 | 2.457383 | +20.2% | 一致 |
| 16000 | 34243 | 3.783130 | **+85.1%** | 一致 |

**音频数据本身没坏**（PCM 逐比特一致），但 **ffprobe 报告的时长按载荷大小线性膨胀**。
根因：ADTS 解复用器拿不到帧数（`nb_frames=N/A`）时用 `文件大小 × 8 / 标称码率` 估算时长，
不透明尾字节被当成音频按码率折算，**误差与载荷大小成正比**。

**这是用户可感知的元数据损坏**，违反本项目"不改变宿主可见属性"的承诺，故否决。

### ⚠️ 可行替代：合成真实 ADTS 帧（成本上升）

把载荷放进**合成的合法 ADTS 帧**里追加（而不是当成裸字节）：

| 变体 | 文件大小 | ffprobe duration | 真值 | 偏差 |
| --- | --- | --- | --- | --- |
| 原始（88 帧） | 18243 | 2.015467 | 2.043 | -1.4% |
| +16000 不透明字节 | 34243 | 3.783130 | 2.043 | **+85.1%** |
| +80 个真实 ADTS 帧（21200 B） | 39443 | 4.357620 | 3.901 | +11.7% |

追加真实帧时，误差来源变为解复用器**固有的**码率估算偏差（原文件本就有 -1.4%），
**不再随我们的载荷线性放大**；完整解码无报错。

**代价**：需要生成合法 ADTS 帧头（采样率索引 / 声道配置 / 帧长编码）+ 承载载荷的
有效 AAC 载荷（静音 fill element 或复制真实帧），成本从 **1 人日 → 1.5~2 人日**，
且仍带上述检测启发式风险。

**决定：AAC 移出本次范围**，作为独立任务排期。若后续要做，按"合成 ADTS 帧"路线实施，
**不要**用 `eof`。

**不做帧 LSB 分散注入**——那需要 §7 的协议升级。

**顺带说明**：AAC 封装在 MP4/M4A 里**已经**由现有 MP4 适配器支持（`box_uuid`），
所以该格式的实际收益仅是"补上裸 `.aac` 文件"这一种场景。

---

## 6. 协议层兼容性总账

| 变更 | 是否改协议 | 影响 |
| --- | --- | --- |
| HEIC/HEIF 复用 `box_uuid`(3) | 否 | 完全向后兼容 |
| WEBP/WAV 用 `riff_chunk`(9) | 否（策略名不是协议字段） | 新策略占新 ID |
| MKV 用 `ebml_void`(10) | 否 | 新策略占新 ID |
| RIFF/MKV 的 strip 派生原值 | 否 | `orig_host_size` / `inject_size` 已在 header 里 |
| 删除 `router.rs` 的 `_ =>` 降级 | 否 | 只让错误变响，不改变已有 ID |
| `envelope.rs` 的 `<= 10` 改为常量 | 否 | 值随注册表增长 |
| `MAX_KNOWN_STRATEGY_ID` | 否 | 纯常量 |

**结论：本次全部改动不动 envelope 二进制布局（`HEADER_SIZE = 112` 不变），
所有已写出的载体继续可读。**

新增策略 ID 分配（只追加，永不重排）：
`9 = riff_chunk`，`10 = ebml_void`。

---

## 7. 明确不在本次范围（以及触发条件）

| 不做 | 触发条件 | 届时需要的协议升级 |
| --- | --- | --- |
| 多点补丁（ZIP64、ISO-BMFF 改 `stco`/`co64`） | 需要支持 >4 GiB ZIP，或要实现"插入 box 且保持媒体偏移" | header 扩容到 ≥128 字节，或引入 v3 版本号 |
| 多段/分散注入（WAV 采样 LSB、MKV cluster 重写、HEIF `iloc` 多 extent） | 需要**文件大小完全不变**的隐蔽信道 | `inject()` 返回值从 4 元组改为 `InjectPlan { regions: Vec<Region>, patches: Vec<Patch>, layout }` |
| 变长整数原值存储（MKV VINT 加宽需**插入字节**而非改值） | 需要支持 Segment size VINT 太窄的 MKV（实测 4/4 主流 muxer 均为 8 字节宽，罕见） | 同上，`Patch` 需支持"插入/删除"原语 |
| **AAC / 裸 ADTS** | 需要支持裸 `.aac` 文件。**注意：`eof` 路线已被实测否决**（§5.5），必须走"合成 ADTS 帧"路线，1.5~2 人日 | 不改协议，但需新的帧合成器 |
| `open_ube_reader` 改为不独占 `&mut carrier` | 需要在同一 carrier 上并发开两个流（消除 `pe.rs:394` 的整段内存读） | 内部重构，不改协议 |
| Python 端同步 | — | `python/` 已冻结，明确不做 |

`InjectPlan` 升级是**唯一需要动 envelope 二进制布局**的改动，届时应引入 `version = 0x03`
并沿用 `FLAG_COMPACT_META` 已验证过的"旧 reader 干净失败"模式（`envelope.rs:27-33` 的注释）。

---

## 8. 执行顺序

### 第 0 步：兼容性实验（0.5 人日）—— ✅ **已完成 2026-10-19**

用 `ffmpeg` / `mkvmerge` / `libheif` / `libwebp` 生成样本，实测五件事。
**完整报告见 `docs/compat_experiment_results_20261019.md`。**

| # | 实验 | 结论 |
| --- | --- | --- |
| 1 | HEIC 尾随 uuid box | ✅ 通过（libheif + ffmpeg 像素级一致 + 还原逐比特） |
| 2 | WEBP/WAV 尾随 `SHRD` chunk | ✅ 通过（含 VP8X+ALPH；4 个解码器验证） |
| 3 | MKV Segment 内 Void 元素 | ✅ 通过（含流式 unknown-size；Seek 抽帧一致） |
| 4 | AAC 尾部追加 | ❌ **`eof` 方案否决**（时长失真 +85%）→ AAC 移出范围 |
| 5 | HEIC `mdat size==0` | ✅ 不损坏，但结构不可分辨 → 保留处置建议 |

**方案的三条主路径全部成立，可以进入 Phase 0 架构整改。**
实验中额外发现两条必须写进实现的约束：
1. **`inject_size` 必须是注入区总长（含容器头）**，否则 `remove` 残留残渣（RIFF/MKV 原型都踩了）。
2. **MKV 流式录制会产生 unknown-size Segment**，该"无补丁"分支必须实现并测试覆盖。

### 第 1 步：Phase 0 架构整改（1.5 人日）

按 §4.1 → §4.5 顺序做，每小步独立提交 + 全量测试。

### 第 2 步：格式接入（6～7.5 人日，AAC 已移出）

| 序号 | 内容 | 人日 | 依赖 |
| --- | --- | --- | --- |
| 2.1 | `isobmff.rs` 抽取（纯搬家，无行为变化） | 0.5 | 第 1 步 |
| 2.2 | HEIC/HEIF adapter + `mdat size==0` 容量报告 | 1.0 | 2.1 |
| 2.3 | `riff.rs` 通用骨架 + `StrategyCapacity` 补齐 | 1.0 | 第 1 步 |
| 2.4 | WEBP adapter | 0.5 | 2.3 |
| 2.5 | WAV adapter（含 RF64 拒绝） | 0.5 | 2.3 |
| 2.6 | `ebml.rs` + MKV adapter | 2.5～3 | 第 1 步 |
| 2.7 | ~~AAC adapter~~ **已移出范围**（`eof` 实测否决） | — | — |
| 2.8 | 测试表驱动接入 + 真实样本测试 | 0.5 | 全部 |

### 第 3 步：文档同步（0.2 人日）

- `README.md` / `README.zh.md` 的载体表格
- `docs/CHANGES-20261019.md` 追加变更摘要
- `docs/smart_file_data_hiding_design.md` 补架构整改章节

---

## 9. 验收标准

每个格式必须同时满足，缺一不可：

1. `write` → `inspect` → `verify`(L1/L2/L3) → `read` → `remove` 全链路通过，
   且 `remove` 后文件 **SHA-256 与原始宿主逐比特一致**
2. 宿主格式在注入后仍被**至少 2 个独立解码器**正确解析（§8 第 0 步已验证可用的工具链：
   ffmpeg/ffprobe、libheif 1.23.4、libwebp 1.6.0、mkvtoolnix v102；
   **ImageMagick 因本地安装损坏不可用**，需修复后另行补测）
   - HEIC/HEIF 额外要求 **ffmpeg 解码出的 rawvideo 像素级 SHA-256 与原文件一致**
   - WEBP 额外要求覆盖 **VP8X + ALPH 扩展格式**（最严格的读取路径）
   - MKV 额外要求覆盖 **unknown-size Segment**（流式录制产物）与 **Seek 到任意时间点抽帧一致**
3. 进入 `matrix_lifecycle.rs` 的 `FORMATS` 表，`eof` / stealth / 无口令 / hint / 二次写入拒绝
   四类通用用例自动覆盖
4. `inspect` 报告的 `Format` 与 `strategy` 正确（HEIF 不能再报成 MP4）
5. `list-strategies` 表格无漂移（由 `ADAPTERS` 自动生成，无需手改）
6. `cargo clippy --all-targets` 0 警告，`cargo fmt` 无 diff

---

## 10. 风险登记册

| 风险 | 概率 | 影响 | 状态 / 缓解 |
| --- | --- | --- | --- |
| HEIF/WebP/MKV 解码器拒绝尾随注入 | 中 | 该格式降级为 `eof` | ✅ **已排除**（§8 第 0 步实测通过） |
| 收窄 MP4 检测导致存量 MP4 被拒 | — | 严重回归 | **采用增量方案：不改 `Mp4Adapter::detect`** |
| `strategy_id` 用满 10 | 高 | 未加密信封静默读错字段 | ⚠️ **必然发生**（9/10 都会占用），§4.2 必须先修 + 注册表一致性测试 |
| Phase 0 重构引入回归 | 中 | 6 种存量格式功能损坏 | 每个小步独立提交 + 190 项测试全绿才推进 |
| AAC 误判导致损坏任意文件 | 中 | 违反项目安全原则 | 已通过移出范围规避 |
| MKV Segment size VINT 太窄 | 低 | 该文件拒绝 `ebml_void` | ✅ 实测 4/4 主流 muxer 均为 8 字节宽，保留为防御性分支 |
| **`inject_size` 误记为载荷长度而非总长** | **高** | **`remove` 残留残渣，SHA-256 校验失败** | ⚠️ **原型已实测踩中**：必须在 `inject()` 处加注释 + 单测断言 `inject_size == 容器头 + 载荷` |
| RIFF/MKV strip 坐标换算错误 | 中 | `remove` 产出坏文件 | strip override 必须有"逐比特还原"测试用例（§9 第 1 条） |

---

## 附录 A：Phase 0 改动清单（逐文件）

| 文件 | 改动 | 行数估计 |
| --- | --- | --- |
| `adapters/mod.rs` | +3 个默认方法、+2 个类型、`SubStream` → `SegmentedSubStream` | +90 / -50 |
| `adapters/io.rs` | **新建**：`copy_exact` / `with_restored_position` / `copy_stream` | +80 |
| `adapters/png.rs` | 实现 `envelope_offset_delta`(8) / `finalize`(CRC) / `strategy_note`；用 `io` 工具 | ±60 |
| `adapters/jpeg.rs` | 实现 `trailer_anchor`(EndOfInjection) / `strategy_note`；删 87 行私有 reader | -87 / +15 |
| `adapters/mp4.rs` | 实现 `envelope_offset_delta` / `strategy_note`；eof 改委托；mdat size==0 检查 | -30 / +25 |
| `adapters/pdf.rs` | 实现 `envelope_offset_delta` / `strategy_note` | +25 |
| `adapters/zip.rs` | 实现 `strategy_note` | +10 |
| `adapters/pe.rs` | 实现 `strategy_note`；eof 改委托 | +10 |
| `engine.rs` | **删 12 处格式分派 + 抽 3 个 helper**；Level 3 改为复用已定位流 | **-150 / +40** |
| `router.rs` | `STRATEGY_REGISTRY` 单一真源；`strategy_to_id` 改 `Result` | +20 |
| `envelope.rs` | `MAX_KNOWN_STRATEGY_ID`；`:308` 改引用常量 | +5 |
| `tests/matrix_lifecycle.rs` | `FORMATS` 表驱动，11 处数组 → 1 处 | -60 / +50 |
| `tests/pe_codebits.rs` | 白名单改从 `ADAPTERS` 派生 | ±10 |

## 附录 B：新增文件清单

| 文件 | 行数估计 | 用途 |
| --- | --- | --- |
| `adapters/io.rs` | 80 | 流泵 / 位置守卫 |
| `adapters/isobmff.rs` | 200 | ISO-BMFF box 语法（从 mp4.rs 抽出 + 泛化） |
| `adapters/riff.rs` | 320 | RIFF 骨架 |
| `adapters/webp.rs` | 200 | WEBP adapter |
| `adapters/wav.rs` | 220 | WAV adapter（含 RF64） |
| `adapters/ebml.rs` | 180 | EBML VINT + 元素遍历 |
| `adapters/mkv.rs` | 400 | MKV adapter |
| `adapters/aac.rs` | 0（**已移出范围**） | ADTS `eof` 方案实测否决；若后续要做需"合成 ADTS 帧"路线（1.5~2 人日） |
| `adapters/heif.rs` | 180 | HEIC/HEIF adapter |