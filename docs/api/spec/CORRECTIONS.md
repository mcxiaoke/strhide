# 旧 WIRE_SPEC 勘误与迁移记录（2026-11-07）

本文件记录拆分 `docs/api/WIRE_SPEC*.md` 时，按**当前 `rust/src` 实现**核对出的旧描述错误。
新规范以 `docs/api/spec/` 为准；旧文档保留作历史参考，但不再维护。

- 旧 [WIRE_SPEC_CONTENT.md](../WIRE_SPEC_CONTENT.md) / [WIRE_SPEC_STRUCTURE.md](../WIRE_SPEC_STRUCTURE.md) 已加“已拆分”横幅。
- 状态列中“已修正”表示新规范已按代码写入正确描述；“记录”表示属于实现事实或限制，新规范以说明性文字收录。

## A. 内容域：密钥派生与信封

| # | 旧描述 | 实际实现 | 新位置 | 状态 |
|---|---|---|---|---|
| A1 | HEVC `session_salt` = 基础头 12B `nonce`（CONTENT:250） | `SHA-256("strhide-hevc-session-v4" ‖ nonce)`（32B）`hevc/engine.rs:452-457` | CRYPTO §1.6 | 已修正 |
| A2 | HEVC `pre_salt = cover_salt‖"hevc-v4"‖parameter_sets`，指向 `carrier_identity`（CONTENT:208） | 容器：`…‖u64be(ps_count)‖Σ(u64be(len)‖bytes)`；Annex-B：`…‖u64be(span_count)‖参数集 NAL / VCL 2B 头 + u64be(nal_len)`（`hevc/engine.rs:4272-4288`、`bitstream.rs:192-211`） | CRYPTO §1.4 / CONTENT-HEVC §7 | 已修正 |
| A3 | JPEG `pre_salt` 的 `block_count` 未定义（CONTENT:205） | component 0 的 8×8 块数（`jpeg/engine.rs:246`） | CRYPTO §1.4 | 已修正 |
| A4 | 域回落顺序“显式 > Profile > 官方默认字符串”（CONTENT:140） | 第三档为 `None`，info 只含 label（`stego/params.rs:987-989`、`format.rs:521-533`） | CRYPTO §1.2 | 已修正 |
| A5 | “salt(16B)/nonce(12B) 只存在载体头中”（CONTENT:156） | HEVC 32B 头只有 12B nonce、无 16B salt（salt 为哈希派生） | CONTENT-ENVELOPE §3.3 | 已修正 |
| A6 | “`format_id` 与部分隐含字段不存储”（CONTENT:519） | PNG/WAV/FLAC 头 offset 34 存储并校验 `1..=3`；仅 JPEG/HEVC 隐含（`stego/header.rs:190,271,306,326-330`） | CONTENT-ENVELOPE §3 | 已修正 |
| A7 | 信封 flags 未提强制校验（CONTENT:152） | 位 4..7 必须 0；未压缩时压缩算法 id 必须 0（`stego/envelope.rs:504-552`） | CONTENT-ENVELOPE §2 | 已修正 |
| A8 | 头校验只列“长度/版本/CRC/suite”（CONTENT:803） | 还要求 `format_id` 匹配、`algorithm_id` 范围、`codec_id` 0/1、音频 `channel_mode/class_rule=0`、`body_len ≥ 22`（`header.rs:326-362`） | CONTENT-ENVELOPE §3 | 已修正 |
| A9 | type 0 padding “值必须全 0 且跳过”（CONTENT:591） | 自 type 0 起必须全 0至扩展区末尾并终止，否则 `CorruptedData`（`header.rs:117-146`） | CONTENT-ENVELOPE §4.2 | 已修正 |

## B. 内容域：PRNG、置换、STC、槽位

| # | 旧描述 | 实际实现 | 新位置 | 状态 |
|---|---|---|---|---|
| B1 | STC 列向量 `splitmix64(seed XOR idx)`（CONTENT:484） | `splitmix64(seed.wrapping_add(idx))`（`coding/stc.rs:355`） | CONTENT-ENVELOPE §7.2 | 已修正 |
| B2 | ChaCha 参考向量首 16 字节写成 `12 05 6e 59 5d 56 b0 f6 …`、种子说明“首字节 1”但示例写成 `00 01…`（CONTENT:290-300） | 正确首行 `12 05 6e 59 d5 65 05 6b ef 0e 0f 09 df 5c 22 9a`；种子= `01 00…00`（`prng.rs:301-327`） | CONTENT-ENVELOPE §6.1 | 已修正 |
| B3 | 正文槽位统一“先取 N 候选再置换，禁止整池置换后取前 N”（CONTENT:384） | 逐载体不同：PNG 先取 N 后 `permute_indices`；JPEG 对全 BodyGrid `permute_prefix` 后截断；音频用整体/正文池 `KeyedPermutation` | CONTENT-ENVELOPE §5、各载体文档 | 已修正 |
| B4 | FLAC 正文置换用 L3 `perm_seed`（CONTENT:459） | 用 L2 `locate_seed`；`perm_seed` 只作方向盐（`audio/core.rs:224-253,831-855`） | CONTENT-AUDIO §4.4 | 已修正 |
| B5 | FLAC 容量按 `total_slots-(512+8*ext_len)`（CONTENT:615） | 扩展槽不挤占正文残差池；容量按 `total_usable+512`（`flac/mod.rs:886-892`） | CAPACITY §2.4 | 已修正 |
| B6 | WAV “槽 = 一个 PCM 采样”（CONTENT:433） | 每个声道分量独立成槽（16/24-bit 各分量） | CONTENT-AUDIO §3 | 已修正 |
| B7 | 音频只支持 16/24-bit（CONTENT:813） | WAV 8/16/24/32-bit；FLAC 4..=24-bit | CONTENT-AUDIO §1 | 已修正 |
| B8 | HEVC 正文参数固定 `h=7,u=2`，头 `stc_u` 冗余（CONTENT:420,869） | 读侧以头内 `stc_u` 构造 trellis（`hevc/engine.rs:2249`）；`stc_h` 才来自 profile | CONTENT-HEVC §6 | 已修正 |
| B9 | HEVC 分带按“不可预测标记”（CONTENT:424） | 按 `nal_unit_type` + `has_inter`；IRAP/RASL 不承载槽位（`hevc/engine.rs:4109-4119`） | CONTENT-HEVC §4 | 已修正 |
| B10 | HEVC 槽位统一按解码顺序编号 | 头部池是原始解码序前缀；正文池按 band0+band1 重编号（`band.start`） | CONTENT-HEVC §3-4 | 已修正 |
| B11 | `max_payload = message_bits/8-22`，漏 `u`（CONTENT:611） | `m = n/u-(h-1)`（`coding/stc.rs:390-392`） | CAPACITY §1 | 已修正 |
| B12 | 工作内存预算只列 PNG 8 GiB（CONTENT:627） | JPEG 同 8 GiB；WAV/FLAC 768 MiB（`jpeg/engine.rs:100`、`audio/core.rs:69`） | CAPACITY §2.6 | 已修正 |
| B13 | 长视频“前 20% 窗口加权估算”（CONTENT:631） | 对可选 picture 抽 20% 样本并 `clamp(150,1000)`；≤150 时全量（`hevc/engine.rs:727-735`） | CAPACITY §2.7 | 已修正 |

## C. 内容域：代价模型与 detmath

| # | 旧描述 | 实际实现 | 新位置 | 状态 |
|---|---|---|---|---|
| C1 | 灰度化直接 `0.299R+…`（CONTENT:656） | 三个通道先 `& 0xF8` 再加权（`png/cost/hill.rs:68-71` 等） | CONTENT-PNG §5 | 已修正 |
| C2 | `val mod 8 ∈[1,6]` 无条件（CONTENT:398） | 读侧按头 `class_rule`，仅 `=1` 执行；写侧恒 1（`png/engine.rs:1359,1721,2141`） | CONTENT-PNG §3 | 已修正 |
| C3 | `sigma` 只用于 S-UNIWARD（CONTENT:684） | MiPOD 时同字段承载 `alpha`，写侧钳 `[0.01,0.90]`、缺省 `0.20f32`（`png/engine.rs:1678-1691,2069-2077`） | CONTENT-PNG §2/§7 | 已修正 |
| C4 | 正文槽数用 `slots_for`，忽略 `codec_id`（CONTENT:400） | `slots_for_codec(...)`，Hamming/STC 槽数不同（`png/engine.rs:1577,2117-2122`） | CONTENT-PNG §3 | 已修正 |
| C5 | “`u=1` 与 Hamming 不吃代价”（CONTENT:743） | 候选集仍由代价排序/截断产生；只是 trellis 不消费方向代价 | CONTENT-PNG §8 | 已修正 |
| C6 | 管线依赖 libm `cos/exp/ln`（CONTENT:723），与 §13.11.5 自相矛盾 | 全部走 `stego::detmath`（`cost_calibration.rs:163-174,216`） | DETMATH §1 | 已修正 |
| C7 | `ln` 级数到 `z^10/21`（CONTENT:757） | 到 `z^11/23`（`detmath.rs:197-207`） | DETMATH §4 | 已修正 |
| C8 | `ln_1p` 约 1 ulp（CONTENT:758） | 审计实测语料最大 6.91 ulp、密集样本 16.6360 ulp | DETMATH §5 | 已修正 |
| C9 | “四组摘要”（CONTENT:785） | 实际五项：`exp/ln/cos/ln_1p/log2`（`detmath.rs:415-421`） | DETMATH §9 | 已修正 |
| C10 | Python/Go 只移植四函数（CONTENT:984） | 两脚本均含 `log2` 摘要 | DETMATH §9 | 已修正 |
| C11 | 三平台全部逐位一致（CONTENT:765,785） | 审计：52,153 条中 20 条不一致；Go 开 FMA 后大量不一致 | DETMATH §9 | 已修正 |
| C12 | JPEG 头槽固定 718（CONTENT:413） | `header_slots(ext_len)=718+4*(8*ext_len+7)`；`ext_len=0` 时仍 746（`jpeg/engine.rs:833`、`format.rs:156-169`） | CONTENT-JPEG §3 | 已修正 |
| C13 | JPEG 块按“分量内光栅顺序” | `dct_io` 返回 MCU 交织序（4:2:0 下索引 2 在 1 下方） | CONTENT-JPEG §3 | 已修正 |
| C14 | JPEG 有 `exclusion_permille` 排序截断 | JPEG 44B 头无该字段，代价只进 trellis 边权 | CONTENT-JPEG §4 | 已修正 |
| C15 | J-MiPOD 与空间 MiPOD 参数相同 | JPEG 为 `p=3/l=3`、`floor=1e-6`、不做 7×7 FI 平滑（`jmipod.rs:30-34`） | CONTENT-JPEG §7 | 已修正 |
| C16 | 内容域支持“原 JPEG 字节级恢复” | 结构域才支持 restore；JPEG 熵编码扫描段会重写（`dct-io`） | CONTENT-JPEG §9 | 已修正 |

## D. 结构域：UBE 信封

| # | 旧描述 | 实际实现 | 新位置 | 状态 |
|---|---|---|---|---|
| D1 | header 校验只列版本/长度/位移（STRUCT:125-132） | 另要求 `strategy_id` 已注册、`inject_size` 形状、`patch_offset+4≤host_len`（`envelope.rs:294-346`） | STRUCTURE-ENVELOPE §3.2 | 已修正 |
| D2 | 追加型策略必须 `ube_offset+size == 文件长度`（STRUCT:154） | `confine_location` 只要求 `<=`；`locate_start` 允许整体平移（`engine.rs:191-207,870-879`） | STRUCTURE-ENVELOPE §12 | 已修正 |
| D3 | 保留位必须为 0 由 `validate_against` 校验（STRUCT:176） | 只由裸头识别门槛检查 `flags & !0x3F`（`envelope.rs:675-689`） | STRUCTURE-ENVELOPE §4 | 已修正 |
| D4 | 读侧“三层识别”（STRUCT:404） | 实际四层，且裸加密头在默认去掩码前判断（`envelope.rs:615-648`） | STRUCTURE-ENVELOPE §11 | 已修正 |
| D5 | 默认去掩码层要求 `version=0x02`（STRUCT:409） | 该层不校验 version；`strategy_id` 要求 `1..=13`（`envelope.rs:622-648`） | STRUCTURE-ENVELOPE §11 | 已修正 |
| D6 | 单块上限 `min(剩余, MAX_CHUNK_SIZE)`（STRUCT:301） | `MIN(剩余, MAX_CHUNK_SIZE+16)`（chunk_len 含 tag）（`crypto.rs:581-588`） | STRUCTURE-ENVELOPE §8 | 已修正 |
| D7 | trailer 不合法一律“无信封”（STRUCT:318） | 魔数匹配但 CRC 错返回 `CorruptedData`（`envelope.rs:844-858`） | STRUCTURE-ENVELOPE §9 | 已修正 |
| D8 | `MIN_UBE_PLAIN=178` / `MIN_UBE_ENCRYPTED=214`（STRUCT:502） | 常量不存在；`min_ube_len(0)=213`、`min_ube_len(1)=214`（`envelope.rs:116-132`） | STRUCTURE-ENVELOPE §2 | 已修正 |
| D9 | stealth 头部掩码 HKDF 未写 salt（STRUCT:379-381） | `HKDF-SHA256(salt=Some(信封 salt), ikm=PBKDF2(...))`（`crypto.rs:305-312`） | CRYPTO §2.4 | 已修正 |
| D10 | 散落策略以 `inject_size==0` 跳过坐标校验（STRUCT:146） | 要求调用方策略名与 header `strategy_id` 同时为 `pe_codebits`（`engine.rs:2835-2850`） | STRUCTURE-ENVELOPE §12 | 已修正 |
| D11 | hint 读侧未说明 | 只按 `hint_len` 读取，不校验 `FLAG_HAS_HINT`（`engine.rs:1836-1844`） | STRUCTURE-ENVELOPE §6 | 已修正 |
| D12 | compact meta 未列强制校验 | `version=0x01`、文件名合法 UTF-8、截断/越界立即报错（`engine.rs:302-330`） | STRUCTURE-ENVELOPE §7 | 已修正 |

## E. 结构域：适配器

| # | 旧描述 | 实际实现 | 新位置 | 状态 |
|---|---|---|---|---|
| E1 | PNG 注入块位移漏列 | `prIv` 块头 8B；`inject_size=8+ube+4`（含 CRC）（`png.rs:189-214`） | STRUCTURE-PNG §4-5 | 已修正 |
| E2 | JPEG 结构域用 COM 段（design 文档） | 固定 APP15；COM 不参与注入/定位（`jpeg.rs:14-15,530-551`） | STRUCTURE-JPEG §5 | 已修正 |
| E3 | JPEG 单段 65,535 / 256 KiB 必退 eof | 单段载荷 65,533；多段链可远超 256 KiB；容量受 16 MiB 扫描窗口与 SOS 约束 | STRUCTURE-JPEG §6 | 已修正 |
| E4 | RIFF `offset_delta` 漏列 | 8B `SHRD` 块头（`wav.rs:100-104`、`webp.rs:118-122`） | STRUCTURE-RIFF §4 | 已修正 |
| E5 | RIFF 容量“4GB 上限”表述 | 实际受 `R+8+N+(N&1) ≤ u32::MAX` 约束（`riff.rs:126-133`） | STRUCTURE-RIFF §6 | 已修正 |
| E6 | ISO-BMFF 注入位置“moov 后 / mdat 前” | 实际写入文件 EOF；`item_hidden` 用第二个 `mdat`（`isobmff.rs:85-88,1183-1192`） | STRUCTURE-ISOBMFF §4 | 已修正 |
| E7 | HEIF item 有 mime/hidden 标志 | 只写 `infe` v2/v3、`item_type="resv"`、空名、protection_index 0（`isobmff.rs:961-984`） | STRUCTURE-ISOBMFF §4 | 已修正 |
| E8 | ZIP 默认 `pre_cd_inject`，空档案/ ZIP64/缺 EOCD 退 eof | 还包含 `cd_offset==0`、ZIP64 locator、32 位溢出（`zip.rs:145-171`）；ZIP64 只探测 locator，不解析 EOCD64 | STRUCTURE-ZIP §3-5 | 已修正 |
| E9 | PDF 增量段固定写经典 `xref`/`trailer` | XRef 流方言写 `/Type /XRef` 流对象（`pdf.rs:787-830`） | STRUCTURE-PDF §4 | 已修正 |
| E10 | PDF `offset_delta` 未列 | `46 + digits(N) + digits(L)`；最大值 66 > `MAX_OFFSET_DELTA=64`，此时 auto 退 `eof`（`pdf.rs:589-591,697-705`） | STRUCTURE-PDF §4 | 已修正 |
| E11 | PE codebits 含 ModR/M 内存/SIB 变换 | 仅 `mod=11` 寄存器-寄存器语义对与 TEST 操作数交换（`pe_codebits.rs:239-243`） | STRUCTURE-PE §5.1 | 已修正 |
| E12 | `pe_slack` 属散落策略、经 ChannelHeader | 连续覆盖写入 padding，无 ChannelHeader/diff（`pe_slack.rs:52-92`） | STRUCTURE-PE §6 | 已修正 |
| E13 | PE 还原 diff 为“紧凑二进制列表” | 无头定长稠密位图，长度 `14+ube_len`、MSB-first（`pe_codebits.rs:344-350,446-448`） | STRUCTURE-PE §5.3 | 已修正 |
| E14 | MKV 插入 SeekHead 后、更新 Segment 大小 | 固定写物理 EOF，新建顶层 Void，不更新 Segment/SeekHead/Cues（`mkv.rs:79-99`） | STRUCTURE-MKV §4 | 已修正 |
| E15 | EBML Void VINT 最多 9 字节 | 实际 1B Void ID + 最多 8B VINT，`offset_delta ≤ 9`（`ebml.rs:28-36`、`mkv.rs:292-306`） | STRUCTURE-MKV §4 | 已修正 |
| E16 | auto “放不下时透明回退 eof” | 多个适配器无回退：MP4 恒 `box_uuid`，HEIF `item_hidden→box_uuid`，PNG 仅超 2 GiB−1 退 eof | STRUCTURE-ISOBMFF §3、STRUCTURE-PNG §3 | 已修正 |

## F. 记录但不修改的范围外问题

以下问题属于实现一致性/健壮性，不在本次“文档拆分”范围内，仅记录供后续处理：

1. ~~`riff.rs` 容量表在接近 4 GiB 时可能报 `available=true`，但实际注入会因 RIFF 大小溢出失败（E5 相关）。~~
   **已修复（2026-11-08）**：`riff_strategy_capacities` 现在用 `riff_chunk_headroom()` 计算
   `capacity_bytes = u32::MAX - declared_size - 8`，headroom 为 0 时置 `available=false`，
   与 `riff_inject` 的实际上限一致（`tests/test_regression/review_20261025.rs::riff_chunk_capacity_reports_the_u32_headroom`）。
2. ~~`webp.rs` 静态容量表对 Simple Format 仍报 `riff_chunk` 可用；`engine.rs` 的 `apply_engine_payload_limit` 不检查 `available`。~~
   **已修复（2026-11-08）**：`reader = None` 时 note 明确标注 “Extended Format (VP8X) only”；
   `apply_engine_payload_limit` 跳过 `available = false` 的条目，不再为不可用策略填入引擎上限
   （`webp_static_capacity_table_marks_the_extended_format_requirement`）。
3. `CAPACITY.md`/`ARCHITECTURE.md` 中若干 auto 策略描述与适配器实际无回退行为不符（E16）。
4. `detmath.rs:320,352` 注释引用不存在的 `scripts/detmath/compare.sh`。
5. `mkv.rs:113-117` 注释提到 `ebml_void` 可平移，但引擎只允许 `chunk`/`eof` 平移。
6. `pe.rs:741-744` 注释提到 legacy `STH!`/`STHC`，实现不接受。
