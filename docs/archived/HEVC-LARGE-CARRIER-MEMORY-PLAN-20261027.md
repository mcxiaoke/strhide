# HEVC 大载体内存与流式化方案

- 日期：2026-10-27
- 触发问题：`strhide embed --capacity big.mp4 --exact` 在 24 分钟 1080p 载体上占用 20+ GB、数分钟不结束；
  同尺寸载荷的真实 `embed` 内存需求更高，32 GB 机器必然 OOM。
- 结论：三条主路径（probe / extract / embed）的内存都是 **O(像素数)**，必须先改内存模型，再谈速度。
  速度本身不是瓶颈（单线程 ~230 fps，24 分钟片子 3–5 分钟），**卡住的是换页抖动**。
- 进展：probe 与 extract 已改为「按需捕获」，24 分钟片的精确扫描 168.7 s / 0.59 GB；embed 仍待窗口化。

---

## 1. 实测数据

release 0.7.2 / 3d8cdbb，本机 32 GB 物理内存。测试载体由 `temp/bighevc/anime-b.mp4` 用 ffmpeg `-c copy` 截取，
产物在 `temp/probe/`。

| 载体 | 大小 | 帧数 | 槽位数 | capacity --exact | embed（4 KB 载荷） | extract |
|---|---|---|---|---|---|---|
| clip60.mp4 | 10.7 MB | 1493 | 8,113,426 | 5.4 s / **0.45 GB** | 5.9 s / **0.69 GB** | — |
| clip120.mp4 | 29.5 MB | 2919 | 24,775,207 | 12.5 s / **1.22 GB** | 15.1 s / **2.12 GB** | 12.7 s / **1.22 GB** |
| anime-b.mp4（外推） | 554.8 MB | ~34460 | 570,563,786 | ~5 min / **18–34 GB** | ~6 min/遍 / **40–55 GB** | **18–34 GB** |

按槽位归一化：probe ≈ 49 B/槽位，embed ≈ 86 B/槽位，extract ≈ 49 B/槽位。
吞吐：probe 233 fps、embed 193 fps（1080p24，本机单线程）。

> 说明：`anime-b.mp4` 的槽位密度（397k 槽位/秒）比测试切片（206k 槽位/秒）高约 2 倍，外推以槽位数为基准而非时长。

**改动后（P0 + P1 已落地，2026-10-27）**

| 载体 | 操作 | 改前 | 改后 |
|---|---|---|---|
| clip120.mp4 | `--capacity --exact` | 12.5 s / 1.22 GB | 11.4 s / **0.093 GB** |
| clip120.mp4 | `extract` | 12.7 s / 1.22 GB | 11.3 s / **0.094 GB** |
| anime-b.mp4（1437 s） | `--capacity --exact` | **20+ GB，不结束** | **168.7 s / 0.592 GB** |

精确值 559,362,333 槽位 / 34,960,104 B 最大载荷；采样估算当时报的是 570,563,786 / 35,660,194 B，**高报约 2%**。
`embed` 未改，仍是 40 GB 量级，见第 6 节 P2/P3。

---

## 2. 内存模型：为什么必然爆

`record_carrier_state` 一次调用同时物化三份与「像素数 × 帧数」成正比的数据：

| 数据 | 结构 | 单条大小 | 谁需要 | 位置 |
|---|---|---|---|---|
| 槽位池 | `Vec<StegoSlot>` | **32 B** | probe / extract / embed | `slot.rs:142` |
| CABAC bin 日志 | `Vec<BinOp>` | **2 B** | 仅 embed | `slot.rs:219` |
| 原始 RBSP | `Vec<u8>` / 片 | ≈ 码流大小 | 仅 embed | `engine.rs:1722` |

实测比例：**1 个槽位 ≈ 18 条 bin**（120 s 切片：embed 比 probe 多 0.90 GB，减去 1.19 B/槽位的 RBSP，
剩 ≈ 35.8 B/槽位 ÷ 2 B ≈ 17.9 bin/槽位）。

对 `anime-b.mp4`（5.7056 亿槽位）：

- 槽位池：`570,563,786 × 32 B = 18.26 GB`；`Vec` 倍增后容量落到 `2^30 = 1,073,741,824`，即 **34.37 GB**。
  这单独一项就超过 32 GB 物理内存 → 分配失败或整机换页，表现就是「20 多 G、几分钟不动」。
- bin 日志：`5.7e8 × 18 × 2 B ≈ 20.5 GB`。
- RBSP + candidates 副本：≈ 1.1 GB。
- 合计 embed ≈ **40 GB（按实际长度）/ 55 GB（按容量倍增）**。

另有两处与载体大小成正比的固定开销（与本次问题同源，一并列出）：

- CLI 用 `std::fs::read` 整体读入载体（`cli/cmd_stego.rs:44`、`:220`、`:433`）；
- `embed` 再 `carrier.to_vec()` 生成输出缓冲（`engine.rs:678`），等于 **2× 文件大小**。
  555 MB 尚可，4K/2 小时素材（10 GB+）仅此一项就是 20 GB。

---

## 3. 为什么不能换 ffmpeg / 硬件解码

这套算法需要 **逐 bin 的 CABAC 轨迹**：每个 bin 的 context 索引、bypass 符号位位置、以及在改动后
**重新编码**同长度码流的能力。三个事实决定这条路不成立：

1. libavcodec 不导出 CABAC bin 序列（只有像素输出），DXVA / D3D11VA / NVDEC 硬解更只有帧缓冲。
2. 现有解码器已 `ablate` 掉运动补偿、帧内预测、残差反变换与重建
   （`rusty_h265/src/ctu.rs:173`，注释明写 "parse coefficients, skip scaling / inverse transform / residual add"），
   是 **纯语法解析**，比 ffmpeg 软解还轻。换 ffmpeg 只会更慢，且拿不到 bin。
3. 重编码必须与原始码流 byte-aligned 等长（信封承诺格式与时长的无损性），任何通用编码器都做不到。

结论：ffmpeg 只可能用于「独立交叉校验容量估算」这类外围工作，不进入 embed / extract 主路径。

---

## 4. 方案清单

按「改动风险 × 收益」排序。A/B/C 不改变产物格式；D 改变格式（项目已声明不需要兼容旧版本文件）。

### A. 容量探测只计数（`RecordMode::Count`）

**做法（已实现）**
- `record_carrier_state` 增加 `Capture` 级别：`Count` / `Bits` / `Full`。`absorb_recorder` 按级别决定
  是否把槽位推进池、是否只记一个 sign bit、还是只累加计数。
- `Count` 级别还跳过 `SliceContext` 的构造（`orig_rbsp` / `ops` / `substreams` 全部不建），
  只保留 per-band 计数、`pictures`、`band_pictures` 与 `digest_inputs`。
- `probe_hevc_pool` 的精确分支、`probe_hevc_capacity`、`verify` 全部走 `Count`。

**实测**（120 s 切片）：**1.22 GB → 0.093 GB**，12.5 s → 11.4 s，槽位数 24,775,207 与改前逐位相同。
内存里剩下的 93 MB 是载体本身、candidate 副本与解码器状态，与槽位无关。

**代价 / 风险**：低。EPB 排除逻辑仍在 `absorb_recorder` 内（`engine.rs:256`），计数口径与 embed 同源。

**验证**：`baseline_hash.py --check` 全绿；probe 槽位数字与改前完全一致（已对 60 s / 120 s 两例核对）。

### B. extract 单遍位池（已实现，取代原「两遍解码」写法）

**关键观察**：extract 只用 `all_slots[p].original_bit`（`engine.rs:1205`、`:1261`）与 band 长度，
**从不读 cost / qp / op_idx**。所以一个槽位只需要 1 bit，不是 32 B。

**做法**：`Capture::Bits` 下按 band 各记一条 LSB-first 位向量（`BitPacker`），解码单遍完成；
池序 = band0 ‖ band1，正好等于原来的稳定分区结果，因此**不需要排序，也不需要 `slot_idx` 重映射**。
`CarrierRecord::slot_bit(p)` 按 band 区间直接寻址。

**实测**（120 s 切片）：**1.22 GB → 0.094 GB**，12.7 s → 11.3 s，恢复出的 4096 字节 sha256 与改前相同
（`c8f5d0341d54d951…`，且是用旧版产物做输入，跨版本也一致）。

**代价**：内存 total_slots/8（24 分钟片 71 MB），**没有第二遍解码，耗时不变**。
**风险**：位序必须与池序严格对应 → 用「单遍 Full 记录」与「Bits 记录」逐位比对的单元测试守住。

### C. embed 只物化被选中的槽位（产物逐字节不变）

**做法**：embed 读 `all_slots[pos]` 的位置只有 `positions`（`engine.rs:687`）与 `forbidden` 标定，
因此可以：
1. 第一遍计数（同 A）；
2. 算出 `positions`，转成位图；
3. 第二遍解码时只保留命中位置槽位的 `(original_bit, cost, op_idx, slice_idx, substream_idx)`（约 16 B/条），
   并只保留**命中 slice** 的 ops / orig_rbsp；
4. 第三遍（或第二遍末尾的 touched slice 集合）重写命中 slice。

**收益**：内存 O(K)。3.4 MB 载荷 ≈ 0.9 GB；35 MB 载荷仍会退化到 9 GB（K = 全池）。
**代价**：2–3 遍解码；`MAX_EMBED_ROUNDS` 每轮都要重放，需确认重放只涉及已保留的 slice。
**风险**：多遍解码的一致性。旧实现靠「把 bin 序列留在内存里回放」，新实现靠「用相同 ablate 参数重放解码器」。
必须在第二、三遍之间校验 bin 序列指纹（可复用 `digest_inputs` 的做法），不一致就报错而不是静默写坏。

### D. 窗口化：按载荷截断 / 分块（推荐方向，见第 5 节）

**收益**：内存 O(窗口) 且与视频时长解耦；extract 只扫到载荷终点；窗口间可并行。
**代价**：格式变更（信封 vN）+ 头部定位改造。

### E. 辅助项

1. **槽位瘦身**：`StegoSlot` 32 B → 12 B（`cost: f64` 量化 `u16`、`qp/trafo/坐标` 打包、去掉可推导的 `slice_idx`）。
   probe 34 GB → 13 GB。单用不够，配合 A/C 才有意义。
2. **并行解码**：片内 WPP/tile 子流（recorder 已有 `substreams` 边界与 `init_contexts`）或窗口间并行。
   当前 HEVC 路径完全单线程，rayon pool 只是包了一层 `with_pool`（`stego/engine.rs:125`）。
3. **载体 mmap**：把 `fs::read` + `to_vec()` 换成只读 mmap + 输出流式写，消除 2× 文件大小的固定开销。

---

## 5. 「按 payload 截断 + 结束标志」可行性评审

用户提案：embed 应按载荷需要决定扫描多少帧，够用即停，几小时的片子后半段完全不碰；
extract 无法这样做，需要一个载荷结束标志。

### 5.1 提案成立，但有一个循环依赖必须先解开

现在的槽位选择是 `band_positions(&bands, count)`：band 区间 = **整个载体**的槽位计数。
只要沿用「全池置换」，embed 想提前停就必须先知道全池计数，而知道全池计数又必须扫完全片 —— 提案失效。

反过来，extract 要定位头部，也要先知道 band 区间，于是**头部位置依赖全片计数**，这形成了第二个循环。

破局点：把「定位头部」与「选择载荷槽位」拆成两件事，头部放在**位置与全片计数无关**的地方。

### 5.2 prelude（定位区）设计

- **位置**：片头第一张 **非参考图片**（band 0）的前 `H` 个槽位，`H = trellis.slots_for(header_bytes×8)`，
  `header_bytes = 40`（`stego/format.rs:223`）→ 约 640 槽位，单张图（~1.6 万槽位）绰绰有余。
- **为什么可定位**：band 由 `nal_type` 决定（`picture_band`），`has_inter` 只需扫 NAL 类型 —— 都是**免 CABAC** 的
  线性扫描，几十毫秒。extract 只解码这一张图即可拿到头部。
- **边界**：若首张 band-0 图可吸收槽位不足 `H`（极低码率/静止画面），顺延到下一张 band-0 图；规则固定即可两端一致。
- **头部新增字段**：`window_pictures`（或 `window_band_slots[2]`）、`window_end_offset`，以及格式版本号。

### 5.3 两种粒度

**V1 单窗口前缀（最小改动）**
- embed 顺序解码，累计槽位直到 ≥ `needed_slots`，即停；窗口 = `[0, N]` 张图。
- 载荷仍是一次 STC，`band_positions` 的输入换成**窗口内**的 band 计数。
- extract：prelude → 头部拿到 `N` → 只扫到 `N` → 内存 O(K)、时间 O(载荷)。
- 单遍解码即可完成 embed（扫到就停，再解 solve）。
- 局限：载荷大到窗口 = 全片时退化回现状（40 GB）。需要「窗口上限 + 拒绝」兜底。

**V2 分块窗口（真正可扩展）**
- 窗口 = 固定图数（如 100 张）或固定槽位预算；每窗独立 STC，各自携带消息分片；
  每窗自带小头（seq / chunk_bits / last 标志 / CRC）。
- 内存 O(窗口) 与载荷大小无关；窗口间天然可并行（8 核接近 8×）。
- 代价：每窗 header 与 trellis 预热开销（几十 KB 级）；格式比 V1 复杂。

### 5.4 结束标志到底要不要

- **有 prelude + 头部声明 `N`**：extract 天然知道终点，**不需要**结束标志。
- 结束标志（每窗 sentinel + CRC）的价值在别处：① 检测截断/损坏时能定位到哪一窗；② V2 的无头部流式探测；
  ③ 允许 extract 在「头部损坏」时仍能逐窗试探。建议 V2 保留，V1 不需要。
- 注意：结束标志**省不了扫描时间**（要扫到标志处才能停），它只把内存变成 O(1)。
  真正的省时收益来自「头部先告诉终点」。

### 5.5 必须先解决的边界条件

1. **Annex-B 的封面摘要依赖全片**：`compute_hevc_cover_digest` 会哈希**所有** VCL span 的头两字节与 `nal_len`
   （`stego/hevc/bitstream.rs`）。若 extract 只扫窗口，摘要算错 → 密钥错 → 解密失败。
   处理：Annex-B 路径必须做一次**全片 NAL span 扫描**（不解 CABAC，代价小），MP4/HEIF 只依赖参数集，不受影响。
2. **band 语义**：`has_inter` 是全局属性（`candidates.iter().any(|c| !is_irap(...))`），窗口内必须用全片的判定，
   否则同一份码流在两端得到不同 band。
3. **截断即失效**：载荷集中在片头窗口，用户裁掉前 N 帧或转码，载荷必然丢失。这是产品语义，需写进 CLI 帮助与文档。
4. **安全档位口径**：`build_hevc_capacity_info` 的视频预算按「每参考图的翻转数 + 非参考带比例」计算，
   窗口化后要在窗口内重算，并保证 `recommended_max` 不小于实际写入量。
5. **载体整体读入内存**（2× 文件大小）与窗口化是两件事，4K/长片要一起改（见 E.3）。
6. **检测面变化**：改动从「均匀散布全片」变为「集中在片头 N 秒」。窗口内仍是 Weyl 置换散布、仍优先非参考图，
   但若检测方按时间轴切片统计，片头的修改密度会明显高于片尾。需要在 `hevc_steganalysis_and_quality_spec`
   口径下重跑一次统计检测评估，或者在窗口够用时按「均分到 M 个分散窗口」而不是「连续前缀」来缓解。

---

## 6. 推荐路线

**硬约束（产品决定）**：不允许用「多解一遍」换内存。省内存的方案必须同时做到时间不变或更短；
做不到就不做。下面每一阶段都按这条验收。

| 阶段 | 内容 | 解决 | 效果 | 状态 |
|---|---|---|---|---|
| P0 | A：probe / verify 只计数 | `--capacity --exact` 崩内存 | 34 GB → 载体本身的量级，时间不变 | **已完成** |
| P1 | B：extract 单遍位池 | 「写得进读不出」 | 18 GB → 71 MB，时间不变 | **已完成** |
| P2 | 流式化基础：mmap 输入 + 增量写出 | 2× 文件大小的固定开销 | 多 GB 载体不再整份驻留 | 待做 |
| P3 | 窗口化 embed（D-V1 / V2） | embed 的 40 GB | 内存 O(窗口)，时间随载荷而不是随片长 | 待做 |
| P4 | 并行（窗口间 / WPP 子流） | 速度 | 233 fps → 1000+ fps | 待做 |
| P5 | 槽位瘦身（E.1） | P3 落地前的过渡手段 | 32 B → 12 B | 视 P3 情况 |

顺序上的两个要点：

1. **P2 先于 P3**：窗口化要按 span 顺序写回，如果仍用 `carrier.to_vec()` 的整份输出缓冲，
   窗口只省了中间的槽位数组，省不下输出副本。
2. **P3 的第二遍（如果有）必须被窗口界定**：窗口化之后「重解一遍」的成本是 `O(窗口)` 而不是
   `O(片长)`，这时多一遍才不再是数倍代价。这也是为什么 P1 没有做「两遍解码」版本。

P3 之后 `--exact` 的语义要重新定义：全片精确 = A（只计数），窗口精确 = 新增 `--capacity --window N`。

## 7. 验收

- `cargo test --all-features --all-targets` 全绿；`cargo clippy --all-targets --all-features -- -D warnings` 无告警。
- `python scripts/baseline_hash.py --check` 逐例全绿（P0/P1 必须零字节差异；P2 起格式变更需 `--write` 重建基线，
  并在文档记录新旧基线的对应关系）。
- 新增回归：① `Capture::Bits` 的位序与 `Capture::Full` 的 `all_slots[p].original_bit` 逐位相同；
  ② 窗口化 embed 后 `extract`/`verify` 通过且 `restore` 后 sha256 不变；
  ③ 对 60/120 s 切片断言峰值 RSS 上限（`GetProcess.PeakWorkingSet64` 的测试脚本）。
- 长片实测：24 min / 1080p（`temp/bighevc/`，gitignored）记录 embed 与 extract 的时间、峰值内存，写入本文档。
