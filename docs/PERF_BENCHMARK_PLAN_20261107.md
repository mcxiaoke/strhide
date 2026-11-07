# strhide 发布基准性能测试方案（内容域 / 结构域）

> 版本冻结期基线测量方案。目标是为 v0.9.2 发布提供可复现、可审计的性能基线数据，
> 并明确"哪些数字代表哪条代码路径"，避免把 KDF 固定开销或文件 I/O 误读成引擎开销。
>
> 状态：**实施完成**（2026-11-07 16:15）。方案与实测有出入处已在 §5 / §10 标注；
> 产物：[结构域报告](./BENCH_STRUCTURE_20261107.md) / [内容域报告](./BENCH_CONTENT_20261107.md)。
> 制定时间：2026-11-07 14:40 (GMT+8)
> 适用版本：`rust/` crate `strhide 0.9.2`（算法与公开 API 已冻结）

---

## 1. 目标

1. 给出**结构域**（容器信封注入）与**内容域**（多媒体隐写）各自独立的写入 / 读取耗时基线。
2. 覆盖发布文档需要的载荷档位：
   - 结构域：`4 KiB`、`64 KiB`、`256 KiB`、`1 MiB`、`4 MiB`
   - 内容域：`1 KiB`、`8 KiB`、`32 KiB`、`128 KiB`
3. 数据必须可复现：固定密码、固定内容域名、固定 32 字节 seed、固定载荷字节流。
4. 每格样本量 20 次，给出均值 / 中位数 / P95 / 标准差 / 变异系数，并对高方差格执行
   去极值（去掉一个最大值与一个最小值）后的截尾均值。
5. 结果落成两份独立报告（`docs/` 下 Markdown），原始样本落 JSON，便于发布前后回归对比。

**不在范围内**：GUI 端耗时、并发吞吐（多任务并行）、跨机器横向对比、隐写安全性
（可检测性）评估、容量极限测量（已有 `sth capacity`，本方案只做"该载荷是否放得下"的前置校验）。

---

## 2. 被测对象与调用路径

只用**库的内存 API**，不经 CLI、不经文件系统：

| 域 | 写入 | 读取 | 备注 |
|---|---|---|---|
| 结构域 | `structure::write_carrier_bytes(cover, PayloadSource::Bytes, &WriteOptions, &LocalParams::default(), &StructureProfile::default())` | `structure::read_carrier_bytes(&stego, Some(pw), &StructureProfile::default())` | 额外校验 `remove_carrier_bytes` 逐字节还原（仅首轮，不计时） |
| 内容域 | `stego::embed_carrier(&cover, &Payload::bytes(payload), &EmbedOptions)` | `stego::extract_carrier(&stego, &ExtractOptions)` | 写侧 `Freshness::Seeded(固定 seed)`，读侧只需密码 |

为什么用内存 API：

- 两端都走与 CLI 完全相同的引擎、AEAD、信封代码路径，只是不落盘；
- 排除 NTFS 缓存抖动、杀软扫描、磁盘调度造成的非线性噪声（4 MiB 载荷落盘时尤甚）；
- 文件 API 的 I/O 成本单独在 §7.3 用一组对照实验量化，不混进主表。

构建方式固定为：

```bash
cd rust
cargo build --release --all-features --example perf_bench
```

`--release` 展开为 `opt-level=3`、`lto=true`、`codegen-units=1`、`panic=abort`、`strip=true`，
与发布二进制一致。

---

## 3. 固定参数

| 项 | 取值 | 说明 |
|---|---|---|
| 密码 | `strhide-bench-v1` | 两域一致；结构域 PBKDF2 100 000 次，内容域 L1 PBKDF2 200 000 次 |
| 内容域 seed | 32 字节 `0x5E 0xED ...`（`docs` 附录 A 记录完整十六进制） | 经 `Freshness::Seeded` 注入，盐/nonce 可复现 |
| 载荷字节流 | SplitMix64(seed=42) 生成，长度精确等于档位 | 不可压缩（Deflate 会退化为 stored），代表最坏情况；避免文本载荷带来压缩率波动 |
| 安全档位（内容域） | 官方默认 `High` + `Advisory` | 超推荐容量只告警不拒绝，报告逐格标注利用率 |
| 结构域策略 | `strategy="auto"`、`preserve_time=true`、`backup=false`、非 stealth | `backup=false` 仅影响文件 API，内存路径无意义，但显式声明 |
| 线程 | 引擎默认全局 rayon 池（16 逻辑核） | 内容域 PNG/JPEG 代价图并行；结构域本身单线程 |
| 每格样本 | 预热 2 次（不计时）+ 计时 20 次 | |
| 顺序 | 按 (载体 × 载荷) 顺序执行，写读配对；同一格的 20 次连续执行 | 减少跨格频率漂移的影响 |
| 进程 | 每个域一个独立进程，不与其他负载并行 | 避免预热/GC/页缓存相互污染 |

---

## 4. 结构域测试矩阵

载体覆盖发布声明支持的全部容器族（PNG、JPEG、WebP、MP4/MOV、MKV、WAV、ZIP 系、PDF、PE）。
所有 5 个载荷档位在每个载体上都跑（结构域无容量上限约束，实际策略可能退化，见 §6）。

| # | 载体家族 | 素材（复制到 `temp/bench/carriers/`，ASCII 名） | 原始大小 | 主要策略 |
|---|---|---|---|---|
| 1 | PNG | `png_baseline.png` ← `testdata/baseline/sample.png` | 85 KiB | `chunk`（IEND 前私有块） |
| 2 | JPEG | `jpg_baseline.jpg` ← `testdata/jpg/img_jpg_0005.jpg` | 949 KiB | `app_segment`（SOS 前 APP15） |
| 3 | WebP | `webp_baseline.webp` ← `testdata/baseline/ASN1.webp` | 8.8 KiB | `chunk` |
| 4 | WAV | `wav_baseline.wav` ← `testdata/baseline/remake02.wav` | 5.4 MiB | `chunk`（RIFF 私有块） |
| 5 | MP4 | `mp4_baseline.mp4` ← `testdata/baseline/sample.mp4` | 964 KiB | `box_uuid` |
| 6 | MKV | `mkv_baseline.mkv` ← `testdata/baseline/SDRSample.mkv` | 3.3 MiB | `chunk` |
| 7 | ZIP（docx） | `zip_baseline.zip` ← `testdata/baseline/file-17.zip` | 74 KiB | `pre_cd_inject` |
| 8 | PDF | `pdf_baseline.pdf` ← `testdata/baseline/docsexport.pdf` | 332 KiB | `incremental` |
| 9 | PE | `pe_baseline.exe` ← `testdata/baseline/FFConv.exe` | 158 KiB | `pe_codebits`/`pe_slack`，大载荷退 `eof` |

规模：`9 载体 × 5 档 = 45 格`，每格 22 次写入 + 22 次读取 ≈ 1 980 次操作。

**策略退化必须记录**：JPEG APP15 段长度字段上限 65 535 字节，`256 KiB` 以上必然退到 `eof`；
PE 的 `codebits/slack` 容量有限，`4 KiB` 以上基本退 `eof`。报告会把 `WriteResult.strategy`
逐格列出，并在表头标注"该行数字对应的实际注入策略"，否则数字会误导读者以为是结构化注入。

---

## 5. 内容域测试矩阵

内容域算法之间的开销差异可达数倍（HILL vs MiPOD、UERD vs J-UNIWARD），
因此矩阵按 **(载体 × 算法 × 载荷档位)** 展开，算法维度不做抽样、全部覆盖。

### 5.1 算法全集（来自 `stego::registry`）

| 格式 | 算法 id | 默认 | 说明 |
|---|---|---|---|
| PNG | `hill` | ✔ | 高通-低通-低通代价模型（Li et al., ICIP 2014） |
| PNG | `suniward` | | 空域小波相对失真（Holub et al., 2014） |
| PNG | `mipod` | | 方差估计下的最优检测器功率最小化（Sedighi et al., 2016） |
| JPEG | `uerd` | ✔ | 8 邻域平均 UERD 变体 |
| JPEG | `juniward` | | DCT 小波相对失真（固定 seed 时走标量路径，无 AVX2） |
| JPEG | `jmipod` | | 联合 DCT 多元正态可检测性（Cogranne et al., 2020） |
| HEVC | `hevc` | ✔ | CABAC bypass sign-bit Scheme C；`HevcMode::{Auto, Cabac}` 在视频载体上等价，按一个场景计 |
| WAV | `wav_pcm` | ✔ | PCM 采样域 STC（h8/u3） |
| FLAC | `flac_residual` | ✔ | 残差域 STC（h8/u3） |

### 5.2 载体与容量（实测，`High` 档 / 物理上限）

| # | 场景 id | 载体 | 尺寸 | 算法 | 推荐容量 / 上限 | 覆盖档位 |
|---|---|---|---|---|---|---|
| 1 | `png_hill` | `png_content_12mp.png`（← `testdata/png/img_png_0005.png`） | 3000×4000 RGB | HILL | 113 396 / 2 323 971 B | 1K, 8K, 32K, 128K |
| 2 | `png_suniward` | 同上 | | S-UNIWARD | 同上 | 1K, 8K, 32K, 128K |
| 3 | `png_mipod` | 同上 | | MiPOD | 同上 | 1K, 8K, 32K, 128K |
| 4 | `jpeg_uerd` | `jpg_content_22mp.jpg`（← `testdata/jpg/img_jpg_0003.jpg`） | 5760×3840 | UERD | 276 458 / 2 721 227 B | 1K, 8K, 32K, 128K |
| 5 | `jpeg_juniward` | 同上 | | J-UNIWARD | 同上 | 1K, 8K, 32K, 128K |
| 6 | `jpeg_jmipod` | 同上 | | J-MiPOD | 同上 | 1K, 8K, 32K, 128K |
| 7 | `hevc_mp4` | `hevc_video.mp4`（← `testdata/hevc/vid_h265_002.mp4`） | 1920×1080@60, 3.3 s | Scheme C | 10 647 / 558 194 B | 1K, 8K, 32K\*, 128K\*\* |
| 8 | `heic` | `heic_image.heic`（← `testdata/heic/img_heic_0003.HEIC`） | 4032×3024 | Scheme C | 86 092 / 296 784 B | 1K, 8K, 32K, 128K\* |
| 9 | `wav_pcm` | `wav_content.wav`（← `testdata/audio/07.朔漠南望.wav`） | 47 MiB PCM | wav_pcm | 197 306 / 3 025 358 B | 1K, 8K, 32K, 128K |
| 10 | `flac_residual` | `flac_content.flac`（← `testdata/audio/22 深深的我们 (伴奏).flac`） | 21 MiB | flac_residual | 19 264 / 98 276 B | 1K, 8K, 32K（128K 超物理上限） |

标记含义：

- `*` 超出 `High` 档推荐值但仍低于物理上限 → `Advisory` 策略下写入并产生
  `SafetyThresholdExceeded` 告警；报告给出 `payload / 推荐值` 与 `payload / 上限` 两个比值。
- `**` 引擎按槽位预算**硬拒**（`HEVC capacity insufficient for tier 'high'`，实测
  128 KiB 需要 10 488 104 槽、短片只有 8 997 363 槽）。按"换载体或降一档"规则，
  该格自动降为 `SafetyLevel::Balanced` 重测，报告中标注 `safety_level` 与降档原因。
- FLAC 128 KiB 在 21 MiB 载体上超物理上限（98 276 B）。按"换载体"规则新增第 11 个场景
  `flac128`：58 MiB Hi-Res 音轨（上限 142 224 B，128 KiB 占 92%），单独跑 `--only flac128`
  （实测单次嵌入 14.6 s / 提取 5.3 s，整格 455 s）。该行只可与自身比较。

规模：`11 场景 × 4 档（FLAC 21 MiB 3 档 + 58 MiB 1 档）= 40 格`，每格 22 次嵌入 + 22 次提取。

**关于 JPEG 的确定性问题**：`Freshness::Seeded` 会让 J-UNIWARD 关闭 AVX2/FMA
（浮点累加结合律不同会翻转近邻平局）。默认算法 UERD 没有 SIMD 分支，因此仅有
`jpeg_juniward` 一行反映标量路径，报告中单独标注，不代表默认配置的性能。

---

## 6. 测量与统计口径

单次样本：`Instant::now()` 紧贴被测调用，取 `elapsed().as_nanos()`；结果写入 `Vec` 后
统一统计，避免统计代码进入计时区。输出缓冲用 `std::hint::black_box` 防优化删除。

每格统计量：

| 指标 | 定义 |
|---|---|
| `mean` | 20 样本算术平均 |
| `median` | 20 样本中位数（第 10/11 位均值） |
| `p95` | 最近秩法 |
| `stddev` | 样本标准差（n−1） |
| `cv` | `stddev / mean` |
| `min` / `max` | 极值 |
| `trimmed_mean` | **当 `cv > 10%` 时**去掉一个最大值与一个最小值后的 18 样本均值；否则等于 `mean` |

报告表格主值用 `median`（对偶发调度抖动更鲁棒），同时列出 `mean`、`trimmed_mean`、`cv`，
并在被截尾的格里加 `†` 标记。这样既不隐藏方差，也不让单次抖动主导结论。

百分位与均值一律保留 2 位小数（毫秒），小于 1 ms 的格用 3 位小数。

---

## 7. 误差控制

### 7.1 已识别的混淆因素

| 因素 | 影响 | 处理 |
|---|---|---|
| PBKDF2 固定开销 | 结构域 100 000 次、内容域 200 000 次迭代，**与载荷大小无关**，会压平小载荷差异 | 主表照实报告端到端耗时；另做 §7.2 拆分实验给出 KDF 占比 |
| 载体解码 / 代价图 | 内容域每次重新计算，且与载荷大小无关 | 同一载体跨档位对比即可分离"固定成本"与"边际成本" |
| 文件 I/O | 4 MiB 落盘受 OS 缓存影响，方差大 | 主表用内存 API；§7.3 单独量化 |
| CPU 频率 / 温度 | 长跑后降频，`cv` 抬升 | 每格连续 20 次缩短时间窗；记录 `cv`，超阈值即截尾；全程单进程 |
| 内存分配器 | 大缓冲重复分配 | 不做特殊处理（真实路径就是这样），但记录 `cv` 供判读 |
| JPEG seeded 强制标量核对 | `deterministic=true` 关闭 J-UNIWARD 的 AVX2 路径 | 默认算法是 UERD，不含 AVX2 分支，故 seeded 不影响主表；附录注明该约束 |

### 7.2 KDF 占比拆分（内容域）

对每个内容域载体，额外跑一组 `Credential::FileKey(32B)`（跳过 PBKDF2）的 8K 档样本
（5 次，不计入主表），得到 `t_key`；主表 8K 档均值减去 `t_key` 即为引擎净耗时估算。
结构域不支持 `FileKey`，改用 `无密码`（走公开默认密钥，仍做 PBKDF2，但迭代次数相同）
无法拆分，故结构域只报告"4K 与 4M 耗时差"作为边际成本下界。

### 7.3 文件 API 开销（两域各一组）

结构域：`256 KiB` 档，每载体 5 次 `write_carrier_with` + `read_carrier_with`（落盘到
`temp/bench/io/`），与内存同档均值相减，得到 I/O + 原子提交开销。
内容域：`32 KiB` 档，同一做法（`io::embed_carrier_file` / `extract_carrier_file_payload`）。

### 7.4 正确性校验（不计时）

每格首轮额外验证：

- 结构域：`read.data == payload`，且 `remove_carrier_bytes(stego) == cover`（逐字节）。
- 内容域：`extract(stego) == payload`。

任一失败立即中止该格并标记 `FAIL`，不允许把错误结果写进报告。

---

## 8. 产物

| 产物 | 路径 | 说明 |
|---|---|---|
| 基准程序 | `rust/examples/perf_bench.rs` | 单文件，`--domain structure\|content\|all`、`--reps`、`--warmup`、`--out` |
| 渲染脚本 | `scripts/bench/render_report.py` / `scripts/bench/gen_summary.py` | JSON → 两份详细报告 + SVG / 根目录简明报告 |
| 原始数据 | `temp/bench/results/structure.json`、`content.json` | 全样本、全元数据 |
| 简明性能报告（根目录） | `BENCHMARK.md` | 两张汇总表 + 主要因素排序，供 README 引用 |
| 结构域报告 | `docs/BENCH_STRUCTURE_20261107.md` | 45 格主表 + 策略说明 + 结论 |
| 内容域报告 | `docs/BENCH_CONTENT_20261107.md` | 20 格主表 + 容量利用率 + 结论 |
| 环境快照 | 两份报告头部 | CPU/内存/OS/rustc/git commit/feature set/构建参数 |

报告结构（两份一致）：

1. 环境与构建信息
2. 方法摘要（含固定参数、统计口径）
3. 主表：写入 / 读取 耗时（median、mean、trimmed、cv）
4. 容量 / 策略 / 警告表
5. 分段分析（固定成本 vs 边际成本、KDF 占比、I/O 开销）
6. 结论与发布建议（含"哪些档位不建议对外承诺"）

---

## 9. 实施步骤

| 步骤 | 内容 | 预估 |
|---|---|---|
| S1 | 建目录、复制载体并做 ASCII 重命名、生成固定载荷 | 2 min |
| S2 | 实现 `examples/perf_bench.rs`，2 次采样试跑（pilot），核对耗时量级与容量告警 | 30 min（实际含算法维度返工约 50 min） |
| S3 | 结构域正式跑（20+2 次） | 5 min |
| S4 | 内容域正式跑（20+2 次，10 场景 39 格） | 实际约 33 min |
| S5 | 渲染两份报告，人工复核异常格（cv 高、策略退化、告警） | 20 min |
| S6 | FLAC 128 KiB 换载体补测（`--only flac128`），并补进度日志/增量落盘 | 实际 455 s |
| S6 | 结论写入 `docs/CHANGES-20261107.md` | 5 min |

---

## 10. 风险与预案

| 风险 | 预案 |
|---|---|
| 24 MP PNG 单次 > 6 s，总时长失控 | **已触发**：24 MP 实测单次嵌入 4.2–4.9 s，按预案改用 `img_png_0005.png`(12 MP, 113 396 B)，128K 标注为超档（1.13×）；JPEG 保留 22 MP（128K 仍在 High 档内） |
| HEVC 128K 在 3.3 s 短片上告警过多、方差大 | **已触发**：引擎在 High 档直接硬拒（槽位不足），按「降一档」改测 `Balanced` 并在报告标注；不再换长片，避免引入第二个变量 |
| 结构域 PE 大载荷全退 `eof`，与“结构化注入”名不符 | 实测 PE 全部落到 `pe_overlay`（不改代码段、不改节表），报告单列策略表说明；WebP 全部回退 `eof` 同样单列 |
| 某格 `cv > 30%` 仍无法收敛 | 该格样本量翻倍到 40 次，报告注明 |
| 渲染脚本缺失绘图依赖 | 图表改为纯手写 SVG（不引入 matplotlib） |

---

## 附录 A：固定常量

```
password  = "strhide-bench-v1"
seed      = 5eed000000000000000000000000000000000000000000000000000000000001
payload   = SplitMix64(state=0x9E3779B97F4A7C15, seed=42) 逐字节输出
```

## 附录 B：复现命令

```bash
cd rust
cargo build --release --all-features --example perf_bench
./target/release/examples/perf_bench --domain structure --reps 20 --warmup 2 \
    --out ../temp/bench/results/structure.json
./target/release/examples/perf_bench --domain content --reps 20 --warmup 2 \
    --out ../temp/bench/results/content.json
pip install -r ../scripts/bench/requirements.txt   # 当前仅用标准库，可跳过
C:/Home/Develop/venv/Scripts/python.exe ../scripts/bench/render_report.py
```
