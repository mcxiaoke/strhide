# strhide 代码审查 issue 处置台账

> 生成时间：2026-11-06 15:02:05 ｜ **最后更新：2026-11-06 15:11:16**（补入 F-02 回退与基线校验方法修正）
> 关联报告：`docs/CODE_REVIEW_20261106_1325.md`（v2，含 v1 `F-01~F-33` 与 v2 `N-01~N-14`、`T-01~T-21`）
> 处置原则（用户给定）：**目的是修 bug；不引入新问题；不导致性能大幅下降；风险大收益不明显就搁置；这是个人用的 CLI 工具，不考虑极端情况与第三方恶意构造/攻击，不做过度设计。**
> 结果：**v1 33 项 + v2 14 项 + 21 组测试缺口 + 文档偏差，全部有确定落点。**

---

## 1. 决策定义

| 决策 | 含义 |
|---|---|
| **修复** | 代码已改、有针对性回归测试、全量门禁通过、已进 git commit |
| **文档修正** | 代码行为正确/有意，改的是过时或自相矛盾的文档 |
| **勘误** | 审查报告自身的描述与源码不符，已在报告与本文档中更正 |
| **搁置** | 问题真实存在，但需改核心路径/专用夹具/重构容量模型，风险大于个人 CLI 工具的收益；记录前置条件，不改动代码 |
| **忽略** | 触发条件属于畸形输入、恶意构造、不可达路径、有意设计或安全特性；按用户原则不处理 |

## 2. 提交总览

| Commit | 批次 | 内容 |
|---|---|---|
| `0e1bf1a` | 1 | 6 项低风险正确性修复 + 3 个新测试 |
| `a3962be` | 2 | 容量口径统一 + 2 个新测试 |
| `c662465` | 3 | 写后自检坐标核对、内存预算文案、2 处过时注释 |
| `16e3dd1` | 4 | **回退**批次 1 的 F-02 删除（见 §3 注）；恢复 HEVC 短 replay 的零填充分支 |
| 本批（第 5 批） | 5 | 6 组文档修正 + 本台账 + 报告 v3 勘误 |

每批均通过：`cargo fmt`、clippy `-D warnings`、lib 内联测试、全部集成测试、`import_lint.py`、`baseline_hash.py --check`（28/28 逐字节一致）。完整的分秒级变更记录见 `docs/CHANGES-20261106.md` 顶部四条。

## 3. 已修复（代码）

| 编号 | 问题 | Commit | 验证 |
|---|---|---|---|
| F-06 | 写后自检只判 `locate` 是否 `Some`，不核对坐标 | `c662465` | 要求 `(ube_offset, ube_total_size)` 与本次封入 trailer 的值完全一致；全部策略的写入测试通过 |
| F-07 | trailer「魔数对、CRC 坏」被吞成"无信封" | `0e1bf1a` | `read_from_tail` 仅在魔数不匹配时返回 `Ok(None)`；新增 `trailer_crc_damage_is_reported_instead_of_no_envelope` |
| F-11 | `LocalParams.chunk_size` 无下限 → 64 MiB 载荷 + 1 字节分块可申请约 1.3 GiB | `0e1bf1a` | `MIN_CHUNK_SIZE = 512`；`invalid_local_params_fail_before_touching_the_carrier` 增加 2 个用例 |
| F-14 | `probe_compressibility` 只有 `debug_assert`，release 下短输入会下溢越界 | `0e1bf1a` | 换成运行时 `Err`；新增 `compression_probe_rejects_short_input_in_release_too` |
| F-15 | `is_pe_bytes` 的 `lfanew + 4` 在 32 位目标回绕 | `0e1bf1a` | 改 `checked_add(4)`；零性能影响 |
| N-01 | 容量三轨分裂（文件级 patch 分支漏调 `filename_safe_capacity`）+ Advisory/Enforced 阈值倒挂 | `a3962be` | 三条 API 路径同一口径；新增 `filename_safe_capacity_only_shrinks_the_raw_ceiling` 与 `file_level_patch_capacity_matches_the_unified_probe` |
| N-02 | 默认去掩码分支的随机碰撞使 `inspect`/`smart_extract` 中断 | `0e1bf1a` | `inspect_core` 把 `validate_against` 失败降级为 `empty_inspect_result`；新增 `inspect_degrades_an_invalid_header_to_no_envelope` |
| F-24（文案） | 只读入口按运行时可用内存拒绝时，文案像在说"载体太大" | `c662465` | 补充说明是内存压力、给出所需工作内存；**准入逻辑未改** |
| F-20 / F-27（注释） | 桥接注释与实现不符、HEVC 置换注释仍写固定 Weyl 步长 | `c662465` | 改为如实描述；**代码未改**（见 §5） |
| F-21（部分） | 统一入口与专家面容量差 256 B | `a3962be` + 文档 | 文件级路径已统一；专家面差异保留（改它会动引擎容量公式），已在 STEGO-API §6 明确写清 |

> **两次被回退的尝试**（均按"不引入新问题"原则处理）：
> ① 曾给 `unpack_with_secrets` 默认去掩码分支加 plausibility gate，导致 `verify_detects_unsupported_envelope_version` 与 `verify_rejects_a_meta_len_above_the_metadata_cap` 丢失具体 Level-2 诊断 → 立即回退，改用 `inspect_core` 降级解决 N-02，保留 `verify` 的既有诊断。
> ② **F-02**（删除 HEVC 短 replay 零填充）在批次 1 曾被列为已修复；重建 release 二进制后基线证明 `IMG_5887.HEIC` 的 cabac 嵌入因此失败 → 在 `16e3dd1` 完整回退，F-02 最终改为**搁置**（见 §6）。这说明该分支是真实载体正常路径所需，审查报告 §3 的 F-02 风险描述仍成立，但"直接删除"不是可行修法。

## 4. 文档修正（代码行为不变）

| 编号 | 修正内容 |
|---|---|
| N-12 | `rust/README.md`：5 处依赖版本 `0.8` → `0.9.1`；示例中不存在的 `write_res.envelope_size` → `ube_size`，`cap_info.capacity` / `safety_tier` → `max_raw_payload_bytes` / `safety_level`（示例现在可编译） |
| F-22 | `docs/api/STEGO-API.md`：`extract` 不再列出根本不存在的 `--p1-window/--p2-window`；明确 PNG 代价图参数由 64B 头自描述、提取端无需重复；补上 `ExtractOptions` 真正需要的凭据/方言/上限 |
| F-21 | 同文档「容量口径」段：说明统一入口为 255 字节文件名预留 256 B、裸载荷可多写 256 B、专家面不预留、`recommended_max_bytes`/`tier_limits` 用的是引擎原值 |
| F-25 | `docs/api/WIRE_SPEC.md`：`ext_len = 0` 时 JPEG 按公式仍占 28 槽（HEVC/空间域为 0），消除 §13.5 与 §13.6 的自相矛盾；`format.rs:538` 的测试已固定该值 |
| 版本 | `ARCHITECTURE.md` / `WIRE_SPEC.md` 头部版本 0.8.5 / 0.8.3 → 0.9.1 |
| 设计文档 | `smart_file_data_hiding_design.md`：旧 ASCII 魔数已移除读取兼容（仅作取证特征）、flags bit6/bit7 均保留、strategy_id 补齐 10~13（与 `STRATEGY_REGISTRY` 一致） |

> 实现细节：两个文档原文件分别是 LF / CRLF，首次编辑触发了全文行尾变更；已 `git checkout` 恢复并用二进制替换重做，最终 diff 仅 29 行，未污染提交。

## 5. 勘误（审查报告自身）

| 位置 | 不准确之处 | 核实结论 |
|---|---|---|
| v1 报告 §2.4 F-22 | 称"CLI `extract --p1-window/--p2-window` 是死参数、被静默忽略" | `rust/src/cli/args.rs:522-557` 的 `ExtractArgs` **根本没有** flatten `StegoTuningArgs`；`p1_window`/`p2_window` 只属于 `StegoTuningArgs`（`:424`），被 `CapacityArgs`(`:236`) 与 `EmbedArgs`(`:409`) 使用。CLI `extract` 无这两个 flag，因此不存在"死参数"。真实问题只是 `STEGO-API.md` 文档过时 + p1/p2 头部自描述。已在 §4 修文档，报告 v3 修订记录中标注此勘误 |

其余 v1/v2 结论均已逐条回源码核实；第三方报告的 15 条误报及反证见报告 §12.5。

## 6. 搁置（真实存在，但本次不改代码）

| 编号 | 搁置理由 | 将来若要做的条件 |
|---|---|---|
| F-02 | **已尝试修复并回退**：删除短 replay 零填充会让 `IMG_5887.HEIC` 的 cabac 嵌入失败（重建 release 二进制后基线 10 字段差异）。零填充可能覆盖 `rbsp_trailing_bits`，但当前 `encode_substream` 对真实 HEIC 会产生短 1–4 字节的 replay | 先让 `encode_substream` 严格等长（或只在差额字节确为合法 trailing zeros 时允许），并有 HEIC/HEVC 完整基线夹具后再改 |
| F-03 | MKV unknown-size streaming Cluster 的 CRC covers 错误；真实 MKV 载体与 CRC 端到端夹具缺失 | 先补 `tests/assets` 的合法 unknown-size MKV 夹具 + `mkvmerge` 复验 |
| F-09 | Annex-B 尾零回收导致 NAL 长度口径漂移，但写读两侧一致、不影响数据 | 有真实含 `cabac_zero_word` 的码流夹具再评估 |
| F-10(c) | 时间戳/权限恢复失败只写 stderr、结果对象无 warning；加 `warnings` 变体要动多个返回结构 | 有明确调用方需要感知该失败时再加 |
| F-16 | `body_len` 硬上限是全局常量，但已有 `needed_body_slots`/工作集预算兜底，不产生错误数据 | 与 V4 头语义重构一起做 |
| F-18 | JPEG probe 只读 SOF 几何、embed 读实际系数；让 probe 也读系数会明显拖慢快速探测 | 找到 `grid_w*grid_h != blocks.len()` 的真实载体夹具后加断言 |
| F-19 | 渐进式 JPEG 分类依赖 `dct-io` 错误文案 | 上游提供结构化错误码 |
| F-20（代码） | 桥接失败丢弃原诊断；改错误类型会影响调用方的错误分类，收益仅是文本 | 需要 `StrHideError` 支持附加上下文时统一做 |
| F-23 / F-33 | `NoHiddenData` 折叠掉 `CorruptedData`/`PayloadTooLarge`；内容域"错密码不可区分"是有意设计，拆分会影响多引擎与大量测试 | 先定义哪些错误可以外露且不破坏不可区分性 |
| F-24（逻辑） | 只读入口按"60% 可用物理内存"准入，内存紧张时结果非确定；改成固定上限会削弱大文件保护 | 有真实的误拒案例与明确内存策略再改 |
| F-26 | 容器头损坏时 EOF fallback 把原生策略误报 `eof`，只影响诊断不丢数据 | 与容器诊断体系一起整理 |
| F-27（死代码） | `is_epb_safe_flip` 无生产调用，但有 3 处内联测试引用，删除要连带改测试 | 与 EPB 规则收敛一起做 |
| F-29 / N-11 | isobmff / mkv 校验循环内重复 seek，正常容器 box 数少、收益不明显 | 有碎片化大 MP4 的实测性能数据再做 |
| F-30 | PNG 并行 deflate 用 `Z_SYNC_FLUSH` 拼接独立流；改法会改变输出字节与压缩率 | 需要大图尺寸回归基线 |
| N-03 | HEIF `item_hidden` 的 iinf 注入/剥离/预检三处判据不对称 | 先补带 iinf/iloc padding 的 HEIF 夹具与完整生命周期测试（T-16） |
| N-04 | PDF 尾部盲搜 `obj`、内联 `/Encrypt` 漏检、`find_int_after` 前缀碰撞 | 需要 PDF 词法解析器或一组合法边界夹具 |
| N-05 | RIFF 哨兵导致 `verify` 把 eof 信封当 chunk；Simple WebP 无 `VP8X` 门槛就追加 `SHRD` | 改动 `riff_verify_structure` / `riff_inject` 核心路径，需 WAV/WebP 全量夹具 |
| N-06 | PE 线性反汇编无函数边界、`DataDirectory[11]` 未排除、64 KiB 头部窗口不一致 | PE 改动可能破坏可执行程序，需 `.pdata` 与真实 PE 语料 |
| N-07 | MP4 文件级 inspect 单 Decoder 跨 GOP、1 MiB 前缀截断 | 改动解码器生命周期风险大，需多 GOP 夹具（T-20） |
| N-08 | CLI `extract --auto` 回退丢弃共享 `BatchOutputs`；但 `unique_batch_path` 已防覆盖 | 改 `handle_read` 签名 + 批量状态，需混合批量夹具（T-19） |
| N-13 | `png_pre_salt` 绑定全部非 IDAT/prIv 辅助块；改它会改变所有 PNG 输出的线格式派生并重建基线 | 项目发布前统一线格式时一并处理 |
| N-14 | 双域 + `eof` 策略在内容域重编码后定位失配；`README.zh.md:28,32` 已声明"重编码后 RestoreMismatch 失败关闭" | 在支持矩阵中排除 `eof`，或为 `eof` 增加与 `chunk` 对称的重定位逻辑 |
| F-21（专家面） | 专家面 `probe_*_capacity` 不预留 256 B | 与引擎容量模型重构一起做，已文档化 |

## 7. 忽略（按用户原则不处理）

| 编号 | 理由 |
|---|---|
| F-01 | 畸形/被篡改 MP4 的 `stco` 指向 `moov`——恶意构造；加 mdat 归属校验有误拒合法文件的风险 |
| F-04 | 公开 patch API 漏刷 MKV CRC：CLI 的 patch 分支限定 MP4/Annex-B，个人 CLI 工具不触发 |
| F-05 | 分卷/多磁盘 ZIP 未校验盘号——极端载体 |
| F-08 | 私有 domain 方言驱动 CLI 时双域预检失效；官方二进制用 `StrHide::new()` 不受影响 |
| F-10(a)(b) | 临时文件符号链接预置、备份→rename 之间的 TOCTOU——攻击面/竞态，项目已有 `TargetLock` 与 `create_new` 备份 |
| F-12 | 伪造 header 注入坐标越界；已有 `confine_location`、`verify_restored` 全量 SHA-256 兜底，不产出损坏文件 |
| F-13 | `make_chunk_nonce` 的 `as u32` 回绕：载荷上限 1 GiB + 分块下限 512 B 下不可达 |
| F-17 | stealth 下同时接受裸 CRC：去特征承诺问题，不涉及数据正确性；改法影响 wire 兼容 |
| F-28 | MP4 零填充静默接受、`size=0` box、WAV RIFF size 不校验、`unpack` 默认分支不校验 version、patch 重叠——均为畸形输入/防御纵深 |
| F-31 | 三次 sniff IO、`compute_default_threads` 的 `max(4)`、`tier_limits` 展示层——微优化/展示，收益为零 |
| F-32 | release `panic = "abort"` 是有意配置；814 处 `unwrap/expect` 多为不变量，fuzz/全局改造属过度设计（本轮已把两个输入相关的改为安全形式：F-14/F-15） |
| N-09 | 全局语言 `AtomicU8`、`EnvelopeHeader` 全字段 `pub`：架构设计选择，项目未发布，可后续收敛 |
| N-10 | cgroup 内存限额、派生密钥 `Copy` 不清零：容器/安全场景 |

## 8. 测试缺口处置（T-01 ~ T-21）

本轮新增 **5 个测试函数 / 用例组**，覆盖已修复的 7 项中的 5 项（F-07、F-11、F-14、N-01、N-02）；其余 2 项由全量既有测试覆盖（F-06 靠全部策略的写入测试、F-15 靠既有 sniff 测试）。F-02 的"修复"已被回退，不计入。

| 缺口 | 决定 | 说明 |
|---|---|---|
| T-01 EPB 24 轮重试 | 搁置 | HEVC 复杂重试逻辑；需构造冲突夹具，属极端码流 |
| T-02 真实 MKV 内容域往返 | 搁置 | 仓库有 `small.mkv` 但只在结构域测试用；需 MKV 语料 |
| T-03 MKV CRC 端到端 | 搁置 | 同 F-03 |
| T-04 FLAC CONSTANT/VERBATIM 子帧 | 搁置 | 现有 e2e 夹具全是 FIXED 子帧；需新夹具 |
| T-05 IO 故障注入（ENOSPC） | 忽略 | 用户明确不考虑极端/攻击场景 |
| T-06 restore 失败不落盘的文件级断言 | 搁置 | 现有测试已断言 `RestoreMismatch` 错误类型；文件副作用断言收益小 |
| T-07 HEVC/音频头逐字段篡改 | 忽略 | 伪造载体负测 |
| T-08 suite 2 非 JPEG 域 | 搁置 | 信封层与 JPEG 已有覆盖；其余格式组合收益有限 |
| T-09 JPEG 容量边界 | 搁置 | 与 F-18 绑定，等真实夹具 |
| T-10 非 baseline JPEG 夹具 | 搁置 | 需 SOF2/多扫描/DNL 语料 |
| T-11 并行 IDAT 路径 | 搁置 | 与 F-30 绑定 |
| T-12 坐标不一致自检负测 | 搁置 | F-06 已修；构造同 magic 双信封需改写入流程，收益小于风险 |
| T-13 多线程取消 | 搁置 | PNG/JPEG 单线程取消已有覆盖 |
| T-14 `--exact` / 20% 采样口径 | 搁置 | 容量一致性已有 5 处覆盖，采样口径差异无实测案例 |
| T-15 双域 restore/verify 闭环 | 搁置 | `heavy_coexistence` 标 `#[ignore]` 且只测 read/extract；README 已声明边界 |
| T-16 HEIF `item_hidden` 生命周期 | 搁置 | 同 N-03 |
| T-17 PDF dirty tail / 内联 Encrypt | 搁置 | 同 N-04 |
| T-18 PE 跳转表 / Bound Import | 忽略 | 同 N-06，属极端 PE 变体 |
| T-19 CLI 混合批量 `--auto` | 搁置 | 同 N-08 |
| T-20 MP4 多 GOP 流式 inspect | 搁置 | 同 N-07 |
| T-21 RIFF 哨兵 / Simple WebP 合规 | 搁置 | 同 N-05 |

## 9. 最终门禁（重建 release 二进制后复验）

```
cargo fmt --check                                    通过
cargo clippy --all-targets --all-features -- -D warnings   无警告
cargo build --release --all-features                 通过（1m08s，CLI 二进制已更新）
cargo test --all-features --all-targets              全部通过（含 examples 编译）
cargo test --all-features --lib                      554 passed / 1 ignored
cargo test --all-features --tests                    cli 139 / lifecycle 152 / media 15
                                                     / pe 41 / regression 117 / security 25
python scripts/import_lint.py                         OK（分层边界完好）
python scripts/baseline_hash.py --check              28/28 逐字节一致（F-02 回退后复验通过）
```

> **重要方法修正**：批次 1~3 记录的 `baseline_hash --check 28/28` 使用的是仓库中**未更新的** `target/release/strhide.exe`（AGENTS.md 明确警告过该陷阱），属于假绿。首次执行 `cargo build --release --all-features` 后真相暴露：`IMG_5887.HEIC` 因 F-02 改动 `embed_failed`（10 字段差异）。回退 F-02 并再次重建后恢复 28/28。**今后凡改解析/注入路径，必须先重建 release CLI 再跑基线。**

## 10. 剩余风险（如实记录）

1. **搁置项仍是真实问题**：N-03/N-05/N-07 等容器路径在特殊但合法的文件上仍可能给出错误结果或诊断；本轮按"风险大收益不明显"未动，台账已记录前置条件。
2. **测试覆盖仍偏薄**：HEVC EPB 重试、真实 MKV、FLAC 非 FIXED 子帧、HEIF `item_hidden` 生命周期仍是空白；`heavy/` `local/` 套件在无外部语料时静默跳过。
3. **第三方报告本身不可信**：约半数断言基于不存在的标识符或过时代码，本报告已把其成立部分合并、不成立部分列入 §12.5；后续若再引用该报告须重新核实。
4. **未触及的发布前事项**：`png_pre_salt` 绑定过宽（N-13）与公开面收敛（N-09）会改变线格式/API，应在项目发布前统一决策。
5. **F-02 的风险仍在**：零填充分支理论上可能覆盖 `rbsp_trailing_bits`（审查报告 §3 F-02），但当前没有可行且不破坏真实 HEIC 载体的替代实现；已加注释标注，并保留 EPB 冲突扫描与 NAL 长度门两道兜底。
6. **基线校验依赖正确的二进制**：CI/本地若跳过 `cargo build --release --all-features`，`baseline_hash.py --check` 会拿旧 CLI 验证新代码，产生假绿。

---

**结论**：47 项代码/接口/算法/文档类 issue 与 21 组测试缺口全部有明确落点——
**修复 7 项 + 文案/注释 3 项 + 部分修复 1 项 + 文档修正 6 组 + 勘误 1 项 + 搁置 25 项 + 忽略 11 项 + 测试缺口 21 组全部决定**，
共 **5 个 git commit**（其中 `16e3dd1` 为按"不引入新问题"原则做的回退）、**5 个新测试**；
重建 release 二进制后的 `baseline_hash --check` 28/28 逐字节一致，全部门禁通过。
