# CODE_REVIEW_20261106-xhx 逐条判定与处置

> 审查报告：`docs/CODE_REVIEW_20261106-xhx.md`
> 判定基线：`04a9388` 之前的 HEAD `1d8431e`，加上本轮 4 个修复提交后的最终 HEAD
> 判定方法：源码自查 + release 二进制实测（复现命令与输出见 `docs/CHANGES-20261106.md` 的批次 3~6）
> 判定口径：
> - `real_reachable`：真实存在，正常路径/日常使用可触发；
> - `real_rare`：真实，但需构造性/极端条件（写明前提）；
> - `not_a_defect`：前提不成立、现有代码已处理、或报告理解有误（含纯性能/风格/测试缺口）；
> - `obsolete`：当前代码已不存在该问题。

## 0. 修复批次总览

| 批次 | 提交 | 覆盖条目 | 结果 |
|---|---|---|---|
| 3 | `04a9388` fix(structure): locate appended EOF envelopes after carrier rewrites | XH-01 | 已修复，新增回归 |
| 4 | `7e9ed5d` fix(cli): stop suggesting --overwrite for occupied structure envelopes | XH-10 | 已修复，新增回归 |
| 5 | `465408f` fix(core): reclaim a target lock left by a dead writer | XH-07 | 已修复，新增 3 单测 |
| 6 | `2abcae8` docs: correct when a structure envelope can be stripped without a password | D4 | 已修正 |

本报告没有新的 `real_reachable` 条目被判定为"必须再改代码"。其余 `real_rare` 条目已给出触发前提与搁置理由（见 §9）。

## 1. §2 架构设计（A1–A4）

| 编号 | 判定 | 一句话结论 | 证据 |
|---|---|---|---|
| A1 | not_a_defect | 构建图事实成立（`analysis` → `structure` → `structure-pe` → `iced-x86`），但这是"默认全量"的设计取舍，不影响任何输出正确性。 | `rust/Cargo.toml:22/30-34/55` |
| A2 | real_rare | 库层 8 处 `eprintln!` 直写 stderr 属实，但仅当时间戳/权限还原失败时触发；不改变写入结果。 | `structure/engine.rs:1571/1577/2408/2414`、`core/commit.rs:446/452/550/556` |
| A3 | real_rare | 全局 `AtomicU8` 语言与全局 rayon 池属实；影响同一进程内多租户/多语言嵌入，单进程 CLI 不受影响。 | `core/i18n/mod.rs:49`、`stego/mod.rs:125` |
| A4 | not_a_defect | `pub mod` 全量导出是未发布 crate 的既有约定，文档已声明内部面非稳定 API；无行为缺陷。 | `docs/api/ARCHITECTURE.md:149`、`rust/src/lib.rs:150-278` |

## 2. §3 P1（XH-01–XH-04）

| 编号 | 判定 | 一句话结论 | 证据 |
|---|---|---|---|
| XH-01 | real_reachable（已修 `04a9388`） | 追加型 `eof` 信封在内容域重编码后位移、原绝对偏移失效，修复前 `read/verify/restore` 全部失败；修复后按"信封仍尾对齐"由 `file_size-ube_total_size` 推导真实起点，PNG 额外校验头魔数，还原仍由宿主 SHA-256 失败关闭。实测 `read` 恢复 3219 B、`verify` L1/L2/L3 全 ok。报告"孤儿信封单调累积"未复现（多轮循环 headers=1/trailers=1）。 | `structure/envelope.rs:870-879`、`structure/engine.rs:1413-1431`、`structure/adapters/{eof,png,jpeg,mkv,isobmff,riff}.rs`、`tests/test_lifecycle/matrix.rs::eof_envelope_survives_carrier_rewrite_relocation` |
| XH-02 | obsolete | `read_from_tail` 已只把"魔数不匹配"当作无信封；魔数匹配但 CRC 失败会向上抛 `CorruptedData`，并有单测固化。 | `structure/envelope.rs:844-858`、`:886` `trailer_crc_damage_is_reported_instead_of_no_envelope` |
| XH-03 | not_a_defect | 报告"异密码写入后必然无法还原"未复现：内容域先写、结构域后写时两载荷各自可读；其证据里的 restore 失败实为 XH-01 的位移路径，已修复。预检仍是凭据范围内的 best-effort，属文档需说明的边界而非数据丢失。 | 实测 `temp/repro`（异密码两域共存）、`facade.rs::ensure_domains_free_impl` |
| XH-04 | real_rare（搁置） | 触发需数十 MP 图像且宿主机内存吃紧；报告建议的"代价图之前按 8 GiB 预算早拒"在当前常量下**永不触发**（64 MP 的 base ≈3.88 GiB < 8 GiB），真正可行的是 `try_reserve`/内存准入，与已搁置的 F-24 同源。 | `stego/png/engine.rs` `MAX_PNG_PIXELS`/`PIPELINE_BYTES_PER_PIXEL`/`MAX_PIPELINE_BYTES`；计算见 `docs/CODE_REVIEW_DISPOSITION_20261106_1502.md` F-24 |

## 3. §4 P2（XH-05–XH-14）

| 编号 | 判定 | 一句话结论 | 证据 |
|---|---|---|---|
| XH-05 | real_rare（搁置） | `read` 按载体缩放上限、`verify` 固定 1 GiB 属实；触发需用公开内置密钥伪造"已认证"的 1 GiB deflate 炸弹信封，属对抗性输入。 | `structure/engine.rs:1861-1866` vs `:1982-1993` |
| XH-06 | real_rare（搁置） | `apply_hevc_patches` release 下越界即 panic、`validate_hevc_patches` 私有、MKV 补丁路径不刷 CRC 均属实；但生产路径先校验，CLI 的 MKV 走整文件提交，只有直接误用专家 API 才触发。改签名是公开 API 破坏性变更。 | `stego/hevc/engine.rs:997-1027`、`:1068-1086` |
| XH-07 | real_reachable（已修 `465408f`） | 崩溃遗留的 `.<name>.strhide.lock` 会让目标永久 `TargetBusy`；修复后读 PID 并证明持有者死亡才回收（Win `OpenProcess`+`WaitForSingleObject`，Linux `/proc`，其它 Unix `kill(0)`），不可证明时保守保留。 | `core/commit.rs:255-395`、新增 3 单测 |
| XH-08 | real_rare（搁置） | `inspect` 报 `eof` 可用、`write -s eof` 被结构门禁拒绝属实；触发需载体自身结构非法（如 odd `data` chunk 缺 pad）。仓库 `tests/assets/small.wav` 正是这种畸形夹具；流式哨兵 WAV 已由 N-05b 处理。 | `structure/adapters/riff.rs:481-515`、`structure/engine.rs:986-994`；实测 `inspect/write small.wav` |
| XH-09 | real_rare（搁置） | stdin/文件载荷先全量 `read_to_end` 再判上限属实；触发需超大输入（数十 GB 管道或数 GB 文件）才会在拒绝前 OOM；阈值本身正确（64 MiB 可写、+1 在读回前拒绝）。 | `structure/engine.rs:398-428`、`:1037-1053` |
| XH-10 | real_reachable（已修 `7e9ed5d`） | 结构域已占用时预检仍建议 `--overwrite`，但结构引擎不接受替换，两条文案互斥；修复后仅结构占用改提示"specify another file"，仅内容占用保留"--overwrite to keep the content payload"。 | `facade.rs::ensure_domains_free_for_structure`、`cli/cmd_structure.rs:146-149`、`tests/test_lifecycle/facade.rs::structure_occupancy_error_does_not_suggest_overwrite` |
| XH-11 | obsolete | `chunk_size` 已有下限 512 B，不再接受病态小值。 | `core/params.rs:52/220` |
| XH-12 | obsolete | 写后自检已把 `locate` 返回坐标与本次写入封入 trailer 的坐标比对（release 生效），报告所称"唯一防线"不成立；第二处 `debug_assert_eq!` 现比较同一记录派生值，注释已说明其无证明力。 | `structure/engine.rs:1413-1431`、`:3002-3018` |
| XH-13 | not_a_defect | `inspect` 多一次 PBKDF2（实测约 30 ms）属实，但只是性能开销，无功能影响。 | `structure/engine.rs:2589/2623/2637` |
| XH-14 | not_a_defect | `SegmentedSubStream::read` 每次线性扫段属实；段数上限约 1024，8 MiB 载荷实测 104 ms 可接受，属可避免的常数开销。 | `structure/adapters/mod.rs:435-489` |

## 4. §5 代码质量（XH-15–XH-19）

| 编号 | 判定 | 一句话结论 | 证据 |
|---|---|---|---|
| XH-15 | not_a_defect | 清洗实现已统一为 `core::fs::sanitize_filename`；`stego::envelope` 的同名 `Option` 包装是"清洗为空就不落地文件"的有意契约，且注释已说明，未见误用。 | `stego/envelope.rs:279-306`、`structure/engine.rs:768` |
| XH-16 | not_a_defect | `let _ = prepared/resolved/&trailer` 与空文档行属可读性残留，无行为影响。 | `stego/engine.rs:975`、`stego/audio/core.rs:1002`、`structure/engine.rs:3018` |
| XH-17 | not_a_defect | 注释里 24/1024/65533 三个数字叙述不统一，但实现正确（末段 ≥24 B，必要时借 1024 B）。 | `structure/adapters/jpeg.rs:170-195`；`suspicious_structures` 的 136 vs 214 阈值偏松仅影响启发式提示 |
| XH-18 | not_a_defect | `WriteOptions.strategy` 仍是 `&str`，拼写错误被报成"适配器不支持"；但 `StrategyChoice` 已存在并提供 `with_strategy_choice`，属可用性/设计改进。 | `structure/options.rs:21-36/69/127-128` |
| XH-19 | not_a_defect | Config 与 flag 合并规则重复三处，行为一致，属维护性问题。 | `cli/cmd_structure.rs` 各 handle 函数 |

## 5. §6 算法与性能（XH-20–XH-24）

| 编号 | 判定 | 一句话结论 | 证据 |
|---|---|---|---|
| XH-20 | real_rare（搁置） | 大载荷整体缓冲 + `Vec::with_capacity` 无 `try_reserve` 属实；需 ~1 GiB 载荷且内存吃紧，`panic=abort` 下才会致命。 | `structure/engine.rs:1278` |
| XH-21 | real_rare（搁置） | 固定 8×32 KiB 采样对"前段随机、后段全零"的载荷会误判为不值得压缩；报告已确认这是有意的性能取舍。 | `core/crypto.rs:668-700` |
| XH-22 | not_a_defect | 批量预检每载体跑完整 `inspect` 属实，是 O(n) 性能开销；正确性无影响。 | `cli/cmd_structure.rs:146-149`、`facade.rs::inspect_any` |
| XH-23 | not_a_defect | 正面确认（PNG `select_nth_unstable`、AVX2 STC/J-UNIWARD、FLAC 分析遍复用），无需处置。 | 报告 §6 XH-23 |
| XH-24 | not_a_defect | 报告自述"不算缺陷"，仅是采样/全量判据的额外一次全量 deflate 浪费。 | `core/params.rs:108-117`、`structure/engine.rs:1074-1093` |

## 6. §7 可靠性（R1–R4）

| 编号 | 判定 | 一句话结论 | 证据 |
|---|---|---|---|
| R1 | real_rare | Windows ACL 拒绝（`ERROR_ACCESS_DENIED=5`）被当作共享冲突重试后报 `TargetBusy`，属错误归类；需 ACL 拒绝场景，无数据损失。 | `core/commit.rs:600-623`、`:214-236` |
| R2 | real_rare | 补丁提交只做上界检查，`fs::copy` 后不复核源 size/mtime；需"补丁生成→复制→写入"之间第三方同长度改动才误打补丁。 | `core/commit.rs:486-545` |
| R3 | real_rare | Unix `sync_parent_dir` 失败被吞，掉电可能丢目录项；窗口极小，且不符注释宣称的 crash-safe。 | `core/commit.rs:545`、`:524-539` |
| R4 | not_a_defect | 正面确认（`TmpGuard`、先 fsync 后 rename、`create_new` 备份、`same_file`、只读提前拒绝），无需处置。 | 报告 §7 R4 |

## 7. §8 业务逻辑（B1–B4）

| 编号 | 判定 | 一句话结论 | 证据 |
|---|---|---|---|
| B1 | not_a_defect | `verified_identical` 确为与写入前宿主 SHA-256 一致（语义正确）；报告所依赖的"孤儿信封累积"未复现，仅"宿主已还原"文案可更精确。 | `structure/engine.rs:759/2258/2391/2427`、`core/i18n/messages.rs:825-828` |
| B2 | obsolete | 两域对"清洗后为空"的名字现均回落 `extracted.bin`；结构域用 `core::fs` 的回落语义，跨域行为一致。 | `stego/envelope.rs:356-357`、`core/fs.rs:19/234-237`、`structure/engine.rs:1965-1969` |
| B3 | not_a_defect | MKV 容量信息缺 fps/duration 属实，是能力/信息缺口，不影响写入与还原。 | `stego/hevc/engine.rs:867-940` |
| B4 | not_a_defect | `total_elements` 与 `available_slots` 量级悬殊属实，数值正确，属渲染可读性问题。 | `stego/hevc/engine.rs:867-874` |

## 8. §9 测试覆盖（T1–T10）

| 编号 | 判定 | 一句话结论 | 证据 |
|---|---|---|---|
| T1 | obsolete（部分） | `eof`+内容域重编码的丢数据路径已修复并新增回归；`heavy_dual_domain_coexistence_matrix` 仍只用默认 `auto` 且不 restore，测试缺口保留。 | `04a9388`、`tests/test_lifecycle/matrix.rs`、`tests/heavy/heavy_coexistence.rs:321-340` |
| T2 | not_a_defect | 异密码预检分支无断言属实，但该分支不构成数据丢失（见 XH-03）。 | `tests/heavy/heavy_coexistence.rs` |
| T3 | obsolete | 已补 3 个单测：死 PID 回收、活 PID 保留、不可解析内容保留。 | `core/commit.rs` tests、`465408f` |
| T4 | not_a_defect | `apply_hevc_patches` 非法 span 无测试属实，属测试缺口；生产路径已校验。 | `stego/hevc/engine.rs:997-1027` |
| T5 | not_a_defect | CI 不跑 `--ignored` 属实，属流程缺口而非运行时缺陷。 | `.github/workflows/ci.yml:54` |
| T6 | not_a_defect | 14 个 adapter 无内置测试属实，测试缺口。 | 报告 §9 T6 |
| T7 | not_a_defect | `small.wav`/`small.flac` 不可用于正向测试属实，属夹具问题（与 XH-08 同源）。 | 实测 `inspect/capacity small.wav/small.flac` |
| T8 | not_a_defect | 无 >4 GiB 端到端属实，测试缺口。 | 报告 §9 T8 |
| T9 | not_a_defect | 无 I/O 故障注入属实，测试缺口。 | 报告 §9 T9 |
| T10 | not_a_defect | CI 不含 `--doc` 属实（与 D8 同一事实）；文档示例暂未腐化。 | `.github/workflows/ci.yml:54` |

## 9. §10 文档偏差（D1–D9）

| 编号 | 判定 | 一句话结论 | 证据 |
|---|---|---|---|
| D1 | obsolete | 已更新为 `0.9.1`。 | `docs/api/ARCHITECTURE.md:3` |
| D2 | obsolete | 已更新为 `0.9.1`。 | `docs/api/WIRE_SPEC.md:3` |
| D3 | not_a_defect | 文档仍列 `MIN_UBE_PLAIN=178`，但同页已明确其为保守门槛、实际最小为 214；代码统一用 `min_ube_len(1)=214`，未发现按 178 预算的路径，仅"pe_codebits 使用 178"的归因已过时。 | `docs/api/WIRE_SPEC.md:717/745-746`、`structure/envelope.rs:116/1011-1012`、`structure/adapters/pe_codebits.rs:56` |
| D4 | real_reachable（已修 `2abcae8`） | 原文"非 stealth 信封免密剥离"错误：加密信封即使非 stealth 也需密码解包头；已按"加密/stealth 两个独立维度"改写。实测无密码 `restore/read` 失败。 | `docs/api/ARCHITECTURE.md:356`、`structure/envelope.rs:61-65` |
| D5 | not_a_defect | 文档称双域两种顺序"均验证"，实际 heavy 测试只用 `auto` 且不 restore，属文档夸大测试覆盖（测试缺口见 T1）。 | `docs/api/ARCHITECTURE.md:553`、`tests/heavy/heavy_coexistence.rs:321-340` |
| D6 | not_a_defect | 报告自述未核验；当前文档仍写 `--extensions` 未接线，未发现与代码冲突的新证据。 | `docs/api/STEGO-API.md:21` |
| D7 | not_a_defect | PNG/JPEG/HEVC 基础槽位与代码一致（核对通过）。 | `docs/api/WIRE_SPEC.md:637-643`、`stego/header.rs:151-157`、`stego/format.rs:107-111` |
| D8 | not_a_defect | 文档称 doctest 由 CI 守护，CI 实际不含 `--doc`；与 T10 重复，属流程/文档偏差。 | `docs/api/ARCHITECTURE.md:606`、`.github/workflows/ci.yml:54` |
| D9 | not_a_defect | AES-256-GCM + PBKDF2 100,000 轮与代码一致（核对通过）。 | `docs/api/ARCHITECTURE.md:594`、`core/crypto.rs:101` |

## 10. 报告 §12.2 未复现项

报告自述未实测的 4 项（ISO-BMFF `item_hidden` 对称性、PDF 多 `%%EOF` 锚定、PE 跳转表误判、CLI `--auto` 批量上下文）本轮同样未构建运行时夹具，**不作判定**，保留为风险观察项。

## 11. 搁置理由汇总

| 条目 | 搁置原因 |
|---|---|
| XH-04 | 报告建议的早检查在当前常量下永不触发；可行修法（`try_reserve`/内存准入）需改多个大块分配点，且触发依赖宿主机内存，风险大于个人 CLI 工具收益（F-24 已搁置）。 |
| XH-05 | 需伪造使用公开内置密钥的"已认证"元数据，属对抗性场景；修法要给 `verify_authenticated_payload` 加载体长度参数，收益限于抗 DoS 不对称。 |
| XH-06 | 改 `apply_hevc_patches` 签名为 `Result` 是公开 API 破坏性变更；生产路径已校验，CLI 不走 MKV 补丁路径。 |
| XH-08 | 触发需载体自身结构非法（畸形 WAV）；放宽写前门禁为"非 eof 才拒绝"会改变格式保持承诺，需产品决策。 |
| XH-09 | 需超大 stdin/文件输入；修法要给 `into_buffered` 加 `max_bytes` 并区分域上限，改动面大于当前收益。 |
| XH-20 | 需 ~1 GiB 载荷 + 内存压力；`try_reserve` 改造涉及结构域整体缓冲策略。 |
| XH-21 | 采样策略是有意取舍，改进会改变压缩判定阈值（可能影响输出字节），需基线重建。 |
| R1/R2/R3 | 均为罕见环境/竞态类诊断精确性问题，无数据丢失；改动集中在原子提交路径，回归风险高于收益。 |
