# 测试套件审计报告（2026-11-07）

> 范围：`C:\Home\Projects\strhide\rust` 的单元测试、集成测试、doctest 与带断言的 example。
> 性质：只读审计。本轮不修改任何现有代码、测试、文档，不 commit、不 push。
> 数据来源：`cargo test --all-features -- --list`、`--list --ignored` 与逐目标实际运行；耗时取 libtest 的 `finished in`，不包含 cargo 启动/编译时间（另行标注 wall time）。

## 1. 摘要

**总量：1110 个用例（1083 个默认运行 + 27 个 `#[ignore]`），8 个 doctest。** 默认全量测试的测试时间合计 **12.48 s**，wall time 23.09 s（含 cargo 启动与多目标链接）。

| 判定维度 | 数量（条目） | 说明 |
|---|---|---|
| 重复 | 16 组 | 集中在 CLI 的 payload/config 来源、PE 的 registry/double-write、HEVC 的 probe 一致性 |
| 弱断言 | 21 处 | 多为 `is_err()`、`> 0`、`assert_ne!(code, 0)`；错误变体其实可用 |
| 无意义 | 2 处 | 常量与自身比较、名为“匹配 CLI”却未比较 CLI |
| 过时 | 4 类 | 掩码头裸改、旧 magic fixture、失效的运行命令注释、缺样本静默返回 |
| 虚假通过 | 10 处 | 缺样本 `return`、空结果 bootstrap、从不自增的 `failed` 计数 |
| 成本过高 | 4 处 | heavy eval/matrix/coexistence 与 `hevc_matrix_bench` example；慢本身不构成删除理由 |

**整体结论：**

1. **重复集中在 CLI 的输入来源与配置优先级**（`test_cli/sources.rs`、`config.rs`、`cli_unification.rs`），其次是 PE 的 `strategy_registry_roundtrip` / `double_write_refused`，以及 HEVC 的三套 probe 一致性用例。
2. **过时集中在“直接改掩码后的头部字节”**：`fixes.rs:647/665` 写入的是 XOR 掩码区，解出的逻辑值是否越过上限取决于随机盐派生的掩码（实测可命中，但属概率性命中），断言又只有 `is_err()`；逻辑改写用例 `p2_protocol.rs:546` 与 `forge.rs:208` 才是确定性的上限覆盖。批次 1 已把这两个用例改为逻辑重打包（见 §1.1）。
3. **危害最大的不是重复，而是虚假通过**：`real_samples.rs` 的 7 个用例在缺样本时静默 `return`，`temp/` 又被 gitignore，CI 实际零断言通过；`heavy_stego.rs` 的 `report.failed` 恒为 0、eval 空结果 `m_z0=0` 恒过。
4. **不应因慢而删**：`heavy_all_algorithms_png_jpeg_matrix`（30.92 s）与 `heavy_dual_domain_coexistence_matrix`（42 s）分别覆盖“全算法矩阵”和“双域共存”，是本套件中少见的唯一覆盖，建议保留并只收紧断言。
5. 删除必须满足“同一结论已被更靠前或更严格的用例覆盖”。本报告把 11 个用例列为可删除，其余归入合并/改断言/保留。

### 1.1 实施进度

- **批次 1（2026-11-08）已完成**：F01、F05、F07、F08 已修复；F06、F09、F10 与 O02 有实测结论修订（见下表）。
  - 套件总数不变（1110）；默认执行 1083 → 1076，`#[ignore]` 27 → 34。
  - 只改测试，未改生产代码；实证与门禁结果见 `docs/CHANGES-20261108.md`。
- **批次 2（2026-11-08）已完成**：纯重复删除 R01、R02、R03、R04、R07、R08、R14、R17、M01，并折叠 R15 的重复断言。
  - 套件总数 1110 → 1101；默认执行 1076 → 1067，`#[ignore]` 34 不变。
  - 各目标：`lib` 572→571、`test_cli` 146→143、`test_media` 16→15、`test_pe` 42→40、`test_regression` 118→117、`test_security` 25→24。
  - 删除前逐项复核了保留用例的严格超集关系；R03 的唯一独立断言（EOCD 注释长度到 EOF）已迁移到 `review_20261030` 的诱饵 EOCD 用例，覆盖未下降。R16 暂缓（涉及跨目标结构），留待后续批次。
- **批次 3（2026-11-08）已完成**：场景合并 R05、R06、R09、R10、R11、R12、R13（13 个用例并为 6 个，另按 R05 删除 1 个，净减 8）。
  - 套件总数 1101 → 1093；默认执行 1067 → 1059，`#[ignore]` 34 不变。
  - 各目标：`test_cli` 143→137、`test_lifecycle` 157→156、`test_media` 15→14。
  - 合并时原断言全部保留并多数增强：R11 的空回答档新增写入/提取/还原断言；R13 的文件级断言由 2 个字段扩到 5 个，且把 HEIC 容器的报告一致性断言并入同一用例（避免删除 HEIC 路径覆盖）。
- **批次 4（2026-11-08）已完成**：剩余虚假通过 F02、F03、F06、F09、F10 已修复。
  - F02 改用仓库内 JPEG fixture；F03 的 fine-tuning 改用 fixture，标定检测器改为 `#[ignore]` + 缺样本 `panic!`；F06/F10 缺语料/空语料改为显式 `panic!`，F10 增加 `total_tested_carriers > 0`、`total_jobs > 0`；F09 的本地语料缺失改为 `panic!`，可选的 `jpeg_huffman` 语料改为带原因的 `[SKIP]` 输出。
  - 套件总数 1093 不变；默认执行 1059 → 1058，`#[ignore]` 34 → 35（`test_lifecycle` 1→2）。
  - 实证：空 `STRHIDE_HEVC_DIR` / 空 `STRHIDE_TESTDATA_DIR` 均从“静默通过”变为带文件名的 `FAILED`；正常语料下 heavy MP4 与双域共存（80 场景/10 载体）通过。
- **批次 5（2026-11-08）已完成**：弱断言 W01-W20、无意义 M02、过时 fixture/注释 O01/O03/O04 已修复。
  - 断言全部按实际错误变体收紧（个别与报告预设不同）：错误密码多数为 `NoHiddenData`（stealth 语义）、PE 缺密码为 `PasswordWithHint`、篡改密文为 `CorruptedData`、HEVC 截断为 `UnsupportedFormat("...truncated")`、强制档超限为 `SafetyThreshold`。
  - W08 `Ok(_)` 分支改为“用全新 `ExtractOptions` 提取并比对载荷”；首次运行实测 `FAILED: a completed embed must round-trip: Cancelled`，修正后通过，证明新断言确实执行。
  - W13 恒真 `!err.to_string().is_empty()` 改为具体失败文案；实测容量不足报 `UnsupportedFormat("insufficient .text steganographic capacity ...")`，与错误模型注释的 `PayloadTooLarge` 不一致，属生产语义，本批不改。
  - O03/F04 改用仓库内 `tests/assets/small.mp4`（实测 1920x1080 / 50 fps / 1000 ms），缺 fixture 即失败；O01 的伪造头改用官方常量；O04 的运行命令注释全部指向 `--test local_tests` / `--test heavy_tests`。
  - 套件总数 1093、默认执行 1058、`#[ignore]` 35 均不变；门禁全绿，详见 `docs/CHANGES-20261108.md`。
- **O02 前提修订**：实测裸写掩码字节后解出的逻辑值分别为 `46400133` 与 `2066267854`，**确实会命中** `MAX_META_LEN` / `MAX_HINT_LEN` 上限错误；但取值由随机盐派生的掩码决定，属于概率性命中。因此未按原建议删除，改为逻辑重打包并断言具体上限文案，保留读路径集成覆盖。

## 2. 全景表

| 目标 | 用例数 | ignored | 实测耗时 | 判定 |
|---|---|---|---|---|
| `src/lib.rs`（单元 + 内嵌 `#[cfg(test)]`） | 572 | 1 | 1.34 s | 健康；仅 2 处无意义、少量弱断言 |
| `tests/test_cli` | 146 | 0 | 5.97 s | 重复最多（9 个可删/可并） |
| `tests/test_lifecycle` | 157 | 1 | 3.34 s | 覆盖好；2 处静默跳过、1 处弱断言 |
| `tests/test_regression` | 118 | 0 | 0.82 s | 存在 7 个静默跳过（real_samples）与 2 个过时掩码测试 |
| `tests/test_pe` | 42 | 0 | 0.32 s | 2 个可删重复、1 个恒真断言 |
| `tests/test_security` | 25 | 0 | 0.20 s | 与 p2 有 1 处近重复 |
| `tests/local_tests` | 21 | 19 | 20.34 s | 默认只跑 2 个；本地用例基本都有实际断言 |
| `tests/test_media` | 16 | 1 | 0.47 s | 1 个可删重复、1 组合并、1 处静默跳过 |
| `tests/heavy_tests` | 5 | 5 | 55.11 s | 3 处虚假通过；矩阵/共存用例应保留 |
| doctest | 8 | 0 | 0.02 s | 1 个 `let _ = tuned` 无断言 |

补充：`local_tests --ignored` wall 142.34 s（含编译）；`heavy_tests --ignored` wall 148.58 s（含 release 编译 93 s）。两者默认都不在 `cargo test --all-features` 中执行，故默认全量的 12.48 s 不含它们。

**heavy 单项实测：** batch 3.01 s、HEVC/MP4 6.03 s、eval 20.15 s、全算法矩阵 30.92 s、双域共存 42 s。
**local 单项实测：** v3 payload matrix 5.24 s、v3 huffman corpus 0.40 s、HEVC 照片批量 1.87 s、MP4 rejects 0.41 s、ffmpeg PSNR 3.15 s、permute bench 2.64 s、stc kernel bench 4.22 s。

**单元测试模块分布（前 15）：** `stego::hevc` 73、`stego::png` 59、`stego::audio` 57、`stego::jpeg` 51、`structure::adapters` 41、`analysis::tests` 27、`stego::coding` 20、`stego::params` 17、`structure::engine` 13、`core::commit` 11、`stego::options` 11、`stego::prng` 10、`stego::io` 10、`stego::format` 10、`stego::header` 9。其余 32 个模块合计 227。

**带断言 example（不参与 `cargo test`）：** `in_memory` 2 断言/0.39 s、`private_format` 2/0.44 s、`private_profile` 1/0.35 s、`stego_profile` 2/0.77 s、`v3_eval` 1/19.01 s、`hevc_matrix_bench` 5/143.76 s、`hevc_window_sweep` 1（本轮未跑）。四个 `*_stress` example 没有断言宏，只打印结果，不算测试用例。

## 3. 问题明细

### 3.1 重复（R）

| ID | 文件:行 / 用例 | 等价性 | 不等价处 | 处置 |
|---|---|---|---|---|
| R01 | [test_media/heif_hidden_item.rs:18](file:///c:/Home/Projects/strhide/rust/tests/test_media/heif_hidden_item.rs#L18) `test_heif_synthetic_stub_auto_strategy_fallback` | 与 [matrix.rs:643](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/matrix.rs#L643) `password_less_roundtrips_on_every_format`、`review_20261025::heif_without_meta_still_uses_box_uuid` 都验证“无 meta 的 HEIF 走 `box_uuid`” | matrix 用例还断言了选定策略、读写内容与 remove 后字节还原；本用例从不检查实际选中的策略 | **删除**（覆盖由 matrix 与 review 用例保留）→ **已删除（批次 2）** |
| R02 | [test_pe/slack.rs:795](file:///c:/Home/Projects/strhide/rust/tests/test_pe/slack.rs#L795) `strategy_registry_roundtrip` | 与 [codebits.rs:449](file:///c:/Home/Projects/strhide/rust/tests/test_pe/codebits.rs#L449) 同名、同 registry 全量遍历 | codebits 版本覆盖的策略更多，断言更完整；slack 版本是其严格子集 | **删除 slack 版本** → **已删除（批次 2）** |
| R03 | [test_regression/fixes.rs:544](file:///c:/Home/Projects/strhide/rust/tests/test_regression/fixes.rs#L544) `zip_fake_eocd_comment_located_correctly` | 与 [review_20261030.rs:103](file:///c:/Home/Projects/strhide/rust/tests/test_regression/review_20261030.rs#L103) `zip_decoy_eocd_does_not_win_over_the_real_one` 都定位 fake EOCD 注释 | review 用例验证“真 EOCD 胜过诱饵”，更严格；fixes 版本只验证位置算术 | **删除 fixes 版本** → **已删除（批次 2）**，唯一断言“EOCD 注释长度到 EOF”已迁移到 review_20261030 用例 |
| R04 | [test_cli/p2.rs:231](file:///c:/Home/Projects/strhide/rust/tests/test_cli/p2.rs#L231) `read_encrypted_without_password_raises_password_variant` | 与 [verify.rs:584](file:///c:/Home/Projects/strhide/rust/tests/test_cli/verify.rs#L584) `read_encrypted_without_password_returns_password_variant_with_hint` 都断言无密码读加密载荷得到 `Password` | verify 版本还断言 hint 文案与退出码，是超集 | **删除 p2 版本** → **已删除（批次 2）** |
| R05 | [sources.rs:122](file:///c:/Home/Projects/strhide/rust/tests/test_cli/sources.rs#L122) `env_text_is_used_as_payload_source` vs [sources.rs:372](file:///c:/Home/Projects/strhide/rust/tests/test_cli/sources.rs#L372) `env_text_fallback_after_mutex_introduced` | 两者写出后都用 `read --stdout` 断言同一 `STRHIDE_TEXT` 值 | 372 的注释记录了“mutex 引入后 env 仍是兜底”，代码路径完全相同 | **合并**：保留 122，把 372 的回归注释并入 → **已合并（批次 3）**，删除 372 |
| R06 | [sources.rs:161](file:///c:/Home/Projects/strhide/rust/tests/test_cli/sources.rs#L161) `empty_env_text_still_rejected` vs [sources.rs:394](file:///c:/Home/Projects/strhide/rust/tests/test_cli/sources.rs#L394) `missing_payload_source_message_unchanged` | 都断言退出码 1 + `Must provide either` | 一个测“环境变量为空”，一个测“环境变量缺失”；是两个输入边界 | **合并为一个表驱动用例**（两个子例保留断言）→ **已合并（批次 3）**，并补充“失败后载体未变”断言 |
| R07 | [sources.rs:251](file:///c:/Home/Projects/strhide/rust/tests/test_cli/sources.rs#L251) `config_password_file_key_is_warned_and_not_used` | 与 [config.rs:122](file:///c:/Home/Projects/strhide/rust/tests/test_cli/config.rs#L122) `config_password_keys_are_warned_and_not_used` 同属“配置里的密码键被警告且不使用” | config 版本同时覆盖 `password` 与 `password_file` 两个键 | **删除 sources 版本** → **已删除（批次 2）** |
| R08 | [config.rs:57](file:///c:/Home/Projects/strhide/rust/tests/test_cli/config.rs#L57) `cwd_config_is_ignored` | 与 [sources.rs:752](file:///c:/Home/Projects/strhide/rust/tests/test_cli/sources.rs#L752) `cwd_strhide_toml_is_ignored_and_home_config_applies` 都验证 cwd 的 `strhide.toml` 被忽略 | 752 还验证 home 配置仍生效，是严格超集 | **删除 config 版本** → **已删除（批次 2）** |
| R09 | [sources.rs:640](file:///c:/Home/Projects/strhide/rust/tests/test_cli/sources.rs#L640) / [662](file:///c:/Home/Projects/strhide/rust/tests/test_cli/sources.rs#L662) / [682](file:///c:/Home/Projects/strhide/rust/tests/test_cli/sources.rs#L682) 三个 backup 用例 | 同一 `config backup` + `--no-backup` 优先级的三种组合 | 三例分别覆盖 false/覆盖/true，属同一参数矩阵 | **合并为 1 个表驱动用例** → **已合并（批次 3）** |
| R10 | [cli_unification.rs:614](file:///c:/Home/Projects/strhide/rust/tests/test_cli/cli_unification.rs#L614) `stego_credential_flags_are_rejected_and_no_password_roundtrips` vs [663](file:///c:/Home/Projects/strhide/rust/tests/test_cli/cli_unification.rs#L663) `removed_stego_credential_sources_are_inert` | 都以“无密码往返成功 + 已移除凭据源不生效”为结论 | 614 走 flags，663 走 config/env 源；可在一个场景里分两段 | **合并为 1 个用例（两段）** → **已合并（批次 3）** |
| R11 | [verify.rs:504](file:///c:/Home/Projects/strhide/rust/tests/test_cli/verify.rs#L504) vs [556](file:///c:/Home/Projects/strhide/rust/tests/test_cli/verify.rs#L556) | 都验证 `strategy_ask` 非法/空输入回退到第一项 | 一个非数字/越界，一个空回答 | **合并为 1 个表驱动用例** → **已合并（批次 3）**，空回答档同时断言写入/提取/还原 |
| R12 | [facade.rs:315](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/facade.rs#L315) `private_dialect_engine_is_isolated_from_official` vs [344](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/facade.rs#L344) `one_dialect_secret_applies_to_both_domains` | 同一“方言隔离”主题、同一 setup | 315 验证私有引擎读不了官方载体；344 验证同一 secret 同时适用于两个域，方向不同 | **合并为一个 dialect-isolation 场景**，保留两个方向的断言 → **已合并（批次 3）** |
| R13 | [hevc_stego.rs:469](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L469) `test_hevc_embed_capacity_report_matches_probe` vs [548](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L548) `file_level_patch_capacity_matches_the_unified_probe` | 都验证 embed 报告容量与 probe 一致 | 548 是文件级封装，覆盖面更大；469 只差一层 API | **合并到 548**，保留文件级断言 → **已合并（批次 3）**：文件级断言扩到 5 个字段，HEIC 容器一致性断言并入同一用例 |
| R14 | [codebits.rs:332](file:///c:/Home/Projects/strhide/rust/tests/test_pe/codebits.rs#L332) `double_write_refused` | 与 [slack.rs:571](file:///c:/Home/Projects/strhide/rust/tests/test_pe/slack.rs#L571) 同名用例、matrix 的重复写入检查同结论 | slack 版本断言具体错误消息；codebits 版本只断言失败 | **删除 codebits 版本** → **已删除（批次 2）** |
| R15 | [codebits.rs:704-705](file:///c:/Home/Projects/strhide/rust/tests/test_pe/codebits.rs#L704-L705) | 同一用例内对同一 `available` 连写两条重复断言 | 无 | 折叠为一条（用例保留）→ **已折叠（批次 2）** |
| R16 | [common/mod.rs:425](file:///c:/Home/Projects/strhide/rust/tests/common/mod.rs#L425) `verify_test_threads_limit` + [79](file:///c:/Home/Projects/strhide/rust/tests/common/mod.rs#L79) `make_png_fixture_is_decodable_as_1x1` | `common/mod.rs` 被 7 个目标 `#[path]` 引入，两项各执行 7 次 | 线程上限检查是环境属性，与具体目标无关；fixture 自检只需一处 | **上移到 CI preflight 或只保留在 `test_lifecycle`**；若 CI 会单跑各目标则保留并在报告中注明“有意重复”。**批次 2 暂缓（涉及跨目标结构）** |
| R17 | [test_security/rejection.rs:91](file:///c:/Home/Projects/strhide/rust/tests/test_security/rejection.rs#L91) `test_jar_signature_rejection` | 与 [test_cli/p2.rs:266](file:///c:/Home/Projects/strhide/rust/tests/test_cli/p2.rs#L266) `signed_zip_renamed_to_zip_is_rejected` + [p2.rs:296](file:///c:/Home/Projects/strhide/rust/tests/test_cli/p2.rs#L296) `clean_zip_is_still_accepted` 同覆盖“JAR 签名守卫与扩展名解耦” | p2 版本走完整 `write_carrier` 路径，断言 `Rejection` 变体与 `digital signature`/`META-INF` 文案，clean 版本断言写入+读取往返；均强于直接调用 `check_jar_signature` | **已删除（批次 2）** |

### 3.2 弱断言（W）

错误模型已经提供具体变体（[core/errors.rs:29/35/132](file:///c:/Home/Projects/strhide/rust/src/core/errors.rs#L29-L132)），因此“只断言 `is_err()`”基本都可以收紧，而不是删除。

| ID | 文件:行 / 用例 | 现状 | 证据与建议 |
|---|---|---|---|
| W01 | [stego.rs:244](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego.rs#L244) `test_png_hill_content_stego_roundtrip` | 错误密码只 `is_err()` | 同文件 238-239 已断言正确密码的内容；把 244 改为 `matches!(err, StrHideError::Password(_))` → **已修复（批次 5）**：实测 stealth 语义为 `NoHiddenData`，按真实变体断言 |
| W02 | [stego.rs:326](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego.rs#L326) `test_jpeg_uerd_content_stego_roundtrip` | 同上 | 同上，断言 `Password` → **已修复（批次 5）**：实际为 `NoHiddenData` |
| W03 | [stego.rs:872-874](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego.rs#L872-L874) `test_stego_private_default_secret_isolation` | 三条 `is_err()` 不区分“密码错/方言错” | 三个分支语义不同；分别断言 `Password` / `NoHiddenData` / `NoHiddenData` → **已修复（批次 5）**：实测三者均为 `NoHiddenData` |
| W04 | [stego.rs:898](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego.rs#L898) `test_stego_legacy_entries_use_the_official_profile` | 旧入口读私有载体只 `is_err()` | 应断言 `NoHiddenData`（官方入口不应“看见”私有信封） → **已修复（批次 5）** |
| W05 | [stego.rs:1260](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego.rs#L1260) `stego_safety_level_and_enforcement_lifecycle` | 强制模式拒绝只 `is_err()` | 1244-1247 已断言三档容量排序；应断言 `General`/具体超限文案 → **已修复（批次 5）**：实际为 `SafetyThreshold { .. }` |
| W06 | [stego_jpeg_v4.rs:68](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego_jpeg_v4.rs#L68) `v4_chacha_suite_roundtrip_and_tamper_rejected` | 篡改后 `is_err()` | 应断言 `CorruptedData`（篡改不是密码错误） → **已修复（批次 5）** |
| W07 | [stego_jpeg_v4.rs:238/250](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego_jpeg_v4.rs#L238-L250) `v4_tampered_carrier_never_panics` | 仅证明不 panic/失败 | 用例名就是“never panics”，可作为不变量保留；但 250 行应是 `CorruptedData`，否则与 238 重复 → **已修复（批次 5）**：两处翻转均断言 `CorruptedData`，截断保留“不得提取” |
| W08 | [cancellation.rs:128-129](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/cancellation.rs#L128-L129) `cancelling_during_the_run_stops_the_embed` | `Err(Cancelled) => {}` 与 `Ok(_) => {}` 都接受 | 文档声称“必须在下个 checkpoint 暴露 Cancelled”；当前写法等于无断言。保留该用例但把 `Ok(_)` 分支按平台/时序显式断言，或改为 `expect_err` + 允许的竞态条件说明 → **已修复（批次 5）**：`Ok` 分支用全新 `ExtractOptions` 提取并比对；编辑后首次运行 `FAILED: ... Cancelled`，证明断言生效 |
| W09 | [facade.rs:162](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/facade.rs#L162) `content_bytes_probe_reports_capacity` | 只断言 `recommended_max_bytes > 0` | 应断言与实际 embed 后长度/`capacity_bytes` 的关系（同文件 144 的 embed 用例可提供上界） → **已修复（批次 5）**：新增上下界并以推荐容量实际往返 |
| W10 | [hevc_stego.rs:108](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L108) / [185](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L185) / [459](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L459) | 导出/校验失败只 `is_err()` | 按场景断言 `CorruptedData` 或 `UnsupportedFormat` → **已修复（批次 5）**：错误密码 `NoHiddenData`，截断 `UnsupportedFormat("...truncated")` |
| W11 | [hevc_stego.rs:53](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L53)、[309-310](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L309-L310)、[385](file:///c:/Home/Projects/strhide/rust/tests/test_media/hevc_stego.rs#L385) | `cap >= 100` / `> 0` 阈值 | 容量断言与真实载荷长度脱节；用 probe 值 + 实际 embed 长度构造等式/上下界 → **已修复（批次 5）**：`available_slots > 2048`、`max_raw >= 120`、`cap > 120` |
| W12 | [codebits.rs:148](file:///c:/Home/Projects/strhide/rust/tests/test_pe/codebits.rs#L148) / [214](file:///c:/Home/Projects/strhide/rust/tests/test_pe/codebits.rs#L214) | 错误密码只 `is_err()` | 同文件 201 已示范 `NoHiddenData`；错误密码应断言 `Password` → **已修复（批次 5）**：T5 `Password`，stealth `NoHiddenData` |
| W13 | [codebits.rs:1339](file:///c:/Home/Projects/strhide/rust/tests/test_pe/codebits.rs#L1339) | `assert!(!err.to_string().is_empty())` | 任何 `Display` 都非空，恒真；应断言容量不足的具体文案或错误变体 → **已修复（批次 5）**：实测 `UnsupportedFormat("insufficient .text steganographic capacity ...")`；生产语义与 `PayloadTooLarge` 注释不一致，记录不改 |
| W14 | [slack.rs:460/471](file:///c:/Home/Projects/strhide/rust/tests/test_pe/slack.rs#L460-L471)、[540](file:///c:/Home/Projects/strhide/rust/tests/test_pe/slack.rs#L540)、[645](file:///c:/Home/Projects/strhide/rust/tests/test_pe/slack.rs#L601-L645) | 加密错误密码/隐身无密码/篡改信封均只 `is_err()` | 645 所属用例随后仍断言 restore 字节精确，可保留该结论；错误侧改为 `Password` / `NoHiddenData` / `CorruptedData` → **已修复（批次 5）**：缺密码实测 `PasswordWithHint`，错误密码 `Password`，篡改 `CorruptedData` |
| W15 | [review_20261019.rs:692](file:///c:/Home/Projects/strhide/rust/tests/test_regression/review_20261019.rs#L692) `a15_unencrypted_corrupted_metadata_reports_corrupted_not_password` | `if let Err` 分支检查，`Ok` 时静默通过 | 用例名就是结论；改为 `expect_err` + 断言 `CorruptedData` → **已修复（批次 5）** |
| W16 | [cli_unification.rs:214](file:///c:/Home/Projects/strhide/rust/tests/test_cli/cli_unification.rs#L214) `key_file_and_max_payload_round_trip` | 多处 `assert_ne!(code, 0)` | 只证明“失败”，不证明失败原因；应断言 stderr 关键文案或具体退出码（解析错误 2 vs 运行时 1） → **已修复（批次 5）**：`code == 2` 且 stderr 含 `cannot be used with` |
| W17 | [private_format.rs:132-142](file:///c:/Home/Projects/strhide/rust/examples/private_format.rs#L132-L142) | 官方方言读私有载体只 `is_err()`，反方向却断言 `NoHiddenData` | 两个方向应对称断言 → **已修复（批次 5）**：两方向均断言 `NoHiddenData`，`Ok` 即 `panic!` |
| W18 | [private_profile.rs:70-76](file:///c:/Home/Projects/strhide/rust/examples/private_profile.rs#L70-L76) | `Ok(_)` 只打印 `UNEXPECTED`，不失败 | 该 example 声称“prints 都是断言的”；`Ok(_) => panic!`，其余分支也应断言变体 → **已修复（批次 5）**：`Ok` 即 `panic!`，其余 `Err` 亦 `panic!` |
| W19 | [facade.rs:46-53](file:///c:/Home/Projects/strhide/rust/src/facade.rs#L46-L53) doctest | `let _ = tuned;` | 文档说“`engine` 不变”，但没有任何断言；应构造两次调用比较结果，或删除误导性注释 → **已修复（批次 5）**：`assert_ne!(tuned.local_params(), engine.local_params())` |
| W20 | [envelope.rs:910](file:///c:/Home/Projects/strhide/rust/src/structure/envelope.rs#L910) `default_demask_rejects_the_unregistered_strategy_id_zero` | 接受任意 `Err`，甚至接受 `strategy_id != 0` 的 `Ok` | 应断言 `Err(CorruptedData)`，并拒绝 `Ok` → **已修复（批次 5）** |
| W21 | [fixes.rs:647/665](file:///c:/Home/Projects/strhide/rust/tests/test_regression/fixes.rs#L647-L680) | 裸改掩码头 + `is_err()` | **已修复（批次 1）**：改为逻辑重打包（`tamper_header`）并断言具体上限文案；见 O02 |

### 3.3 无意义（M）

| ID | 文件:行 / 用例 | 为什么无意义 | 处置 |
|---|---|---|---|
| M01 | [core/params.rs:426](file:///c:/Home/Projects/strhide/rust/src/core/params.rs#L426) `magic_pair_standard_is_the_official_pair` | `MagicPair::STANDARD.header` 就是由 `STANDARD_HEADER_MAGIC` 构造的，断言是“常量等于它自己” | **删除** → **已删除（批次 2）** |
| M02 | [structure/options.rs:371](file:///c:/Home/Projects/strhide/rust/src/structure/options.rs#L371) `write_defaults_match_the_cli` | 名字声称与 CLI 对比，实际只断言 `WriteOptions::default()` 的结构体字面量，从未调用 CLI | 改名为 `write_defaults_are_stable` 或**删除**；若保留“匹配 CLI”，应真正解析 CLI 默认值 → **已改名（批次 5）**：`write_defaults_are_stable` |

> 说明：其余单元测试没有发现“测标准库/getter 原样返回”一类；`stego::params`、`formats::sniff`、`cli::helpers` 等虽然小，但断言的是项目格式化/识别逻辑，不应归入此类。

### 3.4 过时（O）

| ID | 文件:行 / 用例 | 当前真实代码路径 | 处置 |
|---|---|---|---|
| O01 | [review_20261031.rs:193](file:///c:/Home/Projects/strhide/rust/tests/test_regression/review_20261031.rs#L193) `mp4_with_forged_trailer` / `isobmff_rejects_an_envelope_larger_than_the_file` | 伪造头仍写 `b"STRHIDE\0"`，当前 `STANDARD_HEADER_MAGIC` 是 `[0xb7,0x54,0x2c,0x82,0x7e,0x31,0x1d,0x6e]`（[params.rs:27](file:///c:/Home/Projects/strhide/rust/src/core/params.rs#L27)）。但 `isobmff` 的边界检查在解析头之前（[isobmff.rs:137-148](file:///c:/Home/Projects/strhide/rust/src/structure/adapters/isobmff.rs#L137-L148)），断言仍成立 | **保留用例，修正 fixture 的 magic**；否则它只是“坏头导致拒绝”，不再是“越界信封被拒绝”的证明 → **已修复（批次 5）**：改用 `STANDARD_HEADER_MAGIC` / `CURRENT_VERSION` / `strategy_to_id` / `MP4_UUID_NEUTRAL` / `STANDARD_TRAILER_MAGIC` |
| O02 | [fixes.rs:647](file:///c:/Home/Projects/strhide/rust/tests/test_regression/fixes.rs#L647) `tampered_meta_len_rejected` / [665](file:///c:/Home/Projects/strhide/rust/tests/test_regression/fixes.rs#L665) `tampered_hint_len_rejected` | 头部 40..112 被 XOR 掩码（[envelope.rs:415-424](file:///c:/Home/Projects/strhide/rust/src/structure/envelope.rs#L415-L424)），104..108/108..112 的 `meta_len/hint_len` 在掩码区；读侧解掩码后取值（[494-495](file:///c:/Home/Projects/strhide/rust/src/structure/envelope.rs#L494-L495)）并纳入 AAD（[383-390](file:///c:/Home/Projects/strhide/rust/src/structure/envelope.rs#L383-L390)）。裸写 `0xFFFFFFF0` 解出的逻辑值**实测可命中**上限（`46400133` / `2066267854`），但取值由随机盐派生掩码决定，属概率性命中；原断言仅 `is_err()` | **已修复（批次 1）**：原“走不到上限分支”的前提不成立，删除会让 `hint_len` 失去唯一集成覆盖；改为 `tamper_header` 逻辑重打包 + 精确上限文案断言（详见 §1.1） |
| O03 | [facade.rs:778](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/facade.rs#L778) `test_hevc_mp4_inspect_media_info_and_has_inter` | 依赖本地 `temp/testhevc` 样本；本地实测该用例 `finished in 0.00s`（静默返回） | 改为 `#[ignore]` 或使用仓库内 fixture；**保留用例，修依赖** → **已修复（批次 5）**：改用 `tests/assets/small.mp4`（实测 1920x1080 / 50 fps / 1000 ms），fixture 缺失即失败 |
| O04 | 运行命令注释：[local_bench.rs:13](file:///c:/Home/Projects/strhide/rust/tests/local/local_bench.rs#L13)、[local_corpus.rs:31-32/405](file:///c:/Home/Projects/strhide/rust/tests/local/local_corpus.rs#L31-L32)、[local_media.rs:47/285/388/443/496/781](file:///c:/Home/Projects/strhide/rust/tests/local/local_media.rs#L47)、[heavy_stego.rs:56/731](file:///c:/Home/Projects/strhide/rust/tests/heavy/heavy_stego.rs#L56) | 注释仍指向已合并的旧测试目标（`stc_kernel_bench`、`batch_corpus`、`test_heif_hidden_item`、`test_heif_stego_bridge`、`batch_stego`、`stego_eval`），照抄会找不到测试 | **更新注释**（非删除） → **已修复（批次 5）**：全部改为 `--test local_tests ...` / `--test heavy_tests ...` |

### 3.5 虚假通过（F）

| ID | 文件:行 / 用例 | 为什么会“永远通过” | 处置 |
|---|---|---|---|
| F01 | [real_samples.rs:15](file:///c:/Home/Projects/strhide/rust/tests/test_regression/real_samples.rs#L15) + 7 个用例（26/56/86/153/214/276/338） | `samples_dir()` 返回 `Option`，目录不存在时每个用例直接 `return`；`temp/` 被 gitignore，CI 通常没有样本 | **已修复（批次 1）**：`samples_dir()` 缺目录即 `panic!`，7 个用例加显式 `#[ignore]` 原因；默认运行 7 ignored，`--ignored` 缺语料时明确失败 |
| F02 | [scan.rs:106](file:///c:/Home/Projects/strhide/rust/tests/test_cli/scan.rs#L106) `scan_real_jpeg_sample_does_not_panic` | 样本缺失时静默返回（本地 0.03 s） | 同上；或改用仓库内 JPEG fixture，从“不 panic”升级为“发现指定 finding”。**已修复（批次 4）**：改用 `tests/assets/small.jpg`，断言 `format == JPEG` 且 `risk_score < 30`，fixture 缺失直接失败 |
| F03 | [stego.rs:332](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego.rs#L332) `test_jpeg_uerd_fine_tuning` / [936](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/stego.rs#L936) `test_jpeg_calibration_detector_clean_vs_loaded` | 340-341、945 在 `temp/testfiles` 缺失时 `return` | 使用 `tests/assets/carrier.jpg` 或显式 skip 报告。**已修复（批次 4）**：fine-tuning 改用 `fixture_file("carrier.jpg")`；标定检测器改为 `#[ignore]` + 缺相机语料时带路径 `panic!` |
| F04 | [facade.rs:778](file:///c:/Home/Projects/strhide/rust/tests/test_lifecycle/facade.rs#L778) | 同 O03；本地已静默跳过 | 同 O03 → **已修复（批次 5）**：改用仓库内 `tests/assets/small.mp4`，不再静默返回 |
| F05 | [heavy_stego.rs:187-194](file:///c:/Home/Projects/strhide/rust/tests/heavy/heavy_stego.rs#L187-L194)、[227-229](file:///c:/Home/Projects/strhide/rust/tests/heavy/heavy_stego.rs#L227-L229) | 缺 corpus / 目录为空时打印 `[SKIP]` 后 `return`，ignored 用例仍算“通过” | **已修复（批次 1）**：改为带诊断信息的 `panic!` |
| F06 | [heavy_media.rs:175-180](file:///c:/Home/Projects/strhide/rust/tests/heavy/heavy_media.rs#L175-L180) | ffmpeg 缺失或 corpus 缺失即 `return` | 同上。**已修复（批次 4）**：ffmpeg / corpus / 逐文件缺失均为显式 `panic!`；空 `STRHIDE_HEVC_DIR` 实测 `FAILED` |
| F07 | [heavy_stego.rs:707](file:///c:/Home/Projects/strhide/rust/tests/heavy/heavy_stego.rs#L707) `heavy_batch_stego_corpus` | `BatchReport.failed` 只由 `Default` 初始化（[149-154](file:///c:/Home/Projects/strhide/rust/tests/heavy/heavy_stego.rs#L149-L154)），全文件无自增；`assert_eq!(report.failed, 0)` 恒真 | **已修复（批次 1）**：聚合后按 `total - (passed_lifecycle + passed_rejection)` 计算；注入“丢弃 1 条 outcome”后断言报 `1 carrier(s) produced none` |
| F08 | [heavy_stego.rs:1245-1249](file:///c:/Home/Projects/strhide/rust/tests/heavy/heavy_stego.rs#L1245-L1249) `heavy_stego_evaluation_suite` | `filter_map(... .ok()?)` 收集结果；空结果走 [993-994](file:///c:/Home/Projects/strhide/rust/tests/heavy/heavy_stego.rs#L993-L994) 返回 `(0.0,0.0,0.0)`，`m_z0.abs() < 3.0` 必然成立 | **已修复（批次 1）**：读/解码/嵌入失败改为带文件名的 `panic!`，每个 bpp 聚合前断言 `!results.is_empty()`；强制 `payload_len=0` 时断言报 `no evaluation rows were produced` |
| F09 | [local_corpus.rs:405](file:///c:/Home/Projects/strhide/rust/tests/local/local_corpus.rs#L405)、`local_stego.rs` 的空 corpus 分支 | 无样本时静默返回；ignored 运行仍“成功” | 与 F05 同样改为显式失败或明确的 skip 统计。**已修复（批次 4）**：`local_corpus`/v3 矩阵缺语料 `panic!`；可选 `jpeg_huffman` 语料输出 `[SKIP]` 原因（实测先 `FAILED`，确认不再静默） |
| F10 | `heavy_coexistence.rs` 全文 | 任务循环在无 carrier/job 时零次迭代；缺少 `tested > 0` / `total_jobs > 0` 断言 | 增加前置断言，避免空跑通过。**已修复（批次 4）**：缺 testdata `panic!`，新增 `total_tested_carriers > 0`、`total_jobs > 0`；空目录实测 `FAILED` |

### 3.6 成本（C）

| ID | 对象 | 实测成本 | 是否唯一覆盖 | 处置 |
|---|---|---|---|---|
| C01 | `heavy_stego_evaluation_suite` | 20.15 s | 与 `local_v3_payload_matrix_twenty_images`（5.24 s）、`stego_profile` example 有部分重叠，但其断言本身是 F08 | 先修 F08；若修完后仍只验证同一结论，再与 local v3 矩阵合并 |
| C02 | `heavy_all_algorithms_png_jpeg_matrix` | 30.92 s | 覆盖全算法组合，是唯一矩阵 | **保留**；可把重复的 setup 提到循环外 |
| C03 | `heavy_dual_domain_coexistence_matrix` | 42 s | 唯一双域共存覆盖 | **保留**；`total_jobs > 0` 断言已补（批次 4） |
| C04 | `examples/hevc_matrix_bench.rs` | 143.76 s / 5 断言 | 不在 `cargo test` 内；人工性能评测 | 保留为手动工具，不纳入 CI 必需项；若要纳入，先削减轮次 |

## 4. 重组方案（按 crate / 模块）

> 计数取自 `--list`，包含 `common/mod.rs` 在 7 个目标中的重复项。下表的“去重后”方案把 `common` 的两项辅助测试上移/只保留一处；若暂不动 `common`，总数取括号内的值。
> **批次 2、3 已完成（见 §1.1）**：当前为 `lib` 571、`test_cli` 137、`test_lifecycle` 156、`test_media` 14、`test_pe` 40、`test_regression` 117、`test_security` 24。下表“现状/预计”保留原计划值，其余动作按批次 4+ 执行。
> **批次 4、5 已完成（见 §1.1）**：断言/依赖修复不改变用例数，上表计数不变；批次 6 仅剩 R16（`common/mod.rs` 跨目标重复）。

| 目标 | 现状 | 删除 | 合并 | 改断言/修 fixture | 预计 | 预计耗时变化 |
|---|---|---|---|---|---|---|
| `src/lib.rs` | 572（1 ignored） | M01 | — | W19/W20 | 571 | 1.34 → 1.33 s |
| `test_cli` | 146 | R04、R07、R08（3） | R05、R06、R09、R10、R11（-6） | W16 | 135（137） | 5.97 → 约 5.2 s |
| `test_lifecycle` | 157（1 ignored） | — | R12（-1） | W01-W05、F03、O03 | 154（156） | 3.34 → 约 3.2 s |
| `test_media` | 16（1 ignored） | R01（1） | R13（-1） | W10、W11 | 12（14） | 0.47 → 约 0.40 s |
| `test_pe` | 42 | R02、R14（2） | R15（同用例折叠） | W12、W13、W14 | 38（40） | 0.32 → 约 0.28 s |
| `test_regression` | 118 | R03、O02（3） | — | W15、F01 | 113（115） | 0.82 → 约 0.75 s |
| `test_security` | 25 | R17（1） | — | — | 22（24） | 0.20 s 持平 |
| `local_tests` | 21（19 ignored） | — | — | F09 | 19（21） | 20.34 s 持平（含 19 ignored） |
| `heavy_tests` | 5（5 ignored） | — | — | F05/F07/F08/F10 | 5 | 55.11 s 持平 |
| doctest | 8 | — | — | W19 | 8 | 0.02 s |

**总数：1110 → 1079（若保留 common 重复则 1091）。** 默认全量测试时间预计 **12.48 → 11.7-11.8 s**（CLI 约省 0.7 s，lifecycle/pe/regression 的小用例合计约省 0.1 s；heavy/local 不变）。

**建议执行顺序（分 5 个独立提交批次，本报告不执行）：**

1. **纯重复删除**（零风险）：R01、R02、R03、R04、R07、R08、R14、R17、M01。跑 `cargo test --all-features --all-targets`，确认无降低。
2. **场景合并**：R05、R06、R09、R10、R11、R12、R13；每组保持原断言集合，只合并 setup。
3. **收紧断言**：W01-W21。优先 `Password` / `NoHiddenData` / `CorruptedData` 三态；再处理 `> 0`、`assert_ne!(code,0)`、`is_empty()` 恒真。
4. **修虚假通过**：F01-F10。缺样本一律 `panic`/`#[ignore]`；补 `results.is_empty()`、`total_jobs > 0`、`failed` 自增。此批必须先于任何“精简慢用例”的动作，否则无法判断慢用例是否真的在跑。
5. **修 fixture 与注释**：O01、O03、O04。O01 只需把 `STRHIDE\0` 换成真实 magic；O03 改用仓库 fixture 或标 `#[ignore]`。
6. **（单独一章的）测试空洞补齐**放到后续 PR，避免与精简混在一起。

**注意：** `test_pe/codebits.rs:1305` 的 5900..6400 循环（约 500 次 `inspect`，实测 0.09 s）不是成本问题，且它是 213 B 边界的唯一覆盖，**保留**；只把 1339 的恒真断言改掉。

## 5. 测试空洞（新增建议，不是删除建议）

1. **错误变体三态矩阵**：正确密码、错误密码、无密码对 `read/remove/verify` 三个入口，应分别断言 `Ok` / `Password` / `NoHiddenData`，并覆盖有 hint 与无 hint 两种头部。当前多数用例只测其中一态。
2. **跨引擎一致性**：同一 payload 在 JPEG/PNG/HEVC/WAV/FLAC 上执行 write→inspect→verify→read→remove→restore，断言恢复字节与 SHA-256 一致。`test_lifecycle/matrix.rs::run_cell` 已覆盖“格式矩阵”，但算法维度不足。
3. **CLI 退出码矩阵**：解析错误（2）、运行时错误（1）、成功（0）三类，按 `write/read/remove/verify/inspect` 分别断言；现有多处只断言 `assert_ne!(code, 0)`。
4. **取消语义的确定性覆盖**：目前只覆盖“预取消”，运行中取消接受 `Ok` 或 `Err`，等于没有断言；应提供可控的慢编码器/检查点注入。
5. **静默跳过的 CI 策略**：缺样本、缺 corpus、缺 ffmpeg 不应让用例"通过"；建议统一 `require_fixture!` 宏，缺依赖时 `panic!`（本地）或 `#[ignore]` + 计数（CI），并在报告里输出 skip 明细。
6. **篡改矩阵**：头部每个字段（version、flags、strategy_id、offset_delta、meta_len、hint_len、trailer CRC）各一条“逻辑改写”用例；当前只覆盖了部分字段，且存在 O02 这样的裸改写误区。
7. **doctest 语义**：`facade.rs` 的 `with_local_params` 应验证“原 engine 未变 + tuned 只影响本次调用”，而不是 `let _ = tuned`。
8. **空载荷/边界载荷**：0 字节、1 字节、恰好容量、容量 + 1、超长文件名；PE codebits 已有 213 B 边界，其他引擎缺少等价覆盖。

## 6. 附录：复核命令

```bash
cd rust
# 全量清单与 ignored 清单
cargo test --all-features -- --list > temp/audit/list_all.txt
cargo test --all-features -- --list --ignored > temp/audit/list_ignored.txt
cargo test --doc --all-features -- --list

# 逐目标计时（取 libtest 的 finished in）
cargo test --all-features --lib
cargo test --all-features --test test_lifecycle
cargo test --all-features --test test_cli
cargo test --all-features --test test_regression
cargo test --all-features --test test_pe
cargo test --all-features --test test_security
cargo test --all-features --test test_media

# 默认忽略的套件（单独计时）
cargo test --release --all-features --test local_tests -- --ignored
cargo test --release --all-features --test heavy_tests -- --ignored

# 带断言的 example
cargo run --release --all-features --example in_memory
cargo run --release --all-features --example private_format
cargo run --release --all-features --example private_profile
cargo run --release --all-features --example stego_profile
cargo run --release --all-features --example v3_eval
cargo run --release --all-features --example hevc_matrix_bench
```

**计时口径说明：** 上述 `finished in` 不包含 cargo 编译/链接；报告中另列的 wall time（默认 23.09 s、local 142.34 s、heavy 148.58 s）包含 cargo 启动与编译，不能与单项测试时间直接相加。

**本轮临时产物：** `rust/temp/audit/` 下的 `list_all.txt`、`list_doc.txt`、`names.tsv`、`unit_modules.txt`、`example_times.txt`、`heavy_local_times.txt` 仅用于本次统计，报告落盘后删除。
