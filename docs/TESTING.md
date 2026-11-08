# 测试策略 (Testing)

> 这个项目的测试有一条硬约束：**默认参数下的输出字节必须逐字节不变**。任何影响输出的改动，先过基线，再谈其它。

---

## 1. 三条基本原则

1. **字节级确定性**：写入路径的浮点运算全部走项目自有的 [detmath](api/spec/DETMATH.md)，因此同一输入在任何平台上产出同样的字节。维护者本地用字节基线守住这个不变量（见 §4，注意基线不进版本库）。
2. **fail-closed**：还原不一致、容量不足、签名文件、未知版本一律报错，不允许"尽力而为"地输出可疑结果。测试专门验证这些拒绝路径。
3. **按成本分层**：默认 `cargo test` 在 1 分钟内跑完；耗时的语料级评测用 `#[ignore]` 单独跑，避免把日常循环拖慢。

## 2. 测试分层

| 层 | 位置 | 覆盖 | 何时跑 |
| :--- | :--- | :--- | :--- |
| 单元测试 | `src/**` 的 `#[cfg(test)]` | KDF/AEAD 向量、nonce 派生、位打包、代价模型、错误映射 | 每次改动 |
| 集成：生命周期 | `tests/test_lifecycle`（`matrix` / `stego` / `stego_jpeg_v4`） | 各载体注入与位精确还原矩阵；内容域 HILL/UERD/STC 生命周期；JPEG V4 信封契约（超块、扩展、套件、槽位） | 每次改动 |
| 集成：CLI | `tests/test_cli` | 二进制级行为：参数解析、退出码、覆盖保护、`--auto` 跨域回退（**受 `cli` feature 门控**） | 每次改动（带 `--all-features`） |
| 集成：多媒体 | `tests/test_media`（`heif_stego_bridge` / `hevc_stego`） | HEIF 桥接与安全处理、HEVC 容量模型、往返梯度、SPS 缩放 | 每次改动 |
| 集成：PE | `tests/test_pe`（`codebits` / `slack`） | x86/x64 指令替换通道、节对齐填充（零体积膨胀） | 改动 PE 时 |
| 集成：回归 | `tests/test_regression`（`fixes` / `p2_fixes` / `p2_protocol`） | 历史缺陷（脏尾、EOCD 伪装）、错误传播、PDF xref 流等协议边界 | 每次改动 |
| 集成：安全 | `tests/test_security`（`rejection` / `stealth` / `forge`） | 拒绝签名文件/JAR/APK、stealth 掩码一致性、伪造尾部不得驱动分配 | 每次改动 |
| 私有方言 | `tests/private_provenance.rs` | 私有 profile 七项隔离断言（见 [PRIVATE_BUILD.md](PRIVATE_BUILD.md) §5） | 改动方言/标签时 |
| 快速批量 | `tests/local_tests.rs`（`local_` 前缀，全部 `#[ignore]`） | 小语料回归、小型基准 | 提交前 |
| 重型评测 | `tests/heavy_tests.rs`（`heavy_` 前缀，全部 `#[ignore]`） | 全算法矩阵、HEVC MP4 语料、批量隐写、共存场景 | 改动代价模型/引擎时 |
| 压力测试 | `examples/{png,jpg,hevc,audio}_stress` | 8 线程并发、密钥轮换、真随机载荷 + SHA-256 往返、20/40/80/100% 填充 | 改引擎或并发路径时 |
| 桌面端 | `gui/tests/{unit,e2e,e2e-real}`、`gui/src-tauri/tests/cross_validation.rs` | IPC 参数组合、UI 交互与对比度、真实进程、GUI↔CLI 双向校验 | 改动 `gui/` 时 |

## 3. 命令速查

> 下面的 `cargo` 命令在 `rust/` 里执行；`scripts/` 下的检查脚本在仓库根目录执行（脚本内部按自身位置定位仓库根，不依赖当前目录）。

```bash
cd rust

# 全量（默认 feature 集不含 cli，所以 CLI 测试必须带 --all-features）
cargo test --all-features --all-targets

# 快速批量（约 30–60 秒）
cargo test local_ --all-features -- --ignored

# 重型评测（约 2 分钟起）
cargo test heavy_ --all-features -- --ignored

# 单个集成套件
cargo test --all-features --test test_security

# 私有方言隔离
cargo test --all-features --test private_provenance

# 压力测试（release 构建，否则慢到不可用）
cargo run --release --all-features --example png_stress
cargo run --release --all-features --example jpg_stress
cargo run --release --all-features --example hevc_stress
cargo run --release --all-features --example audio_stress
```

桌面端：

```bash
cd gui
pnpm build
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
pnpm test:unit && pnpm test:cross && pnpm test:e2e && pnpm test:e2e:real
```

`test:e2e:real` 需要已构建的 `StrHideStudio` 产物，CI 之外的本地环境先跑 `pnpm tauri build`。

## 4. 字节级基线

```bash
# 在仓库根目录执行
python scripts/baseline_hash.py --check    # 与 temp/baseline/baseline.json 逐例比对
python scripts/baseline_hash.py --write    # 冻结新基线（仅在确认改动是有意的时候）
```

**基线是本地工件，不在版本库里。** 文件在 `temp/baseline/baseline.json`，而 `temp*` 位于 `.gitignore`，因此：

- CI **不跑**基线校验（它跑 `import_lint.py` 与 `check_feature_matrix.py`）；
- 新克隆的仓库没有基线，`--check` 会因缺少参考而无法比对，需要先在完整语料上 `--write`；
- 拉取上游改动后若基线过期，先确认差异来源，不要直接重写。

- 基线覆盖 **28 个用例**，逐例记录输出文件的 SHA-256（见 [api/spec/CRYPTO.md](api/spec/CRYPTO.md) §4 第 7 项）。
- 它守的是"本仓库自身输出不漂移"，**不是**互操作判据：外部实现无法获得同一语料。
- 出现不一致时，先判断是"修复带来的预期变化"还是"回归"。前者要同时更新 [CHANGELOG.md](../CHANGELOG.md) 并说明旧载体是否失效；后者是一个 bug，不是基线的问题。
- 改动任何解析/注入路径、代价模型、浮点运算、压缩策略、槽位规则，都必须先跑这一关。

## 5. 架构边界与特性矩阵

```bash
# 仓库根目录
python scripts/import_lint.py            # 分层红线：stego 不得依赖 structure，core 不得反向依赖上层
python scripts/check_feature_matrix.py   # 各 feature 组合是否都能独立编译
python scripts/cost_vectors_check.py     # 代价模型向量与规范一致
python scripts/gen_third_party_licenses.py --check   # 依赖变动后许可证清单是否过期
```

改动 `Cargo.toml` 的 feature 门控、`#[cfg(feature = ...)]` 分支、或模块可见性时，`check_feature_matrix.py` 是必跑项——单独编译某个 feature 组合经常能暴露"只在 all-features 下才编得过"的问题。

## 6. 结果如何判断

| 现象 | 含义 | 处置 |
| :--- | :--- | :--- |
| 基线不一致，但往返测试通过 | 输出字节变了，语义没变 | 确认是否预期；是则 `--write` + CHANGELOG |
| 往返测试失败 | 读写不对称，真 bug | 不要动基线，先修 |
| `private_provenance` 失败 | 方言隔离被削弱（某个标签/盐漏改或复用） | 见 [PRIVATE_BUILD.md](PRIVATE_BUILD.md) §4 的三个常见错误 |
| `test_security::forge` 失败 | 伪造的长度字段被用于分配 | 视为安全问题，按 [SECURITY.md](../SECURITY.md) 处理 |
| 压力测试偶发失败 | 并发或密钥轮换下的竞态 | 记录线程数/填充率/算法，最小化复现 |

## 7. 已知未覆盖

- **外部第三方实现的互操作**只在开发期用 Python 读取器验证过 PNG 载体，未纳入 CI。
- **统计检测率**没有回归门禁：代价模型改动后检测率可能变化，目前只靠 `heavy_` 与人工评测，不做阈值断言。
- **GUI 在真实 macOS/Linux 桌面上的行为**依赖 CI runner，本地只覆盖 Windows。
