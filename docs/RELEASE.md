# 发布流程 (Release)

> 仓库存量：版本号 `0.9.3`，尚未 `1.0`。发布由 GitHub Actions 完成，本机脚本只用于自建分发包。

---

## 1. 三条发布通道

| 通道 | 触发 | 产出 | 工作流 |
| :--- | :--- | :--- | :--- |
| CLI 二进制 | push tag `v*` | 7 个可执行文件 + `SHA256SUMS.txt` | [.github/workflows/release.yml](../.github/workflows/release.yml) |
| crates.io | push tag `v*` | `strhide` crate | [crates.yml](../.github/workflows/crates.yml) |
| 桌面端 | push tag `v*` 或 `gui-v*` | macOS `.dmg`、Windows `.msi`/`.exe`、Linux `.deb`/`.AppImage` | [gui-release.yml](../.github/workflows/gui-release.yml) |

三条通道都以 **`ci.yml` 的 quality job 为前置门禁**（fmt、clippy `-D warnings`、`import_lint`、`cargo test --release --all-features --all-targets`、rustdoc、doctests、feature matrix，在 ubuntu 与 windows 上各跑一遍）。门禁挂了，后面的构建与发布不会开始。

`crates.yml` 还有两道保险：

1. tag 必须与 `rust/Cargo.toml` 的版本一致（`v0.9.4` 配 `0.9.3` 的 manifest 会直接 error）；
2. 版本若已存在于 crates.io，跳过发布并给 warning——不会静默重复发。

## 2. 产物矩阵

| 文件 | 目标三元组 | 备注 |
| :--- | :--- | :--- |
| `strhide-windows-x86_64.exe` | `x86_64-pc-windows-msvc` | 基线 |
| `strhide-windows-x86_64-avx2.exe` | 同上 + `-C target-cpu=x86-64-v3` | 要求 AVX2 |
| `strhide-windows-aarch64.exe` | `aarch64-pc-windows-msvc` | `windows-11-arm` runner |
| `strhide-linux-x86_64` | `x86_64-unknown-linux-musl` | 全静态 |
| `strhide-linux-x86_64-avx2` | 同上 + v3 | 全静态 |
| `strhide-linux-aarch64` | `aarch64-unknown-linux-musl` | 全静态 |
| `strhide-macos-universal2` | `lipo` 合并 aarch64 + x86_64 | 通用二进制 |
| `strhide-<version>-licenses.zip` | — | `LICENSE` + `NOTICE` + `docs/licenses/THIRD_PARTY_LICENSES.md` + `docs/licenses/*.md`，由 release job 自动打包 |
| `SHA256SUMS.txt` | — | 上面所有资产的校验和 |

发布前必读的两点：

- **只发 `strhide` / `strhide.exe`**。`sth`、`sthc`、`sths`、`sthv` 由源码构建产出，预编译包不含它们。
- **产物未签名**。CI 里没有 Apple 证书、没有 Windows 代码签名、也没有 Tauri updater 密钥。[INSTALL.md](INSTALL.md) 已写明 SmartScreen/Gatekeeper 的处理方式；不要在没有证书的前提下宣称"已签名"。

`SHA256SUMS.txt` 由 `release.yml` 自动生成（对 `dist/` 下除自身外的文件排序后 `sha256sum`），许可证包也包含在内。

许可证包是 Apache-2.0 §4(a)/(d) 的履约动作：二进制分发必须附带许可证与 `NOTICE`。它由 release job 在发布前从仓库现取的 `LICENSE`、`NOTICE`、`docs/licenses/THIRD_PARTY_LICENSES.md` 与 `docs/licenses/` 组装，**不要手工上传**，否则会和代码里的许可清单脱节。

桌面端安装包目前**不内嵌**这些文件，桌面端也**不带**校验和清单：`gui-v*` 单独发布时，许可证以同版本 `v*` Release 里的 licenses 包为准。这是已知缺口，记录在 [ROADMAP.md](ROADMAP.md)。

## 3. 发布前检查清单

版本号有 **4 处**必须一致：

- `rust/Cargo.toml` → `[package] version`
- `gui/src-tauri/Cargo.toml` → `[package] version`
- `gui/src-tauri/tauri.conf.json` → `version`
- `gui/package.json` → `version`

然后逐条走：

```bash
# 1. 门禁全绿（本地先跑一遍，别指望 CI 替你发现问题）
cd rust
cargo build --release --all-features
cargo test --all-features --all-targets
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings

# 仓库根目录
python scripts/import_lint.py
python scripts/check_feature_matrix.py
python scripts/baseline_hash.py --check
python scripts/gen_third_party_licenses.py --check
```

```bash
# 2. 文档
#    CHANGELOG.md 已在顶部写好本次条目（Keep a Changelog）
#    线格式若有变更，spec/ 与 CORRECTIONS.md 已同步
#    新增文档已挂进 docs/README.md 的索引
#    依赖有变动时：python scripts/gen_third_party_licenses.py（并提交 docs/licenses/）

# 3. crates 打包自检（不真正上传）
cd rust && cargo package --no-verify --allow-dirty
#    体积 ≤ 10 MB，测试夹具已 exclude，license/description 齐全

# 4. 桌面端
cd gui && pnpm build && pnpm test:unit && pnpm test:cross && pnpm test:e2e
```

## 4. 打 tag 与发布

```bash
git tag -a v0.9.4 -m "strhide 0.9.4"
git push origin v0.9.4
```

推送后依次发生：

1. `ci.yml` quality → 通过后 fan-out；
2. `release.yml` 构建 7 个产物 → 生成 `SHA256SUMS.txt` → 创建 GitHub Release（release notes 自动生成）；
3. `crates.yml` 校验版本 → Trusted Publishing（OIDC，无长期 token）→ `cargo publish`；
4. `gui-release.yml` 用 `tauri-action` 构建三平台安装包并挂到同一个 Release。

只发桌面端时用 `gui-v*`（例如 `gui-v0.9.4`），不会触发 crate 与 CLI 通道。

## 5. fork 的发布顺序

`content-hevc` 依赖 `strhide-rusty-h265`（自家 fork，见 [CRATES_PUBLISH.md](CRATES_PUBLISH.md)）。**改过 fork 就先发 fork，再发主 crate**——否则主 crate 会在 `cargo publish` 阶段解析到旧版 fork，或者本地能编、线上少补丁。

同理，`crates.io` 版本不可覆盖、不可重发，只能 `cargo yank`；发错版本的唯一补救是 yank + 升版本重发。

## 6. 本机打包（不发 GitHub）

```bash
python scripts/release.py                 # CLI + GUI，按当前版本号
python scripts/release.py 0.9.4 --cli-only
python scripts/release.py --skip-build    # 只对已有产物打包
python scripts/release.py --dry-run       # 打印步骤不执行
```

产物落在 `release/v<version>/`：`strhide-cli-v<version>-<platform>.zip` 内含 4 个 CLI 入口与文档；GUI 走 `strhide-gui-v<version>-<platform>-portable.zip`；同时生成 `SHA256SUMS.txt`。这条路径用于内部分发，不替代 tag 发布。

## 7. 发布后

- 核对 Release 页：7 个 CLI 产物 + `strhide-<version>-licenses.zip` + `SHA256SUMS.txt` 齐全，GUI 安装包齐全。
- 抽查下载：`sha256sum -c SHA256SUMS.txt --ignore-missing`。
- 核对 crates.io 上的版本、README 渲染、feature 列表与 `docs.rs` 构建结果。
- 如果这一版改了线格式：在 Release notes 里明确"旧载体是否仍可读"，不要让用户自己试。
- 发现问题需要撤回时：crate 用 `cargo yank --version <v>`，二进制改 Release 为 pre-release 或删除资产；不要删除 tag 后重推，会破坏已下载者的校验。
