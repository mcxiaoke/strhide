# crates.io 发布说明

> 适用对象：`rust/` 这个 crate（`strhide`）。GUI 通过 `path = "../../rust"` 依赖，不受影响。
> 结论先行：**只有一个 fork 需要发布**（`strhide-rusty-h265`），`oxideav-h265` 用上游正式版。

## 1. crates.io 的硬约束（2026-11 实测）

| 约束 | 内容 | 影响 |
|---|---|---|
| 无命名空间 | 没有 npm 的 `@scope/name`，名字全局唯一、扁平、先到先得 | fork 必须换一个全新包名 |
| 名字等价规则 | 大小写不敏感，`-` 与 `_` 等价（`serde-json` 请求会命中 `serde_json`） | `rusty-h265`、`RUSTY_H265` 都是同一个名字，不能用来区分 fork |
| 字符与长度 | 仅 ASCII 字母/数字/`-`/`_`，首字符不能是数字，≤ 64 字符 | — |
| 禁 git 依赖 | 打包时 git 源被**剥离**，按 crates.io 同名版本解析 | 即使写 `git` + `version` 也会丢补丁，详见 §2 |
| 元数据必填 | `description` + `license`（或 `license-file`） | 缺一个 `cargo publish` 直接失败 |
| 体积 | `.crate` ≤ 10 MB | 测试夹具必须 `exclude` |
| 不可撤回 | 版本不能覆盖、不能重发、代码不能删，只能 `cargo yank` | 发错只能 yank + 升版本；整包删除仅限 72 小时内等特例 |
| fork 合规 | 保留原 LICENSE 与署名、`description` 写明 fork 来源、不得冒充官方 | 满足即可，crates.io 不禁止 fork |

## 2. 本地 vendor 与 git 依赖为什么行不通

```text
$ cargo package --no-verify --allow-dirty
error: all dependencies must have a version requirement specified when packaging.
dependency `oxideav-h265` does not specify a version
Note: The packaged dependency will use the version from crates.io,
the `git` specification will be removed from the dependency declaration.
```

第二行注释是关键：`git` 源在打包阶段就被丢弃了。所以「`version` + `git` 双写」不是解法 —— 它会静默地把
依赖回落到 crates.io 上的同名包（即上游版本），本地能编、线上却少了补丁。**唯一可行解是让改动真的以新
包名出现在 registry 上。**

## 3. 当前的依赖结构

| 依赖 | 来源 | 说明 |
|---|---|---|
| `oxideav-h265` | crates.io `0.0.16` | 上游正式版，**不用 fork**，见 §4 |
| `rusty_h265` | crates.io `strhide-rusty-h265` `0.1.x` | 自家 fork，`package =` 别名引入 |
| `rusty_h265-accel` | crates.io `0.6.2` | fork 仓库里未改动，直接用上游，不重新发布 |
| `oxideav-core` / `rusty_alloc-api` | crates.io | 未改动 |

`rust/Cargo.toml` 里的写法：

```toml
oxideav-h265 = { version = "0.0.16", optional = true }
rusty_h265 = { package = "strhide-rusty-h265", version = "0.1", optional = true }
```

`package =` 只改「从哪个包来」，依赖的 key 仍是 `rusty_h265`，因此 `content-hevc` 特性里的
`dep:rusty_h265` 和源码里的 `rusty_h265::` 路径全部无需改动。

## 4. oxideav-h265 为什么不需要 fork

2026-11-07 核查结论：

- strhide 全仓库对 `encode_flush` 0 引用（fork 的唯一补丁就是它），`engine.rs` 只用到
  `cabac::ContextModel`、`encoder::bitwriter::BitWriter`、`encoder::cabac::CabacEncoder`，都是上游既有 API。
- `Cargo.lock` 原先锁定的 `db02660`（tag `v1-20261024`）经 `git log upstream/HEAD..db02660` 核对为**空**，
  即纯上游代码、不含任何 fork 提交。
- vendor 目录里的 HEAD 反而是坏的：合并上游 master 后引用了 `Frame::StreamParams` / `output_params`，
  而 crates.io 最新的 `oxideav-core 0.1.41` 没有这些，`cargo check` 直接失败。
- 换成 crates.io `oxideav-h265 0.0.16` 后：`cargo test --all-features --all-targets` 全绿，
  `baseline_hash.py --check` **28/28 逐字节一致**（含 HEVC 的 MOV/HEIC 用例）。

若将来确实需要 fork 补丁（例如启用 `encode_flush`），再按 §5 的命名约定发布 `strhide-oxideav-h265` 即可。

## 5. fork 的命名与维护约定

- 包名一律 `strhide-<上游包名>`，如 `strhide-rusty-h265`。
- **`[lib] name` 保持与上游一致**（`rusty_h265`）：这样上游仓库里 examples/tests/bin 的 `rusty_h265::` 路径
  不用改，未来 `git merge upstream` 不会满屏冲突。
- 版本走自己的线（`0.1.0` 起），`description` 写明 fork 自哪个上游版本、并声明不是通用库。
- `repository` 指向自己的 fork，`authors` 保留原作者并追加自己。
- 仓库内 `crates/rusty_h265-accel` 标 `publish = false`（名字不属于我们，且代码与上游一致）。

## 6. 发布流程

### 6.1 前置

- crates.io 账号已通过邮箱验证，`cargo login` 已写入 token。
- **本机 `~/.cargo/config.toml` 把 `crates-io` 替换成了 aliyun 镜像**，所以发布必须显式指定
  `--registry crates-io`，否则报 `crates-io is replaced with non-remote-registry source`。
- `cargo publish` 要求工作区干净；未提交时加 `--allow-dirty`（只建议 dry-run 时用）。

### 6.2 发布 fork（首次或 fork 升级时）

```bash
cd C:/Home/Projects/strhide-vendor/rusty_h265
cargo publish -p strhide-rusty-h265 --dry-run --registry crates-io   # 打包 + 本地 verify，不上传
cargo publish -p strhide-rusty-h265 --registry crates-io
```

`--dry-run` 已验证通过：打包 30 文件 / 448 KiB（压缩后 129 KiB），verify 阶段自动从 registry 取
`rusty_h265-accel 0.6.2`。

### 6.3 发布主包

```bash
cd C:/Home/Projects/strhide/rust
cargo publish --dry-run --registry crates-io     # 等 fork 索引同步 1~5 分钟后再跑
cargo publish --registry crates-io
```

顺序不能反：`strhide` 的 verify 阶段会去 registry 找 `strhide-rusty-h265 0.1.x`，没同步就报找不到。

### 6.4 发布后自检

```bash
cd C:/Home/Projects/strhide/rust && cargo build --all-features    # 刷新 Cargo.lock（原先是 path/git 源）
cargo add strhide --features content-hevc --dry-run               # 确认消费者能解析到 fork
```

注意 `content-hevc` 不在默认特性里，`cargo publish` 的 verify 不会编译到这条路径，必须单独确认一次。

### 6.5 发布前本地开发（fork 尚未上传时）

`strhide` 会暂时编不过。用一次性覆盖（**不要写进 Cargo.toml**）：

```bash
cd C:/Home/Projects/strhide/rust
cargo check --all-features \
  --config 'patch.crates-io.strhide-rusty-h265.path="C:/Home/Projects/strhide-vendor/rusty_h265/crates/rusty_h265"'
```

## 7. fork 跟进上游

```bash
cd C:/Home/Projects/strhide-vendor/rusty_h265
git fetch upstream && git merge upstream/master        # 冲突点集中在 observer/decoder 等被改过的文件
# 改 crates/rusty_h265/Cargo.toml 的 version（workspace.package.version），跑测试
cd ../.. && cargo publish -p strhide-rusty-h265 --registry crates-io
```

`rusty_h265-accel` 若上游升版，同步改 `[workspace.dependencies]` 里的 `version = "0.6.x"` 与
`crates/rusty_h265-accel/Cargo.toml` 的 version，保持一致即可。

## 8. 出问题时

- 版本有问题：`cargo yank --version X.Y.Z -p <pkg> --registry crates-io`（yank 只影响新解析，已有 lockfile 不受影响）。
- 包名发错：72 小时内且无依赖、单 owner 可申请删除，否则只能换名重发。
- 需要第二 owner：`cargo owner --add <github-id> -p <pkg> --registry crates-io`。
