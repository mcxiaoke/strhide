# 静默吞错（error swallowing）审计报告

- 审计时间：2026-11-06 18:30
- 范围：`rust/src`（121 个 .rs）、`gui/src-tauri/src`（6 个 .rs）、`gui/src`（32 个 .ts/.tsx）
- 性质：只读审计，未修改任何代码
- 方法：正则全量命中 → 逐条人工读上下文判定 → 按"错误信息最终去了哪"分类

---

## 一、命中面（先看规模）

| 模式 | Rust 命中数 | 说明 |
|---|---|---|
| `.ok()` | 84 | 把 `Result` 转 `Option`，一半是 `?` 向上传播（正常），另一半是丢弃 |
| `let _ = expr` | 98 | 丢 `#[must_use]`；含大量测试清理代码 |
| `Err(_) =>` | 61 | 未绑定错误变量，结构上不可能记录原因 |
| `if let Ok(..)` | 31 | 无 `else` 分支时错误被丢 |
| `_ => {}` | 12 | 多为 match 分支正常兜底，非错误路径 |
| TS `catch` | 31 | 0 处完全空 `catch {}`（除去注释掉的），但 11 处只 `console.*` |

数字本身不代表问题。真正的判据是下面三问。

## 二、判定标准

一个吞错点应当归入哪一类，只看"错误信息是否还有别的出口"：

- **A 可吞（不处理是对的）**：失败等价于语义上的"否"，且这个"否"就是调用方要的答案。例：`detect()` 读文件头失败 → 该格式不匹配；`SystemTime::duration_since(EPOCH)` 失败 → 用 0。
- **B 需记账（应为 debug/warn 日志）**：失败不改变主流程结果，但属于"本不该发生的降级"，事后排障必须能看到。例：缓存锁中毒、目录 fsync 失败、日志通道 emit 失败。
- **C 需回传 caller（必须改变返回值/诊断字段）**：失败与"不存在/无数据/不支持"是两件事，被合并后用户会得到**错误结论**。

现状的问题集中在 **C 类被当成 A 类处理**，而 **B 类几乎全空**——因为内核根本没有可用的日志出口（见第五节）。

## 三、P1：会把"失败"说成"没有"（用户得到错误结论）

### P1-1 能力表加载失败 → 每个文件都被判"格式不支持"

- `gui/src/hooks/useCapabilities.ts:18-21`：`getCapabilities()` 失败 → `return []`，只 `console.error`
- `gui/src/lib/queue.ts:32-34`：`capabilities.find(...)` 找不到 → `{supported:false, reason:"formatUnsupported"}`
- 消费方：`useFileQueue` 在四个视图里全部使用（ScanView:56、ExtractView:27、StegoEmbedView:25、HideStructureView:23）

后果：IPC 失败（重启 race、序列化失败、权限）时，用户拖入的任何文件都会显示"格式不支持"，而真实原因只在 DevTools 里。这是本次审计里**唯一会让用户直接做出错误判断**的前端路径。

建议：
1. `useCapabilities` 保留三态（loading / ready / error），失败不要把 `[]` 当成"空能力集"；
2. `useFileQueue` 在 `caps === null`（未知）时不做格式判定，直接提示"正在读取格式能力，请稍后重试"，而不是 `formatUnsupported`；
3. `classifyFormat` 增加 `unknown` 分支，与"cap 存在但不支持该 need"区分开（后者才是 `noStego`/`noStructure`）。

### P1-2 探测诊断字段 `note` 已生成，但两端都不显示

这是"半截工程"：错误信息被搬到了一个没人读的地方，效果等同于吞掉。

- 生产端（正确做法）：`rust/src/stego/jpeg/engine.rs:1442-1446` 把 preflight 失败写进 `empty_info.note`；`:1611-1618` 把畸形 extension 区写进 `note`。
- 消费端 CLI：`rust/src/cli/cmd_diag.rs:25-55` `print_content_domain()` 只打印 `has_hidden_data` 与 `content_error`，**从不打印 `cs.note`**。`inspect` 文本模式因此丢掉了 JPEG 引擎已经算出来的全部诊断。
- 消费端 GUI：`gui/src/types/strhide.ts:62` 定义了 `note?`，全仓 `gui/src` 无任何渲染点（`rg '\bnote\b'` 只命中 FileQueue 的局部变量）。

建议（改动可控）：
1. `print_content_domain()` 在 `has_hidden_data == false` 且 `note.is_some()` 时输出 `? {note}`，与既有 `content inspection failed` 行同一缩进风格；
2. GUI 在 `ScanView`/`StegoEmbedView` 的结果区把 `content_stego.note` 作为次要说明文本展示（`has_hidden_data=false` 时尤其重要，用于区分"确认没有"和"没检查成"）。

### P1-3 `content_error` 在 GUI 完全未渲染

- 类型：`gui/src/types/strhide.ts:87`
- 生产端：`rust/src/facade.rs:574-583` 明确注释了"不要用 `.ok()` 吞掉，调用方需要区分无载荷与校验器跑不起来"（R3 P1-1 的修复）
- 消费端：`rg content_error gui/src` 只命中类型定义，`ScanView.tsx:28-48` 只看 `content_stego.has_hidden_data`

后果：CLI 打印了这条错误（`cmd_diag.rs:51-54`），GUI 用户看不到。同一份修复只在 CLI 侧生效。

建议：`ScanView` 在 `content_error` 存在时，把结果行从"未发现隐写"降级为"内容域校验未完成"并附错误摘要。

### P1-4 `catch_unwind` 丢掉了 panic 文本

- `gui/src-tauri/src/state.rs:293-297`：
  ```rust
  match unwind_res {
      Ok(res) => res,
      Err(_) => Err(StrHideError::General("Internal engine panic caught safely at GUI worker boundary".into())),
  }
  ```
- `gui/src-tauri/src/commands/*.rs` 中同类 `catch_unwind` 均未记录 payload。

后果：引擎 panic 时用户只看到一句通用文案，日志里也没有 panic 位置，等于把最有价值的排障信息彻底销毁。这是全仓**信息损失最严重**的一处。

建议：
```rust
Err(p) => {
    let msg = p.downcast_ref::<&str>().map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".into());
    log::error!(target: "engine", "worker panicked: {msg}");
    Err(StrHideError::General(format!("Internal engine panic: {msg}")))
}
```
注意：`ErrorDetail.detail` 会直接展示给用户，建议 detail 用通用文案 + 把 panic 文本放进 `data`/日志，避免把内部路径暴露到 UI。

### P1-5 内容域 `inspect`：解析失败 == 无隐藏数据（且论证不一致）

`inspect` 的契约是 `has_hidden_data: bool`，引擎普遍把"读不出来"折叠成 `false`：

| 位置 | 现状 |
|---|---|
| `rust/src/stego/hevc/engine.rs:2371` | `Ok(None) | Err(_) => return Ok(empty_info)` |
| `rust/src/stego/hevc/engine.rs:2453` | `record_carrier_state` 失败 → `Ok(empty_info)` |
| `rust/src/stego/hevc/engine.rs:2600` | `parse_moov_target` 失败 → `Ok(StegoHeaderInfo::empty("MP4/HEVC"))` |
| `rust/src/stego/jpeg/engine.rs:1455-1461` | `read_coefficients` 失败 → `empty_info`，**且不写 note** |
| `rust/src/stego/png/engine.rs:2237` | `read_slot_bytes` 失败 → `Ok(empty_info)` |
| `rust/src/stego/audio/mod.rs:448,464,480,557,570,593` | 6 处 `Err(_)` → `empty` / 基准 phase |
| `rust/src/stego/audio/core.rs:1076,1105` | `read_base` / `body_slots_for` 失败 → `empty` |
| `rust/src/structure/engine.rs:2591,2623-2642` | 结构域同样折叠，但**有明确论证注释**（private dialect 应对外隐身） |

判断：
- **结构域的折叠是有意设计**（B-06 的结论），不应改语义。
- **内容域不一致**：JPEG 同一函数里 preflight 失败写 `note`、`read_coefficients` 失败不写；HEVC 的 3 处、PNG、Audio 全部不写。说明这不是统一的策略决定，而是各处随手 `Err(_)`。
- 后果与 P1-2 叠加：用户看到"无隐藏数据"，实际是"文件解析失败/超出限制/版本不支持"。

建议（不改 `has_hidden_data` 语义，只补诊断出口）：
- 保持 `Ok(empty)`，但统一 `empty_info.note = Some(format!("...: {e}"))`，并配 `log::debug!(target: "stego::inspect", ...)`；
- 把 `Err(_)` 改成 `Err(e)`（绑定变量），否则连日志都写不出具体原因；
- 对"限制被拒绝"（`limits.validate_header` 失败、`check_l1_floor` 失败）与"解析失败"给出不同 note 前缀，便于区分"没查成"和"查了没有"。

## 四、P2：不改变结论，但排障时找不到线索（应加日志）

### Rust 内核

| 位置 | 现状 | 影响 | 建议 |
|---|---|---|---|
| `core/commit.rs:645` | `let _ = dir.sync_all()` | 崩溃后 rename 可能未落盘，无痕迹 | `log::debug!` |
| `core/commit.rs:711` | `let _ = set_permissions(readonly=false)` | 覆盖只读文件失败后由后续写入报错，原因丢失 | `log::debug!` + 保留错误给上层 |
| `core/commit.rs:277` | `let _ = writeln!(file, pid)` | 锁文件写成空 → `read_lock_pid` 返回 None → 永不被回收 → 后续一律 `TargetBusy` | 写入失败时降级为 `path: None`，别留空锁 |
| `core/commit.rs:308` | `let _ = remove_file(quarantine)` | 隔离文件残留 | `log::debug!` |
| `core/commit.rs:287` | `Err(_) => Ok(Self { path: None })` | 锁创建失败静默降级为"无锁"，跨进程保护消失（已有注释说明是有意为之） | 至少 `log::warn!`，把 `e` 带上 |
| `stego/mod.rs:125` | `let _ = ThreadPoolBuilder::build_global()` | Rayon 全局池建失败 → 用默认线程数，性能与内存预算偏离 | `log::warn!` |
| `structure/engine.rs:2623-2642` | `read_exact(meta_bytes).is_ok()` 否则静默跳过 | 元数据读失败与"没有元数据"不可区分 | 补 `else { log::debug! }`；必要时 `MetadataInspection::Unreadable` |
| `structure/adapters/pe.rs:236` | `if let Ok(info) = parse_pe_headers(r)` → `signed=false` | 容量查询把"签名 PE"报成可用，写入时才拒绝，前后不一致 | capacity 路径把解析失败标为 `available=false` + note |
| `cli/cmd_stego.rs:378` | `.ok()` 吞掉兜底容量探测 | 探测失败 → 安全阈值 `[WARN]` 静默不打印，用户以为没问题 | 失败时 `eprintln!("[WARN] capacity probe failed: {e}")`（quiet 除外） |
| `stego/hevc/engine.rs:2893` | `Ok(None) | Err(_)` → "No valid stego signature (or wrong password)" | 解析失败被写成"密码错"，误导用户反复试密码 | 拆成两条 message |

### GUI 后端（`gui/src-tauri`）

| 位置 | 现状 | 建议 |
|---|---|---|
| `state.rs:238` | `let _ = channel.send(ProgressEvent)` | channel 断开是正常退出，但应 `log::debug!` 一次，避免"进度卡住"无从判断 |
| `logger.rs:96` | `let _ = log::set_logger(...)` | 若全局 logger 已存在，整个 GUI 日志静默失效；失败必须能看到 |
| `logger.rs:86,148` | `let _ = app.emit("app:log")` | 自引用，可接受；建议只在前 N 次失败时 `eprintln!` |
| `commands/{stego,diag,structure}.rs` 6 处 | `serde_json::to_value(&res).ok()` | 序列化失败 → 日志记录缺 payload。改为 `match` 并把 `e` 写进 message |
| `commands/stego.rs:377-380` | `metadata().ok()` / `cache.lock().ok()` | 锁中毒 → 缓存永久失效且无痕迹，建议首次失败 `log::warn!` |
| `commands/stego.rs:403` | `if let Ok(mut guard) = cache.lock()` | 同上 |

### 前端（`gui/src`）

| 位置 | 现状 | 建议 |
|---|---|---|
| `lib/openActions.ts:6,14` | 用户点"打开/定位"失败 → 仅 `console.error`，UI 无反馈 | 用 `parseStrHideError` 出 toast；这是用户主动操作，静默失败体验最差 |
| `components/common/LogModal.tsx:129,436` | 剪贴板写入失败 → `catch {}`，按钮无变化 | 至少把"已复制"改成失败态，或退回 `execCommand` |
| `store/settingsStore.ts:45` | 切换语言失败 → 仅 `console.error`，UI 状态未回滚 | 回滚 + 提示 |
| `lib/queue.ts:68` | `pathExists` 吞掉所有错误返回 false | 当前 `overwrite:false` 兜底，最坏是报"已存在"而非覆盖，可接受；建议区分 `not_found` 与其他错误 |
| `hooks/useFileDrop.ts:40,44` | 仅 `console.warn` | 可接受（Tauri 外环境） |

## 五、基础设施缺口（决定了"加日志"到底有没有用）

1. **CLI 没有初始化任何 logger。**
   `gui/src-tauri/src/logger.rs` 里 `init_logger()` 只在 GUI 调；`rust/src/main.rs` 直接 `run_cli()`，全仓无 `env_logger`/`tracing_subscriber`。
   因此 `rust/src/stego/jpeg/engine.rs:684` 和 `rust/src/stego/png/engine.rs:1469` 两处 `log::info!` 在 CLI 构建里是**空操作**。现在给内核加 `log::debug!` 而不补初始化，等于什么也没加。

   建议：在 `cli/mod.rs` 增加 `init_console_logger(quiet, verbose)`，`--quiet` → `Off`，默认 → `Warn`，`-v` → `Debug`，写 stderr（`[WARN]` 前缀已有先例：`cmd_stego.rs:384`）。

2. **`StegoHeaderInfo.note` 是唯一"结构化诊断"通道，但只接通了生产端。**
   补 P1-2 的两个渲染点后，就能在不改公开 API、不改 `has_hidden_data` 语义的前提下解决大部分 P1-5。

3. **`ErrorDetail` 有 `kind` 分类，但探测类失败没有对应 kind。**
   现在 `no_hidden_data` 与"探测失败"共用一个值，前端 `errorHandler.ts:53-56` 也只能给同一句文案。若要根治 P1-5，需要新增 `inspect_inconclusive` 之类 kind（涉及 i18n 词条与前端 switch）。

4. **没有 lint 兜底。**
   `rust/Cargo.toml` 无 `[lints]` 段，`let _ =` 不会被任何规则提示。可选：加 `[lints.clippy] let_underscore_must_use = "warn"`，对约 15 处已论证的合理点逐个 `#[allow]` 并写明理由。不建议一次全开（98 处会淹没真实问题）。

## 六、判定为"可以保留"的（附理由，避免下次重复审计）

| 位置 | 理由 |
|---|---|
| `structure/adapters/*::detect` 全部 `Err(_) => false` | `HostAdapter::detect` 签名就是 `-> bool`，"读不了"与"不是这个格式"对调用方等价 |
| `core/i18n/mod.rs:203` `let _ = out.write_str` | 写 `String` 不会失败 |
| `core/commit.rs:605,612` rename 重试的 `Err(_) => {}` | 循环内故意重试，最终返回 `TargetBusy`，错误未丢 |
| `formats/sniff.rs:221` `try_into` 的 `Err(_) => false` | 前置 `len >= 8` 已保证不会失败，纯防御分支 |
| `analysis.rs:487-491` PNG 解码失败 → `png_stats_skipped = true` | 已用显式标志影响最终 verdict，是正确示范 |
| `core/fs.rs:151,186` `let _ = write!` | 写 `String`，不可能失败 |
| `hooks/useOutputDir.ts:10,23` | localStorage 不可用只影响记忆功能，已注释说明 |
| `logger.rs:86,148` `let _ = app.emit` | 日志通道自身失败，无更高出口 |

## 七、建议的落地顺序

| 顺序 | 内容 | 改动面 | 收益 |
|---|---|---|---|
| 1 | `state.rs` panic payload 提取 + `log::error!` | 1 文件 ~10 行 | 排障信息从"零"到"有" |
| 2 | CLI `init_console_logger` + `--verbose` | 2 文件 ~30 行 | 让已有和新增的 `log::*` 真正生效 |
| 3 | `print_content_domain` 打印 `cs.note`；GUI 展示 `note` / `content_error` | 3 文件 ~25 行 | 解决 P1-2/P1-3，不加新 API |
| 4 | 内容域 7 处 `Err(_)` 绑定变量并写 `note`（HEVC/JPEG/PNG/Audio） | 5 文件 ~40 行 | 解决 P1-5 的主体 |
| 5 | 前端能力表三态 + `classifyFormat` 的 `unknown` | 3 文件 ~40 行 | 解决 P1-1 |
| 6 | P2 清单的 `log::debug!`/`log::warn!` 批量补齐 | 分散 | 长期可观测性 |

第 1-4 步都不改变任何公开函数签名与 `has_hidden_data` 语义，可独立验证（`cargo test --all-features` + `baseline_hash.py --check` 应全绿）。
