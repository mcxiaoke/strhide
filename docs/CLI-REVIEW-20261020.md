# strhide CLI 命令行参数审查报告

- **审查日期**：2026-10-20
- **审查基线**：`rust/` 当前工作树（HEAD `95363d2`，工作树干净）
- **审查范围**：`rust/src/cli.rs`（1,173 行，全部子命令与参数定义）、`rust/src/main.rs`、`rust/src/config.rs`（配置键与密码来源分层）、`rust/README.md` 用法文档；7 个子命令的 `--help` 输出全部实测
- **审查方法**：逐文件通读 → `cargo build` 后对 7 个子命令逐一执行 `--help` 实测渲染输出 → 对照主流 CLI（git / gh / ripgrep / clap 4 生态惯例）逐项评估 → 按影响面（正确性/可用性/一致性/安全性/脚本化/文档）与修复优先级（P0/P1/P2/P3）分级
- **审查结论**：CLI 整体结构主流（clap 4 derive、子命令划分、全局 `--config`、批量语义、密码来源分层均合理），但存在 **2 个 P0 级硬伤**（互斥参数静默吞掉、帮助文本大面积空白）与一批 P1/P2 的可用性、一致性、文档缺口，共 **19 项发现**。本文档仅审查与建议，未改动任何代码。

---

## 0. 总体结论（先说结论）

| 维度 | 评价 |
|---|---|
| 参数框架 | 主流的 clap 4 derive 结构，`global` 选项、`value_name`、批量 `num_args=1..` 用法正确 |
| 子命令划分 | write / read / remove / inspect / verify / scan / list 职责清晰 |
| 批量语义 | 完整且经过仔细打磨（preflight、单载体原子性、`[SUMMARY]`、中途失败语义） |
| 密码来源分层 | 合理（`-p` > `--password-file` > `STRHIDE_PASSWORD` > config > 交互），非 TTY 明确报错不挂死 |
| 最大缺陷 | ① payload 源多参数**静默互斥**（正确性风险） ② `--help` **大面积空白**（上手障碍） |

**实测证据**：`strhide.exe write --help` 中 13 个参数有 11 个帮助文本为空（`-d`/`-t`/`--text-file`/`--text-base64`/`--stdin`/`-o`/`-p`/`--password-file`/`-e`/`-H`/`--stealth`/`--no-backup`/`--unescape`）；`read`/`remove`/`inspect`/`verify` 的 `-c`/`-o`/`-p`/`--json`/`--stdout` 同样空白。

---

## 1. 缺陷清单（按优先级）

### P0 — 必须修（影响正确性或完全无法上手）

#### P0-1 ｜ `write` 的 payload 源参数无互斥约束，静默吞掉用户输入

- **位置**：`cli.rs:49-109`（`WriteArgs`）、`cli.rs:417-460`（payload 源解析）
- **现象**：6 种 payload 源（`-d/--data`、`-t/--text`、`--text-file`、`--text-base64`、`--stdin`、`STRHIDE_TEXT`）之间**没有任何互斥声明**，`handle_write` 按固定优先级静默取第一个：`stdin > data > text_file > text_base64 > text > STRHIDE_TEXT`。实测 `strhide write -c a.png -d x.zip -t "note"` 静默忽略 `-t`，不报错、不警告。
- **影响**：用户以为两个内容都隐藏了，实际只隐藏了其中一个——**数据完整性风险**，属于静默失败中最危险的一类。
- **修复建议**：
  1. 用 clap `ArgGroup` 声明互斥（`multiple(false).required(true)`），同时传多个直接报错并列出冲突参数；
  2. `STRHIDE_TEXT` 仅作为「无任何 CLI 源时」的最后兜底；
  3. 同类的 `-p` 与 `--password-file` 同时给时（`resolve_password` 固定顺序静默用 `-p`）也应报冲突或至少警告（见 P1-6）。

#### P0-2 ｜ `--help` 帮助文本大面积空白

- **位置**：`cli.rs` 全部子命令的参数定义（多数参数无 `help` 属性 / doc comment）
- **现象**（实测）：`write --help` 中以下参数帮助文本为空：

```
  -d, --data <DATA>
  -t, --text <TEXT>
      --text-file <TEXT_FILE>
      --text-base64 <TEXT_BASE64>
      --stdin
  -o, --output <OUTPUT>
  -p, --password <PASSWORD>
      --password-file <PASSWORD_FILE>
  -e, --encrypt
  -H, --hint <HINT>
      --stealth
      --no-backup
      --unescape
```

`read`/`remove`/`inspect`/`verify` 的 `-c`/`-o`/`-p`/`--json`/`--stdout` 同样空白。仅 `write` 的 `-c`、`-s`、`--no-preserve-time` 与 `scan` 全部参数有手写 help。
- **影响**：新用户无法从 `--help` 上手，只能翻 README 或猜参数语义；`--unescape` 这类非显然参数（解码 C 风格转义）完全不可发现。
- **修复建议**：为每个参数补 doc comment（clap derive 自动取用）或 `help` 属性，写明含义、取值、默认值、示例值；顺带解决 P1 中 #3/#5/#7/#9 的说明缺口。

### P1 — 应该修（明显可用性/一致性/安全性缺陷）

#### P1-3 ｜ `write --stealth` 隐含加密与强制密码，help 未说明

- **位置**：`cli.rs:98-99`（`stealth` 定义）、`cli.rs:364-372`（stealth 触发 `encrypt` 并要求密码）
- **现象**：`--stealth` 帮助文本为空；实现上 stealth 强制加密（其 magic 由口令派生，无口令则报错或交互提示），用户仅看 help 无法得知它隐含加密、必须提供密码。
- **修复建议**：help 写全："Stealth mode: hide without detectable markers; implies encryption and requires a password (-p, --password-file, or STRHIDE_PASSWORD)"。

#### P1-4 ｜ `-p/--password` 明文密码无任何安全提示

- **位置**：`cli.rs:79-80`（`password` 定义）
- **现象**：`-p` 明文密码会暴露在进程列表与 shell 历史中；项目已有安全替代（`--password-file`、`STRHIDE_PASSWORD`），但 help 与 README 均未提示。
- **修复建议**：help 注明"明文密码对进程/历史可见，推荐 --password-file 或 STRHIDE_PASSWORD"；README 补一段密码安全说明。

#### P1-5 ｜ 负向选项命名与默认值不可见（`--no-preserve-time` / `--no-backup`）

- **位置**：`cli.rs:101-105`（`preserve_time`）、`cli.rs:107-108`（`no_backup`）
- **现象**：
  - `--no-preserve-time`：字段名 `preserve_time` 为正向、选项名为负向，help 为"Do not preserve original carrier timestamps (default: preserve)"，**未显示 clap 默认值**，用户从 help 无法确认默认行为；
  - `--no-backup`：帮助文本空白，用户不知道默认会创建 `.bak` 备份。
- **修复建议**：改正向命名 `--preserve-time` / `--backup`，让 clap 4 derive 对 bool 字段自动生成 `--x` / `--no-x` 双 flag（更主流）；若保留负向命名，help 必须写明默认值（如"default: preserve timestamps"）。

#### P1-6 ｜ `-p` 与 `--password-file` 同时给时静默优先

- **位置**：`cli.rs:235-294`（`resolve_password`）
- **现象**：`-p` 与 `--password-file` 同时传入时按固定顺序静默使用 `-p`，不报错不警告；`read` 的 `-o` 与 `--stdout` 同时给时同样静默用 `-o`。
- **修复建议**：clap `conflicts_with` 声明，或运行时检测到多个来源时输出警告。

#### P1-7 ｜ `read` 无 `-o` 时的隐式落盘行为未文档化

- **位置**：`cli.rs:567-602`（`handle_read` 落盘分支）
- **现象**：无 `-o`、无 `--stdout` 且 payload 为文件时，自动在当前目录用信封元数据中的文件名落盘（有 `sanitize_filename` 净化 + 覆盖保护），help 完全未提；文本 payload 则输出到 stdout。行为本身安全，但用户可能不知道文件写到了哪里、为何有时是 stdout 有时是文件。
- **修复建议**：help 写明："无 -o 时：文件 payload 写入当前目录（文件名来自信封元数据并净化），文本 payload 输出到 stdout；用 --stdout 强制输出到标准输出"。

#### P1-8 ｜ `scan` 复用 `-c/--carrier` 语义错位

- **位置**：`cli.rs:196-216`（`ScanArgs`）
- **现象**：`scan` 是黑盒检测，输入是"任意可疑文件/目录"，不是"载体"；value_name 已改为 `FILE`，但 flag 名仍是 `-c/--carrier`，与 write/read/remove 的 `-c` 语义（含隐藏数据的载体）混淆。
- **修复建议**：改为 `-i, --input`（接受文件或目录），语义更准、与其他命令区分开。

#### P1-9 ｜ `verify` 的退出码约定未文档化

- **位置**：`cli.rs:708-754`（`handle_verify`）
- **现象**：退出码只由 Level 1（host format）与 Level 2（envelope boundary）决定；Level 3（crypto/payload）失败**不影响退出码**，仅输出报告。help 未说明，脚本用户 gate 时可能误判。
- **修复建议**：help 注明："Exit 0 when host format and envelope boundary pass; non-zero otherwise (crypto/payload failures are reported but do not change the exit code)"。

#### P1-10 ｜ 各子命令 help 无 Examples 段落

- **位置**：全部子命令
- **现象**：`write` 是重参数命令（6 种 payload 源 + 8 个选项），但所有子命令 help 均无示例；主流 CLI（git、gh、ripgrep）都在 help 内置 2–4 个示例。
- **修复建议**：`#[command(after_help = "EXAMPLES:\n  strhide write -c photo.png -t \"secret\" ...\n  ...")]`，至少 `write`/`read`/`scan` 三个命令补齐。

### P2 — 建议修（改进项）

| # | 位置 | 问题 | 修复建议 |
|---|---|---|---|
| 11 | 全局 | 无 `-q/--quiet`、`-v/--verbose`、`--color/--no-color`；`scan`/`inspect` 输出长，脚本用户无安静模式 | 加 `global=true` 的 `-q`/`-v`；`scan` 输出尤其需要 `--quiet` |
| 12 | 全局 | 无 shell 补全 | 用 `clap_complete` 加 `strhide completions bash\|zsh\|fish\|powershell` 子命令 |
| 13 | `write` | `--text-base64` 命名误导：实际要求解码后为 **UTF-8 文本**（`cli.rs:434-437` 转 `PayloadSource::Text`），名字暗示"任意 base64 内容" | 改名或 help 写清"Base64-encoded text (must decode to UTF-8)"；任意二进制应走 `-d` |
| 14 | `write`/`remove` | `-o <dir>` 语义未说明：单载体时"输出到目录内保留原文件名"，多载体时必须为已存在目录（`batch_output_dir`） | help 写明两种语义 |
| 15 | 文档 | `STRHIDE_PASSWORD` / `STRHIDE_TEXT` 环境变量在 README 与 help 中均无提及（仅 `config.rs` 注释有） | README 与各命令 help 补充说明 |

### P3 — 打磨（可选）

| # | 位置 | 问题 | 修复建议 |
|---|---|---|---|
| 16 | `list` | 表格列宽硬编码（`{:<8} {:<15}`），长格式/策略名会错位 | 动态计算列宽或使用表格库 |
| 17 | `remove` | 命名易误解为"删除文件"；项目文档强调"restore / 100% loss-free restoration" | 加 `restore` 别名（clap `alias`），不破坏现有命令名 |
| 18 | 输出 | 标签风格不统一：`verify` 用 `[PASS]/[FAIL]`、`inspect` 无标签、其余用 `[OK]/[ERROR]` | 统一为同一套前缀标签 |
| 19 | 全部 | 可选：支持位置参数作 carrier（`strhide write photo.png -t x`），贴近主流 | 低优先级，注意与 `-c` 多值参数解析的兼容 |

---

## 2. 优先级 × 影响面矩阵

编号与第 1 节清单一一对应。可见 P0/P1 集中于**可用性与一致性**两类。

| 优先级 | 正确性 | 可用性 | 一致性 | 安全性 | 脚本化 | 文档 | 打磨 |
|---|---|---|---|---|---|---|---|
| **P0 必须修** | #1 互斥源静默 | #2 help 空白 | — | — | — | — | — |
| **P1 应该修** | — | #3 stealth 未说明<br>#7 read 隐式落盘 | #5 负向选项<br>#8 scan 的 -c<br>#10 密码源静默 | #4 明文 -p | #9 verify 退出码 | #6 无 Examples | — |
| **P2 建议修** | — | #12 无补全 | #13 text-base64 | — | #11 无 -q/-v | #14 -o 语义<br>#15 环境变量 | — |
| **P3 打磨** | — | — | #17 restore 别名 | — | — | — | #16 列宽<br>#18 标签<br>#19 位置参数 |

---

## 3. 做得好的地方（无需修改）

- **批量语义完整**：`preflight_batch` 预先校验存在性/目录误用/重复载体/输出冲突，单载体原子性 + `[SUMMARY]` 汇总 + 中途失败"N 成功、M 未尝试"语义明确（`cli.rs:881-906`）。
- **密码来源分层合理**：`-p` > `--password-file` > `STRHIDE_PASSWORD` > config > 交互提示；非 TTY 时明确报错而不是挂死（`resolve_password`），read 对加密信封自动提示 hint 并交互重试一次。
- **安全细节到位**：`read` 默认拒绝覆盖 + `sanitize_filename` 防路径穿越；`--strategy ask` 与批量组合明确拒绝；`--stealth` 与配置来源 hint 的冲突处理正确；未知配置键警告防 typo 静默失效。
- **工程细节**：`--config` 全局化、`scan` 目录递归开关、`inspect`/`verify`/`scan` 的 `--json` 结构化输出、`-o` 对已存在目录的语义与 `read` 对齐。

---

## 4. 建议修复顺序（未动代码）

1. **第一批（P0，改动小、收益大）**：P0-1 互斥校验（ArgGroup）+ P0-2 全量补 help —— 顺手解决 P1-3/P1-5/P1-7/P1-9 的说明缺口。
2. **第二批（P1）**：P1-4 安全提示、P1-6 冲突检测、P1-8 `scan -i` 改名、P1-10 Examples。
3. **第三批（P2）**：按需加 `-q/-v`、shell 补全、README 文档补齐。
4. **打磨（P3）**：有闲再动。

---

## 5. 附：实测 `--help` 输出摘录（2026-10-20，debug 构建）

### `strhide.exe --help`

```
Smart multi-format lossless container data hiding tool

Usage: strhide.exe [OPTIONS] <COMMAND>

Commands:
  write    Hide secret payload into carrier file
  read     Read and extract hidden payload from carrier
  remove   100% loss-free restoration by removing hidden envelope
  inspect  Inspect carrier structure and envelope metadata
  verify   Diagnostic verification of host, envelope, and crypto
  scan     Black-box steganalysis: scan file(s) for hidden content, known or unknown
  list     List all supported formats, strategies, and their capacity limits
  help     Print this message or the help of the given subcommand(s)

Options:
      --config <FILE>  Path to TOML config file (default: ./strhide.toml, then ~/.strhide/config.toml)
  -h, --help           Print help
  -V, --version        Print version
```

### `strhide.exe write --help`（帮助文本空白问题实锤）

```
Usage: strhide.exe write [OPTIONS] --carrier <CARRIER>...

Options:
  -c, --carrier <CARRIER>...           Carrier file(s). List several to embed the same payload into each.
      --config <FILE>                  Path to TOML config file (default: ./strhide.toml, then ~/.strhide/config.toml)
  -d, --data <DATA>
  -t, --text <TEXT>
      --text-file <TEXT_FILE>
      --text-base64 <TEXT_BASE64>
      --stdin
  -o, --output <OUTPUT>
  -p, --password <PASSWORD>
      --password-file <PASSWORD_FILE>
  -e, --encrypt
  -H, --hint <HINT>
  -s, --strategy <STRATEGY>            Hiding strategy (auto|ask|<name>; default: auto or config file)
      --stealth
      --no-preserve-time               Do not preserve original carrier timestamps (default: preserve)
      --no-backup
      --unescape
  -h, --help                           Print help
```

`read`/`remove`/`inspect`/`verify` 的 `-c`/`-o`/`-p`/`--password-file`/`--json`/`--stdout` 均无帮助文本；`scan` 与 `list` 的帮助文本完整（唯二完整子命令）。
