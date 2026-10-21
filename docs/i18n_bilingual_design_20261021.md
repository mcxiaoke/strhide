# 中英文双语（i18n）设计方案 —— 宏双列内联

日期：2026-10-21
状态：已评审修订，实施中（方案 1b：宏双列内联）
范围：`rust/` 实现（Python 目录已冻结，不涉及）

---

## 1. 目标与范围

### 一期目标（本方案）

- CLI 全链路支持中英文：`--help`、状态行、交互提示、人类可读报告、错误类别前缀。
- 语言切换：`--lang` 全局参数 > `STRHIDE_LANG` / `STRHIDE_LANGUAGE` 环境变量 > `config.toml` 的 `lang` 键 > 系统 locale 自动检测 > 默认英文。
- **零新增依赖、零运行时外部文件、不改变单静态二进制分发**（现有 release profile：`lto` / `strip` / `panic=abort` 保持不变）。
- 译文与代码同仓库、同一次 review；key 漏写、占位符不匹配在编译期或 debug 断言中暴露。

### 明确不做（一期）

- **库层 246 处错误细节消息不翻译**（分布在 31 个文件的 `StrHideError::Xxx(format!(...))`）。只翻译 8 个错误**类别前缀**，细节保持英文。效果示例：
  - `[ERROR] 密码错误: AEAD tag verification failed at chunk 3`
  - `[ERROR] 不支持的格式: unknown magic bytes 00 01 02 ...`
- clap 自身的解析错误（`error: unexpected argument ...`、`Usage:` / `Options:` / `Commands:` 等模板标题、did-you-mean tip）保持英文。clap 官方无 i18n 支持，二期可通过 `help_template` + `ErrorKind` 自渲染覆盖（见 §11）。
- `--json` 输出、`--stdout` 载荷、退出码、枚举值（strategy/format/verdict 名称）、文件名一律不翻译。
- 状态标签 `[OK]` / `[INFO]` / `[WARN]` / `[ERROR]` / `[WARNING]` 保持英文（测试有耦合，且便于脚本 grep）。

### 二期候选（不在本次实施）

- 库层错误结构化：`enum X` 变体携带字段而非英文 `String`，渲染层完整翻译。
- clap 解析错误中文化（`help_template` 替换标题，`try_get_matches` 捕获后按 `ErrorKind` 自渲染）。
- 第三种语言：宏表加一列即可，架构无需改动。

---

## 2. 现状盘点（改造面）

| 文本位置 | 数量 | 文件 |
|---|---|---|
| clap help / about / after_help | 约 100 条（含 8 段长 `*_AFTER_HELP`） | `cli.rs` |
| 运行时 print 输出 | 104 处（103 处 `cli.rs`，1 处 `config.rs`） | `cli.rs`、`config.rs` |
| 错误类别前缀 | 8 条 | `errors.rs` |
| 交互提示（rpassword） | 2 条 + hint 显示 | `cli.rs:700` |
| 库层错误细节 | 246 处构造点，**一期不动** | 31 个文件 |
| 测试对英文输出的断言 | 仅 `tests/test_cli/sources.rs:646` 断言 `[INFO] Password hint:` | tests |

CLI 文本高度集中在 `cli.rs`（单文件 2269 行），这是宏双列方案低成本的前提。

---

## 3. 文件布局

新增：

```
rust/src/i18n/mod.rs          # Lang 枚举、当前语言状态、messages!/t! 宏、占位符渲染
rust/src/i18n/messages.rs     # 全部双语消息表（约 170 条，估计 700-900 行）
rust/src/i18n/locale.rs       # 语言检测（env + Windows locale API）
rust/src/cli_i18n.rs          # clap Command 本地化遍历 + (cmd,arg) -> Msg 映射
```

修改：

```
rust/src/lib.rs               # 注册 i18n、cli_i18n 模块
rust/src/cli.rs               # --lang 参数；预解析流程；输出点替换；统一 print_error
rust/src/errors.rs            # 新增 category()/detail() 方法（thiserror 模板保留）
rust/src/config.rs            # FileConfig 加 lang 键
rust/tests/common/mod.rs      # base_cmd() 注入 STRHIDE_LANG=en
rust/tests/...（35 处调用点）  # Command::new(bin()) -> common::base_cmd()
rust/tests/test_cli/i18n.rs   # 新增：中文冒烟测试
```

不新增任何 crate 依赖；`build.rs` 不动。

---

## 4. 核心：`i18n/mod.rs` 宏设计

### 4.1 当前语言状态

CLI 单线程顺序执行，用 `thread_local` 保存当前语言，调用点零侵入；库 API（`examples/`、集成测试中的库调用）不触碰它，默认英文，行为与现状完全一致。

```rust
// src/i18n/mod.rs
use std::cell::Cell;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Lang {
    #[default]
    En,
    Zh,
}

impl Lang {
    /// 接受 "en"、"zh"、"zh-CN"、"zh_Hans"、"zh_cn.UTF-8" 等写法；
    /// 其他语言（fr/ja/...）目前回退 None（=英文）。
    pub fn parse(s: &str) -> Option<Lang> {
        let head = s.trim().split(['.', '@']).next().unwrap_or("");
        let norm = head.to_ascii_lowercase().replace('_', "-");
        let norm = norm.as_str();
        if norm == "c" || norm == "posix" || norm.is_empty() {
            return None;
        }
        if norm.starts_with("zh") {
            Some(Lang::Zh)
        } else if norm.starts_with("en") {
            Some(Lang::En)
        } else {
            None
        }
    }
}

thread_local! {
    static CURRENT: Cell<Lang> = const { Cell::new(Lang::En) };
}

pub fn set_lang(lang: Lang) {
    CURRENT.with(|c| c.set(lang));
}

pub fn lang() -> Lang {
    CURRENT.with(Cell::get)
}
```

### 4.2 消息表宏（双语并排，编译期生成枚举）

```rust
// src/i18n/mod.rs（续）

/// 声明双语消息表。每条消息生成一个 Msg 枚举变体和一个
/// (Msg, Lang) -> &'static str 的 match 分支。
/// 漏写任一列在编译期报错；Msg 变体在 clap 查表和 t! 中复用。
#[macro_export]
macro_rules! i18n_messages {
    (
        $(
            $name:ident:
                en = $en:expr,
                zh = $zh:expr;
        )*
    ) => {
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum Msg {
            $($name,)*
        }

        impl Msg {
            pub fn text(self, lang: $crate::i18n::Lang) -> &'static str {
                match (self, lang) {
                    $(
                        (Msg::$name, $crate::i18n::Lang::En) => $en,
                        (Msg::$name, $crate::i18n::Lang::Zh) => $zh,
                    )*
                }
            }
        }
    };
}

/// 取消息（无参数）。
#[macro_export]
macro_rules! t {
    ($msg:path) => {
        $msg.text($crate::i18n::lang()).to_string()
    };
    ($msg:path, $($key:ident = $val:expr),+ $(,)?) => {
        $crate::i18n::format_msg(
            $msg.text($crate::i18n::lang()),
            &[ $( (stringify!($key), &$val as &dyn std::fmt::Display) ),+ ],
        )
    };
}
pub(crate) use t;
```

### 4.3 命名占位符渲染（约 30 行，零依赖）

中文语序与英文不同，必须用**命名占位符**（`{path}`、`{bytes}`），不能用位置 `{}`。

```rust
// src/i18n/mod.rs（续）

/// 渲染 `{name}` 命名占位符；`{{` / `}}` 转义为字面花括号。
/// 采用流式扫描，参数值内部若含 `}}` 不会被二次转义。
/// 缺少参数：debug 构建 panic（开发期立刻暴露），release 保留原占位文本。
pub fn format_msg(tpl: &str, args: &[(&str, &dyn std::fmt::Display)]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(tpl.len());
    let mut rest = tpl;
    while !rest.is_empty() {
        let next_brace = rest.find(|c| c == '{' || c == '}');
        let pos = match next_brace {
            Some(p) => p,
            None => {
                out.push_str(rest);
                break;
            }
        };
        out.push_str(&rest[..pos]);
        let c = rest[pos..].chars().next().unwrap();
        let after = &rest[pos + c.len_utf8()..];
        if c == '{' {
            if after.starts_with('{') {
                out.push('{');
                rest = &after[1..];
            } else if let Some(end) = after.find('}') {
                let key = after[..end].trim();
                match args.iter().find(|(k, _)| *k == key) {
                    Some((_, v)) => {
                        let _ = write!(out, "{v}");
                    }
                    None => {
                        debug_assert!(false, "i18n: missing arg `{key}` in template");
                        out.push('{');
                        out.push_str(&after[..end + 1]);
                    }
                }
                rest = &after[end + 1..];
            } else {
                out.push('{');
                rest = after;
            }
        } else {
            // c == '}'
            if after.starts_with('}') {
                out.push('}');
                rest = &after[1..];
            } else {
                out.push('}');
                rest = after;
            }
        }
    }
    out
}
```

> 注：`{{` 已在循环内处理；`}}` 用收尾 replace 处理。若模板中出现奇数花括号，debug 断言会暴露。

### 4.4 消息表（messages.rs）

```rust
// src/i18n/messages.rs
crate::i18n_messages! {
    // ---- 错误类别前缀 ----
    ErrIo:
        en = "I/O error",
        zh = "I/O 错误";
    ErrCorrupted:
        en = "Corrupted data",
        zh = "数据损坏";
    ErrPassword:
        en = "Password error",
        zh = "密码错误";
    ErrRejection:
        en = "Rejection error",
        zh = "安全拒绝";
    ErrRestoreMismatch:
        en = "100% restore verification failed",
        zh = "还原校验失败（与原始宿主不一致）";
    ErrUnsupported:
        en = "Unsupported format",
        zh = "不支持的格式";

    // ---- 错误渲染模板（标签 [ERROR] 不翻译）----
    ErrorLine:
        en = "[ERROR] {prefix}: {detail}",
        zh = "[ERROR] {prefix}: {detail}";
    ErrorLinePlain:
        en = "[ERROR] {detail}",
        zh = "[ERROR] {detail}";

    // ---- 交互提示 ----
    PromptEnterPassword:
        en = "Enter password: ",
        zh = "请输入密码：";
    PromptConfirmPassword:
        en = "Confirm password: ",
        zh = "请再次输入密码：";
    PasswordMismatch:
        en = "Passwords do not match, try again.",
        zh = "两次输入的密码不一致，请重试。";

    // ---- read / extract 状态行 ----
    ReadOkExtracted:
        en = "[OK] Extracted payload to '{path}' ({bytes} bytes).",
        zh = "[OK] 已将载荷提取到 '{path}'（{bytes} 字节）。";
    InfoBackupCreated:
        en = "[INFO] Backup created at '{path}'.",
        zh = "[INFO] 已创建备份：'{path}'。";
    InfoPasswordHint:
        en = "[INFO] Password hint: {hint}",
        zh = "[INFO] 密码提示：{hint}";
    // ... 其余约 170 条，按 write/read/restore/embed/extract/
    //     inspect/verify/scan/list/help 分节排列
}
```

消息 key 命名约定：

| 前缀 | 内容 |
|---|---|
| `Err*` | 错误类别与渲染模板 |
| `Prompt*` | 交互输入提示 |
| `Cmd*` | 子命令 about（9 条） |
| `HelpRoot*` / `Help<Command>*` | clap 参数 help |
| `AfterHelp<Command>` | 8 段长示例文本（用 `concat!` 传常量） |
| 其余按命令分组：`Read*`、`Scan*`、`Inspect*`、`Verify*`、`List*` | 状态行与报告标签 |

长 `after_help` 双列常量，经宏传入（`$en:expr` 支持 `concat!`）：

```rust
// cli.rs 中保留现有英文常量，新增中文常量；
// messages.rs 中：
AfterHelpWrite:
    en = crate::cli::WRITE_AFTER_HELP_EN,
    zh = crate::cli::WRITE_AFTER_HELP_ZH;
```

示例块中的命令、参数名、文件名不翻译，只翻译 `#` 注释与说明句。

---

## 5. 语言检测：`i18n/locale.rs`

```rust
// src/i18n/locale.rs
use crate::config::FileConfig;
use crate::i18n::Lang;

/// 优先级：CLI > env > config > 系统 locale > 英文。
pub fn detect(cli_lang: Option<&str>, cfg: &FileConfig) -> Lang {
    cli_lang
        .and_then(Lang::parse)
        .or_else(|| std::env::var("STRHIDE_LANG").ok()
            .or_else(|| std::env::var("STRHIDE_LANGUAGE").ok())
            .and_then(|s| Lang::parse(&s)))
        .or_else(|| cfg.lang.as_deref().and_then(Lang::parse))
        .or_else(system_lang)
        .unwrap_or(Lang::En)
}

fn system_lang() -> Option<Lang> {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(var) {
            if let Some(l) = Lang::parse(&v) {
                return Some(l);
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(name) = windows_locale_name() {
            if let Some(l) = Lang::parse(&name) {
                return Some(l);
            }
        }
    }
    None
}

#[cfg(windows)]
fn windows_locale_name() -> Option<String> {
    use std::os::windows::ffi::OsStringExt;
    const MAX: usize = 85; // LOCALE_NAME_MAX_LENGTH
    let mut buf = [0u16; MAX];
    unsafe extern "system" {
        fn GetUserDefaultLocaleName(lp: *mut u16, cch: i32) -> i32;
    }
    let n = unsafe { GetUserDefaultLocaleName(buf.as_mut_ptr(), MAX as i32) };
    if n <= 1 {
        return None;
    }
    Some(std::ffi::OsString::from_wide(&buf[..n as usize - 1])
        .to_string_lossy()
        .into_owned())
}
```

要点：

- 不引入 `windows-sys`：kernel32 的 `GetUserDefaultLocaleName` 直接 `extern` 声明（Rust 2024 edition 要求 `unsafe extern` 块）。MSVC 与 GNU 工具链默认链接 kernel32。
- 不新增依赖；Unix 读标准三个变量，Windows 走 API，覆盖 Git Bash、PowerShell、原生 cmd 三种环境。
- `C` / `POSIX` / 无法识别的 locale 一律回退英文。

---

## 6. clap 接入

clap derive 属性要求 `&'static str`，**无法在属性中按运行时语言切换**，因此采用"derive 保留英文（天然 fallback）+ parse 前递归替换"的标准做法。

### 6.1 新增全局 `--lang` 参数

```rust
// cli.rs，Cli 结构体中
#[arg(
    long = "lang",
    global = true,
    value_name = "LANG",
    value_parser = ["en", "zh"],
    help = "Interface language: en or zh (default: STRHIDE_LANG / config / system locale)"
)]
pub lang: Option<String>,
```

非法值由 clap 拦截（一期错误文案为英文，属已接受限制）。

### 6.2 Command 本地化遍历：`cli_i18n.rs`

```rust
// src/cli_i18n.rs
use clap::{Arg, Command};
use crate::i18n::{Lang, Msg};

pub fn localize(mut cmd: Command, lang: Lang) -> Command {
    walk(&mut cmd, lang);
    cmd
}

fn walk(cmd: &mut Command, lang: Lang) {
    let name = cmd.get_name();

    if let Some(t) = cmd_about(name, lang) {
        cmd.about(t);
    }
    if let Some(t) = cmd_after_help(name, lang) {
        cmd.after_help(t);
    }

    for arg in cmd.get_arguments_mut() {
        let id = arg.get_id().as_str();
        if let Some(t) = arg_help(name, id, lang) {
            arg.help(t).long_help(t);
        }
    }

    // 递归子命令（clap 4 不允许在同一作用域同时借 arguments_mut 与
    // subcommands_mut；分两个循环即可）。
    for sub in cmd.get_subcommands_mut() {
        walk(sub, lang);
    }
}

/// 子命令 about（含根命令）。
fn cmd_about(name: &str, lang: Lang) -> Option<&'static str> {
    let msg = match name {
        "strhide" => Msg::CmdRoot,
        "write" => Msg::CmdWrite,
        "read" => Msg::CmdRead,
        "restore" => Msg::CmdRestore,
        "inspect" => Msg::CmdInspect,
        "verify" => Msg::CmdVerify,
        "scan" => Msg::CmdScan,
        "embed" => Msg::CmdEmbed,
        "extract" => Msg::CmdExtract,
        "list" => Msg::CmdList,
        _ => return None,
    };
    Some(msg.text(lang))
}

/// (command, arg_id) -> 消息；两级查找：命令专属 → 共享参数（按 arg id）。
fn arg_help(cmd: &str, id: &str, lang: Lang) -> Option<&'static str> {
    let msg = match (cmd, id) {
        ("strhide", "config") => Some(Msg::HelpRootConfig),
        ("strhide", "quiet") => Some(Msg::HelpRootQuiet),
        ("strhide", "lang") => Some(Msg::HelpRootLang),
        // clap 内置的 help / version
        ("strhide", "help") | (_, "help") => Some(Msg::HelpBuiltinHelp),
        ("strhide", "version") | (_, "version") => Some(Msg::HelpBuiltinVersion),
        ("write", "carrier") => Some(Msg::HelpWriteCarrier),
        ("write", "output") => Some(Msg::HelpWriteOutput),
        // ... 命令专属条目

        // flatten 共享参数（PasswordArgs / PayloadSourceArgs）在多个子命令下
        // 出现，help 文本相同，按 id 兜底。
        (_, "password") => Some(Msg::HelpSharedPassword),
        (_, "password-file") => Some(Msg::HelpSharedPasswordFile),
        (_, "data") => Some(Msg::HelpSharedData),
        (_, "text") => Some(Msg::HelpSharedText),
        // ...
        _ => None,
    };
    msg.map(|m| m.text(lang))
}
```

注意：`help`/`version` 内置参数会出现在每一级命令上，按 `(_, id)` 兜底即可。

### 6.3 解析流程改造（`run_cli`）

难点：`--lang` 要在 help 渲染前确定，但 help 本身由 clap 在 parse 时直接打印退出。方案是**预解析**（`try_get_matches_from` 只取 matches、不输出），再自行处理 help/version。

```rust
pub fn run_cli() -> i32 {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();

    // 1) 预解析（英文模板，仅用于取得 matches；不触发任何输出）
    let pre = match Cli::command().try_get_matches_from(argv.clone()) {
        Ok(m) => m,
        Err(e) => return render_early_error(e, &argv),
    };

    // 2) 加载配置（失败也要按最终语言报错）
    let cfg_path = pre.get_one::<std::path::PathBuf>("config");
    let cfg = match config::load(cfg_path.map(|p| p.as_ref())) {
        Ok(c) => c,
        Err(e) => {
            i18n::set_lang(detect_lang_without_config(&pre, &argv));
            print_error(&e);
            return 1;
        }
    };

    // 3) 确定语言并全局生效
    let lang = i18n::locale::detect(
        pre.get_one::<String>("lang").map(String::as_str),
        &cfg,
    );
    i18n::set_lang(lang);

    // 4) 从 matches 构造 Cli（本地化只影响 help 文本，不影响匹配结果）
    let cli = match Cli::from_arg_matches(&pre) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] {e}");
            return 2;
        }
    };

    // 5) 之后保持现有流程不变（banner、各 handle_* 分派）
    if should_print_banner(&cli) {
        println!("{BANNER}");
    }
    // ...
}
```

`render_early_error`（help/version/解析错误）：

```rust
fn render_early_error(e: clap::Error, argv: &[std::ffi::OsString]) -> i32 {
    use clap::error::ErrorKind::*;
    match e.kind() {
        DisplayHelp => {
            // 帮助场景下 config 可能尚未加载：从 argv 粗取 --lang，
            // 再 env -> locale（仅用于 help 语言选择）。
            let lang = i18n::locale::detect(scan_lang_flag(argv), &FileConfig::default());
            i18n::set_lang(lang);
            let mut cmd = cli_i18n::localize(Cli::command(), lang);
            let target = scan_subcommand(argv); // 目前只有一级子命令
            let target_cmd = target
                .and_then(|n| cmd.find_subcommand_mut(n))
                .unwrap_or(&mut cmd);
            let _ = target_cmd.print_help();
            0
        }
        DisplayVersion => {
            // 版本号无文案，直接输出，退出码 0
            println!("{BANNER}");
            0
        }
        _ => {
            // 一期：clap 解析错误保持英文（usage/提示均为 clap 内置）
            e.exit()
        }
    }
}
```

辅助说明：

- `scan_lang_flag(argv)`：约 15 行手写扫描，识别 `--lang zh` 与 `--lang=zh`（遇 `--` 停止），**仅用于 help 场景**；正常流程的语言来自预解析 matches。
- `scan_subcommand(argv)`：在 argv 中匹配 9 个已知子命令名的第一个（避免把 `-c file.toml` 的值误判为子命令）。
- `Cli::from_arg_matches` 需 `use clap::FromArgMatches`，derive(Parser) 已生成实现。
- 全局 `--lang` 放在子命令后也能在根 matches 取到（global 参数传播）。

---

## 7. 错误消息接入

`errors.rs` 增加两个方法，**thiserror 原模板保留不动**（库调用方的 Display 行为不变）：

```rust
// errors.rs
use crate::i18n::Msg;

impl StrHideError {
    /// 错误类别（用于 CLI 渲染时翻译类别前缀）；
    /// NoHiddenData / General 无前缀，返回 None。
    pub fn category(&self) -> Option<Msg> {
        match self {
            StrHideError::Io(_) => Some(Msg::ErrIo),
            StrHideError::CorruptedData(_) => Some(Msg::ErrCorrupted),
            StrHideError::Password(_) => Some(Msg::ErrPassword),
            StrHideError::Rejection(_) => Some(Msg::ErrRejection),
            StrHideError::RestoreMismatch(_) => Some(Msg::ErrRestoreMismatch),
            StrHideError::UnsupportedFormat(_) => Some(Msg::ErrUnsupported),
            StrHideError::NoHiddenData(_) | StrHideError::General(_) => None,
        }
    }

    /// 去掉类别前缀后的细节文本（库层英文原文，一期不翻译）。
    pub fn detail(&self) -> String {
        match self {
            StrHideError::Io(e) => e.to_string(),
            StrHideError::CorruptedData(s)
            | StrHideError::Password(s)
            | StrHideError::Rejection(s)
            | StrHideError::RestoreMismatch(s)
            | StrHideError::UnsupportedFormat(s)
            | StrHideError::NoHiddenData(s)
            | StrHideError::General(s) => s.clone(),
        }
    }
}
```

`cli.rs` 统一错误出口，替换现有 10 处 `eprintln!("[ERROR] {e}")`：

```rust
pub fn print_error(e: &StrHideError) {
    let line = match e.category() {
        Some(cat) => t!(Msg::ErrorLine, prefix = cat.text(i18n::lang()), detail = e.detail()),
        None => t!(Msg::ErrorLinePlain, detail = e.detail()),
    };
    eprintln!("{line}");
}
```

效果：

| 语言 | 输出 |
|---|---|
| en | `[ERROR] Password error: AEAD tag verification failed at chunk 3` |
| zh | `[ERROR] 密码错误: AEAD tag verification failed at chunk 3` |

`config.rs` 的 `[WARNING] Unknown key ...` 与 3 处加载失败消息同样走 `t!`（`config.rs` 目前只有 1 个 print，其余错误经 `General` 由 `print_error` 统一渲染）。

---

## 8. 输出改造清单与翻译边界

### 8.1 需要替换的消息组（约 170 条 key）

| 组 | 位置 | 估计条数 |
|---|---|---|
| 错误类别/模板 | `errors.rs` + `cli.rs` | 10 |
| 密码交互、hint | `prompt_password`、`resolve_password` | 6 |
| write/restore/embed/extract 状态行、备份提示、参数警告 | `handle_*`、`print_write_result`、`print_remove_result`、`warn_nondefault_stego_params` | 35 |
| read/extract 结果、二进制载荷提示 | `handle_read`、`handle_extract` | 12 |
| inspect 报告 | `print_inspect_result` | 20 |
| verify 报告（3 级） | `print_verify_result` | 20 |
| scan 判决与统计标签 | `handle_scan`（人类输出部分） | 25 |
| list 表格（人类表头） | `handle_list` | 10 |
| 批量/递归的跳过/警告 | 各 handle_* 循环 | 10 |
| clap 根/子命令 about | 10 | 10 |
| clap 参数 help | 约 70 个 arg（共享参数去重后） | 70 |
| 8 段 after_help | 8 段（长文本） | 8 |
| config 警告 | `config.rs` | 3 |

### 8.2 不翻译（硬边界）

- `--json` 的字段名与枚举值：`verdict: "LOW"`、`"clean"`、strategy 名、format 名、codec 名、`reason` 代码等。
- `--stdout` / `-o -` 的载荷字节。
- 退出码语义。
- 状态标签 `[OK]`/`[INFO]`/`[WARN]`/`[ERROR]`/`[WARNING]`。
- 日志/调试输出（若有 `STRHIDE_DEBUG` 类）。
- 文件名、路径、哈希、字节数等数据（仅作为占位符参数插入）。

### 8.3 替换手法

机械替换为主：`eprintln!("[WARN] '{}' does not exist, skipping", x)` → `eprintln!("{}", t!(Msg::WarnSkippedMissing, path = x.display()))`。每替换一组立即 `cargo build && cargo test`，保证不夹带逻辑变更。

---

## 9. config.toml 支持

`FileConfig` 增加一个字段，`KNOWN_KEYS` 同步增加：

```rust
pub lang: Option<String>,   // "en" | "zh"；其他值静默忽略并回退
```

`config.rs` 模块注释的键位表补一行：

```toml
lang          = "zh"         # all: interface language (en|zh), default: auto-detect
```

`strhide.sample.toml` 同步加带注释的示例。

---

## 10. 测试策略

1. **固定英文基线**：`tests/common/mod.rs` 增加统一入口并注入环境变量：

   ```rust
   /// 所有 CLI 集成测试的 Command 构造入口；
   /// 固定英文，保证中文开发者机器上的断言不受系统 locale 影响。
   pub fn base_cmd() -> std::process::Command {
       let mut c = std::process::Command::new(bin());
       c.env("STRHIDE_LANG", "en");
       c
   }
   ```

   现有 35 处 `Command::new(bin())` / `Command::new(env!("CARGO_BIN_EXE_strhide"))` 机械替换为 `common::base_cmd()`（注意 `tests/test_lifecycle/stego.rs` 中的全限定写法）。

2. **现有断言**：`sources.rs:646` 的 `[INFO] Password hint:` 在英文基线下保持成立。

3. **新增中文冒烟测试** `tests/test_cli/i18n.rs`：
   - `--lang zh --help`：after_help 中的中文说明出现；参数 help 中文出现。
   - `STRHIDE_LANG=zh` 环境变量路径生效；`--lang` 优先级高于 env。
   - 不支持格式的文件：中文类别前缀出现（`不支持的格式` / `密码错误`）。
   - 中文环境下 `--json` 输出仍为英文枚举值（扫描一个干净样本，断言 `"verdict":"clean"` 等）。
   - `--lang bad` 被 clap 拒绝、退出码非 0。

4. **i18n 单元测试**（`src/i18n/mod.rs` 内 `#[cfg(test)]`）：
   - `Lang::parse` 覆盖 `zh_CN.UTF-8`、`zh-Hans-CN`、`C`、`en_US`、`fr`。
   - `format_msg` 覆盖命名替换、`{{`/`}}` 转义、多参数、缺参数 debug 断言。

5. 质量门禁不变：`cargo fmt --check`、`cargo clippy --all-targets -D warnings`、`cargo test --all-targets` 全绿；语料回归（batch_corpus / batch_stego）不受影响（输出断言极少）。

---

## 11. 已知限制与二期路线

| 限制 | 一期表现 | 二期手段 |
|---|---|---|
| clap 解析错误文案 | 英文（`error: unexpected argument ...`、did-you-mean tip） | `try_get_matches_from` 捕获后按 `ErrorKind` 自渲染中文 |
| help 模板标题 | `Usage:`/`Arguments:`/`Options:`/`Commands:` 英文，正文中文 | `Command::help_template` 按语言切换中文模板（注意自定义模板要覆盖扁平化参数与全局参数样式） |
| 库层错误细节 | 英文（前缀中文） | 错误变体携带结构化字段，渲染层翻译 |
| 非中英 locale | 回退英文 | 消息表加一列 |
| 中文报告与英文标签混排 | `[ERROR] 密码错误: <英文细节>` | 随库层结构化自然消除 |

---

## 12. 实施步骤（建议提交顺序）

1. **i18n 骨架**：`i18n/{mod,messages,locale}.rs`（先放 10 条消息）、单元测试、`lib.rs` 注册；`cargo test` 绿。
2. **解析链路**：`--lang` 参数、预解析流程、`render_early_error`、config `lang` 键；`set_lang` 打通。
3. **clap 本地化**：`cli_i18n.rs` 遍历 + 根命令/9 子命令 about + 内置 help/version + 8 段 after_help；参数 help 先接共享参数组。
4. **错误渲染**：`category()`/`detail()` + `print_error`，替换 10 处 `[ERROR]`；`config.rs` 3 条。
5. **消息表填充**（按命令分批，每批独立可测）：
   - write/read/restore（含交互、备份）
   - embed/extract
   - inspect/verify/scan/list 人类报告
   - 剩余 clap 参数 help 逐条补全（缺失时 clap 自动显示英文，不阻塞）
6. **测试**：`base_cmd()` 与 35 处替换；新增 `test_cli/i18n.rs`。
7. **门禁**：`fmt`/`clippy -D warnings`/`test --all-targets`/两个 ignored 批测；更新 `strhide.sample.toml`、README 中英文说明各加一节语言切换用法；`docs/CHANGES-20261021.md` 追加变更摘要。

建议每个步骤一个 commit，第 5 步可按命令拆成多个 commit；全程不碰 `python/`。

---

## 13. 工作量估计

| 阶段 | 估计 |
|---|---|
| 骨架 + 解析链路 + clap 接入（步骤 1-3） | 0.5 天 |
| 错误渲染 + 全部消息表与输出点替换（步骤 4-5） | 1 天（主要是中文翻译与逐条核对） |
| 测试改造 + 门禁 + 文档（步骤 6-7） | 0.5 天 |
| 合计 | **约 2 天** |

风险点：

- 8 段 after_help 的中文翻译量最大（含大量示例与安全说明），翻译时严格只译说明、不改动命令与参数名。
- `try_get_matches_from` / `from_arg_matches` 双阶段流程是唯一的结构性改动，需要重点验证：全局参数、`--help` 于子命令、`--version`、错误退出码、`-c` 与 `--lang` 组合。
- 不改变任何载荷/信封格式与密码学路径，无格式兼容风险。
