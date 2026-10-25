//! Central bilingual message catalog.
//!
//! Every message has two columns: `en` and `zh`.
//! Missing columns or variants cause compile-time failure.

pub const WRITE_AFTER_HELP_EN: &str = "\
Payload sources are mutually exclusive: -d/--data, -t/--text, --text-file,
--text-base64, or --stdin. When omitted, the STRHIDE_TEXT environment variable
serves as fallback.

Notes:
  * --stealth requires password protection (-p, --password-file, or STRHIDE_PASSWORD).
    Password hints (-H) are disallowed in stealth mode.
  * In-place writes (--in-place) create a '.bak' backup unless --no-backup is set.

Examples:
  strhide write photo.png -t \"meet me at 7\"                 # Save to photo-out.png
  strhide write photo.png -t \"meet me at 7\" --in-place      # Modify photo.png in place
  strhide write report.pdf -d secret.zip -p \"S3cret!\"       # Password-protected
  strhide write photo.png -t \"line1\\nline2\" --unescape      # Expand \\n escapes
  cat secret.txt | strhide write image.jpg --stdin          # Read from standard input
  strhide write a.png b.png -t \"secret\" -o out_dir/         # Batch write to directory
  strhide read photo-out.png                                # Extract back
";

pub const WRITE_AFTER_HELP_ZH: &str = "\
数据来源选项互斥：-d/--data、-t/--text、--text-file、
--text-base64 或 --stdin。若均未提供，则回退使用环境变量 STRHIDE_TEXT。

注意事项：
  * --stealth（潜行模式）必须配合密码使用（-p、--password-file 或 STRHIDE_PASSWORD）；
    该模式下禁止附带密码提示（-H）。
  * 原地写入（--in-place）默认自动生成同名 '.bak' 备份文件，加 --no-backup 可禁用。

常用示例：
  strhide write photo.png -t \"meet me at 7\"                 # 写入新文件 photo-out.png
  strhide write photo.png -t \"meet me at 7\" --in-place      # 原地写入 photo.png（保留备份）
  strhide write report.pdf -d secret.zip -p \"S3cret!\"       # 设置密码加密保护
  strhide write photo.png -t \"line1\\nline2\" --unescape      # 解析 \\n 转义换行
  cat secret.txt | strhide write image.jpg --stdin          # 从标准输入管道写入
  strhide write a.png b.png -t \"secret\" -o out_dir/         # 批量写入指定输出目录
  strhide read photo-out.png                                # 从生成文件中提取数据
";

pub const READ_AFTER_HELP_EN: &str = "\
When neither -o/--output nor --stdout is given:
  * File payloads are restored into the current directory using the original
    stored filename (without overwriting existing files unless --overwrite is set).
  * Text payloads are printed directly to standard output.

Examples:
  strhide read photo.png                   # File -> ./<stored_name>, text -> stdout
  strhide read photo.png -o recovered.zip  # Extract to a specified path
  strhide read photo.png --stdout          # Always print to stdout
  strhide read locked.png                  # Displays stored password hint if available
";

pub const READ_AFTER_HELP_ZH: &str = "\
若未指定 -o/--output 也未指定 --stdout：
  * 文件载荷将以原始文件名提取到当前目录（已有同名文件时不会覆盖，除非加 --overwrite）；
  * 文本载荷直接打印至标准输出。

常用示例：
  strhide read photo.png                   # 文件提取至当前目录，文本直接输出
  strhide read photo.png -o recovered.zip  # 提取并保存到指定路径
  strhide read photo.png --stdout          # 强制直接打印到标准输出
  strhide read locked.png                  # 提示输入密码前会显示已存的密码提示
";

pub const CAPACITY_AFTER_HELP_EN: &str =
    "Probes the maximum embedding capacity of image carrier(s) without modifying
them. The same probe backs `strhide embed --capacity`; this command exists so
a read-only question has a read-only verb.

Examples:
  strhide capacity photo.png photo.jpg       # Text report per carrier
  strhide capacity photo.png --json          # Machine-readable report
  strhide capacity photo.png --safety paranoid
";

pub const CAPACITY_AFTER_HELP_ZH: &str =
    "探测图像载体的最大嵌入容量（不修改文件）。与 `strhide embed --capacity` 使用同一探测：
答案只对探测时的调参组合有效，因此本命令暴露与 embed 相同的调参与凭据参数。

示例：
  strhide capacity photo.png photo.jpg       # 逐载体输出文本报告
  strhide capacity photo.png --json          # 机器可读报告
  strhide capacity photo.png --safety paranoid
";

pub const EMBED_AFTER_HELP_EN: &str = "\
Content-adaptive steganography embeds data directly into image textures or frequency
coefficients (HILL for PNG, UERD for JPEG by default; -a switches to suniward or
juniward), rendering it immune to metadata stripping.
Because pixel/coefficient values are subtly modified, this operation cannot be reversed
to the original carrier bit-for-bit.

Examples:
  strhide embed photo.jpg -t \"secret message\"                 # Save to photo-out.jpg
  strhide embed photo.jpg -t \"secret message\" --in-place      # Modify photo.jpg in place
  strhide embed photo.jpg -t \"secret message\" -o out.jpg      # Save to specified path
  strhide embed graphic.png -d secret.zip -p \"P@ss!\" -o out.png
  strhide embed photo.jpg -t \"custom\" --exclusion-rate 0.40 -o out.jpg
  strhide embed graphic.png -t \"custom\" -a suniward -o out.png  # Switch to S-UNIWARD
  strhide embed photo.jpg -t \"custom\" -a juniward -o out.jpg   # Switch to J-UNIWARD (slower)
";

pub const EMBED_AFTER_HELP_ZH: &str = "\
内容自适应隐写将数据直接嵌入到图像纹理或频域系数中（默认 PNG 用 HILL、JPEG 用 UERD，
可用 -a 切换到 suniward / juniward），
可完全免疫容器元数据剥离攻击。
由于对像素或频域系数值进行了微调，此操作无法 bit-for-bit 还原回原载体文件。

常用示例：
  strhide embed photo.jpg -t \"secret message\"                 # 嵌入并保存为 photo-out.jpg
  strhide embed photo.jpg -t \"secret message\" --in-place      # 原地修改 photo.jpg
  strhide embed photo.jpg -t \"secret message\" -o out.jpg      # 保存至指定输出路径
  strhide embed graphic.png -d secret.zip -p \"P@ss!\" -o out.png
  strhide embed photo.jpg -t \"custom\" --exclusion-rate 0.40 -o out.jpg
  strhide embed graphic.png -t \"custom\" -a suniward -o out.png  # 换用 S-UNIWARD 代价模型
  strhide embed photo.jpg -t \"custom\" -a juniward -o out.jpg   # 换用 J-UNIWARD 代价模型（较慢）
";

pub const EXTRACT_AFTER_HELP_EN: &str = "\
Extracts data embedded via content-adaptive steganography (embed).
Carrier format (PNG, JPEG, HEIF/HEIC, or HEVC) is automatically detected.

Examples:
  strhide extract out.jpg -p \"P@ss!\"               # Print text payload to stdout
  strhide extract out.jpg -p \"P@ss!\" --stdout      # Force stdout output
  strhide extract out.png -p \"P@ss!\" -o secret.zip # Save extracted payload to file
";

pub const EXTRACT_AFTER_HELP_ZH: &str = "\
从自适应隐写图像（embed 生成）中提取隐藏数据。
自动识别图像载体格式（PNG、JPEG、HEIF/HEIC 或 HEVC）。

常用示例：
  strhide extract out.jpg -p \"P@ss!\"               # 文本载荷直接输出至终端
  strhide extract out.jpg -p \"P@ss!\" --stdout      # 强制输出至标准输出
  strhide extract out.png -p \"P@ss!\" -o secret.zip # 提取并保存到文件
";

pub const RESTORE_AFTER_HELP_EN: &str = "\
Restores carrier files to their original state, stripping all hidden envelopes.
Restoration is guaranteed bit-for-bit: the restored SHA-256 hash is verified against
the original host recorded in the envelope.

Examples:
  strhide restore photo.png                 # Save restored file to photo-out.png
  strhide restore photo.png --in-place      # Restore in place (keeps photo.png.bak)
  strhide restore photo.png -o clean.png    # Save restored file to clean.png
  strhide restore a.png b.png c.png         # Batch restore to *-out.png
  strhide restore a.png b.png -o clean_dir/ # Batch restore into target directory
";

pub const RESTORE_AFTER_HELP_ZH: &str = "\
将载体文件无损还原为原始状态，彻底清除所有隐藏数据与信封。
还原过程受严格的 bit-for-bit 校验：还原后的 SHA-256 哈希值必须与
信封中记录的原始宿主完全一致，否则将立即报错拒绝。

常用示例：
  strhide restore photo.png                 # 还原并输出为 photo-out.png
  strhide restore photo.png --in-place      # 原地还原（保留 photo.png.bak 备份）
  strhide restore photo.png -o clean.png    # 还原并保存为 clean.png
  strhide restore a.png b.png c.png         # 批量还原为 *-out.png
  strhide restore a.png b.png -o clean_dir/ # 批量还原至指定目录
";

pub const INSPECT_AFTER_HELP_EN: &str = "\
Examples:
  strhide inspect photo.png             # Inspect a single carrier
  strhide inspect a.png b.png c.png     # Inspect multiple carriers
  strhide inspect dir/ -r               # Recursively inspect directory tree
  strhide inspect photo.png --json      # Output report as JSON object
  strhide inspect a.png b.png --json    # Output report as JSON array
";

pub const INSPECT_AFTER_HELP_ZH: &str = "\
常用示例：
  strhide inspect photo.png             # 检查单个载体文件
  strhide inspect a.png b.png c.png     # 检查多个载体文件
  strhide inspect dir/ -r               # 递归检查整个目录
  strhide inspect photo.png --json      # 以 JSON 对象输出报告
  strhide inspect a.png b.png --json    # 以 JSON 数组输出批量报告
";

pub const VERIFY_AFTER_HELP_EN: &str = "\
Verification Levels:
  Level 1 - Host container format is intact (PNG/JPEG/... valid structure)
  Level 2 - Hidden envelope boundary detected and bounded correctly
  Level 3 - Envelope content integrity and crypto verified (requires password)

Exit codes: 0 if Level 1 and Level 2 pass; 1 otherwise. Level 3 failures are
reported diagnostics and do not affect the exit code.

Examples:
  strhide verify photo.png              # Verify a single carrier
  strhide verify a.png b.png c.png      # Verify multiple carriers
  strhide verify dir/ -r                # Recursively verify directory tree
  strhide verify photo.png --json       # Output report as JSON
";

pub const VERIFY_AFTER_HELP_ZH: &str = "\
校验层级说明：
  级别 1 - 宿主容器格式完整（PNG/JPEG/... 结构合法无损）
  级别 2 - 成功定位隐藏信封边界且结构完整
  级别 3 - 校验信封内容完整性与密码学有效性（需要提供密码）

退出码规则：级别 1 与级别 2 均通过返回 0，否则返回 1。级别 3 校验失败会详细报告，
但不会改变退出码。

常用示例：
  strhide verify photo.png              # 校验单个载体
  strhide verify a.png b.png c.png      # 批量校验多个载体
  strhide verify dir/ -r                # 递归校验目录树
  strhide verify photo.png --json       # 以 JSON 格式输出校验报告
";

pub const SCAN_AFTER_HELP_EN: &str = "\
Treats inputs as unverified suspects rather than known strhide carriers, detecting
structural and statistical anomalies caused by known or unknown hiding tools.

Exit codes:
  0 = Clean or low-suspicion findings across all scanned files
  1 = At least one file has a \"likely-hidden\" verdict

Examples:
  strhide scan photo.png               # Scan a single file
  strhide scan dir/ -r                 # Recursively scan a directory tree
  strhide scan dir/ -r --json          # Machine-readable JSON output
  strhide scan downloads/ -r -q || echo \"Suspicious files found\"
";

pub const SCAN_AFTER_HELP_ZH: &str = "\
将输入文件视为未知的可疑样本进行黑盒隐写分析，检测已知或未知工具
留下的结构性破坏与统计学异常。

退出码判定：
  0 = 所有文件均未检出高置信度隐藏（结论为 clean 或 low/suspicious）
  1 = 至少有一个文件被判定为 \"likely-hidden\"（极可能存在隐藏）

常用示例：
  strhide scan photo.png               # 扫描单个文件
  strhide scan dir/ -r                 # 递归扫描整个目录树
  strhide scan dir/ -r --json          # 输出机器可读的 JSON 报告
  strhide scan downloads/ -r -q || echo \"发现疑似隐写文件\"
";

crate::i18n_messages! {
    // ---- Error category prefixes ----
    ErrIo:
        en = "I/O error",
        zh = "I/O 错误";
    ErrCorrupted:
        en = "Corrupted data",
        zh = "数据损坏或校验失败";
    ErrPassword:
        en = "Password error",
        zh = "密码错误或缺失";
    ErrRejection:
        en = "Safety check rejected",
        zh = "安全策略拦截";
    ErrRestoreMismatch:
        en = "Restore verification failed",
        zh = "还原校验失败（与原文件不一致）";
    ErrUnsupported:
        en = "Unsupported format",
        zh = "不支持的文件格式";

    // ---- Error rendering templates ----
    ErrorLine:
        en = "[ERROR] {prefix}: {detail}",
        zh = "[ERROR] {prefix}: {detail}";
    ErrorLinePlain:
        en = "[ERROR] {detail}",
        zh = "[ERROR] {detail}";

    // ---- Interactive password prompts ----
    PromptEnterPassword:
        en = "Enter password: ",
        zh = "输入密码: ";
    PromptConfirmPassword:
        en = "Confirm password: ",
        zh = "再次确认密码: ";
    PasswordMismatch:
        en = "Passwords do not match, try again.",
        zh = "两次输入的密码不一致，请重试。";

    // ---- Basic status lines ----
    ReadOkExtracted:
        en = "[OK] Extracted payload to '{path}' ({bytes} bytes).",
        zh = "[OK] 成功提取载荷至 '{path}'（共 {bytes} 字节）";
    InfoBackupCreated:
        en = "[INFO] Backup created at '{path}'.",
        zh = "[INFO] 已创建原文件备份: '{path}'";
    InfoPasswordHint:
        en = "[INFO] Password hint: {hint}",
        zh = "[INFO] 密码提示: {hint}";

    // ---- Commands about (subcommands) ----
    CmdRoot:
        en = "Format-preserving lossless data hiding and steganography tool",
        zh = "格式保持、无损数据隐藏与智能隐写工具";
    CmdWrite:
        en = "Hide secret payload into carrier files",
        zh = "向载体文件中隐藏机密数据";
    CmdRead:
        en = "Extract hidden payload from carrier files",
        zh = "从载体文件中提取隐藏数据";
    CmdRestore:
        en = "Restore carrier file to its original state (100% lossless)",
        zh = "彻底还原载体文件，恢复原始宿主（100% 无损）";
    CmdInspect:
        en = "Inspect carrier structure and hidden metadata",
        zh = "查看载体文件结构与隐藏元数据";
    CmdVerify:
        en = "Verify carrier integrity, envelope, and crypto",
        zh = "校验载体完整性、信封结构与密码有效性";
    CmdScan:
        en = "Scan files for hidden content (steganalysis)",
        zh = "扫描检测文件中是否存在隐写或隐藏内容";
    CmdEmbed:
        en = "Embed payload into pixels or DCT coefficients (adaptive stego)",
        zh = "自适应图像隐写：将数据嵌入像素或频域系数";
    CmdExtract:
        en = "Extract payload from adaptive stego images",
        zh = "自适应图像隐写：从像素或频域系数中提取数据";
    CmdList:
        en = "List supported formats, strategies, and capacities",
        zh = "列出支持的载体格式、隐藏策略及容量上限";

    // ---- After help ----
    AfterHelpWrite:
        en = WRITE_AFTER_HELP_EN,
        zh = WRITE_AFTER_HELP_ZH;
    AfterHelpRead:
        en = READ_AFTER_HELP_EN,
        zh = READ_AFTER_HELP_ZH;
    AfterHelpEmbed:
        en = EMBED_AFTER_HELP_EN,
        zh = EMBED_AFTER_HELP_ZH;
    AfterHelpExtract:
        en = EXTRACT_AFTER_HELP_EN,
        zh = EXTRACT_AFTER_HELP_ZH;
    AfterHelpRestore:
        en = RESTORE_AFTER_HELP_EN,
        zh = RESTORE_AFTER_HELP_ZH;
    AfterHelpInspect:
        en = INSPECT_AFTER_HELP_EN,
        zh = INSPECT_AFTER_HELP_ZH;
    AfterHelpVerify:
        en = VERIFY_AFTER_HELP_EN,
        zh = VERIFY_AFTER_HELP_ZH;
    AfterHelpScan:
        en = SCAN_AFTER_HELP_EN,
        zh = SCAN_AFTER_HELP_ZH;

    // ---- Root / shared options help ----
    HelpRootConfig:
        en = "Path to TOML config file (searches ./strhide.toml, ~/.strhide/config.toml)",
        zh = "配置文件路径（默认按序查找 ./strhide.toml、~/.strhide/config.toml）";
    HelpRootQuiet:
        en = "Quiet mode: suppress progress and status reports (payload, --json, and errors still print)",
        zh = "静音模式：不输出普通状态与进度（错误、提取数据及 --json 仍正常输出）";
    HelpRootLang:
        en = "Interface language: en or zh (default: detect from STRHIDE_LANG or system locale)",
        zh = "界面语言：en（英文）或 zh（中文）[默认检测环境变量或系统语言]";
    HelpBuiltinHelp:
        en = "Print help (see more with '--help')",
        zh = "打印帮助信息（使用 '--help' 查看详情）";
    HelpBuiltinVersion:
        en = "Print version information",
        zh = "打印版本信息";

    // ---- Flattened / shared arguments help ----
    HelpSharedPassword:
        en = "Plaintext password (visible in process list; prefer interactive prompt or --password-file)",
        zh = "明文密码（命令行中可见；推荐使用交互输入或 --password-file）";
    HelpSharedPasswordFile:
        en = "Read password from file (first line; trailing newline trimmed; mutually exclusive with -p)",
        zh = "从文件读取密码（读取首行并去除换行符，与 -p 互斥）";
    HelpSharedData:
        en = "Payload file path or direct data string",
        zh = "待隐藏的载荷文件路径或数据内容";
    HelpSharedText:
        en = "Payload text string (supports C-style escapes with --unescape)",
        zh = "待隐藏的文本字符串（支持与 --unescape 搭配）";
    HelpSharedFile:
        en = "Path to secret payload file to hide",
        zh = "待隐藏的机密载荷文件路径";
    HelpSharedStdin:
        en = "Read payload from standard input until EOF",
        zh = "从标准输入 (stdin) 读取待隐藏数据直至 EOF";
    HelpSharedTextFile:
        en = "Path to UTF-8 text file to hide",
        zh = "待隐藏的 UTF-8 文本文件路径";
    HelpSharedTextBase64:
        en = "Base64-encoded text payload (automatically decoded before hiding)",
        zh = "Base64 编码的文本载荷（隐藏前自动解码）";

    // ---- Command specific arguments help ----
    // write
    HelpWriteCarrier:
        en = "Carrier file(s) to hide data in (use '--' before filenames starting with '-')",
        zh = "用于隐藏数据的载体文件（文件名若以 '-' 开头需在其前加 '--'）";
    HelpWriteOutput:
        en = "Output path for modified carrier (file path for single carrier, directory for batch)",
        zh = "生成文件的输出路径（单文件为目标文件名，多文件批处理时为目标目录）";
    HelpWriteInPlace:
        en = "Modify carrier file(s) in place (creates '.bak' backup by default)",
        zh = "直接修改原文件（默认保留 .bak 备份，加 --no-backup 可禁用）";
    HelpWriteOverwrite:
        en = "Overwrite existing destination file(s) without confirmation",
        zh = "覆盖已存在的目标文件而不提示确认";
    HelpWriteStrategy:
        en = "Data-hiding strategy (default: auto; run 'strhide list' to view all)",
        zh = "指定隐藏策略（默认: auto；运行 'strhide list' 可查看所有策略）";
    HelpWriteStealth:
        en = "Enable stealth mode (envelope appears as random bytes without password)",
        zh = "启用潜行隐蔽模式（无密码时信封特征完全呈现为随机噪声）";
    HelpWriteEncrypt:
        en = "Require password (fails immediately if password is not supplied, skips prompt)",
        zh = "要求密码加密（若未提供密码则直接失败，不进入交互输入）";
    HelpWriteNoEncrypt:
        en = "Do not encrypt payload (allows writing without personal password)",
        zh = "不使用密码加密（允许直接写入未设置个人密码的数据）";
    HelpWriteHint:
        en = "Password hint to store in carrier (plaintext, max 128 bytes; disallowed with --stealth)",
        zh = "密码提示信息（明文存入载体，最多 128 字节；潜行模式禁用）";
    HelpWritePreserveTime:
        en = "Preserve carrier access and modification timestamps across write (default)",
        zh = "保留载体原本的访问与修改时间戳（默认开启）";
    HelpWriteNoPreserveTime:
        en = "Do not preserve timestamps (update to current write time)",
        zh = "不保留时间戳，更新为当前写入时间";
    HelpWriteNoBackup:
        en = "Do not create '<carrier>.bak' backup during in-place operations",
        zh = "原地修改时不创建 .bak 备份";
    HelpWriteUnescape:
        en = "Decode C-style escape sequences in text payload (\\n, \\r, \\t, \\\\, \\xHH, etc.)",
        zh = "解析文本中的 C 风格转义字符（如 \\n, \\t, \\xHH 等）";

    // read
    HelpReadCarrier:
        en = "Carrier file to extract hidden payload from (use '--' before filenames starting with '-')",
        zh = "从中提取隐藏数据的载体文件（文件名若以 '-' 开头需在其前加 '--'）";
    HelpReadOutput:
        en = "Path to write extracted payload (file path or existing directory)",
        zh = "提取载荷的保存路径（可为具体文件名或已存在的目录）";
    HelpReadStdout:
        en = "Print extracted payload to standard output (mutually exclusive with -o/--output)",
        zh = "将提取的载荷直接输出至标准输出（与 -o/--output 互斥）";
    HelpReadOverwrite:
        en = "Overwrite existing destination file without confirmation",
        zh = "覆盖已存在的目标文件而不提示确认";

    // restore
    HelpRestoreCarrier:
        en = "Carrier file(s) to restore (use '--' before filenames starting with '-')",
        zh = "待还原的载体文件（文件名若以 '-' 开头需在其前加 '--'）";
    HelpRestoreOutput:
        en = "Output path for restored carrier (file path for single carrier, directory for batch)",
        zh = "还原后文件的输出路径（单文件为目标文件名，多文件批处理时为目标目录）";
    HelpRestoreInPlace:
        en = "Restore carrier file(s) in place (creates '.bak' backup by default)",
        zh = "原地还原载体文件（默认保留 .bak 备份，加 --no-backup 可禁用）";
    HelpRestoreOverwrite:
        en = "Overwrite existing destination file(s) without confirmation",
        zh = "覆盖已存在的目标文件而不提示确认";
    HelpRestoreNoBackup:
        en = "Do not create '<carrier>.bak' backup during in-place restore",
        zh = "原地还原时不创建 .bak 备份";

    // inspect
    HelpInspectCarrier:
        en = "Carrier file(s) or directory to inspect (use '--' before filenames starting with '-')",
        zh = "待检查的载体文件或目录（文件名若以 '-' 开头需在其前加 '--'）";
    HelpInspectRecursive:
        en = "Recursively descend into directories",
        zh = "递归遍历子目录";
    HelpInspectJson:
        en = "Print machine-readable JSON report",
        zh = "以结构化 JSON 格式输出报告";

    // verify
    HelpVerifyCarrier:
        en = "Carrier file(s) or directory to verify (use '--' before filenames starting with '-')",
        zh = "待校验的载体文件或目录（文件名若以 '-' 开头需在其前加 '--'）";
    HelpVerifyRecursive:
        en = "Recursively descend into directories",
        zh = "递归遍历子目录";
    HelpVerifyJson:
        en = "Print machine-readable JSON report",
        zh = "以结构化 JSON 格式输出报告";

    // scan
    HelpScanInput:
        en = "File(s) or directory to scan for hidden content (use '--' before filenames starting with '-')",
        zh = "待扫描分析的文件或目录（文件名若以 '-' 开头需在其前加 '--'）";
    HelpScanRecursive:
        en = "Recursively descend into directories",
        zh = "递归遍历子目录";
    HelpScanJson:
        en = "Print machine-readable JSON array of scan findings",
        zh = "以结构化 JSON 数组输出扫描报告";

    // embed
    HelpEmbedCarrier:
        en = "Carrier image file(s) (PNG, JPEG, HEIF/HEIC, or HEVC; use '--' before filenames starting with '-')",
        zh = "图像载体文件（PNG、JPEG、HEIF/HEIC 或 HEVC；文件名若以 '-' 开头需在其前加 '--'）";
    HelpEmbedOutput:
        en = "Output path for stego image (file path for single image, directory for batch)",
        zh = "生成隐写图像的输出路径（单文件为目标文件名，多文件批处理时为目标目录）";
    HelpEmbedInPlace:
        en = "Modify carrier image(s) in place (creates '.bak' backup by default)",
        zh = "直接修改原图像文件（默认保留 .bak 备份，加 --no-backup 可禁用）";
    HelpEmbedOverwrite:
        en = "Overwrite existing destination file(s) without confirmation",
        zh = "覆盖已存在的目标文件而不提示确认";
    HelpEmbedNoBackup:
        en = "Do not create '<carrier>.bak' backup during in-place embedding",
        zh = "原地嵌入时不创建 .bak 备份";
    HelpEmbedEncrypt:
        en = "Ask for an encryption password when no password source is given (interactive prompt; fails without a TTY)",
        zh = "未提供密码时交互式提示输入加密密码（若无终端 TTY 则直接失败）";
    HelpEmbedSafety:
        en = "Stego capacity safety tier ('paranoid': bpp<=0.06, 'high': bpp<=0.10 [default], 'balanced': bpp<=0.15)",
        zh = "自适应隐写安全容量档位（'paranoid': bpp<=0.06, 'high': bpp<=0.10 [默认], 'balanced': bpp<=0.15）";
    HelpEmbedEnforceSafety:
        en = "Strictly reject payloads exceeding recommended safety tier instead of advisory warning",
        zh = "严格拒绝超出推荐安全档位容量的载荷（默认仅给出警告提示）";
    HelpEmbedExclusionRate:
        en = "Fraction of smoothest regions excluded from embedding (0.00-0.80, default: 0.30)",
        zh = "排除在嵌入之外的最平滑区域比例（0.00-0.80，默认: 0.30；越高越抗检，但容量越低）";

    // extract
    HelpExtractCarrier:
        en = "Stego image file to extract payload from (PNG, JPEG, HEIF/HEIC, or HEVC)",
        zh = "待提取数据的隐写图像文件（PNG、JPEG、HEIF/HEIC 或 HEVC）";
    HelpExtractOutput:
        en = "Output path to write extracted payload (file path or existing directory)",
        zh = "提取载荷的保存路径（可为具体文件名或已存在的目录）";
    HelpExtractStdout:
        en = "Print extracted payload to standard output (mutually exclusive with -o/--output)",
        zh = "将提取的载荷直接输出至标准输出（与 -o/--output 互斥）";
    HelpExtractOverwrite:
        en = "Overwrite existing destination file without confirmation",
        zh = "覆盖已存在的目标文件而不提示确认";

    // list
    HelpListJson:
        en = "Print structured JSON output containing formats, strategies, and algorithms",
        zh = "以结构化 JSON 格式输出支持的格式、策略与算法";

    // ---- Stego tuning options help ----
    HelpStegoAlgorithm:
        en = "Distortion cost algorithm (auto|hill|suniward|uerd|juniward; default: auto = hill for PNG, uerd for JPEG)",
        zh = "失真代价评估算法（auto|hill|suniward|uerd|juniward；默认: auto，即 PNG 用 hill、JPEG 用 uerd）";
    HelpStegoNeighborWeight:
        en = "Fine-tune (JPEG UERD): weight applied to 8-neighborhood block energies (default: 0.25)",
        zh = "微调参数（JPEG UERD）：8 邻域块能量权重（默认: 0.25）";
    HelpStegoP1Window:
        en = "Fine-tune (Spatial HILL): first-stage low-pass filter window size (odd, default: 3)",
        zh = "微调参数（空域 HILL）：第一级低通滤波器窗口尺寸（奇数，默认: 3）";
    HelpStegoP2Window:
        en = "Fine-tune (Spatial HILL): second-stage low-pass filter window size (odd, default: 15)",
        zh = "微调参数（空域 HILL）：第二级低通滤波器窗口尺寸（奇数，默认: 15）";
    HelpStegoStcH:
        en = "Fine-tune (STC): trellis constraint height, 4..=10 (default: 8)",
        zh = "微调参数（STC）：网格约束高度，4..=10（默认: 8）";
    HelpStegoSlotBudget:
        en = "Fine-tune (JPEG STC): slot budget for group size auto-derivation (default: automatic, a quarter of the carrier grid with a 1200000 floor)",
        zh = "微调参数（JPEG STC）：组宽自推导的槽位预算（默认: 自适应，取载体网格的 1/4，下限 1200000）";
    HelpStegoCipherSuite:
        en = "Cipher suite id (1 = PBKDF2-200k / AES-256-GCM, 2 = PBKDF2-600k / AES-256-GCM; default: 1)",
        zh = "密码套件编号（1 = PBKDF2-200k / AES-256-GCM, 2 = PBKDF2-600k / AES-256-GCM；默认: 1）";

    // ---- Capacity probe command ----
    CmdCapacity:
        en = "Probe the maximum embedding capacity of image carrier(s) without modifying them",
        zh = "探测图像载体的最大嵌入容量（不修改文件）";
    AfterHelpCapacity: en = CAPACITY_AFTER_HELP_EN, zh = CAPACITY_AFTER_HELP_ZH;
    HelpCapacityCarrier:
        en = "Carrier image file(s) (PNG, JPEG, HEIF/HEIC, or HEVC). Use `--` before a filename that starts with '-'.",
        zh = "图像载体文件（PNG、JPEG、HEIF/HEIC 或 HEVC；文件名若以 '-' 开头需在其前加 '--'）";
    HelpCapacityJson:
        en = "Print structured JSON output (one StegoCapacityInfo object per carrier)",
        zh = "以结构化 JSON 格式输出（每个载体一个 StegoCapacityInfo 对象）";
    HelpEmbedCapacity:
        en = "Probe and display maximum embedding capacity for the carrier image, then exit without modifying the carrier",
        zh = "探测并显示载体的最大嵌入容量，然后退出（不修改载体）";
    HelpEmbedDryRun:
        en = "Run the full embed in memory (capacity, safety gate, password path) and report the resulting size without writing any file",
        zh = "在内存中完整执行嵌入（容量、安全门、密码路径）并报告产物大小，不写入任何文件";

    // ---- Config warnings ----
    WarnConfigUnknownKey:
        en = "[WARNING] Unknown key '{key}' in config file '{path}' (ignored).",
        zh = "[WARNING] 配置文件 '{path}' 包含未知键 '{key}'（已忽略）。";

    // ---- Strategy selection ----
    PromptAvailableStrategies:
        en = "Available strategies for '{path}':",
        zh = "文件 '{path}' 可用隐藏策略:";
    PromptSelectStrategy:
        en = "Select strategy [1-{max}] (default 1): ",
        zh = "选择隐藏策略 [1-{max}]（默认 1）: ";

    // ---- Read / Extract warnings and messages ----
    WarnEnvelopeNotEncrypted:
        en = "[WARNING] This envelope is not encrypted: written without a password, supplied password was ignored.",
        zh = "[WARNING] 此信封未设置个人密码加密，所提供的密码已被忽略。";
    ExtractOk:
        en = "[OK] Extracted {bytes} bytes to '{path}'",
        zh = "[OK] 成功提取数据至 '{path}'（共 {bytes} 字节）";
    ExtractBinaryDetected:
        en = "[OK] Binary payload detected ({bytes} bytes). Extracted to 'extracted.bin'.",
        zh = "[OK] 检测到二进制载荷（共 {bytes} 字节），已保存为 'extracted.bin'。";

    // ---- Inspect report ----
    InspectCarrier:
        en = "Carrier: {val}",
        zh = "载体路径: {val}";
    InspectFormat:
        en = "Format:  {val}",
        zh = "载体格式: {val}";
    InspectHasHidden:
        en = "Has Hidden Data: {val}",
        zh = "隐藏数据: {val}";
    InspectStrategy:
        en = "Strategy:        {val}",
        zh = "隐藏策略: {val}";
    InspectUbeOffset:
        en = "UBE Offset:      {val}",
        zh = "信封偏移: {val}";
    InspectUbeTotalSize:
        en = "UBE Total Size:  {val} bytes",
        zh = "信封大小: {val} 字节";
    InspectEncrypted:
        en = "Encrypted:       {val}",
        zh = "是否加密: {val}";
    InspectStealth:
        en = "Stealth Mode:    {val}",
        zh = "潜行模式: {val}";
    InspectPasswordHint:
        en = "Password Hint:   {val}",
        zh = "密码提示: {val}";
    InspectOrigSize:
        en = "Original Size:   {val} bytes",
        zh = "原始大小: {val} 字节";
    InspectOrigSha256:
        en = "Original SHA256: {val}",
        zh = "原始哈希: {val}";
    InspectMetadata:
        en = "Metadata:        {val}",
        zh = "元数据:   {val}";
    InspectCapacitiesHeader:
        en = "Strategy capacities (max payload size):",
        zh = "各隐藏策略容量上限:";
    InspectAutoPreference:
        en = " [auto preference]",
        zh = " [auto 默认推荐]";
    InspectUnavailable:
        en = " (unavailable)",
        zh = " (当前不可用)";
    InspectStegoHeader:
        en = "Content-Adaptive Steganography Capacity (embed):",
        zh = "自适应隐写容量（embed）:";
    InspectStegoAlgorithm:
        en = "  Algorithm:       {val}",
        zh = "  隐写算法:     {val}";
    InspectStegoSlots:
        en = "  Available Slots: {val} bits",
        zh = "  可用槽位:     {val} 比特";
    InspectStegoMaxRaw:
        en = "  Max Raw:         {bytes} bytes ({kib:.1} KiB)",
        zh = "  最大原始载荷: {bytes} 字节 ({kib:.1} KiB)";
    InspectStegoMaxRawGrouped:
        en = "  Max Raw:         {bytes} bytes ({kib:.1} KiB) (grouped-code bound; Huffman table over-optimised, u=1 refused)",
        zh = "  最大原始载荷: {bytes} 字节 ({kib:.1} KiB)（分组码上限；Huffman 表过优化，u=1 不可用）";
    InspectStegoSafeMax:
        en = "  Safe Max:        {bytes} bytes ({kib:.1} KiB) (high stealth)",
        zh = "  推荐安全容量: {bytes} 字节 ({kib:.1} KiB)（高抗检隐蔽）";
    WarnInspectFailed:
        en = "[WARN] failed to inspect '{path}': {err}",
        zh = "[WARN] 检查文件 '{path}' 失败: {err}";
    InspectSummary:
        en = "Inspected {total} file(s), {hidden} with hidden data, {failed} failed.",
        zh = "共检查 {total} 个文件: {hidden} 个含隐藏数据，{failed} 个检查失败。";

    // ---- Verify report ----
    VerifyL1:
        en = "Level 1 (Host Format):      [{status}] {detail}",
        zh = "级别 1 (宿主格式):      [{status}] {detail}";
    VerifyL2:
        en = "Level 2 (Envelope Boundary): [{status}] {detail}",
        zh = "级别 2 (信封边界):      [{status}] {detail}";
    VerifyL3:
        en = "Level 3 (Crypto & Payload):  [{status}] {detail}",
        zh = "级别 3 (密码学与载荷):  [{status}] {detail}";
    WarnVerifyFailed:
        en = "[WARN] failed to verify '{path}': {err}",
        zh = "[WARN] 校验文件 '{path}' 失败: {err}";
    VerifySummary:
        en = "Verified {total} file(s): {passed} passed, {failed} with verification failures, {unreadable} unreadable.",
        zh = "共校验 {total} 个文件: {passed} 个通过，{failed} 个未通过，{unreadable} 个无法读取。";

    // ---- Scan report ----
    WarnScanFailed:
        en = "[WARN] failed to scan '{path}': {err}",
        zh = "[WARN] 扫描文件 '{path}' 失败: {err}";
    WarnSkippedMissing:
        en = "[WARN] '{path}' does not exist, skipping",
        zh = "[WARN] '{path}' 不存在，已跳过";
    ScanSummary:
        en = "\nScanned {total} file(s), {findings} with findings, {failed} failed.",
        zh = "\n共扫描 {total} 个文件: {findings} 个存在异常检出，{failed} 个扫描失败。";

    // ---- List table ----
    ListCarrierDependentNotice:
        en = "Carrier-dependent limits are measured by `strhide inspect <carrier>`.",
        zh = "具体载体文件的实际容量请使用 `strhide inspect <carrier>` 测量。";
    ListStegoAlgorithmsHeader:
        en = "\nContent-Adaptive Steganography Algorithms (embed / extract):",
        zh = "\n内容自适应图像隐写算法（embed / extract）:";

    // ---- Stego capacity probe ----
    StegoProbeHeader:
        en = "Content-Adaptive Steganography Capacity for '{path}':",
        zh = "文件 '{path}' 的自适应隐写容量:";
    StegoProbeFormat:
        en = "  Format:          {val}",
        zh = "  图像格式:     {val}";
    StegoProbeAlgorithm:
        en = "  Algorithm:       {val}",
        zh = "  隐写算法:     {val}";
    StegoProbeTotalElements:
        en = "  Total elements:  {val}",
        zh = "  总元素数:     {val}";
    StegoProbePayloadSlots:
        en = "  Payload slots:   {val} slots (body only; header slots excluded)",
        zh = "  载荷槽位:     {val} 个（仅主体；已排除头部槽位）";
    StegoProbeMaxRaw:
        en = "  Max raw payload: {bytes} bytes ({kib:.1} KiB)",
        zh = "  最大原始载荷: {bytes} 字节 ({kib:.1} KiB)";
    StegoProbeMaxRawGrouped:
        en = "  Max raw payload: {bytes} bytes ({kib:.1} KiB) -- grouped-code bound; this carrier's Huffman table is over-optimised, so u=1 (one slot per bit) is refused",
        zh = "  最大原始载荷: {bytes} 字节 ({kib:.1} KiB)（分组码上限；载体 Huffman 表过优化，u=1 每比特单槽位模式不可用）";
    StegoProbeRecommended:
        en = "  Recommended max: {bytes} bytes ({kib:.1} KiB) (tier: {level}, bpp <= {bpp})",
        zh = "  推荐安全容量: {bytes} 字节 ({kib:.1} KiB)（档位: {level}, bpp <= {bpp}）";
    StegoProbeEstChanges:
        en = "  Est. changes:   ~{rate:.3} per payload bit (matrix coding); recommended payload is anchored to low-risk region",
        zh = "  预估修改率:   ~{rate:.3} 每有效比特（矩阵编码）；推荐载荷已锚定至统计低风险区";

    // ---- Embed execution ----
    EmbedOkDest:
        en = "[OK] Embedded {bytes} payload bytes into '{carrier}' -> '{dest}' (took {elapsed})",
        zh = "[OK] 成功将 {bytes} 字节载荷嵌入 '{carrier}' -> '{dest}'（耗时 {elapsed}）";
    EmbedOkInPlace:
        en = "[OK] Embedded {bytes} payload bytes in-place into '{carrier}' (took {elapsed})",
        zh = "[OK] 成功将 {bytes} 字节载荷原地嵌入 '{carrier}'（耗时 {elapsed}）";

    // ---- Multi-carrier batch execution ----
    FailCarrier:
        en = "[FAIL] {path}",
        zh = "[FAIL] {path}";
    SummaryBatchPartial:
        en = "[SUMMARY] {done}/{total} carriers succeeded; {unattempted} not attempted.",
        zh = "[SUMMARY] 批处理完成: {done}/{total} 个成功，{unattempted} 个跳过。";
    SummaryBatchAll:
        en = "[SUMMARY] {done}/{total} carriers succeeded.",
        zh = "[SUMMARY] 批处理完成: 全部 {done}/{total} 个载体均已成功处理。";

    // ---- Write & Restore result ----
    WriteOk:
        en = "[OK] Successfully embedded into '{carrier}' using strategy '{strategy}'.",
        zh = "[OK] 成功写入载体 '{carrier}'（策略: {strategy}）。";
    WritePayloadUbe:
        en = "     Payload: {raw} bytes -> UBE: {ube} bytes.",
        zh = "     载荷大小: {raw} 字节 -> 信封大小: {ube} 字节。";
    WriteStrategyNote:
        en = "     [STRATEGY] {note}",
        zh = "     [STRATEGY] {note}";
    WritePasswordHint:
        en = "     Password Hint: '{hint}'.",
        zh = "     密码提示: '{hint}'。";
    WriteBackupNote:
        en = "     [BACKUP] Original carrier backed up to '{path}'.",
        zh = "     [BACKUP] 原始载体已备份至 '{path}'。";
    WriteWarningNote:
        en = "[WARNING] {warn}",
        zh = "[WARNING] {warn}";
    RestoreOk:
        en = "[OK] Successfully stripped hidden data from '{carrier}'.",
        zh = "[OK] 成功清除隐藏数据，宿主已还原: '{carrier}'。";
    RestoreSize:
        en = "     Restored size: {bytes} bytes.",
        zh = "     还原后大小: {bytes} 字节。";
    RestoreSha256:
        en = "     SHA-256: {sha} (100% verified identical to original).",
        zh = "     SHA-256: {sha}（100% 校验与原文件完全一致）。";
    RestoreBackupNote:
        en = "     [BACKUP] Prior carrier backed up to '{path}'.",
        zh = "     [BACKUP] 修改前载体已备份至 '{path}'。";
}
