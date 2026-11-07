# 两份审查报告的复核与处置建议（2026-11-07 20:10）

复核对象：
- `docs/CODE_REVIEW_VERIFICATION_20261107.md`（下称 **VERIFY**，基线 `ec8146b`，已落 5 个修复提交）
- `docs/REACHABLE_BUGS_AUDIT_20261107.md`（下称 **AUDIT**，基线 `ec8146b` + 工作区）

当前 HEAD：`e25278a`（VERIFY 的文档提交），二进制 `strhide 0.9.3 (49ef993)`。

方法：不采信报告结论，逐条回源码定位 + 命令行实证。AUDIT 快照早于 `deb8ccd`/`49ef993`，
因此其中一部分问题在 HEAD 上已经修掉，必须先剔除再谈处置。

---

## 一、结论总表

| AUDIT 条目 | 真实？ | 该修？ | 依据 |
| --- | --- | --- | --- |
| 1 非 UTF-8 stdout 绕过转义 | 是（可达性窄） | 修，改动极小 | `render.rs:130` 的 `_ =>` 分支裸写 |
| 2 批量 `inspect` 退出码恒 0 | 是 | 修，必改 | 实测 good+bad → 0，同场景 `verify` → 1 |
| 3 JPEG 约 5% 偶发失败 | 未复现 | 暂不修 | 42 次近满容量嵌入 0 次 `missing_symbol` 失败 |
| 4 PNG 双域被辅助 chunk 破坏 | **是（但触发路径错）** | 修，发布前决策 | 实测插入 `tEXt` 后 `No valid payload found`；`png_text` 策略不存在 |
| 5 `verify` 通过但 `restore` 拒绝 | 是（设计已知） | 维持 deferred + 低成本提示 | 代码注释已诚实标注；改造成本高 |
| 6 载荷文件权限 / zeroize | 部分（Unix-only） | 权限可小改，zeroize 单独立项 | `write_bytes_atomic` 无 mode 设置；全仓无 zeroize |
| 7 `extract_file` 缺 `TargetLock` | 是（后果轻微） | 可选 | 原子写已保证无半文件，仅"后写覆盖" |
| 8 `--stdin` 无上限 | **已修** | 否 | `cmd_stego.rs:295-300`，1 GiB |
| 9 `pe_codebits` 破坏可执行文件 | 是（概率未知） | 需产品决策 | `pe.rs:176` 让 `auto` 优先选它 |
| 10 README 用 `sth` | **已修** | 否 | `rust/README.md` 已统一 `strhide` |

VERIFY 的 7 项遗留（P1-1/P1-2 Windows/P1-3 DataDirectory/P1-6/P2-14/P2-16/P3-8/P3-9）复核后
**维持原判定**，其中 P1-2 的"Windows 硬链接不可检测"有新证据（见 §4.1）。

---

## 二、必修：真实且值得现在改

### A1. 批量 `inspect` 的失败信号完全丢失（AUDIT #2，成立）

三层缺陷叠加，`--json` 消费者拿到的是一份"看起来全成功"的报告：

1. `cmd_diag.rs:659-676` `expand_input_paths`：不存在的路径只在 stderr 打 `WarnSkippedMissing`，
   直接不进 `files`，于是既不进 `failures`，也不进 JSON 数组；`-q` 下连 stderr 都没有。
2. `cmd_diag.rs:206` 批量分支不管 `failures` 多少都 `Ok(())`。
3. 结果：单文件路径（走 `?`）报错退出 1，批量路径退出 0 —— 同一份输入换个写法结论相反。

实测（`d.png` 是有效 PNG，`ghost.png` 不存在，`not_a_carrier.bin` 是文本文件）：

```text
inspect d.png ghost.png          -> exit 0   汇总行: "共检查 1 个文件: ... 0 个检查失败"
inspect d.png ghost.png --json   -> exit 0   JSON 里没有 ghost.png 的任何条目
inspect a.bin b.bin      (都失败) -> exit 0
verify  d.png a.bin              -> exit 1
```

修法：`failures > 0` 时返回 `StrHideError::General`（或复用 `cmd_diag.rs:580-589` 已有的
worst-rank → exit code 辅助函数），并把 `WarnSkippedMissing` 的路径折进 `failures`/JSON。
影响面：无基线影响，补 2 条 CLI 测试即可。

### A2. PNG 内容域载荷一旦遇到辅助 chunk 变化就永久不可读（AUDIT #4，成立但描述错）

AUDIT 给的复现命令是假的：PNG 策略只有 `chunk` / `eof`，**不存在 `png_text`**；
`write` 也没有 `-f` 参数（是 `-d`）。但底层问题真实，而且比它描述的更容易触发。

`png_pre_salt`（`stego/png/engine.rs:1162-1184`）把除 `IDAT`/`prIv` 外的**全部** chunk
（类型+长度+数据）混进 L1 PBKDF2 盐。任何外部工具（exiftool、tinypng、编辑器另存、加 ICC 配置）
插入/删除一个 `tEXt`/`iCCP`/`tIME`，派生出的定位密钥和网格坐标就全变，提取端直接
`No valid payload found`，**用户数据静默不可恢复**。

实测（同一张已嵌入 20 B 载荷的 PNG，仅补一个合法的 `tEXt` chunk 并重算 CRC）：

```text
extract d.png      -> content-secret-12345
extract d_text.png -> [ERROR] No valid payload found
```

而默认结构域写入（`chunk` 策略写 `prIv`）不触发，所以 `heavy_dual_domain_coexistence_matrix`
这类测试是绿的 —— 测试覆盖了"我们自己"的双域顺序无关，没覆盖"第三方工具改了元数据"。

修法：盐只绑定稳定的图像身份（IHDR 的宽/高/位深/颜色类型/通道 + `PLTE` + `sRGB`/`gAMA` 之类
影响像素解释的块），不再吃 `tEXt`/`zTXt`/`iTXt`/`tIME`/`eXIf` 等辅助块。
代价与前置条件：
- 定位密钥变化 → 所有 PNG 嵌入输出字节变化 → `baseline_hash --check` 必然红，需确认后 `--write` 重建；
- 需要同步改 `docs/` 里的 PNG 线格式/密钥派生规范；
- 项目未发布，此时改没有兼容包袱，**越晚代价越大**。
- 反方向代价：失去"元数据也参与绑定"的弱身份约束（几何仍绑定），这个取舍需要你拍板。

低成本兜底（若不改 KDF）：提取失败时若能定位到信封但探针全失败，就提示
"载体元数据可能已改变，本工具无法恢复" —— 但**数据仍然救不回来**，只是把静默变明示。

### A3. 非 UTF-8 载荷绕过终端转义（AUDIT #1，成立，可达性比描述窄）

`render.rs:120-133`：`escape == true` 时只对合法 UTF-8 调 `escape_terminal_text`，
`str::from_utf8` 失败就 `out.write_all(data)` 裸写。终端按字节解释，非 UTF-8 里夹的
`ESC[2J` / `OSC 52` 照样生效，转义形同虚设。

可达性实测收窄了 AUDIT 的说法：
- `read`/`extract` 对 `is_file = true` 的载荷会落盘，不会走 stdout；
- `--text-base64` 拒绝非 UTF-8（`Base64 content is not valid UTF-8`），正常 CLI 写不出
  "文本类但非 UTF-8"的载荷；
- 因此只有**构造过的信封**（`is_file = false` + 非 UTF-8 数据；未加密信封任何人都能造）
  才能命中。也就是说这是"恶意载体 → 用户终端"的攻击面，不是日常误触。

修法：`_` 分支改为不写原始字节——输出 `[binary payload: N bytes; use -o/-f to save]`，
或按十六进制小窗展示。`--stdout`（`escape_on_pipe = false`）保持字节精确不变。
影响面：无基线影响，补 1 条单测（构造非 UTF-8 + `escape=true`）。

### A4. PE `auto` 默认优先写 `.text`（AUDIT #9 前半，成立，需决策）

`adapters/pe.rs:176-207` `choose_auto_strategy` 的第一优先级是 `pe_codebits`，
即 `strhide write app.exe` 默认会改可执行文件的指令编码。而 `pe_codebits` 是线性扫描
（`pe_codebits.rs:219-228`，F0 只跳过 `Code::INVALID`），`.text` 里内联的跳转表/常量表
若恰好解码成 `MOV/CMP/ADD/XOR/TEST` 的寄存器-寄存器形式并通过 F2/F4/F5，就会被当成指令翻转，
特定分支运行时崩溃。这是线性反汇编的固有缺陷，不是实现 bug。

它不是"必现 bug"，但默认路径把一个不可验证的风险（不改完跑一遍不知道有没有坏）放在最高优先级。
建议二选一，任选都要改基线里的 PE 用例：
- 保守：`auto` 顺序改为 `pe_slack → pe_overlay → pe_codebits`，`pe_codebits` 需 `-s` 显式指定，
  README/`list` 标注"高级/实验性"；
- 折中：保留优先级，但 `write <pe>` 在选中 `pe_codebits` 时打一条显式 warn（"已修改 .text，
  请验证程序仍可运行"）。

---

## 三、真实但建议维持"不修/缓修"

### B1. `verify` 不校验宿主可恢复性（AUDIT #5 = VERIFY P1-6）
`structure/engine.rs:3155-3177` 只做 L1 容器 / L2 信封 / L3 载荷 SHA；`orig_host_sha256`
只在 `remove` 路径（`:2310` 附近）比对。行为确实自相矛盾（verify 全绿 → restore 报
`RestoreMismatch`），但这是**篡改检测**在工作，不是数据损坏；修它要重跑各格式 strip 并处理回退 seek，
成本远高于收益。

低成本改进（可做）：`verify` 输出里加一行明确的 `host restorability: not checked`
（或给 `VerifyResult` 加 `host_restorable: Option<bool>` = `None`），把"三层全绿 = 可还原"
的错觉消掉。文档已经改了（`00b47e5`），CLI 输出还没改。

### B2. 提取载荷落地文件无权限控制（AUDIT #6 前半）
`core/commit.rs:623-639` `write_bytes_atomic` 用 `File::create`，Unix 下即 `0666 & ~umask`（多为 0644）。
载体本身不受影响：`commit_carrier_bytes:464-508` 会恢复原 carrier 的 permissions，
所以问题只在"提取出的明文载荷是新文件"这一条路径。
小改动可选：Unix 下对提取路径 `set_permissions(0o600)`；但要区分"载荷输出"与"载体输出"，
不能一刀切在 `write_bytes_atomic` 里。

### B3. zeroize（AUDIT #6 后半）
全仓无 `zeroize`/`Zeroizing`，密钥、IKM、密码结构体都不清零。是真实的纵深防御缺口，但要新增依赖 +
逐个敏感类型改 Drop，属于单独立项，不该塞进审查修复。

### B4. `extract_file` / CLI 提取不持 `TargetLock`（AUDIT #7）
锁只在 `stego/io.rs:55`、`structure/engine.rs:1521,2399` 三处（写载体）获取；
`facade.rs:1058`、`cli/cmd_stego.rs:748/769/794` 提取落盘不获取。
但落盘已经是 temp+fsync+rename，**不会出现半文件**，后果仅限于"两个并发提取同一目标，后者覆盖前者"，
与写载体的"丢更新"性质不同。加锁还会让脚本偶发收到 `TargetBusy`。收益低，暂不动。

### B5. macOS 内存查询 / 单特性 clippy / 产物命名（VERIFY P2-14、P2-16、P3-8/P3-9）
维持 deferred：macOS 需要 `sysctlbyname` FFI，本机（Windows）无法编译验证；
子集 `-D warnings` 要动大量 `cfg`；产物命名与 GUI 手动发布流程是发布策略。

---

## 四、不成立 / 已修，别再花时间

### C1. JPEG 5% 偶发失败（AUDIT #3 / VERIFY P1-1）
- 代码注释（`jpeg/engine.rs:556-562`）自身的算术就不自洽：单次 1/3，6 次重试是 (1/3)^6 ≈ 1/729，
  不是注释写的 "one in twenty"（1/20 对应单次 ≈ 0.6）。AUDIT 的 5% 是从这句话抄来的。
- 实测：5 个真实 JPEG，载荷 700-810 KiB（接近满容量，反复 42 次），**0 次 `missing_symbol` 失败**；
  唯一的失败是 `img_jpg_0003` 的确定性容量不足（`have 5921254 < need 6480263 slots`），与重试无关。
- 结论：没有可复现样本就不要调参；若将来真出现，先做"尝试次数-失败率"测量，再决定是否把
  `missing_symbol` 暴露成可重试错误类型。`EMBED_ATTEMPTS` 只有在失败时才付费，调大本身无副作用，
  但属于无证据试错，不建议现在改。

### C2. 已在 HEAD 修复，AUDIT 快照过期
| AUDIT # | 现状 |
| --- | --- |
| 8 `--stdin` 无上限 | `cli/cmd_stego.rs:295-300`，`take(1 GiB + 1)` |
| 10 README 用 `sth` | `rust/README.md` 已统一 `strhide` |
| 排除项里的 symlink/硬链接、PE FORCE_INTEGRITY/CheckSum、release `--features cli` | `49ef993`、`17b5e4c` |
| `--json` 批量丢失败项 | `deb8ccd` 已把失败项写进数组（但见 A1：预过滤跳过的文件仍不在内） |

### C3. AUDIT 里"看起来能跑"的命令其实不存在
`strhide embed photo.jpg -f secret.txt`（`embed` 无 `-f`，是 `-d`）、`strhide write ... -s png_text`
（无此策略，PNG 只有 `chunk`/`eof`）。`strhide extract carrier.png --stdout` 是合法的，这一条没问题
（但 `extract --stdout` 在终端上走的是 `escape_on_pipe = false`，本来就不转义，与 A3 无关）。
复核这类报告时，命令必须先用 `--help` 对齐，否则会把"写错的命令"当成"复现步骤"。

---

## 五、建议的动手顺序

1. **A1**（退出码 + 缺文件计入失败）：零风险，纯 CLI 层，先做。
2. **A3**（二进制载荷不裸写终端）：一行分支，先做。
3. **A2**（PNG 盐收敛到几何/调色板）：需要你决定"是否接受失去元数据绑定 + 重建基线"，
   决定后单独一个提交，同步改线格式规范。
4. **A4**（PE 默认策略）：产品决策，改完要重建 PE 基线。
5. **B1 的低成本部分**（verify 输出显式标注 "host restorability: not checked"）。
6. 其余维持 deferred，写进 `CHANGELOG` 的 known-limitations 更合适，而不是继续堆代码。

验收命令按 `AGENTS.md`：`cargo fmt` → `clippy -D warnings` → `build --release --all-features`
→ `test --all-features --all-targets` → `local_`/`heavy_` → `import_lint` → `baseline_hash --check`
（A2/A4 会红，需确认后 `--write`）。

---

## 六、处置结果（2026-11-07 20:48 完成）

| 条目 | 处置 | 关键证据 |
| --- | --- | --- |
| A1 批量 `inspect` 退出码 | 已修：缺文件进 `failures`/`--json`，`failures > 0` → exit 1；`verify` 同步 | `inspect good.png ghost.png` 0 → 1；`--json` 含 `{"path":"ghost.png","error":"file does not exist"}`；全部存在时仍为 0 |
| A2 PNG 派生盐 | 已修：只绑定关键块（`IHDR`/`PLTE`/`IEND`），排除全部辅助块 | 追加 `tEXt` 后仍可提取；改几何/调色板仍失败；标准载体盐不变 |
| A3 终端裸写二进制 | 已修：`plan_payload_stdout` 分出 `BinaryNotice`，`--stdout` 保持字节精确 | 4 条单测；`extract --stdout | od` 字节不变 |
| A4 PE 默认策略 | 已修：`auto` = `pe_slack → pe_overlay`，`pe_codebits` 仅显式 | 见下方"损坏实证" |
| B1 `verify` 宿主可恢复性 | 维持 deferred（文档已收敛） | 改造成本 > 收益，见 §3 |
| B2/B3 权限/zeroize、B4 `TargetLock` | 未动（低优先，理由见 §3） | — |
| C1 JPEG 5% 失败 | 不修：42 次近满容量 0 次 `missing_symbol` | 见 §4.1 |

### 4.1 补充：PE `pe_codebits` 的损坏实证（A4 的决策依据）

不是靠推断，而是构造了一个能跑出结果的载体：

1. 用 MSYS64 gcc 编译一个 PE，`.text` 里放 1700 组 `16×NOP + 01 C8`（`ADD eax, ecx` 的等长等价对，
   数据表用途），`main` 对整张表做 FNV 哈希并打印；
2. `strhide write proof.exe -d 100B.bin`（写入前把人工构件的 CheckSum 清零以通过完整性门控）。
   旧 `auto` 选 `pe_codebits`，信封 319 B；
3. 程序仍能启动，但输出 `9395146a7b177b93` → `806ccc696fb2cdcf`：表里 **844 个字节** 被 `01`→`03` 改写
   （`ADD eax, ecx` → `ADD ecx, eax`，长度相同、解码合法、数据全变）；
4. `strhide restore` 后逐字节还原、输出复原 —— 说明这不是"还原"的问题，而是**携带期内可执行语义已被改变**；
5. 同样的载体改用新 `auto`（`pe_slack`）写入，程序输出不变。

真实二进制里这些字节就是 switch/jump table：改写后只在读到那条分支时才炸，任何"写完还能启动"的冒烟测试都发现不了。
因此 `pe_codebits` 保留但改为显式策略，并在 `inspect` 的 note 里标注 opt-in。

### 4.2 验收

`fmt`/`clippy -D warnings`/`build --release --all-features`/`test --all-features --all-targets`（EXIT=0）/
`local_` 19 passed/`heavy_` 5 passed/`import_lint` OK/`feature_matrix` 11-11/`baseline_hash --check` 28-28。
基线因 A2、A4 重建（只影响 2 个 PNG + 2 个 PE 用例），旧文件备份在 `temp/baseline/baseline.json.bak-20261107`。
