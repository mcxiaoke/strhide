# strhide

**智能格式保持、无损数据隐藏工具。** 将文本或文件隐藏到普通宿主文件（PNG、JPEG、WebP、HEIC/HEIF、MP4、WAV、MKV、ZIP、PDF、Windows PE 可执行文件）中，不改变宿主的可见格式、外观和功能，事后可逐比特还原原始宿主文件。

本仓库提供两套实现：

| 实现 | 语言 | 状态 |
| --- | --- | --- |
| [`rust/`](rust/) | Rust (edition 2024) | **主力维护中（0.8.x）**——单文件静态二进制，从源码构建 |

> [English documentation (README.md)](README.md)

## 特性

- **格式保持**——宿主文件仍是合法的 PNG/JPEG/WebP/HEIF/MP4/WAV/MKV/ZIP/PDF/PE，可正常显示、播放或运行。
- **100% 可逆**——信封中嵌入原始宿主的 SHA-256，`read`/`restore` 输出保证与原文件逐比特一致。
- **落盘即加密**——每个信封在写入载体前都经 Deflate 压缩与 AES-256-GCM 加密。不设密码时使用内置密钥，载体中不会泄露明文载荷、宿主哈希或文件名；设置密码则获得真正的密钥分离（PBKDF2-HMAC-SHA256 10 万轮 + HKDF-SHA256，分块 GCM）。
- **隐写模式（Stealth）**——设置密码后，信封签名与头部字段均由密码派生，没有密码就无从发现隐藏数据。即使在默认（非 stealth）模式下也没有静态 ASCII 魔数：不存在 `STRHIDE` / `STH!` 这类字符串，只有高熵二进制签名（旧版 ASCII 魔数已不再被识别）。
- **黑盒隐写分析**——`scan` 把文件视为未知对象，报告来自**任意工具**（不只是 strhide）的结构与统计特征异常；JPEG 额外走**校准式 DCT 检验**（`dct:calibration`），并明确标注 `clean` 不构成「无隐藏数据」的证据。
- **密码提示**——可选（≤ 1 KiB）的提示信息随信封存储，在需要输入密码时展示。
- **默认安全**——完整性/签名拒绝检查会拒绝修改不宜触碰的文件（如签名二进制）；`write`、`restore` 与 `embed` 默认输出至 `<stem>-out.<ext>` 新文件，原始宿主 100% 保持干净；提供显式 `--in-place` 选项进行原地修改（自动创建 `.bak` 备份）；`read`、`extract`、`write` 和 `restore` 默认拒绝覆盖已存在的输出文件（需 `--overwrite` 才允许）；保留原始文件时间戳。
- **TOML 配置**——exe 同目录、用户配置目录（`~/.config/strhide/config.toml`、`%APPDATA%\strhide\config.toml`）或系统配置目录提供默认值（不查找当前工作目录，且不支持在配置中写死密码/密钥文件），显式命令行参数（`-c, --config`）始终优先（详见注解模板 [`strhide.sample.toml`](strhide.sample.toml)）。
- **批量与递归载体**——`write`、`restore`、`scan`、`inspect`、`verify`、`embed` 均支持一次处理多个文件或目录递归扫描（`-r, --recursive`）；`read` 针对单个载体。
- **内容自适应隐写（HILL、UERD 与 Scheme C）**——`embed` 与 `extract` 命令直接在图像像素（PNG，按 HILL 成本模型选位）、DCT 频域系数（JPEG，通过 UERD 成本模型）或 H.265/HEVC 变换系数旁路符号位（HEIF/HEIC、HEVC Annex-B 裸流与 MP4/MOV 视频，Scheme C）中嵌入数据。与结构层注入不同，内容隐写修改的是最小失真纹理区，可抵御重封包与元数据剥离清洗。HEIF/HEIC 与 HEVC 隐写达成零字节膨胀（$\Delta = 0$）与标准句法合规，并内建 EPB 竞争防护。PNG 像素写入采用**三元 ±1 匹配**：修改被约束在像素所在的八值类内（`val & 0xF8`），因此概率质量会跨值对边界流动，而不是把每个值对压平——后者正是卡方/SPA 检测器攻击的目标。实测：本仓库语料满容量嵌入后自检分数由 50/100（SUSPICIOUS，RS+SPA）降到 25/100（LOW，仅 SPA）。

## 安装

**预编译二进制（推荐，无需 Python 或 Rust 工具链）：**

从 [GitHub Releases](https://github.com/mcxiaoke/strhide/releases/latest) 下载：

| 平台 | 文件 |
| --- | --- |
| Windows x64 | `strhide-windows-x86_64.exe` |
| Windows ARM64 | `strhide-windows-aarch64.exe` |
| macOS（Intel + Apple Silicon） | `strhide-macos-universal2` |
| Linux x64（全静态） | `strhide-linux-x86_64` |
| Linux ARM64（全静态） | `strhide-linux-aarch64` |

```bash
chmod +x strhide-macos-universal2          # macOS / Linux
./strhide-macos-universal2 --help
sha256sum -c SHA256SUMS.txt                # 校验下载文件
```

> **macOS（未公证）：** Gatekeeper 会拦截未公证的下载二进制。可右键文件 → **打开**，或执行 `xattr -d com.apple.quarantine ./strhide-macos-universal2`。
>
> **Windows：** SmartScreen 可能提示未签名程序——选择 **更多信息 → 仍要运行**。

**从源码构建：**

```bash
cd rust
cargo build --release
# 产物位于 target/release/strhide
```

### 域专用入口

CLI 发布包内除全功能 `strhide` 外，还有 3 个"精简入口"，与全量入口**共用同一份 lib 代码**
（行为、参数定义完全一致，只是命令树更小、`--help` 更清晰）：

| 可执行文件 | 子命令 |
| --- | --- |
| `strhide` | 全部 10 个（全功能工具） |
| `sthc` | `write`、`read`、`restore` —— 容器内封装信封 |
| `sths` | `embed`、`extract`、`capacity` —— 内容自适应隐写 |
| `sthv` | `inspect`、`verify`、`scan`、`list` —— 只读诊断分析 |

```bash
sthc write photo.png -t "meet me at 7"
sths embed photo.png -t "机密信息" -o stego.png
sthv inspect report.pdf --json
```

全局选项（`-c/--config`、`-q/--quiet`、`--lang`）、所有参数定义与全部处理逻辑都与全量 `strhide`
共享，域入口只是收窄了命令列表。

## 命令行快速上手

```bash
# 在图片中隐藏文本（默认写入 photo-out.png，原始 photo.png 保持未修改）
strhide write photo.png -t "meet me at 7"

# 或显式进行原地写入（修改原图并创建 photo.png.bak 备份）
strhide write photo.png -t "meet me at 7" --in-place

# 通过管道隐藏文本（其他载荷源：-d 文件、--text-base64）
cat secret.txt | strhide write image.jpg --stdin

# 隐藏文件，加密并附加密码提示
strhide write report.pdf -d secret.zip -p "S3cret!" -H "my usual one"

# 提取隐藏数据（默认拒绝覆盖已存在文件，需 --overwrite 才允许）
strhide read photo-out.png -o out/
strhide read photo-out.png --stdout

# 批量提取：多个载体写入同一目录。未记录文件名的载荷按载体命名（a.png → a.txt），
# 因此不会互相覆盖
strhide read a.png b.png -o out/

# 黑盒隐写分析：递归扫描文件或整个目录，检测来自任意工具的隐藏内容
# （结构 + 统计特征，不依赖 strhide 内部知识）；支持 --json
strhide scan suspicious.bin ./downloads -r

# 同一份扫描，静默执行并以退出码判定：任一文件被判 "likely-hidden" 则退出码 1，
# 否则 0（suspicious/low 级发现不影响退出码）
strhide scan suspicious.bin ./downloads -r -q

# 查看信封元数据与各策略容量（支持多载体及 -r 递归扫描目录）；支持 --json
strhide inspect report.pdf --json
strhide inspect ./photos -r --json

# 校验宿主与信封完整性（3 级检查，支持多载体与 -r 递归；支持 --json）
strhide verify report.pdf ./photos -r

# 移除隐藏数据，还原原始宿主文件（默认输出为 <carrier>-out.<ext>）
strhide restore photo-out.png -o restored.png
# 或原地还原载体：
strhide restore photo.png --in-place

# --- 内容自适应像素/DCT/CABAC隐写（免疫第三方元数据与chunk清洗）---

# 探测图片的最大安全隐写容量（不修改原图）
strhide embed photo.png --capacity
strhide embed photo.heic --capacity

# 将文本或文件嵌入复杂高频纹理中（PNG 默认 HILL，JPEG 默认 UERD，HEIF/HEIC/HEVC/MP4 默认 Scheme C）
strhide embed photo.png -t "机密信息" -p "P@ss123" -o stego.png
strhide embed cover.jpg -d secret.zip -p "P@ss123" --in-place
strhide embed photo.heic -t "机密信息" -p "P@ss123" -o stego.heic

# 提取内容自适应隐藏数据（支持 --stdout 与 --overwrite 防护）
strhide extract stego.png -p "P@ss123" --stdout
strhide extract stego.jpg -p "P@ss123" -o recovered.zip --overwrite
strhide extract stego.heic -p "P@ss123" --stdout

# 批量：把同一份载荷写入多个载体（输出到目录或默认各自输出为 <stem>-out.<ext>），再批量还原
strhide write a.png b.png c.png -t "meet me at 7" -o done/
strhide restore done/a.png done/b.png done/c.png -o restored/

# 列出全部格式、策略及其容量上限（支持 --json 格式化输出）
strhide list --json
```

密码来源（按顺序检查）：`-p/--password` → `--password-file` → 环境变量 `STRHIDE_PASSWORD` → 交互式输入（`-e/--encrypt`）。`-p` 与 `--password-file` 互斥（注意：配置文件出于安全原因不支持配置密码）。

`write` 的载荷源同样互斥：`-d/--data`、`-t/--text`、`--text-base64`、`--stdin` 不可同时使用。都不提供时，环境变量 `STRHIDE_TEXT` 作为最后兜底。

> **安全提示**：通过 `-p` 传入的密码可能经 shell 历史和进程列表泄露，建议优先使用 `--password-file`、`STRHIDE_PASSWORD` 或交互式输入。

## Rust 库 API

`strhide` 也可作为库使用。推荐入口是一个 **`StrHide`** 实例：构造时绑定一个私有方言（`Dialect`）和一个写侧行为基线（`LocalParams`），两个域各有一个子门面——`.structure()` 是容器信封、`.stego()` 是像素 / DCT / CABAC 嵌入。整个方言可以在编译期声明为 `const`（零运行时开销），并同时提供文件路径与内存（`&[u8]` → `Vec<u8>`）两种形态。

```rust
use strhide::facade::{Dialect, StrHide};
use strhide::structure::{PayloadSource, ReadOptions, WriteOptions};

// 整个私有方言在编译期声明，同时覆盖两个域。
const ENGINE: StrHide = StrHide::new()
    .with_dialect(Dialect::new().with_default_secret("my-deployment-key"));

// 结构域（内存形态）：
let (stego, _) = ENGINE.structure().write_bytes(
    &cover,
    PayloadSource::Bytes(b"secret"),
    &WriteOptions::default(),
)?;
let read = ENGINE.structure().read_bytes(&stego, None)?;
assert_eq!(read.data, b"secret");

// 内容域（图像隐写，内存形态）：
let stego = ENGINE.stego().embed(&jpeg, &Payload::bytes(b"secret"), &EmbedOptions::default())?;
let payload = ENGINE.stego().extract(&stego, &ExtractOptions::default())?;
assert_eq!(payload.as_bytes(), b"secret");
```

接入前值得知道的三点：

- **强类型选项，不是位置参数。** 结构域用 `WriteOptions` / `ReadOptions` / `RestoreOptions`，内容域用 `EmbedOptions` / `ExtractOptions` / `ProbeOptions` / `InspectOptions` / `VerifyOptions`；`ReadOptions::new().with_password("pw").with_overwrite(true)` 不会像 `read(p, out, Some("pw"), true)` 那样被读错。
- **强类型结果。** `WriteResult.format` 是 `FileFormat`，`strategy` 是 `StrategyId`（注册表 id + 名称），`backup_file` 是 `PathBuf`，`warnings` 是带 `kind` 标签的 `Warning` 列表——前端不需要解析任何散文。
- **给 GUI 的错误。** `StrHideError::detail_i18n()` 返回 `ErrorDetail { category, detail, hint }`，`ErrorDetail::render(lang)` 输出与 CLI 同一行；UI 线程可用自己的语言渲染，无需从英文文本里反解。

宿主还可以用绑定的方言驱动自己的命令行（支持全量或限定域）：`ENGINE.run_cli_from(...)` 或 `ENGINE.run_domain_cli_from(Domain::Stego, ...)` 返回退出码而不调用 `process::exit`。底层自由函数（`write_carrier_bytes`、`embed_carrier` 等）仍对偏好直接调用的用户开放；`use strhide::prelude::*;` 一行导入常用类型。

库文档：

- [`docs/api/ARCHITECTURE.md`](docs/api/ARCHITECTURE.md) — 模块拓扑、公开 API、数据流转、扩展点；
- [`docs/api/STEGO-API.md`](docs/api/STEGO-API.md) — 内容域 API、凭据优先级、私有方言配方；
- [`docs/api/WIRE_SPEC.md`](docs/api/WIRE_SPEC.md) — UBE v2.2 二进制线格式、密钥派生、兼容矩阵。

可运行示例：`cargo run --example in_memory`、`cargo run --example private_profile`、`cargo run --example codec_bench`。

## 支持的载体与策略

| 载体 | 识别 | 典型策略 |
| --- | --- | --- |
| PNG | ✓ | IDAT 块之间注入 chunk |
| JPEG | ✓ | APPn 段注入、多段链式 |
| WebP | ✓ | `riff_chunk` 私有 `SHRD` chunk 注入 |
| HEIC / HEIF | ✓ | `item_hidden`（未引用私有 item，首选策略）、`free_box`（ISO BMFF `free` 盒伪装）或 `box_uuid` 规范注入 |
| MP4 | ✓ | `box_uuid` free/uuid box 注入 |
| WAV | ✓ | `riff_chunk` 私有 `SHRD` chunk 注入 |
| MKV | ✓ | `ebml_void` 规范 EBML Void 元素注入 |
| ZIP | ✓ | 中央目录之前插入条目 |
| PDF | ✓ | 增量更新 / 对象注入 |
| Windows PE（exe/dll） | ✓ | `pe_slack` 节填充信封（文件尺寸不变）、`pe_codebits` 指令编码信道，或 overlay 数据 |

无法识别的格式将**被拒绝**：strhide 只修改显式支持的载体——向任意文件追加数据可能损坏该文件。`eof` 策略仍作为受支持格式内部的降级选项存在（如超大 PNG 载荷）。

`strhide inspect <文件>` 可查看某载体实际支持的策略及其容量上限；`-s auto`（默认）自动选择，`-s ask` 交互式选择（仅限单个载体）。

### 内容自适应像素/DCT/CABAC隐写（`embed` / `extract`）

| 隐写域 | 支持格式 | 算法 | 机制特点 |
| --- | --- | --- | --- |
| 空间域 | PNG（RGB/RGBA/灰度） | **HILL**（默认）或 **S-UNIWARD** + 非对称 ±1 | 最小失真 KB 高通 + 双级均值平滑；三元 ±1 写入且不离开像素的八值类，成本图按 `val & 0xF8` 掩码。重编码采用 Rayon 并行 + SIMD `zlib-rs`，大图耗时提速 10.5 倍 |
| DCT 频域 | JPEG / JPG（基线编码） | **UERD**（默认）或 **J-UNIWARD** + 三元 STC（V3） | 全图 AC 位置固定网格、真三元 `±1` 回写、44 字节超块，通过 `dct-io` 实现无损重编 |
| CABAC 旁路域 | HEIF / HEIC、HEVC Annex-B、MP4 / MOV（HEVC） | **H.265 CABAC 旁路符号位 + STC（Scheme C）** | 调制高频变换系数的旁路符号位并避让 EPB 防竞争字节；零文件尺寸膨胀（$\Delta = 0$），严格符合 H.265 标准句法，视觉失真极小 |

*HEIF/HEIC 与 HEVC：CABAC 旁路符号位隐写（Scheme C）*：针对 H.265/HEVC 变换系数的符号位（`coeff_sign_flag`）进行调制。由于符号位在 CABAC 中采用旁路编码（Bypass 模式，等概率单 bit，不更新上下文状态转移概率），调制合法符号位在保持极低人眼感知失真的同时，完全不影响前后宏块的算术解码状态机。系统通过 `CabacObserver` 挂载至 H.265 解码管道提取合法槽位并进行 EPB（防竞争字节 `0x000003`）冲突避让，经由 STC 校验格码嵌入加密 UBE 载荷，文件尺寸精确保持零膨胀（$\Delta = 0$）。原生支持单图 HEIC、网格连拍图集、Annex-B 裸视频码流，以及 MP4/MOV 容器（按样本表定位切片、`hvcC` 提供参数集）。视频载体默认只使用非参考帧，翻转的系数不会向后继帧传播（详见下节）。

*安全拦截防护*：APNG 动图（`acTL`）、调色板索引图（`PLTE`）、隔行扫描图（Adam7）与渐进式 JPEG（SOF2）会被自动检测并优雅拦截，保护原图功能与外观不受破坏。

*私有方言*：无密码时，信封密钥与头部槽位置换都由源码内的公开常量派生，因此任何 strhide 构建都能读取无密码载体。CLI 刻意**不提供**替换该常量的参数：私有方言（自定义密钥、HKDF 域标签、wire 格式身份）属于编译期定制——在自定义构建中绑定库层 `Dialect`（`Dialect::with_default_secret` 同时设置两半，`StegoProfile::with_stego_domain` 隔离图像域）即可，密钥与头部置换经 HKDF（NFC 规范化 + 长度前缀）做子密钥化。写入与提取两端方言必须一致，否则提取报 `NoHiddenData`。交互式使用请传 `-p/--password`：密码是提取端唯一需要记住的凭据。

*UERD 用真实块网格*：代价模型使用文件自身的亮度量化表与真实的 MCU 补齐块映射（4:2:0 的块行是交错的，`ceil(sqrt(n))` 对多数载体都是错的），并且对**每个** AC 位置（含 0）计价——因为编码是三元的。

*JPEG：固定网格三元 STC*：槽位集合是**每个块的全部 AC 位置**（`k = 1..63`），按平坦索引升序再密钥置换。集合不依赖任何系数值，所以提取端不需要代价图、不需要重排序：只读奇偶位并按密钥重建同一序列。格宽 `u` 由**槽位预算**决定（`--slot-budget`，默认 1,200,000）：

```
u = max(1, min(64, floor(budget / (bits + h - 1)), floor(|正文网格| / (bits + h - 1))))
```

1920×1280 照片上 4 KiB 载荷取 `u = 36`（1 bit 摊到 36 个系数），64 KiB 取 `u = 2`。`--slot-budget` 只是嵌入端参数：提取端只信超块里的 `u`，用别的预算写入的载体照样能解。合法性只有一条硬边界——`|c| = 1023` 不能继续增大（`category(1024)` 超出 baseline AC 的 10 档），另外对 Huffman 表过度优化的载体，会挡掉缺少 `(run, category)` 符号的方向。

*PNG：自适应矩阵编码*：空间域载荷默认由库自适应调度**综合征网格码（STC）**，根据槽位充裕程度动态选择最优分组大小 `u`（槽位充裕时自动选择 `u=3` 或 `u=2`，满载时回退到 `u=1`），优化的是**代价加权**失真而非单纯的改动槽位数。`--stc-h 4..10`（默认 8）控制网格约束高度。所选的编解码参数（包括 `u` 与 `h`）均自描述记录在 PNG 载体头部（`FeatureWord`），`extract` 无需任何额外参数。

分组大小 `u` 代表“多少个槽共用一个综合症行”：`u=1` 每槽 1 bit，改动数约 0.50 次/bit；`u=2/3` 把同一消息摊到 2/3 倍的槽位上，改动数与加权失真同步显著下降。STC 的收益来自“挑最便宜的纹理槽”，因此在载体容量大于载荷时，自适应算法会自动享受高 `u` 带来的极高隐蔽性。加权失真相比朴素方法最高可降低上百倍。

*JPEG 头部（44 字节超块）*：版本、flags、16B salt、12B nonce、信封长度、套件 id、codec id、`h`、`u`、分量掩码、扩展区长度。它由 718 个槽承载（STC `h=8, u=2`，恰好 352 bit），整块作为 AEAD 的 AAD——任一字段被改都会让 tag 校验失败，而不是"能解密但行为异常"。可选字段走超块之后的 TLV 扩展区（目前只由库接口写入，无 CLI 开关）。头部**位置**由 `SuiteKDF(password, cover_digest)` 派生，因此读头必须先付一次完整 KDF：不存在廉价口令预言机。套件：id 1 = PBKDF2-SHA256 200k + AES-256-GCM（默认），id 2 = 600k（`--cipher-suite 2`），id 3 = Argon2id 仅保留 id。

*PNG 头部*：32 字节控制字（salt、nonce、长度/codec/h）+ 32 字节 `FeatureWord`（codec、参数、安全规则），共 512 槽，两者一起作为 AAD。

*实测（8 张 1920×1280 照片，默认参数，取均值）*：

| 载荷 | `u` | 嵌入 | 提取 | PSNR | 体积增幅 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4 KiB | 36 | 1.4 s | 0.12 s | 58.2 dB | +0.06% |
| 16 KiB | 9 | 1.4 s | 0.12 s | 50.0 dB | +0.49% |
| 64 KiB | 2 | 0.9 s | 0.12 s | 35.2 dB | +9.8% |

1920×1280 上的 64 KiB 约合 0.22 bpp，已是推荐上限的两倍多，体积增长来自"改动了约 10% 的全部系数"；在推荐档位（≤ 0.10 bpp）内增幅低于 1%。

*自检能看到什么、看不到什么*：`scan` 是筛查工具，不是证据。JPEG 走**校准式 DCT 检验**（`dct:calibration`）：解码像素、裁掉 4 px 让 8×8 网格与嵌入网格错半块、用文件自身的量化表重新量化，再把「幅值配对失衡」与该参照对比——统计现在包含 `(0, 1)` 这一对，因为三元码的大量改动正落在这里。80 图语料实测：干净中位 0.000 / 最大 0.011，推荐载荷（≤ 0.10 bpp）最大 0.007，满容量中位 0.141；阈值 0.05 下**满容量检出 85%、干净零误报**。quality-100（量化步长全 1）的载体按设计不可校准：对解码像素重新量化时 IDCT 舍入与量化步长同量级。**`clean` 结论仍不能当作「没有隐藏数据」的证据**——JPEG 判为 clean/low 时报告会带一条明确的说明。

## 仓库结构

```
strhide/
├── rust/       # Rust 实现（库 + CLI 二进制）
├── docs/       # 设计文档与变更日志
└── LICENSE     # Apache-2.0
```

## 许可证

[Apache License 2.0](LICENSE)
