# strhide

**格式保持、无损数据隐藏与智能隐写工具。** 在保持宿主文件格式规范与视觉/听觉功能完好的前提下，将数据隐藏至常见文件载体（PNG、JPEG、WebP、HEIC/HEIF、MP4、MOV、MKV、WAV、FLAC、ZIP、微软 Office 文档、PDF、Windows PE 可执行程序）中。

---

## 1. 项目结构

```text
strhide/
├── rust/        # 核心 Rust 库 crate（`strhide`）与静态 CLI 二进制程序
├── gui/         # 桌面客户端 `StrHideStudio`（基于 Tauri 2 + React + TypeScript）
├── docs/        # 技术设计规范、架构说明、二进制线格式与工程变更记录
│   ├── smart_file_data_hiding_design.md   # 技术实现综合规范
│   ├── api/
│   │   ├── ARCHITECTURE.md                # 系统分层架构、门面与模块拓扑
│   │   ├── STEGO-API.md                   # 内容域隐写对外 API 规范
│   │   ├── WIRE_SPEC.md                   # 线格式索引（重定向到 spec/）
│   │   ├── spec/                          # 按主题拆分的规范性线格式文档
│   │   │   ├── README.md                  # 总览、术语、文档地图
│   │   │   ├── CRYPTO.md                  # 两域密钥派生与 AEAD
│   │   │   ├── DETMATH.md                 # 确定性数学语义
│   │   │   ├── CAPACITY.md                # 容量公式与限额
│   │   │   ├── CONTENT-*.md               # 内容域（信封 + 各载体）
│   │   │   ├── STRUCTURE-*.md             # 结构域（UBE + 各适配器）
│   │   │   └── CORRECTIONS.md             # 旧 WIRE_SPEC 勘误
│   │   ├── WIRE_SPEC_STRUCTURE.md         # 旧结构域文档（非规范）
│   │   └── WIRE_SPEC_CONTENT.md           # 旧内容域文档（非规范）
│   └── CHANGES-*.md                       # 按日期记录的工程变更日志
├── scripts/     # 基线哈希校验、CI 检查与打包发布脚本
└── testdata/    # 测试样本集与全格式基线语料库
```

---

## 2. 核心能力与工作域

strhide 具备两个相互独立的工作域。库层可在同一载体上组合两个域，但 CLI 默认拒绝第二个域（需显式 `--overwrite`），且还原保证只适用于结构域信封：

| 工作域 | 支持载体格式 | 技术机制与算法模型 | 还原特性 |
| :--- | :--- | :--- | :--- |
| **结构域**（容器空隙隐藏） | PNG、JPEG、WebP、MP4、MOV、WAV、MKV、ZIP（含 `.zip`、`.jar`、`.docx`、`.xlsx`、`.pptx`）、PDF、Windows PE（`.exe`、`.dll`） | 容器结构空隙注入（私有块、注释段、未引用流对象、中央目录前置、PE 节表零填充与代码等价替换） | **100% 逐比特无损还原**写入前的宿主（全量 SHA-256 强校验）；若写入后载体被重编码（例如叠加内容域隐写），则以 `RestoreMismatch` 失败关闭 |
| **内容域**（多媒体自适应隐写） | PNG、JPEG、HEVC/H.265（MP4、MOV、MKV、HEIC/HEIF、Annex-B）、音频（WAV、FLAC） | 自适应代价模型（PNG: HILL/S-UNIWARD/MiPOD；JPEG: UERD/J-UNIWARD/J-MiPOD；HEVC: CABAC 旁路符号位 Scheme C，$\Delta = 0$；Audio: WAV PCM LSB、FLAC 残差匹配） | 单向调制（不可逐比特逆向还原原始载体） |
| **诊断与取证** | 全部受支持格式 | 结构解析、密码学完整性校验、黑盒隐写分析（`scan`） | 只读分析 |

---

## 3. 命令行（CLI）使用说明

### 二进制程序与别名
CLI 编译产物包含单一全功能入口（`strhide` / `sth`）以及三个域专用独立入口：

* `strhide` / `sth`：全功能主入口（包含全部 10 个子命令）。
* `sthc`：容器结构域入口（`write`、`read`、`restore`）。
* `sths`：多媒体隐写域入口（`embed`、`extract`、`capacity`）。
* `sthv`：只读诊断与分析入口（`inspect`、`verify`、`scan`、`list`）。

### 常用命令示例

```bash
# ── 容器结构域 (Container) ──
# 隐藏文件到载体中（默认输出至 <原文件名>-out.<后缀>，保护原文件）
sth write report.pdf -d secret.zip -p "password" -H "提示文本"      # [别名: w]

# 提取隐藏数据（默认拒绝覆盖已有文件，需 --overwrite 才允许覆盖）
sth read report-out.pdf -o out/ -p "password"                       # [别名: r]

# 逐比特还原写入前的宿主（仅结构域；载体被重编码后失败关闭）
sth restore report-out.pdf -o report-restored.pdf                   # [别名: s]

# ── 多媒体内容隐写域 (Media Stego) ──
# 探测多媒体载体的嵌入容量上限
sth capacity photo.jpg                                              # [别名: c]

# 将数据嵌入到图像/视频/音频载体底层数据中
sth embed photo.jpg -t "机密文本" -o stego.jpg -p "password"         # [别名: e]

# 从隐写载体中提取机密数据
sth extract stego.jpg -o secret.txt -p "password"                   # [别名: x]

# ── 诊断与分析 (Diagnostics) ──
sth inspect carrier.png [--json]                                    # 查看载体结构与信封元数据
sth verify carrier.png -p "password"                                # 验证载体完整性与密码有效性
sth scan target_folder/ -r                                          # 黑盒隐写扫描与异常检测
sth list                                                            # 列出受支持的格式与容量参考 [别名: l]
```

---

## 4. 桌面客户端（`StrHideStudio`）

桌面端位于 `gui/` 目录，基于 **Tauri 2**、**React**、**TypeScript** 与 **Tailwind CSS** 构建：

* **动态算法发现**：启动及选择载体时通过 Tauri IPC 动态获取后端算法元数据（`get_stego_algorithms_cmd`），按载体格式自动过滤可用算法并提供原理说明。
* **两阶段提取缓存**：两步提取流程中在后端内存缓存解密数据，用户指定路径保存时直接命中缓存落盘，消除重复解密与 Argon2id 计算。
* **线程隔离与日志浮窗**：受控后台线程池与 `catch_unwind` 异常隔离，内置悬浮日志弹窗与实时诊断输出。
* **开发与构建命令**：
  ```bash
  cd gui
  pnpm install
  pnpm build         # 前端类型检查与 Vite 生产打包
  pnpm tauri dev     # 启动桌面开发调试窗口
  ```

---

## 5. 关联技术文档

* [技术实现综合规范](docs/smart_file_data_hiding_design.md)：协议细节、适配器算法、预检拦截矩阵与还原流水线。
* [系统架构与公开 API 说明](docs/api/ARCHITECTURE.md)：分层拓扑、统一门面、方言机制与管线设计。
* [内容域隐写 API 规范](docs/api/STEGO-API.md)：媒体自适应隐写对外接口与算法自省指南。
* [二进制线格式规范（索引）](docs/api/spec/README.md)：文档地图、术语、字节序、版本策略与各主题规范。
* [结构域线格式规范](docs/api/spec/STRUCTURE-ENVELOPE.md)：UBE v2.2 信封，以及 `docs/api/spec/STRUCTURE-*.md` 下的各格式适配器。
* [内容域线格式规范](docs/api/spec/CONTENT-ENVELOPE.md)：V4 信封、稳定性分级（冻结/方言/自由）、密钥派生、槽位选择、STC syndrome，以及 `docs/api/spec/CONTENT-*.md` 下各载体的代价模型。
* [Rust 库使用指南](rust/README.md)：作为 Rust crate 引入项目的依赖配置与核心 API 示例。
