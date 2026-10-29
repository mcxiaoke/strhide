# CLI 参数与 lib 接口「提取依赖」审查（2026-10-25）

## 0. 背景与判定原则

本审查回答一个问题：**CLI 参数与 lib 公开接口中，哪些参数会在提取/读取端形成"写入时用了什么参数、提取时就必须再给一次"的依赖？** 判定原则：

1. 影响读取（read）/提取（extract）的参数不应在 CLI 暴露——用户可能忘记写入时用的参数，导致提取失败；
2. **密码是唯一例外**（用户理应记住的凭据）；
3. 编译期参数（`Profile` 私有方言）可以依赖——这是定制构建需求，不由运行时命令行承担。

结论先行：**实施后，`extract` 的 CLI 面收敛为「载体 + 输出选项 + password」——password 是唯一需要用户记住的参数。**

## 1. 两条管线的审查结论

### 1.1 结构域（write/read/restore/inspect/verify）——本就达标

`read` 不依赖写入时任何 CLI 参数：

- 策略自动嗅探（router/sniff），`--strategy` 是纯写入选择；
- stealth 信封自动探测：`locate_envelope`（engine.rs）先试密码派生 magic、再试标准 magic，`read` 无 `--stealth` 旗标；
- 分块/压缩自描述：`LocalParams`（chunk_size、压缩、rejection）明确是 writer-only（"The reader never needs these"）；
- 提取面只有 password + 编译期 `Profile`。**无需改动。**

### 1.2 内容域（embed/extract/capacity）——提取路径实际自描述，但 CLI 残留死参数与凭据参数

关键不对称性：

- **JPEG/HEVC 提取完全不重建代价图**：JPEG V3 槽位集是几何的，superblock 自带 `h`/`u`/cipher_suite；`extract_jpeg` 只收 secret/domain/format/`ExtractParams`，`--algorithm` 与全部 `JpegParams` 调优（neighbor_weight、slot_budget、polarize_weight 等）都是 embed-only。
- **PNG 提取要逐位重建代价图**（给 body 槽位排序），自描述靠 64 字节 FeatureWord：`codec`/`u`/`h`/`channel_mode`/`class_rule`/`p1_window`/`p2_window`/`epsilon`（2^-k 量化）/`exclusion_permille`/`algorithm_id`/`sigma`（f32 量化）/`kernel_id`。`extract_png` 读取后**无条件覆盖**调用方传入的对应字段——即写入侧的 `--p1-window`/`--p2-window`/`--exclusion-rate`/`--stc-h` 全部进 wire，提取端自动复现。

由此，实施前 CLI `extract` 暴露的 `--p1-window`/`--p2-window` 是**死参数**（值被 FeatureWord 覆盖；但非法值会先被 `validate()` 拦截，反而挡住本可成功的提取），`--algorithm` 也是死参数（三个格式分支都不读它）。相关帮助文案与 `warn_nondefault_stego_params` 警告（"Extraction succeeds only with the same values"）均为失实的旧实现遗留。

## 2. P 类清单（提取端必须与写入端一致，否则失败）

失败形态统一为 `NoHiddenData`（"No valid payload found"），与密码错误不可区分（反 oracle 刻意设计），因此这类参数越少越好：

| 类别 | 项目 | 处置 |
|---|---|---|
| 运行时凭据 | password（`-p`/`--password-file`/`STRHIDE_PASSWORD`/config） | **保留**——用户应记住的唯一参数 |
| 运行时凭据 | `--stego-secret` / `--stego-domain`（含 `STRHIDE_STEGO_*` env 与 config 键） | **从 CLI/config/env 全部移除**（本次实施） |
| 编译期方言 | `Profile`：`default_secret`、`stealth_domain`、`magic`；`StegoProfile`：`default_secret`、`domain`、jpeg/png/hevc 格式身份 | **保留**——编译期定制需求（原则 3） |
| lib 缺口 | `PngParams.high_pass_kernel`：自定义核无 wire 身份（`kernel_id` 恒 0），写入侧不拒绝、wire 不携带，默认提取端必失败 | **字段删除**，核固化为内置常量（本次实施） |
| lib 缺口（观察项） | `PngParams.algorithm_options` 仅 `sigma` 进 wire（f32、仅 suniward）；未来给 PNG 加影响代价图的新键必须同步进 FeatureWord | 文档告诫，暂不动作 |

`stego_secret` 与密码同类（它就是无密码时的替代密钥，原理上进不了 wire）；`stego_domain` 不是机密却阻断提取，理论可改格式自描述（存入加密 header），但 header 定位本身 keyed on secret+domain（鸡生蛋），且会降低"header 位置不可预测"的抗检测性——权衡后不入 wire，私有需求走编译期 `Profile`。

## 3. 本次实施变更

### 3.1 CLI 删除 `--stego-secret` / `--stego-domain`（两侧同删）

- `cli.rs`：`StegoTuningArgs`（embed/capacity）与 `ExtractArgs` 移除两个字段；删除 `resolve_stego_secret`/`resolve_stego_domain`（CLI > env `STRHIDE_STEGO_SECRET`/`STRHIDE_STEGO_DOMAIN` > config 三级解析链整体退役）；`handle_embed`/`handle_extract`/`run_capacity_probe` 的 secret/domain 兜底赋值删除；`embed_stego_options` 签名收敛为 `(args, password)`。
- `config.rs`：`FileConfig.stego_secret`/`stego_domain` 字段、KNOWN_KEYS、CWD 敏感键检查同步移除；旧配置里的残留键落入"未知键警告"路径（不静默生效）。
- `strhide.sample.toml`：两段配置说明替换为"已从 CLI/config 面移除，私有方言走编译期 Profile"。
- lib 层 `Profile::with_stego_secret`/`with_stego_domain`/`StegoProfile` **原样保留**——自定义构建（`StrHide::new().with_profile(...)` + `run_cli_from`）仍可建立私有方言，满足"编译期定制"。
- 行为含义：无密码 `embed` 一律使用公开常量（`PUBLIC_DEFAULT_SECRET`），`extract` 零凭据可读；要私有性就用 `-p` 密码。

### 3.2 CLI `extract` 删除死参数 `--algorithm` / `--p1-window` / `--p2-window`

- 依据见 §1.2；`handle_extract` 的选项构造收敛为 `StegoOptions { password, ..Default::default() }`。
- `warn_nondefault_stego_params` 连同其 embed 侧调用一并删除（FeatureWord 自描述后警告文本失实）。
- 同步删除 `HelpExtractAlgorithm`/`HelpExtractP1Window`/`HelpExtractP2Window`/`HelpEmbedStegoSecret`/`HelpEmbedStegoDomain` i18n 条目与 cli_i18n 匹配臂；`extract_png` doc 注释（"params must repeat the embed-time filter windows"）等失实注释随改动修正。

### 3.3 `PngParams.high_pass_kernel` 字段删除

- `hill.rs` 内置归一化 KB 核固化为 `KB_HIGH_PASS_KERNEL` 常量（`kernel_id = 0` 的唯一 wire 身份）；`PngParams` 删除字段与校验。
- 效果：L 类参数袋里最后一个"影响代价图却进不了 wire"的字段消失，PNG 提取的全部代价图输入均来自 wire。

### 3.4 测试改写

- `tests/test_cli/cli_unification.rs`：4 个覆盖已删旗标的旧测试（secret/domain 隔离与三级优先级）改写为 2 个新契约测试——①三个动词（embed/extract/capacity）拒绝 `--stego-secret`/`--stego-domain`（exit 2）+ 无密码 embed/extract 零凭据往返；②config 残留键告警忽略 + `STRHIDE_STEGO_*` env 惰性。
- `config.rs` 单测同步改写，新增残留键按未知键忽略的回归项。

## 4. 最终参数面（实施后）

- `extract`：carrier、`-o`/`--stdout`、`--overwrite`、password。**password 是唯一"必须记住"参数。**
- `read`：carrier、`-o`/`--stdout`、`--overwrite`、password。（未变，本就达标）
- `embed`：payload 来源、输出选项、password、写入侧调优（`--algorithm`/`--safety`/`--exclusion-rate`/`--neighbor-weight`/`--stc-h`/`--p1-window`/`--p2-window` 等）——全部自描述进 wire 或 embed-only，提取端无需复现。
- `capacity`：与 embed 同 tuning（容量探测按写入配置重放，语义正确的保留）。
- 私有方言：仅编译期 `Profile`（`default_secret`/`stealth_domain`/`magic`/`StegoProfile`）。

## 5. 验证

`cargo fmt`、`cargo clippy --all-targets -- -D warnings`、`cargo test --all-targets`（641 项全过）、`cargo test local_ -- --ignored`（16 项本地批量全过）。

## 6. 遗留观察（未动作）

1. lib 形状：`extract_carrier_with_profile` 复用 `StegoOptions`（embed 选项袋），实际只读 `password`/`domain`/`extract_params`；行为无害（字段被 wire 覆盖），未来可拆 `ExtractOptions` 收紧接口。
2. `PngParams.algorithm_options`：新增影响 PNG 代价图的模型键时，必须同步进 FeatureWord（现仅 `sigma`），否则重蹈 `high_pass_kernel` 覆辙。
