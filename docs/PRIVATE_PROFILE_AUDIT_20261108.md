# 私有 Profile 定制参数梳理与指纹消除审计报告

> 日期：2026-11-08  
> 状态：审查完成（待规划实施）  
> 适用目标：`rust/` 核心隐写库与定制 CLI

---

## 1. 背景与核心设计原则

### 1.1 定位与诉求
`strhide` 作为格式保持的隐写工具，其官方开源版本在协议魔数、派生标签、格式标识符和容器结构中具有固定的默认常数。为了满足特殊私有场景的需求，项目设计了私有方言（Private Dialect / Private Profile）机制：**通过编译独立的私有定制版本，彻底消除开源公开指纹，使得生成的载体与官方开源版本完全格式隔离，第三方通用检测或提取工具仅能观测到无特征的随机噪声（报错为 `NoHiddenData`）**。

### 1.2 静态编译参数的核心设计哲学
与常规业务参数不同，**私有方言参数必须严格作为静态编译参数（Compile-time `const` Parameters）存在**：
1. **格式强绑定与防丢失**：隐写参数（网格规则、KDF 派生标签、掩码种子、格式魔数等）直接决定了载体内部的位级几何布局与密钥流派生。如果设计为运行时动态传参或配置文件加载，一旦用户在解密时遗忘、配置错配或丢失配置，将导致定制版写入的数据无法被正确寻址和解密，造成不可逆的载体损坏。
2. **单一确定性二进制**：通过 `const Dialect` / `const Profile` 静态编译出独立的 CLI / 二进制产物，确保该二进制自成一体、开箱即具备唯一且自洽的私有方言，避免因运行环境变化产生格式漂移。
3. **零运行时代价**：静态常量在编译期参与单态化展开与内联优化，完全不增加运行期的内存寻址开销。

---

## 2. 结构隐写域（Structure Domain）未公开参数

在 `rust/src/structure/params.rs` 中，当前的 `StructureProfile` 仅公开了三个字段：
```rust
pub struct StructureProfile {
    pub default_secret: Option<&'static str>,
    pub stealth_domain: Option<&'static [u8]>,
    pub magic: Option<MagicPair>,
}
```
经过对底层容器适配器和密码派生层的梳理，以下特征常数被硬编码在代码中，应通过 `StructureProfile` 开放静态编译定制：

### 2.1 容器适配器中的硬编码标记（高危特征）
第三方工具通过静态特征扫描时，以下常量是最直观的开源标识：

| 文件路径 | 硬编码常量/代码 | 现状说明 | 建议公开的编译期参数 |
| :--- | :--- | :--- | :--- |
| `rust/src/structure/adapters/png.rs:13-14` | `CHUNK_PRIV = *b"prIv"`<br>`CHUNK_STEG = *b"stEg"` | 写入 PNG 辅助 chunk 时写死为 `prIv`。分析工具扫描 PNG chunk 树即可识别。 | `png_chunk_tag: [u8; 4]`（默认 `*b"prIv"`） |
| `rust/src/structure/adapters/riff.rs:11` | `RIFF_CHUNK_FOURCC = *b"SHRD"` | RIFF 容器（WAV / WebP）注入时，直接插入名为 `SHRD` 的 chunk，是强特征签名。 | `riff_chunk_tag: [u8; 4]`（默认 `*b"SHRD"`） |
| `rust/src/structure/adapters/isobmff.rs:11-13` | `MP4_UUID_NEUTRAL = [0xd4, 0x1a, ...]` | MP4/MOV/HEIF 使用 `box_uuid` 策略时，写死该 16 字节固定 UUID。 | `isobmff_uuid: [u8; 16]` |
| `rust/src/structure/adapters/jpeg.rs:14, 362` | `JPEG_APP15 = [0xFF, 0xEF]` | JPEG 段插入写死使用罕见的 APP15 marker。 | `jpeg_marker: [u8; 2]`（可定制为 COM `0xFF, 0xFE` 等） |
| `rust/src/structure/adapters/pdf.rs:588-590` | `\n{new_obj_num} 0 obj\n<< /Type /Metadata /Length ... >>\n` | PDF 注入对象写死了固定的字典结构 `/Type /Metadata`。 | `pdf_dict_type: &'static str` |

### 2.2 结构层 KDF 派生标签与计算参数
位于 `rust/src/core/crypto.rs`：
- **PBKDF2 迭代次数**：`PBKDF2_ITERATIONS = 100_000`（L106）。定制版无法调整结构层的派生迭代成本。
- **HKDF-Expand 标签常量**：
  - 载荷与元数据派生标签：`b"strhide-payload"`（L245）、`b"strhide-metadata"`（L247）
  - 头部掩码与隐身标签：`b"strhide-header-mask-v1"`（L268）、`b"strhide-stealth-header"`（L293）、`b"strhide-stealth-trailer"`（L295）
  - PE 通道掩码标签：`b"strhide-pe-channel-mask-v2"`（L341）
- **Stealth 模式下的 Trailer CRC 混淆盐**：
  - `derive_trailer_crc_mask`（L318-L327）硬编码了混淆盐 `b"STEA"`（`[0x53, 0x54, 0x45, 0x41]`）。
- **信封协议版本**：
  - `rust/src/structure/envelope.rs:59` 中 `CURRENT_VERSION = 0x02` 写死在协议头中。

---

## 3. 内容隐写域（Content Domain）未公开参数

在 `rust/src/stego/params.rs` 中，`StegoProfile` 与 `WireCipherProfile` 提供了部分派生标签隔离，但以下深度耦合的指纹与派生标签仍被写死：

### 3.1 通用 V4 信封派生与 AAD 认证
- **AEAD AAD 前缀**（`rust/src/stego/envelope.rs:105`）：
  - `const V4_AAD_PREFIX: &[u8] = b"strhide-content-envelope-v4\0";`
  - 在 `build_v4_aad` 中强制作为所有内容隐写认证数据的前缀，未开放定制。
- **L2 定位密钥中的 STC Trellis 种子标签**（`rust/src/stego/format.rs:482-483`）：
  - `derive_l2_locator_keys` 内部写死：
    - `header_stc_seed: hkdf_expand_u64(master, b"strhide-v4-hdr-stc")`
    - `ext_stc_seed: hkdf_expand_u64(master, b"strhide-v4-ext-stc")`
  - `WireCipherProfile` 包含了其他 5 个标签，唯独漏掉了这两个 STC 种子标签。
- **三大引擎硬编码传参 `b"strhide-v4-hdr-magic"`**：
  - 仅 `HevcFormatProfile` 包含 `magic_label` 字段。
  - PNG (`stego/png/engine.rs:1710`)、JPEG (`stego/jpeg/engine.rs:723`)、Audio (`stego/audio/core.rs:464`) 调用 `derive_l2_locator_keys` 时，均硬编码传入字面量 `b"strhide-v4-hdr-magic"`。
  - 导致 `PngFormatProfile`、`JpegFormatProfile`、`AudioFormatProfile` 无法通过 Profile 定制其 L2 Magic 派生标签。
- **格式 ID 常量**：
  - 各引擎写死格式 ID：PNG=`1`、WAV=`2`、FLAC=`3`、JPEG=`4`、HEVC=`5`。这些 ID 参与了 AAD 认证与头格式解析。
- **内容层 PBKDF2 迭代次数**：
  - `CONTENT_L1_PBKDF2_ITERATIONS = 200_000`（`core/crypto.rs:114`）硬编码。

### 3.2 各多媒体引擎专用硬编码
- **Audio 引擎**：
  - **FLAC 相位哈希**：`rust/src/stego/audio/mod.rs:108` 中写死：
    `h.update(b"strhide-v4-flac-body-phase");`
  - **置换标签绕过了 Profile**：`rust/src/stego/audio/perm.rs:29` 定义了静态常量：
    `const PERM_LABEL: &[u8] = b"strhide-audio-perm-v1";`
    此处没有读取 `WireCipherProfile.perm_label`，导致配置的置换标签在音频引擎中未生效。
- **HEVC 引擎**：
  - **会话盐派生标签**：`rust/src/stego/hevc/engine.rs:454` 中写死：
    `hasher.update(b"strhide-hevc-session-v4");`，未暴露在 `HevcFormatProfile` 中。
- **PNG 空间域引擎**：
  - **高通滤波核矩阵固定**：`stego/params.rs:138-142` 注释说明高通滤波核写死为 KB kernel，`SpatialHeaderV4.kernel_id` 固定为 0。自定义高通滤波核或模型权重是抵御统计特征分析与专用检测模型的最有效手段，应支持编译期注入自定义核。
- **Header 校验特征**：
  - 内容层（JPEG Superblock、PNG/Audio SpatialHeaderV4、HEVC Superblock）均采用无掩码的标准 IEEE 802.3 CRC32，缺少 CRC 掩码定制通道。

---

## 4. 推荐重构与扩展方案（静态 Profile 扩展蓝图）

为了严格遵循“**私有定制属于静态编译参数**”的核心原则，所有新参数均采用 `const`、固定长度数组或 `&'static [u8]` 设计，保证能够在 `const fn` 中初始化。

### 4.1 结构域 Profile 扩展设计
```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StructureProfile {
    // 现有参数
    pub default_secret: Option<&'static str>,
    pub stealth_domain: Option<&'static [u8]>,
    pub magic: Option<MagicPair>,

    // 建议新增的静态编译参数
    pub pbkdf2_iterations: Option<u32>,                // 替代 100_000
    pub crc_salt: Option<&'static [u8]>,               // 替代 b"STEA"
    pub labels: Option<&'static StructureLabels>,       // 替代 strhide-payload 等派生标签
    pub adapter_tags: Option<&'static ContainerTags>,   // 替代 prIv, SHRD, MP4_UUID 等
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerTags {
    pub png_chunk: [u8; 4],                            // 默认 b"prIv"
    pub riff_chunk: [u8; 4],                           // 默认 b"SHRD"
    pub isobmff_uuid: [u8; 16],                        // 默认 MP4_UUID_NEUTRAL
    pub jpeg_marker: [u8; 2],                          // 默认 [0xFF, 0xEF] (APP15)
}
```

### 4.2 内容隐写域 Profile 扩展设计
1. **完善 `WireCipherProfile`**：
   ```rust
   pub struct WireCipherProfile {
       pub domain_label: &'static [u8],
       pub hpos_label: &'static [u8],
       pub enc_label: &'static [u8],
       pub perm_label: &'static [u8],
       pub stc_label: &'static [u8],
       pub default_suite: CipherSuiteId,
       // 新增补全
       pub hdr_stc_label: &'static [u8],              // 替代 b"strhide-v4-hdr-stc"
       pub ext_stc_label: &'static [u8],              // 替代 b"strhide-v4-ext-stc"
       pub aad_prefix: &'static [u8],                 // 替代 b"strhide-content-envelope-v4\0"
   }
   ```
2. **在所有格式 Profile 中暴露 `magic_label` 并修复遗漏调用**：
   - 为 `PngFormatProfile`、`JpegFormatProfile`、`AudioFormatProfile` 增加 `magic_label: &'static [u8]`。
   - 修复 `audio/perm.rs`，使其读取 `WireCipherProfile.perm_label` 而非内部常量。
   - 在 `AudioFormatProfile` 中增加 `flac_body_phase_label: &'static [u8]`。
   - 在 `HevcFormatProfile` 中增加 `session_salt_label: &'static [u8]`。

### 4.3 静态编译构建接入体验
外部私有构建可以直接在私有分支或专用编译单元中定义 `const` 方言：
```rust
const PRIVATE_CIPHER: WireCipherProfile = WireCipherProfile {
    domain_label: b"my-org-domain",
    hpos_label: b"my-hpos",
    enc_label: b"my-enc",
    perm_label: b"my-perm",
    stc_label: b"my-stc",
    hdr_stc_label: b"my-hdr-stc",
    ext_stc_label: b"my-ext-stc",
    aad_prefix: b"my-custom-prefix\0",
    default_suite: CipherSuiteId::Aes256Gcm,
};

const PRIVATE_DIALECT: Dialect = Dialect::new()
    .with_default_secret("my-static-deployment-key")
    .with_structure_profile(StructureProfile::new().with_container_tags(CUSTOM_TAGS))
    .with_stego_profile(StegoProfile::new().with_wire_cipher(&PRIVATE_CIPHER));

// CLI main 直接静态传入
fn main() {
    let exit_code = strhide::facade::StrHide::new()
        .with_dialect(PRIVATE_DIALECT)
        .run_cli_from(std::env::args_os());
    std::process::exit(exit_code);
}
```

---

## 5. 结论

通过静态编译参数将私有 Profile 固化在定制版二进制中，是确保隐写格式自洽且不可丢失的核心架构设计。目前 codebase 在架构上已经完成了 `Dialect` 和各大 `Profile` 的分层解耦，但底层实现中仍残留了数处**容器 tag 标识符、派生标签字符串、AAD 前缀和特定引擎标签**的硬编码。将上述参数完全提升至 `const Profile` 体系中，即可实现 100% 消除开源公开指纹，达到完全的格式隔离与抗检测目标。
