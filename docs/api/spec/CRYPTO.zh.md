# CRYPTO：密钥派生与 AEAD（内容域 V4 / 结构域 UBE v2）
适用 `strhide` 0.9.3（`rust/src`）。范围：两套信封的凭据、域分离、L1/L2/L3、nonce、AEAD 的 AAD 与字段掩码；不讲字节布局。导航：[规范总览](./README.zh.md) · [内容域信封](./CONTENT-ENVELOPE.zh.md) · [结构域信封](./STRUCTURE-ENVELOPE.zh.md) · [架构与公开 API](../ARCHITECTURE.md)。本文按代码编写，引用均写作 `文件:行`（相对仓库根）。

## 0. 约定与稳定性
"实现必须"= 互通必需。哈希全为 SHA-256；HKDF 为 RFC 5869 的 HKDF-SHA256（`L`=目标字节数，`salt=None` 按 §2.2 视为 32 字节全 0）；PBKDF2 为 PBKDF2-HMAC-SHA256，输出 32B。**字节序按域相反**：内容域多字节字段大端，结构域小端。

稳定性分级：**F** 冻结（改则旧载体不可读、基线失效）；**D** 方言（私有 Profile/常量可替换，生成互不可读的新格式）；**I** 自由（只影响写侧细节）。**1.0 之前不承诺跨版本稳定**：F 仅指"本仓库内改动会立刻破坏既有载体与基线"，第三方应以具体版本号固定行为。

## 1. 内容域（V4 内容信封）
### 1.1 凭据、NFC、默认密钥（F / 取值 D）
- 两种凭据（`core/crypto.rs:121-127`）：`Password(&str)` 经 NFC 后走 PBKDF2；`FileKey(&[u8;32])` 直接作 HKDF 的 IKM，跳过 PBKDF2。
- 口令与域名进入派生前各自做 Unicode NFC（`core/crypto.rs:180`），之后不得再做大小写折叠等变换。
- 选择顺序（`stego/options.rs:421-444`）：非空 `password` 与 `key` 互斥 → `key` → 非空 `password` → `StegoProfile.default_secret`（空串=未配置，`stego/params.rs:982-984`）→ `PUBLIC_DEFAULT_SECRET = "strhide-default-content-stego-key-2026"`（`stego/envelope.rs:62`）。空串口令必须按"未提供"处理。
- 域名回落（`stego/options.rs:705-712`）：显式非空 `domain` > `StegoProfile.domain` > **无域**。官方默认是"无域"，不是固定字符串；无域时 info 只含标签。

### 1.2 HKDF info 拼接（F）
```text
info(label, domain) = label                                        当 domain 为 None/空串
                    = label ‖ u64be(len(NFC(domain))) ‖ NFC(domain) 否则
```

出处 `stego/format.rs:521-533`（`info_with_domain`）、`stego/envelope.rs:133-151`。`len` 为 NFC 后字节数；长度前缀必须保留，否则 `("ab","c")` 与 `("a","bc")` 碰撞。

### 1.3 L1：定位主密钥（F）
```text
Password: p_nfc = NFC(p)
  有域: ikm = HKDF-Expand(SHA256, salt=None, ikm=p_nfc, info=info(domain_label, domain), L=32)
  无域: ikm = p_nfc 的 UTF-8 字节（不哈希）
  master = PBKDF2-HMAC-SHA256(pass=ikm, salt=pre_salt(32B), iter=200_000, dkLen=32)
FileKey k[32]:
  master = HKDF-Expand(SHA256, salt=pre_salt(32B), ikm=k, info=info(domain_label, domain), L=32)
```

出处 `stego/format.rs:433-465`；轮数 `CONTENT_L1_PBKDF2_ITERATIONS = 200_000`（`core/crypto.rs:114`）。注意 PBKDF2 的 pass 是有域时的 HKDF 输出，salt 恒为 `pre_salt`。`max_pbkdf2_iterations` 默认 200,000（`stego/params.rs:758-772`），低于它读侧直接拒绝。

### 1.4 载体身份 `pre_salt`（F；公开盐常量 D）
全部 SHA-256 → 32B，多字节字段大端。

| 载体 | 公式（`‖` 为顺序拼接） | 出处 |
|---|---|---|
| PNG | `hpos_salt ‖ "png-v4" ‖ u64be(w) ‖ u64be(h) ‖ [bit_depth, color_type, channels] ‖ meta_digest`；`meta_digest=SHA-256` over 每个**关键块**：`ty(4B) ‖ u32be(len) ‖ data`（文件顺序）；排除 `IDAT`/`prIv`，并排除全部辅助块（首字母小写：`tEXt`/`zTXt`/`iTXt`/`tIME`/`eXIf`/`iCCP`/`gAMA`/`sRGB`/`pHYs`…），只有 `IHDR`/`PLTE`/`IEND` 参与。辅助块是第三方工具随时会改的元数据，纳入盐会让一次元数据编辑把载荷变成不可恢复（2026-11-07 修复） | `stego/png/engine.rs:1155-1204` |
| JPEG | `cover_digest_tag ‖ "jpeg-v4" ‖ cover_digest`；tag=`b"strhide-cover-v1"`（`stego/format.rs:241`）；`cover_digest=SHA-256(tag ‖ u32be(block_count) ‖ u32be(component_count) ‖ 每 component 每 block 的 DC i16be)`，`block_count` 取 component 0 | `stego/jpeg/engine.rs:243-270` |
| WAV | `hpos_salt ‖ "wav-v4" ‖ u16be(channels) ‖ u32be(sample_rate) ‖ u16be(block_align) ‖ u16be(bits) ‖ u32be(data_len)`，bits=8/16/24/32（`stego/audio/sample.rs:66-77`；FLAC 侧另有 24-bit 上限） | `stego/audio/mod.rs:58-68` |
| FLAC | `hpos_salt ‖ "flac-v4" ‖ u32be(sample_rate) ‖ [channels, bits_per_sample] ‖ u64be(total_samples)`，排除 STREAMINFO MD5 | `stego/audio/mod.rs:75-83` |
| HEVC 容器 | `cover_salt ‖ "hevc-v4" ‖ u64be(ps_count) ‖ Σ(u64be(ps_len) ‖ ps_bytes)` | `stego/hevc/engine.rs:4260-4288` |
| HEVC Annex-B | `cover_salt ‖ "hevc-v4" ‖ u64be(span_count) ‖ Σ span`；参数集 span=完整 NAL，VCL span=2B NAL 头 ‖ `u64be(nal_len)`，其余 span 不贡献 | `stego/hevc/engine.rs:4289-4290`；`stego/hevc/bitstream.rs:192-211` |

公开盐常量（D，替换即新方言）：PNG `b"strhide-stego-hpos-salt-v2"`（`stego/format.rs:267`）、WAV `b"strhide-audio-hpos-salt-v1"`（:287）、FLAC `b"strhide-flac-hpos-salt-v1"`（:297）、HEVC `b"strhide-hevc-cover-v1"`（:102）。

### 1.5 L2：头部定位密钥（F）
```text
salt = None
locate_seed     = HKDF-Expand(SHA256, ikm=master, info=info(hpos_label, domain),  L=32)
magic4          = HKDF-Expand(SHA256, ikm=master, info=info(magic_label, domain), L=4)
header_stc_seed = u64be(HKDF-Expand(SHA256, ikm=master, info=b"strhide-v4-hdr-stc", L=8))
ext_stc_seed    = u64be(HKDF-Expand(SHA256, ikm=master, info=b"strhide-v4-ext-stc", L=8))
```

出处 `stego/format.rs:468-486`。两个 STC 种子是固定字面量，不含 domain/suite；实现不得额外加域分离，否则 trellis 无法重建。

### 1.6 L3：会话密钥与 `session_salt`（F）
```text
info_x = info(x_label, domain) ‖ u16be(suite_id)          // x ∈ {enc, perm, stc}
enc_key   = HKDF-Expand(SHA256, salt=session_salt, ikm=master, info=info_enc,  L=32)
perm_seed = HKDF-Expand(SHA256, salt=session_salt, ikm=master, info=info_perm, L=32)
stc_seed  = u64be(HKDF-Expand(SHA256, salt=session_salt, ikm=master, info=info_stc, L=8))
```

出处 `stego/format.rs:488-516`；suite 只以 `u16be` 追加在 info 末尾。`session_salt`：

| 载体 | 值 | 出处 |
|---|---|---|
| PNG / JPEG / WAV / FLAC | 基础头中的 16B `salt` 原样使用 | `stego/png/engine.rs:1506`；`stego/jpeg/engine.rs:945`；`stego/audio/core.rs:725` |
| HEVC | `SHA-256("strhide-hevc-session-v4" ‖ nonce)` → **32B**；nonce 是头的 12B | `stego/hevc/engine.rs:452-457`（用 `1337-1341, 2166-2170`） |

HEVC 必须做上述带标签哈希，**不得**把裸 nonce 当 salt。

### 1.7 标签全表（D：换标签=新方言）
| 载体 | `domain_label` | `hpos_label` | `enc_label` | `perm_label` | `stc_label` | `magic_label` |
|---|---|---|---|---|---|---|
| PNG | `strhide-stego-domain-v1` | `strhide-stego-hpos-v2` | `enc` | `perm` | `strhide-stc-trellis-v1` | `strhide-v4-hdr-magic` |
| JPEG | `strhide-stego-domain-v1` | `hpos` | `enc` | `perm` | `stc-trellis` | `strhide-v4-hdr-magic` |
| WAV | `strhide-stego-domain-v1` | `audio-hpos` | `audio-enc-v1` | `audio-perm-v1` | `audio-stc-trellis-v1` | `strhide-v4-hdr-magic` |
| FLAC | `strhide-stego-domain-v1` | `audio-hpos` | `audio-enc-v1` | `audio-perm-v1` | `audio-stc-trellis-v1` | `strhide-v4-hdr-magic` |
| HEVC | `strhide-stego-domain-v1` | `strhide-hevc-hpos-v4` | `strhide-hevc-enc-v4` | `strhide-hevc-perm-v4` | `strhide-hevc-stc-v4` | `strhide-hevc-magic-v4` |
出处：PNG `stego/format.rs:326-333`、音频 `337-344`、JPEG `348-355`、HEVC `359-366`；HEVC magic 标签 `stego/format.rs:101`；其余三族在调用点传入 `b"strhide-v4-hdr-magic"`（`stego/png/engine.rs:1498`、`stego/jpeg/engine.rs:729`、`stego/audio/core.rs:196`）。WAV/FLAC 共用标签，靠 `hpos_salt` 与 `"wav-v4"`/`"flac-v4"` 分离。

### 1.8 AEAD、AAD 与微头（F）
| `suite_id` | AEAD | nonce | tag |
|---|---|---|---|
| 1（默认） | AES-256-GCM | 12B | 16B |
| 2 | ChaCha20-Poly1305 | 12B | 16B |
出处 `core/crypto.rs:132-166`（wire id 与 tag 16），实现 `stego/envelope.rs:410-447`。`salt`/`nonce` 只存在基础头，不进正文；`body_len` 只计密文+tag（`stego/envelope.rs:64-97`）。

- 微头（属本域、不属密钥派生）：明文为 `4B BE raw_len ‖ 1B flags ‖ micro_header ‖ body`，`BODY_OVERHEAD=22`；`0x00` 文本/裸字节、`0x01` 文件（`1B name_len ‖ name`）；flags bit0=压缩，bit1..3=算法 id（0=Deflate）（`stego/envelope.rs:68-97, 313-330`）。
- **AAD 必须**为 `"strhide-content-envelope-v4\0"(28B) ‖ format_id(1B) ‖ base_header ‖ extension`（`stego/envelope.rs:105, 113-120`）。基础头 64B 空间域 / 44B JPEG / 32B HEVC（`stego/header.rs:153`、`stego/format.rs:109`、`stego/hevc/engine.rs:90`）；extension 上限 255B、HEVC 64B（`stego/header.rs:159`、`stego/hevc/engine.rs:124`）。
- `format_id`：PNG 1（`stego/png/engine.rs:76`）、WAV 2 / FLAC 3（`stego/audio/mod.rs:49-51`）、JPEG 4（`stego/jpeg/engine.rs:65`）、HEVC 5（`stego/hevc/engine.rs:97`）。PNG/WAV/FLAC 的基础头在偏移 34 存该值（解码只接受 1..=3 并与期望值比对，`stego/header.rs:306, 326-330`）；JPEG/HEVC 头不存，隐含 4/5。`build_v4_aad` 一律以载体族常量作 1B 参数。
- 认证失败、未知 suite、flags 预留位非 0、微头非法统一为 `NoHiddenData`（`stego/envelope.rs:454-553`）；基础头 CRC32 只提前拦损坏。版本字节 `0x40` 在头内并被 AAD 覆盖（`stego/header.rs:162`）。

常量：`CONTENT_L1_PBKDF2_ITERATIONS=200_000`（`core/crypto.rs:114`）、`SALT/NONCE/TAG=16/12/16`（`stego/envelope.rs:64-66`）、`PUBLIC_DEFAULT_SECRET`（:62）、`BODY_OVERHEAD=22`（:97）。

## 2. 结构域（UBE v2）
### 2.1 主密钥（F；默认值 D）
```text
pwd = 非空用户口令，否则 StructureProfile.default_secret，否则 BUILTIN_DEFAULT_KEY
ikm = PBKDF2-HMAC-SHA256(pass=NFC(pwd), salt=salt(16B), iter=100_000, dkLen=32)
payload_key = HKDF-Expand(SHA256, salt=Some(salt), ikm=ikm, info=b"strhide-payload",  L=32)
meta_key    = HKDF-Expand(SHA256, salt=Some(salt), ikm=ikm, info=b"strhide-metadata", L=32)
```

出处 `core/crypto.rs:210-217, 240-252`；轮数 `core/crypto.rs:106`；`BUILTIN_DEFAULT_KEY="strhide::structure::envelope::v2::default::builtin::public::secret"`（:171-172）；回落 `structure/params.rs:88-93`、`structure/engine.rs:1153`。PBKDF2 与 HKDF 使用同一个 16B `salt`。AEAD 固定 AES-256-GCM（`core/crypto.rs:382-419`）。

### 2.2 nonce 派生（F）
```text
make_chunk_nonce(base, i): base[0..8] ‖ le32( le32(base[8..12]) XOR (i as u32) )
make_meta_nonce(base):     base[0..8] ‖ le32( le32(base[8..12]) XOR 0xFFFFFFFF )
```

出处 `core/crypto.rs:354-373`。元数据固定占 `0xFFFFFFFF`，与任何分块不重叠；`chunk_index`/`is_last` 只进 AAD。

### 2.3 AAD（F）
固定 80B：`magic_header(8) ‖ version(1) ‖ flags(1) ‖ strategy_id(1) ‖ offset_delta(1) ‖ salt(16) ‖ base_nonce(12) ‖ orig_host_size(u64 LE) ‖ orig_host_sha256(32)`（`core/crypto.rs:56`；`structure/envelope.rs:354-366`）。

变长：`header[0..80] ‖ meta_len(u32 LE) ‖ hint_len(u32 LE) ‖ hint` = 88+hint_len（`structure/envelope.rs:390-397`）；每个分块再追加 `chunk_index(u64 LE) ‖ is_last(u8)` → 97+hint_len（`core/crypto.rs:508-511, 602-605`）。`meta_len`/`hint_len` 位于 104..112，必须由 `auth_aad` 追加认证；注入后坐标（80..104：inject_offset/inject_size/patch_offset/orig_patch_val）不在 AAD，靠物理包含与还原哈希校验（`structure/envelope.rs:148-159`）。

### 2.4 Stealth（F；域分隔常量 D）
```text
1) 魔数（salt=domain 字节，不是信封 salt）:
   ikm = PBKDF2-HMAC-SHA256(NFC(password), salt=domain, iter=100_000, dkLen=32)
   header_magic  = HKDF-Expand(SHA256, salt=Some(domain), ikm, info=b"strhide-stealth-header",  L=8)
   trailer_magic = HKDF-Expand(SHA256, salt=Some(domain), ikm, info=b"strhide-stealth-trailer", L=4)
2) 头字段掩码（salt=信封 16B salt）:
   mask76 = HKDF-Expand(SHA256, salt=Some(salt), ikm=PBKDF2(NFC(pwd),salt,100_000,32),
                        info=b"strhide-header-mask-v1", L=76)
3) Trailer CRC: mask32 = CRC32_IEEE(trailer_magic ‖ b"STEA")；trailer_crc32 = raw_crc ⊕ mask32
```

出处：魔数 `core/crypto.rs:285-300`（调用 `structure/engine.rs:1019`、`structure/envelope.rs:583`）；掩码 `core/crypto.rs:305-312`；CRC `core/crypto.rs:318-329`（写入 `structure/envelope.rs:740-753`）。默认 `STEALTH_DOMAIN=b"strhide-stealth-v1"`（`core/params.rs:37`、`structure/params.rs:95-98`），可替换（D）。

- 掩码范围（`structure/envelope.rs:422-433`）：`header[8..12] ^= mask[0..4]`、`header[40..112] ^= mask[4..76]`；`salt(12..28)` 与 `base_nonce(28..40)` 不掩码。
- 生效条件（`structure/envelope.rs:449-466`）：stealth 用用户口令；非 stealth 且 `FLAG_ENCRYPTED=0` 用 `Profile::secret()`。`FLAG_ENCRYPTED` 头不掩码，供无口令侧识别"需要密码"。
- 标准魔数 `b7 54 2c 82 7e 31 1d 6e` / `78 e6 66 d2`（`core/params.rs:27, 30`）。

### 2.5 PE ChannelHeader 掩码（F）
14B 布局：`magic(4) ‖ version(1) ‖ flags(1) ‖ ube_len(u32 LE) ‖ slack_off(u32 LE)`（`structure/adapters/pe_codebits.rs:372-380`）。仅字节 4..14 被掩码：

```text
mask10 = HKDF-Expand(SHA256, salt=None, ikm=envelope_header_magic(8B),
                     info=b"strhide-pe-channel-mask-v2", L=10)
out[4+i] = plain[4+i] XOR mask10[i]        // i=0..10
```

出处 `core/crypto.rs:342-348`；`pe_codebits.rs:393-400, 414-436`。IKM 必须是 UBE 头 8B `magic_header`（信道 bit 112..176），不是 `ChannelHeader[0..4]` 的明文 `CHANNEL_MAGIC`（`pe_codebits.rs:460-478`）。`CHANNEL_MAGIC=STANDARD_TRAILER_MAGIC`、`CHANNEL_VERSION=1`、`CHANNEL_HEADER_LEN=14`（`pe_codebits.rs:38-44`）。标准模式仅格式混淆，不承诺机密性。

常量：`PBKDF2_ITERATIONS=100_000`（`core/crypto.rs:106`）、`AAD/HEADER/TRAILER=80/112/24`（`structure/envelope.rs:83-89`）、掩码 info 标签见上，CRC 掩码尾 `STEA`（`core/crypto.rs:326-327`）。

## 3. 两域不可混用
| 项目 | 内容域 V4 | 结构域 UBE v2 |
|---|---|---|
| PBKDF2 | 200,000（仅 Password） | 100,000（始终） |
| HKDF 盐 | `pre_salt`（32B，载体派生） | 信封 `salt`（16B）；stealth 魔数用 `domain` |
| AEAD | AES-256-GCM / ChaCha20-Poly1305 | 固定 AES-256-GCM |
| AAD 根 | 28B 内容前缀 + `format_id` | 80B header 前缀 |
| 字节序 | 大端 | 小端 |
| 无密码默认值 | `PUBLIC_DEFAULT_SECRET` | `BUILTIN_DEFAULT_KEY` |
任何一侧读取器不得回落到另一侧的密钥或标签。

## 4. 实现自检清单
以下向量除第 6 项外均无需访问本仓库；通过只证明密码学层正确，不证明载体可读。

1. **ChaCha12 流**：key=`01 00 … 00`（32B，仅首字节 1）、IV=0、12 轮；前 128 字节为（`stego/prng.rs:291-327`）：
   `12 05 6e 59 5d 56 b0 f6 ee f0 90 f0 cd 25 a2 09 / 49 24 8c 27 90 52 5d 0f 93 02 18 ff 0b 4d dd 10 / a6 00 22 39 d9 a4 54 e2 9e 10 7a 7d 06 fe fd fe / f0 21 0f eb a0 44 f9 f2 9b 17 72 c9 60 dc 29 c0`。
2. **整段 Fisher–Yates**：种子 `b"strhide-prng-contract-seed-2026!"`、n=256，前 16 项 `61 121 191 236 8 58 233 146 64 12 35 66 70 210 254 52`，末 16 项 `93 222 27 189 132 24 10 164 145 37 133 170 180 127 4 135`（`stego/prng.rs:337-364`）。
3. **前缀 Fisher–Yates**：同种子、n=256、k=16，前 16 项 `135 5 129 183 174 138 43 152 172 19 34 143 201 40 236 108`（`stego/prng.rs:496-505`）。
4. **suite 交叉否决**：同一 `(key,nonce,aad,plaintext)` 的 suite 1 密文用 suite 2 解密必须失败，反之亦然（`stego/envelope.rs:767-799`）。
5. **结构域 KDF 已知答案**：password=`"test_password"`、salt=`b"1234567890123456"` → `payload_key=2834274fef93d55fc5a3cb070c09c08eedecd8910b9a601fd67b703c8e078674`、`meta_key=5406a23d873a956bcf01781771ea5f96857b61bda4f15ef53d40d87f07477c68`；stealth（domain=`b"strhide-stealth-v1"`）`header_magic=3858efa8820a029b`、`trailer_magic=3a97756c`（`core/crypto.rs:943-970`）。
6. **detmath 摘要**：`exp 68107bf871d53df2`、`ln 6021ef64db0e27ef`、`cos 55f3c5acb971153a`、`ln_1p 23e6e71dccf69b20`、`log2 d97b86f58ee1dfba`（`WIRE_SPEC_CONTENT.md` §13.11.5、`scripts/detmath/`）；只影响写侧排序。
7. **本仓库 28 例字节基线**（`scripts/baseline_hash.py --check`）仅作本仓库回归，外部无法获取语料，不作为互操作判据。

失败面：密钥、域、suite、AAD 任一不一致，内容域统一 `NoHiddenData`，结构域表现为元数据/分块认证失败；实现不应以更详细的错误泄露差异。
