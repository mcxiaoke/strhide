# stego 内容域信封 V4：Step 0 冻结向量（2026-11-03）

> 本文件是 Step 0 的冻结产物，供 Step 1–8 的单元测试逐字节引用。
> 生成方式：独立的 Python 实现（`hashlib.pbkdf2_hmac` + RFC 5869 HKDF-SHA256 +
> `binascii.crc32` + `unicodedata.NFC`），不是由 Rust 实现反向导出。
> 权威布局与公式见 `docs/stego_content_envelope_v4_final_plan_20261103.md` §2–§3。

## 0. 固定输入

| 名称 | 值 |
|---|---|
| Password | `correct horse battery staple` |
| Domain（域隔离向量） | `domain-a` |
| FileKey | `1111111111111111111111111111111111111111111111111111111111111111` |
| pre_salt (32B) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| salt16 (Header salt) | `000102030405060708090a0b0c0d0e0f` |
| nonce12 (Header nonce) | `202122232425262728292a2b` |
| suite（默认） | `1` (`Aes256Gcm`) |

## 1. Header golden bytes

### 1.1 PNG 64B base（format_id=1, HILL, STC h=8 u=2, ext_len=4）

```text
00: 000102030405060708090a0b0c0d0e0f
16: 202122232425262728292a2b0000012c
32: 4001010100010108020101000003000f
48: 0017012c0000803f0000000408d5e33f
```

`crc32` = `08d5e33f`

### 1.2 WAV 64B base（format_id=2, algorithm_id=0, Hamming, ext_len=0）

```text
00: 000102030405060708090a0b0c0d0e0f
16: 202122232425262728292a2b0000012c
32: 4000020000010000000000000003000f
48: 001700000000803f000000007d4b769b
```

`crc32` = `7d4b769b`

### 1.3 FLAC 64B base（format_id=3, algorithm_id=0, Hamming, ext_len=0）

```text
00: 000102030405060708090a0b0c0d0e0f
16: 202122232425262728292a2b0000012c
32: 4000030000010000000000000003000f
48: 001700000000803f000000009a56d00c
```

`crc32` = `9a56d00c`

### 1.4 JPEG 44B base（suite=1, STC h=8 u=24, ext_len=4）

```text
00: 40010001000102030405060708090a0b
16: 0c0d0e0f202122232425262728292a2b
32: 0000012c000818044d475109
```

`crc32` = `4d475109`

### 1.5 HEVC 32B base（magic=12345678, suite=1, STC u=2, window_slices=1, ext_len=4）

```text
00: 1234567840010200010400010000012c
16: 202122232425262728292a2b65db3bcb
```

`crc32` = `65db3bcb`

## 2. TLV golden

输入 `[Tlv{type_id:0x81, value:[01 02 03]}, Tlv{type_id:0x02, value:[]}]`：

```text
encoding = 81 03 01 02 03 02 00
```

padding 示例：`02 01 09` 后跟全 0 尾部可解析；尾部出现非 0 字节拒绝。

## 3. L1 / L2 / L3 向量

### 3.1 L1：Password / domain=None（PNG cipher）

`master = 5c74266ed4bf466efdc5e45163cda9427ef19efc78a7e16ebff3399ce7100195`

### 3.2 L1：Password / domain=`domain-a`（PNG cipher）

`master = 62446079c4653df74842c5ae42d381853084d6d9d9ee022f2b11a4c2b406614c`

### 3.3 L1：FileKey / domain=None（PNG cipher）

`master = 659fae03605b2874adac6d8d06a9be0d818a9bf206d4392111f7b6c24d27e614`

### 3.4 L2：PNG / Password / domain=None

`locate_seed = 43a7f549fa24f4215b93e94db68a7e081766533451884574560b01139f798273`

`header_stc_seed = 11887539032958310912` (`a4f905c481121a00`)

`ext_stc_seed = 14052583312398415470` (`c304ce11a016f66e`)

`magic4 = 6f361b87`

### 3.5 L2：PNG / Password / domain=`domain-a`

`locate_seed = b10faf49f4cb177fc5b913249889d52345fb6a0143e52434b71201328bb00803`

`header_stc_seed = 17242176147011615236` (`ef4883da4d573a04`)

`ext_stc_seed = 5631860850739589937` (`4e28639ad8c33331`)

`magic4 = 9f9c9968`

### 3.6 L3：PNG / suite=1 / session_salt=salt16

`enc_key = 944a517a1c450540bb22bc033bf78231661e151db9006c55dec7f0194fb11da8`

`perm_seed = 620cd14dbd302ca5e63b2f984b07e90a69b9a26752c96cea460a90514b424ae0`

`stc_seed = 13240335620252696060` (`b7bf1f18a81cfdfc`)

### 3.7 L3：PNG / suite=2 / session_salt=salt16（仅验证 suite 进入 info）

`enc_key = 4f9c8db066b8d33ba5f6cdbe75c90bc693d2a093c6c0c9710dc6a705be4f6996`

`perm_seed = b660a92fb3be3b6bb3f4bd4d9dc291ab46f393cf06c9a3e52be208648624b6a6`

`stc_seed = 7702655012707632498` (`6ae553ec73d20572`)

### 3.8 L2：HEVC / Password / domain=None

`master = 5c74266ed4bf466efdc5e45163cda9427ef19efc78a7e16ebff3399ce7100195`

`locate_seed = 67ece4982f1805d48497a032b08f8cabb793513f592b7e1a603bb7589074978f`

`header_stc_seed = 11887539032958310912` (`a4f905c481121a00`)

`ext_stc_seed = 14052583312398415470` (`c304ce11a016f66e`)

`magic4 = 6f361b87`

### 3.9 L3：HEVC / suite=1（session_salt=SHA-256(label||nonce12)）

`session_salt = 84b2263f7aa00ac331e6e64c26372559ed919e2a5020aff25535238242516e38`

`enc_key = b3e72b4ec894dd16129e14edfa8293d6455692110336c9f4d87d2b0b1aa71230`

`perm_seed = 08922a6bca4b5de63a74e4cd03eccb89464f71ed1fc76e0baeeaea2ceaa0c426`

`stc_seed = 18245078319218299937` (`fd338a1094301421`)

## 4. 引用约定

- 测试中的十六进制字符串必须与本节逐字节一致；只允许在文档里换行/空格，不允许改字节。
- `header_stc_seed`/`ext_stc_seed`/`stc_seed` 在 Rust 里是 `u64`；换算为 `u64::from_be_bytes(bytes)`。
- 若未来修订布局或公式，必须新增一份带日期时间戳的向量文档，不能原地改本文件。
