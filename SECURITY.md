# Security Policy

`strhide` derives encryption keys from user passwords, rewrites carrier files in place, and ships a steganography engine. Security reports are treated as first-class issues.

---

## Supported versions

| Version | Supported |
| :--- | :--- |
| `0.9.x` (latest patch only) | Yes |
| earlier than `0.9` | No |

Before `1.0`, security fixes land on the latest release line only, and there are no backports. Wire formats may still change between releases, so carriers written by an older version may become unreadable after an upgrade — see [CHANGELOG.md](CHANGELOG.md) and the stability classes in [docs/api/spec/README.md](docs/api/spec/README.md).

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

1. **Preferred** — GitHub Security Advisory: *Security* tab → *Report a vulnerability*. This keeps the discussion private and gives us a CVE path.
2. **Alternative** — email `mcxiaoke@live.com` with `[strhide-security]` in the subject.

Please include:

- affected version (`strhide --version`) and platform;
- the command or API path involved (`write` / `read` / `restore` / `embed` / `extract` / `capacity` / `inspect` / `verify` / `scan`, or the `facade::StrHide` method);
- a minimal reproducer when the input can be shared, or a precise description when it cannot;
- what an attacker gains (key recovery, payload disclosure, silent data corruption, signature bypass, code execution, …).

Never attach real secrets or real confidential payloads.

## What to expect

| Stage | Target |
| :--- | :--- |
| Acknowledgement | 7 days |
| Triage and severity assessment | 14 days |
| Fix or written mitigation plan | after triage, timeline agreed in the advisory |
| Coordinated disclosure | 90 days from the report (sooner if the issue is exploited in the wild) |

These are best-effort targets, not contractual SLAs. Reporters are credited in [CHANGELOG.md](CHANGELOG.md) unless they ask to stay anonymous.

## In scope

- **Key derivation and AEAD** — PBKDF2/HKDF parameter handling, domain separation, `AAD` construction, nonce derivation, cipher-suite confusion between the two domains.
- **Credential handling** — key material lifetime and wiping, credential sources (`-p`, `--password-file`, `-e`, `STRHIDE_PASSWORD`, `StealthProfile`/`StegoProfile` defaults), unintended leakage into logs, backups, temporary files, or the GUI log console.
- **File handling** — atomic commit and stale temp-file reclamation, in-place backup behaviour, path handling on output (`-o`), permission/timestamp preservation.
- **Carrier patching** — PE `codebits`/slack/overlay patching, PDF incremental update, ZIP/JAR central-directory injection, refusing signed carriers.
- **Parsers** — memory safety, integer overflow, unbounded allocation, and time complexity when reading hostile carriers (truncated, huge, malformed, adversarial chunk/box tables).
- **CLI and GUI surface** — argument parsing, the Tauri IPC command set, the desktop client's CSP and capability configuration, drag-and-drop path handling.
- **Supply chain** — build scripts, feature combinations that unexpectedly weaken defaults, published crates whose behaviour differs from this repository.

## Known design boundaries (not vulnerabilities)

These are documented, intentional behaviours. Reporting them as vulnerabilities is not actionable; if you believe one of them is worse than documented, say so explicitly and we will re-review.

| Boundary | Why it is by design |
| :--- | :--- |
| **Password-less envelopes are readable by any build.** Both domains fall back to public constants (`PUBLIC_DEFAULT_SECRET` for content, `BUILTIN_DEFAULT_KEY` for structure) when no password, key file, or profile secret is supplied. | Interoperability between stock binaries. Supply a password or a private dialect by default. |
| **`--stealth` does not improve steganalysis resistance.** It derives the header/trailer magic and masks header fields from the password, so a no-password probe sees noise; the statistical detectability of the payload is unchanged. | It is an attribution/plausible-deniability feature, not a detection-resistance feature. See [docs/PRIVATE_BUILD.md](docs/PRIVATE_BUILD.md) §6. |
| **Structure-domain markers are visible in non-stealth mode.** `prIv` (PNG), `stEg`/`SHRD`, `MP4_UUID_NEUTRAL`, and the JPEG APP15 marker can be found by static scanners. | Cost-free bit-exact restoration is built on format-legal structure, which must sit somewhere in the container. |
| **Content-domain embeds are irreversible.** The bytes of the media itself change, so no pre-write host can be recovered. | Fundamental to content-adaptive steganography. |
| **Extraction failure is indistinguishable from a wrong password.** The content domain returns the same "no hidden data" result for a wrong key, a wrong dialect, and an absent payload. | Not leaking whether a carrier holds a payload is the point. Do not expect a more specific error. |
| **`restore` fails closed** with `RestoreMismatch` when the carrier changed after the write (for example a later content-domain embed, or any re-encode) instead of emitting a non-matching file. | Emitting a wrong file silently would be worse than refusing. |
| **Signed carriers are refused** (`Rejection`): PE Authenticode, PDF `ByteRange` signatures, and signed JARs are rejected because any injection invalidates the signature. | Silently breaking a signature is a security regression, not a feature. |
| **A lower PBKDF2 iteration count is refused on read.** Readers reject envelopes whose declared iteration count is below `max_pbkdf2_iterations` (default 200 000 for the content domain). | Prevents a downgrade attack that makes brute force cheap. |

## Security-relevant implementation properties

Documented for reviewers; the normative source is [docs/api/spec/CRYPTO.md](docs/api/spec/CRYPTO.md).

- **Primitives** — PBKDF2-HMAC-SHA256 (structure domain: 100 000 iterations; content domain: 200 000 for passwords, skipped for 32-byte file keys), HKDF-SHA256, AES-256-GCM (both domains, default suite) and ChaCha20-Poly1305 (content domain, suite 2; readers cross-reject the wrong suite).
- **Nonces** — structure domain derives per-chunk nonces from a base nonce by XOR-ing the chunk index into the last 4 bytes, with `0xFFFFFFFF` reserved for the metadata block; chunk index and `is_last` are bound in the AAD.
- **AAD binding** — the structure domain authenticates the 80-byte header prefix (host size + host SHA-256 + strategy + salt + nonce) plus hint/meta lengths; the content domain authenticates a 28-byte envelope prefix, `format_id`, the full base header, and the extension block.
- **Key lifetime** — derived keys are not `Copy` and are overwritten on drop with `write_volatile` plus a compiler fence.
- **Atomic writes** — output is written to `<target>.strhide.<pid>.<r>.tmp` in the destination directory and renamed over the target; stale markers from killed processes are reclaimed by rename before reuse.
- **No network, no telemetry** — the crate has no HTTP client dependency and the CLI/GUI make no outbound connections.
- **Configuration lookup excludes the current directory**, so a `strhide.toml` dropped next to an untrusted working directory is never picked up implicitly.

## Cryptographic review status

The implementation has not been through an independent third-party cryptographic audit, and this repository contains no audit report. Treat the cryptographic design as "reviewed by the author, specified in public, not externally audited". The normative specification is public precisely so that others can review or reimplement it.

## Hardening advice for users

- Prefer `--password-file` or `STRHIDE_PASSWORD` over `-p`: a password passed as an argument is visible in the process list and may land in shell history.
- Remember that `--in-place` writes a `.bak` next to the carrier by default; that backup is an unencrypted copy of the original, and deleting it is on you.
- Keep the original stego carrier. Any lossy re-encode, crop, resize, or recompression destroys content-domain payloads permanently.
- If you need isolation from stock builds rather than confidentiality with the maintainers, build a private dialect as described in [docs/PRIVATE_BUILD.md](docs/PRIVATE_BUILD.md).
- Legal and dual-use considerations are in [LEGAL.md](LEGAL.md).
