# Support

## Before you ask

Most questions are already answered. In this order:

1. [docs/FAQ.md](../docs/FAQ.md) — extraction failures, capacity, performance, backups, platform warnings.
2. [INSTALL.md](../docs/INSTALL.md) — installation, checksum verification, unsigned-binary warnings, build errors.
3. [docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md) — what the tool does and does not promise. A "why can't I read my file after sending it through a chat app" question is answered in §4.
4. [docs/CLI_GUIDE.md](../docs/CLI_GUIDE.md) / [docs/GUI_GUIDE.md](../docs/GUI_GUIDE.md) — parameters and UI behaviour.

## Where to ask

| Kind | Where |
| :--- | :--- |
| Bug | [GitHub Issues](https://github.com/mcxiaoke/strhide/issues) — use the bug template |
| Feature request | Issues, feature template. Read [ROADMAP.md](../docs/ROADMAP.md) first; out-of-scope items are listed there |
| Usage question | Issues with the `question` label |
| **Security vulnerability** | **Not an issue** — follow [SECURITY.md](SECURITY.md) |
| Licensing / legal | `mcxiaoke@live.com` |

## What to include in a bug report

```text
strhide --version
platform (OS + version, x86_64 / aarch64, and whether you used the avx2 build)
the exact command line (redact passwords and payloads)
carrier format and approximate size
what you expected vs what happened (full error text)
```

If a file is involved, say **whether the carrier was transferred or re-encoded** between the write and the read. That single fact explains most "it used to work" reports. Do not upload real confidential carriers; reproduce with a synthetic one (any PNG/JPEG plus a short message is enough).

For desktop-app issues, attach the relevant log entries from the `日志` panel after removing paths and payloads.

## What is not supported

- **Recovering a payload from a re-encoded, cropped, resized, or transcoded file.** Not a bug; the data is gone.
- **Recovering the original host after a content-domain embed.** By design irreversible.
- **Diagnosing a custom build.** If you changed feature flags, patched the engine, or built a private dialect, we can help with build errors but cannot reason about your wire format.
- **Production SLAs.** This is a volunteer project; there is no guaranteed response time. Security reports have the targets in [SECURITY.md](SECURITY.md).
- **Requests to help hide data from a specific person, employer, or investigation**, or to bypass DRM. See [LEGAL.md](../docs/legal/LEGAL.md) §2.

## Response expectations

| Channel | Typical response |
| :--- | :--- |
| Security report | acknowledged within 7 days (see [SECURITY.md](SECURITY.md)) |
| Bug with a reproducible case | within a couple of weeks |
| Question | best effort |
| Feature request | triaged, not necessarily answered |

Issues with no reproduction and no version information may be closed without a reply.
