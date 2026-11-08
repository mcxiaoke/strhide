# Legal Notice / 法律声明

`strhide` is dual-use software: it hides data inside ordinary files and can also be used to analyse files for hidden data. This page states the boundaries the project operates under. It is **not legal advice**; if your use is regulated, get advice from a qualified lawyer in your jurisdiction.

---

## 1. License, warranty, and liability

The source code is licensed under the **Apache License 2.0** — see [LICENSE](LICENSE). Third-party components and their licenses are listed in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

The software is provided **"AS IS", without warranties or conditions of any kind**, express or implied (Apache-2.0 §7), and the authors are not liable for any claim, damage, or other liability arising from the software or its use (Apache-2.0 §8).

The full warranty disclaimer, the liability limitation, the backup obligation, and the indemnity clause are stated in the **[DISCLAIMER](DISCLAIMER.md)** ([中文](DISCLAIMER.zh.md)). That document is the authoritative statement of risk; this page does not repeat it, so the two cannot drift apart.

## 2. Acceptable use

Intended use is research, teaching, digital watermarking, format-preservation engineering, forensics education, and authorized red-team/blue-team work. Prohibited uses — illegal activity, infringing others' rights, tampering with evidence, circumventing DRM or access controls, and modifying files you have no right to modify — are enumerated in [DISCLAIMER.md](DISCLAIMER.md) §2.

You are responsible for having the right to modify any carrier you process, and for the legality of the data you hide. The maintainers do not endorse, and are not responsible for, downstream use.

## 3. Cryptography and export control

`strhide` contains and uses cryptographic functionality (PBKDF2, HKDF, AES-256-GCM, ChaCha20-Poly1305). Software with cryptographic functionality is regulated in some jurisdictions — for example under the U.S. Export Administration Regulations, the EU dual-use Regulation 2021/821, or the Export Control Law of the People's Republic of China. Downloading, using, re-exporting, or redistributing this software may be subject to export licenses or reporting duties where you are. Compliance is the user's responsibility.

## 4. HEVC / H.265 patent notice

The content-domain HEVC engine parses and rewrites H.265/HEVC bitstreams, using two upstream implementations: [`oxideav-h265`](https://github.com/OxideAV/oxideav-h265) (MIT) and `strhide-rusty-h265`, the project's fork of [`rusty_h265`](https://github.com/Remade-With-Rust/rusty_h265) (Apache-2.0).

**Copyright licenses (MIT / Apache-2.0) are not patent licenses.** H.265/HEVC is covered by patent pools and individual patent holders, and in some jurisdictions making, using, selling, or distributing an implementation of the standard may require a patent license from those holders. This project grants no patent rights beyond what its dependencies' licenses expressly grant, and makes no representation about the patent status of HEVC in your jurisdiction. If you distribute builds with the `content-hevc` feature enabled, assess that exposure yourself; the feature is optional, and builds without it contain no HEVC code.

## 5. Names and marks

`strhide`, `sth`, `sthc`, `sths`, `sthv`, and `StrHide Studio` identify this project. Forks and derivative distributions are welcome under the license, but they must not imply that they are the official project or that the maintainers endorse them. In line with the upstream fork rules recorded in [docs/CRATES_PUBLISH.md](docs/CRATES_PUBLISH.md): keep the original copyright notices, state the fork origin in the package metadata and README, and use a distinct package name.

## 6. Third-party components

Rust dependencies, the two vendored HEVC implementations, and the GUI's JavaScript dependencies are enumerated — with versions and licenses — in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) and the generated lists under [`docs/licenses/`](docs/licenses/). Binary releases additionally bundle the platform webview runtime provided by the operating system, which is not redistributed by this project.

## 7. Reporting a legal concern

If you believe this project infringes your rights, contact `mcxiaoke@live.com` with the specifics before taking other action. Security issues go through [SECURITY.md](SECURITY.md) instead.
