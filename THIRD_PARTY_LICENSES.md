# Third-Party Licenses

`strhide` is Apache-2.0 (see [LICENSE](LICENSE)). It bundles or links third-party code under permissive licenses; the complete inventories are generated from package metadata, not maintained by hand.

## Inventories

| Scope | File | Count | Source |
| :--- | :--- | ---: | :--- |
| Core crate + CLI binaries | [`docs/licenses/rust-core.md`](docs/licenses/rust-core.md) | 87 crates | `rust/Cargo.toml`, all features, build deps included, dev-deps excluded |
| Desktop app backend (Tauri) | [`docs/licenses/gui-backend.md`](docs/licenses/gui-backend.md) | 503 crates | `gui/src-tauri/Cargo.toml`, all features |
| Desktop app frontend | [`docs/licenses/gui-frontend.md`](docs/licenses/gui-frontend.md) | 11 packages | runtime `dependencies` of `gui/package.json` |

Regenerate and verify:

```bash
python scripts/gen_third_party_licenses.py           # rewrite the three lists
python scripts/gen_third_party_licenses.py --check   # exit 1 if any list is stale
```

The license identifiers come from each package's own metadata (`cargo metadata`, `package.json`). They are not a substitute for reading the upstream license text before you redistribute.

## License families in use

- **Core (87 crates)** — `MIT OR Apache-2.0` (59), `Apache-2.0 OR MIT` (10), `MIT` (6), `Apache-2.0` (4), `Zlib OR Apache-2.0 OR MIT` (2), `(MIT OR Apache-2.0) AND Unicode-3.0` (2), plus one each of `MIT/Apache-2.0`, `Unlicense OR MIT`, `Zlib`, `MIT OR Apache-2.0 OR LGPL-2.1-or-later`. No copyleft-only dependency.
- **GUI backend (503 crates)** — the same permissive set plus the platform layer pulled in by Tauri.
- **GUI frontend (11 packages)** — MIT, ISC, and `Apache-2.0 OR MIT` only.

### Items that need a closer look

| Component | License | Note |
| :--- | :--- | :--- |
| `cssparser`, `cssparser-macros`, `dtoa-short`, `option-ext`, `selectors` | **MPL-2.0** | Present only in the GUI backend graph (Tauri's platform layer). MPL-2.0 is file-level copyleft: distributing unmodified files requires keeping the license and offering the source (the crates.io tarball URL satisfies this); modifying those files would require publishing the modified files. This project does not patch them. |
| `r-efi` | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | UEFI target only; it never enters the shipped Windows/Linux/macOS binaries. The MIT/Apache-2.0 arm applies. |
| `memchr` | `Unlicense OR MIT` | The MIT arm applies. |
| `unicode-ident`, `unicode-normalization` | `(MIT OR Apache-2.0) AND Unicode-3.0` | Both arms are obligations: keep the crate license **and** the [Unicode License v3](https://www.unicode.org/license.txt). |
| `brotli`, `alloc-no-stdlib`, `alloc-stdlib` | BSD-3-Clause (+MIT) | GUI backend only; keep the copyright notice and do not use the names of the copyright holders to endorse derivatives. |
| `strhide-rusty-h265` (package of the `rusty_h265` dependency) | Apache-2.0 | This project's fork of [`rusty_h265`](https://github.com/Remade-With-Rust/rusty_h265). Upstream copyright notices are retained; the fork origin and the scope of local changes are documented in [docs/CRATES_PUBLISH.md](docs/CRATES_PUBLISH.md). |
| `oxideav-h265` | MIT | Upstream, unpatched. See the HEVC patent notice in [LEGAL.md](LEGAL.md) §4 — a copyright license is not a patent license. |

## What a binary release must carry

Apache-2.0 §4 requires that recipients of a binary distribution receive a copy of the license and any `NOTICE` file. The CLI release job builds `strhide-<version>-licenses.zip` from the repository at tag time — `LICENSE`, `NOTICE`, this file, and the three lists under `docs/licenses/` — and uploads it with the binaries, so a download from the Releases page already carries what §4 requires.

If you redistribute a build yourself, ship that archive (or the same files) alongside it. Do not hand-assemble it: the archive must match the dependency set the binary was built from.

The desktop installers do not embed these files yet; for a `gui-v*`-only release, the license bundle from the matching `v*` release applies.

The desktop application additionally loads the operating system's webview runtime (WebView2 on Windows, WKWebView on macOS, WebKitGTK on Linux). That runtime is part of the OS and is not redistributed here.

## Reporting a licensing problem

Open an issue or write to `mcxiaoke@live.com`. If a dependency's metadata is wrong or a required notice is missing, it will be fixed in the next release.
