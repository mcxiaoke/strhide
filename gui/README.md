# StrHide Studio (`gui/`)

Desktop client for `strhide`. Tauri 2 shell + React 18 + TypeScript + Tailwind, with the engine linked directly as a Rust dependency (`path = "../../rust"`) — no sidecar process, no CLI invocation.

- **User manual** — [docs/GUI_GUIDE.md](../docs/GUI_GUIDE.md) (Chinese; includes the UI↔CLI terminology mapping, which is not intuitive).
- **Install / build** — [INSTALL.md](../docs/INSTALL.md) §6.
- **Engine docs** — [docs/api/ARCHITECTURE.md](../docs/api/ARCHITECTURE.md), [rust/README.md](../rust/README.md).

## Layout

```text
gui/
├── src/                    # React frontend
│   ├── App.tsx             # shell: 4 tabs, theme/lang/log toggles
│   ├── views/              # StegoEmbedView, HideStructureView, ExtractView, ScanView
│   ├── components/common/  # FileQueue, PasswordRow, PayloadEditor, DirRow, LogModal, ...
│   ├── api/commands.ts     # typed wrappers over the Tauri IPC commands
│   ├── store/              # zustand: task queue, logs, persisted settings
│   └── lib/i18n.ts         # all user-facing strings (zh + en) — read this before editing copy
├── src-tauri/              # Rust backend
│   ├── src/commands/       # batch.rs, diag.rs, stego.rs, structure.rs
│   ├── capabilities/       # default.json: dialog + opener only
│   └── tests/              # cross_validation: GUI vs CLI round trips
└── tests/                  # Playwright: unit, e2e, e2e-real
```

## Development

```bash
pnpm install
pnpm tauri dev       # hot-reloading dev app
pnpm build           # tsc type-check + vite build
pnpm tauri build     # production bundles
```

Linux prerequisites: `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev`, `patchelf`.

## Tests

| Command | Scope |
| :--- | :--- |
| `pnpm test:unit` | Playwright-driven IPC command/parameter matrix |
| `pnpm test:cross` | GUI ↔ CLI cross-validation (`src-tauri/tests/cross_validation`) |
| `pnpm test:e2e` | UI interaction and contrast checks |
| `pnpm test:e2e:real` | Real process, real carriers — needs a built `StrHideStudio` binary |

All four plus `pnpm build` and `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings` are required before a GUI PR is reviewed. See [docs/TESTING.md](../docs/TESTING.md).

## Behaviour differences from the CLI

These are deliberate, and they surprise people:

- **No `.bak`**: in-place edits always call the engine with `backup: false`; the GUI writes to a target directory instead.
- **No `restore`**: bit-exact carrier restoration is a CLI-only operation (`sth restore`).
- **Algorithm is `auto` in mixed-format batches**: a single algorithm id is not valid across carriers, so the selector falls back to auto when the queue holds more than one format.
- **Two-phase extraction**: a probe call fills a backend cache, so saving the payload does not decode the carrier twice.

## Security posture

The webview runs with `default-src 'self'` CSP, `withGlobalTauri: false`, and a capability set limited to `dialog` and `opener` (no filesystem or shell plugin). The app makes no network requests. Logs stay local but do contain paths and error context — scrub them before pasting into an issue. See [SECURITY.md](../.github/SECURITY.md) and [docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md).
