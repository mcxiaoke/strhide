# strhide (Rust)

Rust implementation of **strhide** — smart format-preserving, lossless data hiding. Builds a single static `strhide` CLI binary (and a library crate).

See the [project README](../README.md) for the full documentation, and the [Chinese version](../README.zh.md).

## Build

```bash
cargo build --release
# binary at target/release/strhide
```

## Usage

```bash
strhide write photo.png -t "secret"           # hide text (in-place, .bak backup)
strhide write report.pdf -d file.zip -p pw    # hide a file, encrypted
strhide write a.png b.png c.png -t "secret"   # same payload into several carriers
strhide read photo.png -o out/                # extract hidden data
strhide inspect report.pdf --json             # envelope metadata + capacity
strhide verify report.pdf                     # verify host + envelope integrity
strhide restore photo.png                      # strip hidden data, restore the original host
strhide restore a.png b.png c.png              # strip several carriers at once
strhide embed photo.png -t "secret" -o out.png # content-adaptive stego (HILL for PNG, UERD for JPEG)
strhide embed photo.png --capacity             # probe image stego capacity without embedding
strhide extract out.png --stdout               # extract content-adaptive payload
strhide list                          # static format/strategy/limit table
strhide scan suspicious.bin dir/ -r # black-box steganalysis (any tool)
```

`write` and `restore` accept one or more carriers (`read`, `inspect`, and
`verify` still take exactly one). `write` embeds the same payload into each
carrier; when more than one is given, `-o` must name an existing directory and a
`[SUMMARY] n/m carriers succeeded` line is printed. Runs stop at the first
failure; every write/restore is atomic per carrier, so carriers already handled
stay modified and the rest are untouched. `read` refuses to overwrite an
existing output file unless `--overwrite` is passed.

The global `-q/--quiet` suppresses status lines and human-readable reports
(payload data from `read`, `--json`/table output, and `[ERROR]` lines always
print), so scripts can act on exit codes alone. `scan` also owns its exit code:
it exits 1 when any report reaches a `likely-hidden` verdict, 0 otherwise.

Supported carriers: PNG, JPEG, MP4, ZIP, PDF, and Windows PE. Unrecognized files
are rejected rather than appended to.

## Compatibility

The Python package is frozen at 0.2.0. Rust can read legacy envelopes written by
it, but Python cannot read Rust's default fully-encrypted envelopes or
`pe_slack` / `pe_codebits` PE carriers.

## License

[Apache-2.0](../LICENSE)
