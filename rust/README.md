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
strhide write -c photo.png -t "secret"           # hide text (in-place, .bak backup)
strhide write -c report.pdf -d file.zip -p pw    # hide a file, encrypted
strhide write -c a.png b.png c.png -t "secret"   # same payload into several carriers
strhide read -c photo.png -o out/                # extract hidden data
strhide inspect -c report.pdf --json             # envelope metadata + capacity
strhide verify -c report.pdf                     # verify host + envelope integrity
strhide remove -c photo.png                      # remove hidden data, restore host
strhide remove -c a.png b.png c.png              # strip several carriers at once
strhide list                          # static format/strategy/limit table
```

`write` and `remove` accept one or more carriers (`read`, `inspect`, and
`verify` still take exactly one). `write` embeds the same payload into each
carrier; when more than one is given, `-o` must name an existing directory and a
`[SUMMARY] n/m carriers succeeded` line is printed. Runs stop at the first
failure; every write/remove is atomic per carrier, so carriers already handled
stay modified and the rest are untouched.

Supported carriers: PNG, JPEG, MP4, ZIP, PDF, and Windows PE. Unrecognized files
are rejected rather than appended to.

## Compatibility

Envelope format is identical to the [Python implementation](../python/): files written by one can be read, verified, and cleaned by the other.

## License

[Apache-2.0](../LICENSE)
