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
strhide read -c photo.png -o out/                # extract hidden data
strhide inspect -c report.pdf --json             # show envelope metadata
strhide verify -c report.pdf                     # verify host + envelope integrity
strhide remove -c photo.png                      # remove hidden data, restore host
strhide list -c report.pdf                       # list supported strategies
```

Supported carriers: PNG, JPEG, MP4, ZIP, PDF, Windows PE, and a generic EOF fallback for any other file.

## Compatibility

Envelope format is identical to the [Python implementation](../python/): files written by one can be read, verified, and cleaned by the other.

## License

[Apache-2.0](../LICENSE)
