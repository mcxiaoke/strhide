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
strhide write photo.png -t "secret"           # hide text (writes to photo-out.png, leaves photo.png untouched)
strhide write photo.png -t "secret" --in-place # modify in-place (creates photo.png.bak backup)
strhide write report.pdf -d file.zip -p pw    # hide a file, encrypted
strhide write a.png b.png -t "secret" -o out/ # batch write into an existing directory
strhide read photo-out.png -o out/            # extract hidden data to directory/file
strhide read photo-out.png --stdout           # print hidden data directly to stdout
strhide inspect report.pdf dir/ -r --json     # envelope metadata + capacity (multi-carrier & recursive)
strhide verify report.pdf dir/ -r             # verify host + envelope integrity (multi-carrier & recursive)
strhide restore photo-out.png -o clean.png    # strip hidden data to clean.png
strhide restore photo.png --in-place          # restore carrier in-place
strhide embed photo.png -t "secret" -o out.png # content-adaptive stego (HILL for PNG, UERD for JPEG)
strhide embed photo.heic -t "secret" -o out.heic # content-adaptive stego (HEIF/HEIC CABAC bypass, zero growth Δ=0)
strhide embed photo.png --capacity             # probe image stego capacity without embedding
strhide embed photo.heic --capacity            # probe HEIF/HEIC stego capacity
strhide extract out.png --stdout               # extract content-adaptive payload
strhide extract out.heic --stdout              # extract HEIF/HEIC payload
strhide embed photo.png -t "secret" --stego-secret "s3cr3t" -o out.png # private dialect (no password, unreadable by stock builds)
strhide list --json                           # format/strategy/limit table (human or --json)
strhide scan suspicious.bin dir/ -r           # black-box steganalysis (any tool)
```

`write`, `restore`, `inspect`, `verify`, `embed`, and `scan` accept one or more
carriers (and directories with `-r/--recursive`). `read` and `extract` take
exactly one carrier. By default, `write`, `restore`, and `embed` write to safe
`<stem>-out.<ext>` target files (or into a `-o` directory for multiple carriers),
leaving input files untouched; pass `--in-place` for in-place modifications.
`read`, `extract`, `write`, and `restore` refuse to overwrite existing files
unless `--overwrite` is explicitly specified.

The global `-q/--quiet` suppresses status lines and human-readable reports
(payload data from `read --stdout`, `--json` output, and `[ERROR]` lines always
print), so scripts can act on exit codes alone. `scan` also owns its exit code:
it exits 1 when any report reaches a `likely-hidden` verdict, 0 otherwise.

JPEG carriers are also analysed with a calibrated DCT test (`dct:calibration`):
the image is decoded, shifted by half a block and re-quantised with its own
table, then the even/odd coefficient-pair imbalance is compared against that
reference. It is a heuristic — `clean`/`low` JPEG reports carry a note saying so,
and quality-100 carriers (all quantization steps == 1) are out of scope.

Supported carriers: PNG, JPEG, WebP, HEIC/HEIF, HEVC (Annex-B), MP4, WAV, MKV, ZIP, PDF, and Windows PE. Unrecognized files
are rejected rather than appended to.

## Library

The recommended entry point is a **`StrHide`** instance (the facade). It binds one private dialect (`Profile`) and one writer-behaviour baseline (`LocalParams`), then exposes every verb as an ordinary method. The whole dialect can be declared `const` at compile time (zero runtime cost), and both path and in-memory variants are provided.

```rust
use strhide::engine::{PayloadSource, WriteOptions};
use strhide::facade::StrHide;
use strhide::params::Profile;

// The whole private dialect is declared at compile time.
const ENGINE: StrHide = StrHide::new()
    .with_profile(Profile::new().with_default_secret("my-deployment-key"));

// Structure domain, in-memory:
let (stego, _) = ENGINE.write_bytes(
    &cover_png,
    PayloadSource::Bytes(b"payload"),
    &WriteOptions::default(),
)?;
let read = ENGINE.read_bytes(&stego, None)?;
assert_eq!(read.data, b"payload");

// Content domain (image steganography), in-memory:
let stego = ENGINE.embed(&cover_jpg, b"payload", &Default::default())?;
let payload = ENGINE.extract(&stego, &Default::default())?;
assert_eq!(payload, b"payload");
```

A host can also drive its own command line: `ENGINE.run_cli_from(std::env::args_os())` returns the exit code without calling `process::exit` (argv must include the program name as its first element).

### Free-function entry points

The facade is a thin forwarder; the underlying free functions stay public and are handy when a single call is all you need. Both families run the same protocol:

| | in/out | atomic commit | `.bak` | timestamps |
|---|---|---|---|---|
| `write_carrier_with` / `read_carrier_with_profile` / `remove_carrier_with_options` | paths | yes | yes | cloned |
| `write_carrier_bytes` / `read_carrier_bytes` / `remove_carrier_bytes` | `&[u8]` → `Vec<u8>` | n/a (you own the buffer) | no | n/a |

The byte API runs the same rejection content checks (Authenticode / PDF / JAR
signatures) but skips the path-based ones — read-only carrier, target-directory
write probe, `.apk`/signature-file name checks — which describe a filesystem the
caller may not have. It also refuses `options.output_path`: a function whose
contract is "return bytes" must not write files.

Payloads are buffered in memory by both families; there is no streaming API. A
multi-GB payload therefore needs that much RAM (the plan's alternative — spilling
the payload to a temporary file — is not implemented).

See [`docs/api/ARCHITECTURE.md`](../docs/api/ARCHITECTURE.md) for the full module
topology and API surface, and [`docs/api/WIRE_SPEC.md`](../docs/api/WIRE_SPEC.md)
for the wire format. Examples: `cargo run --example in_memory`, `cargo run
--example private_profile`, `cargo run --release --example codec_bench --
<carrier.png> <payload>`.

## Compatibility

The Python package is frozen at 0.2.0 and its envelope format is not
interoperable in either direction: Python cannot read Rust's fully-encrypted
envelopes or `pe_slack` / `pe_codebits` PE carriers, and Rust no longer reads
0.2.0-era envelopes (the pre-v2 ASCII magics, JSON metadata and plaintext
sealing were removed on 2026-10-21).

## License

[Apache-2.0](../LICENSE)
