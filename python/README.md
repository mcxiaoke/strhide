# strhide (Python)

> **Deprecation notice (2026-10-18):** this pure-Python implementation is
> frozen at **0.2.0** and will no longer receive new features. Use the
> prebuilt Rust binary for the full feature set. In particular, Python does
> **not** implement the `pe_codebits` PE strategy and cannot read carriers
> written with it. The package stays installable for existing users.

Python implementation of **strhide** — smart format-preserving, lossless data hiding. Provides both a library and a `strhide` CLI. Requires Python ≥ 3.10.

See the [project README](../README.md) for the full documentation, and the [Chinese version](../README.zh.md).

## Install

```bash
pip install strhide
```

## CLI

```bash
strhide write -c photo.png -t "secret"           # hide text (in-place, .bak backup)
strhide write -c report.pdf -d file.zip -p pw    # hide a file, encrypted
strhide read -c photo.png -o out/                # extract hidden data
strhide inspect -c report.pdf --json             # envelope metadata + strategy capacities
strhide verify -c report.pdf                     # verify host + envelope integrity
strhide remove -c photo.png                      # remove hidden data, restore host
strhide list-strategies                          # static format/strategy/limit table
```

Supported carriers: PNG, JPEG, MP4, ZIP, PDF, Windows PE. Unrecognized files are rejected: appending an envelope to an arbitrary file can corrupt it.

## Library

```python
from strhide import write_carrier, read_carrier, inspect_carrier

write_carrier("carrier.png", data_text="hello", password="pw")
result = read_carrier("carrier.png", output_path="restored.txt", password="pw")
meta = inspect_carrier("carrier.png", password="pw")
```

All functions return a result dict and raise `StrHideError` subclasses on failure. Type annotations are included (`py.typed`).

`inspect_carrier` always returns a `strategies` list (`strategy`, `capacity_bytes`, `available`, `limit`, `note`); the first available entry is what `-s auto` would pick.

## Compatibility

Envelope format is identical to the [Rust implementation](../rust/): for the
strategies Python implements, files written by one can be read, verified, and
cleaned by the other. `pe_codebits` carriers are Rust-only.

## License

[Apache-2.0](../LICENSE)
