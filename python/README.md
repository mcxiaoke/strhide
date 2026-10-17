# strhide (Python)

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
strhide inspect -c report.pdf --json             # show envelope metadata
strhide verify -c report.pdf                     # verify host + envelope integrity
strhide remove -c photo.png                      # remove hidden data, restore host
strhide list -c report.pdf                       # list supported strategies
```

Supported carriers: PNG, JPEG, MP4, ZIP, PDF, Windows PE, and a generic EOF fallback for any other file.

## Library

```python
from strhide import write_carrier, read_carrier, inspect_carrier

write_carrier("carrier.png", data_text="hello", password="pw")
result = read_carrier("carrier.png", output_path="restored.txt", password="pw")
meta = inspect_carrier("carrier.png", password="pw")
```

All functions return a result dict and raise `StrHideError` subclasses on failure. Type annotations are included (`py.typed`).

## Compatibility

Envelope format is identical to the [Rust implementation](../rust/): files written by one can be read, verified, and cleaned by the other.

## License

[Apache-2.0](../LICENSE)
