"""Capacity reporting tests: ``inspect`` capacity table and static ``list-strategies``."""

import os
import struct
import subprocess
import sys
import zipfile
import zlib

from strhide.adapters import ADAPTERS
from strhide.core.engine import inspect_carrier


def make_png() -> bytes:
    """Minimal valid 1x1 RGB PNG."""

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return (
            struct.pack(">I", len(data))
            + body
            + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    idat = chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
    iend = chunk(b"IEND", b"")
    return b"\x89PNG\r\n\x1a\n" + ihdr + idat + iend


def test_inspect_reports_png_capacity(tmp_path):
    carrier = tmp_path / "c.png"
    carrier.write_bytes(make_png())

    res = inspect_carrier(str(carrier))
    assert res["format"] == "PNG"
    assert res["has_hidden_data"] is False
    assert "supported_strategies" not in res

    strategies = res["strategies"]
    assert [c["strategy"] for c in strategies] == ["chunk", "eof"]
    chunk = strategies[0]
    assert chunk["capacity_bytes"] == 0x7FFFFFFF
    assert chunk["available"] is True
    assert "2 GiB - 1" in chunk["limit"]
    assert strategies[1]["capacity_bytes"] is None


def test_inspect_measures_zip_capacity(tmp_path):
    carrier = tmp_path / "c.zip"
    with zipfile.ZipFile(carrier, "w") as z:
        z.writestr("a.txt", "hello")

    res = inspect_carrier(str(carrier))
    assert res["format"] == "ZIP"
    pre_cd = res["strategies"][0]
    assert pre_cd["strategy"] == "pre_cd_inject"
    assert pre_cd["available"] is True
    cap = pre_cd["capacity_bytes"]
    assert cap is not None and 0 < cap < 0xFFFFFFFF
    assert "4 GiB - EOCD offset" in pre_cd["limit"]


def test_static_capacity_table_covers_all_adapters():
    formats = []
    for adapter in ADAPTERS:
        name = adapter.format_name()
        formats.append(name)
        caps = adapter.strategy_capacities(None)
        assert caps, f"{name} must list at least one strategy"
        assert [c.strategy for c in caps] == adapter.supported_strategies(), (
            f"{name}: capacity order must match supported_strategies"
        )
        for c in caps:
            assert c.limit, f"{name}/{c.strategy}: empty limit"
            assert c.available, f"{name}/{c.strategy}: static mode must be available"
            if c.limit.startswith("carrier-dependent"):
                assert c.capacity_bytes is None

    for expected in ("PNG", "JPEG", "MP4", "ZIP", "PDF", "PE"):
        assert expected in formats
    # Unrecognized files are not a format: no catch-all adapter may appear.
    assert "GENERIC" not in formats


def test_list_strategies_is_static_and_needs_no_carrier(tmp_path):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, "-m", "strhide.cli", "list-strategies"],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "Format" in out and "Strategy" in out and "Limit" in out
    assert "PNG" in out and "chunk" in out
    assert "carrier-dependent" in out
