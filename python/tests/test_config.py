"""Config file support tests (--config / strhide.toml discovery and
precedence: CLI args > STRHIDE_PASSWORD env > config file > built-ins).

Mirrors rust/tests/config_cli.rs.
"""

import os
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from strhide.config import FileConfig, load_config
from strhide.errors import StrHideError

# --------------------------------------------------------------------------- helpers


def make_png() -> bytes:
    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = (
        struct.pack(">I4s", len(ihdr_data), b"IHDR")
        + ihdr_data
        + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    )
    return magic + ihdr + b"\x00\x00\x00\x00IEND\xaeB`\x82"


def run_cli(args, cwd, env_password=None):
    """Run ``python -m strhide`` inside ``cwd`` with STRHIDE_PASSWORD cleared
    unless ``env_password`` says otherwise."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    env["STRHIDE_PASSWORD"] = env_password or ""
    return subprocess.run(
        [sys.executable, "-m", "strhide", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )


# --------------------------------------------------------------------------- load_config unit tests


def test_load_config_explicit_missing_raises(tmp_path):
    with pytest.raises(StrHideError, match="Failed to read config file"):
        load_config(str(tmp_path / "nope.toml"))


def test_load_config_unknown_key_warns(tmp_path, capsys):
    cfg_path = tmp_path / "c.toml"
    cfg_path.write_text('pasword = "x"\n', encoding="utf-8")
    cfg = load_config(str(cfg_path))
    assert cfg.password is None
    captured = capsys.readouterr()
    assert "Unknown key 'pasword'" in captured.err


def test_load_config_invalid_toml_raises(tmp_path):
    cfg_path = tmp_path / "c.toml"
    cfg_path.write_text("strategy = [broken\n", encoding="utf-8")
    with pytest.raises(StrHideError, match="Invalid"):
        load_config(str(cfg_path))


def test_load_config_wrong_value_type_raises(tmp_path):
    cfg_path = tmp_path / "c.toml"
    cfg_path.write_text('strategy = true\n', encoding="utf-8")
    with pytest.raises(StrHideError, match="must be a string"):
        load_config(str(cfg_path))


def test_minimal_fallback_parser(monkeypatch, tmp_path):
    """The Python 3.10 fallback (no tomllib) handles flat keys/strings/bools."""
    import strhide.config as cfg_mod

    cfg_path = tmp_path / "c.toml"
    cfg_path.write_text(
        '# comment\nstrategy = "ask"\nstealth = true\n'
        'password = "p\\"w"  # trailing comment\nunescape = false\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(cfg_mod, "tomllib", None)
    cfg = load_config(str(cfg_path))
    assert cfg == FileConfig(
        strategy="ask", stealth=True, password='p"w', unescape=False
    )


def test_minimal_fallback_parser_rejects_tables(monkeypatch, tmp_path):
    import strhide.config as cfg_mod

    cfg_path = tmp_path / "c.toml"
    cfg_path.write_text("[section]\nkey = 1\n", encoding="utf-8")
    monkeypatch.setattr(cfg_mod, "tomllib", None)
    with pytest.raises(StrHideError, match="Invalid config file"):
        load_config(str(cfg_path))


# --------------------------------------------------------------------------- CLI integration tests


def test_config_password_and_encrypt_apply_on_write_and_read(tmp_path):
    (tmp_path / "c.png").write_bytes(make_png())
    (tmp_path / "strhide.toml").write_text(
        'encrypt = true\npassword = "cfg-pass-1"\n', encoding="utf-8"
    )

    # Write with no CLI password/encrypt flags: both come from the config.
    r = run_cli(["write", "-c", "c.png", "-t", "hello"], tmp_path)
    assert r.returncode == 0, r.stderr

    # Read without any password: the config supplies it.
    r = run_cli(["read", "-c", "c.png", "-o", "out1.bin"], tmp_path)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "out1.bin").read_text(encoding="utf-8") == "hello"

    # An explicit CLI password equal to the config one still works.
    r = run_cli(["read", "-c", "c.png", "-p", "cfg-pass-1", "-o", "out2.bin"], tmp_path)
    assert r.returncode == 0, r.stderr

    # A wrong CLI password fails even though the config holds the right one.
    r = run_cli(["read", "-c", "c.png", "-p", "wrong", "-o", "out3.bin"], tmp_path)
    assert r.returncode == 1


def test_env_password_overrides_config_password(tmp_path):
    (tmp_path / "c.png").write_bytes(make_png())
    (tmp_path / "strhide.toml").write_text(
        'encrypt = true\npassword = "cfg-pass-1"\n', encoding="utf-8"
    )

    # Write with the env password (wins over the config password).
    r = run_cli(["write", "-c", "c.png", "-t", "hello"], tmp_path, env_password="env-pass-2")
    assert r.returncode == 0, r.stderr

    # Reading with only the config password fails (it is the wrong password).
    r = run_cli(["read", "-c", "c.png", "-o", "o1.bin"], tmp_path)
    assert r.returncode == 1

    # Reading with the env password succeeds.
    r = run_cli(
        ["read", "-c", "c.png", "-o", "o2.bin"], tmp_path, env_password="env-pass-2"
    )
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "o2.bin").read_text(encoding="utf-8") == "hello"


def test_explicit_config_path_applies(tmp_path):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (tmp_path / "c.png").write_bytes(make_png())
    (cfg_dir / "custom.toml").write_text(
        'encrypt = true\npassword = "cfg-pass-3"\n', encoding="utf-8"
    )

    cfg_arg = str(cfg_dir / "custom.toml")
    r = run_cli(["--config", cfg_arg, "write", "-c", "c.png", "-t", "hello"], tmp_path)
    assert r.returncode == 0, r.stderr

    r = run_cli(["--config", cfg_arg, "read", "-c", "c.png", "-o", "out.bin"], tmp_path)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "out.bin").read_text(encoding="utf-8") == "hello"


def test_strategy_from_config_is_used_by_write(tmp_path):
    (tmp_path / "c.png").write_bytes(make_png())
    (tmp_path / "strhide.toml").write_text(
        'strategy = "bogus-strategy"\n', encoding="utf-8"
    )
    r = run_cli(["write", "-c", "c.png", "-t", "hello"], tmp_path)
    assert r.returncode == 1
    assert "bogus-strategy" in r.stderr


def test_explicit_missing_config_is_a_hard_error(tmp_path):
    (tmp_path / "c.png").write_bytes(make_png())
    r = run_cli(["--config", "nope.toml", "list-strategies"], tmp_path)
    assert r.returncode == 1
    assert "Failed to read config file" in r.stderr
