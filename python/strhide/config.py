"""TOML configuration file support (mirrors the Rust implementation).

Lookup order: explicit ``--config <path>``, then ``./strhide.toml``, then
``<home>/.strhide/config.toml``. Every key is optional; values act as
defaults and never override explicit CLI arguments or the
``STRHIDE_PASSWORD`` / ``STRHIDE_TEXT`` environment variables.

Recognized keys (all optional):

.. code-block:: toml

    strategy      = "auto"        # write: auto | ask | <adapter strategy name>
    stealth       = false         # write: stealth mode default
    encrypt       = false         # write: encryption default
    password      = "..."         # all: password default (plaintext on disk!)
    password_file = "..."         # all: password file default
    hint          = "..."         # write: password hint default
    preserve_time = true          # write: timestamp preservation default
    backup        = true          # write/remove: .bak backup default
    unescape      = false         # write: escape-sequence decoding default
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python >= 3.11
except ModuleNotFoundError:  # pragma: no cover - depends on interpreter
    tomllib = None

from strhide.errors import StrHideError

KNOWN_KEYS = frozenset(
    {
        "strategy",
        "stealth",
        "encrypt",
        "password",
        "password_file",
        "hint",
        "preserve_time",
        "backup",
        "unescape",
    }
)

_STR_KEYS = frozenset({"strategy", "password", "password_file", "hint"})
_BOOL_KEYS = frozenset({"stealth", "encrypt", "preserve_time", "backup", "unescape"})


@dataclass
class FileConfig:
    """Parsed configuration file; ``None`` means "not configured"."""

    strategy: Optional[str] = None
    stealth: Optional[bool] = None
    encrypt: Optional[bool] = None
    password: Optional[str] = None
    password_file: Optional[str] = None
    hint: Optional[str] = None
    preserve_time: Optional[bool] = None
    backup: Optional[bool] = None
    unescape: Optional[bool] = None


def default_candidates() -> list:
    """Candidate paths in lookup order, excluding an explicit ``--config`` path."""
    return [
        Path("strhide.toml"),
        Path.home() / ".strhide" / "config.toml",
    ]


def _parse_minimal(text: str, origin: Path) -> dict:
    """Fallback flat ``key = value`` parser for Python 3.10 (no ``tomllib``).

    Supports comments, blank lines, double/single quoted strings (basic
    ``\\\\`` and ``\\"`` escapes in double quotes) and booleans. Tables,
    arrays and other TOML constructs raise a clear error asking for a newer
    interpreter; the config file is flat by design.
    """
    result: dict = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{origin}:{lineno}: expected 'key = value'")
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if value.startswith('"'):
            i, buf = 1, []
            terminated = False
            while i < len(value):
                c = value[i]
                if c == "\\" and i + 1 < len(value):
                    buf.append(value[i + 1])
                    i += 2
                    continue
                if c == '"':
                    terminated = True
                    break
                buf.append(c)
                i += 1
            if not terminated:
                raise ValueError(f"{origin}:{lineno}: unterminated string")
            result[key] = "".join(buf)
        elif value.startswith("'"):
            end = value.find("'", 1)
            if end == -1:
                raise ValueError(f"{origin}:{lineno}: unterminated string")
            result[key] = value[1:end]
        elif value in ("true", "false"):
            result[key] = value == "true"
        else:
            raise ValueError(
                f"{origin}:{lineno}: unsupported value {value!r} "
                "(minimal fallback parser: use quoted strings or booleans)"
            )
    return result


def _parse(text: str, origin: Path) -> FileConfig:
    if tomllib is not None:
        table = tomllib.loads(text)
    else:  # pragma: no cover - depends on interpreter
        table = _parse_minimal(text, origin)
    for key in table:
        if key not in KNOWN_KEYS:
            print(
                f"[WARNING] Unknown key '{key}' in config file '{origin}' (ignored).",
                file=sys.stderr,
            )
    allowed = {k: v for k, v in table.items() if k in KNOWN_KEYS}
    for k, v in allowed.items():
        if k in _STR_KEYS and not isinstance(v, str):
            raise ValueError(f"config key '{k}' must be a string")
        if k in _BOOL_KEYS and not isinstance(v, bool):
            raise ValueError(f"config key '{k}' must be a boolean")
    return FileConfig(**allowed)


def load_config(explicit: Optional[str]) -> FileConfig:
    """Load the effective configuration.

    When ``explicit`` is given (the ``--config`` flag), a missing or
    unreadable file raises :class:`StrHideError`; implicit candidates that do
    not exist are silently skipped.
    """
    if explicit:
        p = Path(explicit)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as e:
            raise StrHideError(f"Failed to read config file '{p}': {e}") from e
        try:
            return _parse(text, p)
        except ValueError as e:
            raise StrHideError(f"Invalid config file '{p}': {e}") from e
    for cand in default_candidates():
        try:
            text = cand.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        except OSError as e:
            raise StrHideError(f"Failed to read config file '{cand}': {e}") from e
        try:
            return _parse(text, cand)
        except ValueError as e:
            raise StrHideError(f"Invalid config file '{cand}': {e}") from e
    return FileConfig()
