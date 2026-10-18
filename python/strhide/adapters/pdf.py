"""PDF format adapter for strhide with compliant Incremental Update object stream hiding."""

from __future__ import annotations

import shutil
from typing import BinaryIO, List, Optional, Tuple

from strhide.adapters.base import HostAdapter, StrategyCapacity
from strhide.core.envelope import EnvelopeHeader, read_trailer_from_tail
from strhide.errors import CorruptedDataError, UnsupportedFormatError

PDF_MAGIC = b"%PDF-"

# ASCII whitespace set shared with the Rust implementation (`is_pdf_ws`):
# space, TAB, LF, VT, FF, CR — the same class `\s` matches on bytes.
_WS_BYTES = frozenset(b" \t\n\r\x0b\x0c")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


def _read_digits_after_ws(text: bytes, i: int) -> Tuple[Optional[int], int]:
    """Read an optional whitespace run followed by a decimal digit run starting
    at ``i``; returns ``(value, new_position)``. The digit run stops at the
    first non-digit, so compact dictionaries such as ``/Size 90/Root`` yield
    90. ``value`` is ``None`` when no digits are present or the value exceeds
    u64 (mirroring the Rust implementation's parse semantics)."""
    n = len(text)
    while i < n and text[i] in _WS_BYTES:
        i += 1
    start = i
    while i < n and 0x30 <= text[i] <= 0x39:
        i += 1
    if i == start:
        return None, i
    val = int(text[start:i])
    if val > _U64_MAX:
        return None, i
    return val, i


def _find_int_after(text: bytes, key: bytes) -> Optional[int]:
    """Decimal number that directly follows ``key`` (after optional
    whitespace), if any."""
    rel = text.find(key)
    if rel == -1:
        return None
    val, _ = _read_digits_after_ws(text, rel + len(key))
    return val


def _parse_indirect_ref_after(text: bytes, pos: int) -> Optional[Tuple[int, int]]:
    """Parse ``<digits> <ws+> <digits> <ws+> R`` starting at ``pos`` (the end of
    a dictionary key such as ``/Root``). The trailing ``R`` only needs to start
    the next token, so compact forms like ``/Root 1 0 R/Info`` parse
    correctly."""
    num1, i = _read_digits_after_ws(text, pos)
    if num1 is None:
        return None
    num2, i = _read_digits_after_ws(text, i)
    if num2 is None:
        return None
    n = len(text)
    while i < n and text[i] in _WS_BYTES:
        i += 1
    if i < n and text[i : i + 1] == b"R":
        return num1, num2
    return None


def _find_indirect_ref(text: bytes, key: bytes, take_last: bool) -> Optional[str]:
    """Find an indirect reference such as ``/Root 12 0 R`` and return its
    normalized ``"12 0 R"`` body. ``take_last`` selects the final valid match
    (most recent incremental update); otherwise the first match wins."""
    found: Optional[str] = None
    search_from = 0
    while True:
        rel = text.find(key, search_from)
        if rel == -1:
            break
        after_key = rel + len(key)
        ref = _parse_indirect_ref_after(text, after_key)
        if ref is not None:
            found = f"{ref[0]} {ref[1]} R"
            if not take_last:
                return found
        search_from = after_key
    return found


def _scan_max_object_number(text: bytes) -> Optional[int]:
    """Highest object number among ``N G obj`` definitions in ``text``.

    The accepted shape is exactly ``<digits> <ws+> <digits> <ws+> obj``,
    matching the Rust implementation. Used for xref-stream PDFs that have no
    ``trailer`` keyword.
    """
    max_obj: Optional[int] = None
    search_from = 0
    n = len(text)
    while True:
        rel = text.find(b"obj", search_from)
        if rel == -1:
            break
        obj_end = rel + 3
        j = rel
        obj_num: Optional[int] = None

        # whitespace before "obj" (at least one byte)
        ws1 = j
        while j > 0 and text[j - 1] in _WS_BYTES:
            j -= 1
        if j < ws1:
            # generation digits (at least one)
            gen_end = j
            while j > 0 and 0x30 <= text[j - 1] <= 0x39:
                j -= 1
            if j < gen_end:
                # whitespace before generation (at least one byte)
                ws2 = j
                while j > 0 and text[j - 1] in _WS_BYTES:
                    j -= 1
                if j < ws2:
                    # object number digits (at least one)
                    num_end = j
                    while j > 0 and 0x30 <= text[j - 1] <= 0x39:
                        j -= 1
                    if j < num_end:
                        tok = text[j:num_end]
                        if len(tok) <= 20:
                            val = int(tok)
                            if val <= _U64_MAX:
                                obj_num = val
        if obj_num is not None and (max_obj is None or obj_num > max_obj):
            max_obj = obj_num
        search_from = obj_end
    return max_obj


def parse_pdf_trailer_info(stream: BinaryIO) -> Tuple[int, int, int, Optional[str], Optional[str]]:
    """Scan PDF from tail to find authentic %%EOF, startxref, Size, and trailer dictionary.
    
    Returns:
        (eof_offset, prev_startxref, new_obj_num, root_ref, info_ref)
    """
    stream.seek(0, 2)
    file_size = stream.tell()
    scan_len = min(file_size, 64 * 1024)
    stream.seek(file_size - scan_len)
    tail = stream.read(scan_len)

    eof_idx = tail.rfind(b"%%EOF")
    if eof_idx == -1:
        raise CorruptedDataError("Valid PDF %%EOF marker not found within tail window")

    # Offset immediately following %%EOF and any trailing newlines
    abs_eof_pos = (file_size - scan_len) + eof_idx + 5
    stream.seek(abs_eof_pos)
    trailing_newlines = stream.read(16)
    idx_nl = 0
    while idx_nl < len(trailing_newlines) and trailing_newlines[idx_nl:idx_nl + 1] in (b"\r", b"\n"):
        idx_nl += 1
    eof_offset = abs_eof_pos + idx_nl

    # Text before %%EOF in tail buffer
    text_before_eof = tail[:eof_idx].rstrip()
    sx_idx = text_before_eof.rfind(b"startxref")
    if sx_idx == -1:
        raise CorruptedDataError("PDF startxref marker not found before %%EOF")

    sx_lines = text_before_eof[sx_idx + len(b"startxref"):].strip().split()
    if not sx_lines or not sx_lines[0].isdigit():
        raise CorruptedDataError("Could not parse startxref offset integer")
    prev_startxref = int(sx_lines[0])

    trailer_idx = text_before_eof.rfind(b"trailer")

    # Next free object number. Classic PDFs expose /Size in a `trailer`
    # dictionary, where Size is defined as one past the highest object number
    # in use, so /Size itself is the next free number. xref-stream PDFs
    # (PDF 1.5+) carry their trailer dictionary inside the XRef stream object
    # and have no `trailer` keyword; for those, scan the tail window for
    # `N G obj` definitions and use max(N) + 1. The previous hardcoded 9999
    # fallback could collide with a real object number and silently corrupt
    # the incremental update.
    new_obj_num: Optional[int] = None
    root_ref: Optional[str] = None
    info_ref: Optional[str] = None

    if trailer_idx != -1:
        trailer_str = text_before_eof[trailer_idx:sx_idx]
        new_obj_num = _find_int_after(trailer_str, b"/Size")
        root_ref = _find_indirect_ref(trailer_str, b"/Root", take_last=False)
        info_ref = _find_indirect_ref(trailer_str, b"/Info", take_last=False)

    # No classic trailer dictionary (xref-stream PDF): derive the next object
    # number from the highest `N G obj` definition in the tail window.
    if new_obj_num is None:
        max_obj = _scan_max_object_number(text_before_eof)
        if max_obj is not None:
            new_obj_num = max_obj + 1

    # /Root and /Info may live inside an xref-stream trailer dict (or an older
    # incremental trailer) even when the newest trailer omits them; the last
    # valid reference in the tail is the currently effective one.
    if root_ref is None:
        root_ref = _find_indirect_ref(text_before_eof, b"/Root", take_last=True)
    if info_ref is None:
        info_ref = _find_indirect_ref(text_before_eof, b"/Info", take_last=True)

    if new_obj_num is None:
        raise CorruptedDataError(
            "cannot determine next PDF object number "
            "(no /Size and no 'N G obj' definitions in tail window)"
        )

    # An incremental trailer without /Root breaks the document tree for every
    # conforming reader; refuse instead of writing a damaged carrier (auto
    # strategy falls back to the lossless EOF overlay).
    if root_ref is None:
        raise CorruptedDataError(
            "cannot locate /Root reference in PDF tail; "
            "incremental update would break the document tree"
        )

    return eof_offset, prev_startxref, new_obj_num, root_ref, info_ref


class PdfAdapter(HostAdapter):
    """Adapter for PDF documents supporting stealth Incremental Update streams and EOF fallback."""

    def format_name(self) -> str:
        return "PDF"

    def detect(self, stream: BinaryIO) -> bool:
        start_pos = stream.tell()
        try:
            stream.seek(0)
            prefix = stream.read(5)
            return prefix == PDF_MAGIC
        finally:
            stream.seek(start_pos)

    def supported_strategies(self) -> List[str]:
        return ["incremental", "eof"]

    def choose_auto_strategy(self, stream: BinaryIO, ube_size: int) -> str:
        # Best-effort: try incremental update first
        try:
            parse_pdf_trailer_info(stream)
            return "incremental"
        except Exception:
            return "eof"

    def strategy_capacities(self, stream=None) -> List[StrategyCapacity]:
        incremental = StrategyCapacity(
            "incremental",
            None,
            True,
            "unlimited (file grows)",
            "incremental update ending in %%EOF; requires a parseable trailer",
        )
        if stream is not None:
            start = stream.tell()
            try:
                parse_pdf_trailer_info(stream)
            except Exception:
                incremental.available = False
                incremental.note = (
                    "PDF trailer / %%EOF could not be parsed; auto falls back to eof"
                )
            finally:
                stream.seek(start)
        return [
            incremental,
            StrategyCapacity(
                "eof", None, True, "unlimited (file grows)", "appended after %%EOF"
            ),
        ]

    def calc_prefix_len(self, stream: BinaryIO, ube_size: int) -> int:
        _, _, new_obj_num, _, _ = parse_pdf_trailer_info(stream)
        obj_header = f"\n{new_obj_num} 0 obj\n<< /Type /Metadata /Length {ube_size} >>\nstream\n".encode("latin-1")
        return len(obj_header)

    def inject(
        self,
        host_in: BinaryIO,
        ube_in: BinaryIO,
        out: BinaryIO,
        strategy: str,
    ) -> Tuple[int, int, int, int]:
        if strategy == "eof":
            from strhide.adapters.eof import EofAdapter
            return EofAdapter().inject(host_in, ube_in, out, strategy)

        if strategy != "incremental":
            raise UnsupportedFormatError(f"Strategy '{strategy}' not supported by PDF adapter")

        try:
            eof_offset, prev_sx, new_obj_num, root_ref, info_ref = parse_pdf_trailer_info(host_in)
        except Exception as e:
            raise UnsupportedFormatError(
                f"PDF cannot be incrementally updated ({e}). Please specify --strategy eof."
            )

        ube_in.seek(0, 2)
        ube_size = ube_in.tell()
        ube_in.seek(0)

        # 1. Write host up to eof_offset
        host_in.seek(0)
        remaining = eof_offset
        while remaining > 0:
            buf = host_in.read(min(64 * 1024, remaining))
            out.write(buf)
            remaining -= len(buf)

        inject_offset = out.tell()

        # 2. Construct object header
        obj_header = f"\n{new_obj_num} 0 obj\n<< /Type /Metadata /Length {ube_size} >>\nstream\n".encode("latin-1")
        actual_obj_offset = inject_offset + 1  # skips the leading \n
        out.write(obj_header)

        # 3. Write UBE data stream
        while True:
            chunk = ube_in.read(64 * 1024)
            if not chunk:
                break
            out.write(chunk)

        # 4. End object stream
        out.write(b"\nendstream\nendobj\n")

        # 5. Write incremental xref
        xref_offset = out.tell()
        xref_str = f"xref\n{new_obj_num} 1\n{actual_obj_offset:010d} 00000 n \n".encode("latin-1")
        out.write(xref_str)

        # 6. Write incremental trailer
        trailer_lines = [f"trailer\n<<\n/Size {new_obj_num + 1}\n"]
        if root_ref:
            trailer_lines.append(f"/Root {root_ref}\n")
        if info_ref:
            trailer_lines.append(f"/Info {info_ref}\n")
        trailer_lines.append(f"/Prev {prev_sx}\n>>\nstartxref\n{xref_offset}\n%%EOF\n")
        out.write("".join(trailer_lines).encode("latin-1"))

        inject_size = out.tell() - inject_offset

        # 7. Preserve any bytes the original host carried after its final
        # %%EOF (non-standard "dirty tail"). Dropping them would silently
        # damage the carrier and break the 100% bit-exact restore guarantee,
        # so they are copied verbatim after the new %%EOF.
        host_in.seek(eof_offset)
        shutil.copyfileobj(host_in, out)

        return inject_offset, inject_size, 0, 0

    def locate(
        self,
        stego_in: BinaryIO,
        expected_trailer_magic: Optional[bytes] = None,
    ) -> Optional[Tuple[int, int, str]]:
        stego_in.seek(0)
        if stego_in.read(5) != PDF_MAGIC:
            return None

        # 1. Check incremental update object stream first
        stego_in.seek(0, 2)
        total_size = stego_in.tell()
        scan_len = min(total_size, 128 * 1024)
        stego_in.seek(total_size - scan_len)
        tail = stego_in.read(scan_len)

        eof_idx = tail.rfind(b"%%EOF")
        if eof_idx != -1:
            endstream_idx = tail.rfind(b"endstream", 0, eof_idx)
            if endstream_idx != -1:
                # Trailer is the last 24 bytes of stream content right before endstream
                stream_content_tail = tail[:endstream_idx].rstrip(b"\r\n")
                stream_end_in_tail = len(stream_content_tail)
                if stream_end_in_tail >= 24:
                    trailer_bytes = stream_content_tail[stream_end_in_tail - 24:stream_end_in_tail]
                    try:
                        from strhide.core.envelope import EnvelopeTrailer
                        trailer = EnvelopeTrailer.unpack(trailer_bytes, expected_magic=expected_trailer_magic)
                        abs_stream_end = (total_size - scan_len) + stream_end_in_tail
                        if (
                            trailer.ube_offset + trailer.ube_total_size == abs_stream_end
                            and trailer.ube_offset >= 0
                        ):
                            # Verify stream keyword precedes ube_offset
                            if trailer.ube_offset >= 8:
                                stego_in.seek(trailer.ube_offset - 8)
                                prefix = stego_in.read(8)
                                if (
                                    prefix.endswith(b"stream\r\n")
                                    or prefix.endswith(b"stream\n")
                                    or prefix.endswith(b"stream")
                                ):
                                    return trailer.ube_offset, trailer.ube_total_size, "incremental"
                    except Exception:
                        pass

        # 2. Fallback to EOF trailer (for backwards compatibility with legacy PDF stego)
        trailer = read_trailer_from_tail(stego_in, expected_magic=expected_trailer_magic)
        if trailer:
            return trailer.ube_offset, trailer.ube_total_size, "eof"

        return None

    def strip(
        self,
        stego_in: BinaryIO,
        out: BinaryIO,
        header: EnvelopeHeader,
    ) -> None:
        # The incremental block is inserted at inject_offset; any original
        # trailing bytes follow it. Copying [0, inject_offset), skipping
        # inject_size, then copying the remainder restores the original PDF
        # bit-exactly (including a preserved dirty tail). Legacy eof-mode
        # carriers have inject_offset == orig_host_size, so the same slicing
        # reproduces the old truncation behaviour.
        stego_in.seek(0)
        remaining = header.inject_offset
        while remaining > 0:
            chunk = stego_in.read(min(64 * 1024, remaining))
            if not chunk:
                break
            out.write(chunk)
            remaining -= len(chunk)

        stego_in.seek(header.inject_offset + header.inject_size)
        shutil.copyfileobj(stego_in, out)

    def verify_structure(self, stego_in: BinaryIO) -> Tuple[bool, str]:
        stego_in.seek(0)
        if stego_in.read(5) != PDF_MAGIC:
            return False, "Not a valid PDF file"

        stego_in.seek(0, 2)
        total_size = stego_in.tell()
        scan_len = min(total_size, 4096)
        stego_in.seek(total_size - scan_len)
        tail = stego_in.read(scan_len)

        eof_idx = tail.rfind(b"%%EOF")
        if eof_idx == -1:
            return False, "PDF missing %%EOF marker"

        trailing_clean = len(tail[eof_idx + 5:].strip(b"\r\n "))
        if trailing_clean == 0:
            return True, "PDF structure valid (clean %%EOF at EOF, 0 trailing garbage bytes)"
        else:
            return True, f"PDF structure verified (%%EOF found, {trailing_clean} trailing bytes)"
