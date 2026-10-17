"""PDF format adapter for strhide with compliant Incremental Update object stream hiding."""

from __future__ import annotations

import re
from typing import BinaryIO, List, Optional, Tuple

from strhide.adapters.base import HostAdapter
from strhide.core.envelope import EnvelopeHeader, read_trailer_from_tail
from strhide.errors import CorruptedDataError, UnsupportedFormatError

PDF_MAGIC = b"%PDF-"


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
    size_val = 9999
    root_ref = None
    info_ref = None

    if trailer_idx != -1:
        trailer_str = text_before_eof[trailer_idx:sx_idx].decode("latin-1", errors="ignore")
        size_m = re.search(r"/Size\s+(\d+)", trailer_str)
        if size_m:
            size_val = int(size_m.group(1))
        root_m = re.search(r"/Root\s+(\d+\s+\d+\s+R)", trailer_str)
        if root_m:
            root_ref = root_m.group(1)
        info_m = re.search(r"/Info\s+(\d+\s+\d+\s+R)", trailer_str)
        if info_m:
            info_ref = info_m.group(1)

    return eof_offset, prev_startxref, size_val, root_ref, info_ref


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
        # Both incremental and eof append data at or past orig_host_size.
        # Copying exactly orig_host_size bytes completely and losslessly restores the original PDF!
        stego_in.seek(0)
        remaining = header.orig_host_size
        while remaining > 0:
            chunk = stego_in.read(min(64 * 1024, remaining))
            if not chunk:
                break
            out.write(chunk)
            remaining -= len(chunk)

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
