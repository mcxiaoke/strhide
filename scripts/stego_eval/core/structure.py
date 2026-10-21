import os
import struct
import math
from typing import Dict, Any, List, Optional
from pathlib import Path


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    total = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def analyze_png_structure(filepath: Path) -> Dict[str, Any]:
    """Parse PNG chunks, check for trailing bytes after IEND, and identify suspicious chunks."""
    result = {
        "format": "PNG",
        "chunks": [],
        "suspicious_chunks": [],
        "trailing_bytes_len": 0,
        "trailing_entropy": 0.0,
        "has_trailing_data": False,
        "warnings": [],
    }

    with open(filepath, "rb") as f:
        data = f.read()

    # PNG magic: \x89PNG\r\n\x1a\n
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        result["warnings"].append("Not a valid PNG signature")
        return result

    standard_chunks = {
        b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP",
        b"sBIT", b"sRGB", b"tEXt", b"zTXt", b"iTXt", b"bKGD", b"hIST", b"pHYs",
        b"sPLT", b"tIME", b"eXIf", b"acTL", b"fcTL", b"fdAT"
    }

    offset = 8
    file_len = len(data)
    iend_found = False
    iend_end_offset = file_len

    while offset + 8 <= file_len:
        try:
            length = struct.unpack(">I", data[offset:offset+4])[0]
            chunk_type = data[offset+4:offset+8]
            result["chunks"].append(chunk_type.decode("latin1", errors="replace"))

            if chunk_type not in standard_chunks:
                result["suspicious_chunks"].append(chunk_type.decode("latin1", errors="replace"))

            # Next chunk is at offset + 4 (len) + 4 (type) + length (data) + 4 (crc)
            chunk_total_len = 12 + length
            offset += chunk_total_len

            if chunk_type == b"IEND":
                iend_found = True
                iend_end_offset = offset
                break
        except Exception as e:
            result["warnings"].append(f"PNG chunk parse error: {e}")
            break

    if iend_found and iend_end_offset < file_len:
        trailing_data = data[iend_end_offset:]
        result["trailing_bytes_len"] = len(trailing_data)
        result["has_trailing_data"] = len(trailing_data) > 0
        result["trailing_entropy"] = calculate_entropy(trailing_data)
        result["warnings"].append(
            f"Found {len(trailing_data)} trailing bytes after IEND chunk (entropy: {result['trailing_entropy']:.2f})"
        )

    return result


def analyze_jpeg_structure(filepath: Path) -> Dict[str, Any]:
    """Parse JPEG markers, check for trailing bytes after EOI, comments, and APP markers."""
    result = {
        "format": "JPEG",
        "markers": [],
        "comments": [],
        "trailing_bytes_len": 0,
        "trailing_entropy": 0.0,
        "has_trailing_data": False,
        "warnings": [],
    }

    with open(filepath, "rb") as f:
        data = f.read()

    if not data.startswith(b"\xff\xd8"):
        result["warnings"].append("Not a valid JPEG signature (missing SOI)")
        return result

    # Find EOI (\xff\xd9)
    # Search for the last \xff\xd9 in file
    eoi_pos = data.rfind(b"\xff\xd9")
    if eoi_pos != -1:
        trailing_len = len(data) - (eoi_pos + 2)
        if trailing_len > 0:
            trailing_data = data[eoi_pos + 2:]
            result["trailing_bytes_len"] = trailing_len
            result["has_trailing_data"] = True
            result["trailing_entropy"] = calculate_entropy(trailing_data)
            result["warnings"].append(
                f"Found {trailing_len} trailing bytes after JPEG EOI marker (entropy: {result['trailing_entropy']:.2f})"
            )

    # Scan basic markers
    offset = 2
    file_len = len(data)
    while offset < file_len - 1:
        if data[offset] == 0xFF:
            marker = data[offset+1]
            if marker in (0xD8, 0xD9):  # SOI, EOI
                offset += 2
                continue
            if marker == 0x00:  # Byte stuffing in entropy data
                offset += 2
                continue
            if marker == 0xFE:  # COM (Comment)
                if offset + 4 <= file_len:
                    seg_len = struct.unpack(">H", data[offset+2:offset+4])[0]
                    com_data = data[offset+4:offset+2+seg_len]
                    result["comments"].append(com_data.decode("latin1", errors="replace")[:100])
                    result["markers"].append("COM")
                    offset += 2 + seg_len
                    continue
            if 0xE0 <= marker <= 0xEF:  # APP0 - APP15
                if offset + 4 <= file_len:
                    seg_len = struct.unpack(">H", data[offset+2:offset+4])[0]
                    result["markers"].append(f"APP{marker-0xE0}")
                    offset += 2 + seg_len
                    continue
            if marker == 0xDA:  # SOS (Start of Scan) - rest is entropy coded
                result["markers"].append("SOS")
                break
            # Other variable-length markers
            if offset + 4 <= file_len:
                seg_len = struct.unpack(">H", data[offset+2:offset+4])[0]
                result["markers"].append(f"0x{marker:02X}")
                offset += 2 + seg_len
                continue
        offset += 1

    return result


def analyze_bmp_structure(filepath: Path) -> Dict[str, Any]:
    """Parse BMP header, check filesize consistency and trailing data."""
    result = {
        "format": "BMP",
        "header_filesize": 0,
        "actual_filesize": 0,
        "trailing_bytes_len": 0,
        "has_trailing_data": False,
        "warnings": [],
    }

    with open(filepath, "rb") as f:
        data = f.read()

    actual_size = len(data)
    result["actual_filesize"] = actual_size

    if not data.startswith(b"BM"):
        result["warnings"].append("Not a valid BMP signature")
        return result

    if len(data) >= 14:
        header_size = struct.unpack("<I", data[2:6])[0]
        result["header_filesize"] = header_size
        if actual_size > header_size:
            diff = actual_size - header_size
            result["trailing_bytes_len"] = diff
            result["has_trailing_data"] = True
            result["warnings"].append(f"BMP has {diff} trailing bytes beyond header declared size")

    return result


def analyze_file_structure(filepath: Path) -> Dict[str, Any]:
    """Top-level container and structural analysis."""
    p = Path(filepath)
    ext = p.suffix.lower()
    total_size = p.stat().st_size

    with open(p, "rb") as f:
        head = f.read(min(total_size, 65536))
    full_entropy = calculate_entropy(head)

    res = {
        "file_name": p.name,
        "file_size": total_size,
        "file_entropy": full_entropy,
        "has_structural_anomaly": False,
        "anomaly_score": 0.0,
        "details": {},
        "warnings": [],
    }

    if ext in (".png",):
        png_info = analyze_png_structure(p)
        res["details"] = png_info
        res["warnings"].extend(png_info["warnings"])
        if png_info["has_trailing_data"]:
            res["has_structural_anomaly"] = True
            # Higher trailing size or high entropy raises anomaly score
            res["anomaly_score"] = min(100.0, 50.0 + min(50.0, png_info["trailing_bytes_len"] / 100))
        if png_info["suspicious_chunks"]:
            res["has_structural_anomaly"] = True
            res["anomaly_score"] = max(res["anomaly_score"], 60.0)

    elif ext in (".jpg", ".jpeg"):
        jpg_info = analyze_jpeg_structure(p)
        res["details"] = jpg_info
        res["warnings"].extend(jpg_info["warnings"])
        if jpg_info["has_trailing_data"]:
            res["has_structural_anomaly"] = True
            res["anomaly_score"] = min(100.0, 50.0 + min(50.0, jpg_info["trailing_bytes_len"] / 100))
        if len(jpg_info["comments"]) > 0:
            res["warnings"].append(f"JPEG contains {len(jpg_info['comments'])} comment segments")

    elif ext in (".bmp",):
        bmp_info = analyze_bmp_structure(p)
        res["details"] = bmp_info
        res["warnings"].extend(bmp_info["warnings"])
        if bmp_info["has_trailing_data"]:
            res["has_structural_anomaly"] = True
            res["anomaly_score"] = min(100.0, 50.0 + min(50.0, bmp_info["trailing_bytes_len"] / 100))

    return res
