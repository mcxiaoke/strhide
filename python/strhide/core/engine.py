"""Core engine orchestrating write, read, verify, inspect, and remove operations."""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import struct
import sys
import time
import unicodedata
import zlib
from typing import Any, BinaryIO, Dict, Optional, Tuple

from strhide.core.crypto import (
    compress_stream,
    compute_file_sha256,
    compute_stream_sha256,
    decompress_stream,
    decrypt_metadata,
    decrypt_stream_from_chunks,
    derive_keys,
    derive_stealth_magics,
    encrypt_metadata,
    encrypt_stream_to_chunks,
)
from strhide.core.envelope import (
    FLAG_COMPRESSED,
    FLAG_ENCRYPTED,
    FLAG_HAS_HINT,
    FLAG_IS_FILE,
    FLAG_STEALTH,
    HEADER_STRUCT,
    STANDARD_HEADER_MAGIC,
    STANDARD_TRAILER_MAGIC,
    EnvelopeHeader,
    EnvelopeTrailer,
)
from strhide.core.rejection import run_all_rejection_checks
from strhide.core.router import find_adapter, id_to_strategy, strategy_to_id
from strhide.errors import (
    CorruptedDataError,
    PasswordError,
    RejectionError,
    RestoreMismatchError,
    StrHideError,
)


def write_carrier(
    carrier_path: str,
    data_bytes: Optional[bytes] = None,
    data_file: Optional[str] = None,
    data_text: Optional[str] = None,
    data_text_file: Optional[str] = None,
    data_stdin: bool = False,
    output_path: Optional[str] = None,
    password: Optional[str] = None,
    password_hint: Optional[str] = None,
    strategy: str = "auto",
    stealth: bool = False,
    preserve_time: bool = True,
    backup: bool = True,
) -> Dict[str, Any]:
    """Hide data inside carrier file with 100% loss-free reversibility."""
    if not os.path.exists(carrier_path):
        raise FileNotFoundError(f"Carrier file '{carrier_path}' not found")

    if password_hint and stealth:
        raise StrHideError("Password hint is not supported in --stealth mode (stealth mode requires password to locate envelope).")

    hint_bytes = b""
    if password_hint:
        hint_clean = unicodedata.normalize("NFC", password_hint.strip())
        hint_bytes = hint_clean.encode("utf-8")
        if len(hint_bytes) > 1024:
            raise ValueError("Password hint cannot exceed 1024 bytes")

    target_path = output_path or carrier_path

    # 1. Run security rejection checks
    with open(carrier_path, "rb") as cf:
        rejection_reason = run_all_rejection_checks(cf, carrier_path)
    if rejection_reason:
        raise RejectionError(rejection_reason)

    # 2. Capture carrier metadata (stats, permissions, timestamps, full SHA-256)
    st = os.stat(carrier_path)
    orig_host_size = st.st_size
    orig_host_mtime = st.st_mtime
    orig_host_atime = st.st_atime
    orig_mode = st.st_mode
    orig_host_sha256 = compute_file_sha256(carrier_path)

    # 3. Detect adapter & choose strategy
    with open(carrier_path, "rb") as cf:
        adapter = find_adapter(cf)
        if strategy == "auto":
            selected_strategy = adapter.choose_auto_strategy(cf, 0)
        else:
            if strategy not in adapter.supported_strategies():
                raise StrHideError(f"Strategy '{strategy}' not supported by adapter '{adapter.format_name()}'")
            selected_strategy = strategy

        # Check if already has an envelope
        existing = adapter.locate(cf)
        if existing is not None:
            raise StrHideError("Carrier already contains hidden data. Use remove first or specify another file.")

    # 4. Prepare data payload stream
    if data_stdin:
        raw_bytes = sys.stdin.buffer.read()
        filename = ""
        raw_size = len(raw_bytes)
        raw_sha256 = compute_stream_sha256(io.BytesIO(raw_bytes)).hex()
        is_file = False
        payload_source_stream = io.BytesIO(raw_bytes)
    elif data_file:
        if not os.path.exists(data_file):
            raise FileNotFoundError(f"Data file '{data_file}' not found")
        filename = os.path.basename(data_file)
        raw_size = os.path.getsize(data_file)
        raw_sha256 = compute_file_sha256(data_file).hex()
        is_file = True
        payload_source_stream = open(data_file, "rb")
    elif data_text_file:
        if not os.path.exists(data_text_file):
            raise FileNotFoundError(f"Text file '{data_text_file}' not found")
        with open(data_text_file, "r", encoding="utf-8") as tf:
            content = tf.read()
        raw_bytes = unicodedata.normalize("NFC", content).encode("utf-8")
        filename = ""
        raw_size = len(raw_bytes)
        raw_sha256 = compute_stream_sha256(io.BytesIO(raw_bytes)).hex()
        is_file = False
        payload_source_stream = io.BytesIO(raw_bytes)
    elif data_text is not None:
        raw_bytes = unicodedata.normalize("NFC", data_text).encode("utf-8")
        filename = ""
        raw_size = len(raw_bytes)
        raw_sha256 = compute_stream_sha256(io.BytesIO(raw_bytes)).hex()
        is_file = False
        payload_source_stream = io.BytesIO(raw_bytes)
    elif data_bytes is not None:
        filename = "payload.bin"
        raw_size = len(data_bytes)
        raw_sha256 = compute_stream_sha256(io.BytesIO(data_bytes)).hex()
        is_file = True
        payload_source_stream = io.BytesIO(data_bytes)
    else:
        raise ValueError("Must provide either data_file, data_text, data_text_file, data_bytes, or data_stdin=True")

    tmp_ube = io.BytesIO()

    try:
        # 5. Compress data with Deflate
        compressed_stream = io.BytesIO()
        raw_len, comp_len = compress_stream(payload_source_stream, compressed_stream)
        compressed_stream.seek(0)

        # Decide whether to keep compression (skip if negligible gain)
        if comp_len < raw_len * 0.98:
            is_compressed = True
            to_encrypt_stream = compressed_stream
        else:
            is_compressed = False
            payload_source_stream.seek(0)
            to_encrypt_stream = payload_source_stream

        # 6. Keys and Magics
        is_encrypted = bool(password)
        flags = 0
        if is_encrypted:
            flags |= FLAG_ENCRYPTED
        if is_compressed:
            flags |= FLAG_COMPRESSED
        if is_file:
            flags |= FLAG_IS_FILE
        if hint_bytes:
            flags |= FLAG_HAS_HINT
        if stealth and password:
            flags |= FLAG_STEALTH
            salt = os.urandom(16)
            base_nonce = os.urandom(12)
            payload_key, meta_key = derive_keys(password, salt)
            header_magic, trailer_magic = derive_stealth_magics(password)
        elif is_encrypted:
            salt = os.urandom(16)
            base_nonce = os.urandom(12)
            payload_key, meta_key = derive_keys(password, salt)
            header_magic = STANDARD_HEADER_MAGIC
            trailer_magic = STANDARD_TRAILER_MAGIC
        else:
            salt = b"\x00" * 16
            base_nonce = b"\x00" * 12
            payload_key = b""
            meta_key = b""
            header_magic = STANDARD_HEADER_MAGIC
            trailer_magic = STANDARD_TRAILER_MAGIC

        # 7. Metadata Block
        meta_dict = {
            "filename": filename,
            "raw_size": raw_size,
            "raw_sha256": raw_sha256,
            "created_at": int(time.time()),
        }
        meta_raw = json.dumps(meta_dict, separators=(",", ":")).encode("utf-8")

        # Estimate total UBE size before finalizing header & AAD
        to_encrypt_len = comp_len if is_compressed else raw_len
        est_meta_len = len(meta_raw) + (16 if is_encrypted else 0)
        est_payload_len = to_encrypt_len + ((to_encrypt_len + 2097152 - 1) // 2097152 * 16 if is_encrypted else 0)
        est_ube_size = HEADER_STRUCT.size + len(hint_bytes) + est_meta_len + est_payload_len + 24

        if strategy == "auto":
            with open(carrier_path, "rb") as cf:
                selected_strategy = adapter.choose_auto_strategy(cf, est_ube_size)

        # 8. Create and populate Header structure
        strat_id = strategy_to_id(selected_strategy)
        header = EnvelopeHeader(
            magic_header=header_magic,
            flags=flags,
            strategy_id=strat_id,
            salt=salt,
            base_nonce=base_nonce,
            orig_host_size=orig_host_size,
            orig_host_sha256=orig_host_sha256,
            hint_len=len(hint_bytes),
        )

        # Encrypt metadata
        fixed_header_aad = header.get_aad()
        if is_encrypted:
            meta_encrypted = encrypt_metadata(meta_raw, meta_key, base_nonce, fixed_header_aad)
            header.meta_len = len(meta_encrypted)
            meta_block = meta_encrypted
        else:
            header.meta_len = len(meta_raw)
            meta_block = meta_raw

        # Encrypt / write payload stream
        payload_cipher_stream = io.BytesIO()
        if is_encrypted:
            payload_written = encrypt_stream_to_chunks(
                to_encrypt_stream, payload_cipher_stream, payload_key, base_nonce, fixed_header_aad
            )
        else:
            shutil.copyfileobj(to_encrypt_stream, payload_cipher_stream)
            payload_written = payload_cipher_stream.tell()

        payload_cipher_stream.seek(0)

        # Compute preliminary UBE size
        # Header (112B) + Hint + Meta + Payload + Trailer (24B)
        ube_total_size = HEADER_STRUCT.size + len(hint_bytes) + header.meta_len + payload_written + 24

        # Check payload size inflation warning (> 50% of carrier original size)
        warning_msg = None
        if orig_host_size > 0 and ube_total_size > (orig_host_size * 0.5):
            ratio_pct = (ube_total_size / orig_host_size) * 100.0
            warning_msg = (
                f"Hidden data envelope size ({ube_total_size:,} bytes) exceeds 50.0% of carrier "
                f"file size ({orig_host_size:,} bytes, {ratio_pct:.1f}%). "
                f"Noticeable file size inflation may compromise stealthiness!"
            )

        # Assemble full UBE
        tmp_ube.write(header.pack())
        if hint_bytes:
            tmp_ube.write(hint_bytes)
        tmp_ube.write(meta_block)
        shutil.copyfileobj(payload_cipher_stream, tmp_ube)

        # Place placeholder for Trailer (24B)
        dummy_trailer = EnvelopeTrailer.create(0, ube_total_size, trailer_magic=trailer_magic)
        tmp_ube.write(dummy_trailer.pack())

    finally:
        payload_source_stream.close()

    # 9. Inject into temporary target file
    tmp_target = target_path + ".strhide.tmp"
    with open(carrier_path, "rb") as host_in, open(tmp_target, "wb") as out_file:
        tmp_ube.seek(0)
        inject_offset, inject_size, patch_offset, orig_patch_val = adapter.inject(
            host_in, tmp_ube, out_file, selected_strategy
        )

    # 10. Update real ube_offset in Header and Trailer
    # Injected file now has UBE starting at inject_offset (or wrapper offset)
    # For PNG: UBE starts at inject_offset + 8
    # For MP4 uuid: UBE starts at inject_offset + 32
    # For ZIP: UBE starts at inject_offset
    # For EOF: UBE starts at inject_offset
    actual_ube_offset = inject_offset
    if adapter.format_name() == "PNG" and selected_strategy == "chunk":
        actual_ube_offset = inject_offset + 8
    elif adapter.format_name() == "MP4" and selected_strategy == "box_uuid":
        actual_ube_offset = inject_offset + adapter.calc_prefix_len(ube_total_size)
    elif adapter.format_name() == "JPEG" and selected_strategy == "app_segment":
        actual_ube_offset = inject_offset + 4
    elif adapter.format_name() == "PDF" and selected_strategy == "incremental":
        with open(carrier_path, "rb") as cf:
            actual_ube_offset = inject_offset + adapter.calc_prefix_len(cf, ube_total_size)

    # Patch final Header & Trailer directly in tmp_target
    header.inject_offset = inject_offset
    header.inject_size = inject_size
    header.patch_offset = patch_offset
    header.orig_patch_val = orig_patch_val

    final_trailer = EnvelopeTrailer.create(actual_ube_offset, ube_total_size, trailer_magic=trailer_magic)

    with open(tmp_target, "r+b") as f:
        # Patch header
        f.seek(actual_ube_offset)
        f.write(header.pack())
        # Patch trailer at end of UBE
        f.seek(actual_ube_offset + ube_total_size - 24)
        f.write(final_trailer.pack())

        # For PNG chunk: recalculate chunk CRC over (chunk_type + patched_ube_data)
        if adapter.format_name() == "PNG" and selected_strategy == "chunk":
            f.seek(actual_ube_offset - 4)
            chunk_type_and_data = f.read(4 + ube_total_size)
            new_crc = zlib.crc32(chunk_type_and_data) & 0xFFFFFFFF
            f.seek(actual_ube_offset + ube_total_size)
            f.write(struct.pack(">I", new_crc))

    # 11. Self-verification check
    with open(tmp_target, "rb") as f:
        loc = adapter.locate(f, expected_trailer_magic=trailer_magic if stealth else None)

    if loc is None:
        if os.path.exists(tmp_target):
            try:
                os.remove(tmp_target)
            except Exception:
                pass
        raise StrHideError("Self-verification failed: could not locate injected envelope")

    # 12. Inplace backup (if applicable) & Atomic commit & preserve attributes
    is_inplace = (os.path.abspath(target_path) == os.path.abspath(carrier_path))
    backup_file = None
    if is_inplace and backup:
        backup_file = carrier_path + ".bak"
        shutil.copy2(carrier_path, backup_file)

    os.replace(tmp_target, target_path)

    try:
        os.chmod(target_path, orig_mode)
        if preserve_time:
            os.utime(target_path, (orig_host_atime, orig_host_mtime))
    except Exception:
        pass

    strategy_note = None
    if adapter.format_name() == "JPEG":
        if selected_strategy == "app_segment":
            strategy_note = "Embedded into compliant JPEG COM segment before SOS (clean EOI at EOF, 0 trailing bytes)."
        elif selected_strategy == "eof" and strategy == "auto":
            strategy_note = f"Payload ({ube_total_size:,} bytes) exceeded JPEG single segment limit (64KB); automatically fell back to EOF overlay."
        elif selected_strategy == "eof":
            strategy_note = "Appended after JPEG EOI marker (EOF overlay)."
    elif adapter.format_name() == "PNG":
        if selected_strategy == "chunk":
            strategy_note = "Embedded into compliant PNG private ancillary chunk 'prIv' before IEND (0 trailing bytes)."
        elif selected_strategy == "eof" and strategy == "auto":
            strategy_note = f"Payload ({ube_total_size:,} bytes) exceeded PNG chunk limit (2GB); automatically fell back to EOF overlay."
        elif selected_strategy == "eof":
            strategy_note = "Appended after PNG IEND (EOF overlay)."
    elif adapter.format_name() == "PDF":
        if selected_strategy == "incremental":
            strategy_note = "Embedded into compliant PDF Incremental Update stream ending with %%EOF (0 trailing garbage bytes)."
        elif selected_strategy == "eof" and strategy == "auto":
            strategy_note = "PDF trailer could not be incrementally parsed; automatically fell back to EOF overlay."
        elif selected_strategy == "eof":
            strategy_note = "Appended after PDF %%EOF (EOF overlay)."
    elif adapter.format_name() == "MP4":
        if selected_strategy == "box_uuid":
            strategy_note = "Embedded into compliant ISO BMFF 64-bit uuid Box (preserves media frame offsets)."
        elif selected_strategy == "eof":
            strategy_note = "Appended after MP4 EOF (EOF overlay)."
    elif adapter.format_name() == "ZIP":
        if selected_strategy == "pre_cd_inject":
            strategy_note = "Embedded before Central Directory with adjusted EOCD offset (all archive entries intact)."
        elif selected_strategy == "eof" and strategy == "auto":
            strategy_note = "ZIP Central Directory could not be safely adjusted; automatically fell back to EOF overlay."
        elif selected_strategy == "eof":
            strategy_note = "Appended after ZIP EOCD (EOF overlay)."
    elif adapter.format_name() == "PE":
        if selected_strategy == "pe_overlay":
            strategy_note = "Embedded into Windows PE image overlay (executable code and PE sections remain 100% intact)."
        elif selected_strategy == "eof":
            strategy_note = "Appended after PE executable EOF (EOF overlay)."


    return {
        "status": "success",
        "carrier": target_path,
        "format": adapter.format_name(),
        "strategy": selected_strategy,
        "strategy_note": strategy_note,
        "raw_size": raw_size,
        "ube_size": ube_total_size,
        "is_encrypted": is_encrypted,
        "is_stealth": stealth,
        "password_hint": password_hint if password_hint else None,
        "backup_file": backup_file,
        "warning": warning_msg,
    }


def read_carrier(
    carrier_path: str,
    output_path: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """Read and extract hidden data from carrier."""
    if not os.path.exists(carrier_path):
        raise FileNotFoundError(f"Carrier file '{carrier_path}' not found")

    with open(carrier_path, "rb") as f:
        adapter = find_adapter(f)
        loc = adapter.locate(f)
        if loc is None and password:
            _, trailer_magic = derive_stealth_magics(password)
            loc = adapter.locate(f, expected_trailer_magic=trailer_magic)

        if loc is None:
            raise StrHideError(f"No hidden strhide data found in '{carrier_path}'")

        ube_offset, ube_total_size, strategy_name = loc

        # Read fixed header
        f.seek(ube_offset)
        header_bytes = f.read(HEADER_STRUCT.size)
        header = EnvelopeHeader.unpack(header_bytes)

        # Read password hint if present
        password_hint = None
        if header.hint_len > 0:
            password_hint = f.read(header.hint_len).decode("utf-8", errors="replace")

        # Derive keys
        if header.is_encrypted:
            if not password:
                hint_str = f" Hint: '{password_hint}'" if password_hint else ""
                raise PasswordError(f"File is encrypted. Password required.{hint_str}")
            payload_key, meta_key = derive_keys(password, header.salt)
        else:
            payload_key = b""
            meta_key = b""

        # Read & decrypt metadata
        meta_raw_bytes = f.read(header.meta_len)
        fixed_header_aad = header.get_aad()
        if header.is_encrypted:
            meta_json_bytes = decrypt_metadata(meta_raw_bytes, meta_key, header.base_nonce, fixed_header_aad)
        else:
            meta_json_bytes = meta_raw_bytes

        meta_dict = json.loads(meta_json_bytes.decode("utf-8"))

        # Read payload stream
        payload_bytes_len = ube_total_size - HEADER_STRUCT.size - header.hint_len - header.meta_len - 24
        payload_decrypted_stream = io.BytesIO()

        if header.is_encrypted:
            decrypt_stream_from_chunks(
                f, payload_decrypted_stream, payload_key, header.base_nonce, fixed_header_aad, payload_bytes_len
            )
        else:
            remaining = payload_bytes_len
            while remaining > 0:
                chunk = f.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                payload_decrypted_stream.write(chunk)
                remaining -= len(chunk)

        payload_decrypted_stream.seek(0)

        # Decompress if needed
        final_stream = io.BytesIO()
        if header.is_compressed:
            decompress_stream(payload_decrypted_stream, final_stream, payload_decrypted_stream.getbuffer().nbytes)
        else:
            shutil.copyfileobj(payload_decrypted_stream, final_stream)

        final_stream.seek(0)
        extracted_bytes = final_stream.read()

        # Verify envelope trailer & CRC32 integrity
        f.seek(ube_offset + ube_total_size - 24)
        trailer_bytes = f.read(24)
        if len(trailer_bytes) == 24:
            expected_trailer_magic = None
            if header.is_stealth and password:
                _, expected_trailer_magic = derive_stealth_magics(password)
            trailer = EnvelopeTrailer.unpack(trailer_bytes, expected_magic=expected_trailer_magic)
            if trailer.ube_offset != ube_offset or trailer.ube_total_size != ube_total_size:
                raise CorruptedDataError("Envelope trailer boundary parameters mismatch")

        # Check raw SHA-256
        actual_sha256 = compute_stream_sha256(io.BytesIO(extracted_bytes)).hex()
        expected_sha256 = meta_dict.get("raw_sha256", "")
        if expected_sha256 and actual_sha256 != expected_sha256:
            raise CorruptedDataError(f"Extracted payload SHA-256 mismatch: {actual_sha256} != {expected_sha256}")

    # Output result
    out_file_written = None
    if output_path:
        if os.path.isdir(output_path):
            filename = meta_dict.get("filename") or "extracted.bin"
            # Sanitize filename against path traversal
            filename = os.path.basename(filename)
            out_target = os.path.join(output_path, filename)
        else:
            out_target = output_path
        with open(out_target, "wb") as out_f:
            out_f.write(extracted_bytes)
        out_file_written = out_target

    return {
        "status": "success",
        "filename": meta_dict.get("filename", ""),
        "raw_size": meta_dict.get("raw_size", len(extracted_bytes)),
        "data": extracted_bytes,
        "written_file": out_file_written,
        "is_file": header.is_file,
        "password_hint": password_hint,
    }


def remove_carrier(
    carrier_path: str,
    output_path: Optional[str] = None,
    password: Optional[str] = None,
    backup: bool = True,
) -> Dict[str, Any]:
    """100% loss-free reverse stripping of hidden data, strictly verified against orig_host_sha256."""
    if not os.path.exists(carrier_path):
        raise FileNotFoundError(f"Carrier file '{carrier_path}' not found")

    target_path = output_path or carrier_path
    st = os.stat(carrier_path)
    orig_mode = st.st_mode
    orig_mtime = st.st_mtime
    orig_atime = st.st_atime

    with open(carrier_path, "rb") as cf:
        adapter = find_adapter(cf)
        loc = adapter.locate(cf)
        if loc is None and password:
            _, trailer_magic = derive_stealth_magics(password)
            loc = adapter.locate(cf, expected_trailer_magic=trailer_magic)

        if loc is None:
            raise StrHideError(f"No hidden data found in '{carrier_path}'")

        ube_offset, ube_total_size, _ = loc
        cf.seek(ube_offset)
        header = EnvelopeHeader.unpack(cf.read(HEADER_STRUCT.size))

        # Perform strip into temporary file
        tmp_target = target_path + ".strhide.restoring.tmp"
        with open(tmp_target, "wb") as out_f:
            adapter.strip(cf, out_f, header)

    # Calculate restored file SHA-256 and size
    restored_size = os.path.getsize(tmp_target)
    restored_sha256 = compute_file_sha256(tmp_target)

    if restored_size != header.orig_host_size or restored_sha256 != header.orig_host_sha256:
        if os.path.exists(tmp_target):
            os.remove(tmp_target)
        raise RestoreMismatchError(
            f"100% restore verification failed!\n"
            f"Restored size: {restored_size} (expected {header.orig_host_size})\n"
            f"Restored SHA256: {restored_sha256.hex()}\n"
            f"Expected SHA256: {header.orig_host_sha256.hex()}"
        )

    # Inplace backup (if applicable) & Atomic commit & preserve attributes
    is_inplace = (os.path.abspath(target_path) == os.path.abspath(carrier_path))
    backup_file = None
    if is_inplace and backup:
        backup_file = carrier_path + ".bak"
        shutil.copy2(carrier_path, backup_file)

    os.replace(tmp_target, target_path)

    try:
        os.chmod(target_path, orig_mode)
        os.utime(target_path, (orig_atime, orig_mtime))
    except Exception:
        pass

    return {
        "status": "success",
        "carrier": target_path,
        "restored_size": restored_size,
        "restored_sha256": restored_sha256.hex(),
        "verified_identical": True,
        "backup_file": backup_file,
    }


def inspect_carrier(carrier_path: str, password: Optional[str] = None) -> Dict[str, Any]:
    """Inspect carrier structure and embedded envelope details without extracting."""
    if not os.path.exists(carrier_path):
        raise FileNotFoundError(f"Carrier file '{carrier_path}' not found")

    with open(carrier_path, "rb") as cf:
        adapter = find_adapter(cf)
        loc = adapter.locate(cf)
        if loc is None and password:
            _, trailer_magic = derive_stealth_magics(password)
            loc = adapter.locate(cf, expected_trailer_magic=trailer_magic)

        if loc is None:
            return {
                "carrier": carrier_path,
                "format": adapter.format_name(),
                "has_hidden_data": False,
                "supported_strategies": adapter.supported_strategies(),
            }

        ube_offset, ube_total_size, strategy_name = loc
        cf.seek(ube_offset)
        header = EnvelopeHeader.unpack(cf.read(HEADER_STRUCT.size))

        password_hint = None
        if header.hint_len > 0:
            password_hint = cf.read(header.hint_len).decode("utf-8", errors="replace")

        meta_info = None
        if not header.is_encrypted:
            meta_bytes = cf.read(header.meta_len)
            try:
                meta_info = json.loads(meta_bytes.decode("utf-8"))
            except Exception:
                pass
        elif password:
            meta_bytes = cf.read(header.meta_len)
            try:
                _, meta_key = derive_keys(password, header.salt)
                dec_bytes = decrypt_metadata(meta_bytes, meta_key, header.base_nonce, header.get_aad())
                meta_info = json.loads(dec_bytes.decode("utf-8"))
            except Exception:
                meta_info = {"error": "Invalid password"}

        return {
            "carrier": carrier_path,
            "format": adapter.format_name(),
            "has_hidden_data": True,
            "strategy": strategy_name,
            "ube_offset": ube_offset,
            "ube_total_size": ube_total_size,
            "is_encrypted": header.is_encrypted,
            "is_compressed": header.is_compressed,
            "is_stealth": header.is_stealth,
            "password_hint": password_hint,
            "orig_host_size": header.orig_host_size,
            "orig_host_sha256": header.orig_host_sha256.hex(),
            "metadata": meta_info,
        }


def verify_carrier(carrier_path: str, password: Optional[str] = None) -> Dict[str, Any]:
    """Perform 3-level diagnostic verification."""
    if not os.path.exists(carrier_path):
        raise FileNotFoundError(f"Carrier file '{carrier_path}' not found")

    with open(carrier_path, "rb") as cf:
        adapter = find_adapter(cf)
        # Level 1: Host format integrity
        l1_ok, l1_msg = adapter.verify_structure(cf)

        # Level 2: Envelope boundary & CRC
        loc = adapter.locate(cf)
        if loc is None and password:
            _, trailer_magic = derive_stealth_magics(password)
            loc = adapter.locate(cf, expected_trailer_magic=trailer_magic)

        if loc is None:
            return {
                "carrier": carrier_path,
                "level1_host": {"ok": l1_ok, "detail": l1_msg},
                "level2_envelope": {"ok": False, "detail": "No envelope found"},
                "level3_crypto": {"ok": False, "detail": "Skipped (no envelope)"},
            }

        ube_offset, ube_total_size, strategy = loc
        try:
            cf.seek(ube_offset)
            header = EnvelopeHeader.unpack(cf.read(HEADER_STRUCT.size))
            cf.seek(ube_offset + ube_total_size - 24)
            expected_trailer_magic = None
            if header.is_stealth and password:
                _, expected_trailer_magic = derive_stealth_magics(password)
            trailer = EnvelopeTrailer.unpack(cf.read(24), expected_magic=expected_trailer_magic)
            if trailer.ube_offset != ube_offset or trailer.ube_total_size != ube_total_size:
                raise CorruptedDataError("Envelope trailer boundary parameters mismatch")
            l2_ok = True
            l2_msg = f"Envelope valid at offset {ube_offset}, size {ube_total_size}B (CRC32 OK)"
        except Exception as e:
            l2_ok = False
            l2_msg = f"Envelope corrupted: {e}"

    # Level 3: Crypto & payload SHA-256
    l3_ok = False
    l3_msg = "Password required for cryptographic verification"
    if not header.is_encrypted or password:
        try:
            res = read_carrier(carrier_path, password=password)
            l3_ok = True
            l3_msg = f"Decryption and SHA-256 verified successfully (payload {res['raw_size']} bytes)"
        except Exception as e:
            l3_ok = False
            l3_msg = str(e)

    return {
        "carrier": carrier_path,
        "format": adapter.format_name(),
        "level1_host": {"ok": l1_ok, "detail": l1_msg},
        "level2_envelope": {"ok": l2_ok, "detail": l2_msg},
        "level3_crypto": {"ok": l3_ok, "detail": l3_msg},
    }
