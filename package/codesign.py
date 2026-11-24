#!/usr/bin/env python3
"""Pure-Python iOS 15-16 ARM64 Mach-O ad-hoc code signer and verifier.

Produces LC_CODE_SIGNATURE blobs compatible with iOS 15-18 Mach-O ad-hoc
signatures and jailbroken/TrollStore/installer workflows:
  - CodeDirectory v0x20400 (SHA-256, 4096-byte pages, CS_ADHOC, execSeg)
  - Requirements blob (empty ad-hoc requirements)
  - XML entitlements blob (0xfade7171, special slot -5)
  - Apple ASN.1 DER entitlements blob (0xfade7172, special slot -7)

Also supports invoking external `ldid` when available and requested.
"""

from __future__ import annotations

import argparse
import hashlib
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Mach-O constants
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_EXECUTE = 0x2

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_BUILD_VERSION = 0x32
PLATFORM_IOS = 2

LINKEDIT_DATA_COMMAND_SIZE = 16
PAGE_SIZE_16K = 16 * 1024
CODE_SIGNATURE_ALIGN = 16

# Code Signing constants (Apple CSCommon.h / kern/cs_blobs.h)
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172

CSSLOT_CODEDIRECTORY = 0
CSSLOT_REQUIREMENTS = 2
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7

CS_ADHOC = 0x00000002
CS_EXECSEG_MAIN_BINARY = 0x1
CS_EXECSEG_ALLOW_UNSIGNED = 0x10
CS_EXECSEG_DEBUGGER = 0x20
CS_EXECSEG_JIT = 0x40
CS_EXECSEG_SKIP_LV = 0x80
CS_EXECSEG_CAN_LOAD_CDHASH = 0x100
CS_EXECSEG_CAN_EXEC_CDHASH = 0x200

CODEDIRECTORY_VERSION_EXECSEG = 0x20400
CODEDIRECTORY_HEADER_LEN = 88
CODEDIRECTORY_PAGE_SIZE_LOG2 = 12
CODEDIRECTORY_PAGE_SIZE = 1 << CODEDIRECTORY_PAGE_SIZE_LOG2
HASH_TYPE_SHA256 = 2
HASH_SIZE_SHA256 = 32

# Hard-banned entitlements on iOS 15+ A12+ CoreTrust/AMFI
BANNED_ENTITLEMENTS = {
    "com.apple.private.cs.debugger",
    "dynamic-codesigning",
    "com.apple.private.skip-library-validation",
}


class CodeSignError(RuntimeError):
    """Raised when Mach-O parsing, signing, or verification fails."""


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _der_len(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_unsigned_int(value: int) -> bytes:
    if value < 0:
        raise CodeSignError(f"negative integers are not supported in DER entitlements: {value}")
    if value == 0:
        return _der_tlv(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _der_value(value: Any, path: str) -> bytes:
    if isinstance(value, bool):
        return _der_tlv(0x01, b"\xff" if value else b"\x00")
    if isinstance(value, int):
        return _der_unsigned_int(value)
    if isinstance(value, str):
        return _der_tlv(0x0C, value.encode("utf-8"))
    if isinstance(value, list):
        body = b"".join(_der_value(item, f"{path}[{i}]") for i, item in enumerate(value))
        return _der_tlv(0x30, body)
    if isinstance(value, dict):
        return _der_tlv(0x31, _der_dict_body(value, path))
    raise CodeSignError(f"unsupported entitlement value type at {path}: {type(value).__name__}")


def _der_dict_body(mapping: dict[str, Any], path: str) -> bytes:
    entries: list[tuple[bytes, bytes]] = []
    for key, value in mapping.items():
        if not isinstance(key, str):
            raise CodeSignError(f"entitlement key at {path} must be a string")
        key_bytes = key.encode("utf-8")
        entry_body = _der_tlv(0x0C, key_bytes) + _der_value(value, f"{path}.{key}")
        entries.append((key_bytes, _der_tlv(0x30, entry_body)))
    entries.sort(key=lambda pair: pair[0])
    return b"".join(entry for _, entry in entries)


def encode_der_entitlements(entitlements: dict[str, Any]) -> bytes:
    """Encode an entitlements dict into Apple's ASN.1 DER envelope (tag 0x70)."""
    dictionary = _der_dict_body(entitlements, "$")
    body = _der_tlv(0x02, b"\x01") + _der_tlv(0xB0, dictionary)
    return _der_tlv(0x70, body)


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise CodeSignError("truncated DER element")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise CodeSignError("truncated DER length")
    first = data[offset]
    offset += 1
    if first < 128:
        length = first
    else:
        num_bytes = first & 0x7F
        if num_bytes == 0 or offset + num_bytes > len(data):
            raise CodeSignError("invalid DER length encoding")
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        offset += num_bytes
    end = offset + length
    if end > len(data):
        raise CodeSignError("DER element extends past buffer")
    return tag, data[offset:end], end


def _decode_der_value(tag: int, body: bytes) -> Any:
    if tag == 0x01:
        if body == b"\xff":
            return True
        if body == b"\x00":
            return False
        raise CodeSignError(f"invalid DER boolean payload: {body!r}")
    if tag == 0x02:
        if not body:
            raise CodeSignError("empty DER integer")
        return int.from_bytes(body, "big", signed=True)
    if tag == 0x0C:
        return body.decode("utf-8")
    if tag == 0x30:
        items = []
        pos = 0
        while pos < len(body):
            item_tag, item_body, pos = _read_der_tlv(body, pos)
            items.append(_decode_der_value(item_tag, item_body))
        return items
    if tag == 0x31:
        return _decode_der_dict_body(body)
    raise CodeSignError(f"unsupported DER tag 0x{tag:02x}")


def _decode_der_dict_body(body: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    pos = 0
    while pos < len(body):
        entry_tag, entry_body, pos = _read_der_tlv(body, pos)
        if entry_tag != 0x30:
            raise CodeSignError(f"expected SEQUENCE (0x30) in DER dict, got 0x{entry_tag:02x}")
        k_tag, k_body, epos = _read_der_tlv(entry_body, 0)
        if k_tag != 0x0C:
            raise CodeSignError(f"expected UTF8String (0x0c) key in DER dict, got 0x{k_tag:02x}")
        v_tag, v_body, epos = _read_der_tlv(entry_body, epos)
        if epos != len(entry_body):
            raise CodeSignError("trailing data in DER entitlement entry")
        result[k_body.decode("utf-8")] = _decode_der_value(v_tag, v_body)
    return result


def decode_der_entitlements(der: bytes) -> dict[str, Any]:
    """Decode Apple's ASN.1 DER entitlements envelope back into a Python dict."""
    tag, body, end = _read_der_tlv(der, 0)
    if tag != 0x70 or end != len(der):
        raise CodeSignError("invalid DER entitlements envelope")
    v_tag, v_body, pos = _read_der_tlv(body, 0)
    if v_tag != 0x02 or v_body != b"\x01":
        raise CodeSignError("unexpected DER entitlements version")
    d_tag, d_body, pos = _read_der_tlv(body, pos)
    if d_tag != 0xB0 or pos != len(body):
        raise CodeSignError("unexpected DER entitlements dictionary wrapper")
    return _decode_der_dict_body(d_body)


def _entitlement_exec_flags(entitlements: dict[str, Any], is_executable: bool) -> int:
    flags = CS_EXECSEG_MAIN_BINARY if is_executable else 0
    mapping = (
        ("get-task-allow", CS_EXECSEG_ALLOW_UNSIGNED),
        ("run-unsigned-code", CS_EXECSEG_ALLOW_UNSIGNED),
        ("com.apple.private.cs.debugger", CS_EXECSEG_DEBUGGER),
        ("dynamic-codesigning", CS_EXECSEG_JIT),
        ("com.apple.private.skip-library-validation", CS_EXECSEG_SKIP_LV),
        ("com.apple.private.amfi.can-load-cdhash", CS_EXECSEG_CAN_LOAD_CDHASH),
        ("com.apple.private.amfi.can-execute-cdhash", CS_EXECSEG_CAN_EXEC_CDHASH),
    )
    for key, bit in mapping:
        if entitlements.get(key) is True:
            flags |= bit
    return flags


def _wrap_blob(magic: int, payload: bytes) -> bytes:
    return struct.pack(">II", magic, 8 + len(payload)) + payload


def _empty_requirements_blob() -> bytes:
    return struct.pack(">III", CSMAGIC_REQUIREMENTS, 12, 0)


def _encode_superblob(blobs: list[tuple[int, bytes]]) -> bytes:
    index_len = len(blobs) * 8
    total_len = 12 + index_len + sum(len(b) for _, b in blobs)
    out = bytearray(struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, total_len, len(blobs)))
    offset = 12 + index_len
    for slot, blob in blobs:
        out.extend(struct.pack(">II", slot, offset))
        offset += len(blob)
    for _, blob in blobs:
        out.extend(blob)
    return bytes(out)


def _encode_code_directory(
    *,
    identifier: str,
    macho_bytes: bytes,
    code_limit: int,
    exec_seg_base: int,
    exec_seg_limit: int,
    exec_seg_flags: int,
    requirements_blob: bytes,
    xml_entitlements_blob: bytes | None,
    der_entitlements_blob: bytes | None,
    flags: int = CS_ADHOC,
) -> bytes:
    ident_bytes = identifier.encode("utf-8") + b"\x00"
    if der_entitlements_blob is not None:
        special_slots = 7
    elif xml_entitlements_blob is not None:
        special_slots = 5
    else:
        special_slots = 2

    code_slots = (code_limit + CODEDIRECTORY_PAGE_SIZE - 1) // CODEDIRECTORY_PAGE_SIZE
    ident_offset = CODEDIRECTORY_HEADER_LEN
    hash_offset = ident_offset + len(ident_bytes) + special_slots * HASH_SIZE_SHA256
    total_len = hash_offset + code_slots * HASH_SIZE_SHA256

    code_limit_32 = code_limit if code_limit <= 0xFFFFFFFF else 0
    code_limit_64 = code_limit if code_limit > 0xFFFFFFFF else 0

    header = struct.pack(
        ">IIIIIIIIIBBBBIIIIQQQQ",
        CSMAGIC_CODEDIRECTORY,
        total_len,
        CODEDIRECTORY_VERSION_EXECSEG,
        flags,
        hash_offset,
        ident_offset,
        special_slots,
        code_slots,
        code_limit_32,
        HASH_SIZE_SHA256,
        HASH_TYPE_SHA256,
        0,  # platform (0 for ad-hoc / non-Apple-platform-cert binaries)
        CODEDIRECTORY_PAGE_SIZE_LOG2,
        0,  # spare2
        0,  # scatterOffset
        0,  # teamOffset (0 for ad-hoc)
        0,  # spare3
        code_limit_64,
        exec_seg_base,
        exec_seg_limit,
        exec_seg_flags,
    )
    assert len(header) == CODEDIRECTORY_HEADER_LEN

    zero_hash = b"\x00" * HASH_SIZE_SHA256
    special_map: dict[int, bytes] = {
        2: hashlib.sha256(requirements_blob).digest(),
    }
    if xml_entitlements_blob is not None:
        special_map[5] = hashlib.sha256(xml_entitlements_blob).digest()
    if der_entitlements_blob is not None:
        special_map[7] = hashlib.sha256(der_entitlements_blob).digest()

    out = bytearray(header)
    out.extend(ident_bytes)
    # Special slots are stored from -special_slots up to -1 in order:
    # e.g., slot -7, -6, -5, -4, -3, -2, -1
    for slot_num in range(special_slots, 0, -1):
        out.extend(special_map.get(slot_num, zero_hash))

    # Code page hashes (4096-byte pages up to code_limit)
    for pos in range(0, code_limit, CODEDIRECTORY_PAGE_SIZE):
        chunk = macho_bytes[pos : min(pos + CODEDIRECTORY_PAGE_SIZE, code_limit)]
        out.extend(hashlib.sha256(chunk).digest())

    assert len(out) == total_len
    return bytes(out)


@dataclass
class MachO64Info:
    cputype: int
    cpusubtype: int
    filetype: int
    ncmds: int
    sizeofcmds: int
    first_section_offset: int
    text_fileoff: int
    text_filesize: int
    linkedit_cmd_offset: int
    linkedit_fileoff: int
    linkedit_filesize: int
    linkedit_vmsize: int
    code_sig_cmd_offset: int | None
    code_sig_dataoff: int | None
    code_sig_datasize: int | None
    platforms: list[int]


def parse_macho64(data: bytes) -> MachO64Info:
    if len(data) < 32:
        raise CodeSignError("file too small to be a 64-bit Mach-O")
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, _flags, _reserved = struct.unpack_from(
        "<IIIIIIII", data, 0
    )
    if magic != MH_MAGIC_64:
        raise CodeSignError(f"unsupported Mach-O magic 0x{magic:08x} (expected 64-bit LE Mach-O)")
    header_size = 32
    commands_end = header_size + sizeofcmds
    if commands_end > len(data):
        raise CodeSignError("Mach-O load commands extend past EOF")

    offset = header_size
    first_section_offset = len(data)
    text_fileoff = 0
    text_filesize = 0
    found_text = False
    linkedit_cmd_offset: int | None = None
    linkedit_fileoff = 0
    linkedit_filesize = 0
    linkedit_vmsize = 0
    code_sig_cmd_offset: int | None = None
    code_sig_dataoff: int | None = None
    code_sig_datasize: int | None = None
    platforms: list[int] = []

    for _ in range(ncmds):
        if offset + 8 > commands_end:
            raise CodeSignError("truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8 or offset + cmdsize > commands_end:
            raise CodeSignError("invalid Mach-O load command size")

        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise CodeSignError("truncated LC_SEGMENT_64")
            segname_raw = data[offset + 8 : offset + 24]
            segname = segname_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            _vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, offset + 24)
            nsects = struct.unpack_from("<I", data, offset + 64)[0]
            if segname == "__TEXT":
                found_text = True
                text_fileoff = fileoff
                text_filesize = filesize
            elif segname == "__LINKEDIT":
                linkedit_cmd_offset = offset
                linkedit_fileoff = fileoff
                linkedit_filesize = filesize
                linkedit_vmsize = vmsize
            sect_off = offset + 72
            for _s in range(nsects):
                if sect_off + 80 > offset + cmdsize:
                    raise CodeSignError("truncated section_64")
                s_size = struct.unpack_from("<Q", data, sect_off + 40)[0]
                s_offset = struct.unpack_from("<I", data, sect_off + 48)[0]
                s_flags = struct.unpack_from("<I", data, sect_off + 64)[0]
                s_type = s_flags & 0xFF
                if s_size > 0 and s_offset > 0 and s_type not in (0x1, 0x11):
                    if s_offset < first_section_offset:
                        first_section_offset = s_offset
                sect_off += 80
        elif cmd == LC_CODE_SIGNATURE:
            if cmdsize < LINKEDIT_DATA_COMMAND_SIZE:
                raise CodeSignError("truncated LC_CODE_SIGNATURE")
            code_sig_cmd_offset = offset
            code_sig_dataoff, code_sig_datasize = struct.unpack_from("<II", data, offset + 8)
        elif cmd == LC_BUILD_VERSION:
            if cmdsize >= 24:
                platform = struct.unpack_from("<I", data, offset + 8)[0]
                platforms.append(platform)

        offset += cmdsize

    if not found_text:
        raise CodeSignError("Mach-O missing __TEXT segment")
    if linkedit_cmd_offset is None:
        raise CodeSignError("Mach-O missing __LINKEDIT segment")

    return MachO64Info(
        cputype=cputype,
        cpusubtype=cpusubtype,
        filetype=filetype,
        ncmds=ncmds,
        sizeofcmds=sizeofcmds,
        first_section_offset=first_section_offset,
        text_fileoff=text_fileoff,
        text_filesize=text_filesize,
        linkedit_cmd_offset=linkedit_cmd_offset,
        linkedit_fileoff=linkedit_fileoff,
        linkedit_filesize=linkedit_filesize,
        linkedit_vmsize=linkedit_vmsize,
        code_sig_cmd_offset=code_sig_cmd_offset,
        code_sig_dataoff=code_sig_dataoff,
        code_sig_datasize=code_sig_datasize,
        platforms=platforms,
    )


def load_and_validate_entitlements(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    parsed = plistlib.loads(raw)
    if not isinstance(parsed, dict):
        raise CodeSignError(f"entitlements file {path} must contain a plist dictionary")
    banned = sorted(k for k in parsed if k in BANNED_ENTITLEMENTS and parsed[k] is True)
    if banned:
        raise CodeSignError(f"refusing iOS 15+ A12+ banned entitlements in {path}: {banned}")
    canonical_xml = plistlib.dumps(parsed, fmt=plistlib.FMT_XML, sort_keys=True)
    return parsed, canonical_xml


def sign_macho_bytes_builtin(
    data: bytes,
    *,
    identifier: str,
    entitlements: dict[str, Any] | None = None,
    entitlements_xml: bytes | None = None,
) -> bytes:
    """Ad-hoc sign a 64-bit ARM64 iOS Mach-O executable with XML + DER entitlements."""
    if not identifier:
        raise CodeSignError("signing identifier must not be empty")

    info = parse_macho64(data)
    if info.cputype != CPU_TYPE_ARM64:
        raise CodeSignError(f"expected ARM64 Mach-O (0x{CPU_TYPE_ARM64:x}), got 0x{info.cputype:x}")
    if info.filetype != MH_EXECUTE:
        raise CodeSignError(f"expected MH_EXECUTE (2), got {info.filetype}")
    if PLATFORM_IOS not in info.platforms:
        raise CodeSignError(f"expected PLATFORM_IOS (2) in LC_BUILD_VERSION, got {info.platforms}")

    buf = bytearray(data)

    # Determine where the new code signature will start.
    if info.code_sig_cmd_offset is not None:
        assert info.code_sig_dataoff is not None and info.code_sig_datasize is not None
        old_end = info.code_sig_dataoff + info.code_sig_datasize
        if info.code_sig_datasize > 0:
            if old_end != len(buf):
                raise CodeSignError(
                    f"existing LC_CODE_SIGNATURE ({old_end}) is not at EOF ({len(buf)})"
                )
            code_limit = info.code_sig_dataoff
            del buf[code_limit:]
        else:
            linkedit_end = info.linkedit_fileoff + info.linkedit_filesize
            if linkedit_end > len(buf):
                raise CodeSignError("__LINKEDIT extends past EOF")
            del buf[linkedit_end:]
            code_limit = _align_up(linkedit_end, CODE_SIGNATURE_ALIGN)
            buf.extend(b"\x00" * (code_limit - linkedit_end))
        cmd_offset = info.code_sig_cmd_offset
    else:
        cmd_offset = 32 + info.sizeofcmds
        cmd_end = cmd_offset + LINKEDIT_DATA_COMMAND_SIZE
        if cmd_end > info.first_section_offset or cmd_end > len(buf):
            raise CodeSignError("insufficient Mach-O header padding for LC_CODE_SIGNATURE")
        if any(b != 0 for b in buf[cmd_offset:cmd_end]):
            raise CodeSignError("non-zero bytes in Mach-O header padding after load commands")
        struct.pack_into("<IIII", buf, cmd_offset, LC_CODE_SIGNATURE, LINKEDIT_DATA_COMMAND_SIZE, 0, 0)
        struct.pack_into("<II", buf, 16, info.ncmds + 1, info.sizeofcmds + LINKEDIT_DATA_COMMAND_SIZE)

        linkedit_end = info.linkedit_fileoff + info.linkedit_filesize
        if linkedit_end > len(buf):
            raise CodeSignError("__LINKEDIT extends past EOF")
        del buf[linkedit_end:]
        code_limit = _align_up(linkedit_end, CODE_SIGNATURE_ALIGN)
        buf.extend(b"\x00" * (code_limit - linkedit_end))

    requirements_blob = _empty_requirements_blob()
    xml_blob: bytes | None = None
    der_blob: bytes | None = None
    ent_dict = entitlements or {}
    if entitlements is not None:
        xml_bytes = (
            entitlements_xml
            if entitlements_xml is not None
            else plistlib.dumps(ent_dict, fmt=plistlib.FMT_XML, sort_keys=True)
        )
        xml_blob = _wrap_blob(CSMAGIC_EMBEDDED_ENTITLEMENTS, xml_bytes)
        der_blob = _wrap_blob(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, encode_der_entitlements(ent_dict))

    exec_flags = _entitlement_exec_flags(ent_dict, is_executable=True)

    # First pass computes exact SuperBlob length so we can finalize LC_CODE_SIGNATURE
    # and __LINKEDIT BEFORE computing page-0 SHA-256 hashes.
    dummy_cd = _encode_code_directory(
        identifier=identifier,
        macho_bytes=bytes(buf),
        code_limit=code_limit,
        exec_seg_base=info.text_fileoff,
        exec_seg_limit=info.text_filesize,
        exec_seg_flags=exec_flags,
        requirements_blob=requirements_blob,
        xml_entitlements_blob=xml_blob,
        der_entitlements_blob=der_blob,
    )
    blobs_probe: list[tuple[int, bytes]] = [
        (CSSLOT_CODEDIRECTORY, dummy_cd),
        (CSSLOT_REQUIREMENTS, requirements_blob),
    ]
    if xml_blob is not None:
        blobs_probe.append((CSSLOT_ENTITLEMENTS, xml_blob))
    if der_blob is not None:
        blobs_probe.append((CSSLOT_DER_ENTITLEMENTS, der_blob))
    superblob_len = len(_encode_superblob(blobs_probe))
    datasize = _align_up(superblob_len, CODE_SIGNATURE_ALIGN)

    # Patch LC_CODE_SIGNATURE and __LINKEDIT header BEFORE final page hashing!
    struct.pack_into("<II", buf, cmd_offset + 8, code_limit, datasize)
    new_linkedit_filesize = (code_limit + datasize) - info.linkedit_fileoff
    new_linkedit_vmsize = _align_up(new_linkedit_filesize, PAGE_SIZE_16K)
    struct.pack_into("<Q", buf, info.linkedit_cmd_offset + 32, new_linkedit_vmsize)
    struct.pack_into("<Q", buf, info.linkedit_cmd_offset + 48, new_linkedit_filesize)

    # Now compute the real CodeDirectory hashes over the finalized Mach-O image [0:code_limit].
    real_cd = _encode_code_directory(
        identifier=identifier,
        macho_bytes=bytes(buf),
        code_limit=code_limit,
        exec_seg_base=info.text_fileoff,
        exec_seg_limit=info.text_filesize,
        exec_seg_flags=exec_flags,
        requirements_blob=requirements_blob,
        xml_entitlements_blob=xml_blob,
        der_entitlements_blob=der_blob,
    )
    blobs: list[tuple[int, bytes]] = [
        (CSSLOT_CODEDIRECTORY, real_cd),
        (CSSLOT_REQUIREMENTS, requirements_blob),
    ]
    if xml_blob is not None:
        blobs.append((CSSLOT_ENTITLEMENTS, xml_blob))
    if der_blob is not None:
        blobs.append((CSSLOT_DER_ENTITLEMENTS, der_blob))
    superblob = _encode_superblob(blobs)
    assert len(superblob) == superblob_len

    buf.extend(superblob)
    if len(superblob) < datasize:
        buf.extend(b"\x00" * (datasize - len(superblob)))
    return bytes(buf)


def sign_macho_file(
    input_path: Path,
    output_path: Path,
    *,
    identifier: str,
    entitlements_path: Path | None = None,
    signer: str = "auto",
    ldid_path: Path | None = None,
) -> str:
    """Sign input_path into output_path using ldid or built-in Mach-O signer.

    Returns the signer backend name used ('ldid' or 'builtin').
    """
    ent_dict: dict[str, Any] | None = None
    ent_xml: bytes | None = None
    if entitlements_path is not None:
        ent_dict, ent_xml = load_and_validate_entitlements(entitlements_path)

    resolved_ldid: str | None = None
    if ldid_path is not None:
        resolved_ldid = str(ldid_path)
    elif signer in ("auto", "ldid"):
        resolved_ldid = shutil.which("ldid") or shutil.which("ldid2")

    if signer == "ldid" and not resolved_ldid:
        raise CodeSignError("requested --signer=ldid but ldid/ldid2 is not available")

    if resolved_ldid and signer in ("auto", "ldid"):
        shutil.copyfile(input_path, output_path)
        cmd = [resolved_ldid]
        if entitlements_path is not None:
            cmd.append(f"-S{entitlements_path}")
        else:
            cmd.append("-S")
        cmd.append(f"-I{identifier}")
        cmd.append(str(output_path))
        subprocess.run(cmd, check=True)
        return "ldid"

    signed = sign_macho_bytes_builtin(
        input_path.read_bytes(),
        identifier=identifier,
        entitlements=ent_dict,
        entitlements_xml=ent_xml,
    )
    output_path.write_bytes(signed)
    return "builtin"


@dataclass
class VerifiedSignature:
    identifier: str
    flags: int
    version: int
    hash_type: int
    code_slots: int
    special_slots: int
    xml_entitlements: dict[str, Any] | None
    der_entitlements: dict[str, Any] | None
    cdhash_sha256: str


def verify_macho_signature(
    data: bytes,
    *,
    expected_entitlements: dict[str, Any] | None = None,
    require_der: bool = True,
) -> VerifiedSignature:
    """Independently verify Mach-O architecture, iOS platform, CodeDirectory page hashes,
    special slot hashes, and XML+DER entitlements."""
    info = parse_macho64(data)
    if info.cputype != CPU_TYPE_ARM64:
        raise CodeSignError(f"not ARM64: cputype=0x{info.cputype:x}")
    if info.filetype != MH_EXECUTE:
        raise CodeSignError(f"not MH_EXECUTE: filetype={info.filetype}")
    if PLATFORM_IOS not in info.platforms:
        raise CodeSignError(f"not iOS platform: platforms={info.platforms}")
    if info.code_sig_cmd_offset is None or info.code_sig_dataoff is None or info.code_sig_datasize is None:
        raise CodeSignError("missing LC_CODE_SIGNATURE")
    if info.code_sig_datasize == 0:
        raise CodeSignError("empty LC_CODE_SIGNATURE")

    sig_start = info.code_sig_dataoff
    sig_end = sig_start + info.code_sig_datasize
    if sig_end != len(data):
        raise CodeSignError(f"LC_CODE_SIGNATURE end ({sig_end}) != file size ({len(data)})")
    if info.linkedit_fileoff + info.linkedit_filesize != sig_end:
        raise CodeSignError("__LINKEDIT filesize does not match end of LC_CODE_SIGNATURE")
    if info.linkedit_vmsize < info.linkedit_filesize or (info.linkedit_vmsize % PAGE_SIZE_16K) != 0:
        raise CodeSignError("__LINKEDIT vmsize is not 16KB page-aligned or smaller than filesize")

    sig = data[sig_start:sig_end]
    if len(sig) < 12:
        raise CodeSignError("truncated SuperBlob")
    sb_magic, sb_len, sb_count = struct.unpack_from(">III", sig, 0)
    if sb_magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise CodeSignError(f"bad SuperBlob magic 0x{sb_magic:08x}")
    if sb_len > len(sig) or 12 + sb_count * 8 > sb_len:
        raise CodeSignError("SuperBlob length/count out of bounds")

    slots: dict[int, bytes] = {}
    for i in range(sb_count):
        slot_type, slot_off = struct.unpack_from(">II", sig, 12 + i * 8)
        if slot_off + 8 > sb_len:
            raise CodeSignError(f"slot {slot_type} offset out of bounds")
        _b_magic, b_len = struct.unpack_from(">II", sig, slot_off)
        if slot_off + b_len > sb_len:
            raise CodeSignError(f"slot {slot_type} length out of bounds")
        slots[slot_type] = sig[slot_off : slot_off + b_len]

    if CSSLOT_CODEDIRECTORY not in slots:
        raise CodeSignError("missing CSSLOT_CODEDIRECTORY")
    cd = slots[CSSLOT_CODEDIRECTORY]
    if len(cd) < CODEDIRECTORY_HEADER_LEN:
        raise CodeSignError("truncated CodeDirectory")
    (
        cd_magic,
        cd_len,
        cd_ver,
        cd_flags,
        hash_off,
        ident_off,
        n_special,
        n_code,
        code_limit_32,
        hash_size,
        hash_type,
        _platform,
        page_size_log2,
        _spare2,
        _scatter,
        _team,
        _spare3,
        code_limit_64,
        exec_base,
        exec_limit,
        exec_flags,
    ) = struct.unpack_from(">IIIIIIIIIBBBBIIIIQQQQ", cd, 0)

    if cd_magic != CSMAGIC_CODEDIRECTORY or cd_len != len(cd):
        raise CodeSignError("invalid CodeDirectory header")
    if cd_ver < CODEDIRECTORY_VERSION_EXECSEG:
        raise CodeSignError(f"CodeDirectory version 0x{cd_ver:x} too old for iOS 15+")
    if hash_type != HASH_TYPE_SHA256 or hash_size != HASH_SIZE_SHA256:
        raise CodeSignError(f"expected SHA-256 CodeDirectory, got type={hash_type} size={hash_size}")
    if exec_base != info.text_fileoff or exec_limit != info.text_filesize:
        raise CodeSignError("execSegBase/execSegLimit do not match __TEXT segment")
    if (exec_flags & CS_EXECSEG_MAIN_BINARY) == 0:
        raise CodeSignError("CS_EXECSEG_MAIN_BINARY missing in execSegFlags")

    code_limit = code_limit_64 if code_limit_64 else code_limit_32
    if code_limit != sig_start:
        raise CodeSignError(f"CodeDirectory codeLimit ({code_limit}) != signature offset ({sig_start})")

    ident_end = cd.find(b"\x00", ident_off)
    if ident_end < 0:
        raise CodeSignError("unterminated CodeDirectory identifier")
    identifier = cd[ident_off:ident_end].decode("utf-8")

    # Verify every code page hash
    page_size = 1 << page_size_log2
    expected_code_slots = (code_limit + page_size - 1) // page_size
    if n_code != expected_code_slots:
        raise CodeSignError(f"nCodeSlots ({n_code}) != expected ({expected_code_slots})")
    for i in range(n_code):
        start = i * page_size
        end = min(start + page_size, code_limit)
        actual_hash = hashlib.sha256(data[start:end]).digest()
        stored_hash = cd[hash_off + i * hash_size : hash_off + (i + 1) * hash_size]
        if actual_hash != stored_hash:
            raise CodeSignError(f"code page {i} SHA-256 hash mismatch")

    def _stored_special(slot_num: int) -> bytes:
        if slot_num > n_special:
            raise CodeSignError(f"special slot -{slot_num} not present (nSpecialSlots={n_special})")
        pos = hash_off - slot_num * hash_size
        return cd[pos : pos + hash_size]

    # Verify Requirements slot if present
    if CSSLOT_REQUIREMENTS in slots:
        req_blob = slots[CSSLOT_REQUIREMENTS]
        if hashlib.sha256(req_blob).digest() != _stored_special(2):
            raise CodeSignError("special slot -2 (requirements) hash mismatch")

    # Verify XML entitlements
    xml_ent: dict[str, Any] | None = None
    if CSSLOT_ENTITLEMENTS in slots:
        xml_blob = slots[CSSLOT_ENTITLEMENTS]
        b_magic, _b_len = struct.unpack_from(">II", xml_blob, 0)
        if b_magic != CSMAGIC_EMBEDDED_ENTITLEMENTS:
            raise CodeSignError("bad XML entitlements blob magic")
        if hashlib.sha256(xml_blob).digest() != _stored_special(5):
            raise CodeSignError("special slot -5 (XML entitlements) hash mismatch")
        parsed = plistlib.loads(xml_blob[8:])
        if not isinstance(parsed, dict):
            raise CodeSignError("XML entitlements payload is not a dict")
        xml_ent = parsed

    # Verify DER entitlements
    der_ent: dict[str, Any] | None = None
    if CSSLOT_DER_ENTITLEMENTS in slots:
        der_blob = slots[CSSLOT_DER_ENTITLEMENTS]
        b_magic, _b_len = struct.unpack_from(">II", der_blob, 0)
        if b_magic != CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
            raise CodeSignError("bad DER entitlements blob magic")
        if hashlib.sha256(der_blob).digest() != _stored_special(7):
            raise CodeSignError("special slot -7 (DER entitlements) hash mismatch")
        der_ent = decode_der_entitlements(der_blob[8:])

    if expected_entitlements is not None:
        if xml_ent != expected_entitlements:
            raise CodeSignError(
                f"XML entitlements mismatch: got {xml_ent!r}, expected {expected_entitlements!r}"
            )
        if require_der:
            if der_ent is None:
                raise CodeSignError("missing DER entitlements (required on iOS 15-16)")
            if der_ent != expected_entitlements:
                raise CodeSignError(
                    f"DER entitlements mismatch: got {der_ent!r}, expected {expected_entitlements!r}"
                )

    cdhash = hashlib.sha256(cd).hexdigest()[:40]
    return VerifiedSignature(
        identifier=identifier,
        flags=cd_flags,
        version=cd_ver,
        hash_type=hash_type,
        code_slots=n_code,
        special_slots=n_special,
        xml_entitlements=xml_ent,
        der_entitlements=der_ent,
        cdhash_sha256=cdhash,
    )


def _run_self_test() -> None:
    # 1. Apple canonical empty DER entitlements envelope test vector
    empty_der = encode_der_entitlements({})
    assert empty_der == bytes([0x70, 0x05, 0x02, 0x01, 0x01, 0xB0, 0x00]), empty_der.hex()
    assert decode_der_entitlements(empty_der) == {}

    # 2. Complex entitlement types round-trip + sorted keys
    sample = {
        "z-flag": False,
        "platform-application": True,
        "com.apple.private.security.no-sandbox": True,
        "com.apple.private.security.container-required": False,
        "nested": {"count": 42, "items": ["a", "b", 0, 128]},
    }
    der = encode_der_entitlements(sample)
    assert decode_der_entitlements(der) == sample
    # Ensure keys are strictly sorted lexicographically (com.apple... before nested before platform...)
    assert der.index(b"com.apple.private.security.container-required") < der.index(
        b"com.apple.private.security.no-sandbox"
    ) < der.index(b"nested") < der.index(b"platform-application") < der.index(b"z-flag")

    # 3. Validate both entitlements plists in this directory if present
    pkg_dir = Path(__file__).resolve().parent
    for name in ("entitlements-app.plist", "entitlements-helper.plist"):
        p = pkg_dir / name
        if p.exists():
            ent_dict, _ = load_and_validate_entitlements(p)
            assert decode_der_entitlements(encode_der_entitlements(ent_dict)) == ent_dict

    print("codesign.py self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser(description="iOS 15-16 ARM64 Mach-O ad-hoc signer and verifier")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sign", type=Path, metavar="INPUT", help="Sign Mach-O executable")
    group.add_argument("--verify", type=Path, metavar="BINARY", help="Verify Mach-O signature")
    group.add_argument("--dump-entitlements", type=Path, metavar="BINARY", help="Print embedded XML entitlements")
    group.add_argument("--self-test", action="store_true", help="Run DER and entitlements self-tests")

    parser.add_argument("-o", "--output", type=Path, help="Output path for --sign (default: in-place)")
    parser.add_argument("-e", "--entitlements", type=Path, help="Entitlements XML plist")
    parser.add_argument("-I", "--identifier", help="CodeDirectory identifier")
    parser.add_argument("--signer", choices=("auto", "ldid", "builtin"), default="auto")
    parser.add_argument("--ldid", type=Path, help="Explicit path to ldid binary")
    args = parser.parse_args()

    if args.self_test:
        _run_self_test()
        return

    if args.sign is not None:
        out = args.output or args.sign
        ident = args.identifier or out.name
        with tempfile.TemporaryDirectory(prefix="codesign-") as td:
            staged = Path(td) / out.name
            backend = sign_macho_file(
                args.sign,
                staged,
                identifier=ident,
                entitlements_path=args.entitlements,
                signer=args.signer,
                ldid_path=args.ldid,
            )
            ent_dict = load_and_validate_entitlements(args.entitlements)[0] if args.entitlements else None
            info = verify_macho_signature(staged.read_bytes(), expected_entitlements=ent_dict, require_der=(ent_dict is not None))
            shutil.copyfile(staged, out)
            out.chmod(0o755)
        print(
            f"Signed {out} via {backend}: ident={info.identifier} flags=0x{info.flags:x} "
            f"pages={info.code_slots} cdhash={info.cdhash_sha256}"
        )
        return

    if args.verify is not None:
        ent_dict = load_and_validate_entitlements(args.entitlements)[0] if args.entitlements else None
        info = verify_macho_signature(
            args.verify.read_bytes(),
            expected_entitlements=ent_dict,
            require_der=(ent_dict is not None),
        )
        print(
            f"OK {args.verify}: ident={info.identifier} ver=0x{info.version:x} "
            f"flags=0x{info.flags:x} pages={info.code_slots} special={info.special_slots} "
            f"xml_ents={len(info.xml_entitlements or {})} der_ents={len(info.der_entitlements or {})} "
            f"cdhash={info.cdhash_sha256}"
        )
        return

    if args.dump_entitlements is not None:
        info = verify_macho_signature(args.dump_entitlements.read_bytes(), require_der=False)
        if info.xml_entitlements is None:
            print("No embedded XML entitlements", file=sys.stderr)
            sys.exit(1)
        sys.stdout.buffer.write(plistlib.dumps(info.xml_entitlements, fmt=plistlib.FMT_XML, sort_keys=True))


if __name__ == "__main__":
    main()
