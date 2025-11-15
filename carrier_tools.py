#!/usr/bin/env python3
"""
carrier_tools.py — Pure-stdlib carrier utilities for small secrets (v2).
- 2-of-2 XOR split & join
- PNG tEXt and JPEG COM carriers
- Zero-width Unicode side channel
- Packed share format CKS2 with 16-byte commitment tag

Format (CKS2):
  SIG="CKS2" (4) | VER=2 (1) | lab_len (1) | label (lab_len)
  | share_len (2, BE) | share (share_len) | commit16 (16)
  | cks8 (SHA-256 over share) (8)
  
Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, struct, binascii, secrets, hashlib
from typing import List, Tuple

# =========================
# Secret splitting (2-of-2)
# =========================

def split_secret_xor(secret: bytes) -> tuple[bytes, bytes]:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise ValueError("secret must be non-empty bytes")
    a = secrets.token_bytes(len(secret))
    b = bytes(x ^ y for x, y in zip(a, secret))
    return a, b

def join_secret_xor(share_a: bytes, share_b: bytes) -> bytes:
    if len(share_a) != len(share_b):
        raise ValueError("share lengths differ")
    return bytes(x ^ y for x, y in zip(share_a, share_b))

# =========================
# CKS2 pack/unpack with commitment
# =========================

_SIG = b"CKS2"
_VER = 2

def pack_share(label: str, share: bytes, commit_tag: bytes) -> bytes:
    """
    Pack a share with label and a 16-byte commitment tag.
    - label: short context (not secret); keep it minimal
    - share: raw share bytes
    - commit_tag: 16 bytes, typically HMAC-SHA512(secret, "commit")[:16]
    """
    if not isinstance(label, str) or not label:
        raise ValueError("label must be a non-empty str")
    if not isinstance(share, (bytes, bytearray)) or len(share) == 0:
        raise ValueError("share must be non-empty bytes")
    if not (isinstance(commit_tag, (bytes, bytearray)) and len(commit_tag) == 16):
        raise ValueError("commit_tag must be exactly 16 bytes")

    lab = label.encode("utf-8")
    if len(lab) > 255:
        raise ValueError("label too long (>255 bytes)")
    body = bytearray()
    body += _SIG
    body += bytes([_VER])
    body += bytes([len(lab)])
    body += lab
    body += struct.pack(">H", len(share))
    body += share
    body += commit_tag
    # lightweight corruption check (share only)
    cks8 = hashlib.sha256(share).digest()[:8]
    body += cks8
    return bytes(body)

def unpack_share(packed: bytes) -> tuple[str, bytes, bytes]:
    """
    Return (label, share, commit_tag16).
    Raises on format/length/checksum errors.
    """
    if not (isinstance(packed, (bytes, bytearray)) and len(packed) >= 4 + 1 + 1 + 2 + 16 + 8):
        raise ValueError("packed share too small")
    off = 0
    if packed[off:off+4] != _SIG:
        raise ValueError("bad signature (not CKS2)")
    off += 4
    ver = packed[off]; off += 1
    if ver != _VER:
        raise ValueError(f"unsupported version {ver}")
    lab_len = packed[off]; off += 1
    need = off + lab_len + 2
    if len(packed) < need:
        raise ValueError("truncated after label")
    label = packed[off:off+lab_len].decode("utf-8", "strict"); off += lab_len
    share_len = struct.unpack(">H", packed[off:off+2])[0]; off += 2
    need = off + share_len + 16 + 8
    if len(packed) < need:
        raise ValueError("truncated after share")
    share = bytes(packed[off:off+share_len]); off += share_len
    commit = bytes(packed[off:off+16]); off += 16
    cks8 = bytes(packed[off:off+8]); off += 8
    if hashlib.sha256(share).digest()[:8] != cks8:
        raise ValueError("share checksum mismatch")
    return label, share, commit

# =========================
# Commit helpers + E2E wrappers
# =========================

def commit16_from_secret(secret: bytes) -> bytes:
    """
    Derive a 16-byte commitment tag from the full secret.
    HMAC-SHA512(secret, b"commit")[:16]
    """
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise ValueError("secret must be non-empty bytes")
    import hmac
    return hmac.new(secret, b"commit", hashlib.sha512).digest()[:16]


def make_packed_shares(secret: bytes, label: str) -> tuple[bytes, bytes]:
    """
    Split a secret into 2-of-2 XOR shares and pack each with a shared 16-byte commitment.
    Returns (packed_a, packed_b)
    """
    a, b = split_secret_xor(secret)
    tag = commit16_from_secret(secret)
    return pack_share(label, a, tag), pack_share(label, b, tag)


def recover_secret_from_packed(packed_a: bytes, packed_b: bytes) -> tuple[bytes, str]:
    """
    Unpack both shares, verify:
      - both parse, checksum OK
      - labels match
      - 16-byte commitment tags match
    Then XOR to recover the original secret. Returns (secret, label)
    """
    lab_a, sh_a, tag_a = unpack_share(packed_a)
    lab_b, sh_b, tag_b = unpack_share(packed_b)

    if lab_a != lab_b:
        raise ValueError("label mismatch between shares")
    if tag_a != tag_b:
        raise ValueError("commitment tag mismatch between shares")
    if len(sh_a) != len(sh_b):
        raise ValueError("share length mismatch")

    secret = join_secret_xor(sh_a, sh_b)
    # optional: recheck commitment against recovered secret
    want = commit16_from_secret(secret)
    if want != tag_a:
        raise ValueError("commitment tag does not verify for recovered secret")
    return secret, lab_a

# =========================
# PNG tEXt chunk carrier
# =========================

_PNG_SIG = b"\x89PNG\r\n\x1a\n"

def _png_chunks(stream: bytes) -> list[tuple[bytes, bytes, bytes]]:
    if not stream.startswith(_PNG_SIG):
        raise ValueError("not a PNG file")
    chunks = []
    off = len(_PNG_SIG)
    while off + 12 <= len(stream):
        length = struct.unpack(">I", stream[off:off+4])[0]; off += 4
        ctype  = stream[off:off+4]; off += 4
        if off + length + 4 > len(stream):
            raise ValueError("PNG truncated")
        data = stream[off:off+length]; off += length
        crc  = stream[off:off+4]; off += 4
        chunks.append((ctype, data, crc))
        if ctype == b"IEND":
            break
    return chunks

def _png_build(chunks: list[tuple[bytes, bytes]]) -> bytes:
    out = bytearray(_PNG_SIG)
    for ctype, data in chunks:
        out += struct.pack(">I", len(data))
        out += ctype
        crc = binascii.crc32(ctype)
        crc = binascii.crc32(data, crc) & 0xffffffff
        out += data
        out += struct.pack(">I", crc)
    return bytes(out)

def embed_png_text(in_path: str, out_path: str, keyword: str, text: bytes) -> None:
    """
    Embed bytes into PNG as a tEXt chunk after IHDR.
    Payload is base64-encoded to stay ISO-8859-1 compliant per PNG tEXt spec.
    """
    if not (1 <= len(keyword) <= 79):
        raise ValueError("keyword must be 1..79 chars")

    raw = open(in_path, "rb").read()
    chunks = _png_chunks(raw)
    out_chunks: list[tuple[bytes, bytes]] = []
    inserted = False

    payload = binascii.b2a_base64(text, newline=False)
    for ctype, data, _crc in chunks:
        out_chunks.append((ctype, data))
        if (not inserted) and ctype == b"IHDR":
            k = keyword.encode("latin-1", "ignore").replace(b"\x00", b"_")
            tdat = k + b"\x00" + payload
            out_chunks.append((b"tEXt", tdat))
            inserted = True
    if not inserted:
        raise ValueError("IHDR not found in PNG")

    out = _png_build(out_chunks)
    with open(out_path, "wb") as f:
        f.write(out)


def extract_png_text(in_path: str, keyword: str) -> List[bytes]:
    """
    Extract bytes from PNG tEXt chunks with the given keyword.
    Payloads are expected to be base64-encoded (per our embed).
    """
    raw = open(in_path, "rb").read()
    chunks = _png_chunks(raw)
    want = keyword.encode("latin-1", "ignore")
    out: List[bytes] = []
    for ctype, data, _crc in chunks:
        if ctype == b"tEXt" and b"\x00" in data:
            k, v = data.split(b"\x00", 1)
            if k == want:
                out.append(binascii.a2b_base64(v))
    return out

# =========================
# JPEG COM carrier
# =========================

def embed_jpeg_comment(in_path: str, out_path: str, comment: bytes) -> None:
    data = bytearray(open(in_path, "rb").read())
    if not (len(data) >= 2 and data[0] == 0xFF and data[1] == 0xD8):
        raise ValueError("not a JPEG (missing SOI)")
    if len(comment) > 65000:
        raise ValueError("comment too large")
    seg = bytearray()
    seg += b"\xFF\xFE"
    seg += struct.pack(">H", len(comment) + 2)
    seg += comment
    off = 2
    while off + 4 <= len(data):
        if data[off] != 0xFF:
            break
        marker = data[off+1]
        if marker == 0xDA:  # SOS
            break
        if off + 4 > len(data):
            break
        seglen = struct.unpack(">H", data[off+2:off+4])[0]
        off += 2 + 2 + (seglen - 2)
    out = data[:off] + seg + data[off:]
    with open(out_path, "wb") as f:
        f.write(out)

def extract_jpeg_comments(in_path: str) -> List[bytes]:
    data = open(in_path, "rb").read()
    out: List[bytes] = []
    if not (len(data) >= 2 and data[0] == 0xFF and data[1] == 0xD8):
        raise ValueError("not a JPEG (missing SOI)")
    off = 2
    while off + 4 <= len(data):
        if data[off] != 0xFF:
            off += 1
            continue
        marker = data[off+1]
        if marker == 0xFE:  # COM
            seglen = struct.unpack(">H", data[off+2:off+4])[0]
            start = off + 4
            end   = start + (seglen - 2)
            out.append(bytes(data[start:end]))
            off = end
            continue
        if marker == 0xDA:  # SOS
            break
        seglen = struct.unpack(">H", data[off+2:off+4])[0]
        off += 2 + 2 + (seglen - 2)
    return out

# =========================
# Zero-width side channel
# =========================

ZW0 = "\u200c"  # 0
ZW1 = "\u200b"  # 1
ZWS = "\u200d\u200b\u200c\u200d"   # start
ZWE = "\u200d\u200c\u200b\u200d"   # end

def zw_encode(payload: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in payload)
    body = "".join(ZW1 if bit == "1" else ZW0 for bit in bits)
    return ZWS + body + ZWE

def zw_decode(text: str) -> bytes:
    start = text.find(ZWS)
    end   = text.find(ZWE, start + len(ZWS)) if start >= 0 else -1
    if start < 0 or end < 0:
        raise ValueError("zero-width block not found")

    block = text[start + len(ZWS): end]

    # Sanity: only our two codepoints should appear
    if any(ch not in (ZW0, ZW1) for ch in block):
        raise ValueError("corrupted zero-width block")

    # Map zero-width chars → bitstring
    bits = "".join("1" if ch == ZW1 else "0" for ch in block)

    if len(bits) % 8 != 0:
        raise ValueError("zero-width bitstream length not multiple of 8")

    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int(bits[i:i+8], 2))
    return bytes(out)

# =========================
# High-level helpers
# =========================

def prepare_photo_carrier_png(input_png: str, output_png: str, packed_share: bytes, *, keyword: str = "KEYBOOK") -> None:
    embed_png_text(input_png, output_png, keyword=keyword, text=packed_share)

def prepare_photo_carrier_jpeg(input_jpeg: str, output_jpeg: str, packed_share: bytes) -> None:
    embed_jpeg_comment(input_jpeg, output_jpeg, comment=packed_share)

def prepare_cover_paragraph(base_text: str, packed_share: bytes) -> str:
    return base_text.rstrip() + zw_encode(packed_share)

def extract_from_png(path: str, *, keyword: str = "KEYBOOK") -> List[bytes]:
    return extract_png_text(path, keyword)

def extract_from_jpeg(path: str) -> List[bytes]:
    return extract_jpeg_comments(path)
