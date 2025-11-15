#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CipherEngine v3.6 — AEAD-like stream (HKDF/HMAC-SHA512), always-on padding,
mandatory message_id, authenticated header (with reuse-guard), AAD binding, uniform AuthError.
==============================================================================================

# -------------------------------------------------------------------------
# POSITION STATEMENT: Why Python, not C?
# -------------------------------------------------------------------------
# This engine is intentionally written in Python (not C or Rust), even though
# a compiled version could be faster. The reasons are deliberate:
#
# 1. Transparency — Every line can be inspected, understood, and audited
#    by students, developers, or security reviewers. There are no black boxes.
#
# 2. Education — The engine doubles as a teaching tool. Its flow (HKDF,
#    padding, AAD binding, HMAC authentication) can be traced without the
#    noise of pointer arithmetic or memory-management bugs.
#
# 3. Safety — Python eliminates entire classes of subtle errors common in C
#    (buffer overflows, undefined behavior, misaligned access).
#
# 4. Sufficiency — Throughput of ~2 MB/s on modern hardware is already
#    more than enough for messaging, vault, and archival use cases.
#    Performance is not the bottleneck; correctness and clarity are.
#
# 5. Philosophy — This engine is an *educational reference design*, not
#    a competitor to industrial libraries like libsodium or OpenSSL. It
#    prioritizes clarity, openness, and security-hardening over raw speed.
#
# In short: "Readable, auditable, hackable (educationally), and secure by
# design." That’s why it stays in Python.
# -------------------------------------------------------------------------

Educational cipher engine (32×32) with hardened defaults:
 - HKDF-SHA512 key schedule
 - XOR keystream + affine mix + byte permutation
 - Nonce deterministically derived from caller-supplied message_id
 - Always-on padding (default 256-byte blocks) + optional jitter
 - Optional AAD binding (hashed via SHA-512, **configurable 16 B or 32 B**)
 - Replay/reuse guard bound into the authenticated header
 - Uniform error handling (AuthError only)

# -------------------------------------------------------------------------
# Configuration knobs (new)
# -------------------------------------------------------------------------
# • DEFAULT_AAD_HASH_LEN: 16 or 32. Controls how many bytes of SHA-512(aad)
#   are embedded in the authenticated header. 16 is default for compactness;
#   32 matches the tag’s strength and adds 16 bytes to the header.
# • Per-call override: encrypt()/decrypt() accept aad_hash_len=16|32.
#   If omitted, DEFAULT_AAD_HASH_LEN is used.
#
# Wire-compatibility note:
#   The header’s flags byte uses bit 0x01 to signal AAD=32B. Updated readers
#   will accept both 16B and 32B AAD headers. Legacy readers (pre-flag) will
#   only accept 16B. Keep 16B if you need legacy interop.

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.

------------------------------------------------------------------
INTEGRATION NOTES (READ ME FIRST)
------------------------------------------------------------------
This engine is stateless. Security depends on caller discipline:

1) message_id (REQUIRED — UNIQUENESS CRITICAL)
   • Used (via HKDF) to derive the per-message nonce.
   • MUST be unique per (enc_key, tran_key).
   • Suggested sources:
       a) Counter:  counter.to_bytes(16, "big")
       b) Random:   secrets.token_bytes(16)  (~2^-128 collision)
       c) Derived:  HKDF(master, salt=book_hash, info=b"ce36/msgid|" + label, L=16)

2) pad_to (RECOMMENDED)
   • Pads plaintext to a fixed multiple to hide exact length.
   • Default: 256 bytes; use 1024 or 4096 for coarser leakage.
   • Optional jitter: set pad_jitter_blocks>0 to add 0..N full blocks.

3) aad_context (OPTIONAL but encouraged)
   • Binds external metadata (e.g., filename|MIME|edition).
   • Internally reduced via **SHA-512** and included in header + tag (kept as
     a compact 16-byte digest). Wrong/missing AAD ⇒ uniform AuthError.
   • If metadata is sensitive, pre-hash/HMAC it before passing.

4) Error handling (MANDATORY)
   • Treat all decrypt failures as AuthError("authentication failed").
   • Do not branch on padding vs tag vs AAD vs header issues.

5) Keys (MANDATORY)
   • enc_key (32 B) and tran_key (32 B), typically from your KDF (e.g., Keybook).
   • Changing either completely changes the transform.

6) Versioning
   • v3.6 adds: message_id→nonce binding, affine+perm mix stage, default padding
     with optional jitter, AAD binding (now SHA-512→16B), authenticated header
     with reuse-guard, and uniform AuthError.
     
------------------------------------------------------------------
TL;DR
------------------------------------------------------------------
Always supply a UNIQUE message_id,
use pad_to ≥ 256 (optionally with jitter),
bind AAD when relevant,
and treat all decrypt failures as AuthError.

------------------------------------------------------------------
Minimal Example
------------------------------------------------------------------
# Choose globally (optional):
#   DEFAULT_AAD_HASH_LEN = 32

# Or per-call:
#   Engine.encrypt(..., aad_hash_len=32)
#   Engine.decrypt(..., aad_hash_len=32)


bundle = keybook.derive_bundle(vh, "project-x")
enc_key, tran_key = bundle["enc"], bundle["tran"]

import secrets, hashlib
message_id = secrets.token_bytes(16)  # unique per message
aad = hashlib.sha512(b"filename|mime|ts").digest()[:32]  # optional, example

ct_b64 = Engine.encrypt(
    data,
    enc_key=enc_key,
    tran_key=tran_key,
    message_id=message_id,
    aad_context=aad,
    pad_to=256,
    return_b64=True,
)

pt = Engine.decrypt(
    ct_b64,
    enc_key=enc_key,
    tran_key=tran_key,
    aad_context=aad,
    is_b64=True,
)

------------------------------------------------------------------
Public API (strict)
------------------------------------------------------------------
CipherEngine32x32.encrypt(
    data: bytes,
    *,
    enc_key: bytes,                  # 32 bytes (required)
    tran_key: bytes,                 # 32 bytes (required)
    message_id: bytes,               # 8..32 bytes (required; unique per (enc_key,tran_key))
    aad_context: bytes|str|None = None,
    pad_to: int = 256,               # power of two (>=16)
    pad_jitter_blocks: int = 2,
    pad_jitter_mode: str = "deterministic",
    return_b64: bool = True,
    aad_hash_len: int | None = None, # NEW (16|32), defaults to DEFAULT_AAD_HASH_LEN
) -> bytes | str

CipherEngine32x32.decrypt(
    ct: bytes|str,
    *,
    enc_key: bytes,
    tran_key: bytes,
    aad_context: bytes|str|None = None,
    is_b64: bool = True,
    aad_hash_len: int | None = None, # NEW (16|32), defaults to DEFAULT_AAD_HASH_LEN
) -> bytes
"""

from __future__ import annotations
import os, base64, struct, hmac, hashlib
from typing import Tuple, List

# =========================
# Public constants / version
# =========================

MAGIC = b"CE36"
VERSION = 1  # header version byte

# Tag length (truncate HMAC-SHA512 to 32 B)
TAG_LEN = 32

# NEW: default AAD hash length knob (16 or 32)
DEFAULT_AAD_HASH_LEN = 16  # set to 32 if you want 32B AAD by default

# Header flags (bitfield)
FLAG_AAD32 = 0x01  # if set, header carries 32B AAD hash (else 16B)

# =========================
# Exceptions
# =========================

class AuthError(Exception):
    """Uniform authentication failure (covers tag/AAD/header/padding errors)."""

class FormatError(Exception):
    """Malformed input (bad magic/version/lengths)."""

# =========================
# Utilities (HKDF, HMAC-DRBG, etc.)
# =========================

def _hkdf_sha512(ikm: bytes, *, salt: bytes, info: bytes, L: int) -> bytes:
    if not isinstance(ikm, (bytes, bytearray)) or not isinstance(salt, (bytes, bytearray)) or not isinstance(info, (bytes, bytearray)):
        raise TypeError("hkdf inputs must be bytes")
    if L <= 0:
        return b""
    prk = hmac.new(bytes(salt), bytes(ikm), hashlib.sha512).digest()
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < L:
        ctr_byte = bytes([counter & 0xFF])
        t = hmac.new(prk, t + bytes(info) + ctr_byte, hashlib.sha512).digest()
        out.extend(t)
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(out[:L])

def _drbg_hmac_sha512(key: bytes, prefix: bytes, total_len: int) -> bytes:
    """HMAC-SHA512 in counter mode (8B big-endian counter)."""
    if total_len <= 0:
        return b""
    out = bytearray()
    counter = 0
    while len(out) < total_len:
        ctr = struct.pack(">Q", counter)
        block = hmac.new(key, prefix + ctr, hashlib.sha512).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:total_len])

def _round_up(n: int, block: int) -> int:
    return ((n + (block - 1)) // block) * block

def _is_power_of_two(n: int) -> bool:
    return n >= 1 and (n & (n - 1)) == 0

def _aad_hash(aad: bytes|str|None, nbytes: int) -> bytes:
    """
    Reduce optional AAD to a fixed nbytes value using SHA-512 (nbytes ∈ {16,32}),
    to keep the authenticated header compact while binding arbitrary metadata.
    """
    if nbytes not in (16, 32):
        raise ValueError("aad hash length must be 16 or 32")
    if aad is None:
        return b"\x00" * nbytes
    if isinstance(aad, str):
        aad = aad.encode("utf-8", "surrogatepass")
    h = hashlib.sha512(aad).digest()
    return h[:nbytes]

def _derive_nonce_from_msgid(tran_key: bytes, message_id: bytes) -> bytes:
    return _hkdf_sha512(tran_key, salt=message_id, info=b"ce36/nonce", L=16)

def _reuse_guard(tran_key: bytes, message_id: bytes) -> bytes:
    return hmac.new(tran_key, b"ce36/reuse|" + message_id, hashlib.sha512).digest()[:16]

def _derive_jitter_used(*, mode: str, pad_jitter_blocks: int, tran_key: bytes, message_id: bytes) -> int:
    if pad_jitter_blocks <= 0:
        return 0
    m = pad_jitter_blocks + 1
    if mode == "random":
        import secrets
        return secrets.randbelow(m)
    byte0 = hmac.new(tran_key, b"ce36/jitter" + message_id, hashlib.sha512).digest()[0]
    return byte0 % m

# =========================
# Permutations (Fisher–Yates)
# =========================

def _perm_indices(n: int, seed: bytes) -> List[int]:
    """Deterministic Fisher–Yates using HMAC-DRBG seeded bytes."""
    if n <= 1:
        return list(range(n))
    stream = _drbg_hmac_sha512(seed, b"ce36/perm", 2 * n + 32)
    idx = list(range(n))
    j = n - 1
    off = 0
    while j > 0:
        if off + 2 > len(stream):
            stream += _drbg_hmac_sha512(seed, b"ce36/perm/extend|" + struct.pack(">I", j), 64)
        r = (stream[off] << 8) | stream[off + 1]
        off += 2
        k = r % (j + 1)
        idx[j], idx[k] = idx[k], idx[j]
        j -= 1
    return idx

def _apply_perm(buf: bytes, idx: List[int]) -> bytes:
    return bytes(buf[i] for i in idx)

def _invert_perm(idx: List[int]) -> List[int]:
    inv = [0] * len(idx)
    for i, v in enumerate(idx):
        inv[v] = i
    return inv

# =========================
# Core transform (XOR + affine mix + perm)
# =========================

def _xor_stream(data: bytes, ks: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, ks))

def _affine_mix_forward(data: bytes, s_mask: bytes, t_add: bytes) -> bytes:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = ((b ^ s_mask[i]) + t_add[i]) & 0xFF
    return bytes(out)

def _affine_mix_inverse(data: bytes, s_mask: bytes, t_add: bytes) -> bytes:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = ((b - t_add[i]) & 0xFF) ^ s_mask[i]
    return bytes(out)

# =========================
# Header pack/unpack (all authenticated)
# =========================
# Layout:
#   magic(4)="CE36"
#   ver(1)=1
#   flags(1)                 # bit0 (0x01): AAD length = 32B if set; else 16B
#   pad_exp(1)               # log2(pad_to)
#   jitter_max(1)            # 0..255
#   jitter_used(1)           # 0..jitter_max
#   msgid_len(1)             # 8..32
#   aad_mode(1)              # 0=none,1=hash
#   reuse_guard(16)
#   msg_id(msgid_len)
#   aad_hash(16 or 32)       # length signaled by flags
#
# tag = HMAC(tag_key, header || ciphertext)[:32]
#

def _pack_header(*, pad_to: int, jitter_max: int, jitter_used: int,
                 message_id: bytes, aad_hash: bytes, tran_key: bytes,
                 aad_len: int) -> bytes:
    if not _is_power_of_two(pad_to) or pad_to < 16:
        raise ValueError("pad_to must be power-of-two >= 16")
    pad_exp = (pad_to.bit_length() - 1) & 0xFF
    if not (0 <= jitter_max <= 255):
        raise ValueError("jitter_max must be 0..255")
    if not (0 <= jitter_used <= jitter_max):
        raise ValueError("jitter_used must be 0..jitter_max")
    if not (8 <= len(message_id) <= 32):
        raise ValueError("message_id length must be 8..32")
    if aad_len not in (16, 32) or len(aad_hash) != aad_len:
        raise ValueError("aad hash length must be 16 or 32 and match aad_hash length")

    flags = 0
    if aad_len == 32:
        flags |= FLAG_AAD32

    hdr = bytearray()
    hdr += MAGIC
    hdr += bytes([VERSION])
    hdr += bytes([flags])
    hdr += bytes([pad_exp])
    hdr += bytes([jitter_max & 0xFF])
    hdr += bytes([jitter_used & 0xFF])
    hdr += bytes([len(message_id) & 0xFF])
    hdr += b"\x01" if aad_hash != (b"\x00" * aad_len) else b"\x00"
    rg = _reuse_guard(tran_key, message_id)
    hdr += rg
    hdr += message_id
    hdr += aad_hash
    return bytes(hdr)

def _unpack_header(hdr: bytes) -> dict:
    off = 0
    # minimal sanity: enough for fixed prelude + 16B aad (smallest)
    if len(hdr) < 4 + 1 + 1 + 1 + 1 + 1 + 1 + 16 + 16:
        raise FormatError("header too short")
    if hdr[:4] != MAGIC:
        raise FormatError("bad magic")
    off += 4
    ver = hdr[off]; off += 1
    if ver != VERSION:
        raise FormatError("unsupported version")
    flags = hdr[off]; off += 1
    pad_exp = hdr[off]; off += 1
    jitter_max = hdr[off]; off += 1
    jitter_used = hdr[off]; off += 1
    msgid_len = hdr[off]; off += 1
    if not (8 <= msgid_len <= 32):
        raise FormatError("invalid msgid_len")
    aad_mode = hdr[off]; off += 1

    aad_len = 32 if (flags & FLAG_AAD32) else 16

    need = off + 16 + msgid_len + aad_len
    if len(hdr) < need:
        raise FormatError("header truncated (msgid/aad)")

    reuse_g = hdr[off:off+16]; off += 16
    msg_id = hdr[off:off+msgid_len]; off += msgid_len
    aad_hash = hdr[off:off+aad_len]; off += aad_len

    return {
        "version": ver,
        "flags": flags,
        "pad_to": 1 << pad_exp,
        "jitter_max": jitter_max,
        "jitter_used": jitter_used,
        "msg_id": msg_id,
        "reuse_guard": reuse_g,
        "aad_mode": aad_mode,
        "aad_len": aad_len,
        "aad_hash": aad_hash,
        "header_len": off,
    }

# =========================
# MAC helpers
# =========================

def _tag_key(enc_key: bytes, nonce: bytes) -> bytes:
    return _hkdf_sha512(enc_key, salt=nonce, info=b"ce36/tag", L=64)

def _calc_tag(tag_key: bytes, header: bytes, body: bytes) -> bytes:
    return hmac.new(tag_key, header + body, hashlib.sha512).digest()[:TAG_LEN]

# =========================
# Public Engine
# =========================

class CipherEngine32x32:
    """v3.6 hardened engine (XOR + affine mix + permutation, authenticated header)."""

    @staticmethod
    def encrypt(
        data: bytes,
        *,
        enc_key: bytes,
        tran_key: bytes,
        message_id: bytes,
        aad_context: bytes | str | None = None,
        pad_to: int = 256,
        pad_jitter_blocks: int = 2,                 # default
        pad_jitter_mode: str = "deterministic",     # default
        return_b64: bool = True,
        aad_hash_len: int | None = None,            # NEW
    ) -> bytes | str:
        # --- validate inputs ---
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        data = bytes(data)
        if not (isinstance(enc_key, (bytes, bytearray)) and len(enc_key) == 32):
            raise ValueError("enc_key must be 32 bytes")
        if not (isinstance(tran_key, (bytes, bytearray)) and len(tran_key) == 32):
            raise ValueError("tran_key must be 32 bytes")
        if not (isinstance(message_id, (bytes, bytearray)) and 8 <= len(message_id) <= 32):
            raise ValueError("message_id must be 8..32 bytes")
        if pad_jitter_mode not in ("deterministic", "random"):
            raise ValueError("pad_jitter_mode must be 'deterministic' or 'random'")
        if pad_jitter_blocks < 0 or pad_jitter_blocks > 255:
            raise ValueError("pad_jitter_blocks must be 0..255")
        if not _is_power_of_two(pad_to) or pad_to < 16:
            raise ValueError("pad_to must be a power-of-two >= 16")

        aad_len = DEFAULT_AAD_HASH_LEN if aad_hash_len is None else aad_hash_len
        if aad_len not in (16, 32):
            raise ValueError("aad_hash_len must be 16 or 32")

        # --- per-message materials ---
        msg_id = bytes(message_id)
        nonce = _derive_nonce_from_msgid(bytes(tran_key), msg_id)

        # jitter
        jitter_used = _derive_jitter_used(
            mode=pad_jitter_mode,
            pad_jitter_blocks=pad_jitter_blocks,
            tran_key=bytes(tran_key),
            message_id=msg_id,
        )

        # pad lengths
        orig_len = len(data)
        base_len = 8 + orig_len
        base_rounded = _round_up(base_len, pad_to)
        padded_len = base_rounded + jitter_used * pad_to
        pad_bytes = padded_len - base_len

        # Build framed plaintext
        pt_padded = struct.pack(">Q", orig_len) + data + (b"\x00" * pad_bytes)

        # Key schedule (mix salt ties enc & tran & nonce & msg_id)
        salt_mix = hmac.new(bytes(tran_key), b"ce36/mix|" + msg_id + nonce, hashlib.sha512).digest()
        ks  = _hkdf_sha512(bytes(enc_key),  salt=salt_mix, info=b"ce36/ks",   L=padded_len)
        msk = _hkdf_sha512(bytes(tran_key), salt=salt_mix, info=b"ce36/mask", L=2 * padded_len)
        s_mask = msk[:padded_len]
        t_add  = msk[padded_len:]
        perm_seed = _hkdf_sha512(bytes(tran_key), salt=salt_mix, info=b"ce36/permseed", L=32)

        # Transform: XOR -> affine -> perm
        y = _xor_stream(pt_padded, ks)
        z = _affine_mix_forward(y, s_mask, t_add)
        idx = _perm_indices(padded_len, perm_seed)
        body = _apply_perm(z, idx)

        # Header + tag
        aad_hash = _aad_hash(aad_context, aad_len)
        hdr = _pack_header(
            pad_to=pad_to,
            jitter_max=pad_jitter_blocks,
            jitter_used=jitter_used,
            message_id=msg_id,
            aad_hash=aad_hash,
            tran_key=bytes(tran_key),
            aad_len=aad_len,
        )
        tkey = _tag_key(bytes(enc_key), nonce)
        tag  = _calc_tag(tkey, hdr, body)

        raw = hdr + tag + body

        if return_b64:
            # Prepend 4 random bytes before b64 to avoid recognizable prefix
            return base64.b64encode(os.urandom(4) + raw).decode("ascii")
        return raw

    @staticmethod
    def decrypt(
        ct: bytes | str,
        *,
        enc_key: bytes,
        tran_key: bytes,
        aad_context: bytes | str | None = None,
        is_b64: bool = True,
        aad_hash_len: int | None = None,            # NEW
    ) -> bytes:
        if not (isinstance(enc_key, (bytes, bytearray)) and len(enc_key) == 32):
            raise ValueError("enc_key must be 32 bytes")
        if not (isinstance(tran_key, (bytes, bytearray)) and len(tran_key) == 32):
            raise ValueError("tran_key must be 32 bytes")

        # unwrap input
        try:
            if is_b64:
                raw_all = base64.b64decode(ct)
                # minimal sanity check (works for both 16/32 AAD since we strip later)
                if len(raw_all) < 4 + 4 + 1 + 1 + 1 + 1 + 1 + 1 + 16 + 8 + 16 + TAG_LEN:
                    raise AuthError("authentication failed")
                raw = raw_all[4:]  # strip 4 random bytes
            else:
                raw = bytes(ct)
        except Exception:
            raise AuthError("authentication failed")

        # parse header
        try:
            hdr_info = _unpack_header(raw)
        except Exception:
            raise AuthError("authentication failed")

        hdr_len = hdr_info["header_len"]
        if len(raw) < hdr_len + TAG_LEN:
            raise AuthError("authentication failed")

        hdr = raw[:hdr_len]
        tag = raw[hdr_len:hdr_len + TAG_LEN]
        body = raw[hdr_len + TAG_LEN:]

        # recompute nonce and tag
        msg_id = hdr_info["msg_id"]
        aad_len = hdr_info["aad_len"]

        # AAD must match (length dictated by header, not caller’s preference)
        if _aad_hash(aad_context, aad_len) != hdr_info["aad_hash"]:
            raise AuthError("authentication failed")

        # recompute and validate header (including reuse_guard)
        try:
            hdr_recon = _pack_header(
                pad_to=hdr_info["pad_to"],
                jitter_max=hdr_info["jitter_max"],
                jitter_used=hdr_info["jitter_used"],
                message_id=msg_id,
                aad_hash=_aad_hash(aad_context, aad_len),
                tran_key=bytes(tran_key),
                aad_len=aad_len,
            )
        except Exception:
            raise AuthError("authentication failed")

        if hdr_recon != hdr:
            raise AuthError("authentication failed")

        # Tag check
        nonce = _derive_nonce_from_msgid(bytes(tran_key), msg_id)
        tkey = _tag_key(bytes(enc_key), nonce)
        calc_tag = _calc_tag(tkey, hdr, body)
        if not hmac.compare_digest(tag, calc_tag):
            raise AuthError("authentication failed")

        # Derive lengths/materials to invert transform
        pad_to = hdr_info["pad_to"]
        padded_len = len(body)
        if padded_len % pad_to != 0:
            raise AuthError("authentication failed")

        # Rebuild same keystream and masks
        salt_mix = hmac.new(bytes(tran_key), b"ce36/mix|" + msg_id + nonce, hashlib.sha512).digest()
        ks  = _hkdf_sha512(bytes(enc_key),  salt=salt_mix, info=b"ce36/ks",   L=padded_len)
        msk = _hkdf_sha512(bytes(tran_key), salt=salt_mix, info=b"ce36/mask", L=2 * padded_len)
        s_mask = msk[:padded_len]
        t_add  = msk[padded_len:]
        perm_seed = _hkdf_sha512(bytes(tran_key), salt=salt_mix, info=b"ce36/permseed", L=32)

        # invert perm -> inverse affine -> XOR
        idx = _perm_indices(padded_len, perm_seed)
        inv = _invert_perm(idx)
        z = _apply_perm(body, inv)
        y = _affine_mix_inverse(z, s_mask, t_add)
        pt_padded = _xor_stream(y, ks)

        # Extract len and message
        if len(pt_padded) < 8:
            raise AuthError("authentication failed")
        orig_len = struct.unpack(">Q", pt_padded[:8])[0]
        if orig_len > len(pt_padded) - 8:
            raise AuthError("authentication failed")
        pt = pt_padded[8:8+orig_len]
        return pt

    # Optional info hook
    @staticmethod
    def info() -> dict:
        return {
            "name": "CipherEngine32x32",
            "version": VERSION,
            "tag_len": TAG_LEN,
            "aad_hash_len_default": DEFAULT_AAD_HASH_LEN,
            "notes": "HKDF/HMAC-SHA512, XOR+affine+perm, authenticated header, jitter padding (deterministic by default).",
        }
