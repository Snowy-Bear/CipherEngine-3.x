#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cipher_engine_v3_5.py   (MT5Obscure Version)
Educational, inspectable stream/permutation cipher pipeline with a 5×MT-based PRNG.

WHY THIS EXISTS (EDUCATIONAL GOALS)
-----------------------------------
This module is built to be read, tinkered with, and taught. It demonstrates:

1) Layering simple, visible transforms:
   - Huffman coding with key-biased, randomized tie-breaking
   - Bit-level permutation
   - Two directional stream passes (forward & reverse)
   - Two byte-level permutations (chunk-local and global)

2) Deterministic seeding & domain separation:
   Every stage obtains its PRNG seed by hashing key material + labels (+ pad_len/+ AAD/+ chunk).
   This shows how to avoid accidental cross-stage correlations without hiding the math.

3) A “non-black-box” PRNG that’s still robust for teaching:
   MT5Obscure uses five MT19937 engines with irregular clocking and a SHA-512 extractor.
   It intentionally avoids linear-state weaknesses of a single MT, while keeping the mechanics
   easy to describe (adds, xors, rotates, hash).

IMPORTANT DISCLAIMER
--------------------
This is an EDUCATIONAL cipher. It is NOT a replacement for vetted AEAD schemes (e.g., ChaCha20-Poly1305, AES-GCM).
It’s designed for clarity, determinism, and to show attack surfaces—not to compete with production crypto.

Public API
----------
- CipherEngine32x32.encrypt(plaintext, enc_key=32B, tran_key=32B, max_rounds:int=5, aad=b"", return_b64=True)
- CipherEngine32x32.decrypt(ciphertext_b64_or_bytes, enc_key=32B, tran_key=32B, max_rounds:int=5, aad=b"", is_b64=True)
- encrypt_bytes_to_b64 / decrypt_b64_to_bytes
- encrypt_with_bundle / decrypt_with_bundle

Wire format (base64 with 4 random prefix bytes):
  version(2="35") | include_masked(1)=1 | salt(32) | key_info(32) | tran_info(32) | ciphertext | tag(64)

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, base64, hashlib, hmac
from typing import Union, Dict, List

BytesLike = Union[bytes, bytearray, memoryview]

__all__ = [
    "CipherEngine32x32",
    "encrypt_bytes_to_b64",
    "decrypt_b64_to_bytes",
    "encrypt_with_bundle",
    "decrypt_with_bundle",
]

# ============================================================
# Section 0 — Hash helpers & AAD normalization
# (Teaches: canonicalization, binding of “context data”)
# ============================================================

def _norm_aad(aad) -> bytes:
    """Normalize Associated Data (AAD) into bytes so hashing is deterministic."""
    if aad is None:
        return b""
    if isinstance(aad, (bytes, bytearray, memoryview)):
        return bytes(aad)
    return str(aad).encode("utf-8")

def _sha512(data: bytes) -> bytes:
    """One-line SHA-512 convenience (teaches: we keep crypto visible)."""
    return hashlib.sha512(data).digest()

def _aad_hash(aad_bytes: bytes) -> bytes:
    """AAD is not secret, but we bind it everywhere with SHA-512 to prevent mixups."""
    return _sha512(aad_bytes)

def _sha512_int(*parts: bytes) -> int:
    """
    Hash parts → 512-bit int. Useful for PRNG seeds.
    (Teaches: converting hashes to integers deterministically)
    """
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "big")

# ============================================================
# Section 1 — MT5Obscure PRNG
# (Teaches: irregular clocking, mixing, extractor)
# ============================================================

def _rol32(x: int, r: int) -> int:
    """32-bit rotate left (ARX building block)."""
    x &= 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

class _StdRand:
    """
    Tiny wrapper around Python's Mersenne Twister to make the dependency explicit.
    We only use .getrandbits(32) here.
    """
    import random as _R
    def __init__(self, seed32: int):
        self.r = self._R.Random(seed32 & 0xFFFFFFFF)
    def word32(self) -> int:
        return self.r.getrandbits(32)

class MT5Obscure:
    """
    Five MT19937 engines with irregular clocking + SHA-512 extractor (duplex-style).

    Educational rationale:
    - Avoids the textbook "clone MT from 624 outputs" linearity problem.
    - Still deterministic & simple to reason about (no hidden magic).
    - The SHA-512 extractor “crushes” structure before we hand bytes to callers.

    Layout:
      Pair A = (mt0, mt1)
      Pair B = (mt2, mt3)
      Controller = mt4   → decides per-tick step counts (1..4) for each member of A and B.

    Each refill (“tick”):
      1) Controller emits 32 bits → four tiny step counts (1..4).
      2) Step pair A & B accordingly, collapsing each pair’s words with tiny ARX mixing.
      3) Combine (wA, wB, ctr, previous digest) via SHA-512 → 64 fresh bytes.
      4) Update chaining digest (duplex) to incorporate history (safe “jitter”).
    """

    PHI = 0x9E3779B1  # golden ratio constant; handy avalanche in 32-bit space

    def __init__(self, master_seed_int: int):
        # Derive 5 distinct 32-bit seeds and an initial chaining value from a big seed int.
        s = master_seed_int.to_bytes(64, "big", signed=False)
        self._mt = []
        for i in range(5):
            h = hashlib.sha256(b"mt5obscure|seed|" + s + bytes([i])).digest()
            self._mt.append(_StdRand(int.from_bytes(h[:4], "big")))
        self._ctr = 0
        self._chain = hashlib.sha512(b"init|" + s).digest()
        self._pool = b""
        self._off = 0

    def _step_pair(self, a: _StdRand, b: _StdRand, steps_a: int, steps_b: int) -> int:
        """
        Advance two MTs irregularly and mix their words (simple ARX).
        (Teaches: irregular clocking disrupts simple linear models)
        """
        x = 0
        n = max(steps_a, steps_b)
        for _ in range(n):
            if steps_a > 0:
                x ^= a.word32()
                steps_a -= 1
            if steps_b > 0:
                x = (x + _rol32(b.word32(), 7)) & 0xFFFFFFFF
                steps_b -= 1
        return x

    def _refill(self):
        """Produce 64 fresh bytes using controller-driven steps + SHA-512 extractor."""
        c = self._mt[4].word32()
        sa = 1 + (c & 3)
        sb = 1 + ((c >> 2) & 3)
        sc = 1 + ((c >> 4) & 3)
        sd = 1 + ((c >> 6) & 3)

        wA = self._step_pair(self._mt[0], self._mt[1], sa, sb)
        wB = self._step_pair(self._mt[2], self._mt[3], sc, sd)

        mix32 = (wA ^ _rol32(wB, 13) ^ ((wA + self.PHI) & 0xFFFFFFFF)) & 0xFFFFFFFF

        h = hashlib.sha512()
        h.update(b"obscure-extract")
        h.update(self._ctr.to_bytes(8, "big"))
        h.update(mix32.to_bytes(4, "big"))
        h.update(wA.to_bytes(4, "big"))
        h.update(wB.to_bytes(4, "big"))
        h.update(self._chain)  # absorb history (safe jitter)
        digest = h.digest()

        self._chain = hashlib.sha512(b"chain|" + digest).digest()
        self._ctr += 1
        self._pool = digest
        self._off = 0

    # ---- Public PRNG interface used by the engine ----

    def get(self, n: int) -> bytes:
        """Return n pseudo-random bytes (deterministic from seed)."""
        out = bytearray()
        while n > 0:
            if self._off >= len(self._pool):
                self._refill()
            take = min(n, len(self._pool) - self._off)
            out += self._pool[self._off : self._off + take]
            self._off += take
            n -= take
        return bytes(out)

    def randint(self, a: int, b: int) -> int:
        """Inclusive randint without modulo bias (teaches: rejection sampling)."""
        if b < a:
            a, b = b, a
        n = b - a + 1
        k = (n - 1).bit_length()
        while True:
            r = int.from_bytes(self.get((k + 7) // 8), "big") & ((1 << k) - 1)
            if r < n:
                return a + r

    def randrange(self, start: int, stop: int = None) -> int:
        """randrange stop or start,stop — used by permutation shuffles."""
        if stop is None:
            start, stop = 0, start
        if stop <= start:
            raise ValueError("empty range")
        return self.randint(start, stop - 1)

    def shuffle(self, seq):
        """Fisher–Yates shuffle driven by this PRNG (teaches: permutation sampling)."""
        for i in range(len(seq) - 1, 0, -1):
            j = self.randrange(i + 1)
            seq[i], seq[j] = seq[j], seq[i]

# ============================================================
# Section 2 — Deterministic seeding utilities
# (Teaches: message binding, domain separation, chunking)
# ============================================================

def _seed_with_pad_aad(key_bytes: bytes, label: bytes, pad_len: int, aad_hash: bytes) -> int:
    """
    Seed for a stage, bound to key material + label + pad_len + aad.
    (Teaches: different labels → different independent streams)
    """
    if not (0 <= pad_len <= 7):
        raise ValueError("pad_len must be in 0..7")
    return _sha512_int(key_bytes, label, bytes([pad_len & 0xFF]), aad_hash)

def _seed_with_pad_aad_chunk(key_bytes: bytes, label: bytes, pad_len: int, aad_hash: bytes, chunk_index: int) -> int:
    """As above, but also binds the chunk index so each chunk gets a distinct stream."""
    ci = chunk_index.to_bytes(4, "big", signed=False)
    return _sha512_int(key_bytes, label, bytes([pad_len & 0xFF]), aad_hash, ci)

def _permutation_indices(n: int, seed_int: int) -> List[int]:
    """
    Sample a permutation of range(n). Shows how a PRNG drives Fisher–Yates.
    (We use MT5Obscure to avoid linearity of plain MT.)
    """
    rng = MT5Obscure(seed_int)
    idx = list(range(n))
    rng.shuffle(idx)
    return idx

def _apply_permutation(data: bytes, perm: List[int]) -> bytes:
    return bytes(data[i] for i in perm)

def _reverse_permutation(data: bytes, perm: List[int]) -> bytes:
    out = bytearray(len(data))
    for i, p in enumerate(perm):
        out[p] = data[i]
    return bytes(out)

# ============================================================
# Section 3 — Keyed Huffman with randomized tie-breaking
# (Teaches: variable-length coding + key influence)
# ============================================================

class _HuffmanNode:
    __slots__ = ("ch", "freq", "left", "right")
    def __init__(self, ch=None, freq=0):
        self.ch = ch; self.freq = freq; self.left = None; self.right = None

def _build_huffman_tree_from_key_random_ties(key_bytes: bytes, tie_seed: int) -> _HuffmanNode:
    """
    Build a Huffman tree where equal-frequency merges are randomized by a PRNG
    seeded from key material. Teaches: 'random but reproducible'.
    """
    if not key_bytes:
        key_bytes = b"\x01"
    # Simple key-biased byte "frequency" source
    freq = [(key_bytes[i % len(key_bytes)] & 0xFF) + 1 for i in range(256)]
    nodes = [_HuffmanNode(i, f) for i, f in enumerate(freq)]
    rng = MT5Obscure(tie_seed)

    while len(nodes) > 1:
        nodes.sort(key=lambda n: n.freq)
        j = 0
        while j < len(nodes):
            k = j + 1; fj = nodes[j].freq
            while k < len(nodes) and nodes[k].freq == fj:
                k += 1
            # Randomly reorder equal-frequency block using our PRNG
            for t in range(k - 1, j, -1):
                u = rng.randrange(j, t + 1)
                nodes[t], nodes[u] = nodes[u], nodes[t]
            j = k
        left = nodes.pop(0); right = nodes.pop(0)
        parent = _HuffmanNode(None, left.freq + right.freq)
        parent.left = left; parent.right = right
        nodes.append(parent)
    return nodes[0]

def _build_codes_from_tree(root: _HuffmanNode) -> Dict[int, str]:
    codes: Dict[int, str] = {}
    def dfs(node, prefix: str):
        if node is None: return
        if node.ch is not None:
            codes[node.ch] = prefix or "0"; return
        dfs(node.left, prefix + "0"); dfs(node.right, prefix + "1")
    dfs(root, ""); return codes

def _huffman_encode_with_key(plaintext_bytes: bytes, key_bytes: bytes, tie_seed: int):
    """
    Keyed Huffman encode. Returns (packed_bytes, pad_len_bits).
    (Teaches: bit padding to full bytes)
    """
    root = _build_huffman_tree_from_key_random_ties(key_bytes, tie_seed)
    codes = _build_codes_from_tree(root)
    bitstream = "".join(codes[b] for b in plaintext_bytes)
    pad_len = (8 - (len(bitstream) % 8)) % 8
    if pad_len:
        bitstream += "0" * pad_len
    out = bytearray()
    for i in range(0, len(bitstream), 8):
        out.append(int(bitstream[i:i+8], 2))
    return bytes(out), pad_len

def _huffman_decode_with_key(encoded_bytes: bytes, key_bytes: bytes, pad_len: int, tie_seed: int):
    """Inverse of the above (Teaches: prefix codes are uniquely decodable)."""
    root = _build_huffman_tree_from_key_random_ties(key_bytes, tie_seed)
    bitstream = "".join(f"{b:08b}" for b in encoded_bytes)
    if pad_len:
        bitstream = bitstream[:-pad_len]
    decoded = bytearray(); node = root
    for bit in bitstream:
        node = node.left if bit == "0" else node.right
        if node.ch is not None:
            decoded.append(node.ch); node = root
    return bytes(decoded)

# ============================================================
# Section 4 — Bit-level permutation around Huffman
# (Teaches: bit/byte views and indexing)
# ============================================================

def _bits_from_bytes(data: bytes) -> List[int]:
    return [(b >> (7 - k)) & 1 for b in data for k in range(8)]

def _bytes_from_bits(bits: List[int]) -> bytes:
    if not bits: return b""
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit: out[i >> 3] |= 1 << (7 - (i & 7))
    return bytes(out)

def _apply_bit_permutation_packed(data_bytes: bytes, seed_int: int) -> bytes:
    if not data_bytes: return b""
    bits = _bits_from_bytes(data_bytes)
    perm = _permutation_indices(len(bits), seed_int)
    return _bytes_from_bits([bits[i] for i in perm])

def _reverse_bit_permutation_packed(data_bytes: bytes, seed_int: int) -> bytes:
    if not data_bytes: return b""
    bits = _bits_from_bytes(data_bytes)
    perm = _permutation_indices(len(bits), seed_int)
    inv = [0]*len(perm)
    for i, p in enumerate(perm): inv[p] = i
    return _bytes_from_bits([bits[i] for i in inv])

# ============================================================
# Section 5 — Stream transforms (forward & reverse)
# (Teaches: sequential dependency, invertibility)
# ============================================================

def _stream_forward(data: bytes, key_bytes: bytes, max_rounds: int, pad_len: int, aad_hash: bytes) -> bytes:
    """
    Forward pass: for each byte, add 1..max_rounds random deltas (1..255), then add 'prev' (sequential link).
    Inverse reconstructs exactly by regenerating the same deltas and subtracting in reverse order.
    """
    seed = _seed_with_pad_aad(key_bytes, b"stream-fwd", pad_len, aad_hash)
    rng = MT5Obscure(seed)
    out = bytearray(); prev = 0
    for b in data:
        rounds = rng.randint(1, max_rounds)
        nl = b
        for _ in range(rounds):
            nl = (nl + rng.randint(1, 255)) % 256
        out_byte = (nl + prev) % 256
        out.append(out_byte)
        prev = nl
    return bytes(out)

def _inv_stream_forward(data: bytes, key_bytes: bytes, max_rounds: int, pad_len: int, aad_hash: bytes) -> bytes:
    seed = _seed_with_pad_aad(key_bytes, b"stream-fwd", pad_len, aad_hash)
    rng = MT5Obscure(seed)
    out = bytearray(); prev = 0
    for c in data:
        rounds = rng.randint(1, max_rounds)
        nl_inner = (c - prev) % 256
        deltas = [rng.randint(1, 255) for _ in range(rounds)]
        nl = nl_inner
        for d in reversed(deltas):
            nl = (nl - d) % 256
        out.append(nl)
        prev = nl_inner
    return bytes(out)

def _stream_reverse(data: bytes, key_bytes: bytes, max_rounds: int, pad_len: int, aad_hash: bytes) -> bytes:
    """
    Reverse pass: same idea as forward, but processes right→left and chains to 'next' instead of 'prev'.
    """
    seed = _seed_with_pad_aad(key_bytes, b"stream-rev", pad_len, aad_hash)
    rng = MT5Obscure(seed)
    out = bytearray(data); nxt = 0
    for i in range(len(data)-1, -1, -1):
        rounds = rng.randint(1, max_rounds)
        nl = data[i]
        for _ in range(rounds):
            nl = (nl + rng.randint(1, 255)) % 256
        out[i] = (nl + nxt) % 256
        nxt = nl
    return bytes(out)

def _inv_stream_reverse(data: bytes, key_bytes: bytes, max_rounds: int, pad_len: int, aad_hash: bytes) -> bytes:
    seed = _seed_with_pad_aad(key_bytes, b"stream-rev", pad_len, aad_hash)
    rng = MT5Obscure(seed)
    out = bytearray(data); nxt = 0
    for i in range(len(data)-1, -1, -1):
        rounds = rng.randint(1, max_rounds)
        nl_inner = (data[i] - nxt) % 256
        deltas = [rng.randint(1, 255) for _ in range(rounds)]
        nl = nl_inner
        for d in reversed(deltas):
            nl = (nl - d) % 256
        out[i] = nl
        nxt = nl_inner
    return bytes(out)

def _compute_hmac(key_bytes: bytes, data_bytes: bytes) -> bytes:
    """Teaches: 'commitment to what was actually sent' (integrity + AAD binding)."""
    return hmac.new(key_bytes, data_bytes, hashlib.sha512).digest()

def _inner_mask_bytes(combined_key: bytes, aad_hash: bytes, n: int) -> bytes:
    """
    Mask for inner header (currently only pad_len). A tiny one-time pad derived per-message.
    """
    return hashlib.sha512(combined_key + b"inner-mask" + aad_hash).digest()[:n]

# ============================================================
# Section 6 — Engine (v3.5 layout with chunking & AAD)
# (Teaches: how stages compose and why order matters)
# ============================================================

CHUNK_SIZE = 4096  # fixed chunking (teaches: seed separation per chunk index)

class CipherEngine32x32:
    VERSION      = b"35"   # version tag for wire compatibility
    SALT_LEN     = 32
    INFO_LEN     = 32
    TAG_LEN      = 64
    INNER_LEN    = 1       # [flags<<3 | pad_len]

    @staticmethod
    def _check_key(name: str, k: bytes):
        if not isinstance(k, (bytes, bytearray, memoryview)):
            raise TypeError(f"{name} must be bytes-like")
        if len(k) != 32:
            raise ValueError(f"{name} must be exactly 32 bytes")

    @classmethod
    def encrypt(
        cls,
        plaintext: BytesLike,
        *,
        enc_key: bytes,
        tran_key: bytes,
        max_rounds: int = 5,
        aad: Union[BytesLike, str, None] = b"",
        return_b64: bool = True,
    ) -> Union[bytes, str]:
        """
        Pipeline (encrypt):
          Huffman(tie-rand) -> BitPerm -> [chunked: StreamFWD -> StreamREV -> P1] -> +INNER -> P0 -> HMAC(AAD)
        """
        cls._check_key("enc_key", enc_key); cls._check_key("tran_key", tran_key)
        if not isinstance(max_rounds, int) or max_rounds <= 0:
            raise ValueError("max_rounds must be a positive integer")

        pt = bytes(plaintext)
        aad_b = _norm_aad(aad)
        aad_h = _aad_hash(aad_b)

        # Per-message randomness (teaches: salts & ephemeral message keys)
        salt = os.urandom(cls.SALT_LEN)
        msg_key  = os.urandom(32)
        msg_tran = os.urandom(32)

        # Combine (teaches: independent mixed “views” of key material)
        combined_key  = bytes((a + b + c) % 256 for a, b, c in zip(msg_key,  enc_key,  salt))
        combined_tran = bytes((a + b + c) % 256 for a, b, c in zip(msg_tran, tran_key, salt))

        # Carry enough info to reconstruct msg_key/msg_tran on decrypt
        key_info  = bytes(a ^ b ^ c for a, b, c in zip(msg_key,  enc_key,  salt))
        tran_info = bytes(a ^ b ^ c for a, b, c in zip(msg_tran, tran_key, salt))
        include_masked = 1

        # ---- Huffman -> BitPerm ----
        tie_seed = _sha512_int(combined_key, b"huff-tie", aad_h)
        huff_packed, pad_len = _huffman_encode_with_key(pt, combined_key, tie_seed)

        bitperm_seed = _seed_with_pad_aad(combined_tran, b"bitperm", pad_len, aad_h)
        after_bitperm = _apply_bit_permutation_packed(huff_packed, bitperm_seed)

        # ---- Chunked: StreamFWD -> StreamREV -> P1 (per chunk) ----
        n_total = len(after_bitperm)
        chunks_out = []
        for ci, off in enumerate(range(0, n_total, CHUNK_SIZE)):
            chunk = after_bitperm[off: off + CHUNK_SIZE]

            s1 = _stream_forward(chunk, combined_key, max_rounds, pad_len, aad_h)
            s2 = _stream_reverse(s1,   combined_key, max_rounds, pad_len, aad_h)

            perm1_seed = _seed_with_pad_aad_chunk(combined_tran, b"perm-ch", pad_len, aad_h, ci)
            perm1 = _permutation_indices(len(s2), perm1_seed)
            out_chunk = _apply_permutation(s2, perm1)
            chunks_out.append(out_chunk)

        main_p1 = b"".join(chunks_out)  # length n_total

        # ---- Inner header (masked) + P0 (global permutation) ----
        inner0 = ((0 & 0x1F) << 3) | (pad_len & 0x07)
        inner = bytes([inner0 ^ _inner_mask_bytes(combined_key, aad_h, cls.INNER_LEN)[0]])
        pre_p0 = main_p1 + inner

        perm0_seed = _sha512_int(combined_tran, b"perm0", aad_h)
        perm0 = _permutation_indices(len(pre_p0), perm0_seed)
        ciphertext_bytes = _apply_permutation(pre_p0, perm0)

        # ---- Header + HMAC (binds AAD) ----
        header = cls.VERSION + bytes([include_masked]) + salt + key_info + tran_info
        hmac_key = combined_key + combined_tran
        tag = _compute_hmac(hmac_key, header + ciphertext_bytes + b"AAD" + aad_h)

        final_blob = header + ciphertext_bytes + tag
        if not return_b64:
            return final_blob
        prefix = os.urandom(4)  # extra base64 noise (teaches: shoulder surfing foil)
        return base64.b64encode(prefix + final_blob).decode("ascii")

    @classmethod
    def decrypt(
        cls,
        ciphertext: Union[str, bytes],
        *,
        enc_key: bytes,
        tran_key: bytes,
        max_rounds: int = 5,
        aad: Union[BytesLike, str, None] = b"",
        is_b64: bool = True,
    ) -> bytes:
        """Inverse pipeline; verifies HMAC before touching internals (teaches: fail closed)."""
        cls._check_key("enc_key", enc_key); cls._check_key("tran_key", tran_key)
        if not isinstance(max_rounds, int) or max_rounds <= 0:
            raise ValueError("max_rounds must be a positive integer")

        aad_b = _norm_aad(aad)
        aad_h = _aad_hash(aad_b)

        data = ciphertext.encode("ascii") if isinstance(ciphertext, str) else ciphertext
        if is_b64:
            data = base64.b64decode(data); data = data[4:]  # drop 4-byte prefix

        # ---- Parse OUTER header ----
        off = 0
        version = data[off:off+2]; off += 2
        if version != cls.VERSION:
            raise ValueError("Unsupported version (expecting v3.5)")
        include_masked = data[off]; off += 1
        salt = data[off:off+cls.SALT_LEN]; off += cls.SALT_LEN
        key_info  = data[off:off+cls.INFO_LEN]; off += cls.INFO_LEN
        tran_info = data[off:off+cls.INFO_LEN]; off += cls.INFO_LEN
        encrypted = data[off:-cls.TAG_LEN]
        tag       = data[-cls.TAG_LEN:]

        # ---- Rebuild per-message keys ----
        msg_key  = bytes(a ^ b ^ c for a, b, c in zip(key_info,  enc_key,  salt))
        msg_tran = bytes(a ^ b ^ c for a, b, c in zip(tran_info, tran_key, salt))
        combined_key  = bytes((a + b + c) % 256 for a, b, c in zip(msg_key,  enc_key,  salt))
        combined_tran = bytes((a + b + c) % 256 for a, b, c in zip(msg_tran, tran_key, salt))

        # ---- Verify HMAC before anything else ----
        header = data[:off]
        hmac_key = combined_key + combined_tran
        tag2 = _compute_hmac(hmac_key, header + encrypted + b"AAD" + aad_h)
        if not hmac.compare_digest(tag, tag2):
            raise ValueError("HMAC verification failed")

        # ---- P0^-1 (global permutation) ----
        perm0_seed = _sha512_int(combined_tran, b"perm0", aad_h)
        perm0 = _permutation_indices(len(encrypted), perm0_seed)
        pre_p0 = _reverse_permutation(encrypted, perm0)

        # ---- Split MAIN_P1 / INNER, recover pad_len ----
        if len(pre_p0) < cls.INNER_LEN:
            raise ValueError("Ciphertext too short")
        main_p1 = pre_p0[:-cls.INNER_LEN]
        inner_b = pre_p0[-cls.INNER_LEN:]
        inner0 = inner_b[0] ^ _inner_mask_bytes(combined_key, aad_h, cls.INNER_LEN)[0]
        pad_len = inner0 & 0x07
        # flags = inner0 >> 3  # reserved

        # ---- Undo chunk P1, then inverse streams per chunk ----
        n_total = len(main_p1)
        recovered_chunks = []
        for ci, off in enumerate(range(0, n_total, CHUNK_SIZE)):
            chunk_p1 = main_p1[off: off + CHUNK_SIZE]

            perm1_seed = _seed_with_pad_aad_chunk(combined_tran, b"perm-ch", pad_len, aad_h, ci)
            perm1 = _permutation_indices(len(chunk_p1), perm1_seed)
            inv = [0]*len(perm1)
            for i, p in enumerate(perm1): inv[p] = i
            s2 = _apply_permutation(chunk_p1, inv)

            s2_inv = _inv_stream_reverse(s2, combined_key, max_rounds, pad_len, aad_h)
            s1_inv = _inv_stream_forward(s2_inv, combined_key, max_rounds, pad_len, aad_h)

            recovered_chunks.append(s1_inv)

        after_bitperm = b"".join(recovered_chunks)

        # ---- UnBitPerm -> Huffman^-1 ----
        bitperm_seed = _seed_with_pad_aad(combined_tran, b"bitperm", pad_len, aad_h)
        huff_packed = _reverse_bit_permutation_packed(after_bitperm, bitperm_seed)

        tie_seed = _sha512_int(combined_key, b"huff-tie", aad_h)
        return _huffman_decode_with_key(huff_packed, combined_key, pad_len, tie_seed)

# ============================================================
# Section 7 — Convenience wrappers
# (Teaches: small, friendly API over the engine)
# ============================================================

def encrypt_bytes_to_b64(
    plaintext: BytesLike, *, enc_key: bytes, tran_key: bytes, max_rounds: int = 5, aad: Union[BytesLike, str, None] = b""
) -> str:
    return CipherEngine32x32.encrypt(
        plaintext, enc_key=enc_key, tran_key=tran_key, max_rounds=max_rounds, aad=aad, return_b64=True
    )

def decrypt_b64_to_bytes(
    ciphertext_b64: Union[str, bytes], *, enc_key: bytes, tran_key: bytes, max_rounds: int = 5, aad: Union[BytesLike, str, None] = b""
) -> bytes:
    return CipherEngine32x32.decrypt(
        ciphertext_b64, enc_key=enc_key, tran_key=tran_key, max_rounds=max_rounds, aad=aad, is_b64=True
    )

def encrypt_with_bundle(
    plaintext: BytesLike, bundle: Dict[str, bytes], *, max_rounds: int = 5, aad: Union[BytesLike, str, None] = b""
) -> str:
    """
    Expects bundle dict with at least 'enc' and 'tran' (both 32 bytes).
    Aux keys may exist but are not used directly here.
    """
    return encrypt_bytes_to_b64(plaintext, enc_key=bundle["enc"], tran_key=bundle["tran"], max_rounds=max_rounds, aad=aad)

def decrypt_with_bundle(
    ciphertext_b64: Union[str, bytes], bundle: Dict[str, bytes], *, max_rounds: int = 5, aad: Union[BytesLike, str, None] = b""
) -> bytes:
    return decrypt_b64_to_bytes(ciphertext_b64, enc_key=bundle["enc"], tran_key=bundle["tran"], max_rounds=max_rounds, aad=aad)


# ============================================================
# Optional: quick self-test (keeps demo minimal & deterministic)
# Run: python cipher_engine_v3_5_mt5obscure.py
# ============================================================

if __name__ == "__main__":
    # 32-byte demo keys (for classroom demos only!)
    enc = bytes(range(32))
    tran = bytes((i * 3 + 7) % 256 for i in range(32))
    msg  = b"Hello TNMOC! This is a friendly demo of v3.5 + MT5Obscure."
    aad  = "museum-demo"

    ct_b64 = encrypt_bytes_to_b64(msg, enc_key=enc, tran_key=tran, aad=aad)
    pt     = decrypt_b64_to_bytes(ct_b64, enc_key=enc, tran_key=tran, aad=aad)

    print("Ciphertext (b64):", ct_b64[:72] + "..." if isinstance(ct_b64, str) else ct_b64[:72])
    print("Plaintext OK?   :", pt == msg)
