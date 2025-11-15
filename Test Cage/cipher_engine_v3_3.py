"""
# cipher_engine_v3_3.py
# Cipher Engine v3.3  —  Educational reference (not a CSPRNG design)
#
# Key points:
# - 32-byte master keys; 32-byte per-message ephemerals.
# - Pure stdlib; deterministic; no I/O.
# - On-the-wire version tag: b"33" (two ASCII bytes: "v3.3").
#
# Wire layout (base64 payload with 4 random prefix bytes):
#   version(2="33")
#   include_masked(1)=1
#   salt(32)
#   key_info(32)              # msg_key ^ enc_key ^ salt
#   tran_info(32)             # msg_tran ^ tran_key ^ salt
#   ciphertext_bytes(...)     # includes hidden inner header (e.g., pad_len)
#   hmac_tag(64)              # HMAC-SHA512 over (outer_header + ciphertext)
#
# v3.1 change:
#   - Stream and permutation PRNG seeds are derived from pad_len as well as the combined keys
#     (domain-separated with labels "stream" and "perm"). This increases message-binding and avalanche
#     without changing the external API.
#
# v3.2 internal changes (API/wire compatible with v3.1 except version tag):
#   - Huffman tie-breaking randomized via PRNG seeded from combined_key (label b"huff-tie")
#   - Bit-level permutation of the Huffman bitstream (pre-stream) using combined_tran + pad_len (label b"bitperm")
#   - Stream and permutation PRNG seeds include pad_len (as in v3.1; labels b"stream", b"perm")
#
# v3.3 internals (differences vs v3.2):
#   - OUTER/INNER header split: pad_len (and future flags) are moved into an
#     inner header that is appended pre-permutation, then globally permuted.
#     Result: no pad_len in the visible header; ciphertext looks flatter.
#   - Two permutations:
#       P1 (byte-level, pad-dependent)   : over main payload only (not inner bytes)
#       P0 (byte-level, pad-independent) : over full payload+inner bytes (final)
#   - Tie-randomized Huffman (seeded from combined_key).
#   - Bit-level permutation of Huffman-packed bytes (seeded from combined_tran + pad_len).
#   - Stream transform & P1 seeds include pad_len.
#
# Decrypt order mirrors encrypt and recovers inner header BEFORE any pad-dependent steps.
#
# Copyright:
#   (c) 2025 Robert Dowell. Educational use encouraged.
"""
from __future__ import annotations
import os, base64, random, hashlib, hmac
from typing import Union, Dict, List

BytesLike = Union[bytes, bytearray, memoryview]

__all__ = [
    "CipherEngine32x32",
    "encrypt_bytes_to_b64",
    "decrypt_b64_to_bytes",
    "encrypt_with_bundle",
    "decrypt_with_bundle",
]

# -------------------------
# Helpers / building blocks
# -------------------------
def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()

def _sha512_int(*parts: bytes) -> int:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "big")

def _seed_with_pad(key_bytes: bytes, label: bytes, pad_len: int) -> int:
    """
    Domain-separated seed that folds in pad_len (0..7).
    Labels used: b"stream", b"perm", b"bitperm".
    """
    if not (0 <= pad_len <= 7):
        raise ValueError("pad_len must be in 0..7")
    return _sha512_int(key_bytes, label, bytes([pad_len & 0xFF]))

def _permutation_indices(n: int, seed_int: int) -> List[int]:
    rng = random.Random(seed_int)
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

# ----- Huffman -----
class _HuffmanNode:
    __slots__ = ("ch", "freq", "left", "right")
    def __init__(self, ch=None, freq=0):
        self.ch = ch
        self.freq = freq
        self.left = None
        self.right = None

def _build_huffman_tree_from_key_random_ties(key_bytes: bytes, tie_seed: int) -> _HuffmanNode:
    """
    Build a keyed Huffman tree with randomized tie-breaking (deterministic from tie_seed).
    Frequencies derived from key bytes (NOT from plaintext).
    """
    if not key_bytes:
        key_bytes = b"\x01"
    freq = [(key_bytes[i % len(key_bytes)] & 0xFF) + 1 for i in range(256)]
    nodes = [_HuffmanNode(i, f) for i, f in enumerate(freq)]
    rng = random.Random(tie_seed)

    while len(nodes) > 1:
        # Primary sort by frequency; then shuffle equal-frequency runs
        nodes.sort(key=lambda n: n.freq)
        j = 0
        while j < len(nodes):
            k = j + 1
            fj = nodes[j].freq
            while k < len(nodes) and nodes[k].freq == fj:
                k += 1
            # Fisher-Yates within [j:k)
            for t in range(k - 1, j, -1):
                u = rng.randrange(j, t + 1)
                nodes[t], nodes[u] = nodes[u], nodes[t]
            j = k

        left = nodes.pop(0)
        right = nodes.pop(0)
        parent = _HuffmanNode(None, left.freq + right.freq)
        parent.left = left
        parent.right = right
        nodes.append(parent)

    return nodes[0]

def _build_codes_from_tree(root: _HuffmanNode) -> Dict[int, str]:
    codes: Dict[int, str] = {}
    def dfs(node, prefix: str):
        if node is None:
            return
        if node.ch is not None:
            codes[node.ch] = prefix or "0"
            return
        dfs(node.left, prefix + "0")
        dfs(node.right, prefix + "1")
    dfs(root, "")
    return codes

def _huffman_encode_with_key(plaintext_bytes: bytes, key_bytes: bytes, tie_seed: int):
    root = _build_huffman_tree_from_key_random_ties(key_bytes, tie_seed)
    codes = _build_codes_from_tree(root)
    bit_parts = [codes[b] for b in plaintext_bytes]
    bitstream = "".join(bit_parts)
    pad_len = (8 - (len(bitstream) % 8)) % 8
    if pad_len:
        bitstream += "0" * pad_len
    out = bytearray()
    for i in range(0, len(bitstream), 8):
        out.append(int(bitstream[i:i+8], 2))
    return bytes(out), pad_len

def _huffman_decode_with_key(encoded_bytes: bytes, key_bytes: bytes, pad_len: int, tie_seed: int):
    root = _build_huffman_tree_from_key_random_ties(key_bytes, tie_seed)
    bitstream = "".join(f"{b:08b}" for b in encoded_bytes)
    if pad_len:
        bitstream = bitstream[:-pad_len]
    decoded = bytearray()
    node = root
    for bit in bitstream:
        node = node.left if bit == "0" else node.right
        if node.ch is not None:
            decoded.append(node.ch)
            node = root
    return bytes(decoded)

# ----- Bit-level permutation around Huffman -----
def _bits_from_bytes(data: bytes) -> List[int]:
    return [ (b >> (7 - k)) & 1 for b in data for k in range(8) ]

def _bytes_from_bits(bits: List[int]) -> bytes:
    if not bits:
        return b""
    n = len(bits)
    out = bytearray((n + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i >> 3] |= 1 << (7 - (i & 7))
    return bytes(out)

def _apply_bit_permutation_packed(data_bytes: bytes, seed_int: int) -> bytes:
    if not data_bytes:
        return b""
    bits = _bits_from_bytes(data_bytes)
    perm = _permutation_indices(len(bits), seed_int)
    permuted_bits = [bits[i] for i in perm]
    return _bytes_from_bits(permuted_bits)

def _reverse_bit_permutation_packed(data_bytes: bytes, seed_int: int) -> bytes:
    if not data_bytes:
        return b""
    bits = _bits_from_bytes(data_bytes)
    perm = _permutation_indices(len(bits), seed_int)
    # invert
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    orig_bits = [bits[i] for i in inv]
    return _bytes_from_bits(orig_bits)

# ----- Stream (pad-dependent seed) -----
def _forward_stream_transform(data: bytes, key_bytes: bytes, max_rounds: int, pad_len: int) -> bytes:
    seed = _seed_with_pad(key_bytes, b"stream", pad_len)
    rng = random.Random(seed)
    out = bytearray()
    prev = 0
    for b in data:
        rounds = rng.randint(1, max_rounds)
        nl = b
        for _ in range(rounds):
            delta = rng.randint(1, 255)
            nl = (nl + delta) % 256
        out_byte = (nl + prev) % 256
        out.append(out_byte)
        prev = nl
    return bytes(out)

def _inverse_stream_transform(data: bytes, key_bytes: bytes, max_rounds: int, pad_len: int) -> bytes:
    seed = _seed_with_pad(key_bytes, b"stream", pad_len)
    rng = random.Random(seed)
    out = bytearray()
    prev = 0
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

def _compute_hmac(key_bytes: bytes, data_bytes: bytes) -> bytes:
    return hmac.new(key_bytes, data_bytes, hashlib.sha512).digest()

# ----- Inner header helpers -----
def _inner_mask_bytes(combined_key: bytes, n: int) -> bytes:
    # Mask for inner header bytes (pad-independent)
    return hashlib.sha512(combined_key + b"inner-mask").digest()[:n]

# -------------------------
# Engine (32-byte masters, 32-byte internals) — v3.3
# -------------------------
class CipherEngine32x32:
    VERSION      = b"33"     # "33" == v3.3
    SALT_LEN     = 32
    INFO_LEN     = 32
    TAG_LEN      = 64
    INNER_LEN    = 1         # bytes in inner header (currently: [flags<<3 | pad_len])

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
        return_b64: bool = True,
    ) -> Union[bytes, str]:
        """
        Encrypt plaintext bytes using 32-byte enc/tran master keys (and 32-byte internals).
        Returns base64 text by default (with 4 random prefix bytes), or raw bytes if return_b64=False.

        v3.3 pipeline:
            Huffman (tie-rand) -> bit-permutation -> stream -> P1 (pad-dependent, main only)
            -> append inner header (masked) -> P0 (pad-independent, main+inner) -> HMAC
        """
        cls._check_key("enc_key", enc_key)
        cls._check_key("tran_key", tran_key)
        if not isinstance(max_rounds, int) or max_rounds <= 0:
            raise ValueError("max_rounds must be a positive integer")

        pt = bytes(plaintext)
        salt = os.urandom(cls.SALT_LEN)

        # Per-message ephemerals (32 bytes each)
        msg_key  = os.urandom(32)
        msg_tran = os.urandom(32)

        # Combine masters + salt (+ mod 256), and masked infos via XOR
        combined_key  = bytes((a + b + c) % 256 for a, b, c in zip(msg_key,  enc_key,  salt))
        combined_tran = bytes((a + b + c) % 256 for a, b, c in zip(msg_tran, tran_key, salt))
        key_info  = bytes(a ^ b ^ c for a, b, c in zip(msg_key,  enc_key,  salt))
        tran_info = bytes(a ^ b ^ c for a, b, c in zip(msg_tran, tran_key, salt))
        include_masked = 1  # masters required

        # 1) Huffman encode (tie-randomized)
        tie_seed = _sha512_int(combined_key, b"huff-tie")
        huff_packed, pad_len = _huffman_encode_with_key(pt, combined_key, tie_seed)

        # 2) Bit-level permutation (pre-stream), seeded by combined_tran + pad_len
        bitperm_seed = _seed_with_pad(combined_tran, b"bitperm", pad_len)
        huff_packed_scrambled = _apply_bit_permutation_packed(huff_packed, bitperm_seed)

        # 3) Stream forward (pad-dependent seed)
        transformed = _forward_stream_transform(huff_packed_scrambled, combined_key, max_rounds, pad_len)  # bytes, length n
        n = len(transformed)

        # 4) P1 (pad-dependent) over MAIN ONLY (length n)
        perm1_seed = _seed_with_pad(combined_tran, b"perm", pad_len)
        perm1 = _permutation_indices(n, perm1_seed)
        main_p1 = _apply_permutation(transformed, perm1)

        # 5) Inner header (masked), appended after P1 (length K=INNER_LEN)
        #    Currently: inner0 = (flags<<3) | pad_len, with flags=0
        inner0 = ((0 & 0x1F) << 3) | (pad_len & 0x07)
        mask = _inner_mask_bytes(combined_key, cls.INNER_LEN)
        inner_bytes = bytes([inner0 ^ mask[0]])

        # Concatenate MAIN+INNER (pre-P0 buffer)
        pre_p0 = main_p1 + inner_bytes  # length n + K

        # 6) P0 (pad-independent) over FULL buffer (MAIN+INNER)
        perm0_seed = _sha512_int(combined_tran, b"perm0")
        perm0 = _permutation_indices(n + cls.INNER_LEN, perm0_seed)
        ciphertext_bytes = _apply_permutation(pre_p0, perm0)

        # OUTER header (no pad_len here)
        header = (
            cls.VERSION +
            bytes([include_masked]) +
            salt +
            key_info +
            tran_info
        )
        blob = header + ciphertext_bytes

        # HMAC
        hmac_key = combined_key + combined_tran  # 64 bytes
        tag = _compute_hmac(hmac_key, blob)
        final_blob = blob + tag

        if not return_b64:
            return final_blob
        prefix = os.urandom(4)
        return base64.b64encode(prefix + final_blob).decode("ascii")

    @classmethod
    def decrypt(
        cls,
        ciphertext: Union[str, bytes],
        *,
        enc_key: bytes,
        tran_key: bytes,
        max_rounds: int = 5,
        is_b64: bool = True,
    ) -> bytes:
        """
        Decrypt to plaintext bytes.

        v3.3 mirror:
            Verify HMAC -> P0^-1 (pad-independent) to get [MAIN_P1 || INNER]
            -> extract/unmask inner -> derive pad_len
            -> P1^-1 (pad-dependent) over MAIN only
            -> inverse stream -> reverse bit-perm -> Huffman decode
        """
        cls._check_key("enc_key", enc_key)
        cls._check_key("tran_key", tran_key)
        if not isinstance(max_rounds, int) or max_rounds <= 0:
            raise ValueError("max_rounds must be a positive integer")

        data = ciphertext
        if isinstance(data, str):
            data = data.encode("ascii")
        if is_b64:
            data = base64.b64decode(data)
            data = data[4:]  # drop random 4-byte prefix

        # Parse OUTER header
        off = 0
        version = data[off:off+2]; off += 2
        if version != cls.VERSION:
            raise ValueError("Unsupported version (expecting v3.3)")
        include_masked = data[off]; off += 1  # kept for structure; expected 1
        salt = data[off:off+cls.SALT_LEN]; off += cls.SALT_LEN
        key_info  = data[off:off+cls.INFO_LEN]; off += cls.INFO_LEN
        tran_info = data[off:off+cls.INFO_LEN]; off += cls.INFO_LEN

        encrypted = data[off:-cls.TAG_LEN]
        tag       = data[-cls.TAG_LEN:]

        # Rebuild combined keys
        msg_key  = bytes(a ^ b ^ c for a, b, c in zip(key_info,  enc_key,  salt))
        msg_tran = bytes(a ^ b ^ c for a, b, c in zip(tran_info, tran_key, salt))
        combined_key  = bytes((a + b + c) % 256 for a, b, c in zip(msg_key,  enc_key,  salt))
        combined_tran = bytes((a + b + c) % 256 for a, b, c in zip(msg_tran, tran_key, salt))

        # Verify HMAC before any reversible work
        blob = data[:-cls.TAG_LEN]
        hmac_key = combined_key + combined_tran
        tag2 = _compute_hmac(hmac_key, blob)
        if not hmac.compare_digest(tag, tag2):
            raise ValueError("HMAC verification failed")

        # 1) Undo P0 (pad-independent) over FULL buffer
        perm0_seed = _sha512_int(combined_tran, b"perm0")
        perm0 = _permutation_indices(len(encrypted), perm0_seed)
        pre_p0 = _reverse_permutation(encrypted, perm0)

        # Partition MAIN_P1 and INNER (INNER_LEN bytes at the end)
        if len(pre_p0) < cls.INNER_LEN:
            raise ValueError("Ciphertext too short")
        main_p1 = pre_p0[:-cls.INNER_LEN]
        inner_bytes = pre_p0[-cls.INNER_LEN:]

        # Extract pad_len from inner header
        mask = _inner_mask_bytes(combined_key, cls.INNER_LEN)
        inner0 = inner_bytes[0] ^ mask[0]
        pad_len = inner0 & 0x07
        flags   = inner0 >> 3  # reserved for future use (currently 0)

        # 2) Undo P1 (pad-dependent) over MAIN only
        n = len(main_p1)
        perm1_seed = _seed_with_pad(combined_tran, b"perm", pad_len)
        perm1 = _permutation_indices(n, perm1_seed)
        main = _reverse_permutation(main_p1, perm1)

        # 3) Inverse stream (pad-dependent)
        recovered_stream = _inverse_stream_transform(main, combined_key, max_rounds, pad_len)

        # 4) Reverse bit-permutation
        bitperm_seed = _seed_with_pad(combined_tran, b"bitperm", pad_len)
        huff_packed = _reverse_bit_permutation_packed(recovered_stream, bitperm_seed)

        # 5) Huffman decode (tie-rand)
        tie_seed = _sha512_int(combined_key, b"huff-tie")
        recovered = _huffman_decode_with_key(huff_packed, combined_key, pad_len, tie_seed)
        return recovered

# -------------------------
# Convenience wrappers
# -------------------------
def encrypt_bytes_to_b64(plaintext: BytesLike, *, enc_key: bytes, tran_key: bytes, max_rounds: int = 5) -> str:
    return CipherEngine32x32.encrypt(
        plaintext, enc_key=enc_key, tran_key=tran_key,
        max_rounds=max_rounds, return_b64=True
    )

def decrypt_b64_to_bytes(ciphertext_b64: Union[str, bytes], *, enc_key: bytes, tran_key: bytes, max_rounds: int = 5) -> bytes:
    return CipherEngine32x32.decrypt(
        ciphertext_b64, enc_key=enc_key, tran_key=tran_key,
        max_rounds=max_rounds, is_b64=True
    )

def encrypt_with_bundle(plaintext: BytesLike, bundle: Dict[str, bytes], *, max_rounds: int = 5) -> str:
    """
    Expects bundle dict with at least 'enc' and 'tran' (both 32 bytes).
    Aux keys 'aux1'/'aux2' may be present but are unused here.
    """
    return encrypt_bytes_to_b64(
        plaintext, enc_key=bundle["enc"], tran_key=bundle["tran"], max_rounds=max_rounds
    )

def decrypt_with_bundle(ciphertext_b64: Union[str, bytes], bundle: Dict[str, bytes], *, max_rounds: int = 5) -> bytes:
    return decrypt_b64_to_bytes(
        ciphertext_b64, enc_key=bundle["enc"], tran_key=bundle["tran"], max_rounds=max_rounds
    )
