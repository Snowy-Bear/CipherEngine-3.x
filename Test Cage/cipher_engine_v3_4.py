"""
# cipher_engine_v3_4.py
# Cipher Engine v3.4  —  Educational reference (not a CSPRNG design)
#
# v3.4 internals (differences vs v3.3)
#   + Adds a reverse stream pass (right->left) with its own pad-dependent seed.
#     Encrypt:  Huffman(tie) -> BitPerm -> StreamFWD -> StreamREV -> P1(pad) -> +Inner -> P0
#     Decrypt:  P0^-1 -> peel Inner(pad_len) -> P1^-1 -> InvStreamREV -> InvStreamFWD -> UnBitPerm -> Huffman^-1
#
#     Wire layout unchanged from v3.3 (outer/inner split). Version tag now b"34".
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
# Hash/seeding & permutation helpers
# -------------------------
def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()

def _sha512_int(*parts: bytes) -> int:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "big")

def _seed_with_pad(key_bytes: bytes, label: bytes, pad_len: int) -> int:
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

# -------------------------
# Huffman (keyed, tie-randomized)
# -------------------------
class _HuffmanNode:
    __slots__ = ("ch", "freq", "left", "right")
    def __init__(self, ch=None, freq=0):
        self.ch = ch; self.freq = freq; self.left = None; self.right = None

def _build_huffman_tree_from_key_random_ties(key_bytes: bytes, tie_seed: int) -> _HuffmanNode:
    if not key_bytes:
        key_bytes = b"\x01"
    freq = [(key_bytes[i % len(key_bytes)] & 0xFF) + 1 for i in range(256)]
    nodes = [_HuffmanNode(i, f) for i, f in enumerate(freq)]
    rng = random.Random(tie_seed)
    while len(nodes) > 1:
        nodes.sort(key=lambda n: n.freq)
        j = 0
        while j < len(nodes):
            k = j + 1; fj = nodes[j].freq
            while k < len(nodes) and nodes[k].freq == fj:
                k += 1
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
    root = _build_huffman_tree_from_key_random_ties(key_bytes, tie_seed)
    codes = _build_codes_from_tree(root)
    bitstream = "".join(codes[b] for b in plaintext_bytes)
    pad_len = (8 - (len(bitstream) % 8)) % 8
    if pad_len: bitstream += "0" * pad_len
    out = bytearray()
    for i in range(0, len(bitstream), 8):
        out.append(int(bitstream[i:i+8], 2))
    return bytes(out), pad_len

def _huffman_decode_with_key(encoded_bytes: bytes, key_bytes: bytes, pad_len: int, tie_seed: int):
    root = _build_huffman_tree_from_key_random_ties(key_bytes, tie_seed)
    bitstream = "".join(f"{b:08b}" for b in encoded_bytes)
    if pad_len: bitstream = bitstream[:-pad_len]
    decoded = bytearray(); node = root
    for bit in bitstream:
        node = node.left if bit == "0" else node.right
        if node.ch is not None:
            decoded.append(node.ch); node = root
    return bytes(decoded)

# -------------------------
# Bit-level permutation (around Huffman)
# -------------------------
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

# -------------------------
# Stream transforms (FWD + REV), pad-dependent seeds
# -------------------------
def _stream_forward(data: bytes, key_bytes: bytes, max_rounds: int, pad_len: int) -> bytes:
    seed = _seed_with_pad(key_bytes, b"stream-fwd", pad_len)
    rng = random.Random(seed)
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

def _inv_stream_forward(data: bytes, key_bytes: bytes, max_rounds: int, pad_len: int) -> bytes:
    seed = _seed_with_pad(key_bytes, b"stream-fwd", pad_len)
    rng = random.Random(seed)
    out = bytearray(); prev = 0
    for c in data:
        rounds = rng.randint(1, max_rounds)
        nl_inner = (c - prev) % 256
        deltas = [rng.randint(1, 255) for _ in range(rounds)]
        nl = nl_inner
        for d in reversed(deltas): nl = (nl - d) % 256
        out.append(nl)
        prev = nl_inner
    return bytes(out)

def _stream_reverse(data: bytes, key_bytes: bytes, max_rounds: int, pad_len: int) -> bytes:
    """Process right->left; chaining depends on next byte."""
    seed = _seed_with_pad(key_bytes, b"stream-rev", pad_len)
    rng = random.Random(seed)
    out = bytearray(data)  # will overwrite
    nxt = 0
    for i in range(len(data)-1, -1, -1):
        rounds = rng.randint(1, max_rounds)
        nl = data[i]
        for _ in range(rounds):
            nl = (nl + rng.randint(1, 255)) % 256
        out[i] = (nl + nxt) % 256
        nxt = nl
    return bytes(out)

def _inv_stream_reverse(data: bytes, key_bytes: bytes, max_rounds: int, pad_len: int) -> bytes:
    seed = _seed_with_pad(key_bytes, b"stream-rev", pad_len)
    rng = random.Random(seed)
    out = bytearray(data)
    nxt = 0
    for i in range(len(data)-1, -1, -1):
        rounds = rng.randint(1, max_rounds)
        nl_inner = (data[i] - nxt) % 256
        deltas = [rng.randint(1, 255) for _ in range(rounds)]
        nl = nl_inner
        for d in reversed(deltas): nl = (nl - d) % 256
        out[i] = nl
        nxt = nl_inner
    return bytes(out)

def _compute_hmac(key_bytes: bytes, data_bytes: bytes) -> bytes:
    return hmac.new(key_bytes, data_bytes, hashlib.sha512).digest()

def _inner_mask_bytes(combined_key: bytes, n: int) -> bytes:
    return hashlib.sha512(combined_key + b"inner-mask").digest()[:n]

# -------------------------
# Engine — v3.4
# -------------------------
class CipherEngine32x32:
    VERSION      = b"34"   # "34" == v3.4
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
        cls, plaintext: BytesLike, *, enc_key: bytes, tran_key: bytes,
        max_rounds: int = 5, return_b64: bool = True
    ) -> Union[bytes, str]:
        cls._check_key("enc_key", enc_key); cls._check_key("tran_key", tran_key)
        if not isinstance(max_rounds, int) or max_rounds <= 0:
            raise ValueError("max_rounds must be a positive integer")

        pt = bytes(plaintext)
        salt = os.urandom(cls.SALT_LEN)
        msg_key  = os.urandom(32)
        msg_tran = os.urandom(32)

        combined_key  = bytes((a + b + c) % 256 for a, b, c in zip(msg_key,  enc_key,  salt))
        combined_tran = bytes((a + b + c) % 256 for a, b, c in zip(msg_tran, tran_key, salt))
        key_info  = bytes(a ^ b ^ c for a, b, c in zip(msg_key,  enc_key,  salt))
        tran_info = bytes(a ^ b ^ c for a, b, c in zip(msg_tran, tran_key, salt))
        include_masked = 1

        # Huffman -> BitPerm
        tie_seed = _sha512_int(combined_key, b"huff-tie")
        huff_packed, pad_len = _huffman_encode_with_key(pt, combined_key, tie_seed)
        bitperm_seed = _seed_with_pad(combined_tran, b"bitperm", pad_len)
        huff_scram = _apply_bit_permutation_packed(huff_packed, bitperm_seed)

        # StreamFWD -> StreamREV
        s1 = _stream_forward(huff_scram, combined_key, max_rounds, pad_len)
        s2 = _stream_reverse(s1,       combined_key, max_rounds, pad_len)

        # P1 (pad-dependent) on MAIN
        n = len(s2)
        perm1_seed = _seed_with_pad(combined_tran, b"perm", pad_len)
        perm1 = _permutation_indices(n, perm1_seed)
        main_p1 = _apply_permutation(s2, perm1)

        # Inner header (masked), then P0 (pad-independent) over ALL
        inner0 = ((0 & 0x1F) << 3) | (pad_len & 0x07)
        inner = bytes([inner0 ^ _inner_mask_bytes(combined_key, cls.INNER_LEN)[0]])
        pre_p0 = main_p1 + inner

        perm0_seed = _sha512_int(combined_tran, b"perm0")
        perm0 = _permutation_indices(n + cls.INNER_LEN, perm0_seed)
        ciphertext_bytes = _apply_permutation(pre_p0, perm0)

        # Outer header + HMAC
        header = cls.VERSION + bytes([include_masked]) + salt + key_info + tran_info
        blob = header + ciphertext_bytes
        hmac_key = combined_key + combined_tran
        tag = _compute_hmac(hmac_key, blob)
        final_blob = blob + tag

        if not return_b64: return final_blob
        prefix = os.urandom(4)
        return base64.b64encode(prefix + final_blob).decode("ascii")

    @classmethod
    def decrypt(
        cls, ciphertext: Union[str, bytes], *, enc_key: bytes, tran_key: bytes,
        max_rounds: int = 5, is_b64: bool = True
    ) -> bytes:
        cls._check_key("enc_key", enc_key); cls._check_key("tran_key", tran_key)
        if not isinstance(max_rounds, int) or max_rounds <= 0:
            raise ValueError("max_rounds must be a positive integer")

        data = ciphertext.encode("ascii") if isinstance(ciphertext, str) else ciphertext
        if is_b64:
            data = base64.b64decode(data); data = data[4:]

        off = 0
        version = data[off:off+2]; off += 2
        if version != cls.VERSION:
            raise ValueError("Unsupported version (expecting v3.4)")
        include_masked = data[off]; off += 1
        salt = data[off:off+cls.SALT_LEN]; off += cls.SALT_LEN
        key_info  = data[off:off+cls.INFO_LEN]; off += cls.INFO_LEN
        tran_info = data[off:off+cls.INFO_LEN]; off += cls.INFO_LEN

        encrypted = data[off:-cls.TAG_LEN]
        tag       = data[-cls.TAG_LEN:]

        msg_key  = bytes(a ^ b ^ c for a, b, c in zip(key_info,  enc_key,  salt))
        msg_tran = bytes(a ^ b ^ c for a, b, c in zip(tran_info, tran_key, salt))
        combined_key  = bytes((a + b + c) % 256 for a, b, c in zip(msg_key,  enc_key,  salt))
        combined_tran = bytes((a + b + c) % 256 for a, b, c in zip(msg_tran, tran_key, salt))

        blob = data[:-cls.TAG_LEN]
        hmac_key = combined_key + combined_tran
        if not hmac.compare_digest(_compute_hmac(hmac_key, blob), tag):
            raise ValueError("HMAC verification failed")

        # P0^-1 -> split MAIN_P1 / INNER -> pad_len
        perm0_seed = _sha512_int(combined_tran, b"perm0")
        perm0 = _permutation_indices(len(encrypted), perm0_seed)
        pre_p0 = _reverse_permutation(encrypted, perm0)

        if len(pre_p0) < cls.INNER_LEN:
            raise ValueError("Ciphertext too short")
        main_p1 = pre_p0[:-cls.INNER_LEN]; inner_b = pre_p0[-cls.INNER_LEN:]

        inner0 = inner_b[0] ^ _inner_mask_bytes(combined_key, cls.INNER_LEN)[0]
        pad_len = inner0 & 0x07
        flags   = inner0 >> 3  # reserved

        # P1^-1 on MAIN
        n = len(main_p1)
        perm1_seed = _seed_with_pad(combined_tran, b"perm", pad_len)
        perm1 = _permutation_indices(n, perm1_seed)
        main = _reverse_permutation(main_p1, perm1)

        # InvStreamREV -> InvStreamFWD
        s2_inv = _inv_stream_reverse(main, combined_key, max_rounds, pad_len)
        s1_inv = _inv_stream_forward(s2_inv, combined_key, max_rounds, pad_len)

        # UnBitPerm -> Huffman^-1
        bitperm_seed = _seed_with_pad(combined_tran, b"bitperm", pad_len)
        huff_packed = _reverse_bit_permutation_packed(s1_inv, bitperm_seed)

        tie_seed = _sha512_int(combined_key, b"huff-tie")
        return _huffman_decode_with_key(huff_packed, combined_key, pad_len, tie_seed)

# -------------------------
# Convenience wrappers
# -------------------------
def encrypt_bytes_to_b64(plaintext: BytesLike, *, enc_key: bytes, tran_key: bytes, max_rounds: int = 5) -> str:
    return CipherEngine32x32.encrypt(plaintext, enc_key=enc, tran_key=tran, max_rounds=max_rounds, return_b64=True)

def decrypt_b64_to_bytes(ciphertext_b64: Union[str, bytes], *, enc_key: bytes, tran_key: bytes, max_rounds: int = 5) -> bytes:
    return CipherEngine32x32.decrypt(ciphertext_b64, enc_key=enc, tran_key=tran, max_rounds=max_rounds, is_b64=True)

def encrypt_with_bundle(plaintext: BytesLike, bundle: Dict[str, bytes], *, max_rounds: int = 5) -> str:
    return encrypt_bytes_to_b64(plaintext, enc_key=bundle["enc"], tran_key=bundle["tran"], max_rounds=max_rounds)

def decrypt_with_bundle(ciphertext_b64: Union[str, bytes], bundle: Dict[str, bytes], *, max_rounds: int = 5) -> bytes:
    return decrypt_b64_to_bytes(ciphertext_b64, enc_key=bundle["enc"], tran_key=bundle["tran"], max_rounds=max_rounds)
