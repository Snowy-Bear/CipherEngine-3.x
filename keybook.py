"""
keybook.py — Snapshot-style key vault (book-cipher-inspired), stdlib only.

Public contract (v2):
  - Build and seal a 1 MiB "book" from public text, using user hints.
  - Derive deterministic keys/tokens from the sealed book + labels.
  - Everything uses SHA-512 (PBKDF2/HKDF/HMAC/DRBG); secrets from `secrets`.

  Nice-to-have helpers (v2+):
  - derive_message_id() / derive_nonce(): deterministic IDs via HKDF (stateless)
  - make_aad_hash() / make_aad_hmac(): AAD binding helpers
  - write_message_meta() / read_message_meta(): optional sidecar for message_id

  Works with cipher_engine_v3_6 and earlier (via shim).

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, io, json, time, base64, shutil, struct, string, secrets, hashlib, hmac
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple, Iterable

# =========================
# Constants / Versioning
# =========================

MAGIC = b"KEYBOOK2"
VERSION = 2

# Sizes (bytes)
BOOK_SIZE_BYTES = 1 * 1024 * 1024  # 1 MiB snapshot
SALT_LEN = 32
SEED_LEN = 32
NONCE_LEN = 32
MASTER_LEN = 32          # master key / subkeys = 32 bytes
HMAC_KEY_LEN = 64        # HMAC key length (SHA-512)
UNLOCK_TOKEN_LEN = 32

# Defaults
DEFAULT_PURPOSES = ("enc", "tran", "hmac", "auth", "aux1", "aux2")

# =========================
# Exceptions
# =========================

class KeybookError(Exception):
    """Base class for all keybook errors."""

class InvalidUnlock(KeybookError):
    """Raised when passphrase/pepper (or unlock token) are wrong."""

class VaultCorrupt(KeybookError):
    """Raised when the vault file is missing, truncated, or fails integrity checks."""

class InvalidLabel(KeybookError):
    """Raised when a requested purpose/label is unsupported."""

class ResequenceUnavailable(KeybookError):
    """Raised when resequencing cannot proceed (e.g., no sources / offline-only policy)."""

# =========================
# Data Structures
# =========================

@dataclass(frozen=True)
class VaultHandle:
    """
    An opened vault descriptor returned by `init_vault` / `open_vault`.
    """
    path: str
    edition_id: str
    created_utc: float
    device_ctx: Optional[str]
    policy: Dict
    book_hash: bytes            # SHA-512(book_bytes)
    salt_kdf: bytes             # 32B public KDF salt
    k_master: bytes             # <-- NEW: 32B PBKDF2-HMAC-SHA512(master) in memory
    kdf_iters: int              # <-- NEW: PBKDF2 iteration count actually used
    purposes: Tuple[str, ...] = DEFAULT_PURPOSES
    
# =========================
# Internal helpers
# =========================

def _normalize_text(raw_bytes: bytes) -> bytes:
    # Minimal, deterministic normalization placeholder.
    # (Lowercase ASCII, collapse whitespace)
    txt = raw_bytes.decode("utf-8", errors="ignore").lower()
    compact = " ".join(txt.split())
    return compact.encode("utf-8")

def _assemble_book(hints: List[str], *, seed: bytes, target_size: int = BOOK_SIZE_BYTES) -> bytes:
    """
    Deterministic, crypto-grade filler based on the hints.
    Later you can plug a real harvester; the snapshot is what matters.
    """
    hint_bytes = "|".join([h.strip() for h in hints if h.strip()]).encode("utf-8")
    key = hashlib.sha512(seed + hashlib.sha512(hint_bytes).digest()).digest()
    prefix = b"book|" + hashlib.sha512(hint_bytes).digest()
    stream = _drbg_hmac_sha512(key, prefix, target_size * 2)  # overshoot
    # fold to printable-ish book but keep bytes entropy-ish
    normalized = _normalize_text(stream).ljust(target_size, b" ")[:target_size]
    return bytes(normalized)

def _make_edition_id(book_bytes: bytes, edition_num: int) -> str:
    """
    Edition display tag: 'ED{edition_num}-{TAG8}'
    Where TAG8 = first 8 base32 chars (RFC 4648, no padding) of SHA-512(book_bytes).
    """
    if not isinstance(book_bytes, (bytes, bytearray)):
        raise TypeError("book_bytes must be bytes")
    if not isinstance(edition_num, int) or edition_num <= 0:
        raise ValueError("edition_num must be a positive integer")

    digest = hashlib.sha512(book_bytes).digest()
    tag = base64.b32encode(digest).decode("ascii").rstrip("=")  # uppercase A–Z2–7
    return f"ED{edition_num}-{tag[:8]}"

def _next_edition_num(edition_id: str) -> int:
    """
    Parse 'ED<num>-TAG' -> num+1. If parsing fails, return 2.
    """
    try:
        if edition_id.startswith("ED"):
            dash = edition_id.find("-")
            if dash > 2:
                return int(edition_id[2:dash]) + 1
    except Exception:
        pass
    return 2

def _seal_vault_payload(payload: bytes, *, passphrase: str, pepper: str,
                        device_id: Optional[str], iters: int,
                        edition_id: str, salt_kdf: bytes) -> bytes:
    """
    Build: header || ciphertext || tag
    - header contains public fields (edition_id, salts, iters, device id, payload_len)
    - ciphertext = payload XOR keystream(HMAC-SHA512(counter), key=K_stream, prefix=b"vault|"+nonce)
    - tag = HMAC-SHA512(K_mac, header || ciphertext)
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    if len(salt_kdf) != SALT_LEN:
        raise ValueError("salt_kdf must be 32 bytes")

    # Wrapping salts/seeds
    salt_vault = secrets.token_bytes(SALT_LEN)
    nonce_vault = secrets.token_bytes(NONCE_LEN)

    # Derive wrapping keys
    material = (passphrase + "|" + pepper).encode("utf-8")
    k_wrap_base = hashlib.pbkdf2_hmac("sha512", material, salt_vault, iters, dklen=MASTER_LEN)
    k_stream = _hkdf_sha512(k_wrap_base, b"keybook|wrap|stream", salt_vault, MASTER_LEN)
    k_mac    = _hkdf_sha512(k_wrap_base, b"keybook|wrap|mac",    salt_vault, HMAC_KEY_LEN)

    # Header (with payload_len)
    header = _pack_header(edition_id=edition_id, salt_vault=salt_vault, nonce_vault=nonce_vault,
                          kdf_iters=iters, device_ctx=device_id, salt_kdf=salt_kdf,
                          payload_len=len(payload))

    # Stream cipher (XOR with HMAC-DRBG)
    prefix = b"vault|stream|" + nonce_vault
    ks = _drbg_hmac_sha512(k_stream, prefix, len(payload))
    ciphertext = bytes(a ^ b for a, b in zip(payload, ks))

    # Integrity tag over header || ciphertext
    tag = hmac.new(k_mac, header + ciphertext, hashlib.sha512).digest()

    return header + ciphertext + tag

def _unseal_vault_payload(vault_bytes: bytes, *, passphrase: str, pepper: str,
                          device_id: Optional[str]) -> Tuple[bytes, dict]:
    """
    Parse header, verify tag, decrypt payload. Returns (payload, header_dict).
    """
    if not isinstance(vault_bytes, (bytes, bytearray)):
        raise TypeError("vault_bytes must be bytes")

    hdr, off = _parse_header(vault_bytes)
    header = vault_bytes[:off]
    if device_id is not None and hdr["device_ctx"] and device_id != hdr["device_ctx"]:
        # Soft policy: allow opening on another device if passphrase+pepper are correct.
        # If you want hard binding, raise InvalidUnlock here instead.
        pass

    payload_len = hdr["payload_len"]
    need = off + payload_len + 64
    if len(vault_bytes) < need:
        raise VaultCorrupt("Truncated ciphertext/tag")

    ciphertext = vault_bytes[off:off+payload_len]
    tag = vault_bytes[off+payload_len:need]

    # Re-derive wrapping keys
    material = (passphrase + "|" + pepper).encode("utf-8")
    k_wrap_base = hashlib.pbkdf2_hmac("sha512", material, hdr["salt_vault"], hdr["kdf_iters"], dklen=MASTER_LEN)
    k_stream = _hkdf_sha512(k_wrap_base, b"keybook|wrap|stream", hdr["salt_vault"], MASTER_LEN)
    k_mac    = _hkdf_sha512(k_wrap_base, b"keybook|wrap|mac",    hdr["salt_vault"], HMAC_KEY_LEN)

    # Verify tag
    calc_tag = hmac.new(k_mac, header + ciphertext, hashlib.sha512).digest()
    if not hmac.compare_digest(tag, calc_tag):
        raise InvalidUnlock("Integrity/tag verification failed")

    # Decrypt
    prefix = b"vault|stream|" + hdr["nonce_vault"]
    ks = _drbg_hmac_sha512(k_stream, prefix, payload_len)
    payload = bytes(a ^ b for a, b in zip(ciphertext, ks))

    return payload, hdr
    
def _derive_master_key(passphrase: str, pepper: str, salt_kdf: bytes, iters: int) -> bytes:
    """
    PBKDF2-HMAC-SHA512(passphrase || '|' || pepper, salt_kdf, iters, dklen=32).
    All inputs must be provided; pepper is required by policy.
    """
    if not isinstance(salt_kdf, (bytes, bytearray)):
        raise TypeError("salt_kdf must be bytes")
    if not isinstance(iters, int) or iters <= 0:
        raise ValueError("iters must be a positive integer")
    if not isinstance(passphrase, str) or not isinstance(pepper, str):
        raise TypeError("passphrase and pepper must be strings")
    material = (passphrase + "|" + pepper).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", material, salt_kdf, iters, dklen=MASTER_LEN)

def _hkdf_sha512(ikm: bytes, info: bytes, salt: bytes, length: int) -> bytes:
    """
    HKDF (RFC 5869) using HMAC-SHA512 for both extract and expand.
    - ikm: input keying material
    - info: context & application specific information (can be empty)
    - salt: optional salt (non-secret, can be empty)
    - length: number of bytes to output
    """
    if not isinstance(ikm, (bytes, bytearray)):
        raise TypeError("ikm must be bytes")
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError("info must be bytes")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    if length <= 0:
        return b""

    # Extract
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()

    # Expand
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha512).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])

def _drbg_hmac_sha512(key: bytes, prefix: bytes, total_len: int) -> bytes:
    """
    Deterministic CSPRNG bytes via HMAC-SHA512 in counter mode.
    Block i = HMAC(key, prefix || counter_be_64(i)), i = 0,1,2,...
    Returns exactly total_len bytes.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if not isinstance(prefix, (bytes, bytearray)):
        raise TypeError("prefix must be bytes")
    if total_len < 0:
        raise ValueError("total_len must be non-negative")

    out = bytearray()
    counter = 0
    while len(out) < total_len:
        ctr = struct.pack(">Q", counter)  # 8-byte big-endian
        block = hmac.new(key, prefix + ctr, hashlib.sha512).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:total_len])



# =========================
# File Headers Pack/Unpack
# =========================


def _pack_header(*, edition_id: str, salt_vault: bytes, nonce_vault: bytes,
                 kdf_iters: int, device_ctx: Optional[str], salt_kdf: bytes,
                 payload_len: int) -> bytes:
    if not isinstance(edition_id, str) or edition_id == "":
        raise ValueError("edition_id required")
    dev_bytes = (device_ctx or "").encode("utf-8")
    ed_bytes  = edition_id.encode("utf-8")
    header = bytearray()
    header += MAGIC                         # 8 bytes
    header += bytes([VERSION])              # 1
    header += bytes([len(ed_bytes)])        # 1
    header += ed_bytes                      # n
    header += salt_vault                    # 32
    header += nonce_vault                   # 32
    header += struct.pack(">I", kdf_iters)  # 4
    header += struct.pack(">H", len(dev_bytes))  # 2
    header += dev_bytes                     # m
    header += salt_kdf                      # 32 (public derivation salt)
    header += struct.pack(">Q", payload_len)     # 8
    return bytes(header)

def _parse_header(blob: bytes) -> Tuple[dict, int]:
    """
    Returns (header_dict, offset_after_header). Raises VaultCorrupt on parse errors.
    """
    off = 0
    need_min = len(MAGIC) + 1 + 1
    if len(blob) < need_min:
        raise VaultCorrupt("Truncated file")
    if blob[:len(MAGIC)] != MAGIC:
        raise VaultCorrupt("Bad magic")
    off += len(MAGIC)
    version = blob[off]; off += 1
    if version != VERSION:
        raise VaultCorrupt(f"Unsupported version {version}")
    ed_len = blob[off]; off += 1
    if len(blob) < off + ed_len + 32 + 32 + 4 + 2:
        raise VaultCorrupt("Truncated header")
    edition_id = blob[off:off+ed_len].decode("utf-8"); off += ed_len
    salt_vault = blob[off:off+SALT_LEN]; off += SALT_LEN
    nonce_vault = blob[off:off+NONCE_LEN]; off += NONCE_LEN
    kdf_iters = struct.unpack(">I", blob[off:off+4])[0]; off += 4
    dev_len = struct.unpack(">H", blob[off:off+2])[0]; off += 2
    if len(blob) < off + dev_len + SALT_LEN + 8:
        raise VaultCorrupt("Truncated header (device)")
    device_ctx = blob[off:off+dev_len].decode("utf-8"); off += dev_len
    salt_kdf = blob[off:off+SALT_LEN]; off += SALT_LEN
    payload_len = struct.unpack(">Q", blob[off:off+8])[0]; off += 8
    hdr = {
        "version": version,
        "edition_id": edition_id,
        "salt_vault": salt_vault,
        "nonce_vault": nonce_vault,
        "kdf_iters": kdf_iters,
        "device_ctx": device_ctx or None,
        "salt_kdf": salt_kdf,
        "payload_len": payload_len,
    }
    return hdr, off

# =========================
# Sealed Payload (Meta JSON + MiB Book)
# =========================

def _build_payload(*, edition_id: str, created_utc: float, policy: Dict,
                   salt_kdf: bytes, book_bytes: bytes, sources: List[Dict]) -> bytes:
    meta = {
        "edition_id": edition_id,
        "created_utc": created_utc,
        "policy": policy or {},
        "salt_kdf_b64": base64.b64encode(salt_kdf).decode("ascii"),
        "sources": sources or [],
        "book_size": len(book_bytes),
    }
    meta_bytes = json.dumps(meta, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return struct.pack(">I", len(meta_bytes)) + meta_bytes + book_bytes

def _parse_payload(payload: bytes) -> Tuple[dict, bytes]:
    if len(payload) < 4:
        raise VaultCorrupt("Payload too small")
    meta_len = struct.unpack(">I", payload[:4])[0]
    if len(payload) < 4 + meta_len:
        raise VaultCorrupt("Payload truncated (meta)")
    meta = json.loads(payload[4:4+meta_len].decode("utf-8"))
    book = payload[4+meta_len:]
    if len(book) != meta.get("book_size", len(book)):
        raise VaultCorrupt("Book size mismatch")
    return meta, book

# =========================
# Public API
# =========================

def init_vault(hints: List[str],
               passphrase: str,
               pepper: str,
               *,
               device_id: Optional[str] = None,
               policy: Optional[Dict] = None,
               out_path: Optional[str] = None) -> VaultHandle:
    if not hints or len([h for h in hints if h.strip()]) < 1:
        raise ValueError("Provide at least one hint (5–10 recommended)")
    if not passphrase or not pepper:
        raise ValueError("Passphrase and (paper) pepper are required")

    created = time.time()
    # Policy with KDF iters (tune later / device-specific)
    policy = dict(policy or {})
    kdf_iters = int(policy.get("pbkdf2_iters", 800_000))
    policy["pbkdf2_iters"] = kdf_iters
    policy.setdefault("purposes", list(DEFAULT_PURPOSES))

    # Assemble deterministic 1 MiB snapshot (placeholder)
    selection_seed = secrets.token_bytes(SEED_LEN)  # not stored; snapshot is the source of truth
    book_bytes = _assemble_book(hints, seed=selection_seed, target_size=BOOK_SIZE_BYTES)

    # Edition id & derivation salt
    edition_id = _make_edition_id(book_bytes, edition_num=1)
    salt_kdf = secrets.token_bytes(SALT_LEN)

    # Minimal sources audit (placeholder)
    sources = [{"title": "dummy", "url": "about:blank", "content_hash":
                hashlib.sha512(book_bytes).hexdigest(), "bytes": len(book_bytes)}]

    # Build sealed payload
    payload = _build_payload(edition_id=edition_id, created_utc=created, policy=policy,
                             salt_kdf=salt_kdf, book_bytes=book_bytes, sources=sources)

    # Seal (device binding echoed in header)
    vault_bytes = _seal_vault_payload(payload, passphrase=passphrase, pepper=pepper,
                                      device_id=device_id, iters=kdf_iters,
                                      edition_id=edition_id, salt_kdf=salt_kdf)

    # Where to write
    path = out_path or (edition_id + ".keybook")
    with open(path, "wb") as f:
        f.write(vault_bytes)

    # Build handle (compute book_hash and k_master for immediate use)
    book_hash = hashlib.sha512(book_bytes).digest()
    k_master = _derive_master_key(passphrase, pepper, salt_kdf, kdf_iters)

    return VaultHandle(
        path=path,
        edition_id=edition_id,
        created_utc=created,
        device_ctx=device_id,
        policy=policy,
        book_hash=book_hash,
        salt_kdf=salt_kdf,
        k_master=k_master,
        kdf_iters=kdf_iters,
        purposes=tuple(policy.get("purposes", DEFAULT_PURPOSES))
    )

def open_vault(path: str,
               passphrase: str,
               pepper: str,
               *,
               device_id: Optional[str] = None) -> VaultHandle:
    if not os.path.exists(path):
        raise VaultCorrupt("Vault file not found")

    with open(path, "rb") as f:
        vault_bytes = f.read()

    payload, hdr = _unseal_vault_payload(vault_bytes, passphrase=passphrase,
                                         pepper=pepper, device_id=device_id)
    meta, book_bytes = _parse_payload(payload)

    # Sanity: edition id and salt_kdf consistency
    edition_id = meta["edition_id"]
    if edition_id != hdr["edition_id"]:
        raise VaultCorrupt("Edition ID mismatch (header vs payload)")

    # Derivation salt (public) comes from header; payload copy is informational
    salt_kdf_hdr = hdr["salt_kdf"]
    salt_kdf_meta = base64.b64decode(meta.get("salt_kdf_b64", "")) if meta.get("salt_kdf_b64") else salt_kdf_hdr
    if salt_kdf_hdr != salt_kdf_meta:
        # Not fatal, but suspicious — prefer header value
        salt_kdf = salt_kdf_hdr
    else:
        salt_kdf = salt_kdf_hdr

    policy = meta.get("policy", {})
    kdf_iters = int(policy.get("pbkdf2_iters", hdr["kdf_iters"]))

    book_hash = hashlib.sha512(book_bytes).digest()
    k_master = _derive_master_key(passphrase, pepper, salt_kdf, kdf_iters)

    return VaultHandle(
        path=path,
        edition_id=edition_id,
        created_utc=float(meta.get("created_utc", time.time())),
        device_ctx=hdr.get("device_ctx"),
        policy=policy,
        book_hash=book_hash,
        salt_kdf=salt_kdf,
        k_master=k_master,
        kdf_iters=kdf_iters,
        purposes=tuple(policy.get("purposes", DEFAULT_PURPOSES))
    )

def derive_key(handle: VaultHandle,
               purpose: str,
               target: str,
               *,
               epoch: Optional[str] = None,
               length: int = MASTER_LEN) -> bytes:
    """
    Derive a deterministic key for (purpose, target, epoch) using HKDF-SHA512.
    """
    if purpose not in handle.purposes:
        raise InvalidLabel(f"Unsupported purpose '{purpose}'. Supported: {handle.purposes}")
    if not isinstance(target, str) or target == "":
        raise ValueError("target must be a non-empty string")
    if not isinstance(length, int) or length <= 0:
        raise ValueError("length must be a positive integer")

    eid = handle.edition_id if epoch is None else epoch
    if not isinstance(eid, str) or eid == "":
        raise ValueError("epoch/edition_id must be a non-empty string")

    # HKDF info string (labels)
    info = ("keybook|v2|" + eid + "|" + purpose + "|" + target).encode("utf-8")

    # HKDF-SHA512 with salt = book_hash ensures book content scopes all keys
    key = _hkdf_sha512(
        ikm=handle.k_master,
        info=info,
        salt=handle.book_hash,
        length=length if purpose != "hmac" else max(length, HMAC_KEY_LEN)
    )

    # If caller asked for <64 bytes for HMAC, trim (derive_bundle requests 64)
    return key[:length]

def derive_bundle(handle: VaultHandle,
                  target: str,
                  *,
                  epoch: Optional[str] = None) -> Dict[str, bytes]:
    """
    Convenience: derive a full bundle of keys for a target.
    """
    eid = handle.edition_id if epoch is None else epoch

    k_enc  = derive_key(handle, "enc",  target, epoch=eid, length=MASTER_LEN)
    k_tran = derive_key(handle, "tran", target, epoch=eid, length=MASTER_LEN)
    k_hmac = derive_key(handle, "hmac", target, epoch=eid, length=HMAC_KEY_LEN)
    k_aux1 = derive_key(handle, "aux1", target, epoch=eid, length=MASTER_LEN)
    k_aux2 = derive_key(handle, "aux2", target, epoch=eid, length=MASTER_LEN)

    return {
        "enc":  k_enc,
        "tran": k_tran,
        "hmac": k_hmac,
        "aux1": k_aux1,
        "aux2": k_aux2,
        "epoch": eid,           # helpful echo for callers
        "edition_id": handle.edition_id,
    }

def resequence_vault(handle: VaultHandle,
                     passphrase: str,
                     pepper: str,
                     new_hints: Optional[List[str]] = None,
                     *,
                     policy: Optional[Dict] = None,
                     device_id: Optional[str] = None,
                     out_path: Optional[str] = None) -> VaultHandle:
    """
    Create a NEW edition (ED<N+1>-TAG) with a fresh 1 MiB book.
    - If new_hints are provided, they steer the new book assembly.
    - Otherwise, we derive a fresh book from the previous book_hash (placeholder mode).
    - Keeps prior edition intact; returns a handle for the new edition.
    """
    created = time.time()
    policy_new = dict(handle.policy)
    if policy:
        policy_new.update(policy)
    kdf_iters = int(policy_new.get("pbkdf2_iters", handle.kdf_iters))
    policy_new["pbkdf2_iters"] = kdf_iters

    # Assemble the new 1 MiB book
    if new_hints and any(h.strip() for h in new_hints):
        selection_seed = secrets.token_bytes(SEED_LEN)
        book_bytes = _assemble_book(new_hints, seed=selection_seed, target_size=BOOK_SIZE_BYTES)
    else:
        # Placeholder resequence: derive new deterministic filler from previous book_hash
        key = hashlib.sha512(handle.book_hash + secrets.token_bytes(SEED_LEN)).digest()
        prefix = b"book|reseq|" + handle.book_hash
        book_bytes = _drbg_hmac_sha512(key, prefix, BOOK_SIZE_BYTES)
        book_bytes = _normalize_text(book_bytes).ljust(BOOK_SIZE_BYTES, b" ")[:BOOK_SIZE_BYTES]

    # Compute next edition id and new derivation salt
    next_num = _next_edition_num(handle.edition_id)
    edition_id = _make_edition_id(book_bytes, edition_num=next_num)
    salt_kdf = secrets.token_bytes(SALT_LEN)

    # Sources audit placeholder (swap with real list when harvesting is wired)
    sources = [{"title": f"resequence-{edition_id}",
                "url": "about:blank",
                "content_hash": hashlib.sha512(book_bytes).hexdigest(),
                "bytes": len(book_bytes)}]

    payload = _build_payload(edition_id=edition_id, created_utc=created, policy=policy_new,
                             salt_kdf=salt_kdf, book_bytes=book_bytes, sources=sources)

    vault_bytes = _seal_vault_payload(payload, passphrase=passphrase, pepper=pepper,
                                      device_id=device_id, iters=kdf_iters,
                                      edition_id=edition_id, salt_kdf=salt_kdf)

    # Choose filename alongside previous vault
    base_dir = os.path.dirname(handle.path) or "."
    path = out_path or os.path.join(base_dir, f"{edition_id}.keybook")
    with open(path, "wb") as f:
        f.write(vault_bytes)

    # Build new handle
    book_hash = hashlib.sha512(book_bytes).digest()
    k_master = _derive_master_key(passphrase, pepper, salt_kdf, kdf_iters)
    return VaultHandle(
        path=path,
        edition_id=edition_id,
        created_utc=created,
        device_ctx=device_id,
        policy=policy_new,
        book_hash=book_hash,
        salt_kdf=salt_kdf,
        k_master=k_master,
        kdf_iters=kdf_iters,
        purposes=tuple(policy_new.get("purposes", DEFAULT_PURPOSES))
    )

def vault_info(handle: VaultHandle) -> Dict:
    """
    Return non-secret metadata for inspection/maintenance UI.
    """
    info = {
        "edition_id": handle.edition_id,
        "created_utc": handle.created_utc,
        "policy": handle.policy,
        "book_size": None,              # to be filled by open/init (bytes) if you store it
        "purposes": list(handle.purposes),
        "kdf": {
            "hash": "sha512",
            "iters": handle.kdf_iters,
            "salt_len": len(handle.salt_kdf),
            "dklen": MASTER_LEN,
        },
        "hash_family": "sha512",
        "device_ctx": handle.device_ctx,
    }
    # If your sealed payload includes a 'sources' list in policy/metadata, surface it:
    if "sources" in handle.policy:
        info["sources"] = handle.policy["sources"]
    return info

def export_unlock_token(handle: VaultHandle,
                        passphrase: str,
                        pepper: str) -> bytes:
    """
    Export a 32-byte unlock token that can open this vault without the passphrase/pepper.
    SECURITY: Anyone with the vault file + this token can decrypt it.
    Store offline (paper/QR or secure storage).
    """
    # Read header to get salt_vault and kdf_iters used for wrapping
    with open(handle.path, "rb") as f:
        vault_bytes = f.read()
    hdr, _ = _parse_header(vault_bytes)

    # Re-derive the *wrapping base key* exactly as used to seal the file
    material = (passphrase + "|" + pepper).encode("utf-8")
    k_wrap_base = hashlib.pbkdf2_hmac("sha512", material,
                                      hdr["salt_vault"], hdr["kdf_iters"],
                                      dklen=MASTER_LEN)  # 32 bytes
    return k_wrap_base

def import_vault(path: str,
                 passphrase: str,
                 pepper: str,
                 unlock_token: Optional[bytes] = None,
                 *,
                 device_id: Optional[str] = None,
                 out_path: Optional[str] = None) -> VaultHandle:
    """
    Rewrap a vault for this device (and/or new passphrase), using either:
      - unlock_token (32B K_wrap_base), OR
      - the original passphrase+pepper.

    If out_path is None, overwrites the existing file.
    Returns a handle to the rewrapped vault (same edition_id).
    """
    if not os.path.exists(path):
        raise VaultCorrupt("Vault file not found")
    with open(path, "rb") as f:
        vault_bytes = f.read()

    # Parse header
    hdr, off = _parse_header(vault_bytes)
    header = vault_bytes[:off]
    ciphertext = vault_bytes[off:off + hdr["payload_len"]]
    tag = vault_bytes[off + hdr["payload_len"] : off + hdr["payload_len"] + 64]

    # Get wrapping base key (either from unlock token or passphrase+pepper)
    if unlock_token is not None:
        if not isinstance(unlock_token, (bytes, bytearray)) or len(unlock_token) != MASTER_LEN:
            raise InvalidUnlock("unlock_token must be 32 bytes")
        k_wrap_base = bytes(unlock_token)
    else:
        material = (passphrase + "|" + pepper).encode("utf-8")
        k_wrap_base = hashlib.pbkdf2_hmac("sha512", material,
                                          hdr["salt_vault"], hdr["kdf_iters"],
                                          dklen=MASTER_LEN)

    # Derive stream/mac keys and verify tag
    k_stream = _hkdf_sha512(k_wrap_base, b"keybook|wrap|stream", hdr["salt_vault"], MASTER_LEN)
    k_mac    = _hkdf_sha512(k_wrap_base, b"keybook|wrap|mac",    hdr["salt_vault"], HMAC_KEY_LEN)
    calc_tag = hmac.new(k_mac, header + ciphertext, hashlib.sha512).digest()
    if not hmac.compare_digest(tag, calc_tag):
        raise InvalidUnlock("Integrity/tag verification failed (wrong token or credentials)")

    # Decrypt payload
    prefix = b"vault|stream|" + hdr["nonce_vault"]
    ks = _drbg_hmac_sha512(k_stream, prefix, hdr["payload_len"])
    payload = bytes(a ^ b for a, b in zip(ciphertext, ks))

    # Parse payload & rewrap with (possibly same) passphrase/pepper for this device
    meta, book_bytes = _parse_payload(payload)
    edition_id = meta["edition_id"]
    policy = meta.get("policy", {})
    created = float(meta.get("created_utc", time.time()))
    # keep existing public derivation salt_kdf from payload/meta
    salt_kdf = base64.b64decode(meta["salt_kdf_b64"])

    # Rebuild sealed bytes with *new* wrapping (device binding echoed in header)
    new_payload = _build_payload(edition_id=edition_id, created_utc=created, policy=policy,
                                 salt_kdf=salt_kdf, book_bytes=book_bytes,
                                 sources=meta.get("sources", []))
    kdf_iters = int(policy.get("pbkdf2_iters", hdr["kdf_iters"]))
    new_vault = _seal_vault_payload(new_payload, passphrase=passphrase, pepper=pepper,
                                    device_id=device_id, iters=kdf_iters,
                                    edition_id=edition_id, salt_kdf=salt_kdf)

    # Write output
    out = out_path or path
    with open(out, "wb") as f:
        f.write(new_vault)

    # Return fresh handle (ready to derive keys)
    book_hash = hashlib.sha512(book_bytes).digest()
    k_master = _derive_master_key(passphrase, pepper, salt_kdf, kdf_iters)
    return VaultHandle(
        path=out,
        edition_id=edition_id,
        created_utc=created,
        device_ctx=device_id,
        policy=policy,
        book_hash=book_hash,
        salt_kdf=salt_kdf,
        k_master=k_master,
        kdf_iters=kdf_iters,
        purposes=tuple(policy.get("purposes", DEFAULT_PURPOSES))
    )

def rotate_passphrase(handle: VaultHandle,
                      *,
                      old_passphrase: Optional[str] = None,
                      pepper: Optional[str] = None,
                      new_passphrase: str,
                      unlock_token: Optional[bytes] = None,
                      device_id: Optional[str] = None) -> VaultHandle:
    """
    Rotate (change) the vault passphrase in place, preserving:
      - edition_id, policy, salt_kdf, book bytes
      - pepper (unchanged)
      - device binding (defaults to handle.device_ctx unless overridden)

    Provide EITHER:
      - old_passphrase + pepper    (normal case), OR
      - unlock_token (32B K_wrap_base)

    Returns a fresh VaultHandle after writing the updated file.
    """
    if not os.path.exists(handle.path):
        raise VaultCorrupt(f"Vault file not found at: {handle.path}")

    with open(handle.path, "rb") as f:
        vault_bytes = f.read()

    # Parse header
    hdr, off = _parse_header(vault_bytes)
    header = vault_bytes[:off]
    payload_len = hdr["payload_len"]
    if len(vault_bytes) < off + payload_len + 64:
        raise VaultCorrupt("Truncated ciphertext/tag during rotate")

    ciphertext = vault_bytes[off:off+payload_len]
    tag = vault_bytes[off+payload_len:off+payload_len+64]

    # Obtain wrapping base key used to decrypt
    if unlock_token is not None:
        if not isinstance(unlock_token, (bytes, bytearray)) or len(unlock_token) != MASTER_LEN:
            raise InvalidUnlock("unlock_token must be 32 bytes")
        k_wrap_base = bytes(unlock_token)
    else:
        if not old_passphrase or not pepper:
            raise InvalidUnlock("Provide old_passphrase + pepper or an unlock_token")
        material = (old_passphrase + "|" + pepper).encode("utf-8")
        k_wrap_base = hashlib.pbkdf2_hmac("sha512", material,
                                          hdr["salt_vault"], hdr["kdf_iters"],
                                          dklen=MASTER_LEN)

    # Verify and decrypt with old wrapping
    k_stream = _hkdf_sha512(k_wrap_base, b"keybook|wrap|stream", hdr["salt_vault"], MASTER_LEN)
    k_mac    = _hkdf_sha512(k_wrap_base, b"keybook|wrap|mac",    hdr["salt_vault"], HMAC_KEY_LEN)
    calc_tag = hmac.new(k_mac, header + ciphertext, hashlib.sha512).digest()
    if not hmac.compare_digest(tag, calc_tag):
        raise InvalidUnlock("Integrity/tag verification failed (wrong credentials/token)")

    prefix = b"vault|stream|" + hdr["nonce_vault"]
    ks = _drbg_hmac_sha512(k_stream, prefix, payload_len)
    payload = bytes(a ^ b for a, b in zip(ciphertext, ks))

    # Parse payload (unchanged content)
    meta, book_bytes = _parse_payload(payload)
    if not book_bytes or len(book_bytes) != meta.get("book_size", 0):
        raise VaultCorrupt("Vault has no valid book content")

    edition_id = meta["edition_id"]
    policy     = meta.get("policy", {})
    created    = float(meta.get("created_utc", time.time()))
    salt_kdf   = base64.b64decode(meta["salt_kdf_b64"])

    # Re-seal with the NEW passphrase (pepper unchanged); device binding can be overridden
    new_payload = _build_payload(edition_id=edition_id, created_utc=created, policy=policy,
                                 salt_kdf=salt_kdf, book_bytes=book_bytes,
                                 sources=meta.get("sources", []))
    kdf_iters = int(policy.get("pbkdf2_iters", hdr["kdf_iters"]))
    new_vault = _seal_vault_payload(new_payload,
                                    passphrase=new_passphrase,
                                    pepper=(pepper or ""),             # unchanged; must be same one user keeps
                                    device_id=(device_id if device_id is not None else handle.device_ctx),
                                    iters=kdf_iters,
                                    edition_id=edition_id,
                                    salt_kdf=salt_kdf)

    # Overwrite in place
    with open(handle.path, "wb") as f:
        f.write(new_vault)

    # Return updated handle (so caller can keep deriving keys)
    book_hash = hashlib.sha512(book_bytes).digest()
    k_master  = _derive_master_key(new_passphrase, (pepper or ""), salt_kdf, kdf_iters)
    return VaultHandle(
        path=handle.path,
        edition_id=edition_id,
        created_utc=created,
        device_ctx=(device_id if device_id is not None else handle.device_ctx),
        policy=policy,
        book_hash=book_hash,
        salt_kdf=salt_kdf,
        k_master=k_master,
        kdf_iters=kdf_iters,
        purposes=tuple(policy.get("purposes", DEFAULT_PURPOSES))
    )

def list_editions(path: str) -> List[str]:
    """
    If `path` is a file, return [edition_id] from its header.
    If `path` is a directory, return edition_ids for all *.keybook files inside.
    """
    out: List[str] = []
    paths: List[str] = []
    if os.path.isdir(path):
        for name in os.listdir(path):
            if name.lower().endswith(".keybook"):
                paths.append(os.path.join(path, name))
    else:
        paths.append(path)

    for p in paths:
        try:
            with open(p, "rb") as f:
                hdr, _ = _parse_header(f.read(1024))
            out.append(hdr["edition_id"])
        except Exception:
            # skip unreadable/corrupt files
            continue
    return out

def verify_credentials(path: str, passphrase: str, pepper: str) -> bool:
    """
    Quick check: verify the vault's HMAC tag using passphrase+pepper without decrypting.
    Returns True if the credentials match this vault file; False otherwise.
    """
    if not os.path.exists(path):
        return False
    with open(path, "rb") as f:
        vb = f.read()

    hdr, off = _parse_header(vb)
    header = vb[:off]
    ciphertext = vb[off:off + hdr["payload_len"]]
    tag = vb[off + hdr["payload_len"] : off + hdr["payload_len"] + 64]

    material = (passphrase + "|" + pepper).encode("utf-8")
    k_wrap_base = hashlib.pbkdf2_hmac(
        "sha512", material, hdr["salt_vault"], hdr["kdf_iters"], dklen=MASTER_LEN
    )
    k_mac = _hkdf_sha512(k_wrap_base, b"keybook|wrap|mac", hdr["salt_vault"], HMAC_KEY_LEN)
    calc = hmac.new(k_mac, header + ciphertext, hashlib.sha512).digest()
    return hmac.compare_digest(calc, tag)

def format_unlock_token_card(edition_id: str,
                             token: bytes,
                             *,
                             label: str = "",
                             device_ctx: Optional[str] = None,
                             created_utc: Optional[float] = None,
                             columns: int = 4,
                             group: int = 4) -> str:
    """
    Make a human-readable paper card for the unlock token (no QR, no images).
    - token is the 32-byte unlock token (bytes).
    - edition_id helps you tie the card to a specific vault edition.
    - label is an optional user note (e.g., 'Home vault', 'Travel').
    - device_ctx is informational (public), shown if provided.
    The token is printed as grouped hex with a short checksum line.

    Example layout:

      KEYBOOK UNLOCK CARD
      Edition: ED1-ABCD1234   Device: My-iPad   Label: Home
      Token (hex):
      216f cd5f 1afd 6019
      950d e621 d1db f41f
      0656 b7a3 1292 481f
      bd69 3270 e782 f5ce
      Checksum: 8c1f4a7b

      Keep this on paper. Anyone with this token + the vault file can open it.
    """
    if not isinstance(token, (bytes, bytearray)) or len(token) == 0:
        raise ValueError("token must be non-empty bytes")
    import time as _time, textwrap as _textwrap

    hexs = token.hex()
    groups = [hexs[i:i+group] for i in range(0, len(hexs), group)]
    # build lines with fixed number of groups per line
    lines = [" ".join(groups[i:i+columns]) for i in range(0, len(groups), columns)]
    checksum = hashlib.sha512(token).hexdigest()[:8]
    ts = created_utc if (created_utc is not None) else _time.time()
    when = _time.strftime("%Y-%m-%d %H:%M:%S UTC", _time.gmtime(ts))

    header = [
        "KEYBOOK UNLOCK CARD",
        f"Edition: {edition_id}   Date: {when}",
        ("Device: " + device_ctx) if device_ctx else None,
        ("Label: " + label) if label else None,
        "Token (hex):",
    ]
    header = [h for h in header if h]
    footer = [
        f"Checksum: {checksum}",
        "",
        "WARNING: This token + the .keybook file opens the vault.",
        "Store OFFLINE (paper). Do NOT photograph or save digitally.",
    ]
    return "\n".join(header + lines + footer)

def parse_unlock_token_card(text: str) -> bytes:
    """
    Recover the 32-byte token from a printed/typed card.
    Robust: extracts only the block between 'Token (hex):' and 'Checksum:'.
    Verifies the optional checksum if present.
    """
    import re as _re

    # Normalize line breaks
    s = text.replace("\r\n", "\n").replace("\r", "\n")

    # Find the token block
    m = _re.search(r"Token\s*\(hex\)\s*:\s*(.*?)(?:\n\s*Checksum\s*:\s*([0-9a-fA-F]{8})|$)",
                   s, flags=_re.IGNORECASE | _re.DOTALL)
    if not m:
        raise ValueError("Token block not found (looked for 'Token (hex):')")

    token_block = m.group(1) or ""
    checksum_want = (m.group(2) or "").lower()

    # Keep only hex from the token block
    hexchars = "".join(_re.findall(r"[0-9a-fA-F]", token_block))

    # We expect exactly 32 bytes = 64 hex chars
    if len(hexchars) < 64:
        raise ValueError(f"No 32-byte hex token found (got {len(hexchars)} hex chars)")
    if len(hexchars) > 64:
        # If someone pasted extras, keep the last 64 from the token block
        hexchars = hexchars[-64:]

    token = bytes.fromhex(hexchars)

    # Verify checksum if present
    if checksum_want:
        checksum_got = hashlib.sha512(token).hexdigest()[:8]
        if checksum_got != checksum_want:
            raise ValueError("Checksum mismatch; token transcription error?")
    return token

def init_vault_from_book(book_bytes: bytes,
                         passphrase: str,
                         pepper: str,
                         *,
                         device_id: Optional[str] = None,
                         policy: Optional[Dict] = None,
                         out_path: Optional[str] = None,
                         sources: Optional[List[Dict]] = None) -> VaultHandle:
    """
    Initialize a vault directly from prebuilt book bytes (exactly 1,048,576 bytes recommended).
    Use this with 'book_seed.txt' produced by your book_seed_builder.
    - book_bytes: normalized & packed text as bytes (UTF-8 suggested), ~1 MiB.
    - sources: optional audit list [{'title','url','content_hash','bytes'}, ...]
    """
    if not isinstance(book_bytes, (bytes, bytearray)) or len(book_bytes) == 0:
        raise ValueError("book_bytes must be non-empty bytes")
    if len(book_bytes) != BOOK_SIZE_BYTES:
        # not fatal; we’ll still allow it, but warn by raising a clearer error
        # (you can relax this to a warning if you prefer)
        raise ValueError(f"book_bytes must be exactly {BOOK_SIZE_BYTES} bytes")

    created = time.time()
    policy = dict(policy or {})
    kdf_iters = int(policy.get("pbkdf2_iters", 800_000))
    policy["pbkdf2_iters"] = kdf_iters
    policy.setdefault("purposes", list(DEFAULT_PURPOSES))

    # Edition + public derivation salt
    edition_id = _make_edition_id(book_bytes, edition_num=1)
    salt_kdf = secrets.token_bytes(SALT_LEN)

    # Sources audit (optional)
    if not sources:
        sources = [{
            "title": "book_seed.txt",
            "url": "file://book_seed.txt",
            "content_hash": hashlib.sha512(book_bytes).hexdigest(),
            "bytes": len(book_bytes),
        }]

    # Build sealed payload and write vault
    payload = _build_payload(edition_id=edition_id, created_utc=created, policy=policy,
                             salt_kdf=salt_kdf, book_bytes=book_bytes, sources=sources)
    vault_bytes = _seal_vault_payload(payload, passphrase=passphrase, pepper=pepper,
                                      device_id=device_id, iters=kdf_iters,
                                      edition_id=edition_id, salt_kdf=salt_kdf)

    path = out_path or (edition_id + ".keybook")
    with open(path, "wb") as f:
        f.write(vault_bytes)

    # Ready-to-use handle
    book_hash = hashlib.sha512(book_bytes).digest()
    k_master = _derive_master_key(passphrase, pepper, salt_kdf, kdf_iters)

    return VaultHandle(
        path=path,
        edition_id=edition_id,
        created_utc=created,
        device_ctx=device_id,
        policy=policy,
        book_hash=book_hash,
        salt_kdf=salt_kdf,
        k_master=k_master,
        kdf_iters=kdf_iters,
        purposes=tuple(policy.get("purposes", DEFAULT_PURPOSES)),
    )

# === Engine integration helpers (v3.5) ===

def _norm_bytes(x) -> bytes:
    if x is None:
        return b""
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    return str(x).encode("utf-8")

def make_aad_from_context(bundle: Dict[str, bytes], context) -> bytes:
    """
    Produce an AAD binding that is unique to this keybook by HMAC'ing the context with aux1.
    - context can be str/bytes (e.g., "file:/vault/plan.pdf" or "proto=sync;step=1").
    - returns 64 bytes (SHA-512 digest).
    """
    aux1 = bundle.get("aux1")
    if not isinstance(aux1, (bytes, bytearray)) or len(aux1) != MASTER_LEN:
        # Fall back to unhashed context (engine will hash internally)
        return _norm_bytes(context)
    return hmac.new(aux1, _norm_bytes(context), hashlib.sha512).digest()

# --- Optional: engine wrappers (keeps call sites tiny) ---
def engine_encrypt_v35(data: bytes, bundle: Dict[str, bytes], *, context=None, max_rounds: int = 7, return_b64: bool = True) -> str | bytes:
    """
    Encrypt with cipher_engine_v3_5 using 'enc'/'tran' from the bundle and context-bound AAD.
    """
    from cipher_engine_v3_5 import CipherEngine32x32 as _E
    aad = make_aad_from_context(bundle, context)
    return _E.encrypt(data, enc_key=bundle["enc"], tran_key=bundle["tran"], max_rounds=max_rounds, aad=aad, return_b64=return_b64)

def engine_decrypt_v35(ct: str | bytes, bundle: Dict[str, bytes], *, context=None, max_rounds: int = 7, is_b64: bool = True) -> bytes:
    """
    Decrypt with cipher_engine_v3_5; 'context' must match what was used at encrypt time.
    """
    from cipher_engine_v3_5 import CipherEngine32x32 as _E
    aad = make_aad_from_context(bundle, context)
    return _E.decrypt(ct, enc_key=bundle["enc"], tran_key=bundle["tran"], max_rounds=max_rounds, aad=aad, is_b64=is_b64)

# === Engine integration helpers (v3.6) ===
#
# Deterministic, stateless helpers for CE v3.6 callers.
# These avoid keeping mutable state in keybook; you can derive unique
# identifiers from (edition_id, label, counter, extra) via HKDF-SHA512.

def _norm_bytes32(x: object) -> bytes:
    b = _norm_bytes(x)
    # deterministic condense for 'extra' fields:
    return hashlib.sha256(b).digest()

def derive_message_id(handle: VaultHandle,
                      *,
                      label: str,
                      counter: Optional[int] = None,
                      extra: Optional[bytes | str] = None,
                      length: int = 16) -> bytes:
    """
    Deterministic message_id (8..32 bytes) from the vault:
      msg_id = HKDF(k_master, salt=book_hash,
                    info=b"keybook|v2|msgid|" + edition_id + "|" + label + "|" + str(counter) + "|" + H(extra),
                    L=length)
    Notes:
      - If 'counter' is None, you still get a stable ID for (edition,label,extra).
      - For strict non-reuse, prefer a monotonic counter you store externally,
        or add an ephemeral 'extra' (e.g., a UUIDv4) at encrypt time.
    """
    if not (8 <= length <= 32):
        raise ValueError("message_id length must be 8..32 bytes")
    eid = handle.edition_id
    info = b"|".join([
        b"keybook", b"v2", b"msgid",
        _norm_bytes(eid),
        _norm_bytes(label),
        _norm_bytes("" if counter is None else str(counter)),
        _norm_bytes32(extra or b""),
    ])
    return _hkdf_sha512(handle.k_master, info, handle.book_hash, length)

def derive_nonce(handle: VaultHandle,
                 *,
                 label: str,
                 counter: Optional[int] = None,
                 extra: Optional[bytes | str] = None,
                 length: int = 16) -> bytes:
    """
    Deterministic nonce, same construction as message_id but namespaced.
    Useful if you want a distinct per-message nonce separate from message_id.
    """
    if not (12 <= length <= 32):
        raise ValueError("nonce length should be 12..32 bytes")
    eid = handle.edition_id
    info = b"|".join([
        b"keybook", b"v2", b"nonce",
        _norm_bytes(eid),
        _norm_bytes(label),
        _norm_bytes("" if counter is None else str(counter)),
        _norm_bytes32(extra or b""),
    ])
    return _hkdf_sha512(handle.k_master, info, handle.book_hash, length)

def make_aad_hash(context) -> bytes:
    """
    AAD helper (hashed): SHA-256 over the provided context (bytes/str).
    Returns 32 bytes. If your metadata is sensitive, prefer this over raw strings.
    """
    return hashlib.sha256(_norm_bytes(context)).digest()

def make_aad_hmac(bundle: Dict[str, bytes], context) -> bytes:
    """
    AAD helper (HMAC): HMAC-SHA512 over context keyed by aux1 (32B) from the bundle.
    Returns 64 bytes. If aux1 missing, falls back to SHA-256(context).
    """
    aux1 = bundle.get("aux1")
    if isinstance(aux1, (bytes, bytearray)) and len(aux1) == MASTER_LEN:
        return hmac.new(aux1, _norm_bytes(context), hashlib.sha512).digest()
    return make_aad_hash(context)

# --- Optional: tiny sidecar helper for message_id persistence ---

def write_message_meta(sidecar_path: str, *, message_id: bytes, aad_hint: Optional[str] = None) -> None:
    """
    Writes a minimal JSON sidecar containing message_id (base64) and optional aad_hint.
    Useful when you need to reuse the same message_id at decrypt time.
    """
    meta = {
        "message_id_b64": base64.b64encode(message_id).decode("ascii"),
    }
    if aad_hint:
        meta["aad_hint"] = aad_hint
    with open(sidecar_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, separators=(",", ":"), ensure_ascii=False)

def read_message_meta(sidecar_path: str) -> Optional[dict]:
    """
    Reads the sidecar JSON if present; returns dict or None if missing/unreadable.
    """
    try:
        with open(sidecar_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# Default AAD header-hash length for CE v3.6 (16 or 32). Keep 16 for backward interop.
CE36_DEFAULT_AAD_HASH_LEN = int(os.getenv("CE36_AAD_HASH_LEN", "16"))

# Try to import the v3.6 engine shim
try:
    from cipher_engine import CipherEngine32x32 as _CE36
except Exception:  # pragma: no cover
    _CE36 = None

def engine_encrypt_v36(
    data: bytes,
    bundle: Dict[str, bytes],
    *,
    message_id: Optional[bytes] = None,
    aad_context: Optional[bytes | str] = None,
    pad_to: int = 256,
    pad_jitter_blocks: int = 0,
    pad_jitter_mode: str = "deterministic",
    return_b64: bool = True,
    aad_hash_len: Optional[int] = None,   # NEW: 16 or 32 (defaults to env/constant)
) -> bytes | str:
    """
    Encrypt using cipher_engine v3.6 with selectable AAD header-hash length (16|32).
    If message_id is omitted, a fresh 16-byte random ID is used.
    """
    if _CE36 is None:
        raise RuntimeError("cipher_engine v3.6 shim not available")

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")

    enc_key = bundle["enc"]
    tran_key = bundle["tran"]
    mid = message_id if isinstance(message_id, (bytes, bytearray)) else secrets.token_bytes(16)

    ahl = CE36_DEFAULT_AAD_HASH_LEN if aad_hash_len is None else int(aad_hash_len)
    if ahl not in (16, 32):
        raise ValueError("aad_hash_len must be 16 or 32")

    return _CE36.encrypt(
        bytes(data),
        enc_key=enc_key,
        tran_key=tran_key,
        message_id=mid,
        aad_context=aad_context,      # bytes or str; engine handles both
        pad_to=pad_to,
        pad_jitter_blocks=pad_jitter_blocks,
        pad_jitter_mode=pad_jitter_mode,
        return_b64=return_b64,
        aad_hash_len=ahl,             # ← NEW knob (16|32)
    )

def engine_decrypt_v36(
    ct: bytes | str,
    bundle: Dict[str, bytes],
    *,
    aad_context: Optional[bytes | str] = None,
    is_b64: bool = True,
) -> bytes:
    """
    Decrypt using cipher_engine v3.6.
    The engine auto-detects 16B vs 32B AAD header-hash from the header; no knob needed here.
    """
    if _CE36 is None:
        raise RuntimeError("cipher_engine v3.6 shim not available")

    return _CE36.decrypt(
        ct,
        enc_key=bundle["enc"],
        tran_key=bundle["tran"],
        aad_context=aad_context,
        is_b64=is_b64,
    )

# =========================
# Maintenance CLI (minimal)
# =========================
import argparse
import getpass
import sys
import json

def _prompt_secret(label: str) -> str:
    v = getpass.getpass(f"{label}: ").strip()
    if not v:
        print(f"{label} is required.", file=sys.stderr)
        sys.exit(2)
    return v

def _main_cli(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="keybook", description="Keybook v2 maintenance CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # --- create ---
    p_create = sub.add_parser("create", help="Create a new vault (.keybook)")
    p_create.add_argument("--vault", required=False, help="Output vault file path (.keybook)")
    p_create.add_argument("--device", required=False, help="Device ID (public context)")
    p_create.add_argument("--hint", action="append", default=[], help="Add a user hint (repeatable)")
    p_create.add_argument("--iters", type=int, default=800_000, help="PBKDF2 iterations (default 800k)")

    # --- info ---
    p_info = sub.add_parser("info", help="Show vault info")
    p_info.add_argument("--vault", required=True, help="Vault file path")
    p_info.add_argument("--device", required=False, help="Device ID (if bound)")

    # --- derive ---
    p_der = sub.add_parser("derive", help="Derive a key or bundle")
    p_der.add_argument("--vault", required=True, help="Vault file path")
    p_der.add_argument("--device", required=False, help="Device ID (if bound)")
    p_der.add_argument("--purpose", choices=list(DEFAULT_PURPOSES), help="Purpose (omit with --bundle)")
    p_der.add_argument("--target", required=True, help="Target label (email/device/project)")
    p_der.add_argument("--epoch", required=False, help="Epoch/edition id (default: vault edition)")
    p_der.add_argument("--length", type=int, default=MASTER_LEN, help="Key length (bytes)")
    p_der.add_argument("--bundle", action="store_true", help="Output full bundle instead of single key")
    p_der.add_argument("--b64", action="store_true", help="Output base64 instead of hex")

    # --- rotate ---
    p_rot = sub.add_parser("rotate", help="Rotate (change) the vault passphrase")
    p_rot.add_argument("--vault", required=True, help="Vault file path")
    p_rot.add_argument("--device", required=False, help="Device ID to bind (defaults to current)")
    p_rot.add_argument("--use-token", action="store_true", help="Use an unlock token instead of old passphrase")

    # --- resequence ---
    p_res = sub.add_parser("resequence", help="Create a new edition of the vault (ED<N+1>)")
    p_res.add_argument("--vault", required=True, help="Vault file path")
    p_res.add_argument("--device", required=False, help="Device ID (if bound)")
    p_res.add_argument("--hint", action="append", default=[], help="Add a new resequence hint (repeatable)")
    p_res.add_argument("--iters", type=int, default=None, help="Override PBKDF2 iterations")

    args = parser.parse_args(argv)

    # --- command handlers ---
    if args.cmd == "create":
        hints = args.hint or []
        if len([h for h in hints if h.strip()]) < 1:
            print("Provide at least one --hint (5–10 recommended).", file=sys.stderr)
            return 2
        passphrase = _prompt_secret("Passphrase")
        pepper = _prompt_secret("Paper Pepper (32 chars)")
        policy = {"pbkdf2_iters": int(args.iters), "purposes": list(DEFAULT_PURPOSES)}
        handle = init_vault(hints, passphrase, pepper, device_id=args.device, policy=policy, out_path=args.vault)
        print(json.dumps({"vault": handle.path, "edition_id": handle.edition_id,
                          "created_utc": handle.created_utc, "iters": handle.kdf_iters}, indent=2))
        return 0

    elif args.cmd == "info":
        passphrase = _prompt_secret("Passphrase")
        pepper = _prompt_secret("Paper Pepper")
        handle = open_vault(args.vault, passphrase, pepper, device_id=args.device)
        print(json.dumps(vault_info(handle), indent=2))
        return 0

    elif args.cmd == "derive":
        passphrase = _prompt_secret("Passphrase")
        pepper = _prompt_secret("Paper Pepper")
        handle = open_vault(args.vault, passphrase, pepper, device_id=args.device)

        def enc(b: bytes) -> str:
            return base64.b64encode(b).decode("ascii") if args.b64 else b.hex()

        if args.bundle:
            bundle = derive_bundle(handle, target=args.target, epoch=args.epoch)
            print(json.dumps({
                "edition_id": bundle["edition_id"],
                "epoch": bundle["epoch"],
                "enc":  enc(bundle["enc"]),
                "tran": enc(bundle["tran"]),
                "hmac": enc(bundle["hmac"]),
                "aux1": enc(bundle["aux1"]),
                "aux2": enc(bundle["aux2"]),
            }, indent=2))
        else:
            if not args.purpose:
                print("When not using --bundle, you must specify --purpose.", file=sys.stderr)
                return 2
            key = derive_key(handle, args.purpose, args.target, epoch=args.epoch, length=args.length)
            print(enc(key))
        return 0

    elif args.cmd == "rotate":
        if args.use_token:
            tok_hex = getpass.getpass("Unlock token (hex, 64 chars): ").strip()
            unlock_token = bytes.fromhex(tok_hex)
            new_pass = _prompt_secret("New passphrase")
            pepper = _prompt_secret("Paper Pepper (unchanged)")
            # Rewrap in place using the token; binds to args.device if provided
            h2 = import_vault(
                args.vault,
                passphrase=new_pass,
                pepper=pepper,
                unlock_token=unlock_token,
                device_id=args.device,
                out_path=None,  # overwrite in place
            )
        else:
            old_pass = _prompt_secret("Old passphrase")
            pepper   = _prompt_secret("Paper Pepper (unchanged)")
            new_pass = _prompt_secret("New passphrase")
            h = open_vault(args.vault, passphrase=old_pass, pepper=pepper, device_id=args.device)
            h2 = rotate_passphrase(h, old_passphrase=old_pass, pepper=pepper,
                                   new_passphrase=new_pass, device_id=args.device)
        print(json.dumps({"vault": h2.path, "edition_id": h2.edition_id}, indent=2))
        return 0

    elif args.cmd == "resequence":
        passphrase = _prompt_secret("Passphrase")
        pepper = _prompt_secret("Paper Pepper")
        h = open_vault(args.vault, passphrase, pepper, device_id=args.device)
        hints = args.hint or []
        policy = dict(h.policy)
        if args.iters:
            policy["pbkdf2_iters"] = int(args.iters)
        h2 = resequence_vault(h, passphrase, pepper, new_hints=hints,
                              policy=policy, device_id=args.device)
        print(json.dumps({"vault": h2.path, "edition_id": h2.edition_id}, indent=2))
        return 0

    return 1

if __name__ == "__main__":
    raise SystemExit(_main_cli())
