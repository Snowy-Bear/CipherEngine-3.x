"""
secure_channel.py — Thin adapter tying Keybook + CipherEngine v3 together.

Dependencies (place alongside this file):
  - keybook.py
  - cipher_engine_v3_5.py  (preferred for v3.5)  OR  cipher_engine.py (v3.6+)
Optional:
  - pickfile.py            (provides pick_file(...) for interactive console picking)

Features:
  - ChannelContext: open vault, derive bundle for a label, set rounds, optional AAD.
  - Bytes/Text/File helpers (+ Base64 text by default for ASCII-safe transport).
  - Line-framed streaming (each line independently authenticated + 4B sequence).
  - iOS-friendly case-insensitive file lookup.
  - Optional interactive file picker when in_path is None.
  - Backward compatible with v3.5 (no message_id/padding knobs) and forwards to v3.6
    (message_id, pad_to, jitter, aad_hash_len, strict-mode if the engine supports it).

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Iterable, Iterator, Dict, Any, Callable
import os
import pathlib
import inspect
import hmac
import hashlib
import struct
import secrets

import keybook

# ---- engine import: prefer v3.5 file, fall back to generic name (v3.6) ----
try:
    # v3.5: may not support aad_context/message_id/padding knobs
    from cipher_engine_v3_5 import CipherEngine32x32 as Engine
    ENGINE_FLAVOR = "v3.5"
except Exception:
    # v3.6 shim: supports message_id, aad_context, pad_to, pad_jitter_blocks,
    # (optionally) strict_mode and aad_hash_len if provided by the engine/shim.
    from cipher_engine import CipherEngine32x32 as Engine
    ENGINE_FLAVOR = "v3.6+"

# ---- optional picker (if pickfile.py is present) ----
try:
    from pickfile import pick_file  # tiny console picker (optional)
except Exception:
    pick_file = None  # gracefully disabled if not available


# ---------- exceptions ----------

class SecureChannelError(Exception):
    """Base exception for secure_channel."""


class BundleShapeError(SecureChannelError):
    """Raised when a derived bundle is missing required keys or wrong sizes."""


# ---------- validation & helpers ----------

_REQUIRED_KEYS = ("enc", "tran")


def _validate_bundle(bundle: Dict[str, bytes]) -> None:
    if not isinstance(bundle, dict):
        raise BundleShapeError("bundle must be a dict of bytes")
    missing = [k for k in _REQUIRED_KEYS if k not in bundle]
    if missing:
        raise BundleShapeError(f"bundle missing keys: {missing}; expected {list(_REQUIRED_KEYS)}")
    for k in _REQUIRED_KEYS:
        v = bundle[k]
        if not isinstance(v, (bytes, bytearray)) or len(v) != 32:
            got_len = len(v) if hasattr(v, "__len__") else "n/a"
            raise BundleShapeError(f"bundle['{k}'] must be 32-byte bytes; got type={type(v)} len={got_len}")


def _sig_has(fn: Callable, name: str) -> bool:
    try:
        return name in inspect.signature(fn).parameters
    except Exception:
        return False


def _engine_supports(name: str) -> bool:
    try:
        return _sig_has(Engine.encrypt, name) and _sig_has(Engine.decrypt, name)
    except Exception:
        return False


SUPPORTS_AAD        = _engine_supports("aad_context") or _sig_has(Engine.encrypt, "aad_context")
SUPPORTS_MSGID      = _sig_has(Engine.encrypt, "message_id")  # decrypt may or may not require it
SUPPORTS_PAD_TO     = _sig_has(Engine.encrypt, "pad_to")
SUPPORTS_JITTER     = _sig_has(Engine.encrypt, "pad_jitter_blocks")
SUPPORTS_STRICT     = _sig_has(Engine.encrypt, "strict_mode") and _sig_has(Engine.decrypt, "strict_mode")
SUPPORTS_AHL        = _sig_has(Engine.encrypt, "aad_hash_len")  # v3.6 header-hash length (16|32)


def _find_path_case_insensitive(name: str | pathlib.Path) -> pathlib.Path:
    """
    Return a real path matching 'name' with case-insensitive search in its directory.
    Raises FileNotFoundError if not found.
    """
    p = pathlib.Path(name)
    if p.exists():
        return p

    base = p.parent if p.parent.as_posix() not in ("", ".") else pathlib.Path(".")
    target = p.name.lower()
    try:
        for fname in os.listdir(base):
            if fname.lower() == target:
                return base / fname
    except FileNotFoundError:
        pass
    raise FileNotFoundError(f"File not found (case-insensitive search): {name}")


def _default_encrypt_out_path(in_real: pathlib.Path, out_path: Optional[str | pathlib.Path], as_base64_text: bool) -> pathlib.Path:
    if out_path is not None:
        return pathlib.Path(out_path)
    return in_real.with_name(in_real.name + (".enc.txt" if as_base64_text else ".enc"))


def _default_decrypt_out_path(in_real: pathlib.Path, out_path: Optional[str | pathlib.Path]) -> pathlib.Path:
    if out_path is not None:
        return pathlib.Path(out_path)
    name = in_real.name
    if name.endswith(".enc.txt"):
        base = name[: -len(".enc.txt")]
        return in_real.with_name(base + ".dec")
    if name.endswith(".enc"):
        base = name[: -len(".enc")]
        return in_real.with_name(base + ".dec")
    return in_real.with_name(name + ".dec")


# ---------- message_id derivation helpers (for v3.6) ----------

def _derive_msgid_from_base(base: bytes, counter: int, length: int = 16) -> bytes:
    """
    Deterministic per-message (or per-chunk) message_id from a base-id and a counter.
    Uses HMAC-SHA512(base, "sc|msgid|" + counter_be64)[:length].
    """
    if not isinstance(base, (bytes, bytearray)) or len(base) == 0:
        raise SecureChannelError("message_id_base must be non-empty bytes")
    ctr = struct.pack(">Q", counter)
    tag = hmac.new(base, b"sc|msgid|" + ctr, hashlib.sha512).digest()
    return tag[:max(8, min(32, length))]


def _fresh_msgid(vault: keybook.VaultHandle, label: str, counter: int) -> bytes:
    """
    Attempt to use keybook helper if present; otherwise fallback to random token.
    """
    # Prefer deterministic derivation (replay-filter friendly) if helper exists
    if hasattr(keybook, "derive_message_id"):
        try:
            return keybook.derive_message_id(vault, label=label, counter=counter)
        except Exception:
            pass
    # Fallback: 16B random (caller should persist externally if needed)
    return secrets.token_bytes(16)


# ---------- main context ----------

@dataclass
class ChannelContext:
    """
    Holds an opened Keybook vault, a label, rounds, the derived bundle, and optional AAD/message-id policy.
    For v3.6 engines, we auto-provide message_id per message/chunk (deterministic from base+counter if provided).
    """
    vault_handle: Any
    label: str
    rounds: int = 7
    bundle: Optional[Dict[str, bytes]] = None
    aad_context: Optional[bytes] = None

    # v3.6+ options (used only if supported by engine)
    pad_to: int = 256
    pad_jitter_blocks: int = 0
    strict_mode: bool = True
    aad_hash_len: Optional[int] = None  # 16 or 32 when supported

    # message-id policy
    message_id_base: Optional[bytes] = None
    _msg_counter: int = field(default=0, init=False, repr=False)

    @classmethod
    def open_and_derive(
        cls,
        vault_path: str | pathlib.Path = "MyVault.keybook",
        passphrase: Optional[str] = None,
        pepper: Optional[str] = None,
        label: str = "dm:default",
        rounds: int = 7,
        aad_context: Optional[bytes] = None,
        *,
        pad_to: int = 256,
        pad_jitter_blocks: int = 0,
        strict_mode: bool = True,
        message_id_base: Optional[bytes] = None,
        aad_hash_len: Optional[int] = None,
    ) -> "ChannelContext":
        """
        Open a Keybook vault and derive a bundle for the given label.
        If aad_context is provided and the engine supports it, it will be used.
        For v3.6, you can pass a message_id_base; otherwise per-message IDs are randomized.
        """
        vh = keybook.open_vault(str(vault_path), passphrase=passphrase, pepper=pepper)
        bundle = keybook.derive_bundle(vh, label)
        _validate_bundle(bundle)
        # Normalize aad_context to bytes if provided
        if aad_context is not None and not isinstance(aad_context, (bytes, bytearray, memoryview)):
            raise TypeError("aad_context must be bytes-like or None")
        ac = bytes(aad_context) if isinstance(aad_context, (bytearray, memoryview)) else aad_context
        # normalize message_id_base if provided
        mib = None
        if message_id_base is not None:
            if not isinstance(message_id_base, (bytes, bytearray)):
                raise TypeError("message_id_base must be bytes or None")
            mib = bytes(message_id_base)
        # normalize aad_hash_len
        ahl = None
        if aad_hash_len is not None:
            if int(aad_hash_len) not in (16, 32):
                raise ValueError("aad_hash_len must be 16 or 32")
            ahl = int(aad_hash_len)
        return cls(
            vault_handle=vh,
            label=label,
            rounds=rounds,
            bundle=bundle,
            aad_context=ac,
            pad_to=pad_to,
            pad_jitter_blocks=pad_jitter_blocks,
            strict_mode=strict_mode,
            message_id_base=mib,
            aad_hash_len=ahl,
        )

    # ---- internal: build kwargs based on engine feature detection ----

    def _common_encrypt_kwargs(self, *, msg_counter_increment: int = 1) -> Dict[str, Any]:
        if self.bundle is None:
            raise BundleShapeError("bundle not initialized")
        kwargs: Dict[str, Any] = dict(
            enc_key=self.bundle["enc"],
            tran_key=self.bundle["tran"],
            max_rounds=self.rounds,
        )
        if SUPPORTS_AAD and self.aad_context is not None:
            kwargs["aad_context"] = self.aad_context
        if SUPPORTS_PAD_TO:
            kwargs["pad_to"] = max(16, int(self.pad_to))
        if SUPPORTS_JITTER:
            kwargs["pad_jitter_blocks"] = max(0, min(16, int(self.pad_jitter_blocks)))
        if SUPPORTS_STRICT:
            kwargs["strict_mode"] = bool(self.strict_mode)
        if SUPPORTS_AHL and self.aad_hash_len is not None:
            kwargs["aad_hash_len"] = int(self.aad_hash_len)
        if SUPPORTS_MSGID:
            # derive a message_id for this encryption
            base = self.message_id_base
            if base is None:
                # derive from keybook if possible; otherwise random per message
                msg_id = _fresh_msgid(self.vault_handle, self.label, self._msg_counter)
            else:
                msg_id = _derive_msgid_from_base(base, self._msg_counter)
            kwargs["message_id"] = msg_id
            self._msg_counter += msg_counter_increment
        return kwargs

    def _common_decrypt_kwargs(self) -> Dict[str, Any]:
        if self.bundle is None:
            raise BundleShapeError("bundle not initialized")
        kwargs: Dict[str, Any] = dict(
            enc_key=self.bundle["enc"],
            tran_key=self.bundle["tran"],
            max_rounds=self.rounds,
        )
        if SUPPORTS_AAD and self.aad_context is not None:
            kwargs["aad_context"] = self.aad_context
        if SUPPORTS_STRICT:
            kwargs["strict_mode"] = bool(self.strict_mode)
        # v3.6 can authenticate header-bound message_id internally.
        return kwargs

    # ---- bytes ----

    def encrypt_bytes(self, data: bytes, return_b64: bool = True) -> bytes | str:
        """
        Encrypt arbitrary bytes. Return Base64 (str) by default; raw bytes if return_b64=False.
        v3.6: supplies message_id, padding knobs, strict_mode, aad_hash_len as supported.
        """
        _validate_bundle(self.bundle)
        kwargs = self._common_encrypt_kwargs()
        kwargs["return_b64"] = return_b64
        return Engine.encrypt(data, **kwargs)

    def decrypt_bytes(self, ct: bytes | str, is_b64: bool = True) -> bytes:
        """
        Decrypt ciphertext (Base64 str by default) back to bytes.
        v3.6: passes aad_context/strict_mode if supported.
        """
        _validate_bundle(self.bundle)
        kwargs = self._common_decrypt_kwargs()
        kwargs["is_b64"] = is_b64
        return Engine.decrypt(ct, **kwargs)

    # ---- text (UTF-8) ----

    def encrypt_text(self, text: str, return_b64: bool = True) -> bytes | str:
        """Encrypt a Unicode string (UTF-8 encoded)."""
        return self.encrypt_bytes(text.encode("utf-8"), return_b64=return_b64)

    def decrypt_text(self, ct: bytes | str, is_b64: bool = True) -> str:
        """Decrypt to Unicode string (UTF-8), replacing invalid sequences if any."""
        pt = self.decrypt_bytes(ct, is_b64=is_b64)
        return pt.decode("utf-8", errors="replace")

    # ---- files ----

    def encrypt_file(
        self,
        in_path: str | pathlib.Path | None = None,
        out_path: str | pathlib.Path | None = None,
        as_base64_text: bool = True,
    ) -> pathlib.Path:
        """
        Encrypt an entire file.

        - If in_path is None and a pick_file helper is available, shows a picker.
        - If as_base64_text=True, writes ASCII .txt with Base64 ciphertext (default name: <in>.enc.txt).
        - If False, writes raw binary ciphertext (default name: <in>.enc).

        Returns the output path written.
        """
        if in_path is None:
            if not pick_file:
                raise ValueError("No input path provided and no picker available (pickfile.py not found).")
            in_path = pick_file("Pick file to encrypt")

        in_real = _find_path_case_insensitive(in_path)
        data = in_real.read_bytes()
        ct = self.encrypt_bytes(data, return_b64=as_base64_text)

        out_p = _default_encrypt_out_path(in_real, out_path, as_base64_text)
        if as_base64_text:
            if not isinstance(ct, str):
                ct = ct.decode("ascii", errors="strict")
            out_p.write_text(ct, encoding="ascii")
        else:
            if isinstance(ct, str):
                raise SecureChannelError("Internal: expected raw bytes when as_base64_text=False")
            out_p.write_bytes(ct)
        return out_p

    def decrypt_file(
        self,
        in_path: str | pathlib.Path | None = None,
        out_path: str | pathlib.Path | None = None,
        is_b64_input: bool = True,
    ) -> pathlib.Path:
        """
        Decrypt a file produced by encrypt_file.

        - If in_path is None and a pick_file helper is available, shows a picker.
        - If is_b64_input=True, reads ASCII Base64; else reads raw binary.

        Returns the output path written.
        """
        if in_path is None:
            if not pick_file:
                raise ValueError("No input path provided and no picker available (pickfile.py not found).")
            exts = [".txt"] if is_b64_input else [".enc", ".bin"]
            try:
                in_path = pick_file("Pick ciphertext to decrypt", extensions=exts)
            except Exception:
                in_path = pick_file("Pick ciphertext to decrypt")

        in_real = _find_path_case_insensitive(in_path)
        if is_b64_input:
            ct = in_real.read_text(encoding="ascii")
        else:
            ct = in_real.read_bytes()

        pt = self.decrypt_bytes(ct, is_b64=is_b64_input)
        out_p = _default_decrypt_out_path(in_real, out_path)
        pathlib.Path(out_p).write_bytes(pt)
        return out_p

    # ---- simple line-framed streaming (each line = a full ciphertext) ----
    # Each line is independently authenticated.
    # v3.6: we derive a unique message_id per chunk (base + seq) if supported.

    def encrypt_to_lines(
        self, data: bytes, chunk_size: int = 64 * 1024
    ) -> Iterator[str]:
        """
        Yield Base64 ciphertext lines, each independently authenticated.
        Adds a 4-byte big-endian sequence number inside each chunk.
        """
        seq = 0
        off = 0
        while off < len(data):
            chunk = data[off: off + chunk_size]
            frame = seq.to_bytes(4, "big") + chunk

            if SUPPORTS_MSGID:
                # one msg per chunk → increment counter only by 1
                kwargs = self._common_encrypt_kwargs(msg_counter_increment=1)
                line = Engine.encrypt(frame, return_b64=True, **kwargs)
            else:
                line = self.encrypt_bytes(frame, return_b64=True)

            if not isinstance(line, str):
                line = line.decode("ascii", errors="strict")
            yield line
            seq += 1
            off += chunk_size

    def decrypt_lines(self, lines: Iterable[str]) -> bytes:
        """
        Combine Base64 ciphertext lines back to bytes.
        Validates order via the 4-byte sequence number.
        """
        out = bytearray()
        expected = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue

            if SUPPORTS_MSGID:
                # For v3.6, decrypt() does not strictly require passing message_id
                # because it’s authenticated in the header.
                kwargs = self._common_decrypt_kwargs()
                frame = Engine.decrypt(line, is_b64=True, **kwargs)
            else:
                frame = self.decrypt_bytes(line, is_b64=True)

            if len(frame) < 4:
                raise SecureChannelError("short frame")
            seq = int.from_bytes(frame[:4], "big")
            if seq != expected:
                raise SecureChannelError(f"out-of-order/missing chunk: got {seq}, expected {expected}")
            out.extend(frame[4:])
            expected += 1
        return bytes(out)
