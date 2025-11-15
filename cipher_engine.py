#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cipher_engine.py — compatibility shim that adapts older v3.x call sites
to the new v3.6 engine.

Purpose
-------
- Accepts legacy kwargs (`max_rounds`, `aad`, `context`, etc.) and ignores/renames them.
- Auto-generates a 16-byte message_id when the caller doesn’t provide one.
- Keeps the public name `CipherEngine32x32` so existing imports keep working.
- Exposes v3.6's `aad_hash_len` knob (16 or 32) for callers that want it.

Hard requirement
----------------
This shim requires `cipher_engine_v3_6.py` in the same folder.

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import secrets

try:
    from cipher_engine_v3_6 import CipherEngine32x32 as _Engine36
except Exception as e:  # pragma: no cover
    raise RuntimeError("cipher_engine.py shim requires cipher_engine_v3_6.py") from e


class CipherEngine32x32:
    """
    Adapter class exposing the familiar v3.x API surface, backed by v3.6.
    """

    VERSION = b"36"

    @staticmethod
    def encrypt(
        data: bytes,
        *,
        enc_key: bytes,
        tran_key: bytes,
        # legacy / optional:
        max_rounds: int | None = None,      # ignored (v3.6 is stream-based)
        return_b64: bool = True,
        aad: bytes | None = None,           # legacy name
        context: bytes | None = None,       # very old legacy name
        aad_context: bytes | str | None = None,
        message_id: bytes | None = None,
        pad_to: int = 256,
        pad_jitter_blocks: int = 0,         # align with other wrappers’ default
        pad_jitter_mode: str = "deterministic",
        aad_hash_len: int | None = None,    # v3.6 feature (16 or 32)
        **kwargs,
    ):
        # Prefer aad_context; fall back to legacy names if needed
        if aad_context is None and aad is not None:
            aad_context = aad
        if aad_context is None and context is not None:
            aad_context = context

        # v3.6 requires a message_id; for legacy callers, generate one.
        if message_id is None:
            message_id = secrets.token_bytes(16)

        # Strip legacy/unknown kwargs that older call sites may pass
        kwargs.pop("rounds", None)
        kwargs.pop("max_rounds", None)

        return _Engine36.encrypt(
            data,
            enc_key=enc_key,
            tran_key=tran_key,
            message_id=message_id,
            aad_context=aad_context,
            pad_to=pad_to,
            pad_jitter_blocks=pad_jitter_blocks,
            pad_jitter_mode=pad_jitter_mode,
            return_b64=return_b64,
            aad_hash_len=aad_hash_len,
            **kwargs,
        )

    @staticmethod
    def decrypt(
        ct: bytes | str,
        *,
        enc_key: bytes,
        tran_key: bytes,
        is_b64: bool = True,
        # legacy / optional:
        max_rounds: int | None = None,      # ignored
        aad: bytes | None = None,           # legacy name
        context: bytes | None = None,       # very old legacy name
        aad_context: bytes | str | None = None,
        **kwargs,
    ) -> bytes:
        # Prefer aad_context; fall back to legacy names if needed
        if aad_context is None and aad is not None:
            aad_context = aad
        if aad_context is None and context is not None:
            aad_context = context

        # Strip legacy/unknown kwargs
        kwargs.pop("rounds", None)
        kwargs.pop("max_rounds", None)

        return _Engine36.decrypt(
            ct,
            enc_key=enc_key,
            tran_key=tran_key,
            aad_context=aad_context,
            is_b64=is_b64,
            **kwargs,
        )

    # Optional: a tiny info probe some tools may call
    @staticmethod
    def info():
        return {
            "backing": "v3.6",
            "version": "36",
            "shim": True,
            "notes": "Legacy kwargs accepted; message_id auto-generated when absent; supports aad_hash_len.",
        }
