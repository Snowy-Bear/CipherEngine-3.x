#!/usr/bin/env python3
"""
sc_cli_selftest.py — End-to-end self-test for sc_cli (v3.5/v3.6 compatible)

What it does
------------
1) Creates a temporary workspace
2) Builds a 1 MiB Keybook vault
3) Writes a random plaintext (128 KiB + 7 bytes)
4) Runs sc_cli encrypt/decrypt in:
   - Base64 mode (default)
   - Raw mode (--raw)
   with AAD, padding, jitter, strict, and deterministic msgid-base
5) Verifies round-trips match exactly
6) Cleans up temp directory on success (keeps it on failure)

No interactive prompts: passes --pass / --pepper to sc_cli.

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, sys, shutil, tempfile, secrets, hashlib

import keybook
import sc_cli


def _p(*a): print(*a, flush=True)


def run():
    # 1) Temp workspace
    tmp = tempfile.mkdtemp(prefix="sc_cli_test_")
    _p("[1/6] Preparing temp workspace...")
    _p("       temp dir:", tmp)

    try:
        # 2) Create vault (exactly 1 MiB book)
        _p("[2/6] Creating vault (1 MiB book)...")
        book = secrets.token_bytes(keybook.BOOK_SIZE_BYTES)  # exact size required
        vault_path = os.path.join(tmp, "SelfTest.keybook")

        passphrase = "pass-" + secrets.token_hex(6)
        pepper     = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 32 chars (paper-friendly)
        handle = keybook.init_vault_from_book(
            book_bytes=book,
            passphrase=passphrase,
            pepper=pepper,
            out_path=vault_path,
            sources=[{
                "title":"selftest",
                "url":"about:selftest",
                "content_hash": hashlib.sha512(book).hexdigest(),
                "bytes": len(book),
            }],
        )
        _p("       vault:", vault_path)

        # 3) Plaintext file
        _p("[3/6] Writing plaintext file...")
        pt = secrets.token_bytes(128 * 1024 + 7)  # odd length to shake edge cases
        pt_path = os.path.join(tmp, "msg.bin")
        with open(pt_path, "wb") as f:
            f.write(pt)

        # Common knobs (v3.6; safely ignored by v3.5)
        label = "selftest"
        aad_literal = "file:/tmp/sc_cli_selftest"
        pad_to = 256
        jitter = 2
        strict = True
        # Deterministic msgid-base: 16B from aux material (any 16..32B works)
        msgid_base = hashlib.sha512(b"ce36-selftest|fixed-seed").digest()[:16].hex()

        # 4) Base64 mode
        _p("[4/6] sc_cli encrypt/decrypt (Base64)...")
        enc_b64 = pt_path + ".enc.txt"
        dec_b64 = pt_path + ".b64.dec"

        rc = sc_cli.main([
            "--vault", vault_path,
            "--label", label,
            "--rounds", "7",
            "--pass", passphrase,
            "--pepper", pepper,
            "--aad", aad_literal,
            "--pad", str(pad_to),
            "--jitter", str(jitter),
            "--strict",
            "--msgid-base", msgid_base,
            "encrypt", pt_path,
            "--out", enc_b64,
        ])
        if rc != 0:
            raise RuntimeError(f"encrypt (b64) returned {rc}")
        _p("Wrote:", enc_b64)

        rc = sc_cli.main([
            "--vault", vault_path,
            "--label", label,
            "--rounds", "7",
            "--pass", passphrase,
            "--pepper", pepper,
            "--aad", aad_literal,
            "--pad", str(pad_to),
            "--jitter", str(jitter),
            "--strict",
            "--msgid-base", msgid_base,
            "decrypt", enc_b64,
            "--out", dec_b64,
        ])
        if rc != 0:
            raise RuntimeError(f"decrypt (b64) returned {rc}")
        _p("Wrote:", dec_b64)

        with open(dec_b64, "rb") as f:
            roundtrip = f.read()
        if roundtrip != pt:
            raise AssertionError("Base64 round-trip mismatch")

        # 5) Raw mode
        _p("[5/6] sc_cli encrypt/decrypt (Raw)...")
        enc_raw = pt_path + ".enc"
        dec_raw = pt_path + ".raw.dec"

        rc = sc_cli.main([
            "--vault", vault_path,
            "--label", label,
            "--rounds", "7",
            "--pass", passphrase,
            "--pepper", pepper,
            "--aad", aad_literal,
            "--pad", str(pad_to),
            "--jitter", str(jitter),
            "--strict",
            "--msgid-base", msgid_base,
            "encrypt", pt_path,
            "--out", enc_raw,
            "--raw",
        ])
        if rc != 0:
            raise RuntimeError(f"encrypt (raw) returned {rc}")
        _p("Wrote:", enc_raw)

        rc = sc_cli.main([
            "--vault", vault_path,
            "--label", label,
            "--rounds", "7",
            "--pass", passphrase,
            "--pepper", pepper,
            "--aad", aad_literal,
            "--pad", str(pad_to),
            "--jitter", str(jitter),
            "--strict",
            "--msgid-base", msgid_base,
            "decrypt", enc_raw,
            "--out", dec_raw,
            "--raw",
        ])
        if rc != 0:
            raise RuntimeError(f"decrypt (raw) returned {rc}")
        _p("Wrote:", dec_raw)

        with open(dec_raw, "rb") as f:
            roundtrip2 = f.read()
        if roundtrip2 != pt:
            raise AssertionError("Raw round-trip mismatch")

        # 6) Done
        _p("\n=== SC_CLI SELF-TEST: PASS ===\n")
        _p("Temp dir:", tmp)
        _p("Temp dir removed.")
        shutil.rmtree(tmp, ignore_errors=True)

    except Exception as e:
        _p(f"\n*** FAIL: {e}")
        _p(f"Temp dir kept at: {tmp} (for inspection)")
        try:
            input("\nPress Enter to close this test...")
        except Exception:
            pass
        return

    try:
        input("\nPress Enter to close this test...")
    except Exception:
        pass


if __name__ == "__main__":
    run()
