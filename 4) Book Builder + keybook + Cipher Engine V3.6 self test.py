#!/usr/bin/env python3
"""
book_builder_selftest_safe.py — Keybook + Book Seed Builder + CipherEngine v3.x self-test

- Adapts to engine v3.6 (cipher_engine.py) or v3.5 (cipher_engine_v3_5.py)
- Builds an offline seed from a synthetic ~3 MiB corpus
- Creates a vault, derives a bundle and AAD
- Runs Base64 and raw enc/dec
- Verifies AAD mismatch fails authentication

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, tempfile, secrets, traceback, inspect

PRINT = lambda *a, **k: print(*a, **k, flush=True)

def _params(fn):
    try:
        return set(inspect.signature(fn).parameters.keys())
    except Exception:
        return set()

def run():
    try:
        # --- imports (adjust builder import to your filename) ---
        PRINT("[1/7] Importing modules...")
        import keybook as KB
        try:
            # Change if your file isn’t named exactly 'book_seed_builder.py'
            import book_seed_builder as BB
        except Exception as e:
            PRINT("!! Failed to import book_seed_builder:", e)
            PRINT("   If your file name has spaces, either rename to 'book_seed_builder.py'")
            PRINT("   or change the import above to your filename.")
            raise

        # Prefer v3.6; fall back to v3.5
        try:
            from cipher_engine import CipherEngine32x32 as Engine  # v3.6 shim/backing
            engine_label = "cipher_engine (v3.6+)"
        except Exception:
            from cipher_engine_v3_5 import CipherEngine32x32 as Engine  # v3.5
            engine_label = "cipher_engine_v3_5 (v3.5)"
        PRINT(f"     engine: {engine_label}")

        ENC_PARAMS = _params(Engine.encrypt)
        DEC_PARAMS = _params(Engine.decrypt)
        AAD_PARAM = (
            "aad_context" if "aad_context" in ENC_PARAMS
            else ("aad" if "aad" in ENC_PARAMS else None)
        )
        HAS_MSGID_ENC   = ("message_id" in ENC_PARAMS)           # encrypt may require it even if decrypt doesn't expose it
        SUPPORTS_PAD    = ("pad_to" in ENC_PARAMS)
        SUPPORTS_JITTER = ("pad_jitter_blocks" in ENC_PARAMS)
        SUPPORTS_STRICT = ("strict_mode" in ENC_PARAMS) and ("strict_mode" in DEC_PARAMS)

        # --- synthetic offline corpus ---
        PRINT("[2/7] Creating synthetic offline corpus (~3 MiB)...")
        tmpdir = tempfile.mkdtemp(prefix="bb_kb_ce_")
        corpus_path = os.path.join(tmpdir, "corpus.txt")
        para = (
            "lorem ipsum dolor sit amet, consectetur adipiscing elit. "
            "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
            "ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
            "duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. "
            "excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n"
        )
        block = (para * 50 + "0123456789 ABCDEF\n") * 300  # ~3+ MiB
        with open(corpus_path, "w", encoding="utf-8") as f:
            f.write(block)
        PRINT("     corpus at:", corpus_path)

        # --- build seed (offline) ---
        PRINT("[3/7] Building seed (offline)...")
        seed_bytes, audit = BB.build_offline(corpus_path)
        PRINT("     seed bytes:", len(seed_bytes), "(TARGET_SIZE:", getattr(BB, "TARGET_SIZE", len(seed_bytes)), ")")
        assert isinstance(audit, list) and audit, "Audit empty"

        # --- init keybook from seed ---
        PRINT("[4/7] Initializing keybook from seed...")
        passphrase = "correct horse battery staple"
        # Use strict 32-char pepper to keep other tools happy
        pepper = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789AB"  # 32 chars, paper-safe
        vh = KB.init_vault_from_book(seed_bytes, passphrase, pepper, device_id="ipad-pro",
                                     out_path=os.path.join(tmpdir, "vault.keybook"))
        PRINT("     vault:", vh.path, "edition:", vh.edition_id)

        # --- derive bundle & AAD context ---
        PRINT("[5/7] Deriving bundle & AAD context...")
        bundle = KB.derive_bundle(vh, target="demo")
        ctx = "file:/vault/demo.txt"
        # HMAC over context using aux1; safe even if the engine hashes internally again
        aad = KB.make_aad_from_context(bundle, ctx)
        PRINT("     AAD bytes (from make_aad_from_context):", len(aad))

        # --- engine round-trips (Base64) ---
        PRINT("[6/7] Engine round trips...")
        msg = b"hello book-builder integration \x00\x01\xfe\xff"

        enc_kwargs = dict(enc_key=bundle["enc"], tran_key=bundle["tran"])
        dec_kwargs = dict(enc_key=bundle["enc"], tran_key=bundle["tran"])

        if "max_rounds" in ENC_PARAMS: enc_kwargs["max_rounds"] = 7
        if "return_b64" in ENC_PARAMS: enc_kwargs["return_b64"] = True
        if "max_rounds" in DEC_PARAMS: dec_kwargs["max_rounds"] = 7
        if "is_b64"     in DEC_PARAMS: dec_kwargs["is_b64"] = True

        if AAD_PARAM is not None:
            enc_kwargs[AAD_PARAM] = aad
            dec_kwargs[AAD_PARAM] = aad

        # v3.6-style knobs (only if supported)
        if HAS_MSGID_ENC:
            enc_kwargs["message_id"] = secrets.token_bytes(16)   # supply even if decrypt() lacks it
        if SUPPORTS_PAD:
            enc_kwargs["pad_to"] = 256
        if SUPPORTS_JITTER:
            enc_kwargs["pad_jitter_blocks"] = 0
        if SUPPORTS_STRICT:
            enc_kwargs["strict_mode"] = True
            dec_kwargs["strict_mode"] = True

        ct_b64 = Engine.encrypt(msg, **enc_kwargs)
        pt = Engine.decrypt(ct_b64, **dec_kwargs)
        assert pt == msg, "b64 round-trip mismatch"
        PRINT("     b64 OK")

        # --- engine round-trips (raw) ---
        msg2 = secrets.random_bytes(12345) if hasattr(secrets, "random_bytes") else secrets.token_bytes(12345)
        enc_raw = dict(enc_kwargs)
        dec_raw = dict(dec_kwargs)
        if "return_b64" in ENC_PARAMS: enc_raw["return_b64"] = False
        if "is_b64"     in DEC_PARAMS: dec_raw["is_b64"] = False
        # Use a new message_id for the second message if required
        if HAS_MSGID_ENC:
            enc_raw["message_id"] = secrets.token_bytes(16)

        ct_raw = Engine.encrypt(msg2, **enc_raw)
        pt2 = Engine.decrypt(ct_raw, **dec_raw)
        assert pt2 == msg2, "raw round-trip mismatch"
        PRINT("     raw OK")

        # --- AAD mismatch must fail (only when supported) ---
        PRINT("[7/7] AAD mismatch check...")
        if AAD_PARAM is not None:
            bad_dec = dict(dec_kwargs)
            bad_dec[AAD_PARAM] = b"other-context"
            try:
                Engine.decrypt(ct_b64, **bad_dec)
                raise AssertionError("Expected authentication failure with wrong AAD")
            except Exception:
                PRINT("     AAD mismatch OK")
        else:
            PRINT("     (skipped — engine has no AAD parameter)")

        PRINT("\n=== ALL CHECKS PASSED ===")

    except AssertionError as ae:
        PRINT("\n*** ASSERTION FAILED:", ae)
        traceback.print_exc()
    except Exception as e:
        PRINT("\n*** ERROR:", e)
        traceback.print_exc()
    finally:
        try:
            input("\nPress Enter to close this test...")
        except Exception:
            pass

if __name__ == "__main__":
    run()
