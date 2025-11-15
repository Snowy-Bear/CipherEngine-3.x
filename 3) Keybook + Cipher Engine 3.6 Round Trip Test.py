#!/usr/bin/env python3
"""
Integration self-test: Keybook v2 × CipherEngine v3.x (auto-adapts to v3.5 and v3.6)

Checks:
  - Bundle derivation -> encrypt/decrypt with bound AAD (if supported)
  - AAD mismatch => auth failure (uniform)
  - Round-trips in Base64 and raw modes
  - Sizes across chunk boundaries (0, 1, CHUNK-1, CHUNK, CHUNK+1, 2*CHUNK+5)
  - Resequence vault -> bundles change -> old CT fails with new bundle

Exit: 0 on pass, 1 on any failure.

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, sys, tempfile, secrets, traceback, inspect

# --- keybook imports (v2 API) ---
from keybook import (
    init_vault, derive_bundle, resequence_vault, make_aad_from_context
)

# --- try v3.6 first (cipher_engine.py shim), then v3.5 (cipher_engine_v3_5.py) ---
Engine = None
ENGINE_IMPORT_LABEL = ""
try:
    from cipher_engine import CipherEngine32x32 as Engine  # v3.6 shim preferred
    ENGINE_IMPORT_LABEL = "cipher_engine (v3.6+ shim)"
except Exception:
    try:
        from cipher_engine_v3_5 import CipherEngine32x32 as Engine  # legacy
        ENGINE_IMPORT_LABEL = "cipher_engine_v3_5 (v3.5)"
    except Exception as e:
        print("ERROR: could not import CipherEngine32x32:", e, file=sys.stderr)
        sys.exit(1)

# CHUNK size (for boundary tests) — best-effort probe
try:
    import cipher_engine as _ce_mod
    CHUNK_SIZE = getattr(_ce_mod, "CHUNK_SIZE", 4096)
except Exception:
    try:
        import cipher_engine_v3_5 as _ce_mod35
        CHUNK_SIZE = getattr(_ce_mod35, "CHUNK_SIZE", 4096)
    except Exception:
        CHUNK_SIZE = 4096

# ---------------- helpers ----------------
def _ok(why=""): return {"ok": True, "why": why}
def _fail(why):  return {"ok": False, "why": why}
def _rand(n):    return secrets.token_bytes(n)

def _report(results):
    names = list(results.keys())
    all_ok = all(results[n]["ok"] for n in names)
    print(f"All passed: {all_ok}")
    for n in names:
        r = results[n]
        print(f" - {n:22s}: {'OK ' if r['ok'] else 'FAIL'}{'' if r['ok'] else '  ('+r['why']+')'}")
    return 0 if all_ok else 1

def _params(fn):  # safe signature read
    try:
        return set(inspect.signature(fn).parameters.keys())
    except Exception:
        return set()

# Detect API knobs
ENC_PARAMS = _params(Engine.encrypt)
DEC_PARAMS = _params(Engine.decrypt)
AAD_PARAM = "aad_context" if "aad_context" in ENC_PARAMS else ("aad" if "aad" in ENC_PARAMS else None)
HAS_MSGID_ENC = ("message_id" in ENC_PARAMS)          # <- new: check encrypt only
SUPPORTS_PAD  = ("pad_to" in ENC_PARAMS)
SUPPORTS_JIT  = ("pad_jitter_blocks" in ENC_PARAMS)
SUPPORTS_STRICT = ("strict_mode" in ENC_PARAMS) and ("strict_mode" in DEC_PARAMS)

# ---------------- main test ----------------
def run():
    results = {}
    tmpdir = tempfile.mkdtemp(prefix="kb_ce_v3x_")
    try:
        print("Engine import:", ENGINE_IMPORT_LABEL)
        print("CHUNK_SIZE   :", CHUNK_SIZE)
        # 0) Build a vault
        vault_path = os.path.join(tmpdir, "test.keybook")
        hints = ["alpha project", "mars", "tea time"]
        passphrase = "correct horse battery staple"
        pepper = "PAPER-PEPPER-1234567890-abcdef"  # keybook v2 doesn't enforce 32 chars

        h = init_vault(hints, passphrase, pepper, device_id="ipad-pro", out_path=vault_path)

        # 1) Derive bundle + AAD context
        bundle = derive_bundle(h, target="demo")
        ctx_str = "file:/vault/demo.txt"
        aad = make_aad_from_context(bundle, ctx_str)  # 64B HMAC over context with aux1

        # Build common kwargs adaptively
        enc_kwargs = dict(enc_key=bundle["enc"], tran_key=bundle["tran"])
        dec_kwargs = dict(enc_key=bundle["enc"], tran_key=bundle["tran"])

        if "max_rounds" in ENC_PARAMS: enc_kwargs["max_rounds"] = 7
        if "return_b64" in ENC_PARAMS: enc_kwargs["return_b64"] = True
        if "max_rounds" in DEC_PARAMS: dec_kwargs["max_rounds"] = 7
        if "is_b64"     in DEC_PARAMS: dec_kwargs["is_b64"] = True

        if AAD_PARAM is not None:
            enc_kwargs[AAD_PARAM] = aad
            dec_kwargs[AAD_PARAM] = aad

        # v3.6 style knobs (set if available)
        if HAS_MSGID_ENC:
            enc_kwargs["message_id"] = secrets.token_bytes(16)  # even if decrypt() doesn’t expose it
        if SUPPORTS_PAD:
            enc_kwargs["pad_to"] = 256
        if SUPPORTS_JIT:
            enc_kwargs["pad_jitter_blocks"] = 0
        if SUPPORTS_STRICT:
            enc_kwargs["strict_mode"] = True
            dec_kwargs["strict_mode"] = True

        # 2) Round trip (Base64)
        try:
            msg = b"hello v3.x integration"
            ct_b64 = Engine.encrypt(msg, **enc_kwargs)
            pt = Engine.decrypt(ct_b64, **dec_kwargs)
            results["round_trip_b64"] = _ok() if pt == msg else _fail("plaintext mismatch")
        except Exception as e:
            results["round_trip_b64"] = _fail(f"exception: {e}")

        # 3) AAD mismatch => auth failure (only if AAD supported)
        try:
            if AAD_PARAM is not None:
                bad_dec = dict(dec_kwargs)
                bad_dec[AAD_PARAM] = b"other-context"
                try:
                    Engine.decrypt(ct_b64, **bad_dec)
                    results["aad_mismatch"] = _fail("decryption unexpectedly succeeded with wrong AAD")
                except Exception:
                    results["aad_mismatch"] = _ok()
            else:
                results["aad_mismatch"] = _ok("skipped (AAD unsupported)")
        except Exception as e:
            results["aad_mismatch"] = _fail(f"exception: {e}")

        # 4) Raw vs Base64 parity
        try:
            msg2 = b"\x00\x01\x02\xff" * 1234
            # enc raw
            enc_raw = dict(enc_kwargs)
            if "return_b64" in ENC_PARAMS:
                enc_raw["return_b64"] = False
            if HAS_MSGID_ENC and "message_id" not in enc_raw:
                enc_raw["message_id"] = secrets.token_bytes(16)
            ct_raw = Engine.encrypt(msg2, **enc_raw)
            # dec raw
            dec_raw = dict(dec_kwargs)
            if "is_b64" in DEC_PARAMS:
                dec_raw["is_b64"] = False
            pt2 = Engine.decrypt(ct_raw, **dec_raw)
            results["raw_vs_b64"] = _ok() if pt2 == msg2 else _fail("raw decrypt mismatch")
        except Exception as e:
            results["raw_vs_b64"] = _fail(f"exception: {e}")

        # 5) Chunk boundary sizes
        try:
            sizes = [0, 1, CHUNK_SIZE-1, CHUNK_SIZE, CHUNK_SIZE+1, 2*CHUNK_SIZE+5]
            for n in sizes:
                data = _rand(n)
                enc_r = dict(enc_kwargs)
                if "return_b64" in ENC_PARAMS:
                    enc_r["return_b64"] = False
                if HAS_MSGID_ENC and "message_id" not in enc_r:
                    enc_r["message_id"] = secrets.token_bytes(16)
                dec_r = dict(dec_kwargs)
                if "is_b64" in DEC_PARAMS:
                    dec_r["is_b64"] = False
                ct = Engine.encrypt(data, **enc_r)
                rec = Engine.decrypt(ct, **dec_r)
                if rec != data:
                    raise AssertionError(f"mismatch at size {n}")
            results["chunk_boundaries"] = _ok()
        except Exception as e:
            results["chunk_boundaries"] = _fail(str(e))

        # 6) Resequence isolation: new bundle must NOT decrypt old ct
        try:
            h2 = resequence_vault(h, passphrase, pepper, new_hints=["new era"], device_id="ipad-pro")
            bundle2 = derive_bundle(h2, target="demo")

            # Build dec kwargs with the new bundle
            dec_iso = dict(dec_kwargs)
            dec_iso["enc_key"] = bundle2["enc"]
            dec_iso["tran_key"] = bundle2["tran"]
            try:
                Engine.decrypt(ct_b64, **dec_iso)
                results["resequence_isolation"] = _fail("old ciphertext decrypted under new bundle")
            except Exception:
                results["resequence_isolation"] = _ok()
        except Exception as e:
            results["resequence_isolation"] = _fail(f"exception: {e}")

        return _report(results)

    except Exception as fatal:
        traceback.print_exc()
        return 1
    finally:
        # Keep tmpdir around for inspection by commenting out the next line
        pass

if __name__ == "__main__":
    sys.exit(run())
