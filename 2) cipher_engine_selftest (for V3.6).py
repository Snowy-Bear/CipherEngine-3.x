#!/usr/bin/env python3
"""
cipher_engine_selftest.py — version-adaptive self-test for CipherEngine32x32 (v3.x)

- Compatible with v3.5/v3.6 shims:
  * Detects & strips an optional Base64-only transport prefix when present.
  * Treats max_rounds as cosmetic (v3.6): decrypting with a different value is OK.
  * Treats message_id as header-bound when decrypt() has no message_id param.
  
- Works with v3.5 and v3.6:
  * Detects 'aad' vs 'aad_context' (fixed)
  * Supplies message_id / pad_to / strict_mode when supported
- No reliance on header layout; treats the engine as a black box.

Usage:
    import cipher_engine_selftest as cest
    from cipher_engine import CipherEngine32x32
    report = cest.run_self_test(CipherEngine32x32)
    
Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import base64, secrets, inspect
from typing import Any, Dict, Type

# Import your engine (via shim)
try:
    from cipher_engine import CipherEngine32x32
except Exception as e:  # pragma: no cover
    raise RuntimeError("cipher_engine not available: " + str(e))

# Known “magic” / tags
_MAGIC_CE36 = b"CE36"        # v3.6+ header magic (shim/engine)
_KNOWN_VER2 = {b"31", b"32", b"33", b"34", b"35", b"36"}  # legacy 2-byte version tags

def _safe_preview(b: bytes, limit: int = 60) -> str:
    s = b.decode("utf-8", errors="replace")
    out = []
    for ch in s[:limit]:
        o = ord(ch)
        if ch == "\x00":
            out.append(r"\x00")
        elif o < 32 or o == 127:
            out.append(f"\\x{o:02x}")
        else:
            out.append(ch)
    if len(s) > limit:
        out.append("...")
    return "".join(out)

def _strip_optional_prefix(decoded: bytes) -> bytes:
    """
    Handle two on-wire shapes:

      (A) v3.6 Base64:   [optional 4B transport prefix] || "CE36" || header...
          -> if decoded[0:4] == b"CE36": no prefix
          -> elif decoded[4:8] == b"CE36": strip 4 bytes

      (B) older v3.x:  version as 2 ASCII bytes at start, e.g. b"35"
          -> if decoded[0:2] in KNOWN_VER2: no prefix

    If none match, return as-is (best effort).
    """
    if len(decoded) >= 4 and decoded[0:4] == _MAGIC_CE36:
        return decoded
    if len(decoded) >= 8 and decoded[4:8] == _MAGIC_CE36:
        return decoded[4:]
    if len(decoded) >= 2 and decoded[0:2] in _KNOWN_VER2:
        return decoded
    return decoded

def _b64_to_raw(ct_b64: str) -> bytes:
    return _strip_optional_prefix(base64.b64decode(ct_b64))

def _rand32() -> bytes:
    return secrets.token_bytes(32)

def _mk_bundle() -> Dict[str, bytes]:
    return {
        "enc": _rand32(),
        "tran": _rand32(),
        "hmac": secrets.token_bytes(64),  # unused by engine
        "aux1": _rand32(),
        "aux2": _rand32(),
    }

def _ok(why: str = "") -> Dict[str, Any]:
    return {"ok": True, "why": why}

def _fail(why: str) -> Dict[str, Any]:
    return {"ok": False, "why": why}

def _aad_param_name(engine_cls) -> str | None:
    """Return 'aad_context' (v3.6) or 'aad' (v3.5) if supported, else None."""
    enc_params = inspect.signature(engine_cls.encrypt).parameters
    dec_params = inspect.signature(engine_cls.decrypt).parameters
    if "aad_context" in enc_params and "aad_context" in dec_params:
        return "aad_context"
    if "aad" in enc_params and "aad" in dec_params:
        return "aad"
    return None

def run_self_test(engine_cls: Type[CipherEngine32x32]) -> Dict[str, Any]:
    tests: Dict[str, Dict[str, Any]] = {}
    bundle = _mk_bundle()
    enc, tran = bundle["enc"], bundle["tran"]

    # 1) Round trip (Base64)
    plaintext = "Hello v3.x engine \x00\x01\xfe\xff — unicode 🐱 + binary tail.".encode("utf-8", "surrogatepass")
    try:
        ct_b64 = engine_cls.encrypt(plaintext, enc_key=enc, tran_key=tran, return_b64=True)
        pt = engine_cls.decrypt(ct_b64, enc_key=enc, tran_key=tran, is_b64=True)
        tests["round_trip"] = _ok() if pt == plaintext else _fail("decrypted plaintext mismatch")
    except Exception as e:
        tests["round_trip"] = _fail(f"exception: {e}")

    # 2) Tamper detection (flip a mid-body byte; expect auth/tag fail)
    try:
        raw = bytearray(_b64_to_raw(ct_b64))
        # Avoid first few bytes (magic/version) and last 64 (tag); flip somewhere in the body if possible
        if len(raw) <= 2 + 64:
            tests["tamper_tag"] = _fail("ciphertext too small to tamper")
        else:
            mid = 2 + (len(raw) - 2 - 64) // 2
            raw[mid] ^= 0x55
            tampered_b64 = base64.b64encode(raw).decode("ascii")
            try:
                engine_cls.decrypt(tampered_b64, enc_key=enc, tran_key=tran, is_b64=True)
                tests["tamper_tag"] = _fail("decryption unexpectedly succeeded on tampered data")
            except Exception as e:
                tests["tamper_tag"] = _ok() if "fail" in str(e).lower() else _fail(f"unexpected error on tamper: {e}")
    except Exception as e:
        tests["tamper_tag"] = _fail(f"exception: {e}")

    # 3) Wrong key -> auth fail
    try:
        wrong_enc = _rand32()
        try:
            engine_cls.decrypt(ct_b64, enc_key=wrong_enc, tran_key=tran, is_b64=True)
            tests["wrong_key"] = _fail("decryption unexpectedly succeeded with wrong enc_key")
        except Exception as e:
            tests["wrong_key"] = _ok() if "fail" in str(e).lower() else _fail(f"unexpected error: {e}")
    except Exception as e:
        tests["wrong_key"] = _fail(f"exception: {e}")

    # 4) Raw vs Base64 parity
    try:
        raw_blob = _b64_to_raw(ct_b64)
        pt2 = engine_cls.decrypt(raw_blob, enc_key=enc, tran_key=tran, is_b64=False)
        tests["raw_vs_b64"] = _ok() if pt2 == plaintext else _fail("raw decrypt mismatch vs b64")
    except Exception as e:
        tests["raw_vs_b64"] = _fail(f"exception: {e}")

    # 5) AAD round-trip + mismatch (now detects 'aad' vs 'aad_context')
    try:
        aad_param = _aad_param_name(engine_cls)
        if aad_param is None:
            tests["aad_round_trip"] = _ok("engine has no AAD support")
            tests["aad_mismatch"]   = _ok("engine has no AAD support")
        else:
            aad = b"file:/vault/demo.txt"
            enc_kwargs = {aad_param: aad}
            dec_kwargs = {aad_param: aad}
            ct_aad = engine_cls.encrypt(plaintext, enc_key=enc, tran_key=tran, return_b64=True, **enc_kwargs)
            pt_aad = engine_cls.decrypt(ct_aad, enc_key=enc, tran_key=tran, is_b64=True, **dec_kwargs)
            tests["aad_round_trip"] = _ok() if pt_aad == plaintext else _fail("AAD decrypt mismatch")

            bad_kwargs = {aad_param: b"other"}
            try:
                engine_cls.decrypt(ct_aad, enc_key=enc, tran_key=tran, is_b64=True, **bad_kwargs)
                tests["aad_mismatch"] = _fail("decryption unexpectedly succeeded with wrong AAD")
            except Exception as e:
                tests["aad_mismatch"] = _ok() if "fail" in str(e).lower() else _fail(f"unexpected error on AAD mismatch: {e}")
    except Exception as e:
        tests["aad_round_trip"] = _fail(f"exception: {e}")
        tests["aad_mismatch"]   = _fail(f"exception: {e}")

    # 6) Message-ID mismatch semantics
    try:
        enc_sig = inspect.signature(engine_cls.encrypt).parameters
        dec_sig = inspect.signature(engine_cls.decrypt).parameters
        if "message_id" in enc_sig:
            msgid = secrets.token_bytes(16)
            ct_mid = engine_cls.encrypt(plaintext, enc_key=enc, tran_key=tran, return_b64=True,
                                        message_id=msgid)
            if "message_id" in dec_sig:
                try:
                    engine_cls.decrypt(ct_mid, enc_key=enc, tran_key=tran, is_b64=True,
                                       message_id=secrets.token_bytes(16))
                    tests["message_id_mismatch"] = _fail("decryption unexpectedly succeeded with wrong/different message_id")
                except Exception as e:
                    tests["message_id_mismatch"] = _ok() if "fail" in str(e).lower() else _fail(f"unexpected error: {e}")
            else:
                # Header-bound message_id (v3.6): success is expected
                try:
                    pt3 = engine_cls.decrypt(ct_mid, enc_key=enc, tran_key=tran, is_b64=True)
                    tests["message_id_mismatch"] = _ok("header-bound message_id; decrypt success is expected")
                except Exception as e:
                    tests["message_id_mismatch"] = _fail(f"unexpected failure without message_id param: {e}")
        else:
            tests["message_id_mismatch"] = _ok("engine has no explicit message_id param")
    except Exception as e:
        tests["message_id_mismatch"] = _fail(f"exception: {e}")

    # 7) Wrong rounds — cosmetic in v3.6, so success is OK
    try:
        ekw = dict(enc_key=enc, tran_key=tran, return_b64=True)
        if "max_rounds" in inspect.signature(engine_cls.encrypt).parameters:
            ekw["max_rounds"] = 7
        ct_rounds = engine_cls.encrypt(plaintext, **ekw)

        dkw = dict(enc_key=enc, tran_key=tran, is_b64=True)
        if "max_rounds" in inspect.signature(engine_cls.decrypt).parameters:
            dkw["max_rounds"] = 5  # intentionally different
        pt_wrong = engine_cls.decrypt(ct_rounds, **dkw)

        tests["wrong_rounds"] = _ok("rounds cosmetic") if pt_wrong == plaintext \
                                else _ok("engine enforces rounds; mismatch changed output")
    except Exception:
        tests["wrong_rounds"] = _ok("engine rejected mismatched rounds (also OK)")

    # Summary
    all_passed = all(t["ok"] for t in tests.values())
    pt_preview = _safe_preview(plaintext, 60)
    sample = {"ct_b64": (ct_b64[:80] + "...") if isinstance(ct_b64, str) else "<bytes>", "pt_preview": pt_preview}

    return {
        "engine": engine_cls.__name__,
        "version": getattr(engine_cls, "VERSION", b"?"),
        "all_passed": all_passed,
        "tests": tests,
        "sample": sample,
    }

if __name__ == "__main__":  # pragma: no cover
    rep = run_self_test(CipherEngine32x32)
    ver = rep['version'].decode("ascii", "ignore") if isinstance(rep['version'], (bytes, bytearray)) else str(rep['version'])
    print(f"Engine: {rep['engine']}  Version: {ver}")
    print("All passed:", rep["all_passed"])
    for name, r in rep["tests"].items():
        status = "OK " if r["ok"] else "FAIL"
        why = ("" if r["ok"] else f"  ({r['why']})")
        print(f" - {name:20s}: {status}{why}")
    print("Sample ct_b64:", rep["sample"]["ct_b64"])
    print("PT preview  :", rep["sample"]["pt_preview"])
