#!/usr/bin/env python3
"""
Self-test for cipher_engine (v3.x, 32x32). Pure stdlib.

Usage (in your app):
    import cipher_engine_selftest as cest
    from cipher_engine import CipherEngine32x32

    report = cest.run_self_test(CipherEngine32x32)
    if not report["all_passed"]:
        for name, r in report["tests"].items():
            if not r["ok"]:
                print(f"[FAIL] {name}: {r['why']}")

If you run this file directly, it will pretty-print a summary.
"""

from __future__ import annotations
import os, secrets, base64
from typing import Any, Dict, Type

# Import your engine (v3.x)
try:
    from cipher_engine import CipherEngine32x32
except Exception as e:  # pragma: no cover
    raise RuntimeError("cipher_engine (v3.x) not available: " + str(e))


# --- version-aware header lengths ---
V3_HEADER_LEN   = 2 + 1 + 32 + 32 + 32 + 1   # includes pad_len (v3 / v3.1 / v3.2)
V33_HEADER_LEN  = 2 + 1 + 32 + 32 + 32       # no pad_len in outer header (v3.3)

# Add near the top (after imports)
def _safe_preview(b: bytes, limit: int = 60) -> str:
    """UTF-8 decode with replacement, then escape control chars for safe console printing."""
    s = b.decode("utf-8", errors="replace")
    s_cut = s[:limit]
    out = []
    for ch in s_cut:
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

def _header_len_from_raw(raw: bytes) -> int:
    ver = raw[:2]
    if ver in (b"33", b"34"):     # v3.3 and v3.4 use outer/inner split
        return V33_HEADER_LEN
    elif ver in (b"32", b"31", b"v3"):
        return V3_HEADER_LEN
    return V3_HEADER_LEN

def _rand32() -> bytes:
    return secrets.token_bytes(32)


def _mk_bundle() -> Dict[str, bytes]:
    # Minimal bundle for engine use; aux keys mirror your keybook shape
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


def _b64_payload(ct_b64: str) -> bytes:
    # Strip the 4-byte random prefix after base64-decoding
    raw = base64.b64decode(ct_b64)
    return raw[4:]


def run_self_test(engine_cls: Type[CipherEngine32x32]) -> Dict[str, Any]:
    """
    Run a suite of invariant checks and return a structured report:
    {
      "engine": "CipherEngine32x32",
      "version": "33",
      "all_passed": bool,
      "tests": {...},
      "sample": {"ct_b64": "...", "pt_preview": "..."}
    }
    """
    tests: Dict[str, Dict[str, Any]] = {}
    bundle = _mk_bundle()
    enc = bundle["enc"]
    tran = bundle["tran"]

    # 1) Round trip
    plaintext = "Hello v3.x engine \x00\x01\xfe\xff — with unicode text 🐱 and binary tail.".encode("utf-8", "surrogatepass")
    try:
        ct_b64 = engine_cls.encrypt(
            plaintext, enc_key=enc, tran_key=tran, max_rounds=7, return_b64=True
        )
        pt = engine_cls.decrypt(
            ct_b64, enc_key=enc, tran_key=tran, max_rounds=7, is_b64=True
        )
        tests["round_trip"] = _ok() if pt == plaintext else _fail("decrypted plaintext mismatch")
    except Exception as e:
        tests["round_trip"] = _fail(f"exception: {e}")

    # 2) Tamper detection (flip a byte in ciphertext body; expect HMAC fail)
    try:
        raw = bytearray(_b64_payload(ct_b64))
        header_len = _header_len_from_raw(raw)
        if len(raw) <= header_len + 1 + 64:
            tests["tamper_tag"] = _fail("ciphertext has no body to tamper with")
        else:
            flip_idx = header_len + (len(raw) - header_len - 64) // 2
            raw[flip_idx] ^= 0x55
            tampered_b64 = base64.b64encode(os.urandom(4) + bytes(raw)).decode("ascii")
            try:
                engine_cls.decrypt(
                    tampered_b64, enc_key=enc, tran_key=tran, max_rounds=7, is_b64=True
                )
                tests["tamper_tag"] = _fail("decryption unexpectedly succeeded on tampered data")
            except Exception as e:
                msg = str(e).lower()
                tests["tamper_tag"] = _ok() if ("hmac" in msg and "fail" in msg) else _fail(f"unexpected error on tamper: {e}")
    except Exception as e:
        tests["tamper_tag"] = _fail(f"exception: {e}")

    # 3) Wrong key detection (expect HMAC fail)
    try:
        wrong_enc = _rand32()
        try:
            engine_cls.decrypt(
                ct_b64, enc_key=wrong_enc, tran_key=tran, max_rounds=7, is_b64=True
            )
            tests["wrong_key"] = _fail("decryption unexpectedly succeeded with wrong enc_key")
        except Exception as e:
            msg = str(e).lower()
            tests["wrong_key"] = _ok() if ("hmac" in msg and "fail" in msg) else _fail(f"unexpected error on wrong key: {e}")
    except Exception as e:
        tests["wrong_key"] = _fail(f"exception: {e}")

    # 4) Wrong rounds detection (engine returns bytes; they should differ)
    try:
        pt_wrong = engine_cls.decrypt(
            ct_b64, enc_key=enc, tran_key=tran, max_rounds=5, is_b64=True
        )
        tests["wrong_rounds"] = _ok() if pt_wrong != plaintext else _fail("decryption matched with wrong max_rounds")
    except Exception:
        # Also acceptable if an engine chooses to throw
        tests["wrong_rounds"] = _ok("decryption failed as expected")

    # 5) Version mismatch (munge version bytes; expect 'unsupported version')
    try:
        raw = bytearray(_b64_payload(ct_b64))
        raw[0:2] = b"vX"
        bad_b64 = base64.b64encode(os.urandom(4) + bytes(raw)).decode("ascii")
        try:
            engine_cls.decrypt(
                bad_b64, enc_key=enc, tran_key=tran, max_rounds=7, is_b64=True
            )
            tests["version_mismatch"] = _fail("decryption accepted unsupported version")
        except Exception as e:
            msg = str(e).lower()
            tests["version_mismatch"] = _ok() if "unsupported version" in msg else _fail(f"unexpected error on version mismatch: {e}")
    except Exception as e:
        tests["version_mismatch"] = _fail(f"exception: {e}")

    # 6) Header corruption (flip a byte in OUTER header; expect HMAC fail)
    try:
        raw = bytearray(_b64_payload(ct_b64))
        salt0_off = 2 + 1  # start of salt in all v3.x variants
        raw[salt0_off] ^= 0xFF
        bad_b64 = base64.b64encode(os.urandom(4) + bytes(raw)).decode("ascii")
        try:
            engine_cls.decrypt(
                bad_b64, enc_key=enc, tran_key=tran, max_rounds=7, is_b64=True
            )
            tests["header_corruption"] = _fail("decryption unexpectedly succeeded on bad header")
        except Exception:
            tests["header_corruption"] = _ok()
    except Exception as e:
        tests["header_corruption"] = _fail(f"exception: {e}")

    # 7) Raw vs b64 handling
    try:
        raw = _b64_payload(ct_b64)
        pt2 = engine_cls.decrypt(
            raw, enc_key=enc, tran_key=tran, max_rounds=7, is_b64=False
        )
        tests["raw_vs_b64"] = _ok() if pt2 == plaintext else _fail("raw decrypt mismatch vs b64")
    except Exception as e:
        tests["raw_vs_b64"] = _fail(f"exception: {e}")

    # Summary
    all_passed = all(t["ok"] for t in tests.values())
    pt_preview = _safe_preview(plaintext, 60)
    sample = {"ct_b64": ct_b64[:80] + "...", "pt_preview": pt_preview}

    return {
        "engine": engine_cls.__name__,
        "version": getattr(engine_cls, "VERSION", b"?").decode("ascii", errors="ignore"),
        "all_passed": all_passed,
        "tests": tests,
        "sample": sample,
    }


# Optional: pretty print when run directly
if __name__ == "__main__":  # pragma: no cover
    rep = run_self_test(CipherEngine32x32)
    print(f"Engine: {rep['engine']}  Version: {rep['version']}")
    print("All passed:", rep["all_passed"])
    for name, r in rep["tests"].items():
        status = "OK " if r["ok"] else "FAIL"
        why = ("" if r["ok"] else f"  ({r['why']})")
        print(f" - {name:18s}: {status}{why}")
    print("Sample ct_b64:", rep["sample"]["ct_b64"])
    print("PT preview  :", rep["sample"]["pt_preview"])
