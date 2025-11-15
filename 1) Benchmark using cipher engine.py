#!/usr/bin/env python3
"""
bench_cipher_engine.py — throughput bench for CipherEngine32x32 (v3.x)

- Imports cipher_engine.py (v3.6 shim) if present, otherwise cipher_engine_v3_5.py
- Measures enc/dec MB/s for sizes × rounds
- Optional AAD (auto-detects 'aad' vs 'aad_context')
- Auto-injects required params (message_id, pad_to, strict_mode, etc.)
- Works with v3.5 and v3.6; if v3.6 exposes aad_hash_len (16|32), we pass it

Env:
  BENCH_AAD_HASH_LEN=16|32   (default 16; used only if engine supports aad_hash_len)

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

import os, time, secrets, platform, csv, sys, inspect, hashlib

# --- engine import (prefer v3.6 shim, fallback to v3.5) ---
Engine = None
_IMPORT_NOTE = ""
try:
    from cipher_engine import CipherEngine32x32 as Engine   # v3.6 shim
    _IMPORT_NOTE = "cipher_engine (v3.6 shim)"
except Exception:
    try:
        from cipher_engine_v3_5 import CipherEngine32x32 as Engine
        _IMPORT_NOTE = "cipher_engine_v3_5"
    except Exception as e:
        print("ERROR: could not import CipherEngine32x32:", e)
        sys.exit(2)


def _engine_meta():
    name = getattr(Engine, "__name__", "CipherEngine32x32")
    ver  = getattr(Engine, "VERSION", getattr(Engine, "version", None))
    try:
        info = Engine.info() if hasattr(Engine, "info") else None
    except Exception:
        info = None
    return name, ver, info


def _param_names(fn):
    try:
        return set(inspect.signature(fn).parameters.keys())
    except Exception:
        return set()


# Map common option names to engine parameter names (if any)
def _aad_key(enc_params, dec_params):
    if "aad_context" in enc_params:  # v3.6 or shims
        return "aad_context"
    if "aad" in enc_params:          # classic v3.5
        return "aad"
    return None

def _has(pname, params): return pname in params

def mbps(bytes_count, seconds):
    if seconds <= 0:
        return float("inf")
    return (bytes_count / (1024*1024)) / seconds


def bench_case(size_bytes, rounds, *, trials=1, use_b64=True, aad_bytes: bytes | None = None):
    enc_key = secrets.token_bytes(32)
    tran_key = secrets.token_bytes(32)
    buf = os.urandom(size_bytes)

    enc_params = _param_names(Engine.encrypt)
    dec_params = _param_names(Engine.decrypt)
    aad_param  = _aad_key(enc_params, dec_params)

    # Optional v3.6 header-hash length (16|32)
    aad_hash_len_env = os.getenv("BENCH_AAD_HASH_LEN")
    aad_hash_len = None
    if aad_hash_len_env:
        try:
            v = int(aad_hash_len_env)
            if v in (16, 32) and _has("aad_hash_len", enc_params):
                aad_hash_len = v
        except Exception:
            pass

    # Build common kwargs (encrypt)
    ekw = dict(enc_key=enc_key, tran_key=tran_key)
    if _has("max_rounds", enc_params):
        ekw["max_rounds"] = rounds
    if use_b64 and _has("return_b64", enc_params):
        ekw["return_b64"] = True

    # v3.6+ requirements (auto-fill when supported)
    # Deterministic message_id per (size, rounds) so decrypt can reuse if required.
    if _has("message_id", enc_params):
        msgid = hashlib.sha512(
            b"bench|" + size_bytes.to_bytes(8, "big") + rounds.to_bytes(2, "big")
        ).digest()[:16]
        ekw["message_id"] = msgid
    if _has("pad_to", enc_params):
        ekw["pad_to"] = 256
    if _has("pad_jitter_blocks", enc_params):
        ekw["pad_jitter_blocks"] = 0
    if _has("strict_mode", enc_params):
        ekw["strict_mode"] = True
    if aad_hash_len is not None:
        ekw["aad_hash_len"] = aad_hash_len

    # AAD (only if supported and requested)
    if aad_bytes is not None and aad_param:
        ekw[aad_param] = aad_bytes

    # Warm-up
    Engine.encrypt(buf, **ekw)

    enc_t = 0.0
    dec_t = 0.0

    for _ in range(trials):
        t0 = time.perf_counter()
        ct = Engine.encrypt(buf, **ekw)
        t1 = time.perf_counter()

        # Build decrypt kwargs mirroring encrypt
        dkw = dict(enc_key=enc_key, tran_key=tran_key)
        if _has("max_rounds", dec_params):
            dkw["max_rounds"] = rounds
        if use_b64 and _has("is_b64", dec_params):
            dkw["is_b64"] = True
        if aad_bytes is not None and aad_param and _has(aad_param, dec_params):
            dkw[aad_param] = aad_bytes
        if _has("message_id", dec_params) and "message_id" in ekw:
            dkw["message_id"] = ekw["message_id"]
        if _has("strict_mode", dec_params) and "strict_mode" in ekw:
            dkw["strict_mode"] = True
        # (aad_hash_len is encrypt-side only)

        t2 = time.perf_counter()
        out = Engine.decrypt(ct, **dkw)
        t3 = time.perf_counter()

        assert out == buf, "round-trip mismatch"

        enc_t += (t1 - t0)
        dec_t += (t3 - t2)

    enc_t /= trials
    dec_t /= trials
    return {
        "size_bytes": size_bytes,
        "rounds": rounds,
        "encrypt_s": enc_t,
        "decrypt_s": dec_t,
        "enc_MBps": mbps(size_bytes, enc_t),
        "dec_MBps": mbps(size_bytes, dec_t),
        "aad_hash_len": aad_hash_len if aad_hash_len is not None else "",
    }


def run_bench(
    sizes=(256*1024, 1<<20, 2<<20, 4<<20),
    rounds_list=(3,5,7),
    trials=1,
    write_csv=True,
    use_b64=True,
    enable_aad=True,
):
    device_label = input("Enter device label (e.g., 'iPad Pro M4 13\"'): ").strip() or "Unknown Device"

    info = {
        "python": platform.python_version(),
        "machine": platform.machine(),
        "platform": platform.platform(),
        "implementation": platform.python_implementation(),
        "device": device_label,
    }

    name, ver, einfo = _engine_meta()

    # If engine supports any AAD param, provide a fixed 32B AAD when enabled
    enc_params = _param_names(Engine.encrypt)
    aad_supported = ("aad_context" in enc_params) or ("aad" in enc_params)
    aad_bytes = (secrets.token_bytes(32) if (enable_aad and aad_supported) else None)

    # Detect aad_hash_len setting so we can print it (only matters for v3.6)
    aad_hash_len_env = os.getenv("BENCH_AAD_HASH_LEN")
    aad_hash_len = ""
    if aad_hash_len_env and _has("aad_hash_len", enc_params):
        try:
            v = int(aad_hash_len_env)
            if v in (16, 32):
                aad_hash_len = v
        except Exception:
            pass

    print("\nCipherEngine v3 Benchmark")
    print("-------------------------")
    print("Device label:", device_label)
    print("Python:", info["python"], "| Impl:", info["implementation"])
    print("Machine:", info["machine"])
    print("Platform:", info["platform"])
    print(f"Engine import: {_IMPORT_NOTE}  |  Class: {name}  |  Version: {ver if ver is not None else '(n/a)'}")
    if einfo:
        try:
            print("Engine info:", einfo)
        except Exception:
            pass
    print("Ciphertext mode:", "Base64" if use_b64 else "Raw bytes")
    print("AAD:", "ON (fixed 32B)" if aad_bytes is not None else "OFF (or unsupported)")
    if aad_hash_len:
        print(f"AAD header-hash len: {aad_hash_len}")
    print("Trials per case:", trials)
    print("")

    results = []
    for sz in sizes:
        for r in rounds_list:
            rdict = bench_case(sz, r, trials=trials, use_b64=use_b64, aad_bytes=aad_bytes)
            results.append(rdict)
            mb = sz / (1024*1024)
            print(f"size={mb:5.2f} MiB  rounds={r}  "
                  f"enc={rdict['encrypt_s']:.3f}s ({rdict['enc_MBps']:.2f} MB/s)  "
                  f"dec={rdict['decrypt_s']:.3f}s ({rdict['dec_MBps']:.2f} MB/s)")

    if write_csv:
        fname = f"cipher_bench_{device_label.replace(' ','_')}_{int(time.time())}.csv"
        with open(fname, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["device","python","implementation","machine","platform","engine_import","engine_class","engine_version","ciphertext_mode","aad","aad_hash_len"])
            w.writerow([info["device"], info["python"], info["implementation"], info["machine"], info["platform"],
                        _IMPORT_NOTE, name, (ver if ver is not None else ""), ("b64" if use_b64 else "raw"),
                        ("on" if aad_bytes is not None else "off"),
                        (aad_hash_len if aad_hash_len else ""),
                        ])
            w.writerow([])
            w.writerow(["size_bytes","rounds","encrypt_s","decrypt_s","enc_MBps","dec_MBps","aad_hash_len"])
            for r in results:
                w.writerow([r["size_bytes"], r["rounds"],
                            f"{r['encrypt_s']:.6f}", f"{r['decrypt_s']:.6f}",
                            f"{r['enc_MBps']:.2f}", f"{r['dec_MBps']:.2f}",
                            r.get("aad_hash_len","")])
        print("\nCSV written:", fname)

    return results


if __name__ == "__main__":
    run_bench(
        sizes=(256*1024, 1<<20, 2<<20, 4<<20),
        rounds_list=(3,5,7),
        trials=1,
        write_csv=True,
        use_b64=True,       # flip to False to benchmark raw
        enable_aad=True,    # set False to disable AAD
    )
