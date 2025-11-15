#!/usr/bin/env python3
"""
Benchmark harness for CipherEngine32x32 (v3.3 vs v3.4)

Measures:
  1) Throughput (encrypt+decrypt MB/s) for several sizes and repetitions
  2) Diffusion: % of differing bytes and bits in the final encoded blob
     when flipping 1 byte in the plaintext (with identical ephemerals)

Pure stdlib. No I/O beyond print.
"""

from __future__ import annotations
import time, random, base64, types
from typing import Tuple, Dict, Any

# ---------------------------
# Imports — adjust as needed:
# ---------------------------
# Option A: if your engines are separate modules/files
# from cipher_engine_v3_3 import CipherEngine32x32 as Engine33
# from cipher_engine_v3_4 import CipherEngine32x32 as Engine34

# Option B: if you only have one file at a time, temporarily alias it twice
# (uncomment one of these pairs as needed)
from cipher_engine_v3_3 import CipherEngine32x32 as Engine33
from cipher_engine_v3_4 import CipherEngine32x32 as Engine34


# ---------------------------
# Helpers
# ---------------------------
def _b64_payload(ct_b64: str) -> bytes:
    raw = base64.b64decode(ct_b64)
    return raw[4:]  # strip 4-byte random prefix


class _DetURandom:
    """
    Deterministic os.urandom replacement for fair diffusion tests.
    Produces identical ephemerals (salt/msg_key/msg_tran) when re-seeded.
    """
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
    def __call__(self, n: int) -> bytes:
        # Generate n bytes deterministically
        return bytes(self.rng.getrandbits(8) for _ in range(n))


class _UrandomPatch:
    """
    Context manager to monkeypatch os.urandom inside a specific engine class's module
    (not globally!), so encrypt() in that engine sees deterministic ephemerals.
    """
    def __init__(self, engine_cls, seed: int):
        self.engine_cls = engine_cls
        self.seed = seed
        self._orig = None
        self._mod = None

    def __enter__(self):
        modname = self.engine_cls.__module__
        self._mod = __import__(modname, fromlist=['os'])
        self._orig = self._mod.os.urandom
        self._mod.os.urandom = _DetURandom(self.seed)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._mod and self._orig:
            self._mod.os.urandom = self._orig
        return False


def _rand_bytes(n: int, seed: int = 12345) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


def _hamming_bytes(a: bytes, b: bytes) -> Tuple[int, int]:
    """Return (# differing bytes, total bytes)."""
    assert len(a) == len(b)
    diff = sum(1 for x, y in zip(a, b) if x != y)
    return diff, len(a)


def _hamming_bits(a: bytes, b: bytes) -> Tuple[int, int]:
    """Return (# differing bits, total bits)."""
    assert len(a) == len(b)
    diff_bits = 0
    for x, y in zip(a, b):
        diff_bits += (x ^ y).bit_count()
    return diff_bits, len(a) * 8


def _throughput(engine_cls, sizes=(1024, 8192, 65536), reps=100, max_rounds=7) -> Dict[str, Any]:
    enc_key = _rand_bytes(32, 111)
    tran_key = _rand_bytes(32, 222)

    results = []
    for n in sizes:
        # prepare payloads
        data = _rand_bytes(n, 333)

        # warm-up
        engine_cls.encrypt(data, enc_key=enc_key, tran_key=tran_key, max_rounds=max_rounds, return_b64=True)
        # time encrypt
        t0 = time.perf_counter()
        for _ in range(reps):
            ct = engine_cls.encrypt(data, enc_key=enc_key, tran_key=tran_key, max_rounds=max_rounds, return_b64=True)
        t1 = time.perf_counter()

        # time decrypt
        # reuse last ct to avoid encoding cost inside loop (we’re measuring engine, not base64)
        raw = _b64_payload(ct)
        t2 = time.perf_counter()
        for _ in range(reps):
            engine_cls.decrypt(raw, enc_key=enc_key, tran_key=tran_key, max_rounds=max_rounds, is_b64=False)
        t3 = time.perf_counter()

        enc_mb_s = (n * reps) / (t1 - t0) / (1024 * 1024)
        dec_mb_s = (n * reps) / (t3 - t2) / (1024 * 1024)
        results.append((n, enc_mb_s, dec_mb_s))
    return {"engine": engine_cls.__name__, "throughput": results}


def _diffusion(engine_cls, n=16384, flip_pos=None, seed=4444, max_rounds=7) -> Dict[str, Any]:
    """
    Measures %diff bytes/bits in the final wire blob when flipping 1 plaintext byte,
    with deterministic ephemerals for fairness.
    """
    enc_key = _rand_bytes(32, 555)
    tran_key = _rand_bytes(32, 666)
    pt0 = _rand_bytes(n, 777)

    if flip_pos is None:
        flip_pos = n // 2
    pt1 = bytearray(pt0)
    pt1[flip_pos] ^= 0x01  # flip one bit of one byte
    pt1 = bytes(pt1)

    # Use identical ephemerals via deterministic urandom patch for both encryptions
    with _UrandomPatch(engine_cls, seed):
        ct0_b64 = engine_cls.encrypt(pt0, enc_key=enc_key, tran_key=tran_key, max_rounds=max_rounds, return_b64=True)
    with _UrandomPatch(engine_cls, seed):
        ct1_b64 = engine_cls.encrypt(pt1, enc_key=enc_key, tran_key=tran_key, max_rounds=max_rounds, return_b64=True)

    # Compare full final blobs (prefix removed) so header+body differences count
    c0 = _b64_payload(ct0_b64)
    c1 = _b64_payload(ct1_b64)

    if len(c0) != len(c1):
        # Shouldn’t happen with deterministic ephemerals + 1-bit PT flip, but guard anyway
        m = min(len(c0), len(c1))
        c0, c1 = c0[:m], c1[:m]

    db, tb = _hamming_bytes(c0, c1)
    dB = 100.0 * db / tb
    dbit, tbit = _hamming_bits(c0, c1)
    dBit = 100.0 * dbit / tbit

    return {
        "engine": engine_cls.__name__,
        "size": n,
        "flip_pos": flip_pos,
        "diff_bytes_pct": dB,
        "diff_bits_pct": dBit,
        "bytes_compared": tb,
    }


def run_bench():
    engines = [("v3.3", Engine33), ("v3.4", Engine34)]

    print("\n=== THROUGHPUT (encrypt+decrypt) ===")
    for label, E in engines:
        res = _throughput(E, sizes=(1024, 8192, 65536), reps=100, max_rounds=7)
        print(f"\nEngine {label} ({E.__name__})")
        print(" size (bytes) | enc MB/s | dec MB/s")
        for n, enc_s, dec_s in res["throughput"]:
            print(f" {n:12d} | {enc_s:8.2f} | {dec_s:8.2f}")

    print("\n=== DIFFUSION (1-bit PT flip with identical ephemerals) ===")
    for label, E in engines:
        res = _diffusion(E, n=16384, flip_pos=None, seed=98765, max_rounds=7)
        print(f"\nEngine {label} ({E.__name__})")
        print(f" size={res['size']}  flip_pos={res['flip_pos']}  compared={res['bytes_compared']} bytes")
        print(f" differing bytes: {res['diff_bytes_pct']:.2f}%")
        print(f" differing bits : {res['diff_bits_pct']:.2f}%")

if __name__ == "__main__":
    run_bench()
