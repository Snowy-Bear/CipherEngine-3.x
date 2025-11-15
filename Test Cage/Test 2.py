def run_bench():
    import sys, time, base64
    from cipher_engine_v3_3 import CipherEngine32x32 as Engine33
    from cipher_engine_v3_4 import CipherEngine32x32 as Engine34

    def bench_one(E, sizes=(1024, 4096, 16384), reps=20, rounds=7):
        enc = bytes([i%256 for i in range(32)])
        tran = bytes([(i*7)%256 for i in range(32)])
        print(f"\nEngine {E.__name__} — starting...", flush=True)
        print(" size (bytes) | enc MB/s | dec MB/s", flush=True)
        for n in sizes:
            data = b"\xAB"*n
            # warmup
            E.encrypt(data, enc_key=enc, tran_key=tran, max_rounds=rounds, return_b64=True)
            # enc
            t0 = time.perf_counter()
            for _ in range(reps):
                ct = E.encrypt(data, enc_key=enc, tran_key=tran, max_rounds=rounds, return_b64=True)
            t1 = time.perf_counter()
            raw = base64.b64decode(ct)[4:]
            # dec
            t2 = time.perf_counter()
            for _ in range(reps):
                E.decrypt(raw, enc_key=enc, tran_key=tran, max_rounds=rounds, is_b64=False)
            t3 = time.perf_counter()
            enc_mb_s = (n*reps)/((t1-t0)*1024*1024)
            dec_mb_s = (n*reps)/((t3-t2)*1024*1024)
            print(f" {n:12d} | {enc_mb_s:8.2f} | {dec_mb_s:8.2f}", flush=True)

    print("\n=== THROUGHPUT (encrypt+decrypt) ===", flush=True)
    bench_one(Engine33, sizes=(1024, 4096, 16384), reps=20, rounds=7)
    bench_one(Engine34, sizes=(1024, 4096, 16384), reps=20, rounds=7)

    print("\n=== DIFFUSION (quick) ===", flush=True)
    # tiny diffusion check so it returns fast
    from cipher_engine_v3_3 import CipherEngine32x32 as E33
    from cipher_engine_v3_4 import CipherEngine32x32 as E34
    for label, E in [("v3.3", E33), ("v3.4", E34)]:
        enc = bytes([i%256 for i in range(32)])
        tran = bytes([(i*7)%256 for i in range(32)])
        n = 8192
        pt0 = bytearray(b"\xCD"*n)
        pt1 = bytearray(pt0); pt1[n//2] ^= 1
        t0 = E.encrypt(bytes(pt0), enc_key=enc, tran_key=tran, max_rounds=7, return_b64=True)
        t1 = E.encrypt(bytes(pt1), enc_key=enc, tran_key=tran, max_rounds=7, return_b64=True)
        a = base64.b64decode(t0)[4:]; b = base64.b64decode(t1)[4:]
        diff_bytes = sum(x!=y for x,y in zip(a,b))
        diff_bits  = sum(((x^y).bit_count()) for x,y in zip(a,b))
        print(f"{label}: bytes diff {100*diff_bytes/len(a):.2f}%  bits diff {100*diff_bits/(8*len(a)):.2f}%", flush=True)

if __name__ == "__main__":
    run_bench()
