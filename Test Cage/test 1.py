from time import perf_counter
from cipher_engine_v3_3 import CipherEngine32x32 as E33
from cipher_engine_v3_4 import CipherEngine32x32 as E34

enc = bytes([i%256 for i in range(32)])
tran = bytes([(i*7)%256 for i in range(32)])
payload = b"A"*8192

for label, E in [("v3.3", E33), ("v3.4", E34)]:
    t0 = perf_counter()
    ct = E.encrypt(payload, enc_key=enc, tran_key=tran, max_rounds=7, return_b64=True)
    t1 = perf_counter()
    pt = E.decrypt(ct, enc_key=enc, tran_key=tran, max_rounds=7, is_b64=True)
    t2 = perf_counter()
    print(f"{label}: enc {1000*(t1-t0):.1f} ms, dec {1000*(t2-t1):.1f} ms, ok={pt==payload}")
