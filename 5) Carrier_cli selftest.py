#!/usr/bin/env python3
"""
carrier_cli_selftest.py (Pythonista-safe)
Smoke test for carrier_cli.py (PNG path):
  1) builds a temp vault (keybook),
  2) creates a tiny valid PNG,
  3) runs carrier_cli make-pair (with patched input/getpass),
  4) runs carrier_cli extract,
  5) prints PASS/FAIL and waits for Enter.

No SystemExit, no sys.exit — safe for iPadOS/Pythonista.

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, io, sys, tempfile, shutil, contextlib, getpass, traceback
import struct, binascii, zlib

def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data))
            + ctype
            + data
            + struct.pack(">I", binascii.crc32(ctype + data) & 0xffffffff))

def _write_minimal_png(path: str) -> None:
    out = bytearray(b"\x89PNG\r\n\x1a\n")
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)  # 1x1 RGBA
    out += _png_chunk(b'IHDR', ihdr)
    scanline = b"\x00" + b"\x00\x00\x00\x00"             # filter=0 + RGBA(0,0,0,0)
    out += _png_chunk(b'IDAT', zlib.compress(scanline))
    out += _png_chunk(b'IEND', b'')
    with open(path, "wb") as f:
        f.write(out)

class _InputFeeder:
    def __init__(self, answers): self.answers = list(answers)
    def __call__(self, prompt=""): return self.answers.pop(0) if self.answers else ""

class _GetpassFeeder:
    def __init__(self, answers): self.answers = list(answers)
    def __call__(self, prompt=""): return self.answers.pop(0) if self.answers else ""

@contextlib.contextmanager
def _patch_io(input_answers, getpass_answers):
    old_input = __builtins__['input'] if isinstance(__builtins__, dict) else __builtins__.input
    old_getpass = getpass.getpass
    feeder_inp = _InputFeeder(input_answers)
    feeder_gp  = _GetpassFeeder(getpass_answers)
    if isinstance(__builtins__, dict): __builtins__['input'] = feeder_inp
    else: __builtins__.input = feeder_inp
    getpass.getpass = feeder_gp
    try:
        yield
    finally:
        if isinstance(__builtins__, dict): __builtins__['input'] = old_input
        else: __builtins__.input = old_input
        getpass.getpass = old_getpass

def _pause():
    try:
        input("\nPress Enter to close this test...")
    except Exception:
        pass

def run():
    print("[1/7] Importing modules...")
    try:
        import keybook
        import carrier_cli
    except Exception as e:
        print("*** ERROR: import failed. Ensure keybook.py and carrier_cli.py are alongside this test.")
        print(e)
        _pause()
        return

    tmp = tempfile.mkdtemp(prefix="carrier_cli_test_")
    cwd0 = os.getcwd()
    try:
        os.chdir(tmp)

        print("[2/7] Creating tiny PNG carrier...")
        src_png = "tiny.png"
        _write_minimal_png(src_png)

        print("[3/7] Building minimal vault...")
        BOOK_SIZE = 1 * 1024 * 1024
        # Deterministic filler for test; exact 1 MiB
        book = (b"A normalized seed\n" * ((BOOK_SIZE // 18) + 10))[:BOOK_SIZE]
        passphrase = "test-pass"
        pepper     = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[:32]  # 32 chars
        h = keybook.init_vault_from_book(
            book_bytes=book,
            passphrase=passphrase,
            pepper=pepper,
            device_id="selftest-device",
            out_path="MyVault.keybook",
            sources=[{"title":"selftest","url":"about:selftest","content_hash":"-", "bytes": len(book)}]
        )

        print("[4/7] Running carrier_cli make-pair...")
        make_inputs = [
            "",                   # vault path -> default MyVault.keybook
            "",                   # (device id prompt path; blank)
            "selftest-target",    # target label
            src_png,              # input photo
            "photo_carrier.png",  # output photo
            "",                   # cover paragraph -> template
            "cover.txt",          # output text
        ]
        make_getpasses = [passphrase, pepper]
        with _patch_io(make_inputs, make_getpasses):
            rc = carrier_cli.main(["make-pair"])
        if rc != 0:
            print("*** FAIL: make-pair returned", rc)
            _pause()
            return

        if not os.path.exists("photo_carrier.png"):
            print("*** FAIL: photo_carrier.png not found after make-pair")
            _pause()
            return
        if not os.path.exists("cover.txt"):
            print("*** FAIL: cover.txt not found after make-pair")
            _pause()
            return

        print("[5/7] Running carrier_cli extract...")
        # (Optional) capture output to sanity-check messages
        buf = io.StringIO()
        extract_inputs = ["photo_carrier.png", "cover.txt"]
        with contextlib.redirect_stdout(buf):
            with _patch_io(extract_inputs, []):
                rc2 = carrier_cli.main(["extract"])
        if rc2 != 0:
            print("*** FAIL: extract returned", rc2)
            _pause()
            return

        # Optional: quick sanity check on output text
        outlog = buf.getvalue()
        if ("Found Share-A" not in outlog) or ("Found Share-B" not in outlog):
            print("*** WARNING: extract did not log both shares (output changed?):")
            print(outlog[:400] + ("..." if len(outlog) > 400 else ""))

        print("\n=== CARRIER_CLI SELF-TEST: PASS ===")
    except Exception as e:
        print("*** UNEXPECTED ERROR:", e)
        traceback.print_exc()
    finally:
        print("\nTemp dir:", tmp)
        try:
            shutil.rmtree(tmp)
            print("Temp dir removed.")
        except Exception:
            print("Temp dir not removed (you can inspect it).")
        os.chdir(cwd0)
        _pause()

if __name__ == "__main__":
    run()
