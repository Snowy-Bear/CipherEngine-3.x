#!/usr/bin/env python3
"""
sc_cli.py — Secure Channel CLI with AAD and v3.6 options (compatible with v3.5).

Encrypt/decrypt files using:
  - keybook.py (vault + bundle derivation)
  - secure_channel.ChannelContext (engine autodetect: v3.5 or v3.6)

Usage:
  sc_cli encrypt INFILE [--out OUT] [--raw]
  sc_cli decrypt INFILE [--out OUT] [--raw]

Global options:
  --vault PATH     Vault file (default: MyVault.keybook)
  --label STR      Derivation label/target (default: dm:default)
  --rounds N       Cipher "rounds" (cosmetic on v3.6; default: 7)
  --pass STR       Passphrase (optional; otherwise prompted)
  --pepper STR     Paper pepper (32 chars) (optional; otherwise prompted)

AAD & v3.6 hardening (silently ignored on v3.5):
  --aad VAL        Associated data:
                     - @path   -> load bytes from file
                     - hex     -> even-length hex string
                     - literal -> UTF-8 literal (fallback)
  --pad N          Pad ciphertext to multiples of N (default 256)
  --jitter J       Add up to J extra full blocks via deterministic jitter (default 0)
  --strict / --no-strict
                   Uniform auth errors (default: --strict)
  --msgid-base VAL Deterministic message-id base (hex or @path). If omitted, per-message
                   random IDs are used (v3.6). Streaming uses base+counter per chunk.
  --aad-hash-len N AAD header-hash length (16 or 32). Ignored on v3.5.

Exit codes: 0=OK, 2=usage/error.

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import argparse
import getpass
import sys
import os

from secure_channel import ChannelContext


# ---------------- helpers ----------------

def _read_bytes_source(spec: str) -> bytes:
    """
    Parse '@path' or hex or literal into bytes.
    """
    if not isinstance(spec, str):
        raise ValueError("spec must be a string")
    s = spec.strip()
    if not s:
        return b""

    # @path → read raw bytes
    if s.startswith("@"):
        path = s[1:]
        with open(path, "rb") as f:
            return f.read()

    # try hex
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s)
        except Exception:
            pass

    # fallback: UTF-8 literal
    return s.encode("utf-8", errors="replace")


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="sc_cli",
        description="Secure Channel file encrypt/decrypt (v3.5/v3.6 compatible)",
    )
    # Global/common options
    ap.add_argument("--vault", default="MyVault.keybook")
    ap.add_argument("--label", default="dm:default")
    ap.add_argument("--rounds", type=int, default=7)
    # Optional non-interactive credentials (used by self-tests/automation)
    ap.add_argument("--pass", dest="pw", default=None, help="Passphrase (unsafe on shared shells)")
    ap.add_argument("--pepper", dest="pep", default=None, help="Paper pepper (exactly 32 chars)")

    # AAD + v3.6 knobs (ignored by v3.5 engines)
    ap.add_argument("--aad", default=None, help="AAD: @path, hex, or literal")
    ap.add_argument("--pad", type=int, default=256, help="Pad-to block size (default 256)")
    ap.add_argument("--jitter", type=int, default=0, help="Extra full blocks via deterministic jitter (default 0)")
    strict = ap.add_mutually_exclusive_group()
    strict.add_argument("--strict", dest="strict", action="store_true", default=True, help="Uniform auth errors (default)")
    strict.add_argument("--no-strict", dest="strict", action="store_false", help="Disable strict-mode if supported")
    ap.add_argument("--msgid-base", default=None, help="Deterministic message-id base: @path or hex")
    ap.add_argument("--aad-hash-len", type=int, choices=(16, 32), default=None,
                    help="AAD header-hash length (16 or 32). Ignored on v3.5.")

    sub = ap.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("infile")
    p_enc.add_argument("--out", default=None, help="Output path (default: <in>.enc or <in>.enc.txt)")
    p_enc.add_argument("--raw", action="store_true", help="Write raw binary ciphertext instead of Base64 text")

    p_dec = sub.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("infile")
    p_dec.add_argument("--out", default=None, help="Output path (default: <in>.dec or stripped suffix)")
    p_dec.add_argument("--raw", action="store_true", help="Read raw binary ciphertext instead of Base64 text")

    return ap


def _load_creds(args) -> tuple[str, str]:
    """Get passphrase/pepper from args or prompt."""
    if args.pw is not None or args.pep is not None:
        if not args.pw or not args.pep:
            print("When using --pass/--pepper, provide both.", file=sys.stderr)
            raise SystemExit(2)
        if len(args.pep) != 32:
            print("Pepper must be exactly 32 characters.", file=sys.stderr)
            raise SystemExit(2)
        return args.pw, args.pep

    pw = getpass.getpass("Passphrase: ").strip()
    pep = getpass.getpass("Paper Pepper (32 chars): ").strip()
    if len(pep) != 32:
        print("Pepper must be exactly 32 characters.", file=sys.stderr)
        raise SystemExit(2)
    return pw, pep


def main(argv: list[str] | None = None) -> int:
    ap = _build_parser()
    args = ap.parse_args(argv)

    try:
        # Quick existence check for nicer errors
        if args.cmd in ("encrypt", "decrypt"):
            if not os.path.exists(args.infile):
                print(f"Input file not found: {args.infile}", file=sys.stderr)
                return 2

        pw, pep = _load_creds(args)

        # Normalize optional extras
        aad_bytes = _read_bytes_source(args.aad) if args.aad else None
        msgid_base = _read_bytes_source(args.msgid_base) if args.msgid_base else None

        # Clamp pad & jitter
        pad_to = max(16, int(args.pad))
        jitter = max(0, min(16, int(args.jitter)))

        # Open context (secure_channel auto-detects engine features)
        ctx = ChannelContext.open_and_derive(
            vault_path=args.vault,
            passphrase=pw,
            pepper=pep,
            label=args.label,
            rounds=args.rounds,
            aad_context=aad_bytes,
            pad_to=pad_to,
            pad_jitter_blocks=jitter,
            strict_mode=bool(args.strict),
            message_id_base=msgid_base,
            aad_hash_len=(args.aad_hash_len if args.aad_hash_len is not None else None),
        )

        if args.cmd == "encrypt":
            default_out = args.infile + (".enc" if args.raw else ".enc.txt")  # fixed
            out = args.out or default_out
            ctx.encrypt_file(args.infile, out, as_base64_text=(not args.raw))
            print("Wrote:", out)
            return 0

        elif args.cmd == "decrypt":
            out = args.out or (args.infile + ".dec")
            ctx.decrypt_file(args.infile, out, is_b64_input=(not args.raw))
            print("Wrote:", out)
            return 0

        else:
            print("Unknown command.", file=sys.stderr)
            return 2

    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 2
    except Exception as e:
        # Keep it simple for scripts/automation
        print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
