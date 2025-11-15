#!/usr/bin/env python3
"""
carrier_cli.py — Make/extract share pairs with commitment verification. Minimal CLI that:
	
  - opens MyVault.keybook via keybook.py,
  - derives a small session secret (or uses provided bytes),
  - splits into 2-of-2 XOR shares,
  - packs each share with label+checksum,
  - embeds Share-A into a photo (PNG tEXt or JPEG COM),
  - appends Share-B invisibly to a cover paragraph (zero-width).

Pure stdlib; PNG/JPEG/ZW carriers only. For larger/other carriers, extend carrier_tools.

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, sys, textwrap, hmac, hashlib
from typing import List, Optional

import keybook
import carrier_tools as ct

DEFAULT_VAULT = "MyVault.keybook"

def _inp(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""

_PNG_KEYWORD_POOL = [
    "Description", "Comment", "Caption", "Camera-Model", "ColorProfile",
    "Software", "DateTime", "Author", "Source", "Notes", "KEYBOOK"
]

def _find_packed_share_in_png(path: str) -> Optional[bytes]:
    """Try common PNG tEXt keywords and return the first payload that unpacks as a CKS2 share."""
    for kw in _PNG_KEYWORD_POOL:
        try:
            payloads = ct.extract_from_png(path, keyword=kw)
        except Exception:
            continue
        for p in (payloads or []):
            try:
                _ = ct.unpack_share(p)  # validate CKS2
                return p
            except Exception:
                continue
    return None

def _find_packed_share_in_jpeg(path: str) -> Optional[bytes]:
    """Scan all JPEG COM segments and return the first payload that unpacks as a CKS2 share."""
    try:
        payloads = ct.extract_from_jpeg(path)
    except Exception:
        return None
    for p in (payloads or []):
        try:
            _ = ct.unpack_share(p)  # validate CKS2
            return p
        except Exception:
            continue
    return None

def open_vault_interactive(vault_path: str = DEFAULT_VAULT) -> keybook.VaultHandle:
    import getpass
    if not os.path.exists(vault_path):
        print(f"Vault not found: {vault_path}")
        sys.exit(2)
    pw = getpass.getpass("Passphrase: ").strip()
    pep = getpass.getpass("Paper Pepper (32 chars): ").strip()
    if len(pep) != 32:
        print("Pepper must be exactly 32 characters.")
        sys.exit(2)
    dev = _inp("Device ID (enter if bound, else blank): ").strip() or None
    return keybook.open_vault(vault_path, pw, pep, device_id=dev)

def derive_session_secret(h: keybook.VaultHandle, *, target: str, bytes_len: int = 32) -> bytes:
    return keybook.derive_key(h, "auth", target, epoch=None, length=bytes_len)

def _commit_tag(secret: bytes) -> bytes:
    """16-byte commitment tag from secret."""
    return hmac.new(secret, b"commit", hashlib.sha512).digest()[:16]

def cmd_make_pair(argv: list[str]) -> int:
    print("== Keybook Carrier: Make Share Pair (with commitment) ==")
    vault = _inp(f"Vault path [{DEFAULT_VAULT}]: ").strip() or DEFAULT_VAULT
    h = open_vault_interactive(vault)

    target = _inp("Target label (e.g., recipient/email/device): ").strip() or "channel-session"
    secret = derive_session_secret(h, target=target, bytes_len=32)
    tag = _commit_tag(secret)

    share_a, share_b = ct.split_secret_xor(secret)
    label_base = f"{h.edition_id}:{target}"
    pack_a = ct.pack_share(f"{label_base}:A", share_a, tag)
    pack_b = ct.pack_share(f"{label_base}:B", share_b, tag)

    in_photo = _inp("Input photo path (.png or .jpg): ").strip()
    if not os.path.exists(in_photo):
        print("Photo not found.")
        return 2
    root, ext = os.path.splitext(in_photo.lower())
    out_photo = _inp("Output photo filename (carrying Share-A): ").strip() or ("photo_carrier" + ext)

    if ext == ".png":
        ct.prepare_photo_carrier_png(in_photo, out_photo, pack_a, keyword="KEYBOOK")
    elif ext in (".jpg", ".jpeg"):
        ct.prepare_photo_carrier_jpeg(in_photo, out_photo, pack_a)
    else:
        print("Unsupported image type; use PNG or JPEG.")
        return 2
    print("Wrote photo carrier:", out_photo)

    print("\nEnter a short cover paragraph (or leave blank to use a template).")
    cover = _inp("> ").rstrip()
    if not cover:
        cover = textwrap.dedent("""\
            Great to hear from you! Here's that photo from the trip I mentioned.
            Let me know if you'd like the higher-resolution version or the raw images.
            """).strip()
    cover_with_zw = ct.prepare_cover_paragraph(cover, pack_b)
    out_text = _inp("Output text filename for the cover paragraph [cover.txt]: ").strip() or "cover.txt"
    with open(out_text, "w", encoding="utf-8") as f:
        f.write(cover_with_zw)
    print("Wrote cover paragraph with invisible data:", out_text)

    print("\nShare with the recipient:")
    print("  • Send the PHOTO (Share-A) via your normal channel.")
    print("  • Send the TEXT (Share-B) via a different channel.")
    print("Recipient needs both files to reassemble and verify the session secret.\n")
    return 0

def cmd_extract(argv: list[str]) -> int:
    print("== Keybook Carrier: Extract & Join (commit-verified) ==")
    # Photo / Share-A
    in_photo = _inp("Photo file with Share-A (PNG/JPEG): ").strip()
    if not os.path.exists(in_photo):
        print("Photo not found.")
        return 2
    _, ext = os.path.splitext(in_photo.lower())

    try:
        if ext == ".png":
            packed = _find_packed_share_in_png(in_photo)
            if not packed:
                print("No valid packed share found in PNG tEXt (metadata stripped or keyword uncommon?).")
                return 2
            label_a, share_a, commit_a = ct.unpack_share(packed)
        elif ext in (".jpg", ".jpeg"):
            packed = _find_packed_share_in_jpeg(in_photo)
            if not packed:
                print("No valid packed share found in JPEG COM (metadata stripped?).")
                return 2
            label_a, share_a, commit_a = ct.unpack_share(packed)
        else:
            print("Unsupported image type; use PNG or JPEG.")
            return 2
    except Exception as e:
        print("Failed to parse photo:", e)
        return 2

    print("Found Share-A:", label_a)

    # Text / Share-B
    in_text = _inp("Cover text file with Share-B: ").strip()
    if not os.path.exists(in_text):
        print("Text file not found.")
        return 2
    text = open(in_text, "r", encoding="utf-8").read()
    try:
        packed_b = ct.zw_decode(text)
        label_b, share_b, commit_b = ct.unpack_share(packed_b)
    except Exception as e:
        print("Could not recover Share-B from text:", e)
        return 2
    print("Found Share-B:", label_b)

    # Basic label sanity (edition/target match)
    base_a = label_a.rsplit(":", 1)[0]
    base_b = label_b.rsplit(":", 1)[0]
    if base_a != base_b:
        print("Warning: share labels differ (mismatched edition/target).")

    # Commit tags from both carriers must match
    if commit_a != commit_b:
        print("Tamper detected: commit tags differ between carriers.")
        return 2

    # Re-join and verify commitment
    try:
        secret = ct.join_secret_xor(share_a, share_b)
    except Exception as e:
        print("Failed to join shares:", e)
        return 2
    commit_calc = _commit_tag(secret)
    if commit_calc != commit_a:
        print("Tamper detected: commitment mismatch after re-join.")
        return 2

    print("\nSession secret (hex):", secret.hex())
    print("Commit OK (16 bytes).")
    return 0

def main(argv: Optional[list[str]] = None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print("Usage: carrier_cli.py make-pair | extract")
        return 2
    cmd = argv[0].lower()
    if cmd == "make-pair":
        return cmd_make_pair(argv[1:])
    if cmd == "extract":
        return cmd_extract(argv[1:])
    print("Unknown command.")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
