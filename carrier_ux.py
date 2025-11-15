#!/usr/bin/env python3
"""
carrier_ux.py — Sender/Receiver wizard for split-share carriers (with commitment)
Requires: keybook.py, carrier_tools.py in the same folder (CKS2 format).

Flows:
  1) Sender: open vault -> derive 32B session secret -> commit tag -> split -> embed
     - Share-A -> photo (PNG tEXt or JPEG COM)
     - Share-B -> zero-width encoded into a cover paragraph
     - Optional health check (verify the outputs before you actually send)
  2) Receiver: extract both shares -> verify commit -> reveal session secret (hex)
  3) Health check: quick validate that outputs still contain intact shares
  4) Settings: label blinding toggle, PNG keyword behavior, channel tips
  
Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, textwrap, getpass, hmac, hashlib, secrets
from typing import Optional, List, Tuple

import keybook
import carrier_tools as ct

# ---------------------------
# Environment / UI knobs
# ---------------------------
PYTHONISTA_MODE = True
SHOW_FULL_PATHS = False

# Settings (user-toggleable in the menu)
BLIND_LABELS = True
RANDOMIZE_PNG_KEYWORD = True
PNG_KEYWORD_FIXED = "KEYBOOK"  # used if RANDOMIZE_PNG_KEYWORD is False

# Benign-looking PNG tEXt keywords to rotate through (when randomizing)
_PNG_KEYWORD_POOL = [
    "Description", "Comment", "Caption", "Camera-Model", "ColorProfile",
    "Software", "DateTime", "Author", "Source", "Notes"
]

def _short(path: str) -> str:
    return os.path.abspath(path) if SHOW_FULL_PATHS else os.path.basename(path)

def _clear():
    try:
        if PYTHONISTA_MODE:
            import console as _py_console
            _py_console.clear()
            return
    except Exception:
        pass
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass

def _inp(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""

def _yesno(prompt: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    while True:
        v = _inp(f"{prompt} [{d}]: ").strip().lower()
        if not v:
            return default
        if v in ("y", "yes"): return True
        if v in ("n", "no"):  return False

def _section(title: str):
    _clear()
    print(title)
    print("=" * len(title))
    print("")

# ---------------------------
# Core helpers
# ---------------------------

DEFAULT_VAULT = "MyVault.keybook"

def _open_vault_interactive(vault_path: str = DEFAULT_VAULT) -> keybook.VaultHandle:
    if not os.path.exists(vault_path):
        raise FileNotFoundError(f"Vault not found: {vault_path}")
    try:
        pw = getpass.getpass("Passphrase: ").strip()
    except Exception:
        print("(Heads up: passphrase input visible on this console.)")
        pw = _inp("Passphrase: ").strip()
    try:
        pep = getpass.getpass("Paper Pepper (32 chars): ").strip()
    except Exception:
        print("(Heads up: pepper input visible on this console.)")
        pep = _inp("Paper Pepper (32 chars): ").strip()
    if len(pep) != 32:
        raise ValueError("Pepper must be exactly 32 characters.")
    dev = _inp("Device ID (enter if bound; else blank): ").strip() or None
    return keybook.open_vault(vault_path, pw, pep, device_id=dev)

def _derive_session_secret(h: keybook.VaultHandle, *, target: str, nbytes: int = 32) -> bytes:
    # Use 'auth' purpose by convention for session bootstrap material
    return keybook.derive_key(h, "auth", target, epoch=None, length=nbytes)

def _commit16(secret: bytes) -> bytes:
    return hmac.new(secret, b"commit", hashlib.sha512).digest()[:16]

def _label_for_share(h: keybook.VaultHandle, target: str, side: str, secret: bytes) -> str:
    # If blinding is on: put a short, unlinkable tag instead of human-readable edition/target
    if BLIND_LABELS:
        tag8 = hashlib.blake2s(secret, person=b"label", digest_size=4).hexdigest()  # 8 hex chars
        return f"{tag8}:{side}"
    return f"{h.edition_id}:{target}:{side}"

def _choose_png_keyword() -> str:
    if RANDOMIZE_PNG_KEYWORD:
        return secrets.choice(_PNG_KEYWORD_POOL)
    return PNG_KEYWORD_FIXED
    
# --- PNG keyword brute finder for randomized tEXt keys ---

def _all_png_keywords_try_order() -> List[str]:
    # Try pool first, then the fixed keyword, then classic "KEYBOOK".
    seen = set()
    order = []
    for kw in _PNG_KEYWORD_POOL + [PNG_KEYWORD_FIXED, "KEYBOOK"]:
        if kw and kw not in seen:
            order.append(kw)
            seen.add(kw)
    return order

def _find_packed_share_in_png(photo_path: str) -> Optional[bytes]:
    """
    Try all common keywords and return the FIRST packed CKS2 payload we can unpack.
    Returns the raw packed bytes, or None if not found/valid.
    """
    for kw in _all_png_keywords_try_order():
        try:
            payloads = ct.extract_from_png(photo_path, keyword=kw)
        except Exception:
            continue
        for p in (payloads or []):
            try:
                # If this raises, it's not a valid CKS2 packed share
                _lab, _share, _commit = ct.unpack_share(p)
                return p
            except Exception:
                continue
    return None

def _find_packed_share_in_jpeg(photo_path: str) -> Optional[bytes]:
    """
    Scan all JPEG COM segments and return the first payload that unpacks
    as a valid CKS2 share. Returns None if nothing valid is found.
    """
    try:
        payloads = ct.extract_from_jpeg(photo_path)
    except Exception:
        return None
    for p in (payloads or []):
        try:
            _lab, _share, _commit = ct.unpack_share(p)
            return p
        except Exception:
            continue
    return None
        
# ---------------------------
# Sender flow
# ---------------------------

def sender_flow():
    _section("Carrier UX — Make Share Pair (commit-checked)")
    vault = _inp(f"Vault path [{DEFAULT_VAULT}]: ").strip() or DEFAULT_VAULT
    try:
        h = _open_vault_interactive(vault)
    except Exception as e:
        print("Failed to open vault:", e)
        _pause()
        return

    target = _inp("Target label (e.g., recipient/email/device): ").strip() or "channel-session"
    try:
        secret = _derive_session_secret(h, target=target, nbytes=32)
    except Exception as e:
        print("Could not derive session secret:", e)
        _pause()
        return
    commit = _commit16(secret)

    # Split
    share_a, share_b = ct.split_secret_xor(secret)

    # Pack with commitment tag
    label_a = _label_for_share(h, target, "A", secret)
    label_b = _label_for_share(h, target, "B", secret)
    pack_a = ct.pack_share(label_a, share_a, commit)
    pack_b = ct.pack_share(label_b, share_b, commit)

    # Photo carrier
    in_photo = _inp("Input photo path (.png or .jpg): ").strip()
    if not os.path.exists(in_photo):
        print("Photo not found.")
        _pause()
        return
    root, ext = os.path.splitext(in_photo.lower())
    out_photo = _inp("Output photo filename (Share-A) [photo_carrier" + ext + "]: ").strip() or ("photo_carrier" + ext)
    try:
        if ext == ".png":
            kw = _choose_png_keyword()
            ct.prepare_photo_carrier_png(in_photo, out_photo, pack_a, keyword=kw)
            print(f"Wrote photo carrier: {_short(out_photo)}  (PNG tEXt='{kw}')")
        elif ext in (".jpg", ".jpeg"):
            ct.prepare_photo_carrier_jpeg(in_photo, out_photo, pack_a)
            print(f"Wrote photo carrier: {_short(out_photo)}  (JPEG COM)")
        else:
            print("Unsupported image type; use PNG or JPEG.")
            _pause()
            return
    except Exception as e:
        print("Failed to embed Share-A in photo:", e)
        _pause()
        return

    # Cover paragraph
    print("\nEnter a short cover paragraph (or leave blank to use a template).")
    cover = _inp("> ").rstrip()
    if not cover:
        cover = textwrap.dedent("""\
            Great to hear from you. I’m sending the photo we talked about.
            Let me know if you want the original or a different resolution.
        """).strip()
    try:
        with_zw = ct.prepare_cover_paragraph(cover, pack_b)
        out_text = _inp("Output text filename (Share-B) [cover.txt]: ").strip() or "cover.txt"
        with open(out_text, "w", encoding="utf-8") as f:
            f.write(with_zw)
        print(f"Wrote cover text with invisible data: {_short(out_text)}")
    except Exception as e:
        print("Failed to embed Share-B in text:", e)
        _pause()
        return

    # Optional self-check (non-destructive)
    if _yesno("\nRun a quick health check on these outputs now?", default=True):
        ok = health_check_core(out_photo, out_text, ext)
        print("Health check:", "OK" if ok else "FAILED")

    # Handoff guidance
    print("\nSend these via TWO different channels:")
    print(f"  • PHOTO (Share-A): {_short(out_photo)}")
    print(f"  • TEXT  (Share-B): {_short(out_text)}")
    print("Do not send both in the same message/thread/platform if you can avoid it.")
    print("Commit tag (16B, for human read-back if needed):", commit.hex())

    _pause()

# ---------------------------
# Receiver flow
# ---------------------------

def receiver_flow():
    _section("Carrier UX — Extract & Join (verify commit)")
    in_photo = _inp("Photo file with Share-A (PNG/JPEG): ").strip()
    if not os.path.exists(in_photo):
        print("Photo not found.")
        _pause()
        return
    _, ext = os.path.splitext(in_photo.lower())

    # Extract packed A
    try:
        if ext == ".png":
            packed_a = _find_packed_share_in_png(in_photo)
            if not packed_a:
                print("No valid packed share found in PNG tEXt (metadata may be stripped or keyword uncommon).")
                _pause()
                return
            label_a, share_a, commit_a = ct.unpack_share(packed_a)
        elif ext in (".jpg", ".jpeg"):
            packed_a = _find_packed_share_in_jpeg(in_photo)
            if not packed_a:
                print("No valid packed share found in JPEG COM (metadata stripped?).")
                _pause()
                return
            label_a, share_a, commit_a = ct.unpack_share(packed_a)
        else:
            print("Unsupported image type; use PNG or JPEG.")
            _pause()
            return
    except Exception as e:
        print("Failed to parse photo:", e)
        _pause()
        return
    print("Found Share-A:", label_a)

    # Extract packed B from text
    in_text = _inp("Cover text file with Share-B: ").strip()
    if not os.path.exists(in_text):
        print("Text file not found.")
        _pause()
        return
    try:
        text = open(in_text, "r", encoding="utf-8").read()
        packed_b = ct.zw_decode(text)
        label_b, share_b, commit_b = ct.unpack_share(packed_b)
    except Exception as e:
        print("Could not recover Share-B:", e)
        _pause()
        return
    print("Found Share-B:", label_b)

    # Basic label sanity
    base_a = label_a.rsplit(":", 1)[0]
    base_b = label_b.rsplit(":", 1)[0]
    if base_a != base_b:
        print("Warning: share labels differ (mismatched pair).")

    # Commit tags must match
    if commit_a != commit_b:
        print("Tamper detected: different commit tags in A and B.")
        _pause()
        return

    # Re-join and verify commitment
    try:
        secret = ct.join_secret_xor(share_a, share_b)
    except Exception as e:
        print("Failed to join shares:", e)
        _pause()
        return

    import hmac, hashlib as _hashlib
    if hmac.new(secret, b"commit", _hashlib.sha512).digest()[:16] != commit_a:
        print("Tamper detected: commitment mismatch after join.")
        _pause()
        return

    print("\nSession secret (hex):", secret.hex())
    print("Commit OK.")
    if _yesno("Write a small receipt (no secrets)?", default=True):
        rec = _write_receipt(label_base=base_a, commit16=commit_a, artifacts=[in_photo, in_text])
        print("Receipt:", _short(rec))
    _pause()
    
# ---------------------------
# Health check (non-secret)
# ---------------------------

def health_check_core(photo_path: str, text_path: str, photo_ext: str) -> bool:
    try:
        if photo_ext == ".png":
            packed_a = _find_packed_share_in_png(photo_path)
            if not packed_a:
                print("  Photo: no valid packed share found in PNG.")
                return False
            la, sa, ca = ct.unpack_share(packed_a)
        else:
            packed_a = _find_packed_share_in_jpeg(photo_path)
            if not packed_a:
                print("  Photo: no embedded payload found.")
                return False
            la, sa, ca = ct.unpack_share(packed_a)
    except Exception as e:
        print("  Photo error:", e)
        return False

    try:
        txt = open(text_path, "r", encoding="utf-8").read()
        packed_b = ct.zw_decode(txt)
        lb, sb, cb = ct.unpack_share(packed_b)
    except Exception as e:
        print("  Text error:", e)
        return False

    if ca != cb:
        print("  Commit tags differ between carriers.")
        return False

    try:
        sec = ct.join_secret_xor(sa, sb)
    except Exception as e:
        print("  Join error:", e)
        return False

    import hmac, hashlib as _hashlib
    if hmac.new(sec, b"commit", _hashlib.sha512).digest()[:16] != ca:
        print("  Commitment mismatch after join.")
        return False

    print("  Photo/text both carry intact, matching shares. ✔")
    return True

def health_check_flow():
    _section("Carrier UX — Health Check")
    ph = _inp("Photo carrier path: ").strip()
    if not os.path.exists(ph):
        print("Photo not found.")
        _pause()
        return
    _, ext = os.path.splitext(ph.lower())
    tx = _inp("Cover text path: ").strip()
    if not os.path.exists(tx):
        print("Cover text not found.")
        _pause()
        return
    ok = health_check_core(ph, tx, ext)
    print("Health check:", "OK" if ok else "FAILED")
    _pause()

# ---------------------------
# Settings / tips
# ---------------------------

def settings_flow():
    global BLIND_LABELS, RANDOMIZE_PNG_KEYWORD, PNG_KEYWORD_FIXED
    _section("Carrier UX — Settings & Tips")
    print(f"1) Label blinding: {'ON' if BLIND_LABELS else 'OFF'}")
    print(f"2) PNG keyword: {'random' if RANDOMIZE_PNG_KEYWORD else ('fixed: ' + PNG_KEYWORD_FIXED)}")
    print(f"3) Channel tips")
    print("X) Back\n")
    ch = _inp("Select: ").strip().lower()
    if ch == "1":
        BLIND_LABELS = not BLIND_LABELS
        print("Label blinding is now", "ON" if BLIND_LABELS else "OFF")
        _pause()
    elif ch == "2":
        if RANDOMIZE_PNG_KEYWORD:
            if _yesno("Switch to fixed keyword?", default=True):
                RANDOMIZE_PNG_KEYWORD = False
                val = _inp(f"Enter fixed keyword [default: {PNG_KEYWORD_FIXED}]: ").strip()
                if val:
                    PNG_KEYWORD_FIXED = val
        else:
            if _yesno("Switch to randomized keyword per image?", default=True):
                RANDOMIZE_PNG_KEYWORD = True
        _pause()
    elif ch == "3":
        _clear()
        print("Channel Tips (informal)")
        print("-----------------------")
        print("• Some messengers/email/hosts STRIP PNG/JPEG metadata (tEXt/COM).")
        print("• Prefer channels that preserve original files (no recompress).")
        print("• Zero-width text can be normalized by editors and CMS pipelines.")
        print("• Test your intended path with Health Check before using it live.")
        print("• If unsure, send a ZIP archive containing the photo and text file.")
        print("")
        _pause()

# ---------------------------
# Receipts / utils
# ---------------------------

def _write_receipt(label_base: str, commit16: bytes, artifacts: List[str]) -> str:
    ts = _utc_ts()
    name = f"CarrierReceipt-{ts}.txt"
    with open(name, "w", encoding="utf-8") as f:
        f.write("CARRIER RECEIPT (no secrets)\n")
        f.write("============================\n")
        f.write(f"Time (UTC): {ts}\n")
        f.write(f"Label base: {label_base}\n")
        f.write(f"Commit16  : {commit16.hex()}\n")
        f.write("Artifacts : " + ", ".join(_short(a) for a in artifacts) + "\n")
    return name

def _utc_ts() -> str:
    import time
    return time.strftime("%Y-%m-%d_%H%M%S", time.gmtime())

def _pause():
    _inp("\nPress Return to continue...")

# ---------------------------
# Menu
# ---------------------------

def main_menu(argv: Optional[List[str]] = None) -> int:
    while True:
        _section("Carrier Tools")
        print("1) Make share pair (photo + text) [commit-checked]")
        print("2) Extract & join shares (verify commit)")
        print("3) Health check (validate outputs)")
        print("4) Settings & tips")
        print("X) Back\n")
        choice = _inp("Select: ").strip().lower()
        if choice in ("x", "q", "exit"):
            return 0
        try:
            if choice == "1":
                sender_flow()
            elif choice == "2":
                receiver_flow()
            elif choice == "3":
                health_check_flow()
            elif choice == "4":
                settings_flow()
            else:
                print("Unknown choice.")
                _pause()
        except KeyboardInterrupt:
            print("\nCancelled.")
            _pause()
        except Exception as e:
            print("Error:", e)
            _pause()

if __name__ == "__main__":
    raise SystemExit(main_menu())
