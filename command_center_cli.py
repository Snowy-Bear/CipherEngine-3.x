#!/usr/bin/env python3
"""
Command Center CLI for Keybook (pure stdlib, Pythonista-friendly)

Workflow:
  1) Build seed: ONLINE (Wikipedia) or OFFLINE (local text file)
  2) Create vault from seed
  3) Write Unlock Card + Recovery Summary
  4) (Optional) secure-delete any plaintext seed if ever written
  5) Promote to MyVault.keybook (keep archival edition file)
  6) Derive a sample key bundle (sanity check)

Other actions:
  - Vault info, verify credentials
  - Derive key bundle
  - Export unlock token (+paper card)
  - Import / Rewrap vault (token or creds)
  - Resequence (new edition)
  - Rotate passphrase (via Import/Rewrap creds path)
  - Pepper alphabet settings (Human-friendly vs Full ASCII)
  - Sanity encrypt/decrypt (v3.5) — existing
  - Sanity encrypt/decrypt (v3.6) — NEW

Requires: keybook.py, book_seed_builder.py in the same folder.
v3.6 sanity also expects cipher_engine shim (CipherEngine32x32) to point to v3.6.

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, sys, json, time, shutil, secrets, getpass, string, pathlib, warnings
from datetime import datetime
from getpass import GetPassWarning
from typing import Optional, List

import keybook
import book_seed_builder as bsb
try:
    import camocoat
except Exception:
    camocoat = None
    
# ---------------------------
# Pythonista niceties + layout knobs
# ---------------------------
PYTHONISTA_MODE = True
SHOW_FULL_PATHS = False
SECTION_SPACER_LINES = 1

# --- UI toggles ---
PREVIEW_CARD_AND_SUMMARY = False
PREVIEW_SEED_AUDIT      = False

# --- Privacy / archival policy switches ---
ARCHIVE_DIR = "Archived Books"
SAVE_AUDIT = False              # default: do not write seed_audit.json
SAVE_PLAINTEXT_SEED = False     # default: do not write book_seed.txt
ARCHIVE_BACKUPS = True

try:
    import console as _py_console
except Exception:
    _py_console = None

try:
    import carrier_ux
except Exception:
    carrier_ux = None

def _clear_screen():
    if PYTHONISTA_MODE and _py_console:
        try:
            _py_console.clear()
            return
        except Exception:
            pass
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass

def _quicklook(path: str):
    if PYTHONISTA_MODE and _py_console and os.path.exists(path):
        try:
            _py_console.quicklook(path)
        except Exception:
            pass

def _short(path: str) -> str:
    return os.path.abspath(path) if SHOW_FULL_PATHS else os.path.basename(path)

def _section(title: str):
    _clear_screen()
    print(title)
    print("=" * len(title))
    if SECTION_SPACER_LINES > 0:
        print("\n" * SECTION_SPACER_LINES, end="")

def _pause_to_menu():
    _inp("\nPress Return to go back to the main menu...")
    _clear_screen()

# ---------------------------
# Pepper generation options
# ---------------------------
USE_FULL_ASCII_PEPPER = False
SAFE_PAPER_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
FULL_ASCII_ALPHABET = string.ascii_letters + string.digits + string.punctuation

def generate_pepper(length: int = 32) -> str:
    alphabet = FULL_ASCII_ALPHABET if USE_FULL_ASCII_PEPPER else SAFE_PAPER_ALPHABET
    return "".join(secrets.choice(alphabet) for _ in range(length))

def _timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")

def _write_temp_pepper_card(pepper: str) -> str:
    fname = f"Pepper-{_timestamp()}.txt"
    with open(fname, "w", encoding="utf-8") as f:
        f.write("KEYBOOK PAPER PEPPER\n")
        f.write("====================\n\n")
        f.write("WRITE THIS ON PAPER. DO NOT STORE DIGITALLY.\n")
        f.write("Anyone with your pepper + passphrase + .keybook can open your vault.\n\n")
        f.write("Pepper (32 chars):\n")
        f.write(pepper + "\n")
    return fname

# ---------------------------
# Input / UX helpers
# ---------------------------
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
        if v in ("y", "yes"):
            return True
        if v in ("n", "no"):
            return False

def prompt_secret(label: str, *, confirm: bool = False, allow_empty: bool = False) -> str:
    """Prompt for a secret; suppress getpass warnings; fall back to visible input if needed."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", GetPassWarning)
            val = getpass.getpass(f"{label}: ")
    except (GetPassWarning, Exception):
        print(f"(Heads up: input for '{label}' will be visible on screen.)")
        val = input(f"{label}: ")
    val = (val or "").strip()
    if not allow_empty and not val:
        print(f"{label} is required.")
        return prompt_secret(label, confirm=confirm, allow_empty=allow_empty)
    if confirm:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", GetPassWarning)
                val2 = getpass.getpass(f"Confirm {label}: ")
        except (GetPassWarning, Exception):
            val2 = input(f"Confirm {label}: ")
        val2 = (val2 or "").strip()
        if val2 != val:
            print("Values did not match. Try again.")
            return prompt_secret(label, confirm=confirm, allow_empty=allow_empty)
    return val

def _pepper_checksum8(pepper: str) -> str:
    import hashlib
    return hashlib.sha512(pepper.encode("utf-8")).hexdigest()[:8]

def prompt_pepper() -> str:
    """
    Paper Pepper UX:
      - Enter = auto-generate 32 chars (paper-friendly by default).
      - Show once + 8-hex checksum; optional verify/type step.
      - If user types their own, enforce exactly 32 chars + confirmation.
    """
    print("Paper Pepper: press Enter to auto-generate a 32-char pepper,")
    print("or type your own (exactly 32 chars). We recommend auto-generate.\n")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", GetPassWarning)
            raw = getpass.getpass("Paper Pepper (exactly 32 chars, keep on paper) [Enter = auto]: ")
    except (GetPassWarning, Exception):
        print("(Heads up: input will be visible on screen.)")
        raw = input("Paper Pepper (exactly 32 chars, keep on paper) [Enter = auto]: ")
    raw = (raw or "").strip()

    if not raw:
        pep = generate_pepper(32)
        chksum = _pepper_checksum8(pep)
        print("\n--- WRITE THIS ON PAPER (do NOT store digitally) ---")
        print("Paper Pepper:", pep)
        print("Checksum (first 8 hex of SHA-512):", chksum)
        print("----------------------------------------------------\n")

        if _yesno("Have you written the pepper down (and checked the checksum)?", default=True):
            if _yesno("Optional: verify by typing the pepper now?", default=False):
                typed = prompt_secret("Type the pepper (verify)", confirm=False)
                if typed != pep:
                    print("Mismatch. Showing it once more so you can copy carefully:\n")
                    print("Paper Pepper:", pep)
                    print("Checksum:", chksum, "\n")
                    if not _yesno("Proceed with this pepper?", default=True):
                        return prompt_pepper()
            if _yesno("Save a temporary pepper card .txt for printing (then delete it)?", default=False):
                fname = _write_temp_pepper_card(pep)
                print("Wrote:", _short(fname))
                if _yesno("Delete the temporary pepper card now (recommended)?", default=True):
                    try:
                        os.remove(fname)
                        print("Temporary pepper card deleted.")
                    except Exception:
                        print("Couldn't delete the temporary card; please remove it manually.")
            return pep
        else:
            return prompt_pepper()

    if len(raw) != 32:
        print("Pepper must be exactly 32 characters.")
        return prompt_pepper()

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", GetPassWarning)
            c2 = getpass.getpass("Confirm Paper Pepper: ")
    except (GetPassWarning, Exception):
        c2 = input("Confirm Paper Pepper: ")
    c2 = (c2 or "").strip()
    if c2 != raw:
        print("Values did not match. Try again.")
        return prompt_pepper()

    return raw

def _now_utc_str(t=None):
    if t is None:
        t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t))

# ---- secure delete (Pythonista-safe) ----
def secure_delete(path: str | pathlib.Path) -> None:
    p = pathlib.Path(path)
    try:
        if not p.exists() or not p.is_file():
            return
        size = p.stat().st_size
        try:
            with p.open("r+b") as f:
                f.write(b"\x00" * size)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        except Exception:
            pass
        try:
            p.unlink()
        except FileNotFoundError:
            pass
        print(f"Deleted: {p.name}")
    except Exception as e:
        print(f"Could not delete {p}: {e}")

def _print_handle_summary(h: keybook.VaultHandle):
    print(f" Vault:       {_short(h.path)}")
    print(f" Edition ID:  {h.edition_id}")
    print(f" Device ID:   {h.device_ctx or '(none)'}")
    print(f" Created:     {_now_utc_str(h.created_utc)}")
    print(f" KDF:         PBKDF2-HMAC-SHA512 iters={h.kdf_iters} dklen=32")

def _promote_to_current(edition_path: str, current_name: str = "MyVault.keybook") -> str:
    cur_path = os.path.abspath(current_name)
    src_path = os.path.abspath(edition_path)
    if os.path.exists(cur_path):
        backup = f"{os.path.splitext(current_name)[0]}.{_timestamp()}.bak.keybook"
        shutil.move(cur_path, backup)
        print(f"Previous {current_name} moved to {_short(backup)}")
    shutil.copyfile(src_path, cur_path)
    print(f"{current_name} updated → {_short(cur_path)}")
    return cur_path

def _prompt_vault_path(default: str = "MyVault.keybook") -> str:
    p = _inp(f"Vault path [{default}]: ").strip()
    return p or default

def _ensure_dir(path: str | pathlib.Path) -> pathlib.Path:
    p = pathlib.Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p

def archive_backups(edition_id: str) -> None:
    dest = _ensure_dir(ARCHIVE_DIR)
    patterns = [
        f"{edition_id}.keybook",
        f"RecoverySummary-{edition_id}.txt",
        f"UnlockCard-{edition_id}.txt",
    ]
    for pat in patterns:
        for p in pathlib.Path(".").glob(pat):
            try:
                target = dest / p.name
                shutil.move(str(p), str(target))
                print(f"Archived: {p.name} -> {target}")
            except Exception as e:
                print(f"Could not archive {p}: {e}")

# ---------------------------
# Main flows
# ---------------------------

def flow_create_vault():
    _section("Create New Vault")
    mode = ""
    while mode not in ("o", "f"):
        mode = _inp("Choose mode: (O)nline or (F)ile? ").strip().lower()

    hints: List[str] = []
    seed_bytes: bytes = b""
    audit: List[dict] = []

    if mode == "o":
        print("Enter 3–10 hints (one per line). Blank line to finish.")
        while True:
            line = _inp("> ").strip()
            if not line:
                break
            hints.append(line)
            if len(hints) >= 10:
                break
        if not hints:
            print("No hints provided; aborting.")
            _pause_to_menu()
            return
        print(f"\nGot {len(hints)} hint(s). Fetching a few pages per hint (polite delays)...")
        try:
            seed_bytes, audit = bsb.build_online(hints)
        except Exception as e:
            print("Failed to build online seed:", e)
            _pause_to_menu()
            return
    else:
        path = _inp("Path to UTF-8 text file (>= ~2–4 MiB recommended): ").strip()
        try:
            seed_bytes, audit = bsb.build_offline(path)
        except Exception as e:
            print("Failed to build offline seed:", e)
            _pause_to_menu()
            return

    # Always report harvest count
    print(f"Harvested pages: {len(audit)}")

    # Save seed + audit only if flags enabled
    if SAVE_PLAINTEXT_SEED:
        seed_path = "book_seed.txt"
        with open(seed_path, "wb") as f:
            f.write(seed_bytes)
        print(f"Seed built: {_short(seed_path)} ({len(seed_bytes)} bytes)")
    else:
        print("Plaintext seed NOT saved (default).")

    if SAVE_AUDIT:
        audit_path = "seed_audit.json"
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump({"size_bytes": len(seed_bytes), "sources": audit}, f, indent=2)
        print(f"Audit saved: {_short(audit_path)}")
        if PREVIEW_SEED_AUDIT:
            _quicklook(audit_path)
    else:
        print("Audit not saved (default).")

    # Credentials
    passphrase = prompt_secret("Passphrase", confirm=True)
    pepper = prompt_pepper()
    if passphrase == pepper:
        print("Warning: passphrase and pepper should NOT be the same. Consider changing one.")
    device_id = _inp("Device ID (optional, public label): ").strip() or None
    out_vault = _inp("Output vault filename (e.g., MyVault.keybook) [enter for auto]: ").strip() or None

    # Create vault from seed
    try:
        h = keybook.init_vault_from_book(
            book_bytes=seed_bytes,
            passphrase=passphrase,
            pepper=pepper,
            device_id=device_id,
            out_path=out_vault,
            sources=audit
        )
    except Exception as e:
        print("Failed to create vault:", e)
        _pause_to_menu()
        return

    _section("Vault Created")
    _print_handle_summary(h)

    # Export unlock token + write card + summary
    try:
        tok = keybook.export_unlock_token(h, passphrase=passphrase, pepper=pepper)
        import hashlib
        checksum8 = hashlib.sha512(tok).hexdigest()[:8]
        card = keybook.format_unlock_token_card(
            edition_id=h.edition_id, token=tok, label="Primary vault",
            device_ctx=h.device_ctx, created_utc=h.created_utc
        )
        card_path = f"UnlockCard-{h.edition_id}.txt"
        with open(card_path, "w", encoding="utf-8") as f:
            f.write(card)

        def make_summary():
            lines = []
            lines.append("KEYBOOK RECOVERY SUMMARY")
            lines.append("========================")
            lines.append(f"Vault file:   {_short(h.path)}")
            lines.append(f"Edition ID:   {h.edition_id}")
            lines.append(f"Device ID:    {h.device_ctx or '(none)'}")
            lines.append(f"Created:      {_now_utc_str(h.created_utc)}")
            lines.append(f"KDF:          PBKDF2-HMAC-SHA512, iters={h.kdf_iters}, dklen=32")
            lines.append("")
            lines.append("Paper Pepper:")
            lines.append("  (written on paper; do not store digitally)")
            lines.append("")
            lines.append("Unlock token checksum (first 8 hex of SHA-512(token)):")
            lines.append(f"  {checksum8}")
            lines.append("")
            lines.append("Recovery steps:")
            lines.append("  1) Copy your .keybook file and your paper pepper to the new device.")
            lines.append("  2) Enter the passphrase and pepper to open the vault;")
            lines.append("     OR import via the unlock token card if passphrase is lost.")
            lines.append("  3) Derive keys as needed; resequence to a new edition if rotating sources.")
            lines.append("")
            lines.append("Important:")
            lines.append("  • Anyone with the unlock token + the .keybook file can open the vault.")
            lines.append("  • Keep the token card and pepper strictly OFFLINE (paper).")
            lines.append("  • Device ID is a public label; it is not a secret.")
            return "\n".join(lines)

        summary = make_summary()
        summary_path = f"RecoverySummary-{h.edition_id}.txt"
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(summary)

        print("\nWrote:")
        print(f" - {_short(card_path)}  (paper unlock card)")
        print(f" - {_short(summary_path)}  (recovery summary)")
        if PREVIEW_CARD_AND_SUMMARY:
            _quicklook(card_path)
            _quicklook(summary_path)
    except Exception as e:
        print("Warning: failed to export unlock token/card:", e)

    # Promote newest edition to MyVault.keybook
    try:
        _promote_to_current(h.path, "MyVault.keybook")
    except Exception as e:
        print("Warning: could not update MyVault.keybook:", e)

    # NEW: archive the edition artifacts (optional)
    if ARCHIVE_BACKUPS:
        archive_backups(h.edition_id)

    # Post-creation sanity derivation
    print("\nDeriving a sample key bundle (post-creation sanity check)...")
    target = _inp("Target label (e.g., project/device/email) [default: sample]: ").strip() or "sample"
    b = keybook.derive_bundle(h, target=target)
    print("Bundle:")
    print(" enc:", b["enc"].hex())
    print(" tran:", b["tran"].hex())
    print(" hmac:", b["hmac"].hex())
    print("(aux1 and aux2 reserved; available via derive_bundle)")

    _pause_to_menu()

def flow_info():
    _section("Vault Info")
    path = _prompt_vault_path()
    passphrase = prompt_secret("Passphrase")
    pepper = prompt_secret("Paper Pepper")
    device = _inp("Device ID (if bound): ").strip() or None
    try:
        h = keybook.open_vault(path, passphrase, pepper, device_id=device)
        _print_handle_summary(h)
    except Exception as e:
        print("Failed:", e)
    _pause_to_menu()

def flow_verify():
    _section("Verify Credentials")
    path = _prompt_vault_path()
    passphrase = prompt_secret("Passphrase")
    pepper = prompt_secret("Paper Pepper")
    ok = keybook.verify_credentials(path, passphrase, pepper)
    print("Valid credentials:", ok)
    _pause_to_menu()

def flow_export_token():
    _section("Export Unlock Token")
    path = _prompt_vault_path()
    passphrase = prompt_secret("Passphrase")
    pepper = prompt_secret("Paper Pepper")
    device = _inp("Device ID (if bound): ").strip() or None
    try:
        h = keybook.open_vault(path, passphrase, pepper, device_id=device)
        tok = keybook.export_unlock_token(h, passphrase, pepper)
        print("Token (hex):", tok.hex())
        if _yesno("Write a paper card file?", default=True):
            card = keybook.format_unlock_token_card(
                h.edition_id, tok, label="Exported",
                device_ctx=h.device_ctx, created_utc=h.created_utc
            )
            out = f"UnlockCard-{h.edition_id}.txt"
            with open(out, "w", encoding="utf-8") as f:
                f.write(card)
            print("Wrote:", _short(out))
            if PREVIEW_CARD_AND_SUMMARY:
                _quicklook(out)
    except Exception as e:
        print("Failed:", e)
    _pause_to_menu()

def flow_import_rewrap():
    _section("Import / Rewrap Vault")
    path = _prompt_vault_path()
    device = _inp("New Device ID (optional): ").strip() or None
    out_path = _inp("Output path (enter to overwrite): ").strip() or None
    use_tok = _yesno("Use unlock token? (if No, uses passphrase+pepper)", default=True)
    if use_tok:
        tok_hex = prompt_secret("Unlock token (hex, 64 chars)")
        try:
            tok = bytes.fromhex(tok_hex)
        except Exception:
            print("Bad token hex.")
            _pause_to_menu()
            return
        new_pass = prompt_secret("New passphrase", confirm=True)
        pepper = prompt_secret("Paper Pepper (unchanged)")
        try:
            h = keybook.import_vault(
                path, passphrase=new_pass, pepper=pepper,
                unlock_token=tok, device_id=device, out_path=out_path
            )
            _print_handle_summary(h)
            try:
                _promote_to_current(h.path, "MyVault.keybook")
            except Exception as e:
                print("Warning: could not update MyVault.keybook:", e)
            if ARCHIVE_BACKUPS:
                archive_backups(h.edition_id)
        except Exception as e:
            print("Failed:", e)
    else:
        old_pass = prompt_secret("Old passphrase")
        pepper = prompt_secret("Paper Pepper")
        new_pass = prompt_secret("New passphrase", confirm=True)
        try:
            h = keybook.open_vault(path, old_pass, pepper, device_id=device)
            h2 = keybook.rotate_passphrase(
                h, old_passphrase=old_pass, pepper=pepper,
                new_passphrase=new_pass, device_id=device
            )
            _print_handle_summary(h2)
            try:
                _promote_to_current(h2.path, "MyVault.keybook")
            except Exception as e:
                print("Warning: could not update MyVault.keybook:", e)
            if ARCHIVE_BACKUPS:
                archive_backups(h2.edition_id)
        except Exception as e:
            print("Failed:", e)
    _pause_to_menu()

def flow_resequence():
    _section("Resequence (new edition)")
    path = _prompt_vault_path()
    passphrase = prompt_secret("Passphrase")
    pepper = prompt_secret("Paper Pepper")
    device = _inp("Device ID (if bound): ").strip() or None
    hints: List[str] = []
    print("Add resequence hints (blank line to finish, or just press enter to skip):")
    while True:
        line = _inp("> ").strip()
        if not line:
            break
        hints.append(line)
        if len(hints) >= 10:
            break
    try:
        h = keybook.open_vault(path, passphrase, pepper, device_id=device)
        h2 = keybook.resequence_vault(
            h, passphrase, pepper, new_hints=hints or None, device_id=device
        )
        _print_handle_summary(h2)
        print("New file:", _short(h2.path))
        try:
            _promote_to_current(h2.path, "MyVault.keybook")
        except Exception as e:
            print("Warning: could not update MyVault.keybook:", e)
        if ARCHIVE_BACKUPS:
            archive_backups(h2.edition_id)
    except Exception as e:
        print("Failed:", e)
    _pause_to_menu()

def flow_derive_bundle():
    _section("Derive Key Bundle")
    path = _prompt_vault_path()
    passphrase = prompt_secret("Passphrase")
    pepper = prompt_secret("Paper Pepper")
    device = _inp("Device ID (if bound): ").strip() or None
    target = _inp("Target label (email/device/project): ").strip() or "sample"
    epoch = _inp("Epoch/edition (enter to use current): ").strip() or None
    try:
        h = keybook.open_vault(path, passphrase, pepper, device_id=device)
        b = keybook.derive_bundle(h, target=target, epoch=epoch)
        print("Edition:", b["edition_id"], "Epoch:", b["epoch"])
        print(" enc:", b["enc"].hex())
        print(" tran:", b["tran"].hex())
        print(" hmac:", b["hmac"].hex())
        print(" aux1:", b["aux1"].hex())
        print(" aux2:", b["aux2"].hex())
    except Exception as e:
        print("Failed:", e)
    _pause_to_menu()

def flow_pepper_settings():
    """Toggle pepper alphabet between Human-friendly and Full ASCII, and show entropy/help."""
    import math
    global USE_FULL_ASCII_PEPPER

    _section("Pepper Alphabet Settings")

    def _mode_name(flag: bool) -> str:
        return "FULL ASCII (94 printable chars)" if flag else "Human-friendly (no look-alikes)"

    cur_flag = USE_FULL_ASCII_PEPPER
    cur_alphabet = FULL_ASCII_ALPHABET if cur_flag else SAFE_PAPER_ALPHABET
    cur_bits = 32 * math.log2(len(cur_alphabet))

    print(f"Current mode: {_mode_name(cur_flag)}")
    print(f"Alphabet size: {len(cur_alphabet)} characters")
    print(f"Pepper entropy (32 chars): ~{cur_bits:.1f} bits\n")
    print("Human-friendly avoids ambiguous characters like O/0 and I/1, easier to transcribe.")
    print("Full ASCII maximizes entropy but is harder to copy by hand.\n")
    sample = generate_pepper(32)
    print("Example pepper (sample):")
    print(sample)
    print("")

    if _yesno("Toggle the pepper alphabet mode?", default=True):
        USE_FULL_ASCII_PEPPER = not USE_FULL_ASCII_PEPPER
        new_flag = USE_FULL_ASCII_PEPPER
        new_alphabet = FULL_ASCII_ALPHABET if new_flag else SAFE_PAPER_ALPHABET
        new_bits = 32 * math.log2(len(new_alphabet))
        print("")
        print(f"New mode: {_mode_name(new_flag)}")
        print(f"Alphabet size: {len(new_alphabet)}")
        print(f"Pepper entropy (32 chars): ~{new_bits:.1f} bits")
        print("\nThis setting affects peppers generated from now on.")
    _pause_to_menu()

def flow_carrier_tools():
    _section("Carrier Tools (photo/text shares)")
    if carrier_ux is None:
        print("carrier_ux.py not found in this folder.\n"
              "Place it alongside command_center_cli.py and try again.")
        _pause_to_menu()
        return
    print("Launching carrier submenu... (you'll return here when done)\n")
    try:
        carrier_ux.main_menu()
    except KeyboardInterrupt:
        print("\nCancelled.")
    except Exception as e:
        print("Carrier tools error:", e)
    _pause_to_menu()
    
def flow_camocoat():
    _section("Camocoat (wrap/unwrap ciphertext)")
    if camocoat is None:
        print("camocoat.py not found in this folder.\n"
              "Place it alongside command_center_cli.py and try again.")
        _pause_to_menu()
        return

    mode = ""
    while mode not in ("w", "u"):
        mode = _inp("Choose: (W)rap ciphertext  or  (U)nwrap to raw ciphertext? ").strip().lower()

    if mode == "w":
        in_path = _inp("Input ciphertext file (raw bytes or Base64 text): ").strip()
        if not in_path:
            print("No input provided.")
            _pause_to_menu()
            return
        is_b64 = _yesno("Is the input ciphertext Base64 text?", default=False)

        fmt = ""
        while fmt not in ("png", "pdf", "zip", "log"):
            fmt = _inp("Coat format [png/pdf/zip/log] (default: png): ").strip().lower() or "png"

        out_default = {
            "png":  in_path + ".png",
            "pdf":  in_path + ".pdf",
            "zip":  in_path + ".zip",
            "log":  in_path + ".log.txt",
        }[fmt]
        out_path = _inp(f"Output path [{out_default}]: ").strip() or out_default

        try:
            if fmt == "log":
                # LOG expects Base64 text; if user gave raw bytes, base64 it.
                if is_b64:
                    payload_b64 = open(in_path, "r", encoding="utf-8", errors="replace").read()
                else:
                    payload_b = open(in_path, "rb").read()
                    import base64
                    payload_b64 = base64.b64encode(payload_b).decode("ascii")
                wrapped = camocoat.wrap_log(payload_b64)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(wrapped)
            elif fmt == "png":
                raw = open(in_path, "rb").read() if not is_b64 else __import__("base64").b64decode(open(in_path, "r").read())
                wrapped = camocoat.wrap_png(raw)
                open(out_path, "wb").write(wrapped)
            elif fmt == "pdf":
                raw = open(in_path, "rb").read() if not is_b64 else __import__("base64").b64decode(open(in_path, "r").read())
                title = _inp("Optional PDF title [Report]: ").strip() or "Report"
                wrapped = camocoat.wrap_pdf(raw, title=title)
                open(out_path, "wb").write(wrapped)
            else:  # zip
                raw = open(in_path, "rb").read() if not is_b64 else __import__("base64").b64decode(open(in_path, "r").read())
                inner = _inp("Filename inside ZIP [data.bin]: ").strip() or "data.bin"
                wrapped = camocoat.wrap_zip(raw, name=inner)
                open(out_path, "wb").write(wrapped)

            print("Wrote:", _short(out_path))
            if _yesno("Preview (Quick Look) if available?", default=False):
                _quicklook(out_path)
        except Exception as e:
            print("Camocoat wrap failed:", e)

    else:  # unwrap
        in_path = _inp("Input coated file (png/pdf/zip/log): ").strip()
        if not in_path:
            print("No input provided.")
            _pause_to_menu()
            return
        data = None
        try:
            with open(in_path, "rb") as f:
                data = f.read()
        except Exception:
            print("Could not read input file.")
            _pause_to_menu()
            return

        kind = camocoat.detect_format(data)["format"]
        print("Detected format:", kind)

        # For ZIP, allow alternate inner name
        zip_name = None
        if kind == "zip":
            zip_name = _inp("Name inside ZIP [data.bin]: ").strip() or "data.bin"

        # Choose output style: raw bytes or Base64 text
        as_b64 = _yesno("Write output as Base64 text instead of raw bytes?", default=False)
        out_default = in_path + (".ct.b64.txt" if as_b64 else ".ct")
        out_path = _inp(f"Output path [{out_default}]: ").strip() or out_default

        try:
            raw = camocoat.unwrap_auto(data, zip_name=zip_name or "data.bin")
            if as_b64:
                import base64
                b64 = base64.b64encode(raw).decode("ascii")
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(b64)
            else:
                with open(out_path, "wb") as f:
                    f.write(raw)
            print("Wrote:", _short(out_path))
            if _yesno("Preview (Quick Look) if available?", default=False):
                _quicklook(out_path)
        except Exception as e:
            print("Camocoat unwrap failed:", e)

    _pause_to_menu()

# --- sanity encrypt/decrypt (engine v3.5) -------------------------
def flow_sanity_encrypt():
    _section("Sanity Encrypt/Decrypt (v3.5)")
    path = _prompt_vault_path()
    passphrase = prompt_secret("Passphrase")
    pepper = prompt_secret("Paper Pepper")
    device = _inp("Device ID (if bound): ").strip() or None
    try:
        h = keybook.open_vault(path, passphrase, pepper, device_id=device)
    except Exception as e:
        print("Open failed:", e)
        _pause_to_menu()
        return

    target = _inp("Target label (default: sanity): ").strip() or "sanity"
    ctx = _inp("AAD context (default: file:/tmp/sanity.txt): ").strip() or "file:/tmp/sanity.txt"
    msg_in = _inp("Message to encrypt (leave empty for random 512 bytes): ")
    if msg_in:
        msg = msg_in.encode("utf-8", errors="replace")
    else:
        msg = secrets.token_bytes(512)

    try:
        bundle = keybook.derive_bundle(h, target=target)
        ct_b64 = keybook.engine_encrypt_v35(msg, bundle, context=ctx, max_rounds=7, return_b64=True)
        pt = keybook.engine_decrypt_v35(ct_b64, bundle, context=ctx, max_rounds=7, is_b64=True)
        ok = (pt == msg)
        print("\nRound-trip OK:", ok)
        print("Ciphertext (b64, first 96 chars):", ct_b64[:96] + ("..." if len(ct_b64) > 96 else ""))
        if not ok:
            print("(!) Plaintext mismatch")
    except Exception as e:
        print("Sanity encrypt/decrypt failed:", e)

    _pause_to_menu()

# --- sanity encrypt/decrypt (engine v3.6) -------------------------
def flow_sanity_encrypt_v36():
    _section("Sanity Encrypt/Decrypt (v3.6)")
    # Lazy import to avoid hard dependency if v3.6 not installed here:
    try:
        from cipher_engine import CipherEngine32x32 as Engine  # v3.6 shim
    except Exception as e:
        print("cipher_engine (v3.6) not available:", e)
        _pause_to_menu()
        return

    path = _prompt_vault_path()
    passphrase = prompt_secret("Passphrase")
    pepper = prompt_secret("Paper Pepper")
    device = _inp("Device ID (if bound): ").strip() or None
    try:
        h = keybook.open_vault(path, passphrase, pepper, device_id=device)
    except Exception as e:
        print("Open failed:", e)
        _pause_to_menu()
        return

    target = _inp("Target label (default: sanity36): ").strip() or "sanity36"
    meta_str = _inp("AAD context (default: file:/tmp/sanity36.txt): ").strip() or "file:/tmp/sanity36.txt"
    aad_mode = _inp("AAD mode: (h)ash / (m)ac-with-aux1 [h]: ").strip().lower() or "h"
    pad_to_str = _inp("pad_to bytes [256]: ").strip() or "256"
    jitter_str = _inp("pad_jitter_blocks [0..3] [0]: ").strip() or "0"
    msg_in = _inp("Message to encrypt (leave empty for random 512 bytes): ")

    try:
        pad_to = max(16, int(pad_to_str))
        jitter = max(0, min(16, int(jitter_str)))
    except Exception:
        pad_to, jitter = 256, 0

    if msg_in:
        msg = msg_in.encode("utf-8", errors="replace")
    else:
        msg = secrets.token_bytes(512)

    try:
        bundle = keybook.derive_bundle(h, target=target)

        # message_id: derive deterministically for demo; in production you might use a counter or uuid
        msg_id = keybook.derive_message_id(h, label=target, counter=int(time.time()))

        # AAD: choose hash or HMAC
        if aad_mode.startswith("m"):
            aad = keybook.make_aad_hmac(bundle, meta_str)  # 64B
        else:
            aad = keybook.make_aad_hash(meta_str)          # 32B

        ct_b64 = Engine.encrypt(
            msg,
            enc_key=bundle["enc"],
            tran_key=bundle["tran"],
            message_id=msg_id,
            aad_context=aad,
            pad_to=pad_to,
            pad_jitter_blocks=jitter,
            return_b64=True,
        )
        pt = Engine.decrypt(
            ct_b64,
            enc_key=bundle["enc"],
            tran_key=bundle["tran"],
            message_id=msg_id,
            aad_context=aad,
            is_b64=True,
        )
        ok = (pt == msg)
        print("\nRound-trip OK:", ok)
        if isinstance(ct_b64, str):
            preview = ct_b64[:96] + ("..." if len(ct_b64) > 96 else "")
            print("Ciphertext (b64 preview):", preview)
        print(f"pad_to={pad_to}, jitter_blocks={jitter}, aad_len={len(aad)}")
        if not ok:
            print("(!) Plaintext mismatch")
    except Exception as e:
        print("Sanity (v3.6) failed:", e)

    _pause_to_menu()

# ------- MENU & MAIN LOOP -------

def _menu():
    mode_label = "FULL ASCII" if USE_FULL_ASCII_PEPPER else "Human-friendly"
    print("Keybook Command Center  ·  Pepper:", mode_label)
    print("=======================")
    print("1) Create new vault (online/offline)")
    print("2) Vault info")
    print("3) Verify credentials")
    print("4) Derive key bundle")
    print("5) Export unlock token (+paper card)")
    print("6) Import / Rewrap vault (token or creds)")
    print("7) Camocoat: wrap/unwrap ciphertext")   # ← NEW
    print("8) Resequence (new edition)")
    print("9) Rotate passphrase (in place)")
    print("10) Pepper alphabet settings")
    print("11) Carrier tools (photo/text shares)")
    print("12) Sanity encrypt/decrypt (v3.5)")
    print("13) Sanity encrypt/decrypt (v3.6)")
    print("X) Exit")

def _main_cli(argv: Optional[List[str]] = None) -> int:
    while True:
        _clear_screen()
        _menu()
        choice = _inp("Select: ").strip().lower()
        if choice in ("x", "q", "exit"):
            _clear_screen()
            return 0
        try:
            if choice == "1":
                flow_create_vault()
            elif choice == "2":
                flow_info()
            elif choice == "3":
                flow_verify()
            elif choice == "4":
                flow_derive_bundle()
            elif choice == "5":
                flow_export_token()
            elif choice == "6":
                flow_import_rewrap()
            elif choice == "7":
                flow_camocoat()
            elif choice == "8":
                flow_resequence()
            elif choice == "9":
                flow_import_rewrap()  # rotate via creds path
            elif choice == "10":
                flow_pepper_settings()
            elif choice == "11":
                flow_carrier_tools()
            elif choice == "12":
                flow_sanity_encrypt()
            elif choice == "13":
                flow_sanity_encrypt_v36()
            else:
                print("Unknown choice.")
                _pause_to_menu()
        except KeyboardInterrupt:
            print("\nCancelled.")
            _pause_to_menu()
        except Exception as e:
            print("Error:", e)
            _pause_to_menu()

if __name__ == "__main__":
    raise SystemExit(_main_cli())
