# command_center.py
from __future__ import annotations
import os, json, time, hashlib, secrets
from typing import Optional, List
import keybook
import book_seed_builder as bsb  # your builder script

# ---------- helpers ----------
def _now_utc_str(t=None):
    if t is None: t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t))

def best_effort_secure_delete(path: str) -> bool:
    """
    Best-effort: overwrite file size with random bytes once, then delete.
    (Note: on iOS/APFS/journaled FS this is not a guaranteed forensic wipe.)
    """
    try:
        if not os.path.exists(path):
            return True
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            chunk = 64 * 1024
            remaining = size
            while remaining > 0:
                n = min(chunk, remaining)
                f.write(secrets.token_bytes(n))
                remaining -= n
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)
        return True
    except Exception:
        return False

def make_recovery_summary(handle: keybook.VaultHandle,
                          paper_pepper_note: str,
                          token_checksum: Optional[str] = None) -> str:
    lines = []
    lines.append("KEYBOOK RECOVERY SUMMARY")
    lines.append("========================")
    lines.append(f"Vault file:   {handle.path}")
    lines.append(f"Edition ID:   {handle.edition_id}")
    lines.append(f"Device ID:    {handle.device_ctx or '(none)'}")
    lines.append(f"Created:      {_now_utc_str(handle.created_utc)}")
    lines.append(f"KDF:          PBKDF2-HMAC-SHA512, iters={handle.kdf_iters}, dklen=32")
    lines.append("")
    lines.append("Paper Pepper:")
    lines.append(f"  {paper_pepper_note}")
    lines.append("")
    if token_checksum:
        lines.append(f"Unlock token checksum (first 8 hex of SHA-512(token)):")
        lines.append(f"  {token_checksum}")
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

# ---------- main workflow ----------
def create_vault_command_center(*,
                                mode: str,
                                hints: Optional[List[str]] = None,
                                offline_path: Optional[str] = None,
                                passphrase: str,
                                pepper: str,
                                device_id: Optional[str] = None,
                                out_vault: Optional[str] = None,
                                delete_seed_after: bool = True) -> dict:
    """
    Orchestrate: build seed (online/offline) -> init vault from seed -> export token
    -> write paper card + recovery summary -> optional secure delete of seed.

    Returns a dict with paths to outputs and basic identifiers.
    """
    # 1) Build seed (or file->seed)
    if mode.lower() == "online":
        if not hints or not any(h.strip() for h in hints):
            raise ValueError("Provide at least one non-empty hint for online mode")
        seed_bytes, audit = bsb.build_online([h for h in hints if h.strip()])
    elif mode.lower() == "offline":
        if not offline_path:
            raise ValueError("Provide offline_path for offline mode")
        seed_bytes, audit = bsb.build_offline(offline_path)
    else:
        raise ValueError("mode must be 'online' or 'offline'")

    # 2) Save seed + audit (so user can choose to review/print)
    seed_path = "book_seed.txt"
    with open(seed_path, "wb") as f:
        f.write(seed_bytes)
    audit_path = "seed_audit.json"
    with open(audit_path, "w", encoding="utf-8") as f:
        json.dump({"size_bytes": len(seed_bytes), "sources": audit}, f, indent=2)

    # 3) Init vault directly from seed
    handle = keybook.init_vault_from_book(
        book_bytes=seed_bytes,
        passphrase=passphrase,
        pepper=pepper,
        device_id=device_id,
        out_path=out_vault,
        sources=audit
    )

    # 4) Export unlock token + produce paper card
    token = keybook.export_unlock_token(handle, passphrase=passphrase, pepper=pepper)
    checksum8 = hashlib.sha512(token).hexdigest()[:8]
    card = keybook.format_unlock_token_card(
        edition_id=handle.edition_id,
        token=token,
        label="Primary vault",
        device_ctx=handle.device_ctx,
        created_utc=handle.created_utc
    )
    card_path = f"UnlockCard-{handle.edition_id}.txt"
    with open(card_path, "w", encoding="utf-8") as f:
        f.write(card)

    # 5) Recovery summary (don’t include the token itself)
    summary = make_recovery_summary(
        handle, paper_pepper_note="(written on paper; do not store digitally)", token_checksum=checksum8
    )
    summary_path = f"RecoverySummary-{handle.edition_id}.txt"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary)

    # 6) Optionally delete the seed (recommended)
    seed_deleted = False
    if delete_seed_after:
        seed_deleted = best_effort_secure_delete(seed_path)

    return {
        "edition_id": handle.edition_id,
        "vault_path": handle.path,
        "device_id": handle.device_ctx,
        "created_utc": handle.created_utc,
        "seed_path": seed_path,
        "seed_deleted": seed_deleted,
        "audit_path": audit_path,
        "unlock_card": card_path,
        "recovery_summary": summary_path,
    }

# Example programmatic use (uncomment to run interactively in Pythonista):
# result = create_vault_command_center(
#     mode="online",
#     hints=["tea", "first car", "summer 1999"],
#     passphrase="hunter2",
#     pepper="ABCDEFGHIJKLMNOPQRSTUVWX123456",
#     device_id="My-iPad",
#     out_vault="MyVault.keybook",
#     delete_seed_after=True
# )
# print(result)
