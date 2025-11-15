import keybook, hashlib, hmac

def check_credentials(vault_path, passphrase, pepper):
    with open(vault_path, "rb") as f:
        vb = f.read()
    hdr, off = keybook._parse_header(vb)  # public header: no secrets needed
    header = vb[:off]
    ciphertext = vb[off:off+hdr["payload_len"]]
    tag = vb[off+hdr["payload_len"]: off+hdr["payload_len"]+64]

    # Recreate the MAC key exactly as open_vault does
    material = (passphrase + "|" + pepper).encode("utf-8")
    k_wrap_base = hashlib.pbkdf2_hmac("sha512", material, hdr["salt_vault"], hdr["kdf_iters"], dklen=keybook.MASTER_LEN)
    k_mac = keybook._hkdf_sha512(k_wrap_base, b"keybook|wrap|mac", hdr["salt_vault"], keybook.HMAC_KEY_LEN)
    calc_tag = hmac.new(k_mac, header + ciphertext, hashlib.sha512).digest()

    print("Header edition:", hdr["edition_id"], "iters:", hdr["kdf_iters"], "payload_len:", hdr["payload_len"])
    print("Tag match:", hmac.compare_digest(calc_tag, tag))

# ---- use it:
check_credentials("MyVault.keybook", "old pass", "YOUR-32-CHAR-PEPPER")
