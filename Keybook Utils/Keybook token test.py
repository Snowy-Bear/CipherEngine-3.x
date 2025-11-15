import keybook

# --- Export an unlock token (on the original device) ---
h = keybook.open_vault("MyVault.keybook", passphrase="hunter2",
                       pepper="ABCDEFGHIJKLMNOPQRSTUVWX123456", device_id="My-iPad")
tok = keybook.export_unlock_token(h, passphrase="hunter2", pepper="ABCDEFGHIJKLMNOPQRSTUVWX123456")
print("Unlock token (base64):", tok.hex())  # or base64 if you prefer

# (Store tok somewhere safe! Treat it like a master key.)

# --- Import onto a new device (or just rewrap for this one) ---
h2 = keybook.import_vault("ED1-RI76WNYS.keybook", passphrase="hunter2",
                          pepper="ABCDEFGHIJKLMNOPQRSTUVWX123456",
                          unlock_token=tok, device_id="My-New-iPad",
                          out_path="ED1-RI76WNYS.keybook")  # overwrite in place (or pick a new filename)

print("Rewrapped vault bound to:", h2.device_ctx)

# --- Resequence to a new edition (ED2-...) ---
h3 = keybook.resequence_vault(h2, passphrase="hunter2",
                              pepper="ABCDEFGHIJKLMNOPQRSTUVWX123456",
                              new_hints=["oolong", "japanese tea ceremony", "first job"],
                              device_id="My-New-iPad")
print("New edition:", h3.edition_id)

# Derive keys from the new edition
bundle = keybook.derive_bundle(h3, target="projectX")
print("New enc key:", bundle["enc"].hex())
