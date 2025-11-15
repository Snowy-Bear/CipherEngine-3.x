import keybook

# create a new vault
handle = keybook.init_vault(
    hints=["tea", "first car", "summer 1999"],
    passphrase="hunter2",  # replace with your secret
    pepper="ABCDEFGHIJKLMNOPQRSTUVWX123456",  # 32-char paper pepper you’ve written down
    device_id="My-iPad",
    out_path="MyVault.keybook"
)
print("Created vault:", handle.edition_id)

# later, open the same vault
handle2 = keybook.open_vault(
    path="MyVault.keybook",
    passphrase="hunter2",
    pepper="ABCDEFGHIJKLMNOPQRSTUVWX123456",
    device_id="My-iPad"
)
print("Opened vault:", handle2.edition_id)

# derive a single key
k_enc = keybook.derive_key(handle2, purpose="enc", target="alice@example.com")
print("enc key (hex):", k_enc.hex())

# derive a full bundle
bundle = keybook.derive_bundle(handle2, target="projectX")
print("bundle keys:", {k: v.hex() for k, v in bundle.items() if k in ("enc","tran","hmac")})
