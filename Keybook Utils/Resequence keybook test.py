import keybook

# Open your existing vault (ED1-...)
h = keybook.open_vault(
    path="MyVault.keybook",
    passphrase="old pass",
    pepper="YOUR-32-CHAR-PEPPER",
    device_id="My-iPad"
)

# Make a new edition with fresh hints (optional) and/or new KDF iters
h2 = keybook.resequence_vault(
    handle=h,
    passphrase="old pass",
    pepper="YOUR-32-CHAR-PEPPER",
    new_hints=["oolong", "japanese tea ceremony", "first job"],  # or [] to reuse policy-only
    policy={"pbkdf2_iters": 900_000},  # optional override
    device_id="My-iPad",               # keep same binding (or change it)
    # out_path="ED2-XXXX.keybook",     # optional custom filename
)

print("New edition:", h2.edition_id, "bound to:", h2.device_ctx)

# Derive keys from the new edition
bundle = keybook.derive_bundle(h2, target="projectX")
print("enc key (hex):", bundle["enc"].hex())
