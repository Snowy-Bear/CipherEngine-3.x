import keybook

# 1) Open your vault (adjust names/secrets)
h = keybook.open_vault(
    path="MyVault.keybook",
    passphrase="hunter2",
    pepper="ABCDEFGHIJKLMNOPQRSTUVWX123456",
    device_id="My-iPad"
)

# 2) Export the unlock token
tok = keybook.export_unlock_token(h, passphrase="hunter2", pepper="ABCDEFGHIJKLMNOPQRSTUVWX123456")

# 3) Format a paper card (string)
card = keybook.format_unlock_token_card(
    edition_id=h.edition_id,
    token=tok,
    label="Home vault",
    device_ctx=h.device_ctx,
    created_utc=h.created_utc
)
print(card)  # just to see it

# 4) Parse the card back and verify
tok2 = keybook.parse_unlock_token_card(card)
assert tok2 == tok, "Token parsed from card does NOT match the original!"
print("Round-trip worked ✅")
