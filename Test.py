from secure_channel import ChannelContext

ctx = ChannelContext.open_and_derive(
    vault_path="MyVault.keybook",
    passphrase="Pegasus the flying horse",
    pepper="RXMJ8JACVVF9CGYLEA6G73LPTCYVWHEP",  # 32 chars
    label="dm:alice-bob:images",
    rounds=7,
)

ciphertext_b64 = ctx.encrypt_bytes(b"hello world")      # Base64 str
plaintext      = ctx.decrypt_bytes(ciphertext_b64)      # -> b"hello world"

ct = ctx.encrypt_text("hi 👋")
pt = ctx.decrypt_text(ct)

ctx.encrypt_file("photo.jpg", "photo.jpg.enc.txt", as_base64_text=True)
ctx.decrypt_file("photo.jpg.enc.txt", "photo.restored.jpg", is_b64_input=True)

# sender
with open("blob.bin", "rb") as f:
    data = f.read()
lines = list(ctx.encrypt_to_lines(data, chunk_size=64*1024))
# transmit lines...

# receiver
restored = ctx.decrypt_lines(lines)
