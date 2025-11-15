import keybook   # <-- this loads keybook.py sitting in the same folder

handle2 = keybook.open_vault(
    path="MyVault.keybook",
    passphrase="hunter2",
    pepper="ABCDEFGHIJKLMNOPQRSTUVWX123456",
    device_id="My-iPad"
)

# now you can run the checks
k1 = keybook.derive_key(handle2, "enc", "alice@example.com")
k2 = keybook.derive_key(handle2, "enc", "alice@example.com")
assert k1 == k2

k3 = keybook.derive_key(handle2, "enc", "bob@example.com")
assert k1 != k3

t1 = keybook.derive_key(handle2, "tran", "alice@example.com")
assert k1 != t1
