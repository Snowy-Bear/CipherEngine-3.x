import keybook

# 0) Pick EASY test secrets to eliminate typos for this run
PASS = "pass1234"
PEPPER = "ABCDabcd1234ABCDabcd1234ABCDab"   # 32 chars, keep simple for the test
DEVICE = "My-iPad"

# 1) Create a brand new test vault with a fixed filename
h = keybook.init_vault(
    hints=["tea","first car","summer 1999"],
    passphrase=PASS,
    pepper=PEPPER,
    device_id=DEVICE,
    out_path="TestVault.keybook",
    policy={"pbkdf2_iters": 800_000}
)
print("Created:", h.path, h.edition_id)

# 2) Verify credentials against the file (should be True)
# (Uses the same logic as open_vault to compute the tag)
from keybook import _parse_header, _hkdf_sha512, MASTER_LEN, HMAC_KEY_LEN
import hashlib, hmac

with open("TestVault.keybook","rb") as f:
    vb = f.read()
hdr, off = _parse_header(vb)
header = vb[:off]
ciphertext = vb[off:off+hdr["payload_len"]]
tag = vb[off+hdr["payload_len"]:off+hdr["payload_len"]+64]
material = (PASS + "|" + PEPPER).encode("utf-8")
k_wrap_base = hashlib.pbkdf2_hmac("sha512", material, hdr["salt_vault"], hdr["kdf_iters"], dklen=MASTER_LEN)
k_mac = _hkdf_sha512(k_wrap_base, b"keybook|wrap|mac", hdr["salt_vault"], HMAC_KEY_LEN)
print("Tag match (fresh):", hmac.compare_digest(hmac.new(k_mac, header + ciphertext, hashlib.sha512).digest(), tag))

# 3) Open the vault normally (should succeed)
h2 = keybook.open_vault("TestVault.keybook", passphrase=PASS, pepper=PEPPER, device_id=DEVICE)
print("Opened:", h2.edition_id)

# 4) Resequence to a new edition and print the new filename
h3 = keybook.resequence_vault(h2, passphrase=PASS, pepper=PEPPER,
                              new_hints=["oolong","first job"], device_id=DEVICE)
print("Resequenced:", h3.edition_id, "->", h3.path)
