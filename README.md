------------------------------------------------------------------------

        C I P H E R   E N G I N E   3 . X   S E R I E S

Cipher Engine 3.x — Educational Encryption Suite

Cipher Engine 3.x is a transparent encryption suite built for teaching,
experimentation, and museum demonstrations. It avoids black-box
cryptographic libraries in favour of clear, traceable operations.

Versions

3.5 – Traditional Obfuscation
• Multi-round transforms
• PRNG-driven offsets
• Full 94-character ASCII domain

3.6 – Authenticated Encryption
• Integrity-checked payloads
• Authenticated headers
• Replay-resistance

Keybook Password Generator

Produces strong deterministic passwords from simple user seeds to ensure
users avoid weak or repeated keys.

Usage in Other Projects

• School or University exhibits demonstrating cipher mechanics
• Cover-traffic prototypes masking message boundaries
• Secure messaging demos (Pythonista, Raspberry Pi)
• Student workshops and PRNG teaching modules

Console Display

Show this README within the program:

    python cipher_engine3x.py --about

Help & Integration Guide

Import:

    from cipher_engine3x import CipherEngine

Init:

    engine = CipherEngine(password="pw", mode="3.5")

Encrypt:

    engine.encrypt("TEXT")

Decrypt:

    engine.decrypt(ciphertext)

Command-Line:

    python cipher_engine3x.py --enc "msg"
    python cipher_engine3x.py --dec "cipher"

Cipher Pipeline Diagram

[ Input ] | v +———+ | ASCII | | Normal. | +———+ | v +——————–+ | PRNG
Round Count | +——————–+ | v +——————–+ | Symbol Transform | | (3.5 or 3.6
mode) | +——————–+ | v [ Output Ciphertext ]

Examples

Encrypt:

    engine = CipherEngine(password="alpha", mode="3.6")
    print(engine.encrypt("HELLO"))

Decrypt:

    c = "5F8@#)A..."
    print(engine.decrypt(c))

Using Keybook:

    strong = keybook.generate("tiger mountain")
    engine = CipherEngine(password=strong, mode="3.5")

Troubleshooting

• If decryption fails, confirm:
- Same password/keybook seed
- Same mode used on both sides
- Ciphertext unchanged

• If randomness seems wrong:
- Ensure Python random isn’t reseeded

• If terminal shows odd characters:
- Use an ASCII-safe terminal

FAQ

Q: Is Cipher Engine 3.x a modern secure cipher?
A: No — it is intentionally educational and transparent.

Q: Can it be used for real secure messaging?
A: Only for demonstrations; not formally audited.

Q: Why include AE in 3.6?
A: To demonstrate integrity protection in an open, visible form.

Security Note

Cipher Engine 3.x has not been peer-reviewed for hardness, and should
therefore be used with appropriate caution. However, internal testing
indicates that when used exactly as described—with strong Keybook-derived 
passwords and proper operational discipline—the system is surprisingly
robust and would be effective against even a determined hacker.
