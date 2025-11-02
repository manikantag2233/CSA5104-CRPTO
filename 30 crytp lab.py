# cbc_mac_forgery_demo.py
# Demonstrates: If T = CBC-MAC_K(X) for one-block X, then
# CBC-MAC_K(X || (X XOR T)) == T (for raw CBC-MAC with zero IV).

import os
from hashlib import sha256

BLOCK_SIZE = 16

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# Try to use AES (PyCryptodome). If unavailable, use a toy XOR "block cipher".
try:
    from Crypto.Cipher import AES
    AES_AVAILABLE = True
except Exception:
    AES_AVAILABLE = False

def encrypt_block(key: bytes, block: bytes) -> bytes:
    if AES_AVAILABLE:
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(block)
    else:
        # Toy (insecure) block cipher: XOR block with key (both 16 bytes)
        return xor_bytes(block, key)

def cbc_mac(key: bytes, message: bytes) -> bytes:
    """Compute CBC-MAC with zero IV. Message length must be multiple of BLOCK_SIZE."""
    if len(message) % BLOCK_SIZE != 0:
        raise ValueError("Message must be a multiple of block size for this demo (no padding).")
    chaining = bytes(BLOCK_SIZE)  # IV = 0^block
    for i in range(0, len(message), BLOCK_SIZE):
        block = message[i:i+BLOCK_SIZE]
        chained = xor_bytes(block, chaining)
        chaining = encrypt_block(key, chained)
    return chaining  # tag (last cipher-block)

def main():
    key = os.urandom(BLOCK_SIZE)   # symmetric key for CBC-MAC (block-cipher key)
    X = os.urandom(BLOCK_SIZE)     # one-block message X
    T = cbc_mac(key, X)            # T = MAC(K, X)

    # Construct forged two-block message: X || (X XOR T)
    second_block = xor_bytes(X, T)
    forged_msg = X + second_block
    T_forged = cbc_mac(key, forged_msg)

    print("AES available:", AES_AVAILABLE)
    print("Key:", key.hex())
    print("One-block message X:", X.hex())
    print("Tag T = CBC-MAC(K, X):", T.hex())
    print()
    print("Second block (X XOR T):", second_block.hex())
    print("Two-block message X || (X ⊕ T):", forged_msg.hex())
    print("Tag for two-block message (CBC-MAC):", T_forged.hex())
    print()
    if T_forged == T:
        print("SUCCESS: CBC-MAC(K, X) == CBC-MAC(K, X || (X ⊕ T)) — forgery works.")
    else:
        print("FAIL: Tags differ (unexpected under this construction).")

if __name__ == "__main__":
    main()
