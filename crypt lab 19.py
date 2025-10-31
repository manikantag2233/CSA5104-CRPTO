#!/usr/bin/env python3
"""
CBC-mode encryption/decryption using 3DES (Triple DES) with PKCS#7 padding.
Requires: pycryptodome (pip install pycryptodome)

Features:
 - 3DES (DES3) key length: 16 or 24 bytes (this code uses 24 bytes for full 3-key 3DES)
 - Random IV (8 bytes for DES block size)
 - PKCS#7 padding to block size (8 bytes for DES)
 - Hex input/output for ciphertext/IV
 - Example usage at bottom
"""

import os
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from typing import Tuple

BLOCK_SIZE = 8  # DES / 3DES block size in bytes

# ---- Padding (PKCS#7 for block size 8) ----
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if len(padded) == 0 or len(padded) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding byte")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return padded[:-pad_len]

# ---- Key helpers ----
def generate_3des_key(triple_key: bool = True) -> bytes:
    """
    Generate a 3DES key.
      - If triple_key True -> create a 24-byte key (K1,K2,K3) (full 3DES).
      - If triple_key False -> create a 16-byte key (K1,K2) (K3 = K1) - 2-key 3DES.
    """
    if triple_key:
        return DES3.adjust_key_parity(get_random_bytes(24))
    else:
        return DES3.adjust_key_parity(get_random_bytes(16))

def validate_3des_key(key: bytes) -> bytes:
    """
    Ensure the key has correct parity bits for DES3. DES3.adjust_key_parity does this.
    Pass the returned key to DES3.new().
    """
    return DES3.adjust_key_parity(key)

# ---- CBC Encrypt / Decrypt ----
def encrypt_3des_cbc(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext using 3DES/CBC.
    Returns: (iv, ciphertext)
    """
    key = validate_3des_key(key)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    ct = cipher.encrypt(padded)
    return iv, ct

def decrypt_3des_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using 3DES/CBC and return the plaintext (unpadded).
    Raises ValueError on bad padding or key/iv length errors.
    """
    key = validate_3des_key(key)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded, BLOCK_SIZE)

# ---- Simple CLI example ----
if __name__ == "__main__":
    # Example plaintext
    plaintext = b"Attack at dawn! Meet on the river bank at midnight."

    # Generate a 24-byte 3DES key (K1,K2,K3) - full 3-key 3DES
    key = generate_3des_key(triple_key=True)
    print("3DES key (hex):", key.hex())

    # Encrypt
    iv, ciphertext = encrypt_3des_cbc(key, plaintext)
    print("IV (hex):", iv.hex())
    print("Ciphertext (hex):", ciphertext.hex())

    # Decrypt (example)
    recovered = decrypt_3des_cbc(key, iv, ciphertext)
    print("Recovered plaintext:", recovered.decode('utf-8'))

    # Example: show that wrong key fails to produce original plaintext (will raise padding error likely)
    try:
        wrong_key = generate_3des_key(triple_key=True)
        _ = decrypt_3des_cbc(wrong_key, iv, ciphertext)
        print("Decryption with wrong key unexpectedly succeeded")
    except Exception as e:
        print("Decryption with wrong key failed as expected:", str(e))
