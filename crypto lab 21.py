from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16  # AES block size = 128 bits

# --- Bit padding (1-bit followed by 0 bits) ---
def bit_padding(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size  # Always add one padding block even if not needed
    # 0x80 = binary 10000000
    return data + bytes([0x80]) + bytes(pad_len - 1)

def remove_bit_padding(padded: bytes) -> bytes:
    # Remove zeros at end until 0x80 found
    i = len(padded) - 1
    while i >= 0 and padded[i] == 0x00:
        i -= 1
    if i >= 0 and padded[i] == 0x80:
        return padded[:i]
    else:
        raise ValueError("Invalid bit padding")

# --- AES Encryption/Decryption for all modes ---
def encrypt_decrypt_modes(plaintext: bytes):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    print(f"\nKey (hex): {key.hex()}")
    print(f"IV  (hex): {iv.hex()}")

    padded = bit_padding(plaintext)
    print(f"\nOriginal plaintext: {plaintext}")
    print(f"Padded plaintext: {padded.hex()} (length={len(padded)} bytes)")

    # ECB Mode
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    ct_ecb = cipher_ecb.encrypt(padded)
    pt_ecb = remove_bit_padding(cipher_ecb.decrypt(ct_ecb))
    print("\n--- ECB MODE ---")
    print("Ciphertext (hex):", ct_ecb.hex())
    print("Recovered plaintext:", pt_ecb)

    # CBC Mode
    cipher_cbc = AES.new(key, AES.MODE_CBC, iv)
    ct_cbc = cipher_cbc.encrypt(padded)
    pt_cbc = remove_bit_padding(AES.new(key, AES.MODE_CBC, iv).decrypt(ct_cbc))
    print("\n--- CBC MODE ---")
    print("Ciphertext (hex):", ct_cbc.hex())
    print("Recovered plaintext:", pt_cbc)

    # CFB Mode
    cipher_cfb = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    ct_cfb = cipher_cfb.encrypt(padded)
    pt_cfb = remove_bit_padding(AES.new(key, AES.MODE_CFB, iv, segment_size=128).decrypt(ct_cfb))
    print("\n--- CFB MODE ---")
    print("Ciphertext (hex):", ct_cfb.hex())
    print("Recovered plaintext:", pt_cfb)

# --- Example run ---
if __name__ == "__main__":
    message = b"HELLO BLOCK CIPHER DEMO"
    encrypt_decrypt_modes(message)
