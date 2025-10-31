from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import copy

BLOCK_SIZE = 16  # AES block size

def show_blocks(label, data):
    print(f"\n{label}:")
    for i in range(0, len(data), BLOCK_SIZE):
        print(f"Block {i//BLOCK_SIZE + 1}: {data[i:i+BLOCK_SIZE].hex()}")

# --- ECB Mode Demo ---
def ecb_demo():
    print("\n===== ECB MODE DEMO =====")
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b"The quick brown fox jumps over the lazy dog!"
    padded = pad(plaintext, BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)
    show_blocks("Original Ciphertext", ciphertext)

    # Introduce a 1-bit error in ciphertext block 2
    corrupted = bytearray(ciphertext)
    corrupted[BLOCK_SIZE + 2] ^= 0x01  # flip one bit
    show_blocks("Corrupted Ciphertext", bytes(corrupted))

    # Decrypt both
    dec_original = unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), BLOCK_SIZE)
    dec_corrupted = AES.new(key, AES.MODE_ECB).decrypt(bytes(corrupted))

    print("\nDecrypted (with error):")
    print(dec_corrupted)

# --- CBC Mode Demo ---
def cbc_demo():
    print("\n===== CBC MODE DEMO =====")
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = b"The quick brown fox jumps over the lazy dog!"
    padded = pad(plaintext, BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)
    show_blocks("Original Ciphertext", ciphertext)

    # Introduce 1-bit error in ciphertext block 1
    corrupted = bytearray(ciphertext)
    corrupted[2] ^= 0x01  # flip one bit in block 1
    show_blocks("Corrupted Ciphertext", bytes(corrupted))

    # Decrypt both
    dec_cipher = AES.new(key, AES.MODE_CBC, iv)
    dec_corrupted = dec_cipher.decrypt(bytes(corrupted))

    print("\nDecrypted (with error):")
    print(dec_corrupted)

if __name__ == "__main__":
    ecb_demo()
    cbc_demo()
