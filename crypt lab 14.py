import random
import string

# Function to generate a random key stream of the same length as plaintext
def generate_key(length):
    return [random.randint(0, 25) for _ in range(length)]

# Function to encrypt plaintext using one-time pad (Vigenère style)
def encrypt_otp(plaintext, key):
    plaintext = plaintext.upper().replace(" ", "")
    ciphertext = ""
    for i in range(len(plaintext)):
        p = ord(plaintext[i]) - ord('A')
        c = (p + key[i]) % 26
        ciphertext += chr(c + ord('A'))
    return ciphertext

# Function to decrypt ciphertext using the same key
def decrypt_otp(ciphertext, key):
    plaintext = ""
    for i in range(len(ciphertext)):
        c = ord(ciphertext[i]) - ord('A')
        p = (c - key[i]) % 26
        plaintext += chr(p + ord('A'))
    return plaintext

# --- Main program ---
plaintext = "HELLO THIS IS A SECRET MESSAGE"

# Generate a random key stream
key = generate_key(len(plaintext.replace(" ", "")))

print("Plaintext:", plaintext)
print("Random key stream:", key)

# Encrypt
ciphertext = encrypt_otp(plaintext, key)
print("Ciphertext:", ciphertext)

# Decrypt
decrypted = decrypt_otp(ciphertext, key)
print("Decrypted Plaintext:", decrypted)
