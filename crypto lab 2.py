import string
import random
def generate_key():
    letters = list(string.ascii_lowercase)
    shuffled = letters.copy()
    random.shuffle(shuffled)
    return dict(zip(letters, shuffled))
def encrypt(plaintext, key):
    ciphertext = ""
    for char in plaintext.lower():
        if char in key:
            ciphertext += key[char]
        else:
            ciphertext += char  
    return ciphertext
def decrypt(ciphertext, key):
    reversed_key = {v: k for k, v in key.items()}
    plaintext = ""
    for char in ciphertext:
        if char in reversed_key:
            plaintext += reversed_key[char]
        else:
            plaintext += char
    return plaintext
plaintext = input("Enter the plaintext: ")
key = generate_key()
print("\nGenerated Cipher Key:")
for p, c in key.items():
    print(f"{p} → {c}")
ciphertext = encrypt(plaintext, key)
print("\nEncrypted text:", ciphertext)
decrypted = decrypt(ciphertext, key)
print("Decrypted text:", decrypted)
