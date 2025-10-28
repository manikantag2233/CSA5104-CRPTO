# Affine Caesar Cipher Program

import math

# Function to encrypt plaintext
def affine_encrypt(text, a, b):
    result = ""
    for char in text.upper():
        if char.isalpha():
            p = ord(char) - 65  # Convert to 0–25
            c = (a * p + b) % 26
            result += chr(c + 65)
        else:
            result += char
    return result

# Function to find modular inverse of a mod 26
def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_decrypt(cipher, a, b):
    result = ""
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return "Invalid key: 'a' has no modular inverse (not coprime with 26)"
    
    for char in cipher.upper():
        if char.isalpha():
            c = ord(char) - 65
            p = (a_inv * (c - b)) % 26
            result += chr(p + 65)
        else:
            result += char
    return result


# --- Example usage ---
plaintext = "HELLO"
a = 5
b = 8

print("Plaintext:", plaintext)
cipher = affine_encrypt(plaintext, a, b)
print("Encrypted:", cipher)
decrypted = affine_decrypt(cipher, a, b)
print("Decrypted:", decrypted)
