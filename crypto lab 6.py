from collections import Counter
def modinv(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None
def affine_decrypt(ciphertext, a, b, m=26):
    a_inv = modinv(a, m)
    if a_inv is None:
        return None
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            y = ord(char.upper()) - ord('A')
            x = (a_inv * (y - b)) % m
            plaintext += chr(x + ord('A'))
        else:
            plaintext += char
    return plaintext
def char_to_num(c): return ord(c.upper()) - ord('A')
def num_to_char(n): return chr((n % 26) + ord('A'))
cipher_freq1, cipher_freq2 = char_to_num('B'), char_to_num('U')
plain_freq1, plain_freq2 = char_to_num('E'), char_to_num('T')
denominator = (plain_freq1 - plain_freq2) % 26
numerator = (cipher_freq1 - cipher_freq2) % 26
inv_denominator = modinv(denominator, 26)
a = (numerator * inv_denominator) % 26
b = (cipher_freq1 - a * plain_freq1) % 26
print(f"Possible keys: a={a}, b={b}")
ciphertext = "YOURCIPHERTEXTHERE"
decrypted = affine_decrypt(ciphertext, a, b)
print("Decrypted Text:", decrypted)
