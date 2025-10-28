def caesar_cipher(text, k):
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) + k - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + k - 97) % 26 + 97)
        else:
            result += char
    return result
text = input("Enter the text to encrypt: ")
k = int(input("Enter the key (1-25): "))
if 1 <= k <= 25:
    encrypted_text = caesar_cipher(text, k)
    print("Encrypted text:", encrypted_text)
else:
    print("Key must be between 1 and 25.")

