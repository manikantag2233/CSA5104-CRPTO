from string import ascii_uppercase

def generate_cipher_alphabet(keyword: str) -> str:
    """
    Generate a 26-letter cipher alphabet from a keyword.
    Repeats in the keyword are removed and only A-Z are used.
    Returns the cipher alphabet as an uppercase string of length 26.
    """
    keyword = keyword.upper()
    seen = set()
    cipher_letters = []

    # Add unique letters from keyword in order
    for ch in keyword:
        if ch.isalpha() and ch not in seen:
            seen.add(ch)
            cipher_letters.append(ch)

    # Append remaining letters A-Z that were not in keyword
    for ch in ascii_uppercase:
        if ch not in seen:
            cipher_letters.append(ch)

    return "".join(cipher_letters)


def build_maps(cipher_alphabet: str):
    """
    Build encryption and decryption maps (dicts) for quick lookup.
    Maps preserve uppercase/lowercase automatically in encrypt/decrypt functions.
    """
    plain_alphabet = ascii_uppercase
    enc_map = {plain_alphabet[i]: cipher_alphabet[i] for i in range(26)}
    dec_map = {cipher_alphabet[i]: plain_alphabet[i] for i in range(26)}
    return enc_map, dec_map


def encrypt(plaintext: str, keyword: str) -> str:
    cipher_alpha = generate_cipher_alphabet(keyword)
    enc_map, _ = build_maps(cipher_alpha)

    result = []
    for ch in plaintext:
        if ch.isalpha():
            if ch.isupper():
                result.append(enc_map[ch])
            else:
                # map lowercase by mapping uppercase then lowercasing
                result.append(enc_map[ch.upper()].lower())
        else:
            result.append(ch)  # preserve punctuation/spaces/digits
    return "".join(result)


def decrypt(ciphertext: str, keyword: str) -> str:
    cipher_alpha = generate_cipher_alphabet(keyword)
    _, dec_map = build_maps(cipher_alpha)

    result = []
    for ch in ciphertext:
        if ch.isalpha():
            if ch.isupper():
                result.append(dec_map[ch])
            else:
                result.append(dec_map[ch.upper()].lower())
        else:
            result.append(ch)
    return "".join(result)


if __name__ == "__main__":
    # Example using the keyword 'CIPHER' as in your prompt
    keyword = "CIPHER"
    cipher_alphabet = generate_cipher_alphabet(keyword)
    enc_map, dec_map = build_maps(cipher_alphabet)

    print("Keyword:", keyword)
    print("Cipher alphabet:", cipher_alphabet)
    print("\nMapping (plaintext -> cipher):")
    for p, c in zip(ascii_uppercase, cipher_alphabet):
        print(f"{p} -> {c}", end="  ")
    print("\n\nSample usage:")

    sample_plain = "Attack at dawn! Meet at 06:00."
    encrypted = encrypt(sample_plain, keyword)
    decrypted = decrypt(encrypted, keyword)

    print("Plaintext: ", sample_plain)
    print("Encrypted: ", encrypted)
    print("Decrypted: ", decrypted)
