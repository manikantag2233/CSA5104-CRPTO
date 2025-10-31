import string
from collections import Counter

# English letter frequency (approximate percentage)
ENGLISH_FREQ = {
    'E': 12.0, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 'S': 6.3,
    'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4,
    'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5, 'V': 1.0,
    'K': 0.8, 'X': 0.2, 'J': 0.15, 'Q': 0.1, 'Z': 0.07
}

# Function to decrypt using additive cipher (Caesar cipher)
def decrypt(ciphertext, key):
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            shift = (ord(c.upper()) - ord('A') - key) % 26
            plaintext += chr(shift + ord('A'))
        else:
            plaintext += c
    return plaintext

# Function to compute similarity score between English freq & text freq
def score_text(text):
    text = [c for c in text.upper() if c.isalpha()]
    total = len(text)
    if total == 0:
        return float('inf')
    freq = Counter(text)
    chi_sq = 0
    for letter in ENGLISH_FREQ:
        observed = freq.get(letter, 0) * 100 / total
        expected = ENGLISH_FREQ[letter]
        chi_sq += ((observed - expected) ** 2) / expected
    return chi_sq

# Function to perform frequency attack
def frequency_attack(ciphertext, top_n=10):
    print("Ciphertext:", ciphertext)
    print(f"\nPerforming letter frequency attack... (Top {top_n} results)\n")

    results = []
    for key in range(26):
        plaintext = decrypt(ciphertext, key)
        score = score_text(plaintext)
        results.append((key, score, plaintext))

    # Sort results by best (lowest chi-square score)
    results.sort(key=lambda x: x[1])

    print(f"{'Rank':<5} {'Key':<5} {'Score':<10} Plaintext")
    print("-" * 70)
    for i, (key, score, plaintext) in enumerate(results[:top_n], start=1):
        print(f"{i:<5} {key:<5} {score:<10.3f} {plaintext}")

# --- Main Program ---
ciphertext = input("Enter the ciphertext: ").upper().strip()
top_n = int(input("Enter how many possible plaintexts to display (e.g. 10): "))

frequency_attack(ciphertext, top_n)
