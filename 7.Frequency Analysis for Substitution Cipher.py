# Simple Substitution Cipher - Frequency Analysis Attack

from collections import Counter

# Given ciphertext
cipher_text = """53‡‡†305))6*;4826)4‡.)4‡);806*;48†8¶60))85;;]8*;:‡*8†83
(88)5*†;46(;88*96*?;8)*‡(;485);5*†2:*‡(;4956*2(5*—4)8¶8*
;4069285);)6†8)4‡‡;1(‡9;48081;8:8‡1;48†85;4)485†528806*81
(‡9;48;(88;4(‡?34;48)4‡;161;:188;‡?;"""

# Step 1: Count frequency of each character
frequency = Counter(cipher_text)

print("Character Frequency:")
for char, freq in frequency.most_common():
    print(f"{repr(char)} : {freq}")

# Step 2: Common English letters by frequency
english_freq = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

print("\nMost common English letters (for reference):")
print(english_freq)

# Step 3: Optional – You can replace symbols manually based on pattern observation
# Example (partial mapping for demo):
mapping = {
    '‡': 'T',
    '†': 'H',
    ')': 'E',
    '*': 'A',
    ';': 'R',
    '8': 'O',
    '4': 'N',
    '5': 'I',
    '6': 'S',
    '3': 'D',
}

# Step 4: Replace using the mapping
decrypted_text = ""
for ch in cipher_text:
    if ch in mapping:
        decrypted_text += mapping[ch]
    else:
        decrypted_text += ch  # keep same if not in mapping

print("\nDecrypted (partial guess):")
print(decrypted_text)
