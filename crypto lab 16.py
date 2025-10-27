from collections import Counter
import itertools
ENGLISH_FREQ = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
def get_freq_table(text):
    text = [c for c in text.upper() if c.isalpha()]
    freq = Counter(text)
    freq_lst = [x[0] for x in freq.most_common()]
    return freq_lst
def freq_attack(ciphertext, top_n=10):
    ciphertext = ciphertext.upper()
    cipher_freq = get_freq_table(ciphertext)
    length = len(cipher_freq)
    num_permutations = min(top_n, 720)  # 6! = 720
    results = []
    K = min(6, length)
    cipher_top = cipher_freq[:K]
    plain_top = ENGLISH_FREQ[:K]
    for perm in itertools.islice(itertools.permutations(plain_top, K), num_permutations):
        mapping = dict(zip(cipher_top, perm))
        result = ''
        for char in ciphertext:
            if char in mapping:
                result += mapping[char]
            else:
                result += char
        results.append(result)
    print(f"Top {min(top_n, len(results))} probable plaintexts:")
    for i, candidate in enumerate(results[:top_n]):
        print(f"{i+1}: {candidate}")
if __name__ == "__main__":
    print("Enter ciphertext (letters, spaces, punctuation allowed):")
    ciphertext = input()
    print("How many top plaintexts do you want to see (e.g. 10)?")
    top_n = int(input())
    freq_attack(ciphertext, top_n)
