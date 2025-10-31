# Hill cipher encryption & decryption with step-by-step calculations
import re, string

alpha = string.ascii_uppercase

# Key matrix
K = [[9,4],[5,7]]

# Determinant and modular inverse helper
def modinv(a, m):
    a = a % m
    t0, t1 = 0, 1
    r0, r1 = m, a
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        return None
    return t0 % m

# 1) determinant
det = K[0][0]*K[1][1] - K[0][1]*K[1][0]
det_mod26 = det % 26
det_inv = modinv(det_mod26, 26)

# 2) adjugate and inverse
adj = [[K[1][1], -K[0][1]], [-K[1][0], K[0][0]]]
Kinv = [[(det_inv * adj[i][j]) % 26 for j in range(2)] for i in range(2)]

print("Hill cipher key K =", K)
print("\n1) Determinant calculation:")
print("   det = 9*7 - 4*5 = {} -> det mod 26 = {}".format(det, det_mod26))
print("2) modular inverse of det mod 26 =", det_inv)
print("3) adjugate =", adj)
print("4) inverse K^{-1} (mod 26) =", Kinv)
print("Verification K * Kinv mod26 =", [
    [(K[0][0]*Kinv[0][0] + K[0][1]*Kinv[1][0]) % 26, (K[0][0]*Kinv[0][1] + K[0][1]*Kinv[1][1]) % 26],
    [(K[1][0]*Kinv[0][0] + K[1][1]*Kinv[1][0]) % 26, (K[1][0]*Kinv[0][1] + K[1][1]*Kinv[1][1]) % 26]
])

# Plaintext and preprocessing
plaintext = "meet me at the usual place at ten rather than eight oclock"
letters = re.sub('[^A-Za-z]','', plaintext).upper()
print("\nPlaintext (letters only):", letters)
if len(letters) % 2 == 1:
    letters_padded = letters + 'X'
else:
    letters_padded = letters
print("Prepared (padded if needed):", letters_padded)

# split into digraphs
pairs = [letters_padded[i:i+2] for i in range(0, len(letters_padded), 2)]
print("\nDigraphs:", pairs)

# helpers
def l2n(ch): return alpha.index(ch)
def n2l(n): return alpha[n % 26]

# Encryption
cipher_pairs = []
print("\nEncryption steps (for each pair):")
for pair in pairs:
    p0, p1 = l2n(pair[0]), l2n(pair[1])
    c0 = (K[0][0]*p0 + K[0][1]*p1) % 26
    c1 = (K[1][0]*p0 + K[1][1]*p1) % 26
    cipher_pairs.append(n2l(c0) + n2l(c1))
    print(f" {pair} -> P=[{p0},{p1}] -> c0=9*{p0}+4*{p1}={9*p0+4*p1} ≡ {c0} -> '{n2l(c0)}', "
          f"c1=5*{p0}+7*{p1}={5*p0+7*p1} ≡ {c1} -> '{n2l(c1)}'")

ciphertext = ''.join(cipher_pairs)
print("\nComplete ciphertext:", ciphertext)

# Decryption
print("\nDecryption steps (apply K^{-1} to each cipher pair):")
dec_pairs = []
for cp in cipher_pairs:
    c0, c1 = l2n(cp[0]), l2n(cp[1])
    p0 = (Kinv[0][0]*c0 + Kinv[0][1]*c1) % 26
    p1 = (Kinv[1][0]*c0 + Kinv[1][1]*c1) % 26
    dec_pairs.append(n2l(p0) + n2l(p1))
    print(f" {cp} -> C=[{c0},{c1}] -> p0={Kinv[0][0]}*{c0}+{Kinv[0][1]}*{c1} = {Kinv[0][0]*c0 + Kinv[0][1]*c1} ≡ {p0} -> '{n2l(p0)}', "
          f"p1={Kinv[1][0]}*{c0}+{Kinv[1][1]}*{c1} = {Kinv[1][0]*c0 + Kinv[1][1]*c1} ≡ {p1} -> '{n2l(p1)}'")

recovered = ''.join(dec_pairs)
print("\nRecovered plaintext (with padding):", recovered)
print("Matches prepared plaintext:", recovered == letters_padded)
