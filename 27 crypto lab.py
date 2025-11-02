# rsa_letter_attack.py
# Demonstration: encrypt letters 0..25 separately with RSA and how attacker recovers them.

from math import isclose
from sympy import nextprime  # only for demo key generation (optional)
import math

# --- Helper functions ---

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        return None
    return x % m

def int_nth_root(k, n):
    """Return floor(n**(1/k)) and a boolean whether it's exact."""
    lo, hi = 0, int(n**(1.0/k)) + 2
    while lo < hi:
        mid = (lo + hi) // 2
        p = pow(mid, k)
        if p < n:
            lo = mid + 1
        else:
            hi = mid
    root = lo - 1
    return root, pow(root, k) == n

# --- Demo: generate a small RSA key (for demonstration only) ---
# In real use you'd have large primes. We pick small ones so demonstration is easy.
p = 61
q = 53
n = p * q         # 3233
phi = (p - 1) * (q - 1)
e = 17            # common small public exponent
d = modinv(e, phi)

print("Demo RSA key:")
print("  p =", p, "q =", q)
print("  n =", n)
print("  e =", e, "d =", d)
print()

# --- Plaintext encoding: letters A->0 ... Z->25 ---
def encode_letter(ch):
    ch = ch.upper()
    return ord(ch) - ord('A')

def decode_number(m):
    return chr(ord('A') + m)

# Example plaintext (letters only)
plaintext = "HELLO"
numbers = [encode_letter(c) for c in plaintext]
print("Plaintext:", plaintext)
print("Numbers:", numbers)

# Encrypt each number separately: c = m^e mod n
cipher_blocks = [pow(m, e, n) for m in numbers]
print("Cipher blocks:", cipher_blocks)
print()

# --- ATTACK 1: Brute-force lookup (precompute all 26 encryptions) ---
lookup = { pow(m, e, n): m for m in range(26) }  # attacker builds this
recovered = []
for c in cipher_blocks:
    m = lookup.get(c, None)
    if m is None:
        recovered.append('?')  # unknown
    else:
        recovered.append(decode_number(m))

print("Attacker brute-force lookup recovered:", ''.join(recovered))

# --- ATTACK 2: Small-exponent root attack (if applicable) ---
# If c == m^e (integer) i.e. m^e < n, attacker can take integer e-th root.
recovered_by_root = []
root_attack_possible = True
for c in cipher_blocks:
    root, exact = int_nth_root(e, c)
    if exact and 0 <= root <= 25:
        recovered_by_root.append(decode_number(root))
    else:
        root_attack_possible = False
        recovered_by_root.append('?')

print("Attacker small-exponent root attack recovered (if exact):", ''.join(recovered_by_root))
print("Small-exponent root attack fully possible?" , root_attack_possible)
print()

# --- Notes for the demo key ---
# For our demo n=3233 and e=17, m^17 is already much larger than n for m>=1,
# so the root attack isn't applicable here. But for small e like e=3 and small n it can be.

# --- Conclusion (programmatic) ---
print("Conclusion:")
print(" - Because there are only 26 possible plaintext values, attacker can precompute the 26 ciphertexts")
print("   and invert the mapping in constant time. This completely breaks confidentiality.")
print(" - Also if e is small and m^e < n, attacker can directly take integer e-th root of ciphertext to get m.")
print(" - Use randomized padding (RSA-OAEP) or hybrid encryption instead to secure messages.")
