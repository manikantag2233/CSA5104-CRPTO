import math

# --- Step 1: Original RSA Key Generation ---
p = 59
q = 61
n = p * q
phi_n = (p - 1) * (q - 1)

e = 31  # Public exponent
# Compute private key d (modular inverse)
def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

d = mod_inverse(e, phi_n)

print("Original Keys:")
print(f"Public key (e, n) = ({e}, {n})")
print(f"Private key (d, n) = ({d}, {n})\n")

# --- Step 2: Suppose Bob's private key leaks ---
print("Bob's private key leaked! Attacker can compute φ(n)...")
k_phi = e * d - 1
print("Value of e*d - 1 =", k_phi)

# --- Step 3: Attacker can find φ(n) and factor n ---
# Since k_phi = k * φ(n), we can test small k to recover φ(n)
for k in range(1, 50):
    if k_phi % k == 0:
        possible_phi = k_phi // k
        if possible_phi == phi_n:
            print("φ(n) recovered by attacker:", possible_phi)
            break

# --- Step 4: Bob generates new e2, d2 using same n ---
e2 = 37
d2 = mod_inverse(e2, phi_n)
print("\nBob tries new public and private keys:")
print(f"New public key (e2, n) = ({e2}, {n})")
print(f"New private key (d2, n) = ({d2}, {n})")

print("\n⚠️ Not safe: Once φ(n) is known, attacker can compute any new private key d2.")
