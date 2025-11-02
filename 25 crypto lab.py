import math

# Given public key components
n = 3599       # n = p * q
e = 31         # public exponent

# Assume one plaintext block shares a common factor with n
M = 59         # Example plaintext block (has factor with n)

# Step 1: Compute gcd
g = math.gcd(M, n)

print("Common factor found (prime p):", g)

# Step 2: Compute q
if g > 1:
    p = g
    q = n // p
    print("p =", p)
    print("q =", q)

    # Step 3: Compute φ(n)
    phi_n = (p - 1) * (q - 1)

    # Step 4: Compute private key d (modular inverse)
    def mod_inverse(a, m):
        for d in range(1, m):
            if (a * d) % m == 1:
                return d
        return None

    d = mod_inverse(e, phi_n)
    print("φ(n) =", phi_n)
    print("Private key d =", d)

else:
    print("No common factor found — attack not possible.")
