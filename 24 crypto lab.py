# RSA Private Key Calculation
def gcd_extended(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = gcd_extended(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# Given values
e = 31
n = 3599

# Step 1: Find p and q (manually found)
p = 59
q = 61

# Step 2: Compute φ(n)
phi_n = (p - 1) * (q - 1)

# Step 3: Compute multiplicative inverse of e mod φ(n)
gcd, x, y = gcd_extended(e, phi_n)

# Step 4: Make x positive
d = x % phi_n

print("p =", p)
print("q =", q)
print("φ(n) =", phi_n)
print("Private Key d =", d)
