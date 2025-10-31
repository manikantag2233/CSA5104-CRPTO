import numpy as np

# Convert letter to number (A=0,...,Z=25)
def char_to_num(c):
    return ord(c.upper()) - ord('A')

# Convert number to letter
def num_to_char(n):
    return chr((n % 26) + ord('A'))

# Convert string to numeric vector
def text_to_matrix(text, size):
    text = text.upper().replace(" ", "")
    nums = [char_to_num(c) for c in text]
    # Split into blocks of given size
    return np.array(nums).reshape(size, size)

# Modular inverse of a matrix (mod 26)
def mod_inverse_matrix(matrix, mod=26):
    det = int(round(np.linalg.det(matrix))) % mod
    det_inv = pow(det, -1, mod)
    matrix_mod_inv = det_inv * np.round(det * np.linalg.inv(matrix)).astype(int)
    return np.mod(matrix_mod_inv, mod)

# Known plaintext attack function
def known_plaintext_attack(plaintext, ciphertext, block_size=2):
    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext)

    # Step 1: Convert plaintext and ciphertext into matrices
    P = text_to_matrix(plaintext, block_size)
    C = text_to_matrix(ciphertext, block_size)

    print("\nPlaintext matrix (P):\n", P)
    print("\nCiphertext matrix (C):\n", C)

    # Step 2: Compute P inverse mod 26
    P_inv = mod_inverse_matrix(P, 26)
    print("\nInverse of P (mod 26):\n", P_inv)

    # Step 3: Compute key matrix
    K = np.mod(np.dot(C, P_inv), 26)
    print("\nRecovered Key matrix (K = C × P⁻¹ mod 26):\n", K)

    return K

# Example Known Plaintext & Ciphertext
plaintext = "HELP"
ciphertext = "ZEBB"   # Example ciphertext from encryption using unknown key

key = known_plaintext_attack(plaintext, ciphertext, block_size=2)
