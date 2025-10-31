# Simplified DES (S-DES) with CBC mode encryption/decryption
# Given: IV = 10101010, Key = 0111111101, Plaintext = 0000000100100011
# Expected Ciphertext = 1111010000001011

def permute(bits, pattern):
    return ''.join(bits[i - 1] for i in pattern)

def left_shift(bits, n):
    return bits[n:] + bits[:n]

# --- Key Generation ---
def generate_keys(key):
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8  = [6, 3, 7, 4, 8, 5, 10, 9]
    
    key = permute(key, P10)
    left, right = key[:5], key[5:]
    
    # 1-bit shift
    left1, right1 = left_shift(left, 1), left_shift(right, 1)
    K1 = permute(left1 + right1, P8)
    
    # 2-bit shift
    left2, right2 = left_shift(left1, 2), left_shift(right1, 2)
    K2 = permute(left2 + right2, P8)
    
    return K1, K2

# --- S-DES Functions ---
def fk(bits, key):
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ]
    S1 = [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
    ]
    P4 = [2, 4, 3, 1]
    left, right = bits[:4], bits[4:]
    temp = permute(right, EP)
    xored = ''.join(str(int(a) ^ int(b)) for a, b in zip(temp, key))
    left4, right4 = xored[:4], xored[4:]
    row0 = int(left4[0] + left4[3], 2)
    col0 = int(left4[1:3], 2)
    row1 = int(right4[0] + right4[3], 2)
    col1 = int(right4[1:3], 2)
    s0_val = format(S0[row0][col0], '02b')
    s1_val = format(S1[row1][col1], '02b')
    s_output = permute(s0_val + s1_val, P4)
    result = ''.join(str(int(a) ^ int(b)) for a, b in zip(left, s_output))
    return result + right

def switch(bits):
    return bits[4:] + bits[:4]

# --- Encrypt / Decrypt One Block ---
def sdes_encrypt_block(block, K1, K2):
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    bits = permute(block, IP)
    temp = fk(bits, K1)
    temp = switch(temp)
    temp = fk(temp, K2)
    return permute(temp, IP_inv)

def sdes_decrypt_block(block, K1, K2):
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    bits = permute(block, IP)
    temp = fk(bits, K2)
    temp = switch(temp)
    temp = fk(temp, K1)
    return permute(temp, IP_inv)

# --- CBC MODE ---
def xor_bits(a, b):
    return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))

def cbc_encrypt(plaintext, key, iv):
    K1, K2 = generate_keys(key)
    blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
    prev = iv
    ciphertext = ''
    for block in blocks:
        xored = xor_bits(block, prev)
        c = sdes_encrypt_block(xored, K1, K2)
        ciphertext += c
        prev = c
    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    K1, K2 = generate_keys(key)
    blocks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
    prev = iv
    plaintext = ''
    for block in blocks:
        d = sdes_decrypt_block(block, K1, K2)
        p = xor_bits(d, prev)
        plaintext += p
        prev = block
    return plaintext

# --- TEST CASE ---
if __name__ == "__main__":
    IV = "10101010"
    KEY = "0111111101"
    PLAINTEXT = "0000000100100011"
    EXPECTED_CT = "1111010000001011"

    print("IV:", IV)
    print("Key:", KEY)
    print("Plaintext:", PLAINTEXT)

    ct = cbc_encrypt(PLAINTEXT, KEY, IV)
    print("\nCiphertext:", ct)
    print("Expected  :", EXPECTED_CT)

    pt = cbc_decrypt(ct, KEY, IV)
    print("\nDecrypted plaintext:", pt)
