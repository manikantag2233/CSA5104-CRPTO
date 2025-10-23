def generate_key_matrix(keyword):
    keyword = keyword.upper().replace("J", "I")  # Treat I and J as same
    matrix = []
    used = set()
    for char in keyword:
        if char not in used and char.isalpha():
            used.add(char)
            matrix.append(char)
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in used:
            used.add(char)
            matrix.append(char)
    key_matrix = [matrix[i:i + 5] for i in range(0, 25, 5)]
    return key_matrix
def find_position(char, key_matrix):
    for i in range(5):
        for j in range(5):
            if key_matrix[i][j] == char:
                return i, j
def encrypt_pair(a, b, key_matrix):
    r1, c1 = find_position(a, key_matrix)
    r2, c2 = find_position(b, key_matrix)

    if r1 == r2:  
        return key_matrix[r1][(c1 + 1) % 5] + key_matrix[r2][(c2 + 1) % 5]
    elif c1 == c2:  
        return key_matrix[(r1 + 1) % 5][c1] + key_matrix[(r2 + 1) % 5][c2]
    else:  
        return key_matrix[r1][c2] + key_matrix[r2][c1]
def prepare_text(plaintext):
    plaintext = plaintext.upper().replace("J", "I")
    prepared = ""
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        if not a.isalpha():
            i += 1
            continue
        if i + 1 < len(plaintext):
            b = plaintext[i + 1]
            if a == b:
                prepared += a + "X"
                i += 1
            else:
                prepared += a + b
                i += 2
        else:
            prepared += a + "X"
            i += 1
    return prepared
def playfair_encrypt(plaintext, key_matrix):
    plaintext_pairs = prepare_text(plaintext)
    ciphertext = ""
    for i in range(0, len(plaintext_pairs), 2):
        a = plaintext_pairs[i]
        b = plaintext_pairs[i + 1]
        ciphertext += encrypt_pair(a, b, key_matrix)
    return ciphertext
keyword = input("Enter the keyword: ")
plaintext = input("Enter the plaintext: ")
key_matrix = generate_key_matrix(keyword)
print("\n5x5 Key Matrix:")
for row in key_matrix:
    print(row)
ciphertext = playfair_encrypt(plaintext, key_matrix)
print("\nEncrypted Text:", ciphertext)
