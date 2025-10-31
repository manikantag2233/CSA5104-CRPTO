# Playfair Cipher Encryption with custom matrix
# Given key square:
# M F H I/J K
# U N O P Q
# Z V W X Y
# E L A R G
# D S T B C

def generate_fixed_square():
    """Create the given fixed Playfair 5x5 matrix."""
    square = [
        ['M', 'F', 'H', 'I', 'K'],
        ['U', 'N', 'O', 'P', 'Q'],
        ['Z', 'V', 'W', 'X', 'Y'],
        ['E', 'L', 'A', 'R', 'G'],
        ['D', 'S', 'T', 'B', 'C']
    ]
    return square


def find_position(square, letter):
    """Find row and column of a letter in the square."""
    if letter == 'J':  # I and J are the same
        letter = 'I'
    for i in range(5):
        for j in range(5):
            if square[i][j] == letter:
                return i, j
    return None, None


def prepare_text(text):
    """Prepare plaintext: remove non-letters, handle pairs, add filler if needed."""
    text = text.upper()
    text = ''.join([ch for ch in text if ch.isalpha()])  # keep only letters
    text = text.replace('J', 'I')  # replace J with I

    prepared = ""
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else 'X'

        if a == b:  # same letter pair -> insert X
            prepared += a + 'X'
            i += 1
        else:
            prepared += a + b
            i += 2

    if len(prepared) % 2 != 0:
        prepared += 'X'

    return prepared


def encrypt_pair(a, b, square):
    """Encrypt a single pair using Playfair rules."""
    row1, col1 = find_position(square, a)
    row2, col2 = find_position(square, b)

    if row1 == row2:
        # Same row → move right
        return square[row1][(col1 + 1) % 5] + square[row2][(col2 + 1) % 5]
    elif col1 == col2:
        # Same column → move down
        return square[(row1 + 1) % 5][col1] + square[(row2 + 1) % 5][col2]
    else:
        # Rectangle rule → swap columns
        return square[row1][col2] + square[row2][col1]


def encrypt(text, square):
    """Encrypt the prepared plaintext using the Playfair cipher."""
    prepared = prepare_text(text)
    ciphertext = ""

    for i in range(0, len(prepared), 2):
        a = prepared[i]
        b = prepared[i + 1]
        ciphertext += encrypt_pair(a, b, square)

    return ciphertext


# --- MAIN PROGRAM ---
if __name__ == "__main__":
    plaintext = "Must see you over Cadogan West. Coming at once."
    print("Playfair Cipher Encryption\n")
    print("Plaintext:", plaintext)

    # Use given fixed matrix
    square = generate_fixed_square()
    print("\nPlayfair Matrix:")
    for row in square:
        print(" ".join(row))

    # Encrypt the message
    ciphertext = encrypt(plaintext, square)

    print("\nEncrypted Ciphertext:")
    print(ciphertext)
