import math

def playfair_keyspace():
    # 25 letters (I/J combined)
    total_keys = math.factorial(25)

    # Convert to approximate power of 2
    power_of_2 = math.log2(total_keys)

    # Adjust for duplicate-equivalent keys (approx. divide by 4)
    unique_keys = total_keys / 4
    unique_power_of_2 = math.log2(unique_keys)

    print("Playfair Cipher Keyspace Calculation\n")
    print(f"Total possible keys (25!) = {total_keys:.3e}")
    print(f"Approx. as 2^{power_of_2:.2f}")
    print()
    print(f"After considering equivalent keys ≈ 25!/4")
    print(f"Effectively unique keys = {unique_keys:.3e}")
    print(f"Approx. as 2^{unique_power_of_2:.2f}")

if __name__ == "__main__":
    playfair_keyspace()
