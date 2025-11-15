"""
Caesar Cipher Encryption/Decryption

This script implements a simple substitution cipher (Caesar cipher) to encrypt
and decrypt text. The Caesar cipher shifts each letter by a fixed number of
positions in the alphabet.

Author: Paul Sommers
Course: SDEV245
"""


def encrypt(plaintext, shift):
    """
    Encrypt plaintext using Caesar cipher with the specified shift.
    
    Args:
        plaintext (str): Text to encrypt
        shift (int): Number of positions to shift (1-25)
        
    Returns:
        str: Encrypted ciphertext
    """
    ciphertext = ""
    
    # Process each character in the plaintext
    for char in plaintext:
        if char.isalpha():
            # Determine if uppercase or lowercase
            ascii_offset = ord('A') if char.isupper() else ord('a')
            
            # Shift character and wrap around using modulo 26
            shifted = (ord(char) - ascii_offset + shift) % 26
            ciphertext += chr(shifted + ascii_offset)
        else:
            # Keep non-alphabetic characters unchanged
            ciphertext += char
    
    return ciphertext


def decrypt(ciphertext, shift):
    """
    Decrypt ciphertext using Caesar cipher with the specified shift.
    
    Args:
        ciphertext (str): Text to decrypt
        shift (int): Number of positions that were shifted (1-25)
        
    Returns:
        str: Decrypted plaintext
    """
    # Decryption is just encryption with negative shift
    return encrypt(ciphertext, -shift)


def brute_force_decrypt(ciphertext):
    """
    Attempt to decrypt ciphertext by trying all possible shifts (1-25).
    Useful when the shift key is unknown.
    
    Args:
        ciphertext (str): Text to decrypt
        
    Returns:
        list: List of tuples containing (shift, decrypted_text)
    """
    results = []
    
    # Try all possible shifts
    for shift in range(1, 26):
        decrypted = decrypt(ciphertext, shift)
        results.append((shift, decrypted))
    
    return results


def main():
    """
    Main function to demonstrate Caesar cipher encryption and decryption.
    """
    print("=" * 60)
    print("Caesar Cipher Demonstration")
    print("=" * 60)
    print()
    
    # Demo 1: Basic encryption and decryption
    print("-" * 60)
    print("1. Basic Encryption/Decryption")
    print("-" * 60)
    
    plaintext = "Hello, World! This is a secret message."
    shift = 3
    
    print(f"Original Plaintext: {plaintext}")
    print(f"Shift Value:        {shift}")
    print()
    
    # Encrypt the message
    ciphertext = encrypt(plaintext, shift)
    print(f"Encrypted Message:  {ciphertext}")
    print()
    
    # Decrypt the message
    decrypted = decrypt(ciphertext, shift)
    print(f"Decrypted Message:  {decrypted}")
    print(f"Match Original:     {plaintext == decrypted}")
    print()
    
    # Demo 2: Different shift values
    print("-" * 60)
    print("2. Different Shift Values")
    print("-" * 60)
    
    test_message = "Python is awesome!"
    
    for test_shift in [1, 5, 13, 25]:
        encrypted = encrypt(test_message, test_shift)
        print(f"Shift {test_shift:2d}: {encrypted}")
    print()
    
    # Demo 3: Brute force decryption
    print("-" * 60)
    print("3. Brute Force Decryption (Unknown Key)")
    print("-" * 60)
    
    secret_message = "Wklv lv d vhfuhw phvvdjh!"
    print(f"Encrypted Message: {secret_message}")
    print("\nTrying all possible shifts (1-25):")
    print()
    
    results = brute_force_decrypt(secret_message)
    for shift, decrypted in results:
        print(f"Shift {shift:2d}: {decrypted}")
    
    print("\nNotice: Shift 3 produces readable text!")
    print()
    
    # Interactive mode
    print("-" * 60)
    print("4. Interactive Mode")
    print("-" * 60)
    print()
    
    while True:
        print("Choose an option:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Brute force decrypt (try all shifts)")
        print("4. Exit")
        
        choice = input("\nEnter choice (1-4): ").strip()
        
        if choice == '1':
            message = input("Enter message to encrypt: ")
            try:
                shift = int(input("Enter shift value (1-25): "))
                if 1 <= shift <= 25:
                    encrypted = encrypt(message, shift)
                    print(f"\nEncrypted: {encrypted}\n")
                else:
                    print("\nError: Shift must be between 1 and 25.\n")
            except ValueError:
                print("\nError: Please enter a valid number.\n")
                
        elif choice == '2':
            message = input("Enter message to decrypt: ")
            try:
                shift = int(input("Enter shift value (1-25): "))
                if 1 <= shift <= 25:
                    decrypted = decrypt(message, shift)
                    print(f"\nDecrypted: {decrypted}\n")
                else:
                    print("\nError: Shift must be between 1 and 25.\n")
            except ValueError:
                print("\nError: Please enter a valid number.\n")
                
        elif choice == '3':
            message = input("Enter message to brute force decrypt: ")
            print("\nTrying all possible shifts:\n")
            results = brute_force_decrypt(message)
            for shift, decrypted in results:
                print(f"Shift {shift:2d}: {decrypted}")
            print()
            
        elif choice == '4':
            print("\nExiting Caesar cipher tool.")
            break
        else:
            print("\nInvalid choice. Please enter 1, 2, 3, or 4.\n")


if __name__ == "__main__":
    main()