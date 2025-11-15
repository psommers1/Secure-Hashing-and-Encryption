"""
SHA-256 Hashing Demonstration

This script demonstrates SHA-256 hashing for both strings and files.
SHA-256 produces a fixed 256-bit (32-byte) hash value regardless of input size.

Author: Paul Sommers
Course: SDEV245
"""

import hashlib
import sys
import os


def hash_string(input_string):
    """
    Generate SHA-256 hash for a string input.
    
    Args:
        input_string (str): The string to hash
        
    Returns:
        str: Hexadecimal representation of the hash
    """
    # Create SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    # Update hash with encoded string (bytes required)
    sha256_hash.update(input_string.encode('utf-8'))
    
    # Return hexadecimal digest
    return sha256_hash.hexdigest()


def hash_file(filepath):
    """
    Generate SHA-256 hash for a file.
    Reads file in chunks to handle large files efficiently.
    
    Args:
        filepath (str): Path to the file to hash
        
    Returns:
        str: Hexadecimal representation of the hash
    """
    # Create SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    # Open file in binary mode and read in chunks
    with open(filepath, 'rb') as f:
        # Read file in 4KB chunks to handle large files
        for chunk in iter(lambda: f.read(4096), b''):
            sha256_hash.update(chunk)
    
    # Return hexadecimal digest
    return sha256_hash.hexdigest()


def main():
    """
    Main function to demonstrate SHA-256 hashing for both strings and files.
    """
    print("=" * 60)
    print("SHA-256 Hashing Demonstration")
    print("=" * 60)
    print()
    
    # Demo 1: Hash a string
    print("-" * 60)
    print("1. String Hashing")
    print("-" * 60)
    
    test_string = "Hello, this is a test message for SHA-256 hashing!"
    string_hash = hash_string(test_string)
    
    print(f"Original String: {test_string}")
    print(f"SHA-256 Hash:    {string_hash}")
    print()
    
    # Show that even a small change produces completely different hash
    modified_string = "Hello, this is a test message for SHA-256 hashing?"
    modified_hash = hash_string(modified_string)
    
    print(f"Modified String: {modified_string}")
    print(f"SHA-256 Hash:    {modified_hash}")
    print()
    print("Notice: Even changing one character (! to ?) produces a completely different hash.")
    print()
    
    # Demo 2: Hash a file
    print("-" * 60)
    print("2. File Hashing")
    print("-" * 60)
    
    # Create a test file for demonstration
    test_file = "test_file.txt"
    with open(test_file, 'w') as f:
        f.write("This is a test file for SHA-256 hashing.\n")
        f.write("SHA-256 is a cryptographic hash function.\n")
    
    file_hash = hash_file(test_file)
    file_size = os.path.getsize(test_file)
    
    print(f"File Name:       {test_file}")
    print(f"File Size:       {file_size} bytes")
    print(f"SHA-256 Hash:    {file_hash}")
    print()
    
    # Demonstrate that same content produces same hash
    print("Verifying hash consistency...")
    file_hash_2 = hash_file(test_file)
    print(f"Second Hash:     {file_hash_2}")
    print(f"Hashes Match:    {file_hash == file_hash_2}")
    print()
    
    # Clean up test file
    os.remove(test_file)
    
    # Interactive mode
    print("-" * 60)
    print("3. Interactive Mode")
    print("-" * 60)
    print()
    
    while True:
        print("Choose an option:")
        print("1. Hash a string")
        print("2. Hash a file")
        print("3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            user_string = input("Enter string to hash: ")
            hash_result = hash_string(user_string)
            print(f"\nSHA-256 Hash: {hash_result}\n")
            
        elif choice == '2':
            file_path = input("Enter file path: ").strip()
            try:
                hash_result = hash_file(file_path)
                print(f"\nSHA-256 Hash: {hash_result}\n")
            except FileNotFoundError:
                print(f"\nError: File '{file_path}' not found.\n")
            except Exception as e:
                print(f"\nError: {str(e)}\n")
                
        elif choice == '3':
            print("\nExiting SHA-256 hasher.")
            break
        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.\n")


if __name__ == "__main__":
    main()