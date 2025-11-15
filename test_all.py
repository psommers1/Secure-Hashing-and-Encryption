"""
Quick test script to verify all three programs work correctly.
"""

import sys

def test_sha256():
    """Test SHA-256 hashing"""
    print("Testing SHA-256 Hasher...")
    try:
        from sha256_hasher import hash_string, hash_file
        
        # Test string hashing
        result = hash_string("Test")
        assert len(result) == 64
        
        # Test file hashing
        with open("temp_test.txt", "w") as f:
            f.write("test content")
        result = hash_file("temp_test.txt")
        assert len(result) == 64
        
        import os
        os.remove("temp_test.txt")
        
        print("✓ SHA-256 hasher working correctly\n")
        return True
    except Exception as e:
        print(f"✗ SHA-256 hasher failed: {e}\n")
        return False

def test_caesar():
    """Test Caesar cipher"""
    print("Testing Caesar Cipher...")
    try:
        from caesar_cipher import encrypt, decrypt
        
        plaintext = "Hello World"
        ciphertext = encrypt(plaintext, 3)
        decrypted = decrypt(ciphertext, 3)
        
        assert plaintext == decrypted
        assert ciphertext != plaintext
        
        print("✓ Caesar cipher working correctly\n")
        return True
    except Exception as e:
        print(f"✗ Caesar cipher failed: {e}\n")
        return False

def test_digital_signature():
    """Test digital signatures"""
    print("Testing Digital Signatures...")
    try:
        from digital_signature import generate_key_pair, sign_message, verify_signature
        
        private_key, public_key = generate_key_pair()
        message = "Test message"
        signature = sign_message(message, private_key)
        is_valid = verify_signature(message, signature, public_key)
        
        assert is_valid == True
        
        # Test tampering detection
        tampered = "Modified message"
        is_valid_tampered = verify_signature(tampered, signature, public_key)
        assert is_valid_tampered == False
        
        print("✓ Digital signatures working correctly\n")
        return True
    except Exception as e:
        print(f"✗ Digital signatures failed: {e}\n")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("Testing All Scripts")
    print("=" * 60)
    print()
    
    results = []
    results.append(test_sha256())
    results.append(test_caesar())
    results.append(test_digital_signature())
    
    print("=" * 60)
    if all(results):
        print("All tests passed! ✓")
    else:
        print("Some tests failed! ✗")
    print("=" * 60)