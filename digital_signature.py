"""
Digital Signature Demonstration

This script demonstrates digital signatures using RSA encryption.
Digital signatures verify the authenticity and integrity of messages.

Author: Paul Sommers
Course: SDEV245
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64


def generate_key_pair():
    """
    Generate an RSA key pair for signing and verification.
    
    Returns:
        tuple: (private_key, public_key)
    """
    # Generate 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Extract public key from private key
    public_key = private_key.public_key()
    
    return private_key, public_key


def sign_message(message, private_key):
    """
    Sign a message using the private key.
    
    Args:
        message (str): Message to sign
        private_key: RSA private key
        
    Returns:
        bytes: Digital signature
    """
    # Convert message to bytes
    message_bytes = message.encode('utf-8')
    
    # Sign the message using PSS padding with SHA-256
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def verify_signature(message, signature, public_key):
    """
    Verify a message signature using the public key.
    
    Args:
        message (str): Original message
        signature (bytes): Digital signature to verify
        public_key: RSA public key
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Convert message to bytes
        message_bytes = message.encode('utf-8')
        
        # Verify signature using PSS padding with SHA-256
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        # Verification failed
        return False


def export_public_key(public_key):
    """
    Export public key to PEM format string.
    
    Args:
        public_key: RSA public key
        
    Returns:
        str: PEM-formatted public key
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')


def export_private_key(private_key):
    """
    Export private key to PEM format string (without encryption for demo).
    
    Args:
        private_key: RSA private key
        
    Returns:
        str: PEM-formatted private key
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')


def main():
    """
    Main function to demonstrate digital signature creation and verification.
    """
    print("=" * 60)
    print("Digital Signature Demonstration")
    print("=" * 60)
    print()
    
    # Demo 1: Generate key pair
    print("-" * 60)
    print("1. Generating RSA Key Pair (2048-bit)")
    print("-" * 60)
    
    private_key, public_key = generate_key_pair()
    print("Private key generated (kept secret)")
    print("Public key generated (can be shared)")
    print()
    
    # Display public key
    public_key_pem = export_public_key(public_key)
    print("Public Key (PEM format):")
    print(public_key_pem)
    
    # Demo 2: Sign a message
    print("-" * 60)
    print("2. Signing a Message")
    print("-" * 60)
    
    message = "This is an important message that needs to be verified."
    print(f"Original Message: {message}")
    print()
    
    # Sign the message
    signature = sign_message(message, private_key)
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    print(f"Digital Signature (Base64):")
    print(f"{signature_b64}")
    print()
    
    # Demo 3: Verify the signature
    print("-" * 60)
    print("3. Verifying the Signature")
    print("-" * 60)
    
    is_valid = verify_signature(message, signature, public_key)
    print(f"Message:          {message}")
    print(f"Signature Valid:  {is_valid}")
    print()
    
    # Demo 4: Demonstrate signature fails with modified message
    print("-" * 60)
    print("4. Tampering Detection")
    print("-" * 60)
    
    tampered_message = "This is an important message that has been modified."
    print(f"Original Message: {message}")
    print(f"Tampered Message: {tampered_message}")
    print()
    
    # Try to verify tampered message with original signature
    is_valid_tampered = verify_signature(tampered_message, signature, public_key)
    print(f"Original Signature Valid for Tampered Message: {is_valid_tampered}")
    print()
    
    if not is_valid_tampered:
        print("Good! The signature verification correctly detected the tampering.")
    print()
    
    # Demo 5: Complete workflow
    print("-" * 60)
    print("5. Complete Signing/Verification Workflow")
    print("-" * 60)
    
    print("\nScenario: Alice sends a signed message to Bob")
    print()
    
    # Alice generates her key pair
    alice_private, alice_public = generate_key_pair()
    print("Step 1: Alice generates her key pair")
    print("        - Private key (Alice keeps secret)")
    print("        - Public key (Alice shares with Bob)")
    print()
    
    # Alice signs a message
    alice_message = "Meet me at the library at 3pm - Alice"
    alice_signature = sign_message(alice_message, alice_private)
    print(f"Step 2: Alice signs her message")
    print(f"        Message: {alice_message}")
    print()
    
    # Bob receives the message and signature
    print("Step 3: Bob receives message and signature from Alice")
    print()
    
    # Bob verifies using Alice's public key
    is_authentic = verify_signature(alice_message, alice_signature, alice_public)
    print(f"Step 4: Bob verifies signature using Alice's public key")
    print(f"        Signature Valid: {is_authentic}")
    print()
    
    if is_authentic:
        print("Result: Bob can trust this message is from Alice and hasn't been modified!")
    print()
    
    # Interactive mode
    print("-" * 60)
    print("6. Interactive Mode")
    print("-" * 60)
    print()
    
    # Generate a key pair for interactive use
    user_private, user_public = generate_key_pair()
    current_signature = None
    current_message = None
    
    print("Key pair generated for this session.")
    print()
    
    while True:
        print("Choose an option:")
        print("1. Sign a message")
        print("2. Verify a signature")
        print("3. View public key")
        print("4. Exit")
        
        choice = input("\nEnter choice (1-4): ").strip()
        
        if choice == '1':
            message = input("Enter message to sign: ")
            signature = sign_message(message, user_private)
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            current_signature = signature
            current_message = message
            print(f"\nDigital Signature (Base64):")
            print(f"{signature_b64}\n")
            
        elif choice == '2':
            if current_message and current_signature:
                verify_msg = input("Enter message to verify: ")
                is_valid = verify_signature(verify_msg, current_signature, user_public)
                print(f"\nSignature Valid: {is_valid}")
                if verify_msg == current_message:
                    print("Message matches the signed message.\n")
                else:
                    print("Message differs from the signed message.\n")
            else:
                print("\nNo signature available. Please sign a message first.\n")
                
        elif choice == '3':
            pem = export_public_key(user_public)
            print("\nPublic Key (PEM format):")
            print(pem)
            
        elif choice == '4':
            print("\nExiting digital signature tool.")
            break
        else:
            print("\nInvalid choice. Please enter 1, 2, 3, or 4.\n")


if __name__ == "__main__":
    main()