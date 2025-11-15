# Secure Hashing and Encryption

Simple demonstration of SHA-256 hashing, Caesar cipher encryption, and digital signatures in Python.

**Author:** Paul Sommers  
**Course:** SDEV245

## What This Does

This project contains three Python scripts that demonstrate fundamental cryptographic concepts:
- SHA-256 hashing for strings and files
- Caesar cipher substitution encryption/decryption
- Digital signatures using RSA encryption

Each script includes both automated demonstrations and interactive modes for hands-on experimentation.

## Files

- `sha256_hasher.py` - SHA-256 hashing demonstration for strings and files
- `caesar_cipher.py` - Caesar cipher encryption and decryption tool
- `digital_signature.py` - Digital signature creation and verification using RSA
- `requirements.txt` - Python dependencies (cryptography library)
- `README.md` - This file

## How to Run

**Step 1: Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 2: Run any of the scripts**
```bash
python sha256_hasher.py
python caesar_cipher.py
python digital_signature.py
```

Each script will:
1. Display automated demonstrations of core functionality
2. Provide clear input/output examples
3. Enter interactive mode for hands-on experimentation

## Script Functionality

### 1. SHA-256 Hashing (`sha256_hasher.py`)

SHA-256 is a cryptographic hash function that produces a fixed 256-bit (32-byte) hash value from any input.

**Key Features:**
- Hash strings with `hash_string(input_string)`
- Hash files with `hash_file(filepath)` (handles large files efficiently)
- Demonstrates hash consistency (same input = same hash)
- Shows how small changes produce completely different hashes
- Interactive mode for custom inputs

**How it works:**
1. Takes any input (string or file)
2. Processes it through SHA-256 algorithm
3. Outputs a 64-character hexadecimal hash
4. Same input always produces identical hash
5. Any change in input produces completely different hash

**Use cases:**
- Verify file integrity (detect corruption or tampering)
- Store password hashes (never store plain passwords)
- Create unique identifiers for data
- Verify downloads (compare hash to source)

### 2. Caesar Cipher (`caesar_cipher.py`)

The Caesar cipher is a simple substitution cipher that shifts each letter by a fixed number of positions in the alphabet.

**Key Features:**
- Encrypt text with `encrypt(plaintext, shift)`
- Decrypt text with `decrypt(ciphertext, shift)`
- Brute force decryption (try all 25 possible shifts)
- Preserves non-alphabetic characters (spaces, punctuation)
- Interactive mode for encryption/decryption

**How it works:**
1. Each letter shifts forward by the shift value (e.g., shift 3: A→D, B→E)
2. Wraps around the alphabet (Z with shift 3 → C)
3. Keeps uppercase/lowercase formatting
4. Leaves numbers and punctuation unchanged
5. Decryption uses negative shift (reverse the process)

**Strengths:**
- Simple to understand and implement
- Fast encryption/decryption
- No special tools required

**Weaknesses:**
- Very insecure (only 25 possible keys)
- Vulnerable to frequency analysis
- Easy to crack with brute force
- Not suitable for real security needs

### 3. Digital Signatures (`digital_signature.py`)

Digital signatures use asymmetric encryption (RSA) to verify message authenticity and integrity.

**Key Features:**
- Generate RSA key pairs (2048-bit)
- Sign messages with `sign_message(message, private_key)`
- Verify signatures with `verify_signature(message, signature, public_key)`
- Detect message tampering
- Export keys in PEM format
- Interactive mode for signing/verification

**How it works:**
1. Generate key pair (private key + public key)
2. Sender signs message with their private key
3. Receiver verifies signature using sender's public key
4. Verification succeeds only if:
   - Message hasn't been modified
   - Signature was created by the private key owner

**Key Concepts:**
- **Private Key:** Kept secret, used to create signatures
- **Public Key:** Shared openly, used to verify signatures
- **Authenticity:** Proves who sent the message
- **Integrity:** Proves message wasn't modified
- **Non-repudiation:** Sender can't deny signing the message

**Use cases:**
- Verify software downloads (code signing)
- Authenticate email senders (S/MIME, PGP)
- Digital contracts and legal documents
- Cryptocurrency transactions
- Secure communications (TLS/SSL certificates)

## Cryptographic Concepts Explained

### Hashing vs. Encryption

**Hashing (SHA-256):**
- One-way function (cannot reverse)
- Same input always produces same output
- Used for verification, not secrecy
- Fixed output size regardless of input size

**Encryption (Caesar, RSA):**
- Two-way function (can encrypt and decrypt)
- Used for confidentiality
- Requires a key to decrypt
- Output size varies with input size

### Symmetric vs. Asymmetric

**Symmetric (Caesar Cipher):**
- Same key for encryption and decryption
- Fast but requires secure key exchange
- Key distribution problem

**Asymmetric (RSA Digital Signatures):**
- Different keys for signing and verifying
- Slower but solves key distribution
- Private key signs, public key verifies

## Security Notes

**Important:** These implementations are for educational purposes only.

- **SHA-256 Hasher:** Production-ready algorithm, but implementation lacks salt for password hashing
- **Caesar Cipher:** NOT secure - easily broken, use only for learning
- **Digital Signatures:** Uses industry-standard RSA-2048, but keys should be password-protected in production

For real-world security needs, always use established cryptographic libraries and follow security best practices.

## Learning Objectives

This assignment demonstrates understanding of:
- How cryptographic hash functions work and their applications
- The difference between hashing and encryption
- Basic substitution ciphers and their limitations
- Digital signature creation and verification
- Public key cryptography concepts
- When to use each cryptographic method

## Links

- **GitHub:** https://github.com/psommers1/Secure-Hashing-and-Encryption

## Sample Usage Examples

### SHA-256 Hashing
```python
from sha256_hasher import hash_string, hash_file

# Hash a string
message_hash = hash_string("Hello, World!")
print(message_hash)  # Outputs 64-character hex string

# Hash a file
file_hash = hash_file("document.txt")
print(file_hash)
```

### Caesar Cipher
```python
from caesar_cipher import encrypt, decrypt

# Encrypt a message
ciphertext = encrypt("Secret Message", 13)
print(ciphertext)  # "Frperg Zrffntr"

# Decrypt the message
plaintext = decrypt(ciphertext, 13)
print(plaintext)  # "Secret Message"
```

### Digital Signatures
```python
from digital_signature import generate_key_pair, sign_message, verify_signature

# Generate keys
private_key, public_key = generate_key_pair()

# Sign a message
message = "Important document"
signature = sign_message(message, private_key)

# Verify signature
is_valid = verify_signature(message, signature, public_key)
print(is_valid)  # True