# Post-Quantum Security Analysis: Password Digital Signatures

This document analyzes whether the Digital Signatures currently stored in the MongoDB `users` collection (`digital_signature` field) can be broken via Classical computing, Decryption algorithms, or Quantum computers.

## Current Cryptographic Architecture
When a user registers, their plaintext password is converted into a deterministic string using **HMAC-SHA256**:
- **Algorithm:** Hash-based Message Authentication Code (HMAC) utilizing Secure Hash Algorithm 256-bit (SHA-256).
- **Key:** A 256-bit minimum length `PASSWORD_HMAC_KEY` retained exclusively in the backend memory environment.
- **Message:** The user's plaintext password.

## 1. Classical Decryption Feasibility
### Is it vulnerable to "decryption"?
**No.** HMAC-SHA256 is a one-way cryptographic hashing function, not an encryption cipher.
- Decryption requires a two-way algorithm (like RSA or AES) where math exists to reverse-engineer ciphertext mathematically. 
- You physically *cannot* decrypt an SHA-256 HMAC because the original data mapping is permanently destroyed during the Avalanche operation.

### Is it vulnerable to Brute-Force?
If an attacker breaches the MongoDB and steals the `digital_signature`, they **cannot** run an offline dictionary attack (brute force) because they do not have the server's `PASSWORD_HMAC_KEY`. 

## 2. Quantum Algorithms (Shor's & Grover's)
Quantum computers threaten cryptography through two primary algorithms:

### Shor's Algorithm
Shor's Algorithm exponentially accelerates the breaking of asymmetric cryptography that relies on prime factorization or discrete logarithms (e.g., standard RSA-2048 or Elliptic Curve signatures like Ed25519).
- **Vulnerability:** **ZERO**. HMAC-SHA256 is symmetric and hash-based; it is entirely immune to Shor's Algorithm.

### Grover's Algorithm
Grover's Quantum Search Algorithm accelerates the brute-forcing of symmetric keys and hash collisions, reducing the effective security space to its square root.
- **Vulnerability:** **SAFE (Post-Quantum Secure)**. 
- While Grover's algorithm halves the bit-strength of a key search, an HMAC using SHA-256 effectively degrades from 256 bits of security to **128 bits of post-quantum security**. 
- 128 bits of security is the NSA and NIST standard threshold line for "Post-Quantum Cryptography Resilience". A quantum computer requires $2^{128}$ quantum operations (approximately $3.4 \times 10^{38}$ calculations) to crack the key. Even a colossal theoretical quantum array achieving a trillion operations per second would require billions of years to break a single hash.

## Conclusion 
The current backend setup natively achieves robust Post-Quantum Cryptography (PQC) resilience. The digital signatures residing in your database are completely unbreakable by foreseeable classical or quantum methods.
