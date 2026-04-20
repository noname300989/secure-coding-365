# 🔐 Cryptography: Zero to Hero

> A Complete Guide for Security Engineers — From mathematical foundations to post-quantum algorithms, real-world attacks, and applied protocols.

---

## Contents

1. [What Is Cryptography? Core Concepts](#01-what-is-cryptography-core-concepts)
2. [Mathematical Foundations](#02-mathematical-foundations)
3. [Symmetric Encryption — AES, DES & Block Ciphers](#03-symmetric-encryption--aes-des--block-ciphers)
4. [Asymmetric Encryption — RSA, ECC & Key Exchange](#04-asymmetric-encryption--rsa-ecc--key-exchange)
5. [Hash Functions & Message Authentication](#05-hash-functions--message-authentication)
6. [Digital Signatures & Non-Repudiation](#06-digital-signatures--non-repudiation)
7. [PKI, Certificates & Trust Models](#07-pki-certificates--trust-models)
8. [TLS/SSL Deep Dive](#08-tlsssl-deep-dive)
9. [Password Security & Key Derivation](#09-password-security--key-derivation)
10. [Cryptographic Attacks & Vulnerabilities](#10-cryptographic-attacks--vulnerabilities)
11. [Applied Cryptography — Real-World Protocols](#11-applied-cryptography--real-world-protocols)
12. [Post-Quantum Cryptography](#12-post-quantum-cryptography)
13. [Common Crypto Mistakes & Hardening](#13-common-crypto-mistakes--hardening)
14. [Interview Questions & Model Answers](#14-interview-questions--model-answers)

---

## 01 — What Is Cryptography? Core Concepts

Cryptography is the science of securing communication and data through mathematical transformations. It converts readable information (**plaintext**) into an unreadable form (**ciphertext**) and back, ensuring that only authorized parties can access the original content.

### The CIA Triad + Beyond

| Property | Definition | Crypto Mechanism |
|---|---|---|
| **Confidentiality** | Only authorized parties can read the data | Encryption (AES, RSA, ChaCha20) |
| **Integrity** | Data has not been altered in transit or at rest | Hash functions (SHA-256), MACs (HMAC) |
| **Authentication** | Verify identity of sender/receiver | Digital signatures, certificates, MACs |
| **Non-Repudiation** | Sender cannot deny having sent a message | Digital signatures (RSA-PSS, ECDSA) |
| **Forward Secrecy** | Past sessions stay safe if long-term key leaks | Ephemeral Diffie-Hellman (DHE, ECDHE) |

### Kerckhoffs' Principle

> 🔑 **The Golden Rule**: A cryptosystem should be secure even if everything about the system — except the key — is public knowledge. The security must reside entirely in the **key**, not in the secrecy of the algorithm. This is why we use open, peer-reviewed algorithms (AES, RSA) rather than proprietary "security through obscurity."

### Taxonomy of Cryptographic Primitives

```
                    Cryptographic Primitives
         ┌──────────────┬──────────────┬──────────────┐
      Symmetric       Asymmetric      Hash Functions
    AES, ChaCha20    RSA, ECC, DH    SHA-256, SHA-3
   Same key both    Public + Private   One-way, no key
    ├─ Block ciphers  ├─ Encryption    ├─ MDCs (keyless)
    └─ Stream ciphers ├─ Signatures    └─ MACs (keyed)
                      └─ Key exchange
```

### Historical Milestones

| Year | Event | Significance |
|---|---|---|
| ~1900 BC | Egyptian hieroglyph substitution | Earliest known cipher |
| ~50 BC | Caesar cipher | Simple shift cipher — still taught today |
| 1976 | Diffie-Hellman key exchange | Birth of public-key cryptography |
| 1977 | RSA published | First practical public-key encryption |
| 1977 | DES standardized (NIST) | First government-standard symmetric cipher |
| 2001 | AES selected (Rijndael) | Replaced DES — the modern standard |
| 2015 | SHA-3 (Keccak) standardized | Alternative hash family to SHA-2 |
| 2024 | NIST PQC standards finalized | ML-KEM, ML-DSA for post-quantum era |

---

## 02 — Mathematical Foundations

You don't need a PhD in math to understand cryptography, but a few core concepts underpin nearly every algorithm. Mastering these makes everything else click.

### Modular Arithmetic

The backbone of RSA, Diffie-Hellman, and elliptic curves. Think of it as "clock arithmetic" — numbers wrap around after reaching the modulus.

```
# Modular arithmetic basics
17 mod 5 = 2          # 17 ÷ 5 = 3 remainder 2
(7 + 9) mod 10 = 6   # Addition wraps around
(3 × 4) mod 5 = 2    # Multiplication wraps too

# Modular exponentiation (core of RSA)
7^13 mod 11 = 2      # Computed efficiently via square-and-multiply
```

### Prime Numbers & Factoring

> 💡 **The RSA Assumption**: Multiplying two large primes is easy: `p × q = n`. But given only `n`, finding `p` and `q` is computationally infeasible for sufficiently large primes (2048+ bits). This **asymmetry** is what makes RSA secure.

| Concept | What It Is | Used In |
|---|---|---|
| **Prime factoring** | Decomposing n into p × q | RSA security assumption |
| **GCD / Euclidean algorithm** | Find greatest common divisor | RSA key generation, coprimality check |
| **Euler's totient φ(n)** | Count of integers coprime to n | RSA: φ(n) = (p-1)(q-1) |
| **Modular inverse** | Find d such that e·d ≡ 1 mod φ(n) | RSA private key derivation |
| **Discrete logarithm** | Find x in g^x ≡ h mod p | Diffie-Hellman, DSA, ElGamal |
| **Elliptic curve points** | Points on y² = x³ + ax + b over finite field | ECC — ECDH, ECDSA, EdDSA |

### XOR — The Simplest Cipher

XOR (exclusive or) is foundational: it's its own inverse, making it perfect for combining keys with data.

```
# XOR properties
A ⊕ 0 = A          # Identity
A ⊕ A = 0          # Self-inverse
A ⊕ B ⊕ B = A      # Encrypt then decrypt

# One-Time Pad (perfect secrecy)
plaintext  = 01001000 01101001  # "Hi"
key        = 11010110 10101010  # random, same length
ciphertext = 10011110 11000011  # plaintext ⊕ key
```

### Entropy & Randomness

Cryptographic security depends entirely on quality randomness. A predictable random number generator (RNG) can break even the strongest algorithms.

| Source | Type | Security |
|---|---|---|
| `/dev/urandom` (Linux) | CSPRNG | ✅ SAFE — Use for all crypto |
| `CryptGenRandom` (Windows) | CSPRNG | ✅ SAFE |
| `Math.random()` (JS) | PRNG | ❌ UNSAFE — Predictable, never for crypto |
| `random.random()` (Python) | PRNG (Mersenne Twister) | ❌ UNSAFE — Use `secrets` module instead |

---

## 03 — Symmetric Encryption — AES, DES & Block Ciphers

Symmetric encryption uses the **same key** for both encryption and decryption. It's fast, efficient, and handles the bulk of data encryption in every protocol you use daily (TLS, disk encryption, VPNs).

### Block Ciphers vs. Stream Ciphers

| Property | Block Cipher | Stream Cipher |
|---|---|---|
| **Unit** | Fixed-size blocks (128 bits for AES) | One byte/bit at a time |
| **Speed** | Fast with hardware (AES-NI) | Fast in software |
| **Examples** | AES, DES, 3DES, Blowfish | ChaCha20, RC4, Salsa20 |
| **Use case** | Disk encryption, TLS, databases | TLS (mobile), VPNs, real-time |
| **Padding needed?** | Yes (except CTR/GCM modes) | No |

### AES (Advanced Encryption Standard)

AES (Rijndael) is **the** symmetric cipher. Selected by NIST in 2001 after a 5-year competition, it operates on 128-bit blocks with key sizes of 128, 192, or 256 bits.

#### AES Internal Rounds

```
Plaintext Block (128 bits)
    ↓ AddRoundKey (initial XOR with key)
    ↓ SubBytes → ShiftRows → MixColumns → AddRoundKey  × (Nr-1 rounds)
    ↓ SubBytes → ShiftRows → AddRoundKey (final round — no MixColumns)
    ↓
Ciphertext Block (128 bits)

AES-128: 10 rounds  |  AES-192: 12 rounds  |  AES-256: 14 rounds
```

### Modes of Operation — Critical for Security

A block cipher alone encrypts one block. **Modes of operation** define how to encrypt data larger than one block. Choosing the wrong mode is a classic vulnerability.

| Mode | How It Works | IV/Nonce | Security |
|---|---|---|---|
| **ECB** | Each block encrypted independently | None | ❌ BROKEN — Leaks patterns |
| **CBC** | Each block XOR'd with previous ciphertext | Random IV | ⚠️ OK — Vulnerable to padding oracle |
| **CTR** | Encrypts counter; XOR with plaintext | Nonce + counter | ✅ GOOD — Parallelizable, no padding |
| **GCM** | CTR + built-in authentication (GHASH) | 96-bit nonce | ✅ BEST — Encryption + integrity |
| **CCM** | CTR + CBC-MAC authentication | Nonce | ✅ GOOD — Used in WiFi (WPA2) |

> ⚠️ **ECB Mode — The Classic Blunder**: ECB encrypts identical plaintext blocks to identical ciphertext blocks. This leaks patterns — the famous "ECB Penguin" shows an image encrypted with ECB where the penguin shape is still perfectly visible. **Never use ECB for anything.**

### Python: AES-256-GCM Example

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate key and nonce
key   = AESGCM.generate_key(bit_length=256)  # 32 bytes
nonce = os.urandom(12)                       # 96-bit nonce for GCM

# Encrypt with associated data (AAD)
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, b"secret message", b"authenticated-header")

# Decrypt — tampered data raises InvalidTag
plaintext = aesgcm.decrypt(nonce, ciphertext, b"authenticated-header")
```

### DES, 3DES & Why They're Dead

| Cipher | Key Size | Block Size | Status |
|---|---|---|---|
| DES | 56 bits | 64 bits | ❌ BROKEN — Brute-forced in 1999 in 22 hours |
| 3DES | 112/168 bits | 64 bits | ❌ DEPRECATED — Sweet32 attack, retired by NIST 2023 |
| AES-128 | 128 bits | 128 bits | ✅ STANDARD — No known practical attacks |
| AES-256 | 256 bits | 128 bits | ✅ FUTURE-PROOF — Quantum-resistant key size |
| ChaCha20 | 256 bits | Stream | ✅ MODERN — Fast on mobile, no AES-NI needed |

---

## 04 — Asymmetric Encryption — RSA, ECC & Key Exchange

Asymmetric (public-key) cryptography uses a **key pair**: a public key anyone can know, and a private key only the owner holds. This solves the fundamental problem of symmetric crypto — *how do you share the key securely?*

### RSA — The Workhorse

#### Key Generation

```
# RSA Key Generation (simplified)
1. Pick two large primes: p, q  (each ~1024 bits for RSA-2048)
2. Compute n = p × q             (the modulus — public)
3. Compute φ(n) = (p-1)(q-1)     (Euler's totient — secret)
4. Choose e = 65537               (public exponent — standard)
5. Compute d = e⁻¹ mod φ(n)      (private exponent)

Public key:  (e, n)
Private key: (d, n)

# Encrypt:  c = m^e mod n
# Decrypt:  m = c^d mod n
```

#### RSA Key Sizes & Security Levels

| RSA Key Size | Security (bits) | Status | Quantum Risk |
|---|---|---|---|
| 1024 | ~80 | ❌ BROKEN | Factorable today with effort |
| 2048 | ~112 | ✅ STANDARD | Vulnerable to Shor's algorithm |
| 3072 | ~128 | ✅ RECOMMENDED | Vulnerable to Shor's algorithm |
| 4096 | ~140 | ✅ HIGH SECURITY | Vulnerable to Shor's algorithm |

### Elliptic Curve Cryptography (ECC)

ECC achieves the same security as RSA with **much smaller keys**. An ECC 256-bit key ≈ RSA 3072-bit key in security strength.

> 📐 **The Elliptic Curve**: An elliptic curve is defined by y² = x³ + ax + b over a finite field. Points on the curve form a group under "point addition." The security relies on the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**: given points P and Q = kP, finding k is computationally infeasible.

| Curve | Key Size | Security | Used By |
|---|---|---|---|
| P-256 (secp256r1) | 256 bits | ~128 bits | TLS, AWS, most web services |
| P-384 (secp384r1) | 384 bits | ~192 bits | Government (NSA Suite B) |
| Curve25519 | 256 bits | ~128 bits | Signal, WireGuard, SSH |
| Ed25519 | 256 bits | ~128 bits | SSH keys, GPG, blockchain |
| secp256k1 | 256 bits | ~128 bits | Bitcoin, Ethereum |

### Diffie-Hellman Key Exchange

The protocol that started it all (1976). Allows two parties to agree on a shared secret over an insecure channel — without ever transmitting the secret itself.

```
              Diffie-Hellman Key Exchange

Alice                        Public                        Bob
a = random private           g, p (public params)          b = random private
A = g^a mod p       ──── A ────→
                     ←──── B ────            B = g^b mod p
s = B^a mod p                                s = A^b mod p

            Both compute: s = g^(ab) mod p  ← shared secret!
```

> ⚠️ **Static DH vs. Ephemeral DH**: **Static DH** reuses the same key pair — if the private key leaks, all past sessions are compromised. **Ephemeral DH (DHE/ECDHE)** generates a fresh key pair per session, providing **Perfect Forward Secrecy (PFS)**. Always prefer ECDHE in TLS configurations.

---

## 05 — Hash Functions & Message Authentication

A hash function takes arbitrary-length input and produces a fixed-length output (the "digest"). Cryptographic hash functions add strict security properties that make them indispensable.

### Properties of Cryptographic Hash Functions

| Property | Definition | Why It Matters |
|---|---|---|
| **Pre-image resistance** | Given h, infeasible to find m where H(m) = h | Can't reverse a hash to find the input |
| **Second pre-image resistance** | Given m₁, infeasible to find m₂ where H(m₁) = H(m₂) | Can't forge a different message with same hash |
| **Collision resistance** | Infeasible to find any m₁ ≠ m₂ where H(m₁) = H(m₂) | No two inputs should ever produce the same hash |
| **Avalanche effect** | 1-bit input change → ~50% output bits change | Similar inputs produce completely different hashes |

### Hash Function Comparison

| Algorithm | Output Size | Speed | Status |
|---|---|---|---|
| MD5 | 128 bits | Very fast | ❌ BROKEN — Collision attacks trivial |
| SHA-1 | 160 bits | Fast | ❌ BROKEN — SHAttered attack (2017) |
| SHA-256 | 256 bits | Fast | ✅ STANDARD — Most widely used |
| SHA-384/512 | 384/512 bits | Fast on 64-bit | ✅ STANDARD |
| SHA-3 (Keccak) | 224-512 bits | Moderate | ✅ STANDARD — Different design (sponge) |
| BLAKE2 | 1-64 bytes | Faster than SHA-3 | ✅ MODERN — Used in Argon2, WireGuard |
| BLAKE3 | 256 bits | Fastest | ✅ MODERN — Parallelizable, tree hashing |

### HMAC — Hash-Based Message Authentication Code

A hash alone doesn't prove who created it. HMAC combines a hash function with a secret key to provide both integrity and authentication.

```
# HMAC construction (RFC 2104)
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))

# Where:
# K'   = key padded/hashed to block size
# ipad = 0x36 repeated to block size
# opad = 0x5C repeated to block size

# Python example
import hmac, hashlib
mac = hmac.new(b"secret-key", b"message", hashlib.sha256).hexdigest()
# Verify: use hmac.compare_digest() — constant-time!
```

> ⚠️ **Timing Attacks on MAC Verification**: Never compare MACs with `==`. String comparison short-circuits on the first different byte, leaking information about the correct MAC through timing. Always use `hmac.compare_digest()` or equivalent constant-time comparison.

### Common Hash Use Cases

| Use Case | Recommended Algorithm | Notes |
|---|---|---|
| File integrity | SHA-256, BLAKE3 | Detect tampering or corruption |
| API authentication | HMAC-SHA256 | AWS Signature V4, Stripe webhooks |
| Password storage | Argon2id, bcrypt | NOT plain SHA — see Section 09 |
| Digital signatures | SHA-256 (with RSA/ECDSA) | Hash-then-sign pattern |
| Blockchain | SHA-256 (Bitcoin), Keccak-256 (Ethereum) | Proof of work, Merkle trees |
| Git commits | SHA-1 (migrating to SHA-256) | Content-addressed storage |

---

## 06 — Digital Signatures & Non-Repudiation

Digital signatures prove three things: **who** sent a message (authentication), that it **wasn't altered** (integrity), and the sender **can't deny** sending it (non-repudiation). Unlike MACs, signatures use asymmetric keys — only the private key holder can sign.

### How Signing Works

```
Sign:   hash(message) → encrypt hash with private key → signature

Verify: decrypt signature with public key → expected hash
        hash(message) → actual hash
        expected hash =?= actual hash → ✓ valid / ✗ invalid
```

### Signature Algorithm Comparison

| Algorithm | Key Size | Sig Size | Speed | Status |
|---|---|---|---|---|
| RSA-PKCS#1 v1.5 | 2048+ bits | 256 bytes | Slow sign, fast verify | ⚠️ LEGACY |
| RSA-PSS | 2048+ bits | 256 bytes | Slow sign, fast verify | ✅ RECOMMENDED |
| ECDSA (P-256) | 256 bits | 64 bytes | Fast both | ✅ STANDARD |
| EdDSA (Ed25519) | 256 bits | 64 bytes | Fastest | ✅ MODERN — Deterministic |
| ML-DSA (Dilithium) | ~1.3 KB | ~2.4 KB | Fast | ✅ POST-QUANTUM |

> 🔑 **Why EdDSA (Ed25519) Is Preferred**: **Deterministic** — no random nonce needed (ECDSA's nonce reuse leads to private key recovery — see the PlayStation 3 hack). **Fast** — one of the fastest signature schemes. **Small keys** — 32 bytes. **Resistant to side-channel attacks** by design.

### Python: Ed25519 Signing

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Generate key pair
private_key = Ed25519PrivateKey.generate()
public_key  = private_key.public_key()

# Sign
signature = private_key.sign(b"important document")

# Verify (raises InvalidSignature if tampered)
public_key.verify(signature, b"important document")
```

### Real-World Signature Applications

- **Code signing** — OS verifies software wasn't tampered (Apple, Microsoft Authenticode)
- **TLS certificates** — CA signs server's public key with CA's private key
- **JWT tokens** — RS256 (RSA) or ES256 (ECDSA) signed claims
- **Git commits** — GPG/SSH signatures prove commit authorship
- **Blockchain** — Every Bitcoin transaction is ECDSA-signed by the sender's private key
- **Email (S/MIME, PGP)** — Sign emails to prove sender identity

---

## 07 — PKI, Certificates & Trust Models

Public Key Infrastructure (PKI) solves the trust problem: *how do you know a public key actually belongs to who you think it does?* The answer is a chain of digitally signed certificates rooted in trusted Certificate Authorities (CAs).

### X.509 Certificate Anatomy

```
# Key fields in an X.509 v3 certificate
Version:            v3
Serial Number:      03:A1:B2:C3...           # Unique per CA
Issuer:             CN=Let's Encrypt R3       # Who signed it
Subject:            CN=example.com            # Who it's for
Not Before:         2026-01-01                # Validity start
Not After:          2026-04-01                # Validity end
Public Key:         EC (P-256)                # Subject's public key
Signature Algorithm: ECDSA-with-SHA256        # How issuer signed
Extensions:
  Subject Alt Names: example.com, *.example.com
  Key Usage:         Digital Signature
  Basic Constraints: CA:FALSE                 # Not a CA cert
  OCSP:              http://ocsp.letsencrypt.org
```

### Certificate Chain of Trust

```
Root CA (self-signed, embedded in OS/browser trust store)
    ↓ signs
Intermediate CA (signed by Root CA)
    ↓ signs
End-Entity / Leaf Certificate (your server's cert — signed by Intermediate)

Browser validates: Leaf → Intermediate → Root (in trust store?) → ✓ Trusted
```

### Certificate Revocation

| Method | How It Works | Pros | Cons |
|---|---|---|---|
| **CRL** | CA publishes list of revoked serial numbers | Simple | Large, slow to download, stale |
| **OCSP** | Client queries CA: "is cert X revoked?" | Real-time | Privacy leak, latency, CA must be online |
| **OCSP Stapling** | Server fetches OCSP response, sends with TLS | Fast, private | Server must support it |
| **Short-lived certs** | Cert expires in days — no revocation needed | Simplest | Requires automation (Let's Encrypt model) |

### Certificate Transparency (CT)

CT logs are public, append-only logs of all issued certificates. They allow domain owners to detect mis-issued certificates. Browsers (Chrome) require certificates to include Signed Certificate Timestamps (SCTs) from CT logs to be trusted.

### Trust Models Compared

| Model | Trust Anchor | Example | Weakness |
|---|---|---|---|
| **Hierarchical PKI** | Root CAs | TLS/HTTPS (browsers) | Any trusted CA can issue for any domain |
| **Web of Trust** | Peers vouch for each other | PGP/GPG | Doesn't scale, complex UX |
| **TOFU** | Trust first connection | SSH known_hosts | Vulnerable on first connection |
| **DANE/TLSA** | DNS (DNSSEC) | Email servers | DNSSEC adoption still limited |
| **SPIFFE/SPIRE** | Workload identity | Kubernetes service mesh | Infrastructure complexity |

> ⚠️ **CA Compromises in the Wild**: **DigiNotar (2011)** — Hacked CA issued fraudulent *.google.com certs, used for MITM in Iran. CA was revoked and went bankrupt. **Symantec (2017)** — Mis-issued thousands of certificates; Google Chrome distrusted all Symantec-rooted certs.

---

## 08 — TLS/SSL Deep Dive

Transport Layer Security (TLS) is the protocol that encrypts virtually all internet traffic. Understanding TLS inside-out is essential for any security engineer.

### TLS 1.3 Handshake (Current Standard)

```
               TLS 1.3 — 1-RTT Handshake

Client                                              Server
ClientHello + key_share  ─────────→
                         ←─────────  ServerHello + key_share
                         ←─────────  {EncryptedExtensions}
                         ←─────────  {Certificate}
                         ←─────────  {CertificateVerify}
                         ←─────────  {Finished}
{Finished}               ─────────→
Application Data         ⟷          Application Data  [encrypted]
```

### TLS 1.3 vs. TLS 1.2

| Feature | TLS 1.2 | TLS 1.3 |
|---|---|---|
| **Handshake RTTs** | 2-RTT | 1-RTT (0-RTT resumption) |
| **Key exchange** | RSA, DHE, ECDHE | ECDHE only (PFS mandatory) |
| **Cipher suites** | ~37 (many insecure) | 5 (all AEAD) |
| **RSA key transport** | Supported (no PFS) | ❌ REMOVED |
| **CBC mode ciphers** | Supported | ❌ REMOVED |
| **Encryption starts** | After full handshake | After ServerHello |
| **0-RTT** | Not supported | Supported (replay risk) |

### TLS 1.3 Cipher Suites

```
# Only 5 cipher suites in TLS 1.3 — all are AEAD
TLS_AES_256_GCM_SHA384         # Most common
TLS_AES_128_GCM_SHA256         # Default in most configs
TLS_CHACHA20_POLY1305_SHA256   # Mobile-friendly, no AES-NI needed
TLS_AES_128_CCM_SHA256         # IoT / constrained devices
TLS_AES_128_CCM_8_SHA256       # IoT with 8-byte tag
```

### TLS Vulnerabilities Timeline

| CVE / Name | Year | Target | Impact |
|---|---|---|---|
| BEAST | 2011 | TLS 1.0 CBC | Decrypt cookies via chosen-boundary attack |
| CRIME/BREACH | 2012-13 | TLS compression | Recover secrets via compression side-channel |
| Heartbleed | 2014 | OpenSSL | Read server memory (keys, passwords) — 64KB per heartbeat |
| POODLE | 2014 | SSL 3.0 | Padding oracle decrypts traffic — killed SSL 3.0 |
| FREAK | 2015 | Export ciphers | Downgrade to 512-bit RSA — factorable |
| Logjam | 2015 | DHE export | Downgrade to 512-bit DH |
| ROBOT | 2017 | RSA PKCS#1 v1.5 | Bleichenbacher attack variant — decrypt TLS |
| Raccoon | 2020 | DH key exchange | Timing side-channel on DH shared secret |

> 🩸 **Heartbleed (CVE-2014-0160)**: A buffer over-read in OpenSSL's heartbeat extension let attackers read up to 64KB of server memory per request — potentially exposing private keys, session tokens, and passwords. Affected ~17% of all HTTPS servers. The fix was trivial (bounds check), but the impact was catastrophic. **Lesson:** Memory-safe languages and fuzzing catch these bugs.

---

## 09 — Password Security & Key Derivation

Passwords are the weakest link in most systems. Proper cryptographic handling of passwords is a critical skill for security engineers.

### The Password Hashing Problem

> ❌ **What NOT To Do**:
> - `SHA-256(password)` — Fast hashes let attackers try billions of guesses/second.
> - `SHA-256(password + salt)` — Better, but still too fast for password hashing.
> - `MD5(password)` — Broken hash + fast = worst of both worlds.

### Password Hashing Algorithms

| Algorithm | Year | Tunable | GPU Resistant | Status |
|---|---|---|---|---|
| **Argon2id** | 2015 | Time, memory, parallelism | ✅ YES | ✅ BEST — PHC winner |
| **bcrypt** | 1999 | Cost factor | ✅ Partially | ✅ GOOD — 72-byte input limit |
| **scrypt** | 2009 | CPU + memory | ✅ YES | ✅ GOOD — Memory-hard |
| **PBKDF2** | 2000 | Iteration count | ❌ NO | ⚠️ LEGACY — GPU-friendly |

### Argon2id — The Gold Standard

```python
import argon2

# Hash a password
hasher = argon2.PasswordHasher(
    time_cost=3,         # iterations
    memory_cost=65536,   # 64 MB
    parallelism=4,       # threads
    hash_len=32,         # output length
    type=argon2.Type.ID  # hybrid: resists side-channel + GPU
)
hashed = hasher.hash("user_password")
# $argon2id$v=19$m=65536,t=3,p=4$salt$hash

# Verify
try:
    hasher.verify(hashed, "user_password")
except argon2.exceptions.VerifyMismatchError:
    print("Invalid password")
```

### Key Derivation Functions (KDFs)

KDFs transform a password or shared secret into one or more cryptographic keys. They're different from password hashing — the goal is to produce keys, not just verify passwords.

| KDF | Input | Use Case |
|---|---|---|
| **HKDF** | High-entropy secret (e.g., DH output) | TLS key derivation, Signal Protocol |
| **PBKDF2** | Low-entropy password | Disk encryption (older), Wi-Fi WPA2 |
| **Argon2** | Low-entropy password | Password hashing + key derivation |
| **scrypt** | Low-entropy password | Cryptocurrency wallets, disk encryption |

### Salting — Why It Matters

A **salt** is a random value unique to each password hash. Without it, identical passwords produce identical hashes, enabling rainbow table attacks. With salting, each password must be attacked individually.

```
# Without salt → rainbow table attack
SHA256("password123") = ef92b778...  # Same hash for every user with this password

# With unique salt → each hash is unique
SHA256("a8f3e1" + "password123") = 7b2d91...  # User A
SHA256("c2b4d7" + "password123") = e4a1f3...  # User B — different hash!
```

---

## 10 — Cryptographic Attacks & Vulnerabilities

Understanding attacks is as important as understanding algorithms. Here's the attacker's playbook — these are the vulnerabilities and techniques that have broken real-world crypto.

### Attack Taxonomy

| Category | Attack | Target | Severity |
|---|---|---|---|
| **Brute Force** | Exhaustive key search | Short keys (DES 56-bit) | 🔴 HIGH |
| | Dictionary / Rainbow tables | Unsalted password hashes | 🔴 HIGH |
| **Mathematical** | Birthday attack | Hash collisions (128-bit hashes) | 🟠 MEDIUM |
| | Factoring (NFS) | RSA with small keys | 🔴 HIGH |
| | Pohlig-Hellman | Weak DH group parameters | 🔴 HIGH |
| **Side-Channel** | Timing attack | Key-dependent execution time | 🔴 HIGH |
| | Power analysis (DPA/SPA) | Hardware crypto (smart cards) | 🔴 HIGH |
| | Cache timing (Spectre) | Shared CPU cache | 🔴 HIGH |
| **Protocol** | Padding oracle | CBC mode encryption | 🔴 HIGH |
| | Downgrade attack | TLS version/cipher negotiation | 🔴 HIGH |
| | Replay attack | Protocols without nonces/timestamps | 🟠 MEDIUM |
| **Implementation** | Nonce reuse | AES-GCM, ChaCha20, ECDSA | 🔴 CRITICAL |

### Padding Oracle Attack — Deep Dive

One of the most elegant and devastating attacks. The attacker can decrypt **any** CBC-encrypted ciphertext by observing whether the server returns a "padding error" vs. other errors.

```
Padding Oracle Attack Flow:

Attacker sends modified ciphertext → Server decrypts → Checks padding
→ Returns "padding invalid" (different error or timing than "decryption ok")
→ Attacker learns 1 byte of plaintext per ~128 requests
→ Full plaintext recovery in ~256 × block_count requests
```

### Nonce Reuse — The Silent Killer

> 💀 **AES-GCM Nonce Reuse = Catastrophic Failure**:
> If the same (key, nonce) pair is ever reused in AES-GCM:
> 1. XOR of two ciphertexts reveals XOR of two plaintexts
> 2. Authentication key (GHASH) is fully recovered
> 3. Attacker can forge arbitrary authenticated messages
>
> **Real-world:** The PS3 ECDSA nonce reuse allowed extraction of Sony's private signing key, enabling pirated game signing. The PS Vita repeated the same mistake.

### Length Extension Attack

Affects Merkle–Damgård hashes (MD5, SHA-1, SHA-256): knowing `H(secret || message)` and the length of `secret`, an attacker can compute `H(secret || message || padding || extension)` without knowing the secret.

```
# Vulnerable pattern
mac = SHA256(secret_key + user_data)  # ← attacker can extend!

# Safe patterns
mac = HMAC_SHA256(secret_key, user_data)  # ← HMAC blocks extension
mac = SHA3_256(secret_key + user_data)    # ← SHA-3 (sponge) is immune
```

### Real-World Crypto Failures

| Incident | Root Cause | Impact |
|---|---|---|
| PS3 ECDSA hack (2010) | Static ECDSA nonce (used random() = 4) | Private signing key extracted |
| Debian OpenSSL (2008) | RNG seeded only with PID (15 bits) | All keys generated in 2 years were predictable |
| WEP cracking (2001) | Short IV (24 bits), RC4 key scheduling | Wi-Fi passwords cracked in minutes |
| Heartbleed (2014) | Missing bounds check in OpenSSL heartbeat | Server memory disclosure including private keys |
| ROCA (2017) | Infineon TPM generated weak RSA primes | RSA-2048 keys factorable for affected chips |

---

## 11 — Applied Cryptography — Real-World Protocols

Theory meets practice. Here's how cryptographic primitives combine into the protocols that secure billions of communications daily.

### Signal Protocol (End-to-End Encryption)

Used by Signal, WhatsApp, and Facebook Messenger. Considered the gold standard for secure messaging.

| Component | Crypto Used | Purpose |
|---|---|---|
| **X3DH** (Extended Triple DH) | Curve25519 | Initial key agreement (even if recipient is offline) |
| **Double Ratchet** | ECDH + HKDF + AES-256-CBC | Forward secrecy per-message, self-healing |
| **Sesame** | — | Multi-device session management |
| **Sealed Sender** | Encryption of sender identity | Metadata protection |

> 🔄 **Double Ratchet — Why It's Brilliant**: Each message uses a new encryption key derived from the previous state. Even if an attacker compromises a session key, they can only decrypt that single message — past messages (**forward secrecy**) and future messages (**post-compromise security**) remain safe because the ratchet advances.

### HTTPS / Web PKI in Practice

```
User types https://example.com
    ↓
DNS resolves → TCP connect → TLS 1.3 handshake begins
    ↓
Client sends ClientHello (supported ciphers, ECDHE key share)
Server sends ServerHello + Certificate (signed by CA) + ECDHE key share
    ↓
Client verifies: cert chain → root in trust store? → hostname match?
                 → not expired? → CT logs? → OCSP?
    ↓
Both derive session keys from ECDHE shared secret via HKDF
    ↓
Application data encrypted with AES-256-GCM
```

### Disk Encryption

| Solution | Cipher | Mode | KDF | Platform |
|---|---|---|---|---|
| LUKS (Linux) | AES-256 | XTS | Argon2id / PBKDF2 | Linux |
| BitLocker | AES-256 | XTS | TPM-backed | Windows |
| FileVault 2 | AES-256 | XTS | PBKDF2 | macOS |
| VeraCrypt | AES/Serpent/Twofish | XTS | PBKDF2/Argon2 | Cross-platform |

### Blockchain Cryptography

- **ECDSA (secp256k1)** — Transaction signing in Bitcoin and Ethereum
- **SHA-256 (double)** — Bitcoin proof-of-work and block hashing
- **Keccak-256** — Ethereum address generation and smart contract hashing
- **Merkle trees** — Efficient verification of transactions in a block
- **zk-SNARKs / zk-STARKs** — Zero-knowledge proofs for privacy (Zcash, zkSync)
- **BLS signatures** — Aggregate signatures in Ethereum 2.0 consensus

### Zero-Knowledge Proofs (ZKP)

A ZKP lets you prove you know something **without revealing what you know**. Three properties: **completeness** (honest prover convinces verifier), **soundness** (cheating prover can't convince), **zero-knowledge** (verifier learns nothing beyond the statement's truth).

| ZKP Type | Proof Size | Verification | Trusted Setup? | Used In |
|---|---|---|---|---|
| zk-SNARKs | ~200 bytes | Fast (ms) | Yes | Zcash, Filecoin |
| zk-STARKs | ~45 KB | Moderate | No | StarkNet, immutable X |
| Bulletproofs | ~700 bytes | Slow | No | Monero range proofs |
| PLONK | ~400 bytes | Fast | Universal | zkSync, Aztec |

---

## 12 — Post-Quantum Cryptography

Quantum computers running Shor's algorithm will break RSA, ECC, and Diffie-Hellman. Grover's algorithm halves symmetric key security. The industry is migrating now — NIST finalized post-quantum standards in 2024.

### What Quantum Computers Break

| Algorithm | Type | Quantum Impact | Action Required |
|---|---|---|---|
| RSA | Asymmetric | ❌ BROKEN by Shor's algorithm | Migrate to ML-KEM / ML-DSA |
| ECC (ECDH, ECDSA) | Asymmetric | ❌ BROKEN by Shor's algorithm | Migrate to ML-KEM / ML-DSA |
| Diffie-Hellman | Key exchange | ❌ BROKEN by Shor's algorithm | Migrate to ML-KEM |
| AES-128 | Symmetric | ⚠️ WEAKENED — Grover's → 64-bit security | Use AES-256 |
| AES-256 | Symmetric | ✅ SAFE — Grover's → 128-bit security | No change needed |
| SHA-256 | Hash | ✅ SAFE — Grover's → 128-bit security | No change needed |

### NIST Post-Quantum Standards (2024)

| Standard | Algorithm | Type | Based On | Key/Sig Size |
|---|---|---|---|---|
| **FIPS 203 (ML-KEM)** | CRYSTALS-Kyber | Key encapsulation | Lattice (M-LWE) | PK: 800–1.5 KB, CT: 768–1.5 KB |
| **FIPS 204 (ML-DSA)** | CRYSTALS-Dilithium | Digital signature | Lattice (M-LWE) | PK: 1.3 KB, Sig: 2.4 KB |
| **FIPS 205 (SLH-DSA)** | SPHINCS+ | Digital signature | Hash-based | PK: 32 B, Sig: 7–50 KB |

### Harvest Now, Decrypt Later (HNDL)

> ⏰ **The Urgent Threat**: Nation-state adversaries are **recording encrypted traffic today** to decrypt it when quantum computers become available. Data with long confidentiality requirements (government secrets, medical records, financial data) is already at risk. This is why migration to PQC must happen **now**, not when quantum computers arrive.

### Hybrid Key Exchange (Transition Strategy)

During the transition, combine classical and post-quantum algorithms so security holds even if one is broken:

```
# Chrome/Firefox TLS 1.3 hybrid key exchange (deployed since 2024)
X25519Kyber768Draft00:
  classical  = X25519 (ECDH)     # Proven, fast
  pq         = ML-KEM-768        # Post-quantum
  shared_key = HKDF(x25519_ss || ml_kem_ss)

# If ML-KEM is broken → X25519 still protects
# If X25519 is broken by quantum → ML-KEM still protects
```

---

## 13 — Common Crypto Mistakes & Hardening

Most cryptographic failures are not algorithm breaks — they're implementation mistakes. Here's the definitive list of what goes wrong and how to prevent it.

### The "Don't" List

| # | Mistake | Why It's Dangerous | Fix |
|---|---|---|---|
| 1 | Rolling your own crypto | Homegrown ciphers are never peer-reviewed | Use established libraries (libsodium, OpenSSL) |
| 2 | ECB mode | Leaks plaintext patterns | Use GCM or ChaCha20-Poly1305 |
| 3 | Nonce reuse in GCM | Complete authentication + confidentiality failure | Use random nonces or SIV mode |
| 4 | SHA-256 for passwords | Too fast — billions of guesses/second | Argon2id, bcrypt, scrypt |
| 5 | Encrypt without authenticate | Ciphertext can be modified undetected | AEAD (GCM, Poly1305) or Encrypt-then-MAC |
| 6 | Hardcoded keys / secrets | Exposed in source code, logs, binaries | Use KMS (AWS KMS, HashiCorp Vault) |
| 7 | Math.random() for crypto | Predictable PRNG | CSPRNG: /dev/urandom, secrets module |
| 8 | Comparing MACs with == | Timing attack leaks correct bytes | hmac.compare_digest() or constant-time compare |
| 9 | Ignoring key rotation | Long-lived keys increase blast radius | Rotate keys periodically, use key versioning |
| 10 | RSA without OAEP | PKCS#1 v1.5 vulnerable to Bleichenbacher | Use RSA-OAEP for encryption, RSA-PSS for signing |

### Encryption Order — MAC-then-Encrypt vs. Encrypt-then-MAC

| Order | Process | Security | Example |
|---|---|---|---|
| **Encrypt-then-MAC** | Encrypt plaintext, then MAC the ciphertext | ✅ SECURE | IPsec ESP |
| **MAC-then-Encrypt** | MAC plaintext, then encrypt both | ⚠️ RISKY | TLS ≤ 1.2 (padding oracle) |
| **Encrypt-and-MAC** | Encrypt plaintext, MAC plaintext | ❌ BROKEN | SSH (leaks info about plaintext) |
| **AEAD** | Single operation: encrypt + authenticate | ✅ BEST | AES-GCM, ChaCha20-Poly1305 |

### Hardening Checklist

#### ✅ Encryption
- Use AES-256-GCM or ChaCha20-Poly1305 (AEAD)
- Never reuse nonces — use random 96-bit nonces for GCM
- Rotate data encryption keys (DEKs) regularly
- Use envelope encryption: DEK encrypted by a KEK in KMS

#### ✅ Key Management
- Store keys in HSMs or cloud KMS (AWS KMS, GCP CMEK, Azure Key Vault)
- Implement key rotation with versioning
- Use separate keys per purpose (encryption, signing, MAC)
- Destroy keys securely — zero memory after use

#### ✅ TLS Configuration
- TLS 1.3 only (disable 1.0, 1.1, 1.2 if possible)
- ECDHE for key exchange (PFS mandatory)
- HSTS with preload, includeSubDomains
- Certificate pinning for mobile apps (or CT monitoring)
- Enable OCSP stapling

#### ✅ Passwords & Secrets
- Hash with Argon2id (time_cost=3, memory_cost=64MB)
- Minimum password length: 12 characters
- Store secrets in vaults (Vault, AWS Secrets Manager)
- Never log secrets, tokens, or keys

---

## 14 — Interview Questions & Model Answers

Five FAANG-style cryptography questions with detailed model answers. Use the STAR framework for scenario questions.

### Q1: System Design — "Design an end-to-end encrypted messaging system like Signal"

**Key Agreement:** Use X3DH (Extended Triple Diffie-Hellman) with Curve25519 for initial key exchange. Each user publishes identity keys, signed pre-keys, and one-time pre-keys to the server, enabling asynchronous key agreement even when the recipient is offline.

**Message Encryption:** Implement the Double Ratchet Algorithm. Each message gets a unique key derived from both a DH ratchet (new ECDH per message exchange) and a symmetric-key ratchet (HKDF chain). This provides forward secrecy and post-compromise security. Encrypt messages with AES-256-CBC + HMAC-SHA256 (or AES-256-GCM).

**Key Storage:** Store private keys in secure enclaves (SGX/TrustZone) or Keychain/Keystore. Never transmit private keys to the server.

**Server Role:** The server is a message relay and key distribution service. It never sees plaintext. Store only encrypted blobs. Implement sealed sender to hide metadata.

**Group Messaging:** Use Sender Keys — each member generates a chain key, distributes it to the group via pairwise Signal sessions. All members can decrypt without the server learning group membership patterns.

### Q2: Attack Analysis — "You find AES-GCM nonce reuse in production"

**Immediate Impact (Critical):**
- XOR of two ciphertexts encrypted with the same (key, nonce) reveals XOR of the two plaintexts — an attacker can recover plaintext with known-plaintext or crib-dragging
- The GHASH authentication key is fully recoverable — the attacker can forge authenticated ciphertexts for arbitrary plaintexts
- Both confidentiality and integrity are completely compromised

**Incident Response:** Immediately rotate all affected encryption keys. Identify all data encrypted with reused nonces (audit nonce generation logs). Assume affected ciphertext is compromised. Notify stakeholders per IR policy.

**Remediation:** Switch to random 96-bit nonces via CSPRNG. For high-volume systems, consider AES-GCM-SIV (nonce-misuse resistant) or XChaCha20-Poly1305 (192-bit nonce — negligible collision probability). Add monitoring to detect nonce reuse. Add code review gates for all crypto changes.

### Q3: Concepts — "Explain Perfect Forward Secrecy"

PFS ensures that compromising a server's long-term private key doesn't allow decryption of past recorded sessions. In TLS 1.2 with RSA key transport, the client encrypts the pre-master secret with the server's RSA public key. If the private key later leaks, every recorded session can be decrypted retroactively.

TLS 1.3 mandates ephemeral Diffie-Hellman (ECDHE). Each session generates a fresh key pair, derives session keys, then discards the ephemeral private key. Even if the server's long-term key is compromised, past sessions remain secure because the ephemeral keys no longer exist.

This directly counters the "harvest now, decrypt later" strategy used by nation-state adversaries. It's one of the most important changes in TLS 1.3 — RSA key transport was completely removed to enforce PFS.

### Q4: Practical — "How would you audit a crypto implementation?"

1. **Inventory:** Map all crypto usage — encryption (data at rest, in transit), hashing, signing, key storage, random number generation
2. **Algorithm review:** Verify no deprecated algorithms (DES, RC4, MD5, SHA-1). Check key sizes meet NIST recommendations (AES-256, RSA-2048+, P-256+)
3. **Mode of operation:** Confirm AEAD modes (GCM, Poly1305). Flag any ECB or unauthenticated CBC
4. **Key management:** Where are keys stored? (HSM/KMS vs. config files). Rotation policy? Separation of duties? Key per tenant/environment?
5. **RNG audit:** Verify all randomness uses CSPRNG. Check for seeding issues (e.g., low-entropy VM boots)
6. **Nonce handling:** Ensure nonces are unique per encryption operation. Check for counter overflow or predictable patterns
7. **Error handling:** Ensure crypto errors don't leak information (no padding oracles, no timing differences)
8. **Library review:** Is the crypto library maintained, up to date, and well-reviewed? (libsodium > hand-rolled OpenSSL wrappers)

### Q5: Emerging — "Create a post-quantum migration plan"

**Phase 1 — Inventory (Now):** Create a cryptographic Bill of Materials (CBOM). Catalog every algorithm, key size, and protocol in use. Identify high-value data with long confidentiality requirements (10+ years). These are most vulnerable to "harvest now, decrypt later."

**Phase 2 — Crypto Agility (Now):** Ensure systems can swap algorithms without major re-architecture. Abstract crypto behind interfaces. This is the most impactful engineering investment.

**Phase 3 — Hybrid Deployment (2024-2027):** Deploy hybrid key exchange (X25519 + ML-KEM-768) in TLS. Chrome, Firefox, and Cloudflare already support this. Both classical and PQC must be broken to compromise the session.

**Phase 4 — Full PQC Migration (2027+):** Transition to ML-KEM for key exchange, ML-DSA for signatures, and SLH-DSA as a conservative backup (hash-based, minimal assumptions). Update all certificates, VPNs, and internal services.

**Key consideration:** Symmetric algorithms (AES-256) and hash functions (SHA-256) are already quantum-safe at current key sizes. The urgent migration is for public-key cryptography.

---

*Prepared for Gayatri Rachakonda • April 2026 • FAANG Security Engineer Prep*
