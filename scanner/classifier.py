"""
Classification module for cryptographic primitives detected by the PQC-Readiness Scanner.
Maps primitive names/strings to post-quantum vulnerability categories.
"""

from typing import Literal

# Category constants
VULNERABLE = "post-quantum-vulnerable"  # RSA, ECDSA, ECDH, DH, ElGamal
SAFE = "quantum-safe"  # AES, SHA-2, SHA-3, ChaCha20, HMAC
PQC_READY = "pqc-ready"  # Kyber/ML-KEM, Dilithium/ML-DSA, SPHINCS+, NTRU, liboqs
UNKNOWN = "unknown"

Classification = Literal["post-quantum-vulnerable", "quantum-safe", "pqc-ready", "unknown"]

# Maps primitive names (case-insensitive key) to category. Easy to extend.
PRIMITIVE_CLASSIFICATION: dict[str, str] = {
    # Post-quantum vulnerable (public-key / key exchange)
    "rsa": VULNERABLE,
    "ecdsa": VULNERABLE,
    "ec": VULNERABLE,
    "ecdhe": VULNERABLE,
    "ecdh": VULNERABLE,
    "diffiehellman": VULNERABLE,
    "diffie_hellman": VULNERABLE,
    "dh": VULNERABLE,
    "elgamal": VULNERABLE,
    "dsa": VULNERABLE,
    "p-256": VULNERABLE,
    "p-384": VULNERABLE,
    "p-521": VULNERABLE,
    "p256": VULNERABLE,
    "p384": VULNERABLE,
    "p521": VULNERABLE,
    "secp256r1": VULNERABLE,
    "secp384r1": VULNERABLE,
    "secp521r1": VULNERABLE,
    "prime256v1": VULNERABLE,
    "ed25519": VULNERABLE,  # signature; not PQ-vulnerable in same way but often grouped
    "x25519": VULNERABLE,
    # Java getInstance strings
    "rsa/ecb/pkcs1padding": VULNERABLE,
    "rsa/ecb/oaepwithsha-1andmgf1padding": VULNERABLE,
    "rsa/ecb/oaepwithsha-256andmgf1padding": VULNERABLE,
    "sha256withrsa": VULNERABLE,
    "sha384withrsa": VULNERABLE,
    "sha512withrsa": VULNERABLE,
    "sha256withecdsa": VULNERABLE,
    "sha384withecdsa": VULNERABLE,
    "sha512withecdsa": VULNERABLE,
    "ecdh": VULNERABLE,
    # Quantum-safe (symmetric / hash)
    "aes": SAFE,
    "sha-256": SAFE,
    "sha-384": SAFE,
    "sha-512": SAFE,
    "sha256": SAFE,
    "sha384": SAFE,
    "sha512": SAFE,
    "sha2": SAFE,
    "sha3": SAFE,
    "shake": SAFE,
    "chacha20": SAFE,
    "chacha20-poly1305": SAFE,
    "hmac": SAFE,
    "hmac-sha256": SAFE,
    "hmac-sha384": SAFE,
    "hmac-sha512": SAFE,
    "pbkdf2": SAFE,
    "aes/gcm/nopadding": SAFE,
    "aes/cbc/pkcs5padding": SAFE,
    # PQC-ready (NIST ML-KEM / ML-DSA and variants)
    "kyber": PQC_READY,
    "kyber512": PQC_READY,
    "kyber768": PQC_READY,
    "kyber1024": PQC_READY,
    "ml-kem": PQC_READY,
    "mlkem": PQC_READY,
    "dilithium": PQC_READY,
    "dilithium2": PQC_READY,
    "dilithium3": PQC_READY,
    "dilithium5": PQC_READY,
    "ml-dsa": PQC_READY,
    "mldsa": PQC_READY,
    "sphincs": PQC_READY,
    "sphincs+": PQC_READY,
    "ntru": PQC_READY,
    "frodo": PQC_READY,
    "saber": PQC_READY,
    "liboqs": PQC_READY,
    "oqs": PQC_READY,
}


def normalize_primitive_name(name: str) -> str:
    """Normalize primitive name for lookup: lowercase, strip, replace spaces with underscores."""
    if not name or not isinstance(name, str):
        return ""
    return name.strip().lower().replace(" ", "_").replace("-", "").replace(".", "")


def classify_primitive(primitive_name: str) -> str:
    """
    Classify a primitive name into one of: VULNERABLE, SAFE, PQC_READY, UNKNOWN.
    Uses PRIMITIVE_CLASSIFICATION with normalized key; returns UNKNOWN if not found.
    """
    if not primitive_name:
        return UNKNOWN
    key = normalize_primitive_name(primitive_name)
    if key in PRIMITIVE_CLASSIFICATION:
        return PRIMITIVE_CLASSIFICATION[key]
    return UNKNOWN
