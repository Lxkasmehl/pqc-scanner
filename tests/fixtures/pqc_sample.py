# Fixture for PQC-ready detection: Open Quantum Safe (pyoqs) – Kyber, Dilithium
import oqs

def kem_example():
    kem = oqs.KeyEncapsulation("Kyber512")
    public_key = kem.generate_keypair()
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret
