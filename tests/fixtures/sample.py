# Synthetic Python snippet for detector tests
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey import RSA, ECC
import hashlib
import ssl

def keygen():
    key = RSA.generate(2048)
    return key

def load_key(pem_data):
    return serialization.load_pem_private_key(pem_data, password=None)

def ecc_curve():
    curve = ECC.generate(curve="P-256")
    return curve
