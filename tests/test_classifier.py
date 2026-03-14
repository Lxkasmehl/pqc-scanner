"""Tests for scanner.classifier."""

import pytest
from scanner.classifier import (
    VULNERABLE,
    SAFE,
    PQC_READY,
    UNKNOWN,
    PRIMITIVE_CLASSIFICATION,
    classify_primitive,
    get_canonical_primitive_key,
    normalize_primitive_name,
)


def test_normalize_primitive_name():
    assert normalize_primitive_name("RSA") == "rsa"
    assert normalize_primitive_name("  SHA-256  ") == "sha256"
    assert normalize_primitive_name("P-256") == "p256"
    assert normalize_primitive_name("") == ""
    assert normalize_primitive_name("SHA256withRSA") == "sha256withrsa"


def test_classify_vulnerable():
    assert classify_primitive("RSA") == VULNERABLE
    assert classify_primitive("rsa") == VULNERABLE
    assert classify_primitive("ECDSA") == VULNERABLE
    assert classify_primitive("EC") == VULNERABLE
    assert classify_primitive("DiffieHellman") == VULNERABLE
    assert classify_primitive("P-256") == VULNERABLE
    assert classify_primitive("SHA256withRSA") == VULNERABLE


def test_classify_safe():
    assert classify_primitive("AES") == SAFE
    assert classify_primitive("SHA-256") == SAFE
    assert classify_primitive("SHA256") == SAFE
    assert classify_primitive("HMAC") == SAFE
    assert classify_primitive("ChaCha20") == SAFE


def test_classify_pqc_ready():
    assert classify_primitive("Kyber") == PQC_READY
    assert classify_primitive("Dilithium") == PQC_READY
    assert classify_primitive("SPHINCS+") == PQC_READY
    assert classify_primitive("liboqs") == PQC_READY


def test_classify_unknown():
    assert classify_primitive("CustomCipher") == UNKNOWN
    assert classify_primitive("") == UNKNOWN
    assert classify_primitive("xyz") == UNKNOWN


def test_primitive_classification_extensible():
    assert "rsa" in PRIMITIVE_CLASSIFICATION
    assert "aes" in PRIMITIVE_CLASSIFICATION
    assert "kyber" in PRIMITIVE_CLASSIFICATION


def test_get_canonical_primitive_key():
    # Duplicates merged for report aggregation
    assert get_canonical_primitive_key("RSA") == "rsa"
    assert get_canonical_primitive_key("ECDSA") == "ecdsa"
    assert get_canonical_primitive_key("ecdsa") == "ecdsa"
    assert get_canonical_primitive_key("crypto/rsa") == "rsa"
    assert get_canonical_primitive_key("crypto/ecdsa") == "ecdsa"
    assert get_canonical_primitive_key("rsa.GenerateKey") == "rsa"
    assert get_canonical_primitive_key("ecdsa.GenerateKey") == "ecdsa"
    assert get_canonical_primitive_key("elliptic.P256") == "ec"
    assert get_canonical_primitive_key("sphincs") == "sphincs+"
    assert get_canonical_primitive_key("sphincs+") == "sphincs+"
    assert get_canonical_primitive_key("DiffieHellman") == "diffiehellman"
    assert get_canonical_primitive_key("diffie_hellman") == "diffiehellman"
    assert get_canonical_primitive_key("crypto/tls") == "tls"
    assert get_canonical_primitive_key("crypto/x509") == "x509"
