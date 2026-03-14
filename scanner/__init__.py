"""
PQC-Readiness Scanner: detects cryptographic primitives in source code
and classifies them as post-quantum-vulnerable, quantum-safe, or pqc-ready.
"""

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

__all__ = [
    "VULNERABLE",
    "SAFE",
    "PQC_READY",
    "UNKNOWN",
    "PRIMITIVE_CLASSIFICATION",
    "classify_primitive",
    "get_canonical_primitive_key",
    "normalize_primitive_name",
]
