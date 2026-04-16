"""Tests for minimal liboqs C API marker detector."""

from pathlib import Path

from scanner.classifier import PQC_READY, classify_primitive
from scanner.detectors.c_liboqs_detector import CLibOqsDetector


def test_c_liboqs_marker():
    d = CLibOqsDetector()
    src = """
#include <oqs/oqs.h>
void f(void) {
    OQS_KEM *kem = OQS_KEM_new("Kyber512");
}
"""
    findings = d.detect(Path("k.c"), src)
    assert findings
    assert classify_primitive(findings[0].primitive) == PQC_READY


def test_c_liboqs_negative():
    d = CLibOqsDetector()
    assert d.detect(Path("x.c"), "int main() { return 0; }") == []
