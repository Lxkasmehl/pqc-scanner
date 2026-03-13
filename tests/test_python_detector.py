"""Tests for the Python detector."""

import pytest
from pathlib import Path

from scanner.detectors.python_detector import PythonDetector
from scanner.detectors.base import Confidence

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_python_detector_imports():
    detector = PythonDetector()
    path = FIXTURES_DIR / "sample.py"
    source = path.read_text(encoding="utf-8")
    findings = detector.detect(path, source)
    primitives = {f.primitive for f in findings}
    libraries = {f.library for f in findings}
    assert "cryptography" in str(primitives) or "serialization" in str(primitives) or "load_pem_private_key" in str(primitives)
    assert "RSA" in primitives or "RSA.generate" in primitives
    assert "ECC" in primitives or "ECC.generate" in primitives
    assert any(f.confidence in ("high", "medium") for f in findings)


def test_python_detector_rsa_generate():
    source = """
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
"""
    detector = PythonDetector()
    findings = detector.detect(Path("x.py"), source)
    assert any("RSA" in f.primitive and f.confidence == "high" for f in findings)


def test_python_detector_ecc():
    source = """
from Crypto.PublicKey import ECC
curve = ECC.generate(curve="P-256")
"""
    detector = PythonDetector()
    findings = detector.detect(Path("x.py"), source)
    assert any("ECC" in f.primitive for f in findings)


def test_python_detector_load_pem():
    source = """
from cryptography.hazmat.primitives.serialization import load_pem_private_key
key = load_pem_private_key(data, password=None)
"""
    detector = PythonDetector()
    findings = detector.detect(Path("x.py"), source)
    assert any("load_pem_private_key" in f.primitive for f in findings)


def test_python_detector_invalid_syntax_returns_empty():
    detector = PythonDetector()
    findings = detector.detect(Path("x.py"), "syntax error {{{")
    assert findings == []


def test_python_detector_value_error_returns_empty():
    detector = PythonDetector()
    source = """
    y = 20
    x = f\"{2:{y=}}\"
    """
    findings = detector.detect(Path("x.py"), source)
    assert findings == []


def test_python_detector_pqc_oqs_import():
    """PQC-ready: import oqs (pyoqs / Open Quantum Safe) is detected and classifies as PQC_READY."""
    from scanner.classifier import classify_primitive, PQC_READY
    detector = PythonDetector()
    path = FIXTURES_DIR / "pqc_sample.py"
    source = path.read_text(encoding="utf-8")
    findings = detector.detect(path, source)
    assert findings, "expected at least one finding from pqc_sample.py"
    oqs_findings = [f for f in findings if f.primitive == "oqs"]
    assert oqs_findings, "expected primitive 'oqs' from import oqs"
    for f in oqs_findings:
        assert classify_primitive(f.primitive) == PQC_READY
