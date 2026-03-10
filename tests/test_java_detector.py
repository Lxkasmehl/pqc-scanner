"""Tests for the Java detector (requires tree-sitter-java)."""

import pytest
from pathlib import Path

from scanner.detectors.java_detector import JavaDetector

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def java_detector():
    d = JavaDetector()
    if d._parser is None:
        pytest.skip("tree-sitter Java not available")
    return d


def test_java_detector_imports(java_detector):
    path = FIXTURES_DIR / "sample.java"
    source = path.read_text(encoding="utf-8")
    findings = java_detector.detect(path, source)
    # Should detect javax.crypto, java.security
    assert len(findings) >= 1
    libraries = {f.library for f in findings}
    primitives = {f.primitive for f in findings}
    assert any("crypto" in lib or "security" in lib for lib in libraries) or len(primitives) >= 1


def test_java_detector_get_instance_rsa(java_detector):
    source = '''
import java.security.KeyPairGenerator;
class X {
    void m() throws Exception {
        KeyPairGenerator.getInstance("RSA");
    }
}
'''
    findings = java_detector.detect(Path("X.java"), source)
    assert any("rsa" in f.primitive.lower() for f in findings)


def test_java_detector_get_instance_ec(java_detector):
    source = '''
class Y {
    void m() throws Exception {
        java.security.KeyPairGenerator.getInstance("EC");
    }
}
'''
    findings = java_detector.detect(Path("Y.java"), source)
    assert any("ec" in f.primitive.lower() for f in findings)
