"""Tests for the Go detector (requires tree-sitter-go)."""

import pytest
from pathlib import Path

from scanner.detectors.go_detector import GoDetector

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def go_detector():
    d = GoDetector()
    if d._parser is None:
        pytest.skip("tree-sitter Go not available")
    return d


def test_go_detector_imports(go_detector):
    path = FIXTURES_DIR / "sample.go"
    source = path.read_text(encoding="utf-8")
    findings = go_detector.detect(path, source)
    assert len(findings) >= 1
    primitives = {f.primitive for f in findings}
    libraries = {f.library for f in findings}
    assert "crypto/rsa" in primitives or "rsa" in libraries or any("rsa" in p for p in primitives)


def test_go_detector_rsa_generate_key(go_detector):
    source = '''
package main
import "crypto/rsa"
func main() {
    rsa.GenerateKey(nil, 2048)
}
'''
    findings = go_detector.detect(Path("main.go"), source)
    assert any("GenerateKey" in f.primitive or "rsa" in f.primitive for f in findings)


def test_go_detector_elliptic_p256(go_detector):
    source = '''
package main
import "crypto/elliptic"
func main() {
    elliptic.P256()
}
'''
    findings = go_detector.detect(Path("main.go"), source)
    assert any("P256" in f.primitive or "elliptic" in f.primitive for f in findings)
