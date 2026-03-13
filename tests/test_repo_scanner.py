"""Tests for repo scanner; includes end-to-end PQC-ready detection."""

import pytest
from pathlib import Path

from scanner.repo_scanner import scan_repository

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_scan_repository_detects_pqc_ready():
    """
    Full pipeline: scan a directory containing PQC usage (Kyber/Dilithium/oqs)
    and assert at least one finding is classified as PQC_READY.
    This validates that the scanner would report PQC-ready primitives if present.
    """
    result = scan_repository(FIXTURES_DIR, exclude_tests=False)
    pqc_findings = [f for f in result["findings"] if f["classification"] == "pqc-ready"]
    assert result["summary"]["pqc_ready_count"] >= 1, (
        "Scanner must detect PQC-ready primitives (e.g. oqs, Kyber, Dilithium) in fixtures; "
        "got 0 – check detectors and classifier."
    )
    assert any(f["primitive"] in ("oqs", "kyber", "dilithium") for f in pqc_findings), (
        "Expected at least one PQC finding with primitive oqs, kyber, or dilithium."
    )
