"""
Lightweight liboqs (C API) markers for open-quantum-safe/liboqs-style repositories.

Full C parsing is out of scope; this only flags obvious OQS usage so repo-level
has_pqc_ready can match the curated ground truth for the C core library.
"""
from __future__ import annotations

from pathlib import Path

from scanner.detectors.base import BaseDetector, Finding


class CLibOqsDetector(BaseDetector):
    language = "c"

    def detect(self, file_path: Path, source: str) -> list[Finding]:
        if "OQS_" not in source and "oqs.h" not in source.lower():
            return []
        # Strong signals from liboqs public API / headers
        strong = (
            "OQS_KEM_new",
            "OQS_SIG_new",
            "OQS_init",
            "oqs/oqs.h",
            "oqs\\oqs.h",
            "OQS_SUCCESS",
        )
        if not any(s in source for s in strong):
            return []
        line_no = 1
        snippet = ""
        for i, line in enumerate(source.splitlines(), 1):
            if "OQS_" in line or "oqs.h" in line.lower():
                line_no = i
                snippet = line.strip()[:200]
                break
        return [
            Finding(
                file=str(file_path),
                line=line_no,
                language="c",
                primitive="oqs",
                library="liboqs",
                snippet=snippet or "(liboqs C API)",
                confidence="medium",
            )
        ]
