"""
Repository scanner: walks a local repo, runs language detectors, and aggregates findings.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger

from scanner.classifier import classify_primitive
from scanner.detectors.base import Finding
from scanner.detectors.python_detector import PythonDetector

# Path segments that indicate test/vendor code (skip for main vulnerability summary when exclude_tests=True)
SKIP_DIRS = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        "testdata",
        "vendor",
        "node_modules",
        "third_party",
        ".git",
    }
)

EXT_TO_DETECTOR: dict[str, Any] = {
    ".py": PythonDetector(),
}


def _is_test_path(path: Path, repo_root: Path) -> bool:
    """True if any path segment (relative to repo_root) is in SKIP_DIRS."""
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return False
    parts = rel.parts
    return any(p in SKIP_DIRS for p in parts)


def _get_detector(ext: str):
    try:
        return EXT_TO_DETECTOR[ext]
    except KeyError:
        return None


def _register_java_detector():
    try:
        from scanner.detectors.java_detector import JavaDetector
        EXT_TO_DETECTOR[".java"] = JavaDetector()
    except ImportError:
        pass


def _register_go_detector():
    try:
        from scanner.detectors.go_detector import GoDetector
        EXT_TO_DETECTOR[".go"] = GoDetector()
    except ImportError:
        pass


def _register_c_liboqs_detector():
    try:
        from scanner.detectors.c_liboqs_detector import CLibOqsDetector
        d = CLibOqsDetector()
        EXT_TO_DETECTOR[".c"] = d
        EXT_TO_DETECTOR[".h"] = d
    except ImportError:
        pass


def scan_repository(
    repo_path: str | Path,
    exclude_tests: bool = True,
) -> dict[str, Any]:
    """
    Scan a local repository and return the aggregated result structure.
    """
    repo_path = Path(repo_path).resolve()
    if not repo_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {repo_path}")

    _register_java_detector()
    _register_go_detector()
    _register_c_liboqs_detector()

    language_stats = {"python": 0, "java": 0, "go": 0, "c": 0}
    findings_agg: list[dict[str, Any]] = []
    file_count = {"python": 0, "java": 0, "go": 0}

    progress_every = int(os.getenv("PQC_SCAN_PROGRESS", "0") or "0")
    scanned_files = 0

    for path in repo_path.rglob("*"):
        try:
            if not path.is_file():
                continue
        except OSError:
            continue  # skip symlinks, permission errors, long paths on Windows
        ext = path.suffix.lower()
        if ext == ".py":
            language_stats["python"] += 1
        elif ext == ".java":
            language_stats["java"] += 1
        elif ext == ".go":
            language_stats["go"] += 1
        elif ext in (".c", ".h"):
            language_stats["c"] += 1

        detector = _get_detector(ext)
        if detector is None:
            continue

        scanned_files += 1
        if progress_every > 0 and scanned_files % progress_every == 0:
            print(
                f"  [scan progress] {scanned_files} source files in {repo_path.name} ...",
                flush=True,
            )

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("Could not read {}: {}", path, e)
            continue

        try:
            raw_findings = detector.detect(path, source)
        except Exception as e:
            logger.warning("Could not parse {}: {}", path, e)
            continue

        is_test = _is_test_path(path, repo_path)
        file_count[detector.language] = file_count.get(detector.language, 0) + 1

        for f in raw_findings:
            classification = classify_primitive(f.primitive)
            findings_agg.append({
                "file": f.file,
                "line": f.line,
                "language": f.language,
                "primitive": f.primitive,
                "library": f.library,
                "classification": classification,
                "snippet": f.snippet,
                "confidence": f.confidence,
                "is_test_file": is_test,
            })

    total = len(findings_agg)
    vulnerable = sum(1 for r in findings_agg if r["classification"] == "post-quantum-vulnerable")
    safe = sum(1 for r in findings_agg if r["classification"] == "quantum-safe")
    pqc_ready = sum(1 for r in findings_agg if r["classification"] == "pqc-ready")

    if exclude_tests:
        findings_for_summary = [r for r in findings_agg if not r["is_test_file"]]
    else:
        findings_for_summary = findings_agg
    total_summary = len(findings_for_summary)
    vulnerable_summary = sum(1 for r in findings_for_summary if r["classification"] == "post-quantum-vulnerable")
    vulnerability_score = (vulnerable_summary / total_summary) if total_summary else 0.0

    return {
        "repo_path": str(repo_path),
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "language_stats": language_stats,
        "findings": findings_agg,
        "summary": {
            "total_findings": total,
            "vulnerable_count": vulnerable,
            "safe_count": safe,
            "pqc_ready_count": pqc_ready,
            "has_vulnerable_primitives": vulnerable > 0,
            "vulnerability_score": round(vulnerability_score, 4),
        },
    }
