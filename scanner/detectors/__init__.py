"""
Detectors for cryptographic primitives in Python, Java, and Go source code.
"""

from scanner.detectors.base import BaseDetector, Finding, Confidence
from scanner.detectors.python_detector import PythonDetector

__all__ = ["BaseDetector", "Finding", "Confidence", "PythonDetector"]

try:
    from scanner.detectors.java_detector import JavaDetector
    __all__.append("JavaDetector")
except ImportError:
    JavaDetector = None  # type: ignore

try:
    from scanner.detectors.go_detector import GoDetector
    __all__.append("GoDetector")
except ImportError:
    GoDetector = None  # type: ignore
