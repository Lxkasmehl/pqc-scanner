"""
Abstract base class for language-specific cryptographic primitive detectors.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Confidence = Literal["high", "medium", "low"]


@dataclass
class Finding:
    """A single detected cryptographic primitive usage."""

    file: str
    line: int
    language: str
    primitive: str
    library: str
    snippet: str
    confidence: Confidence = "high"

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "language": self.language,
            "primitive": self.primitive,
            "library": self.library,
            "snippet": self.snippet,
            "confidence": self.confidence,
        }


class BaseDetector(ABC):
    """Base class for AST/tree-based detectors. Each language has one implementation."""

    language: str = ""

    @abstractmethod
    def detect(self, file_path: Path, source: str) -> list[Finding]:
        """
        Analyze source code and return a list of findings.
        :param file_path: Path to the file (for reporting).
        :param source: Full file content as string.
        :return: List of Finding objects.
        """
        pass
