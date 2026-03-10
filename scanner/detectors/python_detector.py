"""
Python detector using the built-in ast module.
Detects imports and API calls for cryptographic libraries.
"""

import ast
from pathlib import Path
from scanner.detectors.base import BaseDetector, Finding, Confidence


# Libraries we care about and their canonical name for reporting
CRYPTO_LIBRARIES = {
    "cryptography",
    "Crypto",
    "Crypto.Cipher",
    "Crypto.PublicKey",
    "Crypto.Hash",
    "ssl",
    "hashlib",
    "hmac",
    "rsa",
    "ecdsa",
}

# (module_or_attr_path, primitive_name) for high-confidence API detection
# e.g. ("Crypto.PublicKey.RSA", "RSA") -> primitive "RSA"
API_SIGNATURES = [
    # PyCryptodome / PyCrypto
    (("RSA", "generate"), "RSA.generate"),
    (("RSA", "import_key"), "RSA.import_key"),
    (("ECC",), "ECC"),
    (("ECC", "generate"), "ECC.generate"),
    (("ECDSA",), "ECDSA"),
    (("DSA",), "DSA"),
    (("DSA", "generate"), "DSA.generate"),
    (("DiffieHellman",), "DiffieHellman"),
    (("ElGamal",), "ElGamal"),
    # cryptography.io
    (("serialization", "load_pem_private_key"), "load_pem_private_key"),
    (("serialization", "load_der_private_key"), "load_der_private_key"),
    (("serialization", "load_pem_public_key"), "load_pem_public_key"),
    (("serialization", "load_der_public_key"), "load_der_public_key"),
]


def _attr_chain(node: ast.AST) -> tuple[str, ...]:
    """Return (a, b, c) for a.b.c."""
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        base = _attr_chain(node.value)
        return base + (node.attr,)
    return ()


def _get_line_snippet(source: str, line_no: int) -> str:
    """Return the line at line_no (1-based), stripped."""
    lines = source.splitlines()
    if 0 <= line_no - 1 < len(lines):
        return lines[line_no - 1].strip()
    return ""


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source: str):
        self.file_path = file_path
        self.source = source
        self.findings: list[Finding] = []
        self._imported: set[str] = set()  # names brought into scope (e.g. RSA, ECC)

    def _add(self, line: int, primitive: str, library: str, snippet: str, confidence: Confidence):
        self.findings.append(
            Finding(
                file=str(self.file_path),
                line=line,
                language="python",
                primitive=primitive,
                library=library,
                snippet=snippet or _get_line_snippet(self.source, line),
                confidence=confidence,
            )
        )

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            mod = alias.name
            for lib in CRYPTO_LIBRARIES:
                if mod == lib or mod.startswith(lib + "."):
                    self._imported.add(name.split(".")[0])
                    self._add(
                        node.lineno,
                        mod,
                        mod.split(".")[0],
                        f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""),
                        "medium",
                    )
                    break
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module is None:
            self.generic_visit(node)
            return
        mod = node.module
        for lib in CRYPTO_LIBRARIES:
            if mod == lib or mod.startswith(lib + "."):
                for alias in node.names:
                    name = alias.asname or alias.name
                    self._imported.add(name)
                    self._add(
                        node.lineno,
                        f"{mod}.{alias.name}",
                        mod.split(".")[0],
                        f"from {mod} import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""),
                        "medium",
                    )
                break
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        chain = _attr_chain(node.func)
        if not chain:
            self.generic_visit(node)
            return

        for attr_chain, primitive in API_SIGNATURES:
            if len(chain) >= len(attr_chain) and chain[-len(attr_chain) :] == attr_chain:
                lib = chain[0] if chain else "unknown"
                self._add(
                    node.lineno,
                    primitive,
                    lib,
                    _get_line_snippet(self.source, node.lineno),
                    "high",
                )
                break

        # ECC(curve='P-256') or ECC.generate(curve=...)
        if chain and chain[-1] == "ECC":
            lib = chain[0] if len(chain) > 1 else "Crypto.PublicKey"
            self._add(
                node.lineno,
                "ECC",
                lib,
                _get_line_snippet(self.source, node.lineno),
                "high",
            )
        if len(chain) >= 2 and chain[-2] == "ECC" and chain[-1] == "generate":
            lib = chain[0] if len(chain) > 2 else "Crypto.PublicKey"
            self._add(
                node.lineno,
                "ECC.generate",
                lib,
                _get_line_snippet(self.source, node.lineno),
                "high",
            )

        self.generic_visit(node)


class PythonDetector(BaseDetector):
    language = "python"

    def detect(self, file_path: Path, source: str) -> list[Finding]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        visitor = _PythonVisitor(file_path, source)
        visitor.visit(tree)
        return visitor.findings
