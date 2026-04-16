"""
Go detector using tree-sitter. Detects crypto/rsa, crypto/ecdsa, crypto/elliptic,
crypto/dh, crypto/tls, crypto/x509, golang.org/x/crypto and function calls like
rsa.GenerateKey, ecdsa.GenerateKey, elliptic.P256.

Methodologic note: Many Go services use TLS (crypto/tls) or X.509 (crypto/x509)
with RSA/ECDSA certificates without explicit key generation in code. Import-based
detection of crypto/tls and crypto/x509 is therefore included and classified as
post-quantum-vulnerable (medium confidence) for the paper.
"""
from __future__ import annotations

from pathlib import Path

from scanner.detectors.base import BaseDetector, Finding, Confidence

try:
    import tree_sitter
    from tree_sitter import Language, Parser, Node
    try:
        import tree_sitter_go as ts_go
        _GO_LANGUAGE = Language(ts_go.language())
    except ImportError:
        _GO_LANGUAGE = None
except ImportError:
    tree_sitter = None
    _GO_LANGUAGE = None

# Import path -> (primitive for report, confidence). Order matters: check specific before prefixes.
GO_IMPORT_PRIMITIVE_MAP: list[tuple[str, str, str]] = [
    # PQC: Cloudflare CIRCL (KEM/sign subpackages; listed before broad x/crypto)
    ("github.com/cloudflare/circl/kem/kyber", "kyber", "medium"),
    ("github.com/cloudflare/circl/pqc/", "kyber", "medium"),
    ("github.com/cloudflare/circl/sign/dilithium", "dilithium", "medium"),
    ("github.com/cloudflare/circl/sign/mldsa", "mldsa", "medium"),
    ("github.com/cloudflare/circl/sign/sphincs", "sphincs", "medium"),
    # PQC: Tink Go v2 (public + internal PQ packages; module uses mldsa/slhdsa not ml_dsa)
    ("github.com/tink-crypto/tink-go/v2/signature/mldsa", "mldsa", "medium"),
    ("github.com/tink-crypto/tink-go/v2/signature/slhdsa", "sphincs", "medium"),
    ("github.com/tink-crypto/tink-go/v2/internal/signature/mldsa", "mldsa", "medium"),
    ("github.com/tink-crypto/tink-go/v2/internal/signature/slhdsa", "sphincs", "medium"),
    # PQC (report as oqs for classifier)
    ("github.com/open-quantum-safe/liboqs-go", "oqs", "medium"),
    ("github.com/open-quantum-safe/", "oqs", "medium"),
    # Classic PKI: explicit packages
    ("crypto/rsa", "crypto/rsa", "medium"),
    ("crypto/ecdsa", "crypto/ecdsa", "medium"),
    ("crypto/elliptic", "crypto/elliptic", "medium"),
    ("crypto/dh", "crypto/dh", "medium"),
    # TLS/X.509: implies RSA/ECDSA certs in practice (methodologic note in paper)
    ("crypto/tls", "tls", "medium"),
    ("crypto/x509", "x509", "medium"),
    # Catch-all for golang.org/x/crypto (may include classic or PQC)
    ("golang.org/x/crypto", "golang.org/x/crypto", "low"),
]
# (selector, func_name) -> primitive for high confidence
GO_CALL_SIGNATURES = [
    (("rsa", "GenerateKey"), "rsa.GenerateKey"),
    (("rsa", "EncryptPKCS1v15"), "rsa.EncryptPKCS1v15"),
    (("rsa", "DecryptPKCS1v15"), "rsa.DecryptPKCS1v15"),
    (("rsa", "SignPKCS1v15"), "rsa.SignPKCS1v15"),
    (("rsa", "VerifyPKCS1v15"), "rsa.VerifyPKCS1v15"),
    (("ecdsa", "GenerateKey"), "ecdsa.GenerateKey"),
    (("ecdsa", "Sign"), "ecdsa.Sign"),
    (("ecdsa", "Verify"), "ecdsa.Verify"),
    (("elliptic", "P256"), "elliptic.P256"),
    (("elliptic", "P384"), "elliptic.P384"),
    (("elliptic", "P521"), "elliptic.P521"),
]


def _get_text(source: bytes, node: "Node") -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _get_line_snippet(source: str, line_no: int) -> str:
    lines = source.splitlines()
    if 0 <= line_no - 1 < len(lines):
        return lines[line_no - 1].strip()
    return ""


def _node_line(node: "Node", source_bytes: bytes) -> int:
    return source_bytes[: node.start_byte].count(b"\n") + 1


def _selector_chain(node: "Node", source_bytes: bytes) -> tuple[str, ...]:
    """For a call like a.b.c(...), return ('a','b','c')."""
    if node.type == "identifier":
        return (_get_text(source_bytes, node),)
    if node.type == "selector_expression":
        # selector_expression: operand . field
        operand = node.child(0)
        field = node.child_by_field_name("field")
        if field is None and node.child_count >= 3:
            field = node.child(2)  # . field
        base = _selector_chain(operand, source_bytes) if operand else ()
        if field is not None:
            return base + (_get_text(source_bytes, field),)
        return base
    return ()


class _GoVisitor:
    def __init__(self, file_path: Path, source: str):
        self.file_path = file_path
        self.source = source
        self.source_bytes = source.encode("utf-8")
        self.findings: list[Finding] = []

    def _add(self, line: int, primitive: str, library: str, snippet: str, confidence: Confidence):
        self.findings.append(
            Finding(
                file=str(self.file_path),
                line=line,
                language="go",
                primitive=primitive,
                library=library,
                snippet=snippet,
                confidence=confidence,
            )
        )

    def _import_path_from_spec(self, spec: "Node") -> str | None:
        """Resolve import path string from an import_spec node (grouped or single import)."""
        path_node = spec.child_by_field_name("path")
        if path_node is None:
            for j in range(spec.child_count):
                t = spec.child(j).type
                if t in ("string_literal", "interpreted_string_literal"):
                    path_node = spec.child(j)
                    break
        if path_node is None:
            return None
        raw = _get_text(self.source_bytes, path_node)
        if len(raw) < 2:
            return None
        # Go uses double-quoted import paths; strip quotes
        if raw[0] in '"\'' and raw[-1] == raw[0]:
            return raw[1:-1].strip()
        return raw.strip()

    def _visit_import_specs_recursive(self, node: "Node") -> None:
        """Grouped imports nest import_spec under import_spec_list; walk the full subtree."""
        if node.type == "import_spec":
            path = self._import_path_from_spec(node)
            if not path:
                return
            for prefix, primitive, confidence in GO_IMPORT_PRIMITIVE_MAP:
                p = prefix.rstrip("/")
                if path == p or path.startswith(p + "/"):
                    line = _node_line(node, self.source_bytes)
                    lib = path.split("/")[0] if "/" in path else path
                    self._add(
                        line,
                        primitive,
                        lib,
                        _get_line_snippet(self.source, line),
                        confidence,
                    )
                    break
            return
        for i in range(node.child_count):
            self._visit_import_specs_recursive(node.child(i))

    def _visit_node(self, node: "Node") -> None:
        if node.type == "import_declaration":
            # import "x" or import ( "a" "b" ) — specs may be under import_spec_list
            self._visit_import_specs_recursive(node)
            return
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func is None and node.child_count > 0:
                func = node.child(0)
            if func is not None:
                chain = _selector_chain(func, self.source_bytes)
                for (sel_chain, primitive) in GO_CALL_SIGNATURES:
                    if len(chain) >= len(sel_chain) and chain[-len(sel_chain):] == sel_chain:
                        line = _node_line(node, self.source_bytes)
                        lib = chain[0] if chain else "crypto"
                        self._add(
                            line,
                            primitive,
                            lib,
                            _get_line_snippet(self.source, line),
                            "high",
                        )
                        break
            return
        for i in range(node.child_count):
            self._visit_node(node.child(i))

    def run(self, root: "Node") -> list[Finding]:
        self._visit_node(root)
        return self.findings


class GoDetector(BaseDetector):
    language = "go"

    def __init__(self):
        self._parser: Parser | None = None
        if tree_sitter and _GO_LANGUAGE:
            self._parser = Parser(_GO_LANGUAGE)
        else:
            self._parser = None

    def detect(self, file_path: Path, source: str) -> list[Finding]:
        if self._parser is None:
            return []
        try:
            tree = self._parser.parse(source.encode("utf-8"))
        except Exception:
            return []
        if tree.root_node is None or tree.root_node.has_error:
            return []
        visitor = _GoVisitor(file_path, source)
        return visitor.run(tree.root_node)
