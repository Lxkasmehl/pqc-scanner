"""
Go detector using tree-sitter. Detects crypto/rsa, crypto/ecdsa, crypto/elliptic,
crypto/dh, golang.org/x/crypto and function calls like rsa.GenerateKey, ecdsa.GenerateKey, elliptic.P256.
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

GO_IMPORT_PREFIXES = (
    "crypto/rsa", "crypto/ecdsa", "crypto/elliptic", "crypto/dh", "golang.org/x/crypto",
    "github.com/open-quantum-safe/liboqs-go",  # PQC: Kyber, Dilithium via liboqs
)
# Import path substring → primitive for PQC (so classifier maps to PQC_READY)
GO_PQC_IMPORT_PRIMITIVE = "oqs"
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

    def _visit_node(self, node: "Node") -> None:
        if node.type == "import_declaration":
            # import ( "path" ) or import "path"
            for i in range(node.child_count):
                c = node.child(i)
                if c.type == "import_spec":
                    path_node = c.child_by_field_name("path")
                    if path_node is None:
                        for j in range(c.child_count):
                            if c.child(j).type == "string_literal":
                                path_node = c.child(j)
                                break
                    if path_node is not None:
                        raw = _get_text(self.source_bytes, path_node)
                        if len(raw) >= 2:
                            path = raw[1:-1].strip()
                            for prefix in GO_IMPORT_PREFIXES:
                                if path == prefix or path.startswith(prefix + "/"):
                                    line = _node_line(node, self.source_bytes)
                                    # PQC lib: report canonical primitive for classifier
                                    primitive = GO_PQC_IMPORT_PRIMITIVE if "liboqs-go" in path or "open-quantum-safe" in path else path
                                    lib = path.split("/")[0] if "/" in path else path
                                    self._add(
                                        line,
                                        primitive,
                                        lib,
                                        _get_line_snippet(self.source, line),
                                        "medium",
                                    )
                                    break
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
