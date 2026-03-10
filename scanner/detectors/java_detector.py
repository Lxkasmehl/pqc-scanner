"""
Java detector using tree-sitter. Detects javax.crypto, java.security, Bouncy Castle
and getInstance(...) usage with cryptographic algorithm strings.
"""
from __future__ import annotations

from pathlib import Path

from scanner.detectors.base import BaseDetector, Finding, Confidence

try:
    import tree_sitter
    from tree_sitter import Language, Parser, Node
    try:
        import tree_sitter_java as ts_java
        _JAVA_LANGUAGE = Language(ts_java.language())
    except ImportError:
        _JAVA_LANGUAGE = None
except ImportError:
    tree_sitter = None
    _JAVA_LANGUAGE = None

JAVA_IMPORT_PREFIXES = ("javax.crypto", "java.security", "org.bouncycastle")
GETINSTANCE_ALGOS = {
    "rsa", "ec", "ecdh", "diffiehellman", "dsa",
    "sha256withrsa", "sha384withrsa", "sha512withrsa",
    "sha256withecdsa", "sha384withecdsa", "sha512withecdsa",
    "aes", "sha-256", "sha-384", "sha-512",
}


def _get_text(source: bytes, node: "Node") -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _get_line_snippet(source: str, line_no: int) -> str:
    lines = source.splitlines()
    if 0 <= line_no - 1 < len(lines):
        return lines[line_no - 1].strip()
    return ""


def _find_string_literal_argument(source_bytes: bytes, node: "Node") -> str | None:
    """If node is a method_invocation, find first string literal argument and return its value (lowercase)."""
    if node.type != "method_invocation":
        return None
    # method_invocation has: object (optional), name, arguments
    for i in range(node.child_count):
        child = node.child(i)
        if child.type == "argument_list":
            # First argument that is a string
            for j in range(child.child_count):
                arg = child.child(j)
                if arg.type == "string_literal":
                    raw = _get_text(source_bytes, arg)
                    # Strip quotes and normalize
                    if len(raw) >= 2 and raw[0] in '"\'' and raw[-1] == raw[0]:
                        return raw[1:-1].strip().lower().replace("-", "").replace("/", "").replace(".", "")
                elif arg.type == "identifier":  # e.g. constant
                    return _get_text(source_bytes, arg).lower()
            break
    return None


def _node_line(node: "Node", source_bytes: bytes) -> int:
    """1-based line number of node start."""
    return source_bytes[: node.start_byte].count(b"\n") + 1


class _JavaVisitor:
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
                language="java",
                primitive=primitive,
                library=library,
                snippet=snippet,
                confidence=confidence,
            )
        )

    def _visit_node(self, node: "Node") -> None:
        if node.type == "import_declaration":
            # Scrape import path from children
            for i in range(node.child_count):
                c = node.child(i)
                if c.type == "scoped_identifier" or c.type == "identifier":
                    imp = _get_text(self.source_bytes, c).strip()
                    for prefix in JAVA_IMPORT_PREFIXES:
                        if imp.startswith(prefix) or prefix in imp:
                            line = _node_line(node, self.source_bytes)
                            self._add(
                                line,
                                imp,
                                imp.split(".")[0] if "." in imp else imp,
                                _get_line_snippet(self.source, line),
                                "medium",
                            )
                            break
            return
        if node.type == "method_invocation":
            name_node = None
            for i in range(node.child_count):
                c = node.child(i)
                if c.type == "identifier" and (name_node is None or c.type == "identifier"):
                    # Method name is often the last identifier (getInstance)
                    name_node = c
            if name_node is not None:
                method_name = _get_text(self.source_bytes, name_node)
                if method_name == "getInstance":
                    algo = _find_string_literal_argument(self.source_bytes, node)
                    if algo:
                        line = _node_line(node, self.source_bytes)
                        # Normalize for classification
                        self._add(
                            line,
                            algo,
                            "java.security/javax.crypto",
                            _get_line_snippet(self.source, line),
                            "high",
                        )
            return
        for i in range(node.child_count):
            self._visit_node(node.child(i))

    def run(self, root: "Node") -> list[Finding]:
        self._visit_node(root)
        return self.findings


class JavaDetector(BaseDetector):
    language = "java"

    def __init__(self):
        self._parser: Parser | None = None
        if tree_sitter and _JAVA_LANGUAGE:
            self._parser = Parser(_JAVA_LANGUAGE)
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
        visitor = _JavaVisitor(file_path, source)
        return visitor.run(tree.root_node)
