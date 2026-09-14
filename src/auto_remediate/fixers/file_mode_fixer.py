"""Fixer determinista basado en AST para remediación de archivos temporales inseguros (CWE-732)."""

from __future__ import annotations

import ast
from typing import Tuple


class _FileModeTransformer(ast.NodeTransformer):
    """Reemplaza `tempfile.mktemp` obsoleto y vulnerable por `tempfile.NamedTemporaryFile`."""

    def __init__(self):
        super().__init__()
        self.mutated = False

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        # Detectar tempfile.mktemp(...)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "tempfile":
                if node.func.attr == "mktemp":
                    node.func.attr = "NamedTemporaryFile"
                    # Asegurar delete=False si se usaba como ruta
                    has_delete = any(kw.arg == "delete" for kw in node.keywords)
                    if not has_delete:
                        node.keywords.append(ast.keyword(arg="delete", value=ast.Constant(value=False)))
                    self.mutated = True

        return node


class FileModeFixer:
    """Remediador determinista de vulnerabilidades de creación insegura de archivos."""

    @staticmethod
    def fix_code_ast(code: str) -> tuple[str, bool]:
        """Aplica transformación AST para reemplazar mktemp por NamedTemporaryFile.

        Args:
            code: Código fuente Python.

        Returns:
            Tupla (código_remediado, fue_modificado).
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return code, False

        transformer = _FileModeTransformer()
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)

        if transformer.mutated:
            return ast.unparse(new_tree), True
        return code, False
