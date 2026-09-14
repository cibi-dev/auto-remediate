"""Fixer determinista basado en AST para inyectar timeouts en llamadas de red (CWE-400)."""

from __future__ import annotations

import ast
from typing import Tuple


class _TimeoutTransformer(ast.NodeTransformer):
    """Inserta el argumento `timeout=10.0` en llamadas a requests y httpx si no está presente."""

    def __init__(self, default_timeout: float = 10.0):
        super().__init__()
        self.default_timeout = default_timeout
        self.mutated = False

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        # Detectar llamadas tipo requests.get, requests.post, httpx.get, client.get, etc.
        target_methods = {"get", "post", "put", "delete", "patch", "head", "options", "request"}
        is_http_call = False

        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            if method_name in target_methods:
                if isinstance(node.func.value, ast.Name):
                    caller = node.func.value.id.lower()
                    if caller in ("requests", "httpx", "client", "session"):
                        is_http_call = True
                elif isinstance(node.func.value, ast.Attribute):
                    # ej. client.session.get
                    is_http_call = True

        if not is_http_call:
            return node

        # Verificar si ya tiene el parámetro timeout
        has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
        if not has_timeout:
            timeout_kw = ast.keyword(
                arg="timeout",
                value=ast.Constant(value=self.default_timeout),
            )
            node.keywords.append(timeout_kw)
            self.mutated = True

        return node


class TimeoutFixer:
    """Remediador determinista de llamadas HTTP sin timeout para prevenir denegación de servicio (DoS)."""

    @staticmethod
    def fix_code_ast(code: str, default_timeout: float = 10.0) -> tuple[str, bool]:
        """Aplica transformación AST inyectando timeout en llamadas requests/httpx.

        Args:
            code: Código fuente Python.
            default_timeout: Valor de tiempo de espera en segundos.

        Returns:
            Tupla (código_remediado, fue_modificado).
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return code, False

        transformer = _TimeoutTransformer(default_timeout=default_timeout)
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)

        if transformer.mutated:
            return ast.unparse(new_tree), True
        return code, False
