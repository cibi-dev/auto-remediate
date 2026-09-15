"""Fixer determinista basado en AST para neutralizar inyecciones de comandos en subprocess."""

from __future__ import annotations

import ast
import shlex
from typing import Optional


class _SubprocessTransformer(ast.NodeTransformer):
    """Transforma llamadas de subprocess con shell=True a llamadas seguras shell=False con argumentos tokenizados."""

    def __init__(self):
        super().__init__()
        self.mutated = False

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        # Detectar subprocess.<func>
        is_subprocess = False
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                    is_subprocess = True

        if not is_subprocess:
            return node

        # 1. Buscar si tiene keyword shell=True
        shell_kw = None
        for kw in node.keywords:
            if kw.arg == "shell":
                shell_kw = kw
                break

        if shell_kw is not None:
            # Si shell es True, cambiar a False o remover
            if isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is True:
                shell_kw.value = ast.Constant(value=False)
                self.mutated = True

        # 2. Si el primer argumento es una cadena constante literal (ej. "ls -la /tmp"),
        # transformarlo a una lista de constantes ["ls", "-la", "/tmp"]
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            cmd_str = node.args[0].value.strip()
            try:
                tokens = shlex.split(cmd_str)
                if len(tokens) > 1:
                    node.args[0] = ast.List(
                        elts=[ast.Constant(value=tok) for tok in tokens],
                        ctx=ast.Load(),
                    )
                    self.mutated = True
            except Exception:
                pass

        return node


class SubprocessFixer:
    """Remediador determinista de vulnerabilidades CWE-78 en llamadas a subprocess."""

    @staticmethod
    def fix_code_ast(code: str) -> tuple[str, bool]:
        """Aplica transformación formal en el árbol AST de Python.

        Args:
            code: Código fuente Python.

        Returns:
            Tupla (código_remediado, fue_modificado).
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return code, False

        transformer = _SubprocessTransformer()
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)

        if transformer.mutated:
            return ast.unparse(new_tree), True
        return code, False
