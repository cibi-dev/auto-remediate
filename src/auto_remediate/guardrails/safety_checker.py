"""Guardrails agénticos estrictos para prevenir mutaciones destructivas o no autorizadas."""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from typing import Optional

PROTECTED_KEYWORDS = [
    "auth",
    "crypto",
    "migration",
    "jwt",
    "password",
    "login",
    "secret",
    "credential",
    "keys",
    "token",
]

DANGEROUS_CALLS = {"eval", "exec", "__import__", "compile"}


@dataclass
class GuardrailVerdict:
    """Veredicto estructurado de validación de seguridad agéntica."""

    is_allowed: bool
    status: str  # ALLOWED, BLOCKED_PROTECTED_PATH, BLOCKED_LINE_LIMIT_EXCEEDED, BLOCKED_SYNTAX_ERROR, BLOCKED_DANGEROUS_CALL
    reason: str


class SafetyGuardrails:
    """Validador estricto de rutas, sintaxis y contención de cambios para remediaciones automáticas."""

    def __init__(self, max_lines_changed: int = 15):
        self.max_lines_changed = max_lines_changed

    @staticmethod
    def is_file_protected(file_path: str) -> bool:
        """Determina si la ruta del archivo corresponde a módulos críticos protegidos."""
        norm = file_path.lower().replace(os.sep, "/")
        return any(keyword in norm for keyword in PROTECTED_KEYWORDS)

    def inspect_ast_safety(self, code: str) -> tuple[bool, Optional[str]]:
        """Analiza el árbol sintáctico (AST) para verificar validez y ausencia de llamadas prohibidas."""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, f"Error de sintaxis Python: {e}"

        # Comprobar llamadas a funciones peligrosas
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALLS:
                    return False, f"Inyección prohibida de función peligrosa '{node.func.id}()'"
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr == "system"
                ):
                    return False, "Inyección prohibida de 'os.system()'"

        return True, None

    def evaluate_patch(
        self,
        file_path: str,
        original_code: str,
        proposed_code: str,
    ) -> GuardrailVerdict:
        """Evalúa un parche propuesto contra todas las capas de guardrails.

        Args:
            file_path: Ruta del archivo afectado.
            original_code: Código original antes de la mutación.
            proposed_code: Código propuesto por el agente o fixer.

        Returns:
            GuardrailVerdict con el resultado de la auditoría.
        """
        # 1. Chequeo de ruta protegida
        if self.is_file_protected(file_path):
            return GuardrailVerdict(
                is_allowed=False,
                status="BLOCKED_PROTECTED_PATH",
                reason=f"Archivo '{file_path}' en ruta sensible protegida (auth, crypto, migration, etc.).",
            )

        # 2. Chequeo de sintaxis y llamadas prohibidas
        ast_ok, ast_err = self.inspect_ast_safety(proposed_code)
        if not ast_ok:
            if "sintaxis" in str(ast_err):
                return GuardrailVerdict(
                    is_allowed=False,
                    status="BLOCKED_SYNTAX_ERROR",
                    reason=ast_err or "Sintaxis inválida.",
                )
            return GuardrailVerdict(
                is_allowed=False,
                status="BLOCKED_DANGEROUS_CALL",
                reason=ast_err or "Llamada peligrosa detectada en AST.",
            )

        # 3. Límite de líneas modificadas
        orig_lines = original_code.splitlines()
        prop_lines = proposed_code.splitlines()
        diff_lines = abs(len(prop_lines) - len(orig_lines)) + sum(
            1 for o, p in zip(orig_lines, prop_lines) if o != p
        )

        if diff_lines > self.max_lines_changed:
            return GuardrailVerdict(
                is_allowed=False,
                status="BLOCKED_LINE_LIMIT_EXCEEDED",
                reason=f"El cambio ({diff_lines} líneas) excede el umbral seguro de {self.max_lines_changed} líneas.",
            )

        return GuardrailVerdict(
            is_allowed=True,
            status="ALLOWED",
            reason="El parche cumple con todos los guardrails agénticos de seguridad.",
        )
