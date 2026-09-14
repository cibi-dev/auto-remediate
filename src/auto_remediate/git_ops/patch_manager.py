"""Gestor de parches deterministas, validación con guardrails y operaciones GitOps."""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Optional

from auto_remediate.classifier.triage_engine import TriagedFinding
from auto_remediate.fixers.file_mode_fixer import FileModeFixer
from auto_remediate.fixers.subprocess_fixer import SubprocessFixer
from auto_remediate.fixers.timeout_fixer import TimeoutFixer
from auto_remediate.guardrails.safety_checker import SafetyGuardrails
from auto_remediate.schemas import PatchProposal


class PatchManager:
    """Genera, audita con guardrails agénticos y aplica parches deterministas a código vulnerable."""

    def __init__(self, guardrails: Optional[SafetyGuardrails] = None):
        self.guardrails = guardrails or SafetyGuardrails()

    def generate_proposal(self, triaged: TriagedFinding) -> PatchProposal:
        """Crea una propuesta formal de parche validada por AST y guardrails.

        Args:
            triaged: Hallazgo clasificado por el motor de triaje.

        Returns:
            PatchProposal con snippets, diff unificado y veredicto de seguridad.
        """
        f = triaged.finding
        target_path = Path(f.file_path)

        if not target_path.exists():
            return PatchProposal(
                finding_id=f.id,
                target_file=f.file_path,
                original_snippet="",
                proposed_snippet="",
                diff="",
                is_safe=False,
                guardrail_status="FILE_NOT_FOUND",
            )

        original_code = target_path.read_text(encoding="utf-8")
        proposed_code = original_code
        mutated = False

        # Aplicar el fixer correspondiente
        if triaged.fixer_type == "SUBPROCESS_SHELL_TRUE":
            proposed_code, mutated = SubprocessFixer.fix_code_ast(original_code)
        elif triaged.fixer_type == "MISSING_TIMEOUT":
            proposed_code, mutated = TimeoutFixer.fix_code_ast(original_code)
        elif triaged.fixer_type == "INSECURE_FILE_MODE":
            proposed_code, mutated = FileModeFixer.fix_code_ast(original_code)

        if not mutated or proposed_code == original_code:
            return PatchProposal(
                finding_id=f.id,
                target_file=f.file_path,
                original_snippet=original_code,
                proposed_snippet=original_code,
                diff="",
                is_safe=False,
                guardrail_status="NO_MUTATION_GENERATED",
            )

        # Evaluar contra guardrails agénticos
        verdict = self.guardrails.evaluate_patch(
            file_path=f.file_path,
            original_code=original_code,
            proposed_code=proposed_code,
        )

        # Generar diff unificado
        diff_lines = list(
            difflib.unified_diff(
                original_code.splitlines(keepends=True),
                proposed_code.splitlines(keepends=True),
                fromfile=f"a/{f.file_path}",
                tofile=f"b/{f.file_path}",
            )
        )
        diff_text = "".join(diff_lines)

        return PatchProposal(
            finding_id=f.id,
            target_file=f.file_path,
            original_snippet=original_code,
            proposed_snippet=proposed_code,
            diff=diff_text,
            is_safe=verdict.is_allowed,
            guardrail_status=verdict.status,
        )

    def apply_patch(self, proposal: PatchProposal, backup: bool = True) -> bool:
        """Aplica un parche al archivo de destino si superó los guardrails de seguridad.

        Args:
            proposal: Propuesta de parche verificada.
            backup: Si es True, crea un archivo .bak antes de escribir.

        Returns:
            True si el parche fue aplicado con éxito.
        """
        if not proposal.is_safe:
            return False

        target_path = Path(proposal.target_file)
        if not target_path.exists():
            return False

        if backup:
            backup_path = target_path.with_suffix(target_path.suffix + ".bak")
            backup_path.write_text(proposal.original_snippet, encoding="utf-8")

        target_path.write_text(proposal.proposed_snippet, encoding="utf-8")
        return True
