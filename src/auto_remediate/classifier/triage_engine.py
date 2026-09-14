"""Motor de triaje, priorización de severidad y clasificación de auto-remediabilidad."""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field

from auto_remediate.schemas import SecurityFinding


class TriagedFinding(BaseModel):
    """Hallazgo de seguridad triado con clasificación de auto-remediación."""

    finding: SecurityFinding
    is_fixable: bool
    fixer_type: str  # SUBPROCESS_SHELL_TRUE, MISSING_TIMEOUT, INSECURE_FILE_MODE, CREDENTIAL_LEAK, MANUAL_REVIEW_REQUIRED
    priority_score: int = Field(ge=1, le=100)
    action_plan: str
    remediation_notes: Optional[str] = None


class TriageEngine:
    """Clasifica hallazgos SAST/Secretos para determinar la estrategia de reparación y prioridad."""

    @staticmethod
    def _compute_priority(severity: str, is_fixable: bool) -> int:
        base_scores = {
            "CRITICAL": 90,
            "HIGH": 70,
            "MEDIUM": 45,
            "LOW": 20,
        }
        score = base_scores.get(severity.upper(), 30)
        # Priorizar hallazgos remediables de inmediato de forma automatizada
        if is_fixable:
            score += 5
        return min(100, score)

    def triage_finding(self, finding: SecurityFinding) -> TriagedFinding:
        """Clasifica un hallazgo individual y determina si existe un fixer determinista disponible."""
        cwe = finding.cwe.upper()
        desc = finding.description.lower()
        tool = finding.tool.lower()

        # 1. Detección de CWE-78 (OS Command Injection / Subprocess shell=True)
        if (
            "CWE-78" in cwe
            or "shell=true" in desc
            or "subprocess" in desc
            or "b602" in finding.id.lower()
            or "b603" in finding.id.lower()
        ):
            fixer_type = "SUBPROCESS_SHELL_TRUE"
            is_fixable = True
            action = "Reemplazar shell=True por lista de argumentos tokens en llamada a subprocess."

        # 2. Detección de CWE-400 (Falta de timeout en llamadas HTTP / Bandit B113)
        elif (
            "CWE-400" in cwe
            or "timeout" in desc
            or "b113" in finding.id.lower()
            or "requests" in desc
            or "httpx" in desc
        ):
            fixer_type = "MISSING_TIMEOUT"
            is_fixable = True
            action = "Inyectar parámetro timeout=10.0 en llamada HTTP requests/httpx para prevenir DoS."

        # 3. Detección de CWE-732 (Permisos inseguros en archivos temporales / Bandit B108)
        elif (
            "CWE-732" in cwe
            or "mktemp" in desc
            or "b108" in finding.id.lower()
            or "tempfile" in desc
        ):
            fixer_type = "INSECURE_FILE_MODE"
            is_fixable = True
            action = "Reemplazar mktemp obsoleto por NamedTemporaryFile seguro con permisos restrictivos."

        # 4. Detección de Secretos / Credenciales (CWE-798)
        elif "CWE-798" in cwe or tool == "gitleaks" or "secret" in desc or "credential" in desc:
            fixer_type = "CREDENTIAL_LEAK"
            is_fixable = False
            action = "Requiere intervención humana inmediata (HITL): rotar credencial y migrar a variables de entorno."

        # 5. Otros hallazgos no automatizables
        else:
            fixer_type = "MANUAL_REVIEW_REQUIRED"
            is_fixable = False
            action = "Auditoría manual de seguridad requerida por arquitectura o lógica de negocio."

        priority = self._compute_priority(finding.severity, is_fixable)

        return TriagedFinding(
            finding=finding,
            is_fixable=is_fixable,
            fixer_type=fixer_type,
            priority_score=priority,
            action_plan=action,
        )

    def triage_batch(self, findings: list[SecurityFinding]) -> list[TriagedFinding]:
        """Triaje por lote ordenado por prioridad descendente."""
        triaged = [self.triage_finding(f) for f in findings]
        triaged.sort(key=lambda item: item.priority_score, reverse=True)
        return triaged

    def get_fixable_findings(self, triaged: list[TriagedFinding]) -> list[TriagedFinding]:
        """Filtra únicamente los hallazgos que pueden ser remediados por los fixers AST."""
        return [t for t in triaged if t.is_fixable]
