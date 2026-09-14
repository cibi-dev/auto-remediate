"""Generador de reportes de reducción de deuda técnica y remediación DevSecOps."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from auto_remediate.classifier.triage_engine import TriagedFinding
from auto_remediate.schemas import PatchProposal


class DebtReporter:
    """Genera reportes ejecutivos en formato Markdown y JSON con métricas de remediación."""

    @staticmethod
    def generate_report_dict(
        triaged_findings: list[TriagedFinding],
        proposals: list[PatchProposal],
        applied_count: int,
    ) -> dict[str, Any]:
        total = len(triaged_findings)
        fixable = sum(1 for t in triaged_findings if t.is_fixable)
        blocked = sum(1 for p in proposals if not p.is_safe and p.guardrail_status != "NO_MUTATION_GENERATED")
        safe_patches = sum(1 for p in proposals if p.is_safe)
        reduction_rate = round((applied_count / total * 100), 2) if total > 0 else 0.0

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics": {
                "total_findings": total,
                "fixable_findings": fixable,
                "unfixable_findings": total - fixable,
                "safe_proposals_generated": safe_patches,
                "proposals_blocked_by_guardrails": blocked,
                "patches_applied": applied_count,
                "debt_reduction_ratio_pct": reduction_rate,
            },
            "proposals": [
                {
                    "finding_id": p.finding_id,
                    "target_file": p.target_file,
                    "is_safe": p.is_safe,
                    "guardrail_status": p.guardrail_status,
                }
                for p in proposals
            ],
        }

    @staticmethod
    def generate_markdown_report(
        triaged_findings: list[TriagedFinding],
        proposals: list[PatchProposal],
        applied_count: int,
        output_file: Path | None = None,
    ) -> str:
        data = DebtReporter.generate_report_dict(triaged_findings, proposals, applied_count)
        m = data["metrics"]

        md = [
            "# 🛡️ Informe Ejecutivo de Auto-Remediación DevSecOps",
            f"\n> **Fecha de Análisis:** {data['timestamp']}  ",
            "> **Filosofía:** Remediacón Determinista AST con Guardrails Agénticos Estrictos",
            "\n---",
            "\n## 📊 Métricas de Deuda Técnica & Remediación",
            f"- **Total Hallazgos Detectados:** {m['total_findings']}",
            f"- **Hallazgos Candidatos a Fixer AST:** {m['fixable_findings']}",
            f"- **Parches Seguros Generados:** {m['safe_proposals_generated']}",
            f"- **Parches Bloqueados por Guardrails:** {m['proposals_blocked_by_guardrails']}",
            f"- **Parches Aplicados con Éxito:** {m['patches_applied']}",
            f"- **Tasa de Reducción de Deuda:** **{m['debt_reduction_ratio_pct']}%**",
            "\n---",
            "\n## 📋 Detalle de Propuestas & Veredictos",
            "| Finding ID | Archivo Objetivo | Seguro | Estado Guardrail |",
            "|---|---|:---:|---|",
        ]

        for p in proposals:
            safe_badge = "✅ Sí" if p.is_safe else "❌ No"
            md.append(f"| `{p.finding_id}` | `{p.target_file}` | {safe_badge} | `{p.guardrail_status}` |")

        md_content = "\n".join(md) + "\n"
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(md_content, encoding="utf-8")

        return md_content
