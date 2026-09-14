"""CLI interactiva y de automatización para el motor de auto-remediación DevSecOps."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from auto_remediate.classifier.triage_engine import TriageEngine
from auto_remediate.git_ops.patch_manager import PatchManager
from auto_remediate.reporting.debt_reporter import DebtReporter
from auto_remediate.scanners.bandit_runner import BanditRunner
from auto_remediate.scanners.gitleaks_runner import GitleaksRunner
from auto_remediate.scanners.semgrep_runner import SemgrepRunner


def cmd_scan(args: argparse.Namespace) -> int:
    """Escanea un directorio con los motores SAST y detectores de secretos configurados."""
    target = Path(args.target)
    if not target.exists():
        print(f"[ERROR] Ruta no encontrada: {args.target}", file=sys.stderr)
        return 1

    print(f"=== Escaneo DevSecOps en '{args.target}' ===")
    runner = BanditRunner()
    findings = runner.scan(target)

    print(f"Total hallazgos detectados (Bandit): {len(findings)}")
    for f in findings:
        print(f"  [{f.severity}] {f.id} — {f.cwe}: {f.description} ({f.file_path}:{f.line_number})")

    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    """Clasifica y prioriza los hallazgos según su riesgo y capacidad de reparación AST."""
    target = Path(args.target)
    if not target.exists():
        print(f"[ERROR] Ruta no encontrada: {args.target}", file=sys.stderr)
        return 1

    runner = BanditRunner()
    findings = runner.scan(target)
    engine = TriageEngine()
    triaged = engine.triage_batch(findings)

    print(f"=== Triaje y Clasificación ({len(triaged)} hallazgos) ===")
    for t in triaged:
        f = t.finding
        fixable_str = "FIXABLE" if t.is_fixable else "MANUAL"
        print(f"\n[{f.severity}] [{fixable_str}] {f.id} (Prioridad: {t.priority_score})")
        print(f"  Archivo: {f.file_path}:{f.line_number}")
        print(f"  Fixer: {t.fixer_type}")
        print(f"  Plan: {t.action_plan}")

    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    """Genera y opcionalmente aplica parches AST con validación estricta de guardrails."""
    target = Path(args.target)
    if not target.exists():
        print(f"[ERROR] Ruta no encontrada: {args.target}", file=sys.stderr)
        return 1

    runner = BanditRunner()
    findings = runner.scan(target)
    engine = TriageEngine()
    triaged = engine.triage_batch(findings)
    fixable = engine.get_fixable_findings(triaged)

    patch_mgr = PatchManager()
    applied_count = 0

    print(f"=== Pipeline de Remediación AST ({len(fixable)} candidatos remediables) ===")

    for t in fixable:
        proposal = patch_mgr.generate_proposal(t)
        print(f"\n--- Hallazgo: {proposal.finding_id} ({proposal.target_file}) ---")
        print(f"Guardrail Status: {proposal.guardrail_status} | Seguro: {proposal.is_safe}")

        if proposal.diff:
            print("Diff propuesto:")
            for line in proposal.diff.splitlines():
                print(f"  {line}")

        if args.apply:
            if proposal.is_safe:
                success = patch_mgr.apply_patch(proposal, backup=not args.no_backup)
                if success:
                    print("[ÉXITO] Parche aplicado satisfactoriamente.")
                    applied_count += 1
                else:
                    print("[FALLO] No se pudo aplicar el parche.")
            else:
                print(f"[BLOQUEADO] El parche violó los guardrails de seguridad: {proposal.guardrail_status}")

    if not args.apply:
        print("\nModo Dry-Run: No se aplicaron modificaciones en disco. Use --apply para ejecutar cambios.")
    else:
        print(f"\nResumen: {applied_count} parches aplicados exitosamente.")

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Genera un informe completo de reducción de deuda técnica."""
    target = Path(args.target)
    if not target.exists():
        print(f"[ERROR] Ruta no encontrada: {args.target}", file=sys.stderr)
        return 1

    runner = BanditRunner()
    findings = runner.scan(target)
    engine = TriageEngine()
    triaged = engine.triage_batch(findings)
    patch_mgr = PatchManager()

    proposals = []
    for t in triaged:
        if t.is_fixable:
            proposals.append(patch_mgr.generate_proposal(t))

    out_path = Path(args.output) if args.output else None
    md = DebtReporter.generate_markdown_report(triaged, proposals, applied_count=0, output_file=out_path)

    if not out_path:
        print(md)
    else:
        print(f"Informe de deuda técnica generado en: {out_path}")

    return 0


def main(argv: list[str] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auto-remediate",
        description="Auto-Remediate — Pipeline determinista de remediación AST con guardrails agénticos",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando scan
    p_scan = subparsers.add_parser("scan", help="Escanear directorio en busca de vulnerabilidades")
    p_scan.add_argument("target", help="Ruta del directorio a auditar")
    p_scan.set_defaults(func=cmd_scan)

    # Subcomando triage
    p_triage = subparsers.add_parser("triage", help="Triar y clasificar hallazgos de seguridad")
    p_triage.add_argument("target", help="Ruta del directorio a auditar")
    p_triage.set_defaults(func=cmd_triage)

    # Subcomando fix
    p_fix = subparsers.add_parser("fix", help="Generar y aplicar parches AST deterministas")
    p_fix.add_argument("target", help="Ruta del directorio a auditar")
    p_fix.add_argument("--apply", action="store_true", help="Aplicar los cambios en disco")
    p_fix.add_argument("--no-backup", action="store_true", help="Omitir la creación de archivos .bak")
    p_fix.set_defaults(func=cmd_fix)

    # Subcomando report
    p_rep = subparsers.add_parser("report", help="Generar informe Markdown de deuda técnica")
    p_rep.add_argument("target", help="Ruta del directorio a auditar")
    p_rep.add_argument("--output", "-o", help="Ruta del archivo Markdown de salida")
    p_rep.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
