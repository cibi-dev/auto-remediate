"""Runner y adaptador para el detector de secretos y credenciales Gitleaks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from auto_remediate.scanners.base import BaseScanner
from auto_remediate.schemas import SecurityFinding


class GitleaksRunner(BaseScanner):
    """Adaptador para Gitleaks con parseo de reportes JSON de secretos."""

    def __init__(self, timeout_seconds: float = 30.0):
        super().__init__(name="gitleaks", timeout_seconds=timeout_seconds)

    def scan(self, target_path: str | Path) -> list[SecurityFinding]:
        """Ejecuta Gitleaks sobre la ruta especificada generando reporte temporal."""
        report_file = Path(target_path) / ".gitleaks_tmp_report.json"
        cmd = [
            "gitleaks",
            "detect",
            "--no-git",
            "--source",
            str(target_path),
            "--report-path",
            str(report_file),
            "--report-format",
            "json",
        ]
        ret, stdout, stderr = self.execute_safe_cmd(cmd)

        findings: list[SecurityFinding] = []
        if report_file.exists():
            try:
                raw_json = report_file.read_text(encoding="utf-8")
                findings = self.parse_output(raw_json)
            finally:
                report_file.unlink(missing_ok=True)

        return findings

    def parse_output(self, raw_json: str) -> list[SecurityFinding]:
        """Parsea la lista JSON de secretos detectados por Gitleaks."""
        if not raw_json.strip():
            return []

        try:
            items = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        if not isinstance(items, list):
            return []

        findings: list[SecurityFinding] = []
        for idx, item in enumerate(items, start=1):
            rule_id = item.get("RuleID", "generic-secret")
            desc = item.get("Description", "Hardcoded credential detected")
            file_path = item.get("File", "")
            start_line = item.get("StartLine", 1)

            finding = SecurityFinding(
                id=f"gitleaks-{rule_id}-{idx:03d}",
                tool="gitleaks",
                cwe="CWE-798",
                file_path=file_path,
                line_number=start_line,
                severity="CRITICAL",
                description=f"Secreto detectado ({rule_id}): {desc}",
            )
            findings.append(finding)

        return findings
