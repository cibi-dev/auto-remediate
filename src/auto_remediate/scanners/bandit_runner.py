"""Runner y adaptador para el escáner SAST Bandit (Python AST Security)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from auto_remediate.scanners.base import BaseScanner
from auto_remediate.schemas import SecurityFinding


class BanditRunner(BaseScanner):
    """Adaptador seguro para Bandit SAST con salida estructurada JSON."""

    def __init__(self, timeout_seconds: float = 30.0):
        super().__init__(name="bandit", timeout_seconds=timeout_seconds)

    def scan(self, target_path: str | Path) -> list[SecurityFinding]:
        """Ejecuta Bandit sobre la ruta especificada en formato JSON."""
        cmd = ["bandit", "-r", str(target_path), "-f", "json", "-q"]
        ret, stdout, stderr = self.execute_safe_cmd(cmd)
        # Bandit retorna 1 si encuentra problemas o 0 si no hay
        if ret not in (0, 1):
            return []
        return self.parse_output(stdout)

    def parse_output(self, raw_json: str) -> list[SecurityFinding]:
        """Parsea la salida JSON de Bandit a modelos SecurityFinding."""
        if not raw_json.strip():
            return []

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        results = data.get("results", [])
        findings: list[SecurityFinding] = []

        for idx, item in enumerate(results, start=1):
            test_id = item.get("test_id", "UNKNOWN")
            cwe_obj = item.get("issue_cwe", {})
            cwe_id = str(cwe_obj.get("id", ""))
            cwe_str = f"CWE-{cwe_id}" if cwe_id else "CWE-UNKNOWN"

            finding = SecurityFinding(
                id=f"bandit-{test_id.lower()}-{idx:03d}",
                tool="bandit",
                cwe=cwe_str,
                file_path=item.get("filename", ""),
                line_number=item.get("line_number", 1),
                severity=item.get("issue_severity", "MEDIUM").upper(),
                description=item.get("issue_text", ""),
            )
            findings.append(finding)

        return findings
