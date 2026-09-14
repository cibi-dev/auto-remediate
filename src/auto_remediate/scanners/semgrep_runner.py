"""Runner y adaptador para el escáner de análisis semántico Semgrep."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from auto_remediate.scanners.base import BaseScanner
from auto_remediate.schemas import SecurityFinding


class SemgrepRunner(BaseScanner):
    """Adaptador para Semgrep con soporte de reglas semánticas y salida JSON."""

    def __init__(self, timeout_seconds: float = 45.0):
        super().__init__(name="semgrep", timeout_seconds=timeout_seconds)

    def scan(self, target_path: str | Path) -> list[SecurityFinding]:
        """Ejecuta Semgrep si está instalado."""
        cmd = ["semgrep", "scan", "--json", "--quiet", str(target_path)]
        ret, stdout, stderr = self.execute_safe_cmd(cmd)
        if ret not in (0, 1):
            return []
        return self.parse_output(stdout)

    def parse_output(self, raw_json: str) -> list[SecurityFinding]:
        """Parsea la salida JSON de Semgrep a modelos SecurityFinding."""
        if not raw_json.strip():
            return []

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        results = data.get("results", [])
        findings: list[SecurityFinding] = []

        for idx, item in enumerate(results, start=1):
            check_id = item.get("check_id", "semgrep-rule")
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            cwe_str = cwe_list[0].split(":")[0] if cwe_list else "CWE-UNKNOWN"

            raw_sev = extra.get("severity", "WARNING").upper()
            sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            severity = sev_map.get(raw_sev, "MEDIUM")

            start = item.get("start", {})
            line_no = start.get("line", 1)

            finding = SecurityFinding(
                id=f"semgrep-{check_id.split('.')[-1]}-{idx:03d}",
                tool="semgrep",
                cwe=cwe_str,
                file_path=item.get("path", ""),
                line_number=line_no,
                severity=severity,
                description=extra.get("message", "Semgrep security finding"),
            )
            findings.append(finding)

        return findings
