"""Interfaz abstracta y ejecución segura de escáneres de seguridad SAST."""

from __future__ import annotations

import abc
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from auto_remediate.schemas import SecurityFinding


class BaseScanner(abc.ABC):
    """Clase base abstracta para escáneres SAST y detectores de secretos."""

    def __init__(self, name: str, timeout_seconds: float = 30.0):
        self.name = name
        self.timeout_seconds = timeout_seconds

    def execute_safe_cmd(self, cmd_args: list[str], cwd: Optional[str | Path] = None) -> tuple[int, str, str]:
        """Ejecuta un comando del sistema de forma segura sin invocar intérprete de shell.

        Cumple con el estándar de seguridad anti-CWE-78:
        - shell=False explícito.
        - Argumentos suministrados como lista estricta.
        - Timeout preventivo contra DoS.

        Args:
            cmd_args: Lista de binario y argumentos.
            cwd: Directorio de trabajo opcional.

        Returns:
            Tupla (returncode, stdout, stderr).
        """
        try:
            proc = subprocess.run(
                cmd_args,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
                check=False,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Timeout ({self.timeout_seconds}s) alcanzado ejecutando {cmd_args[0]}"
        except FileNotFoundError:
            return 127, "", f"Binario no encontrado en PATH: {cmd_args[0]}"

    @abc.abstractmethod
    def scan(self, target_path: str | Path) -> list[SecurityFinding]:
        """Ejecuta el escáner sobre la ruta objetivo y retorna hallazgos estructurados."""
        pass

    @abc.abstractmethod
    def parse_output(self, raw_json: str) -> list[SecurityFinding]:
        """Parsea la salida JSON cruda del escáner a una lista de SecurityFinding."""
        pass
