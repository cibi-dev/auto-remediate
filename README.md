# Auto-Remediate 🛡️⚙️

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Security: Bandit](https://img.shields.io/badge/Security-Bandit%20Passing-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero-Cost](https://img.shields.io/badge/API%20Cost-%240.00%2Fmo-success.svg)](https://github.com/cibi-dev/auto-remediate)
[![Coverage](https://img.shields.io/badge/Coverage-91%25-brightgreen.svg)](https://github.com/cibi-dev/auto-remediate)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-Interactive%20Showcase-2563eb?style=flat-square&logo=googlechrome&logoColor=white)](https://cibi-dev.github.io/crimai-platform/)

> **Motor autónomo de auditoría y auto-remediación determinista basada en AST (Abstract Syntax Tree) con guardrails agénticos estrictos y reducción medible de deuda técnica.**

Diseñado bajo la filosofía **Zero Hallucination / Sovereign DevSecOps**: no inventa código arbitrario ni delega la sintaxis a LLMs sin contención. Todas las transformaciones se ejecutan mediante manipulaciones formales de nodos del compilador de Python (`ast.NodeTransformer`), auditadas por guardrails de contención antes de cualquier mutación en disco.

> 🌐 **Interactive Demo Showcase:** Este motor DevSecOps está integrado en la plataforma unificada **CrimAI Platform**. Puedes probar las mutaciones AST y diffs automáticos en vivo en el [Showcase Interactivo en GitHub Pages](https://cibi-dev.github.io/crimai-platform/).

[![CrimAI Platform Showcase Preview](https://raw.githubusercontent.com/cibi-dev/crimai-platform/main/docs/assets/showcase-preview.svg)](https://cibi-dev.github.io/crimai-platform/)

---

## 🏗️ Arquitectura del Sistema

```
                      CÓDIGO FUENTE DEL REPOSITORIO
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │             Capa de Escáneres SAST & Secretos          │
       │   - Bandit Runner (AST security issues, B602, B113)    │
       │   - Semgrep Runner (Patrones y reglas semánticas)      │
       │   - Gitleaks Runner (Detección de credenciales)        │
       └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │        Motor de Triaje & Priorización de Riesgo        │
       │   - Mapeo de CWE a Fixers AST Disponibles              │
       │   - Score de Criticidad (1 a 100)                      │
       │   - Flag de Auto-Remediabilidad vs. HITL (Humano)      │
       └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │           Fixers Deterministas Basados en AST          │
       │   - SubprocessFixer: shell=True -> shell=False + tokens│
       │   - TimeoutFixer: inyección timeout=10.0 en HTTP       │
       │   - FileModeFixer: mktemp obsoleto -> NamedTempFile    │
       └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │             Guardrails Agénticos Estrictos             │
       │   - Bloqueo de Rutas Críticas: auth, crypto, jwt, db   │
       │   - Límite de Mutación: max <= 15 líneas por archivo   │
       │   - Auditoría AST Anti-Inyección: bloquea eval/exec/os │
       │   - Verificación de Compilación (ast.parse)            │
       └──────────────┬───────────────────────────┬─────────────┘
                      │ Aprobado                  │ Rechazado
                      ▼                           ▼
       ┌──────────────────────────────┐   ┌─────────────────────┐
       │   Gestor GitOps & Parches    │   │ Alerta de Bloqueo   │
       │   - Generación de Diff       │   │ & Triaje Humano     │
       │   - Backup atómico (.bak)    │   └─────────────────────┘
       │   - Escritura segura         │
       └──────────────┬───────────────┘
                      │
                      ▼
       [ Informe Ejecutivo de Reducción de Deuda Técnica ]
```

---

## ⚡ Reglas & Guardrails Agénticos

Para evitar que un agente o script corrompa lógica sensible de negocio, el motor impone **4 barreras infranqueables**:

1. **Barrera de Rutas Protegidas (`BLOCKED_PROTECTED_PATH`):**
   - Rechazo inmediato de mutaciones si la ruta del archivo incluye: `auth`, `crypto`, `migration`, `jwt`, `password`, `login`, `secret`, `credential`, `keys`, `token`.
2. **Límite de Contención de Código (`BLOCKED_LINE_LIMIT_EXCEEDED`):**
   - Máximo $\le 15$ líneas modificadas por archivo. Los cambios masivos son descartados para revisión manual.
3. **Auditoría Anti-Inyección en AST (`BLOCKED_DANGEROUS_CALL`):**
   - El código resultante no puede introducir llamadas a `eval()`, `exec()`, `compile()`, `__import__()` o `os.system()`.
4. **Validación Sintáctica Estricta (`BLOCKED_SYNTAX_ERROR`):**
   - El código propuesto debe compilar limpiamente con `ast.parse()`. Ante cualquier error sintáctico, la operación se cancela sin tocar el disco.

---

## 🔧 Catálogo de Fixers AST

| Vulnerabilidad | CWE | Fixer AST | Acción Determinista |
|---|---|---|---|
| **Command Injection** | CWE-78 | `SubprocessFixer` | Elimina `shell=True` forzando `shell=False`. Si el comando era un string ("ls -la"), lo tokeniza formalmente en lista con `shlex.split`. |
| **Missing HTTP Timeout** | CWE-400 | `TimeoutFixer` | Inyecta el parámetro `timeout=10.0` en llamadas a `requests` o `httpx` que carezcan de él, evitando cuelgues o ataques DoS por agotamiento de sockets. |
| **Insecure Temp Files** | CWE-732 | `FileModeFixer` | Sustituye el obsoleto y vulnerable `tempfile.mktemp` por `tempfile.NamedTemporaryFile(delete=False)` con permisos restrictivos. |
| **Hardcoded Secret** | CWE-798 | `HITL Gate` | Clasificado como **no automatizable**. Se genera alerta de intervención humana para rotación de credenciales en vault o variables de entorno. |

---

## 🚀 Instalación y Uso de CLI (`auto-remediate`)

```bash
# 1. Instalar en modo editable
git clone https://github.com/cibi-dev/auto-remediate.git
cd auto-remediate
pip install -e .

# 2. Escanear un repositorio o directorio
auto-remediate scan ./src

# 3. Clasificar y triar vulnerabilidades detectadas
auto-remediate triage ./src

# 4. Modo Simulación (Dry-Run): previsualizar parches y diffs
auto-remediate fix ./src

# 5. Aplicar parches que hayan superado los guardrails (con backup .bak)
auto-remediate fix ./src --apply

# 6. Generar informe Markdown de reducción de deuda técnica
auto-remediate report ./src -o ./DEBT_REPORT.md
```

---

## 🧪 Pruebas y Seguridad (DevSecOps)

El motor cumple con el estándar canónico universal del workspace:

```bash
# Ejecutar suite de pruebas unitarias e integración (45 tests, 91% coverage)
pytest -v --cov=src/auto_remediate

# Auditoría SAST con Bandit (0 vulnerabilidades)
bandit -r src/ -ll

# Detección de secretos con Gitleaks
gitleaks detect -v
```

---

## 📄 Licencia

Distribuido bajo la Licencia MIT. Consulta `LICENSE` para más información.
