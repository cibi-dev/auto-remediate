from dataclasses import dataclass
from typing import Any, Dict, Optional

@dataclass
class SecurityFinding:
    id: str
    tool: str  # bandit, semgrep, gitleaks
    cwe: str
    file_path: str
    line_number: int
    severity: str
    description: str

@dataclass
class PatchProposal:
    finding_id: str
    target_file: str
    original_snippet: str
    proposed_snippet: str
    diff: str
    is_safe: bool
    guardrail_status: str  # ALLOWED, BLOCKED_PROTECTED_PATH, SYNTAX_ERROR
