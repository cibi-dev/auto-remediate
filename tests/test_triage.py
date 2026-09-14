import pytest
from auto_remediate.classifier import TriageEngine, TriagedFinding
from auto_remediate.schemas import SecurityFinding


def test_triage_subprocess_finding():
    engine = TriageEngine()
    f = SecurityFinding(
        id="bandit-b602-001",
        tool="bandit",
        cwe="CWE-78",
        file_path="src/tools.py",
        line_number=10,
        severity="HIGH",
        description="subprocess call with shell=True identified",
    )
    res = engine.triage_finding(f)
    assert res.is_fixable is True
    assert res.fixer_type == "SUBPROCESS_SHELL_TRUE"
    assert res.priority_score >= 70
    assert "shell=True" in res.action_plan


def test_triage_timeout_finding():
    engine = TriageEngine()
    f = SecurityFinding(
        id="bandit-b113-001",
        tool="bandit",
        cwe="CWE-400",
        file_path="src/client.py",
        line_number=25,
        severity="MEDIUM",
        description="Requests call without timeout",
    )
    res = engine.triage_finding(f)
    assert res.is_fixable is True
    assert res.fixer_type == "MISSING_TIMEOUT"
    assert "timeout=10.0" in res.action_plan


def test_triage_mktemp_finding():
    engine = TriageEngine()
    f = SecurityFinding(
        id="bandit-b108-001",
        tool="bandit",
        cwe="CWE-732",
        file_path="src/io.py",
        line_number=14,
        severity="MEDIUM",
        description="Probable insecure usage of temp file/directory via mktemp",
    )
    res = engine.triage_finding(f)
    assert res.is_fixable is True
    assert res.fixer_type == "INSECURE_FILE_MODE"


def test_triage_credential_finding():
    engine = TriageEngine()
    f = SecurityFinding(
        id="gitleaks-api-key-001",
        tool="gitleaks",
        cwe="CWE-798",
        file_path="src/config.py",
        line_number=5,
        severity="CRITICAL",
        description="Hardcoded Stripe API Key",
    )
    res = engine.triage_finding(f)
    assert res.is_fixable is False
    assert res.fixer_type == "CREDENTIAL_LEAK"
    assert res.priority_score >= 90
    assert "HITL" in res.action_plan


def test_triage_unknown_finding():
    engine = TriageEngine()
    f = SecurityFinding(
        id="semgrep-custom-999",
        tool="semgrep",
        cwe="CWE-999",
        file_path="src/domain.py",
        line_number=100,
        severity="LOW",
        description="Complex business logic flaw",
    )
    res = engine.triage_finding(f)
    assert res.is_fixable is False
    assert res.fixer_type == "MANUAL_REVIEW_REQUIRED"


def test_triage_batch_sorting():
    engine = TriageEngine()
    f_low = SecurityFinding(
        id="1", tool="semgrep", cwe="CWE-1", file_path="a.py", line_number=1, severity="LOW", description="minor"
    )
    f_crit = SecurityFinding(
        id="2", tool="bandit", cwe="CWE-78", file_path="b.py", line_number=1, severity="CRITICAL", description="shell=True"
    )
    batch = engine.triage_batch([f_low, f_crit])
    assert len(batch) == 2
    assert batch[0].finding.id == "2"  # CRITICAL primero
    assert batch[1].finding.id == "1"

    fixables = engine.get_fixable_findings(batch)
    assert len(fixables) == 1
    assert fixables[0].finding.id == "2"
