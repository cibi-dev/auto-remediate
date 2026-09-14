import pytest
from pathlib import Path

from auto_remediate.classifier import TriageEngine
from auto_remediate.git_ops import PatchManager
from auto_remediate.guardrails import SafetyGuardrails
from auto_remediate.reporting import DebtReporter
from auto_remediate.schemas import SecurityFinding


def test_patch_manager_generates_valid_proposal(tmp_path: Path):
    vulnerable_file = tmp_path / "worker.py"
    vulnerable_file.write_text(
        'import subprocess\nres = subprocess.run(["ls", "-la"], shell=True, check=True)\n',
        encoding="utf-8",
    )

    finding = SecurityFinding(
        id="b602-01",
        tool="bandit",
        cwe="CWE-78",
        file_path=str(vulnerable_file),
        line_number=2,
        severity="HIGH",
        description="subprocess shell=True",
    )

    engine = TriageEngine()
    triaged = engine.triage_finding(finding)

    mgr = PatchManager()
    proposal = mgr.generate_proposal(triaged)

    assert proposal.is_safe is True
    assert proposal.guardrail_status == "ALLOWED"
    assert "shell=False" in proposal.proposed_snippet
    assert "-res = subprocess.run" in proposal.diff or "-res" in proposal.diff


def test_patch_manager_blocks_protected_path(tmp_path: Path):
    auth_file = tmp_path / "auth_tokens.py"
    auth_file.write_text('subprocess.run("cmd", shell=True)\n', encoding="utf-8")

    finding = SecurityFinding(
        id="b602-02",
        tool="bandit",
        cwe="CWE-78",
        file_path=str(auth_file),
        line_number=1,
        severity="HIGH",
        description="subprocess shell=True",
    )
    engine = TriageEngine()
    triaged = engine.triage_finding(finding)

    mgr = PatchManager()
    proposal = mgr.generate_proposal(triaged)

    assert proposal.is_safe is False
    assert proposal.guardrail_status == "BLOCKED_PROTECTED_PATH"


def test_patch_manager_apply_patch_with_backup(tmp_path: Path):
    target = tmp_path / "client.py"
    original_code = 'import requests\nresp = requests.get("https://example.com")\n'
    target.write_text(original_code, encoding="utf-8")

    finding = SecurityFinding(
        id="b113-01",
        tool="bandit",
        cwe="CWE-400",
        file_path=str(target),
        line_number=2,
        severity="MEDIUM",
        description="Requests without timeout",
    )
    triaged = TriageEngine().triage_finding(finding)
    mgr = PatchManager()
    prop = mgr.generate_proposal(triaged)

    assert prop.is_safe is True
    applied = mgr.apply_patch(prop, backup=True)
    assert applied is True

    # Verificar que el archivo fue modificado
    new_code = target.read_text(encoding="utf-8")
    assert "timeout=10.0" in new_code

    # Verificar existencia del backup
    bak_file = target.with_suffix(".py.bak")
    assert bak_file.exists()
    assert bak_file.read_text(encoding="utf-8") == original_code


def test_debt_reporter_generates_markdown(tmp_path: Path):
    findings = [
        SecurityFinding(
            id="f-01",
            tool="bandit",
            cwe="CWE-78",
            file_path="src/a.py",
            line_number=1,
            severity="HIGH",
            description="shell=True",
        ),
        SecurityFinding(
            id="f-02",
            tool="gitleaks",
            cwe="CWE-798",
            file_path="src/b.py",
            line_number=2,
            severity="CRITICAL",
            description="API Key",
        ),
    ]
    engine = TriageEngine()
    triaged = engine.triage_batch(findings)
    rep_file = tmp_path / "DEBT_REPORT.md"

    md = DebtReporter.generate_markdown_report(triaged, [], applied_count=1, output_file=rep_file)
    assert "# 🛡️ Informe Ejecutivo de Auto-Remediación DevSecOps" in md
    assert "Tasa de Reducción de Deuda" in md
    assert rep_file.exists()


def test_patch_manager_nonexistent_file():
    mgr = PatchManager()
    finding = SecurityFinding(
        id="f-missing",
        tool="bandit",
        cwe="CWE-78",
        file_path="/path/that/does/not/exist_123.py",
        line_number=1,
        severity="HIGH",
        description="test",
    )
    triaged = TriageEngine().triage_finding(finding)
    prop = mgr.generate_proposal(triaged)
    assert prop.guardrail_status == "FILE_NOT_FOUND"
    assert prop.is_safe is False
    assert mgr.apply_patch(prop) is False


def test_patch_manager_apply_without_backup(tmp_path: Path):
    target = tmp_path / "app.py"
    target.write_text('import subprocess\nsubprocess.run(["ls"], shell=True)\n', encoding="utf-8")

    finding = SecurityFinding(
        id="f-nobak",
        tool="bandit",
        cwe="CWE-78",
        file_path=str(target),
        line_number=2,
        severity="HIGH",
        description="shell=True",
    )
    triaged = TriageEngine().triage_finding(finding)
    mgr = PatchManager()
    prop = mgr.generate_proposal(triaged)
    assert prop.is_safe is True

    applied = mgr.apply_patch(prop, backup=False)
    assert applied is True
    assert not (tmp_path / "app.py.bak").exists()


def test_debt_reporter_json_dict_structure():
    findings = [
        SecurityFinding(
            id="f-01",
            tool="bandit",
            cwe="CWE-78",
            file_path="src/a.py",
            line_number=1,
            severity="HIGH",
            description="shell=True",
        )
    ]
    engine = TriageEngine()
    triaged = engine.triage_batch(findings)
    data = DebtReporter.generate_report_dict(triaged, [], applied_count=1)
    assert "timestamp" in data
    assert "metrics" in data
    assert data["metrics"]["total_findings"] == 1
    assert data["metrics"]["debt_reduction_ratio_pct"] == 100.0

