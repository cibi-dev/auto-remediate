import json
import pytest
from pathlib import Path
from auto_remediate.scanners import BanditRunner, SemgrepRunner, GitleaksRunner
from auto_remediate.schemas import SecurityFinding


def test_bandit_parser_valid_json():
    runner = BanditRunner()
    sample_json = json.dumps({
        "results": [
            {
                "test_id": "B602",
                "issue_severity": "HIGH",
                "issue_text": "subprocess popen with shell equals true",
                "line_number": 15,
                "filename": "src/dangerous.py",
                "issue_cwe": {"id": 78},
            }
        ]
    })
    findings = runner.parse_output(sample_json)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "bandit"
    assert f.cwe == "CWE-78"
    assert f.severity == "HIGH"
    assert f.line_number == 15
    assert f.file_path == "src/dangerous.py"


def test_bandit_parser_empty_or_invalid():
    runner = BanditRunner()
    assert runner.parse_output("") == []
    assert runner.parse_output("invalid json {}") == []
    assert runner.parse_output("{}") == []


def test_semgrep_parser_valid_json():
    runner = SemgrepRunner()
    sample_json = json.dumps({
        "results": [
            {
                "check_id": "rules.python.security.subprocess-shell",
                "path": "app/worker.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Dangerous shell=True in subprocess call",
                    "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
                    "severity": "ERROR",
                },
            }
        ]
    })
    findings = runner.parse_output(sample_json)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "semgrep"
    assert f.cwe == "CWE-78"
    assert f.severity == "HIGH"
    assert f.line_number == 42
    assert f.file_path == "app/worker.py"


def test_gitleaks_parser_valid_json():
    runner = GitleaksRunner()
    sample_json = json.dumps([
        {
            "RuleID": "aws-access-key-id",
            "Description": "AWS Access Key",
            "File": "config/aws.py",
            "StartLine": 8,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
        }
    ])
    findings = runner.parse_output(sample_json)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "gitleaks"
    assert f.cwe == "CWE-798"
    assert f.severity == "CRITICAL"
    assert f.line_number == 8
    assert "AWS Access Key" in f.description


def test_gitleaks_parser_empty():
    runner = GitleaksRunner()
    assert runner.parse_output("") == []
    assert runner.parse_output("[]") == []
    assert runner.parse_output("not-a-list") == []


def test_safe_execution_not_found():
    runner = BanditRunner()
    ret, stdout, stderr = runner.execute_safe_cmd(["non_existent_binary_xyz_123"])
    assert ret == 127
    assert "Binario no encontrado" in stderr


def test_safe_execution_timeout():
    runner = BanditRunner(timeout_seconds=0.1)
    ret, stdout, stderr = runner.execute_safe_cmd(["sleep", "1"])
    assert ret == -1
    assert "Timeout" in stderr


def test_scanner_runners_custom_timeout():
    b = BanditRunner(timeout_seconds=60.0)
    assert b.timeout_seconds == 60.0
    s = SemgrepRunner(timeout_seconds=90.0)
    assert s.timeout_seconds == 90.0
    g = GitleaksRunner(timeout_seconds=15.0)
    assert g.timeout_seconds == 15.0
