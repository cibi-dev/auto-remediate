import pytest
from auto_remediate.guardrails import SafetyGuardrails, GuardrailVerdict


def test_guardrails_path_blocking():
    g = SafetyGuardrails()
    v = g.evaluate_patch("src/auth/jwt.py", "a = 1", "a = 2")
    assert v.is_allowed is False
    assert v.status == "BLOCKED_PROTECTED_PATH"

    v2 = g.evaluate_patch("config/keys.py", "b = 1", "b = 2")
    assert v2.is_allowed is False
    assert v2.status == "BLOCKED_PROTECTED_PATH"


def test_guardrails_syntax_error_blocking():
    g = SafetyGuardrails()
    original = "x = 10\n"
    broken_proposal = "def broken(:\n    pass"
    v = g.evaluate_patch("src/app.py", original, broken_proposal)
    assert v.is_allowed is False
    assert v.status == "BLOCKED_SYNTAX_ERROR"
    assert "sintaxis" in v.reason.lower()


def test_guardrails_dangerous_calls_blocking():
    g = SafetyGuardrails()
    original = "data = 'test'\n"
    
    # Intento de inyectar eval
    evil_proposal_1 = "eval('__import__(\"os\").system(\"rm -rf /\")')"
    v1 = g.evaluate_patch("src/utils.py", original, evil_proposal_1)
    assert v1.is_allowed is False
    assert v1.status == "BLOCKED_DANGEROUS_CALL"

    # Intento de inyectar os.system
    evil_proposal_2 = "import os\nos.system('whoami')"
    v2 = g.evaluate_patch("src/utils.py", original, evil_proposal_2)
    assert v2.is_allowed is False
    assert v2.status == "BLOCKED_DANGEROUS_CALL"


def test_guardrails_line_limit_exceeded():
    g = SafetyGuardrails(max_lines_changed=5)
    original = "line1\nline2\n"
    massive_proposal = "\n".join([f"line_{i} = {i}" for i in range(20)])
    v = g.evaluate_patch("src/worker.py", original, massive_proposal)
    assert v.is_allowed is False
    assert v.status == "BLOCKED_LINE_LIMIT_EXCEEDED"


def test_guardrails_valid_patch_allowed():
    g = SafetyGuardrails(max_lines_changed=15)
    original = 'import subprocess\nsubprocess.run(["ls"], shell=True)\n'
    proposal = 'import subprocess\nsubprocess.run(["ls"], shell=False)\n'
    v = g.evaluate_patch("src/cli/tools.py", original, proposal)
    assert v.is_allowed is True
    assert v.status == "ALLOWED"


def test_guardrails_compile_call_blocked():
    g = SafetyGuardrails()
    evil = 'code = compile("print(1)", "<string>", "exec")'
    v = g.evaluate_patch("src/app.py", "x = 1", evil)
    assert v.is_allowed is False
    assert v.status == "BLOCKED_DANGEROUS_CALL"
    assert "compile" in v.reason
