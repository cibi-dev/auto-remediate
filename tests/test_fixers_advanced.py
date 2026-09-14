import pytest
from auto_remediate.fixers import SubprocessFixer, TimeoutFixer, FileModeFixer


def test_subprocess_ast_fixer_shell_true_removal():
    code = 'res = subprocess.run(["ls", "-la"], shell=True, check=True)'
    fixed, mutated = SubprocessFixer.fix_code_ast(code)
    assert mutated is True
    assert "shell=False" in fixed
    assert "check=True" in fixed


def test_subprocess_ast_fixer_string_command_tokenization():
    code = 'subprocess.Popen("cat /etc/passwd", shell=True)'
    fixed, mutated = SubprocessFixer.fix_code_ast(code)
    assert mutated is True
    assert "shell=False" in fixed
    assert "['cat', '/etc/passwd']" in fixed or '["cat", "/etc/passwd"]' in fixed


def test_subprocess_ast_fixer_no_op_on_safe_code():
    code = 'subprocess.run(["git", "status"], shell=False)'
    fixed, mutated = SubprocessFixer.fix_code_ast(code)
    assert mutated is False
    assert fixed == code


def test_timeout_ast_fixer_requests_get():
    code = 'resp = requests.get("https://api.example.com/data")'
    fixed, mutated = TimeoutFixer.fix_code_ast(code)
    assert mutated is True
    assert "timeout=10.0" in fixed


def test_timeout_ast_fixer_httpx_post():
    code = 'client.post("https://api.example.com/submit", json={"key": "val"})'
    fixed, mutated = TimeoutFixer.fix_code_ast(code, default_timeout=5.0)
    assert mutated is True
    assert "timeout=5.0" in fixed


def test_timeout_ast_fixer_ignores_existing_timeout():
    code = 'requests.get("https://api.example.com/data", timeout=30)'
    fixed, mutated = TimeoutFixer.fix_code_ast(code)
    assert mutated is False


def test_file_mode_ast_fixer_mktemp():
    code = 'temp_path = tempfile.mktemp(suffix=".tmp")'
    fixed, mutated = FileModeFixer.fix_code_ast(code)
    assert mutated is True
    assert "NamedTemporaryFile" in fixed
    assert "delete=False" in fixed


def test_file_mode_ast_fixer_ignores_named_temp():
    code = 'f = tempfile.NamedTemporaryFile(delete=True)'
    fixed, mutated = FileModeFixer.fix_code_ast(code)
    assert mutated is False


def test_fixers_handle_syntax_errors():
    broken = "def broken(:"
    f1, m1 = SubprocessFixer.fix_code_ast(broken)
    assert m1 is False
    f2, m2 = TimeoutFixer.fix_code_ast(broken)
    assert m2 is False
    f3, m3 = FileModeFixer.fix_code_ast(broken)
    assert m3 is False
