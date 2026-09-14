from auto_remediate.fixers.subprocess_fixer import SubprocessFixer

def test_subprocess_shell_removal():
    code = 'subprocess.run(["ls", "-la"], shell=True, check=True)'
    fixed = SubprocessFixer.fix_shell_true(code)
    assert "shell=True" not in fixed
    assert 'subprocess.run(["ls", "-la"], check=True)' in fixed
