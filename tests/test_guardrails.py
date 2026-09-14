def test_protected_files_blocked(guardrails):
    assert guardrails.is_file_protected("src/auth/jwt_token.py") is True
    assert guardrails.is_file_protected("db/migrations/001_initial.py") is True
    assert guardrails.is_file_protected("crypto/hasher.py") is True

def test_safe_files_allowed(guardrails):
    assert guardrails.is_file_protected("src/utils/formatter.py") is False
    assert guardrails.is_file_protected("src/network/client.py") is False
