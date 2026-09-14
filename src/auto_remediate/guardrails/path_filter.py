import os

PROTECTED_KEYWORDS = ["auth", "crypto", "migration", "jwt", "password", "login", "secret"]

class SafetyGuardrails:
    @staticmethod
    def is_file_protected(file_path: str) -> bool:
        norm = file_path.lower().replace(os.sep, "/")
        return any(keyword in norm for keyword in PROTECTED_KEYWORDS)

    @staticmethod
    def validate_proposal(file_path: str) -> str:
        if SafetyGuardrails.is_file_protected(file_path):
            return "BLOCKED_PROTECTED_PATH"
        return "ALLOWED"
