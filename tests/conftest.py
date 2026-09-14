import pytest
from auto_remediate.guardrails.path_filter import SafetyGuardrails

@pytest.fixture
def guardrails():
    return SafetyGuardrails()
