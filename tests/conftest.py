import pytest


@pytest.fixture(autouse=True)
def _no_llm_key(monkeypatch):
    """No test may reach the Anthropic API: the AI explanation is off unless a test injects a fake client."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
