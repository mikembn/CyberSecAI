import pytest

from app.config import get_openai_api_key


def test_get_openai_api_key_returns_environment_value(monkeypatch):
    monkeypatch.setenv(
        "OPENAI_API_KEY",
        "test-key-123",
    )

    assert get_openai_api_key() == "test-key-123"


def test_get_openai_api_key_raises_when_missing(monkeypatch):
    monkeypatch.delenv(
        "OPENAI_API_KEY",
        raising=False,
    )

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        get_openai_api_key()