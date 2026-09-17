from app.ai_provider import AIProvider
from app.mock_ai_provider import MockAIProvider


def test_mock_ai_provider_implements_ai_provider():
    provider = MockAIProvider()

    assert isinstance(provider, AIProvider)


def test_mock_ai_provider_returns_analysis():
    provider = MockAIProvider()

    result = provider.analyze(
        "Analyze this authorized security assessment."
    )

    assert isinstance(result, str)
    assert "Mock AI analysis completed successfully" in result