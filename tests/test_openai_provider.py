from unittest.mock import MagicMock, patch

from app.ai_provider import AIProvider
from app.openai_provider import OpenAIProvider


def test_openai_provider_implements_ai_provider():
    with patch(
        "app.openai_provider.OpenAI"
    ):
        provider = OpenAIProvider()

    assert isinstance(provider, AIProvider)


def test_openai_provider_returns_response_text():
    mock_response = MagicMock()
    mock_response.output_text = "AI security analysis completed."

    with patch(
        "app.openai_provider.OpenAI"
    ) as mock_openai:

        mock_client = mock_openai.return_value
        mock_client.responses.create.return_value = mock_response

        provider = OpenAIProvider()

        result = provider.analyze(
            "Analyze this security evidence."
        )

    assert result == "AI security analysis completed."

    mock_client.responses.create.assert_called_once_with(
        model="gpt-5.6-mini",
        input="Analyze this security evidence.",
    )