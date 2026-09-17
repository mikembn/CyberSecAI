from app.ai_provider import AIProvider


class MockAIProvider(AIProvider):
    """
    Local test provider used to validate the AI workflow
    without connecting to an external AI service.
    """

    def analyze(self, prompt: str) -> str:
        return (
            "Mock AI analysis completed successfully. "
            "The prompt was received and processed."
        )