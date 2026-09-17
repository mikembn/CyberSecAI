from openai import OpenAI

from app.ai_provider import AIProvider
from app.config import get_openai_api_key


class OpenAIProvider(AIProvider):
    """
    OpenAI-backed AI provider for CyberSecAI.
    """

    def __init__(
        self,
        model: str = "gpt-5.6-luna",
    ) -> None:
        self.model = model
        self.client = OpenAI(
            api_key=get_openai_api_key()
        )

    def analyze(self, prompt: str) -> str:
        """
        Send a security-analysis prompt to OpenAI
        and return the generated response.
        """

        response = self.client.responses.create(
            model=self.model,
            input=prompt,
        )

        return response.output_text