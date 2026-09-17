from abc import ABC, abstractmethod


class AIProvider(ABC):
    """
    Interface for AI providers used by CyberSecAI.
    """

    @abstractmethod
    def analyze(self, prompt: str) -> str:
        """
        Analyze a security prompt and return the AI response.
        """
        raise NotImplementedError