from typing import Any

from app.ai_analyzer import build_ai_prompt
from app.ai_provider import AIProvider


def run_ai_analysis(
    provider: AIProvider,
    target: str,
    ports: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> str:
    """
    Run an AI-assisted security analysis using a configured provider.
    """

    prompt = build_ai_prompt(
        target=target,
        ports=ports,
        findings=findings,
    )

    return provider.analyze(prompt)