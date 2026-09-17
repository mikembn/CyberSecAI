import os


def get_openai_api_key() -> str:
    """
    Return the OpenAI API key from the environment.

    Raises:
        RuntimeError: If the API key is not configured.
    """

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not configured."
        )

    return api_key