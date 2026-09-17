from app.ai_workflow import run_ai_analysis
from app.mock_ai_provider import MockAIProvider


def test_run_ai_analysis_uses_provider():
    provider = MockAIProvider()

    result = run_ai_analysis(
        provider=provider,
        target="127.0.0.1",
        ports=[],
        findings=[],
    )

    assert "Mock AI analysis completed successfully" in result


def test_run_ai_analysis_accepts_security_data():
    provider = MockAIProvider()

    ports = [
        {
            "port": 445,
            "protocol": "tcp",
            "state": "open",
            "service": "microsoft-ds",
            "version": None,
        }
    ]

    findings = [
        {
            "port": 445,
            "protocol": "tcp",
            "service": "microsoft-ds",
            "version": None,
            "severity": "medium",
            "type": "security",
            "category": "File Sharing Service",
            "finding": "SMB is exposed.",
            "recommendation": "Restrict access.",
            "evidence": {
                "port": 445,
                "protocol": "tcp",
                "state": "open",
                "service": "microsoft-ds",
                "version": None,
            },
        }
    ]

    result = run_ai_analysis(
        provider=provider,
        target="127.0.0.1",
        ports=ports,
        findings=findings,
    )

    assert isinstance(result, str)
    assert "Mock AI analysis completed successfully" in result