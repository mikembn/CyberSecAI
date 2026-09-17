from app.ai_analyzer import build_ai_prompt


def test_build_ai_prompt_contains_target():
    prompt = build_ai_prompt(
        target="127.0.0.1",
        ports=[],
        findings=[],
    )

    assert "127.0.0.1" in prompt


def test_build_ai_prompt_contains_security_evidence():
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

    prompt = build_ai_prompt(
        target="127.0.0.1",
        ports=ports,
        findings=findings,
    )

    assert "445" in prompt
    assert "microsoft-ds" in prompt
    assert "SMB is exposed." in prompt
    assert "Restrict access." in prompt


def test_build_ai_prompt_prevents_hallucinated_evidence():
    prompt = build_ai_prompt(
        target="127.0.0.1",
        ports=[],
        findings=[],
    )

    assert "Do not invent vulnerabilities" in prompt
    assert "Use only the evidence provided" in prompt