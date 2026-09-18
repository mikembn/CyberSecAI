from app.summary import summarize_findings


def test_summarize_findings_counts_severities():
    findings = [
        {"severity": "medium"},
        {"severity": "low"},
        {"severity": "low"},
        {"severity": "informational"},
    ]

    result = summarize_findings(findings)

    assert result["total_findings"] == 4
    assert result["severity_counts"]["critical"] == 0
    assert result["severity_counts"]["high"] == 0
    assert result["severity_counts"]["medium"] == 1
    assert result["severity_counts"]["low"] == 2
    assert result["severity_counts"]["informational"] == 1


def test_summarize_findings_handles_empty_findings():
    result = summarize_findings([])

    assert result["total_findings"] == 0

    for severity in [
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    ]:
        assert result["severity_counts"][severity] == 0


def test_summarize_findings_is_case_insensitive():
    findings = [
        {"severity": "MEDIUM"},
        {"severity": "Low"},
        {"severity": "INFORMATIONAL"},
    ]

    result = summarize_findings(findings)

    assert result["severity_counts"]["medium"] == 1
    assert result["severity_counts"]["low"] == 1
    assert result["severity_counts"]["informational"] == 1