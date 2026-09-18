from collections import Counter
from typing import Any


SEVERITY_ORDER = [
    "critical",
    "high",
    "medium",
    "low",
    "informational",
]


def summarize_findings(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create a severity summary from security findings."""

    severity_counts = Counter(
        finding["severity"].lower()
        for finding in findings
    )

    counts = {
        severity: severity_counts.get(severity, 0)
        for severity in SEVERITY_ORDER
    }

    return {
        "total_findings": len(findings),
        "severity_counts": counts,
    }