import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SECURITY_SEVERITIES = {
    "critical",
    "high",
    "medium",
    "low",
}

OBSERVATION_SEVERITIES = {
    "informational",
}


def build_report(
    target: str,
    ports: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    ai_analysis: str | None = None,
) -> dict[str, Any]:
    """
    Build a structured CyberSecAI security assessment report.
    """

    severity_counts = Counter(
        finding["severity"].lower()
        for finding in findings
    )

    security_findings = sum(
        1
        for finding in findings
        if finding.get("type", "").lower() == "security"
        or (
            "type" not in finding
            and finding.get("severity", "").lower()
            in SECURITY_SEVERITIES
        )
    )

    observations = sum(
        1
        for finding in findings
        if finding.get("type", "").lower() == "observation"
        or (
            "type" not in finding
            and finding.get("severity", "").lower()
            in OBSERVATION_SEVERITIES
        )
    )

    report = {
        "tool": "CyberSecAI",
        "report_version": "0.6",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "summary": {
            "open_ports": len(ports),
            "findings": len(findings),
            "security_findings": security_findings,
            "observations": observations,
            "severity_counts": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "informational": severity_counts.get(
                    "informational",
                    0,
                ),
            },
        },
        "open_ports": ports,
        "findings": findings,
    }

    if ai_analysis is not None:
        report["ai_analysis"] = ai_analysis

    return report


def save_json_report(
    report: dict[str, Any],
    output_directory: str = "reports",
) -> Path:
    """
    Save a security assessment report as a JSON file.
    """

    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = (
        report["target"]
        .replace(":", "_")
        .replace("/", "_")
    )

    report_file = (
        output_path
        / f"scan_{target}_{timestamp}.json"
    )

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return report_file