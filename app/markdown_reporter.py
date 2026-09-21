from pathlib import Path
from typing import Any


SEVERITY_ORDER = [
    "critical",
    "high",
    "medium",
    "low",
    "informational",
]


def _format_value(value: Any) -> str:
    """Convert a value into safe Markdown text."""
    if value is None or value == "":
        return "Not identified"

    return str(value).replace("|", "\\|").replace("\n", " ")


def build_markdown_report(report: dict[str, Any]) -> str:
    """
    Build a human-readable Markdown security assessment report
    from a CyberSecAI report dictionary.
    """

    target = _format_value(report.get("target"))
    generated_at = _format_value(report.get("generated_at"))
    report_version = _format_value(report.get("report_version"))

    summary = report.get("summary", {})
    open_ports = report.get("open_ports", [])
    findings = report.get("findings", [])
    ai_analysis = report.get("ai_analysis")

    lines: list[str] = []

    lines.append("# CyberSecAI Security Assessment")
    lines.append("")
    lines.append(f"**Target:** `{target}`")
    lines.append(f"**Generated:** {generated_at}")
    lines.append(f"**Report Version:** {report_version}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")

    lines.append(
        f"CyberSecAI identified **{summary.get('open_ports', len(open_ports))}** "
        f"open port(s) and **{summary.get('findings', len(findings))}** "
        "finding(s) during the assessment."
    )
    lines.append("")

    lines.append("| Metric | Count |")
    lines.append("|---|---:|")
    lines.append(
        f"| Open Ports | {summary.get('open_ports', len(open_ports))} |"
    )
    lines.append(
        f"| Total Findings | {summary.get('findings', len(findings))} |"
    )
    lines.append(
        f"| Security Findings | {summary.get('security_findings', 0)} |"
    )
    lines.append(
        f"| Observations | {summary.get('observations', 0)} |"
    )

    severity_counts = summary.get("severity_counts", {})

    for severity in SEVERITY_ORDER:
        lines.append(
            f"| {severity.capitalize()} | "
            f"{severity_counts.get(severity, 0)} |"
        )

    lines.append("")

    lines.append("## Open Ports")
    lines.append("")

    if not open_ports:
        lines.append("No open ports were identified.")
        lines.append("")
    else:
        lines.append("| Port | Protocol | Service | Version |")
        lines.append("|---:|---|---|---|")

        for port in open_ports:
            lines.append(
                f"| {_format_value(port.get('port'))} "
                f"| {_format_value(port.get('protocol'))} "
                f"| {_format_value(port.get('service'))} "
                f"| {_format_value(port.get('version'))} |"
            )

        lines.append("")

    lines.append("## Security Findings")
    lines.append("")

    if not findings:
        lines.append("No security findings were generated.")
        lines.append("")
    else:
        for index, finding in enumerate(findings, start=1):
            severity = _format_value(
                finding.get("severity", "unknown")
            ).upper()

            category = _format_value(
                finding.get("category", "Uncategorized")
            )

            lines.append(
                f"### {index}. {category}"
            )
            lines.append("")

            lines.append(f"**Severity:** {severity}")
            lines.append("")

            if finding.get("port") is not None:
                lines.append(
                    f"**Port:** `{_format_value(finding.get('port'))}`"
                )
                lines.append("")

            if finding.get("finding"):
                lines.append("**Finding:**")
                lines.append("")
                lines.append(
                    _format_value(finding["finding"])
                )
                lines.append("")

            if finding.get("evidence"):
                lines.append("**Evidence:**")
                lines.append("")

                evidence = finding["evidence"]

                if isinstance(evidence, dict):
                    lines.append(
                        f"- **Port:** {_format_value(evidence.get('port'))}/"
                        f"{_format_value(evidence.get('protocol'))}"
                    )
                    lines.append(
                        f"- **State:** {_format_value(evidence.get('state'))}"
                    )
                    lines.append(
                        f"- **Service:** {_format_value(evidence.get('service'))}"
                    )
                    lines.append(
                        f"- **Version:** {_format_value(evidence.get('version'))}"
                    )
                else:
                    lines.append(_format_value(evidence))

                lines.append("")

            if finding.get("recommendation"):
                lines.append("**Recommendation:**")
                lines.append("")
                lines.append(
                    _format_value(finding["recommendation"])
                )
                lines.append("")

    if ai_analysis:
        lines.append("## AI Security Analysis")
        lines.append("")
        lines.append(str(ai_analysis).strip())
        lines.append("")

    lines.append("## Assessment Notes")
    lines.append("")
    lines.append(
        "This report was generated automatically by CyberSecAI. "
        "Findings are based on the scan results and analysis rules "
        "available at the time of the assessment."
    )
    lines.append("")

    return "\n".join(lines)


def save_markdown_report(
    report: dict[str, Any],
    report_file: str | Path,
) -> Path:
    """
    Save a Markdown report using the same base filename as the JSON report.
    """

    report_path = Path(report_file)
    markdown_file = report_path.with_suffix(".md")

    markdown_content = build_markdown_report(report)

    markdown_file.write_text(
        markdown_content,
        encoding="utf-8",
    )

    return markdown_file