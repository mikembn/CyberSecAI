from pathlib import Path

from app.markdown_reporter import (
    build_markdown_report,
    save_markdown_report,
)


def sample_report():
    return {
        "tool": "CyberSecAI",
        "report_version": "0.3",
        "generated_at": "2026-09-21T06:00:00+00:00",
        "target": "127.0.0.1",
        "summary": {
            "open_ports": 2,
            "findings": 2,
            "security_findings": 1,
            "observations": 1,
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0,
                "informational": 1,
            },
        },
        "open_ports": [
            {
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "version": "Apache httpd",
            },
            {
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "version": "OpenSSH",
            },
        ],
        "findings": [
            {
                "severity": "medium",
                "category": "Administrative Service",
                "port": 22,
                "finding": "SSH service is exposed.",
                "evidence": "Port 22/tcp is open.",
                "recommendation": "Restrict SSH access to authorized sources.",
            },
            {
                "severity": "informational",
                "category": "Version Information",
                "port": 80,
                "finding": "Web service version identified.",
                "evidence": "Apache httpd detected.",
                "recommendation": "Keep the web server updated.",
            },
        ],
        "ai_analysis": "Review exposed services and restrict unnecessary access.",
    }


def test_build_markdown_report_contains_expected_sections():
    report = sample_report()

    markdown = build_markdown_report(report)

    assert "# CyberSecAI Security Assessment" in markdown
    assert "## Executive Summary" in markdown
    assert "## Open Ports" in markdown
    assert "## Security Findings" in markdown
    assert "## AI Security Analysis" in markdown


def test_build_markdown_report_contains_report_data():
    report = sample_report()

    markdown = build_markdown_report(report)

    assert "127.0.0.1" in markdown
    assert "Apache httpd" in markdown
    assert "Administrative Service" in markdown
    assert "SSH service is exposed." in markdown
    assert "Restrict SSH access to authorized sources." in markdown


def test_save_markdown_report_creates_matching_md_file(tmp_path):
    report = sample_report()

    json_file = tmp_path / "scan_127.0.0.1_20260921_060000.json"

    markdown_file = save_markdown_report(
        report,
        json_file,
    )

    assert markdown_file == Path(
        tmp_path / "scan_127.0.0.1_20260921_060000.md"
    )

    assert markdown_file.exists()

    content = markdown_file.read_text(encoding="utf-8")

    assert "# CyberSecAI Security Assessment" in content
    assert "127.0.0.1" in content


def test_save_markdown_report_accepts_string_path(tmp_path):
    report = sample_report()

    json_file = str(
        tmp_path / "scan_127.0.0.1_20260921_060000.json"
    )

    markdown_file = save_markdown_report(
        report,
        json_file,
    )

    assert markdown_file.exists()
    assert markdown_file.suffix == ".md"