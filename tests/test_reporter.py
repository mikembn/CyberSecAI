import json

from app.reporter import build_report, save_json_report


def test_build_report_contains_scan_data():
    ports = [
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "version": "Apache",
        }
    ]

    findings = [
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "version": "Apache",
            "severity": "medium",
            "type": "security",
            "category": "Web Service",
            "finding": "Web service detected.",
            "recommendation": "Verify that the service is required.",
        },
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "version": "OpenSSH",
            "severity": "low",
            "type": "observation",
            "category": "Administrative Service",
            "finding": "SSH detected.",
            "recommendation": "Restrict SSH access.",
        },
    ]

    report = build_report("127.0.0.1", ports, findings)

    assert report["tool"] == "CyberSecAI"
    assert report["report_version"] == "0.3"
    assert report["target"] == "127.0.0.1"

    assert report["summary"]["open_ports"] == 1
    assert report["summary"]["findings"] == 2
    assert report["summary"]["security_findings"] == 1
    assert report["summary"]["observations"] == 1

    assert report["summary"]["severity_counts"]["critical"] == 0
    assert report["summary"]["severity_counts"]["high"] == 0
    assert report["summary"]["severity_counts"]["medium"] == 1
    assert report["summary"]["severity_counts"]["low"] == 1
    assert report["summary"]["severity_counts"]["informational"] == 0

    assert report["open_ports"] == ports
    assert report["findings"] == findings
    assert "generated_at" in report


def test_save_json_report_creates_valid_file(tmp_path):
    report = build_report("127.0.0.1", [], [])

    report_file = save_json_report(
        report,
        output_directory=str(tmp_path),
    )

    assert report_file.exists()
    assert report_file.suffix == ".json"

    with report_file.open("r", encoding="utf-8") as file:
        saved_report = json.load(file)

    assert saved_report["tool"] == "CyberSecAI"
    assert saved_report["target"] == "127.0.0.1"
    assert saved_report["report_version"] == "0.3"


def test_build_report_counts_multiple_severities():
    findings = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
        {"severity": "informational"},
        {"severity": "informational"},
    ]

    report = build_report("127.0.0.1", [], findings)

    counts = report["summary"]["severity_counts"]
    assert report["summary"]["security_findings"] == 5
    assert report["summary"]["observations"] == 2

    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert counts["medium"] == 1
    assert counts["low"] == 1
    assert counts["informational"] == 2

def test_build_report_includes_ai_analysis():
    report = build_report(
        target="127.0.0.1",
        ports=[],
        findings=[],
        ai_analysis="Example AI security analysis.",
    )

    assert report["ai_analysis"] == "Example AI security analysis."