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
            "service": "http",
            "version": "Apache",
            "severity": "low",
            "category": "Web Service",
            "finding": "Web service detected.",
            "recommendation": "Verify that the service is required.",
        }
    ]

    report = build_report("127.0.0.1", ports, findings)

    assert report["tool"] == "CyberSecAI"
    assert report["target"] == "127.0.0.1"
    assert report["summary"]["open_ports"] == 1
    assert report["summary"]["findings"] == 1
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