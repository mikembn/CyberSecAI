from app.analyzer import analyze_ports


def test_analyze_ports_identifies_file_sharing():
    ports = [
        {
            "port": 445,
            "protocol": "tcp",
            "state": "open",
            "service": "microsoft-ds",
            "version": None,
        }
    ]

    findings = analyze_ports(ports)

    assert any(
        finding["category"] == "File Sharing Service"
        for finding in findings
    )


def test_analyze_ports_identifies_uncertain_service():
    ports = [
        {
            "port": 9080,
            "protocol": "tcp",
            "state": "open",
            "service": "glrpc?",
            "version": None,
        }
    ]

    findings = analyze_ports(ports)

    assert any(
        finding["category"] == "Service Identification"
        for finding in findings
    )


def test_analyze_ports_identifies_administrative_service():
    ports = [
        {
            "port": 3389,
            "protocol": "tcp",
            "state": "open",
            "service": "ms-wbt-server",
            "version": "Microsoft Terminal Services",
        }
    ]

    findings = analyze_ports(ports)

    assert any(
        finding["category"] == "Administrative Service"
        for finding in findings
    )


def test_analyze_ports_returns_empty_for_no_ports():
    findings = analyze_ports([])

    assert findings == []