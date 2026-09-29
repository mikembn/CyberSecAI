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

    file_sharing_findings = [
        finding
        for finding in findings
        if finding["category"] == "File Sharing Service"
    ]

    assert len(file_sharing_findings) == 1
    assert file_sharing_findings[0]["severity"] == "medium"
    assert file_sharing_findings[0]["type"] == "security"
        
    evidence = file_sharing_findings[0]["evidence"]

    assert evidence["port"] == 445
    assert evidence["protocol"] == "tcp"
    assert evidence["state"] == "open"
    assert evidence["service"] == "microsoft-ds"
    assert evidence["version"] is None


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

    service_findings = [
        finding
        for finding in findings
        if finding["category"] == "Service Identification"
    ]

    assert len(service_findings) == 1
    assert service_findings[0]["severity"] == "low"
    assert service_findings[0]["type"] == "observation"


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

    administrative_findings = [
        finding
        for finding in findings
        if finding["category"] == "Administrative Service"
    ]

    assert len(administrative_findings) == 1
    assert administrative_findings[0]["severity"] == "medium"
    assert administrative_findings[0]["type"] == "security"


def test_analyze_ports_missing_version_is_observation():
    ports = [
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "version": None,
        }
    ]

    findings = analyze_ports(ports)

    version_findings = [
        finding
        for finding in findings
        if finding["category"] == "Version Information"
    ]

    assert len(version_findings) == 1
    assert version_findings[0]["severity"] == "informational"
    assert version_findings[0]["type"] == "observation"


def test_analyze_ports_returns_empty_for_no_ports():
    findings = analyze_ports([])

    assert findings == []
def test_analyze_ports_identifies_telnet_as_high_risk():
    ports = [
        {
            "port": 23,
            "protocol": "tcp",
            "state": "open",
            "service": "telnet",
            "version": None,
        }
    ]

    findings = analyze_ports(ports)

    telnet_findings = [
        finding
        for finding in findings
        if finding["category"] == "Legacy Administrative Service"
    ]

    assert len(telnet_findings) == 1
    assert telnet_findings[0]["severity"] == "high"
    assert telnet_findings[0]["type"] == "security"
def test_analyze_ports_identifies_ssh_as_administrative_service():
    ports = [
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "version": "OpenSSH 9.6",
        }
    ]

    findings = analyze_ports(ports)

    administrative_findings = [
        finding
        for finding in findings
        if finding["category"] == "Administrative Service"
    ]

    assert len(administrative_findings) == 1
    assert administrative_findings[0]["severity"] == "medium"


def test_analyze_ports_identifies_vnc_as_administrative_service():
    ports = [
        {
            "port": 5900,
            "protocol": "tcp",
            "state": "open",
            "service": "vnc",
            "version": None,
        }
    ]

    findings = analyze_ports(ports)

    administrative_findings = [
        finding
        for finding in findings
        if finding["category"] == "Administrative Service"
    ]

    assert len(administrative_findings) == 1
    assert administrative_findings[0]["severity"] == "medium"
def test_analyze_ports_findings_include_standardized_evidence():
    ports = [
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "version": "OpenSSH 9.6",
        }
    ]

    findings = analyze_ports(ports)

    assert findings

    for finding in findings:
        assert "evidence" in finding
        assert finding["evidence"]["port"] == 22
        assert finding["evidence"]["protocol"] == "tcp"
        assert finding["evidence"]["state"] == "open"
        assert finding["evidence"]["service"] == "ssh"
        assert finding["evidence"]["version"] == "OpenSSH 9.6"
def test_analyze_ports_identifies_web_and_database_services():
    ports = [
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "version": "Example Web Server 2.4",
        },
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "service": "https",
            "version": "Example Web Server 2.4",
        },
        {
            "port": 3306,
            "protocol": "tcp",
            "state": "open",
            "service": "mysql",
            "version": "MySQL 8.0",
        },
        {
            "port": 5432,
            "protocol": "tcp",
            "state": "open",
            "service": "postgresql",
            "version": "PostgreSQL 16",
        },
    ]

    findings = analyze_ports(ports)

    assert len(findings) == 4

    web_findings = [
        finding
        for finding in findings
        if finding["category"] == "Web Service"
    ]

    database_findings = [
        finding
        for finding in findings
        if finding["category"] == "Database Service"
    ]

    assert len(web_findings) == 2
    assert len(database_findings) == 2

    assert web_findings[0]["severity"] == "low"
    assert web_findings[1]["severity"] == "informational"

    for finding in database_findings:
        assert finding["severity"] == "medium"
        assert finding["type"] == "security"


def test_analyze_ports_identifies_alternate_web_services():
    ports = [
        {
            "port": 8080,
            "protocol": "tcp",
            "state": "open",
            "service": "http-proxy",
            "version": "Example Web Server 2.4",
        },
        {
            "port": 8443,
            "protocol": "tcp",
            "state": "open",
            "service": "https-alt",
            "version": "Example Web Server 2.4",
        },
    ]

    findings = analyze_ports(ports)

    web_findings = [
        finding
        for finding in findings
        if finding["category"] == "Web Service"
    ]

    assert len(web_findings) == 2
    assert web_findings[0]["severity"] == "low"
    assert web_findings[1]["severity"] == "informational"
def test_analyze_ports_assigns_finding_ids():
    ports = [
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "version": "OpenSSH 9.6",
        },
        {
            "port": 445,
            "protocol": "tcp",
            "state": "open",
            "service": "microsoft-ds",
            "version": None,
        },
    ]

    findings = analyze_ports(ports)

    finding_ids = {finding["finding_id"] for finding in findings}

    assert "CYB-ADMIN-001" in finding_ids
    assert "CYB-FILE-001" in finding_ids
    assert "CYB-VER-001" in finding_ids

    for finding in findings:
        assert finding["finding_id"].startswith("CYB-")