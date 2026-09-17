from app.scanner import parse_nmap_output


def test_parse_nmap_output_finds_open_ports():
    sample_output = """
    PORT      STATE SERVICE       VERSION
    22/tcp    open  ssh           OpenSSH 9.6
    80/tcp    open  http          Apache httpd 2.4
    443/tcp   closed https
    """

    result = parse_nmap_output(sample_output)

    assert len(result) == 2

    assert result[0]["port"] == 22
    assert result[0]["protocol"] == "tcp"
    assert result[0]["state"] == "open"
    assert result[0]["service"] == "ssh"
    assert result[0]["version"] == "OpenSSH 9.6"

    assert result[1]["port"] == 80
    assert result[1]["service"] == "http"


def test_parse_nmap_output_ignores_closed_ports():
    sample_output = """
    PORT      STATE SERVICE
    22/tcp    closed ssh
    80/tcp    open   http
    """

    result = parse_nmap_output(sample_output)

    assert len(result) == 1
    assert result[0]["port"] == 80