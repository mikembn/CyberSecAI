import subprocess

from app.scanner import (
    parse_nmap_output,
    run_nmap_scan,
    validate_target,
)

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


def test_run_nmap_scan_success(monkeypatch):
    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="22/tcp open ssh OpenSSH 9.6",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", mock_run)

    result = run_nmap_scan("127.0.0.1")

    assert result["success"] is True
    assert result["return_code"] == 0
    assert "22/tcp" in result["stdout"]
    assert result["stderr"] == ""


def test_run_nmap_scan_handles_timeout(monkeypatch):
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=args,
            timeout=120,
        )

    monkeypatch.setattr(subprocess, "run", mock_run)

    result = run_nmap_scan("127.0.0.1")

    assert result["success"] is False
    assert result["return_code"] == -1
    assert "timed out" in result["stderr"]


def test_run_nmap_scan_handles_missing_nmap(monkeypatch):
    def mock_run(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", mock_run)

    result = run_nmap_scan("127.0.0.1")

    assert result["success"] is False
    assert result["return_code"] == -1
    assert "not found" in result["stderr"]


def test_run_nmap_scan_handles_nmap_failure(monkeypatch):
    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout="",
            stderr="Nmap scan failed.",
        )

    monkeypatch.setattr(subprocess, "run", mock_run)

    result = run_nmap_scan("127.0.0.1")

    assert result["success"] is False
    assert result["return_code"] == 1
    assert result["stderr"] == "Nmap scan failed."
def test_validate_target_strips_surrounding_whitespace():
    assert validate_target("  127.0.0.1  ") == "127.0.0.1"


def test_validate_target_rejects_empty_target():
    import pytest

    with pytest.raises(ValueError, match="cannot be empty"):
        validate_target("")


def test_validate_target_rejects_whitespace_only_target():
    import pytest

    with pytest.raises(ValueError, match="cannot be empty"):
        validate_target("   ")


def test_validate_target_rejects_internal_whitespace():
    import pytest

    with pytest.raises(ValueError, match="cannot contain whitespace"):
        validate_target("192.168.1.1 test")
