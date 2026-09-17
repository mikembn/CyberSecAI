import re
import subprocess
from typing import Any


def run_nmap_scan(target: str) -> dict[str, Any]:
    """
    Run a basic Nmap service-detection scan against an authorized target.
    """

    command = [
        "nmap",
        "-sV",
        "--version-light",
        target,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        return {
            "target": target,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0,
        }

    except subprocess.TimeoutExpired:
        return {
            "target": target,
            "return_code": -1,
            "stdout": "",
            "stderr": "Nmap scan timed out after 120 seconds.",
            "success": False,
        }

    except FileNotFoundError:
        return {
            "target": target,
            "return_code": -1,
            "stdout": "",
            "stderr": "Nmap executable was not found.",
            "success": False,
        }


def parse_nmap_output(output: str) -> list[dict[str, Any]]:
    """
    Parse open TCP ports from standard Nmap output.

    Returns:
        A list of dictionaries containing port, protocol, state,
        service, and version information.
    """

    ports = []

    for line in output.splitlines():
        match = re.match(
            r"^(\d+)/(\w+)\s+(\w+)\s+(\S+)(?:\s+(.*))?$",
            line.strip(),
        )

        if not match:
            continue

        port, protocol, state, service, version = match.groups()

        if state != "open":
            continue

        ports.append(
            {
                "port": int(port),
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version.strip() if version else None,
            }
        )

    return ports