from typing import Any


ADMINISTRATIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
}

FILE_SHARING_PORTS = {
    139: "NetBIOS/SMB",
    445: "SMB",
}


def create_finding(
    port_info: dict[str, Any],
    *,
    severity: str,
    category: str,
    finding: str,
    recommendation: str,
) -> dict[str, Any]:
    """Create a standardized security finding."""

    return {
        "port": port_info["port"],
        "protocol": port_info["protocol"],
        "service": port_info["service"],
        "version": port_info.get("version"),
        "severity": severity,
        "category": category,
        "finding": finding,
        "recommendation": recommendation,
    }


def analyze_ports(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Analyze discovered open ports and generate security findings.

    An open port is not automatically a vulnerability.
    Findings identify services that deserve additional review.
    """

    findings = []

    for port_info in ports:
        port = port_info["port"]
        service = port_info["service"]
        version = port_info.get("version")

        # Administrative services
        if port in ADMINISTRATIVE_PORTS:
            service_name = ADMINISTRATIVE_PORTS[port]

            findings.append(
                create_finding(
                    port_info,
                    severity="medium",
                    category="Administrative Service",
                    finding=(
                        f"{service_name} is exposed on port {port}. "
                        "Remote administrative services should be "
                        "restricted to authorized systems."
                    ),
                    recommendation=(
                        "Verify that remote administration is required. "
                        "Restrict access using firewall rules, network "
                        "segmentation, and strong authentication."
                    ),
                )
            )

        # File-sharing services
        elif port in FILE_SHARING_PORTS:
            service_name = FILE_SHARING_PORTS[port]

            findings.append(
                create_finding(
                    port_info,
                    severity="medium",
                    category="File Sharing Service",
                    finding=(
                        f"{service_name} is exposed on port {port}. "
                        "File-sharing services can provide network access "
                        "to shared resources."
                    ),
                    recommendation=(
                        "Verify that file sharing is required and restrict "
                        "access to trusted systems using firewall rules "
                        "and network segmentation."
                    ),
                )
            )

        # Uncertain service identification
        if service.endswith("?"):
            findings.append(
                create_finding(
                    port_info,
                    severity="low",
                    category="Service Identification",
                    finding=(
                        f"Nmap reported uncertain service identification "
                        f"for port {port} ({service})."
                    ),
                    recommendation=(
                        "Identify the process listening on this port and "
                        "confirm whether the service is expected."
                    ),
                )
            )

        # Missing version information
        if version is None:
            findings.append(
                create_finding(
                    port_info,
                    severity="informational",
                    category="Version Information",
                    finding=(
                        f"No service version information was identified "
                        f"for port {port}."
                    ),
                    recommendation=(
                        "Perform additional authorized service "
                        "identification when version information is "
                        "required for the assessment."
                    ),
                )
            )

    return findings