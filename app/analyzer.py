from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PortRule:
    """Define the security classification for a network port."""

    port: int
    service_name: str
    severity: str
    category: str
    finding_type: str


PORT_RULES = {
    22: PortRule(
        port=22,
        service_name="SSH",
        severity="medium",
        category="Administrative Service",
        finding_type="security",
    ),
    3389: PortRule(
        port=3389,
        service_name="RDP",
        severity="medium",
        category="Administrative Service",
        finding_type="security",
    ),
    5900: PortRule(
        port=5900,
        service_name="VNC",
        severity="medium",
        category="Administrative Service",
        finding_type="security",
    ),
    23: PortRule(
        port=23,
        service_name="Telnet",
        severity="high",
        category="Legacy Administrative Service",
        finding_type="security",
    ),
    139: PortRule(
        port=139,
        service_name="NetBIOS/SMB",
        severity="medium",
        category="File Sharing Service",
        finding_type="security",
    ),
    445: PortRule(
        port=445,
        service_name="SMB",
        severity="medium",
        category="File Sharing Service",
        finding_type="security",
    ),
}

def create_finding(
    port_info: dict[str, Any],
    *,
    severity: str,
    finding_type: str,
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
        "type": finding_type,
        "category": category,
        "finding": finding,
        "recommendation": recommendation,
        "evidence": {
            "port": port_info["port"],
            "protocol": port_info["protocol"],
            "state": port_info["state"],
            "service": port_info["service"],
            "version": port_info.get("version"),
        },
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
     
        rule = PORT_RULES.get(port)

        if rule:
            if rule.port == 23:
                finding = (
                    f"{rule.service_name} is exposed on port {port}. "
                    "Telnet transmits administrative traffic without "
                    "the protections provided by modern encrypted "
                    "remote-administration protocols."
                )
                recommendation = (
                    "Disable Telnet when it is not required and use "
                    "a secure administrative protocol such as SSH. "
                    "Restrict administrative access to authorized "
                    "systems."
                )

            elif rule.category == "Administrative Service":
                finding = (
                    f"{rule.service_name} is exposed on port {port}. "
                    "Remote administrative services should be "
                    "restricted to authorized systems."
                )
                recommendation = (
                    "Verify that remote administration is required. "
                    "Restrict access using firewall rules, network "
                    "segmentation, and strong authentication."
                )

            elif rule.category == "File Sharing Service":
                finding = (
                    f"{rule.service_name} is exposed on port {port}. "
                    "File-sharing services can provide network access "
                    "to shared resources."
                )
                recommendation = (
                    "Verify that file sharing is required and restrict "
                    "access to trusted systems using firewall rules "
                    "and network segmentation."
                )

            else:
                finding = (
                    f"{rule.service_name} is exposed on port {port}."
                )
                recommendation = (
                    "Verify that the service is required and restrict "
                    "access to authorized systems."
                )

            findings.append(
                create_finding(
                    port_info,
                    severity=rule.severity,
                    finding_type=rule.finding_type,
                    category=rule.category,
                    finding=finding,
                    recommendation=recommendation,
                )
            )

        # Uncertain service identification
        if service.endswith("?"):
            findings.append(
                create_finding(
                    port_info,
                    severity="low",
                    finding_type="observation",
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
                    finding_type="observation",
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