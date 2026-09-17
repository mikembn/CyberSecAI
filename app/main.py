from app.analyzer import analyze_ports
from app.scanner import parse_nmap_output, run_nmap_scan


def main() -> None:
    target = input("Enter an authorized target to scan: ").strip()

    if not target:
        print("Error: Target cannot be empty.")
        return

    print(f"\nScanning {target}...\n")

    scan_result = run_nmap_scan(target)

    if not scan_result["success"]:
        print("Scan failed.")
        print(scan_result["stderr"])
        return

    ports = parse_nmap_output(scan_result["stdout"])
    findings = analyze_ports(ports)

    print("=" * 60)
    print("CyberSecAI Security Scan")
    print("=" * 60)

    print(f"\nTarget: {target}")
    print(f"Open ports found: {len(ports)}")
    print(f"Security findings: {len(findings)}")

    print("\nOpen Ports")
    print("-" * 60)

    for port in ports:
        version = port["version"] or "Version not identified"

        print(
            f'{port["port"]}/{port["protocol"]} '
            f'- {port["service"]} '
            f'- {version}'
        )

    print("\nSecurity Findings")
    print("-" * 60)

    if not findings:
        print("No findings generated.")

    for finding in findings:
        print(
            f'\n[{finding["severity"].upper()}] '
            f'{finding["category"]}'
        )
        print(f'Port: {finding["port"]}')
        print(f'Finding: {finding["finding"]}')
        print(f'Recommendation: {finding["recommendation"]}')


if __name__ == "__main__":
    main()