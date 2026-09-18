import argparse

from app.ai_workflow import run_ai_analysis
from app.analyzer import analyze_ports
from app.openai_provider import OpenAIProvider
from app.reporter import build_report, save_json_report
from app.scanner import parse_nmap_output, run_nmap_scan
from app.summary import summarize_findings


def parse_args() -> argparse.Namespace:
    """Parse CyberSecAI command-line arguments."""
    parser = argparse.ArgumentParser(
        description="CyberSecAI - AI-assisted cybersecurity assessment tool."
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Authorized target to scan.",
    )

    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI security analysis.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target = args.target.strip()

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
    summary = summarize_findings(findings)

    print("\nSecurity Summary")
    print("-" * 60)

    print(f'Total findings: {summary["total_findings"]}')

    for severity, count in summary["severity_counts"].items():
        print(f"{severity.capitalize():<15}: {count}")

    ai_analysis = None

    print("\nAI Security Analysis")
    print("-" * 60)

    if args.no_ai:
        print("AI analysis skipped (--no-ai).")
    else:
        try:
            provider = OpenAIProvider()

            ai_analysis = run_ai_analysis(
                provider=provider,
                target=target,
                ports=ports,
                findings=findings,
            )

            print(ai_analysis)

        except Exception as exc:
            print(f"AI analysis failed: {exc}")

    report = build_report(
        target=target,
        ports=ports,
        findings=findings,
        ai_analysis=ai_analysis,
    )

    report_file = save_json_report(report)

    print("\nReport")
    print("-" * 60)
    print(f"JSON report saved to: {report_file}")


if __name__ == "__main__":
    main()