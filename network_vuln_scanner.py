#!/usr/bin/env python3
"""
CLI Network Vulnerability Scanner.

This tool wraps Nmap for port scanning and service enumeration, then applies a
small rule-based vulnerability check against discovered services. It is intended
for authorized security testing and as a base for future CVE mapping.
"""

from __future__ import annotations

import argparse
import csv
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SCAN_PROFILES = {
    "quick": "-T4 -F -sV --version-light",
    "default": "-sV",
    "safe": "-sV --version-light --script default,safe",
    "deep": "-T4 -A --version-all",
    "vuln": "-sV --script vuln",
}
COMMON_PORT_GROUPS = {
    "web": "80,443,8000,8080,8443",
    "admin": "22,23,3389,5900,5985,5986",
    "database": "1433,1521,3306,5432,6379,27017",
    "windows": "135,137,138,139,445,3389,5985,5986",
    "top100": "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157",
}


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str = "unknown"
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    risk: str
    title: str
    description: str
    recommendation: str
    port: int | None = None
    service: str | None = None
    evidence: str = ""


@dataclass
class ScanResult:
    target: str
    profile: str = "default"
    scan_arguments: str = "-sV"
    scanned_at: str = ""
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def ensure_nmap_available(nmap_path: str = "nmap") -> None:
    """Validate that Nmap exists before attempting a scan."""
    if shutil.which(nmap_path) is None:
        raise RuntimeError(
            "Nmap was not found. Install Nmap and ensure it is available in PATH."
        )


def build_nmap_command(
    target: str,
    ports: str | None,
    scan_arguments: str,
    output_path: Path,
    nmap_path: str = "nmap",
) -> list[str]:
    """Build a safe Nmap command list for subprocess execution."""
    command = [nmap_path, "-oX", str(output_path)]

    if ports:
        command.extend(["-p", ports])

    command.extend(shlex.split(scan_arguments))
    command.append(target)
    return command


def resolve_scan_arguments(profile: str, nmap_args: str | None, aggressive: bool) -> str:
    """Choose Nmap arguments from custom args, legacy aggressive flag, or a named profile."""
    if nmap_args is not None:
        return nmap_args
    if aggressive:
        return SCAN_PROFILES["deep"]
    return SCAN_PROFILES[profile]


def resolve_ports(ports: str | None, port_group: str | None) -> str | None:
    """Resolve explicit ports or a named common port group."""
    if ports:
        return ports
    if port_group:
        return COMMON_PORT_GROUPS[port_group]
    return None


def run_nmap_scan(
    target: str,
    ports: str | None,
    scan_arguments: str,
    nmap_path: str = "nmap",
) -> str:
    """Run Nmap and return XML output as text."""
    ensure_nmap_available(nmap_path)

    with tempfile.TemporaryDirectory(prefix="nvs_") as temp_dir:
        output_path = Path(temp_dir) / "scan.xml"
        command = build_nmap_command(
            target=target,
            ports=ports,
            scan_arguments=scan_arguments,
            output_path=output_path,
            nmap_path=nmap_path,
        )

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "Nmap failed without error output."
            raise RuntimeError(stderr)

        return output_path.read_text(encoding="utf-8")


def parse_services_from_nmap_xml(xml_text: str) -> list[Service]:
    """Parse open services from Nmap XML output."""
    root = ET.fromstring(xml_text)
    services: list[Service] = []

    for host in root.findall("host"):
        for port_node in host.findall("./ports/port"):
            state_node = port_node.find("state")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            if state != "open":
                continue

            service_node = port_node.find("service")
            service = Service(
                port=int(port_node.get("portid", "0")),
                protocol=port_node.get("protocol", "tcp"),
                state=state,
                name=service_node.get("name", "unknown") if service_node is not None else "unknown",
                product=service_node.get("product", "") if service_node is not None else "",
                version=service_node.get("version", "") if service_node is not None else "",
                extra_info=service_node.get("extrainfo", "") if service_node is not None else "",
                cpe=parse_cpe(service_node),
                scripts=parse_script_output(port_node),
            )
            services.append(service)

    return services


def parse_cpe(service_node: ET.Element | None) -> str:
    """Extract the first CPE value reported for a service."""
    if service_node is None:
        return ""
    cpe_node = service_node.find("cpe")
    return cpe_node.text.strip() if cpe_node is not None and cpe_node.text else ""


def parse_script_output(port_node: ET.Element) -> dict[str, str]:
    """Extract Nmap script output attached to a port."""
    scripts: dict[str, str] = {}
    for script_node in port_node.findall("script"):
        script_id = script_node.get("id", "unknown")
        scripts[script_id] = script_node.get("output", "")
    return scripts


def identify_service_findings(service: Service) -> list[Finding]:
    """Apply basic vulnerability rules to one discovered service."""
    findings: list[Finding] = []
    service_name = service.name.lower()
    product_version = f"{service.product} {service.version}".strip()

    if service.port in {21} or service_name == "ftp":
        findings.append(
            Finding(
                risk="medium",
                title="FTP service exposed",
                description="FTP often transmits credentials and data in clear text.",
                recommendation="Use SFTP/FTPS, restrict access, and disable anonymous login.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {23} or service_name == "telnet":
        findings.append(
            Finding(
                risk="high",
                title="Telnet service exposed",
                description="Telnet sends authentication data without encryption.",
                recommendation="Disable Telnet and use SSH with key-based authentication.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {80, 8080, 8000} and service_name in {"http", "http-proxy"}:
        findings.append(
            Finding(
                risk="low",
                title="Unencrypted HTTP service detected",
                description="HTTP traffic can be intercepted or modified on the network.",
                recommendation="Enforce HTTPS, redirect HTTP to HTTPS, and enable HSTS.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {139, 445} or "smb" in service_name or "netbios" in service_name:
        findings.append(
            Finding(
                risk="medium",
                title="SMB/NetBIOS service exposed",
                description="SMB exposure increases risk from weak shares, legacy protocol versions, and lateral movement.",
                recommendation="Restrict SMB to trusted networks and disable SMBv1.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {3306, 5432, 1433, 1521, 27017, 6379}:
        findings.append(
            Finding(
                risk="high",
                title="Database service exposed",
                description="Database ports should rarely be reachable from untrusted networks.",
                recommendation="Bind databases to private interfaces, require strong authentication, and use firewall rules.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {3389} or service_name in {"ms-wbt-server", "rdp"}:
        findings.append(
            Finding(
                risk="medium",
                title="Remote Desktop service exposed",
                description="RDP exposed to broad networks is a common target for brute force and credential attacks.",
                recommendation="Restrict RDP with VPN, firewall allowlists, account lockout, and multi-factor authentication.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {5900, 5901} or service_name == "vnc":
        findings.append(
            Finding(
                risk="medium",
                title="VNC service exposed",
                description="VNC services are often weakly protected and should not be exposed to untrusted networks.",
                recommendation="Disable public VNC access or place it behind a VPN with strong authentication.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {25, 110, 143} or service_name in {"smtp", "pop3", "imap"}:
        findings.append(
            Finding(
                risk="low",
                title="Legacy mail protocol exposed",
                description="Mail services can leak user enumeration details or support weak authentication paths if misconfigured.",
                recommendation="Require TLS, disable insecure authentication, and limit access where possible.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {161} or service_name == "snmp":
        findings.append(
            Finding(
                risk="medium",
                title="SNMP service exposed",
                description="SNMP can disclose sensitive host, interface, and configuration information.",
                recommendation="Disable public SNMP, use SNMPv3, and restrict access to monitoring systems.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {2049} or service_name == "nfs":
        findings.append(
            Finding(
                risk="medium",
                title="NFS service exposed",
                description="NFS exports can expose files or allow unsafe trust relationships if misconfigured.",
                recommendation="Restrict NFS to trusted hosts and review export permissions.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {9200, 9300} or "elasticsearch" in service_name:
        findings.append(
            Finding(
                risk="high",
                title="Search database service exposed",
                description="Exposed search databases can leak indexed data and administrative APIs.",
                recommendation="Require authentication, bind to private interfaces, and restrict access with firewall rules.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.port in {11211} or service_name == "memcached":
        findings.append(
            Finding(
                risk="high",
                title="Memcached service exposed",
                description="Public Memcached services may leak cached data and can be abused for amplification attacks.",
                recommendation="Bind Memcached to localhost/private interfaces and block external access.",
                port=service.port,
                service=service.name,
                evidence=f"{service.port}/{service.protocol} {service.name}",
            )
        )

    if service.version and any(token in service.version.lower() for token in {"beta", "dev", "test"}):
        findings.append(
            Finding(
                risk="medium",
                title="Non-production service version marker detected",
                description=f"The service version string contains a non-production marker: {product_version}.",
                recommendation="Avoid exposing development builds and remove version banners where possible.",
                port=service.port,
                service=service.name,
                evidence=product_version,
            )
        )

    for script_id, output in service.scripts.items():
        lowered = output.lower()
        if "vulnerable" in lowered or "cve-" in lowered:
            findings.append(
                Finding(
                    risk="high",
                    title=f"Nmap script reported possible vulnerability: {script_id}",
                    description="An Nmap script returned output indicating a possible vulnerability.",
                    recommendation="Manually validate the script result, patch the service, or restrict exposure.",
                    port=service.port,
                    service=service.name,
                    evidence=output[:300],
                )
            )

    if service.product or service.version:
        findings.append(
            Finding(
                risk="info",
                title="Service banner reveals version information",
                description=f"Detected banner: {product_version}.",
                recommendation="Review whether detailed version disclosure is necessary.",
                port=service.port,
                service=service.name,
                evidence=product_version,
            )
        )

    return findings


def identify_vulnerabilities(
    services: Iterable[Service],
    minimum_risk: str = "info",
) -> list[Finding]:
    """Run all basic vulnerability checks against discovered services."""
    findings: list[Finding] = []
    for service in services:
        findings.extend(identify_service_findings(service))
    filtered = filter_findings_by_risk(findings, minimum_risk)
    return sorted(filtered, key=lambda item: RISK_ORDER[item.risk], reverse=True)


def filter_findings_by_risk(findings: Iterable[Finding], minimum_risk: str) -> list[Finding]:
    """Return findings at or above a minimum severity."""
    threshold = RISK_ORDER[minimum_risk]
    return [finding for finding in findings if RISK_ORDER[finding.risk] >= threshold]


def summarize_findings(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    summary = {risk: 0 for risk in RISK_ORDER}
    for finding in findings:
        summary[finding.risk] += 1
    return summary


def summarize_services(services: Iterable[Service]) -> dict[str, int]:
    """Count open services by service name."""
    summary: dict[str, int] = {}
    for service in services:
        summary[service.name] = summary.get(service.name, 0) + 1
    return dict(sorted(summary.items()))


def perform_scan(
    target: str,
    ports: str | None,
    scan_arguments: str,
    nmap_path: str = "nmap",
    profile: str = "default",
    minimum_risk: str = "info",
) -> ScanResult:
    """Execute Nmap, parse services, and produce vulnerability findings."""
    xml_text = run_nmap_scan(target, ports, scan_arguments, nmap_path)
    services = parse_services_from_nmap_xml(xml_text)
    findings = identify_vulnerabilities(services, minimum_risk)
    return ScanResult(
        target=target,
        profile=profile,
        scan_arguments=scan_arguments,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        services=services,
        findings=findings,
    )


def render_text_report(result: ScanResult) -> str:
    """Render a terminal-friendly report."""
    lines = [
        "Network Vulnerability Scanner Report",
        "=" * 38,
        f"Target: {result.target}",
        f"Profile: {result.profile}",
        f"Nmap args: {result.scan_arguments}",
        f"Scanned at: {result.scanned_at or 'not recorded'}",
        "",
        "Summary",
        "-" * 7,
        f"Open services: {len(result.services)}",
    ]

    risk_summary = summarize_findings(result.findings)
    lines.append(
        "Findings: "
        + ", ".join(f"{risk}={count}" for risk, count in risk_summary.items() if count)
        if any(risk_summary.values())
        else "Findings: 0"
    )

    lines.extend([
        "",
        "Open Services",
        "-" * 13,
    ])

    if not result.services:
        lines.append("No open services discovered.")
    else:
        for service in result.services:
            banner = " ".join(
                part for part in [service.product, service.version, service.extra_info, service.cpe] if part
            )
            details = f" ({banner})" if banner else ""
            lines.append(
                f"- {service.port}/{service.protocol} {service.name} [{service.state}]{details}"
            )
            if service.scripts:
                lines.append(f"  Scripts: {', '.join(sorted(service.scripts))}")

    lines.extend(["", "Findings", "-" * 8])

    if not result.findings:
        lines.append("No basic vulnerabilities identified.")
    else:
        for finding in result.findings:
            location = f" on {finding.port}/{finding.service}" if finding.port else ""
            lines.extend(
                [
                    f"- [{finding.risk.upper()}] {finding.title}{location}",
                    f"  {finding.description}",
                    f"  Recommendation: {finding.recommendation}",
                ]
            )
            if finding.evidence:
                lines.append(f"  Evidence: {finding.evidence}")

    return "\n".join(lines)


def write_report(result: ScanResult, output_path: Path, output_format: str) -> None:
    """Write a scan report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "json":
        payload = asdict(result)
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return
    if output_format == "csv":
        output_path.write_text(render_csv_report(result), encoding="utf-8")
        return

    output_path.write_text(render_text_report(result), encoding="utf-8")


def render_csv_report(result: ScanResult) -> str:
    """Render findings as CSV rows for spreadsheets and dashboards."""
    from io import StringIO

    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "target",
            "risk",
            "title",
            "port",
            "service",
            "description",
            "recommendation",
            "evidence",
        ],
    )
    writer.writeheader()
    for finding in result.findings:
        writer.writerow(
            {
                "target": result.target,
                "risk": finding.risk,
                "title": finding.title,
                "port": finding.port or "",
                "service": finding.service or "",
                "description": finding.description,
                "recommendation": finding.recommendation,
                "evidence": finding.evidence,
            }
        )
    return output.getvalue()


def render_json_report(result: ScanResult) -> str:
    """Render the full scan result as JSON."""
    return json.dumps(asdict(result), indent=2)


def render_report(result: ScanResult, output_format: str) -> str:
    """Render a scan result in the requested format."""
    if output_format == "json":
        return render_json_report(result)
    if output_format == "csv":
        return render_csv_report(result)
    return render_text_report(result)


def render_profiles() -> str:
    """Render available Nmap scan profiles."""
    lines = ["Available scan profiles", "=======================", ""]
    for name, args in SCAN_PROFILES.items():
        lines.append(f"- {name}: {args}")
    return "\n".join(lines)


def render_port_groups() -> str:
    """Render available named port groups."""
    lines = ["Available port groups", "=====================", ""]
    for name, ports in COMMON_PORT_GROUPS.items():
        lines.append(f"- {name}: {ports}")
    return "\n".join(lines)


def render_service_inventory(result: ScanResult) -> str:
    """Render only discovered service inventory."""
    summary = summarize_services(result.services)
    lines = [
        "Service Inventory",
        "=================",
        f"Target: {result.target}",
        "",
    ]
    if not summary:
        lines.append("No open services discovered.")
        return "\n".join(lines)
    for service_name, count in summary.items():
        lines.append(f"- {service_name}: {count}")
    return "\n".join(lines)


def add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach shared scan arguments to a parser."""
    parser.add_argument("target", help="Target host, IP, or CIDR range to scan.")
    parser.add_argument(
        "-p",
        "--ports",
        help="Ports to scan, for example 22,80,443 or 1-1000. Defaults to the selected profile.",
    )
    parser.add_argument(
        "-g",
        "--port-group",
        choices=tuple(COMMON_PORT_GROUPS),
        help="Use a named port group instead of typing ports manually.",
    )
    parser.add_argument(
        "--profile",
        choices=tuple(SCAN_PROFILES),
        default="default",
        help="Named Nmap scan profile. Defaults to default.",
    )
    parser.add_argument(
        "-A",
        "--aggressive",
        action="store_true",
        help="Legacy shortcut for the deep profile.",
    )
    parser.add_argument(
        "--nmap-args",
        default=None,
        help="Custom Nmap arguments. Overrides profile and aggressive options.",
    )
    parser.add_argument(
        "--nmap-path",
        default="nmap",
        help="Path to the Nmap executable. Defaults to nmap from PATH.",
    )
    parser.add_argument(
        "--min-risk",
        choices=tuple(RISK_ORDER),
        default="info",
        help="Only show findings at or above this risk level.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional path to save the report.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "csv"),
        default="text",
        help="Report format for stdout and saved output. Defaults to text.",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    if not argv:
        argv = ["--help"]

    parser = argparse.ArgumentParser(
        description="CLI network vulnerability scanner powered by Nmap.",
        epilog="Only scan systems you own or have explicit permission to test.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a target and identify basic vulnerabilities.")
    add_scan_arguments(scan_parser)

    inventory_parser = subparsers.add_parser("inventory", help="Scan a target and show service counts only.")
    add_scan_arguments(inventory_parser)

    subparsers.add_parser("profiles", help="List built-in scan profiles.")
    subparsers.add_parser("ports", help="List built-in port groups.")

    if argv and argv[0] not in {"scan", "inventory", "profiles", "ports", "-h", "--help"}:
        argv = ["scan", *argv]
    return parser.parse_args(argv)


def run_scan_command(args: argparse.Namespace) -> ScanResult:
    """Run a scan from parsed CLI arguments."""
    scan_arguments = resolve_scan_arguments(
        profile=args.profile,
        nmap_args=args.nmap_args,
        aggressive=args.aggressive,
    )
    ports = resolve_ports(args.ports, args.port_group)
    profile = "custom" if args.nmap_args else ("deep" if args.aggressive else args.profile)
    return perform_scan(
        target=args.target,
        ports=ports,
        scan_arguments=scan_arguments,
        nmap_path=args.nmap_path,
        profile=profile,
        minimum_risk=args.min_risk,
    )


def print_or_save_result(result: ScanResult, args: argparse.Namespace) -> None:
    """Print a report and optionally save it."""
    print(render_report(result, args.format))

    if args.output:
        write_report(result, args.output, args.format)
        print(f"\nReport saved to: {args.output}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.command == "profiles":
        print(render_profiles())
        return 0

    if args.command == "ports":
        print(render_port_groups())
        return 0

    try:
        result = run_scan_command(args)
    except (RuntimeError, ET.ParseError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.command == "inventory":
        print(render_service_inventory(result))
        if args.output:
            write_report(result, args.output, args.format)
            print(f"\nReport saved to: {args.output}")
    else:
        print_or_save_result(result, args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
