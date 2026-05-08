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
import re
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
from urllib.parse import urlparse


CLI_COMMAND = "netvs"
PACKAGE_NAME = "netvs"
CLI_VERSION = "1.1.5"
CLI_DESCRIPTION = "Network vulnerability scanner powered by Nmap."
CLI_COMMANDS = [
    ("scan", "Scan a target and identify basic vulnerabilities."),
    ("inventory", "Scan a target and show service counts only."),
    ("cves", "List CVEs in the bundled or custom correlation database."),
    ("profiles", "List built-in scan profiles."),
    ("ports", "List built-in port groups."),
    ("uninstall-help", "Show pip uninstall commands and Windows troubleshooting tips."),
]
CLI_EXAMPLES = [
    f"{CLI_COMMAND} scan 192.168.1.10 --profile quick",
    f"{CLI_COMMAND} scan https://example.com",
    f"{CLI_COMMAND} scan https://example.com --score-only",
    f"{CLI_COMMAND} scan 192.168.1.10 -p 22,80,443",
    f"{CLI_COMMAND} inventory 192.168.1.10",
    f"{CLI_COMMAND} uninstall-help",
]
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_CYAN = "\033[36m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RISK_SCORE_PENALTIES = {"info": 0.1, "low": 0.6, "medium": 1.2, "high": 2.1, "critical": 3.0}
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
DEFAULT_CVE_DATABASE = [
    {
        "cve_id": "CVE-2021-41773",
        "products": ["apache httpd", "apache http server", "httpd"],
        "cpe_keywords": ["apache:http_server"],
        "service_names": ["http"],
        "affected_versions": [{"operator": "==", "version": "2.4.49"}],
        "risk": "high",
        "cvss": 7.5,
        "summary": "Apache HTTP Server 2.4.49 path traversal and file disclosure vulnerability.",
        "recommendation": "Upgrade Apache HTTP Server to 2.4.51 or later and review path alias configuration.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    },
    {
        "cve_id": "CVE-2021-42013",
        "products": ["apache httpd", "apache http server", "httpd"],
        "cpe_keywords": ["apache:http_server"],
        "service_names": ["http"],
        "affected_versions": [{"operator": "==", "version": "2.4.50"}],
        "risk": "critical",
        "cvss": 9.8,
        "summary": "Apache HTTP Server 2.4.50 path traversal and possible remote code execution vulnerability.",
        "recommendation": "Upgrade Apache HTTP Server to 2.4.51 or later immediately.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
    },
    {
        "cve_id": "CVE-2019-0211",
        "products": ["apache httpd", "apache http server", "httpd"],
        "cpe_keywords": ["apache:http_server"],
        "service_names": ["http"],
        "affected_versions": [{"operator": ">=", "version": "2.4.17"}, {"operator": "<=", "version": "2.4.38"}],
        "risk": "high",
        "cvss": 7.8,
        "summary": "Apache HTTP Server privilege escalation vulnerability in affected 2.4.x releases.",
        "recommendation": "Upgrade Apache HTTP Server to 2.4.39 or later.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0211"],
    },
    {
        "cve_id": "CVE-2021-23017",
        "products": ["nginx"],
        "cpe_keywords": ["nginx:nginx"],
        "service_names": ["http", "https"],
        "affected_versions": [{"operator": ">=", "version": "0.6.18"}, {"operator": "<=", "version": "1.20.0"}],
        "risk": "high",
        "cvss": 7.7,
        "summary": "Nginx resolver off-by-one heap write vulnerability when resolver is configured.",
        "recommendation": "Upgrade Nginx to 1.20.1, 1.21.0, or later and review resolver configuration.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
    },
    {
        "cve_id": "CVE-2019-19781",
        "products": ["citrix adc", "citrix gateway", "netscaler"],
        "cpe_keywords": ["citrix"],
        "service_names": ["http", "https"],
        "affected_versions": [{"operator": "*", "version": "*"}],
        "risk": "critical",
        "cvss": 9.8,
        "summary": "Citrix ADC and Gateway path traversal vulnerability that can lead to arbitrary code execution.",
        "recommendation": "Apply vendor mitigations and upgrade to a fixed Citrix ADC/Gateway release.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-19781"],
    },
    {
        "cve_id": "CVE-2018-13379",
        "products": ["fortinet fortigate", "fortios", "fortinet"],
        "cpe_keywords": ["fortinet:fortios"],
        "service_names": ["http", "https"],
        "affected_versions": [{"operator": "*", "version": "*"}],
        "risk": "critical",
        "cvss": 9.8,
        "summary": "Fortinet FortiOS SSL VPN path traversal vulnerability exposing session files.",
        "recommendation": "Upgrade FortiOS to a fixed release and rotate potentially exposed credentials.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-13379"],
    },
    {
        "cve_id": "CVE-2018-15473",
        "products": ["openssh"],
        "cpe_keywords": ["openbsd:openssh"],
        "service_names": ["ssh"],
        "affected_versions": [{"operator": "<=", "version": "7.7"}],
        "risk": "medium",
        "cvss": 5.3,
        "summary": "OpenSSH user enumeration vulnerability in affected releases.",
        "recommendation": "Upgrade OpenSSH to 7.8 or later and restrict SSH exposure.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
    },
    {
        "cve_id": "CVE-2023-38408",
        "products": ["openssh"],
        "cpe_keywords": ["openbsd:openssh"],
        "service_names": ["ssh"],
        "affected_versions": [{"operator": ">=", "version": "5.5"}, {"operator": "<=", "version": "9.3"}],
        "risk": "high",
        "cvss": 9.8,
        "summary": "OpenSSH ssh-agent remote code execution risk through forwarded agents in specific conditions.",
        "recommendation": "Upgrade OpenSSH to 9.3p2 or later and avoid agent forwarding to untrusted hosts.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
    },
    {
        "cve_id": "CVE-2017-0144",
        "products": ["microsoft windows smb", "samba", "smb"],
        "cpe_keywords": ["microsoft:windows", "samba:samba"],
        "service_names": ["microsoft-ds", "netbios-ssn", "smb"],
        "allow_service_only": True,
        "affected_versions": [{"operator": "*", "version": "*"}],
        "risk": "critical",
        "cvss": 8.1,
        "summary": "SMBv1 remote code execution vulnerability widely associated with EternalBlue.",
        "recommendation": "Apply MS17-010 patches, disable SMBv1, and restrict SMB access.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
    },
    {
        "cve_id": "CVE-2020-0796",
        "products": ["microsoft windows smb", "smb"],
        "cpe_keywords": ["microsoft:windows"],
        "service_names": ["microsoft-ds", "smb"],
        "allow_service_only": True,
        "affected_versions": [{"operator": "*", "version": "*"}],
        "risk": "critical",
        "cvss": 10.0,
        "summary": "SMBv3 compression remote code execution vulnerability.",
        "recommendation": "Apply Microsoft security updates and restrict SMB exposure.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-0796"],
    },
    {
        "cve_id": "CVE-2010-2075",
        "products": ["proftpd"],
        "cpe_keywords": ["proftpd"],
        "service_names": ["ftp"],
        "affected_versions": [{"operator": "<=", "version": "1.3.3"}],
        "risk": "medium",
        "cvss": 5.0,
        "summary": "ProFTPD affected releases can disclose information through malformed commands.",
        "recommendation": "Upgrade ProFTPD to a maintained release and restrict FTP access.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2010-2075"],
    },
    {
        "cve_id": "CVE-2015-3306",
        "products": ["proftpd"],
        "cpe_keywords": ["proftpd"],
        "service_names": ["ftp"],
        "affected_versions": [{"operator": "==", "version": "1.3.5"}],
        "risk": "high",
        "cvss": 10.0,
        "summary": "ProFTPD mod_copy command execution vulnerability in vulnerable configurations.",
        "recommendation": "Upgrade ProFTPD and disable vulnerable modules if not required.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"],
    },
    {
        "cve_id": "CVE-2012-2122",
        "products": ["mysql", "mariadb"],
        "cpe_keywords": ["mysql:mysql", "mariadb"],
        "service_names": ["mysql"],
        "affected_versions": [{"operator": ">=", "version": "5.1.0"}, {"operator": "<=", "version": "5.5.23"}],
        "risk": "high",
        "cvss": 7.5,
        "summary": "MySQL and MariaDB authentication bypass vulnerability in affected builds.",
        "recommendation": "Upgrade database packages and restrict MySQL to trusted hosts.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2012-2122"],
    },
    {
        "cve_id": "CVE-2019-0708",
        "products": ["microsoft terminal services", "rdp", "remote desktop"],
        "cpe_keywords": ["microsoft:windows"],
        "service_names": ["ms-wbt-server", "rdp"],
        "allow_service_only": True,
        "affected_versions": [{"operator": "*", "version": "*"}],
        "risk": "critical",
        "cvss": 9.8,
        "summary": "Remote Desktop Services remote code execution vulnerability known as BlueKeep.",
        "recommendation": "Apply Microsoft security updates, enable NLA, and restrict RDP access.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
    },
    {
        "cve_id": "CVE-2017-5638",
        "products": ["apache struts", "struts"],
        "cpe_keywords": ["apache:struts"],
        "service_names": ["http", "https"],
        "affected_versions": [{"operator": ">=", "version": "2.3.5"}, {"operator": "<=", "version": "2.3.31"}],
        "risk": "critical",
        "cvss": 10.0,
        "summary": "Apache Struts Jakarta multipart parser remote code execution vulnerability.",
        "recommendation": "Upgrade Apache Struts to a fixed version and review exposed applications.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
    },
    {
        "cve_id": "CVE-2021-44228",
        "products": ["log4j"],
        "cpe_keywords": ["apache:log4j"],
        "service_names": ["http", "https"],
        "affected_versions": [{"operator": ">=", "version": "2.0"}, {"operator": "<=", "version": "2.14.1"}],
        "risk": "critical",
        "cvss": 10.0,
        "summary": "Apache Log4j remote code execution vulnerability known as Log4Shell.",
        "recommendation": "Upgrade Log4j to a fixed release and search applications for bundled vulnerable libraries.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
]


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
class CVEMatch:
    cve_id: str
    risk: str
    cvss: float
    summary: str
    affected: str
    recommendation: str
    references: list[str] = field(default_factory=list)
    port: int | None = None
    service: str | None = None
    product: str = ""
    installed_version: str = ""
    match_reason: str = ""


@dataclass
class ScanResult:
    target: str
    input_target: str = ""
    profile: str = "default"
    scan_arguments: str = "-sV"
    scanned_at: str = ""
    security_score: int = 10
    score_label: str = "Strongest"
    score_details: dict[str, float] = field(default_factory=dict)
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    cve_matches: list[CVEMatch] = field(default_factory=list)


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


def parse_target_url(target: str):
    """Parse user input as a URL when it clearly contains a scheme."""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", target, flags=re.IGNORECASE):
        return None
    parsed = urlparse(target)
    if not parsed.hostname:
        raise ValueError(f"URL target must include a hostname: {target}")
    return parsed


def normalize_scan_target(target: str) -> str:
    """Accept direct website URLs while passing only a host/IP/CIDR to Nmap."""
    parsed = parse_target_url(target)
    if parsed is None:
        return target
    return parsed.hostname


def resolve_url_default_ports(target: str) -> str | None:
    """Choose sensible web ports when the user scans a URL without explicit ports."""
    parsed = parse_target_url(target)
    if parsed is None:
        return None
    if parsed.port:
        return str(parsed.port)
    if parsed.scheme.lower() in {"http", "https"}:
        return COMMON_PORT_GROUPS["web"]
    return None


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


def resolve_scan_ports(ports: str | None, port_group: str | None, target: str) -> str | None:
    """Resolve ports from explicit CLI input, a named group, or a URL target hint."""
    return resolve_ports(ports, port_group) or resolve_url_default_ports(target)


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


def normalize_text(value: str) -> str:
    """Normalize text for matching service, product, and CPE data."""
    return re.sub(r"[^a-z0-9_.:+-]+", " ", value.lower()).strip()


def extract_version_parts(version: str) -> tuple[int, ...]:
    """Extract comparable numeric version parts from a version string."""
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts)


def compare_versions(installed: str, expected: str) -> int | None:
    """Compare two dotted versions. Return -1, 0, 1, or None if not comparable."""
    installed_parts = extract_version_parts(installed)
    expected_parts = extract_version_parts(expected)
    if not installed_parts or not expected_parts:
        return None

    length = max(len(installed_parts), len(expected_parts))
    left = installed_parts + (0,) * (length - len(installed_parts))
    right = expected_parts + (0,) * (length - len(expected_parts))

    if left < right:
        return -1
    if left > right:
        return 1
    return 0


def version_condition_matches(installed_version: str, condition: dict[str, str]) -> bool:
    """Check if a detected version satisfies one affected-version condition."""
    operator = condition.get("operator", "")
    expected_version = condition.get("version", "")

    if operator == "*":
        return True

    comparison = compare_versions(installed_version, expected_version)
    if comparison is None:
        return False

    return {
        "==": comparison == 0,
        "<": comparison < 0,
        "<=": comparison <= 0,
        ">": comparison > 0,
        ">=": comparison >= 0,
    }.get(operator, False)


def affected_version_matches(installed_version: str, conditions: list[dict[str, str]]) -> bool:
    """Return true if all affected-version conditions match the installed version."""
    if not conditions:
        return False
    if any(condition.get("operator") == "*" for condition in conditions):
        return True
    if not installed_version:
        return False
    return all(version_condition_matches(installed_version, condition) for condition in conditions)


def cve_entry_matches_service(service: Service, cve_entry: dict[str, object]) -> tuple[bool, str]:
    """Check whether one CVE catalog entry applies to a discovered service."""
    product_text = normalize_text(f"{service.product} {service.name} {service.extra_info}")
    cpe_text = normalize_text(service.cpe)
    service_name = normalize_text(service.name)

    product_matched = any(
        normalize_text(str(product)) in product_text
        for product in cve_entry.get("products", [])
    )
    cpe_matched = any(
        normalize_text(str(keyword)) in cpe_text
        for keyword in cve_entry.get("cpe_keywords", [])
    )
    service_matched = service_name in {
        normalize_text(str(name)) for name in cve_entry.get("service_names", [])
    }

    service_only_allowed = bool(cve_entry.get("allow_service_only", False))
    evidence_matched = product_matched or cpe_matched or (service_matched and service_only_allowed)

    if not evidence_matched:
        return False, ""

    conditions = cve_entry.get("affected_versions", [])
    if not isinstance(conditions, list) or not affected_version_matches(service.version, conditions):
        return False, ""

    reasons = []
    if product_matched:
        reasons.append("product")
    if cpe_matched:
        reasons.append("cpe")
    if service_matched and service_only_allowed:
        reasons.append("service")
    reasons.append("version")
    return True, "+".join(reasons)


def load_cve_database(database_path: Path | None = None) -> list[dict[str, object]]:
    """Load a CVE database from JSON or return the bundled offline catalog."""
    if database_path is None:
        return DEFAULT_CVE_DATABASE

    raw_data = json.loads(database_path.read_text(encoding="utf-8"))
    if not isinstance(raw_data, list):
        raise ValueError("CVE database must be a JSON array of CVE entries.")
    return raw_data


def correlate_cves(
    services: Iterable[Service],
    cve_database: list[dict[str, object]],
    minimum_risk: str = "info",
) -> list[CVEMatch]:
    """Correlate discovered services with known CVE entries."""
    matches: list[CVEMatch] = []
    seen: set[tuple[str, int | None, str]] = set()

    for service in services:
        for cve_entry in cve_database:
            matched, reason = cve_entry_matches_service(service, cve_entry)
            if not matched:
                continue

            risk = str(cve_entry.get("risk", "info")).lower()
            if RISK_ORDER.get(risk, 0) < RISK_ORDER[minimum_risk]:
                continue

            cve_id = str(cve_entry.get("cve_id", "UNKNOWN-CVE"))
            dedupe_key = (cve_id, service.port, service.name)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            matches.append(
                CVEMatch(
                    cve_id=cve_id,
                    risk=risk,
                    cvss=float(cve_entry.get("cvss", 0.0)),
                    summary=str(cve_entry.get("summary", "")),
                    affected=describe_affected_versions(cve_entry),
                    recommendation=str(cve_entry.get("recommendation", "")),
                    references=[str(ref) for ref in cve_entry.get("references", [])],
                    port=service.port,
                    service=service.name,
                    product=service.product,
                    installed_version=service.version,
                    match_reason=reason,
                )
            )

    return sorted(matches, key=lambda item: (RISK_ORDER[item.risk], item.cvss), reverse=True)


def describe_affected_versions(cve_entry: dict[str, object]) -> str:
    """Render affected version rules for reports."""
    conditions = cve_entry.get("affected_versions", [])
    if not isinstance(conditions, list):
        return "unknown"
    rendered = []
    for condition in conditions:
        if not isinstance(condition, dict):
            continue
        operator = condition.get("operator", "")
        version = condition.get("version", "")
        rendered.append("all versions" if operator == "*" else f"{operator} {version}")
    return " and ".join(rendered) if rendered else "unknown"


def extract_cve_ids_from_scripts(service: Service) -> list[str]:
    """Extract CVE identifiers reported by Nmap scripts."""
    cve_ids: set[str] = set()
    for output in service.scripts.values():
        cve_ids.update(re.findall(r"CVE-\d{4}-\d{4,7}", output, flags=re.IGNORECASE))
    return sorted(cve_id.upper() for cve_id in cve_ids)


def correlate_script_cves(
    services: Iterable[Service],
    cve_database: list[dict[str, object]],
    minimum_risk: str = "info",
) -> list[CVEMatch]:
    """Create CVE matches from CVE IDs already reported by Nmap script output."""
    database_by_id = {str(entry.get("cve_id", "")).upper(): entry for entry in cve_database}
    matches: list[CVEMatch] = []
    seen: set[tuple[str, int | None, str]] = set()

    for service in services:
        for cve_id in extract_cve_ids_from_scripts(service):
            entry = database_by_id.get(cve_id, {})
            risk = str(entry.get("risk", "high")).lower()
            if RISK_ORDER.get(risk, 0) < RISK_ORDER[minimum_risk]:
                continue

            dedupe_key = (cve_id, service.port, service.name)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            matches.append(
                CVEMatch(
                    cve_id=cve_id,
                    risk=risk,
                    cvss=float(entry.get("cvss", 0.0)),
                    summary=str(entry.get("summary", "Nmap script output referenced this CVE.")),
                    affected=describe_affected_versions(entry) if entry else "reported by Nmap script",
                    recommendation=str(entry.get("recommendation", "Validate the Nmap script result and patch or mitigate the affected service.")),
                    references=[str(ref) for ref in entry.get("references", [])],
                    port=service.port,
                    service=service.name,
                    product=service.product,
                    installed_version=service.version,
                    match_reason="nmap-script",
                )
            )

    return sorted(matches, key=lambda item: (RISK_ORDER[item.risk], item.cvss), reverse=True)


def merge_cve_matches(*match_groups: Iterable[CVEMatch]) -> list[CVEMatch]:
    """Merge and deduplicate CVE matches."""
    merged: list[CVEMatch] = []
    seen: set[tuple[str, int | None, str]] = set()
    for matches in match_groups:
        for match in matches:
            key = (match.cve_id, match.port, match.service or "")
            if key in seen:
                continue
            seen.add(key)
            merged.append(match)
    return sorted(merged, key=lambda item: (RISK_ORDER[item.risk], item.cvss), reverse=True)


def cve_matches_to_findings(cve_matches: Iterable[CVEMatch]) -> list[Finding]:
    """Represent correlated CVEs as normal findings for unified severity filtering and CSV output."""
    findings: list[Finding] = []
    for match in cve_matches:
        findings.append(
            Finding(
                risk=match.risk,
                title=f"{match.cve_id}: {match.summary}",
                description=(
                    f"Detected {match.product or match.service} {match.installed_version or ''} "
                    f"matches affected versions: {match.affected}."
                ).strip(),
                recommendation=match.recommendation,
                port=match.port,
                service=match.service,
                evidence=f"CVSS {match.cvss}; match={match.match_reason}",
            )
        )
    return findings


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


def score_label(score: int) -> str:
    """Map a 1-10 score to a human-readable strength label."""
    if score <= 2:
        return "Weakest"
    if score <= 4:
        return "Weak"
    if score <= 6:
        return "Moderate"
    if score <= 8:
        return "Strong"
    return "Strongest"


def calculate_security_score_details(
    services: Iterable[Service],
    findings: Iterable[Finding],
) -> dict[str, float]:
    """Calculate the score penalty components used in strength reports."""
    service_list = list(services)
    finding_list = list(findings)
    service_penalty = min(len(service_list) * 0.15, 2.0)
    finding_penalty = sum(RISK_SCORE_PENALTIES.get(finding.risk, 0) for finding in finding_list)

    risky_ports = {21, 23, 139, 445, 3389, 5900, 5985, 5986, 11211, 9200, 9300}
    exposed_risky_ports = {service.port for service in service_list if service.port in risky_ports}
    risky_port_penalty = min(len(exposed_risky_ports) * 0.4, 1.5)
    total_penalty = service_penalty + finding_penalty + risky_port_penalty

    return {
        "base_score": 10.0,
        "open_service_penalty": round(service_penalty, 2),
        "finding_penalty": round(finding_penalty, 2),
        "risky_port_penalty": round(risky_port_penalty, 2),
        "total_penalty": round(total_penalty, 2),
    }


def calculate_security_score(services: Iterable[Service], findings: Iterable[Finding]) -> int:
    """Calculate a 1-10 target strength score from exposure and finding severity."""
    score_details = calculate_security_score_details(services, findings)
    return max(1, min(10, round(score_details["base_score"] - score_details["total_penalty"])))


def perform_scan(
    target: str,
    ports: str | None,
    scan_arguments: str,
    nmap_path: str = "nmap",
    profile: str = "default",
    minimum_risk: str = "info",
    cve_database: list[dict[str, object]] | None = None,
    enable_cve_correlation: bool = True,
    input_target: str | None = None,
) -> ScanResult:
    """Execute Nmap, parse services, and produce vulnerability findings."""
    xml_text = run_nmap_scan(target, ports, scan_arguments, nmap_path)
    services = parse_services_from_nmap_xml(xml_text)
    cve_matches: list[CVEMatch] = []
    if enable_cve_correlation:
        database = cve_database if cve_database is not None else load_cve_database()
        cve_matches = merge_cve_matches(
            correlate_cves(services, database, minimum_risk),
            correlate_script_cves(services, database, minimum_risk),
        )
    findings = identify_vulnerabilities(services, minimum_risk)
    findings.extend(cve_matches_to_findings(cve_matches))
    findings = sorted(findings, key=lambda item: RISK_ORDER[item.risk], reverse=True)
    score_details = calculate_security_score_details(services, findings)
    security_score = max(1, min(10, round(score_details["base_score"] - score_details["total_penalty"])))
    return ScanResult(
        target=target,
        input_target=input_target or target,
        profile=profile,
        scan_arguments=scan_arguments,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        security_score=security_score,
        score_label=score_label(security_score),
        score_details=score_details,
        services=services,
        findings=findings,
        cve_matches=cve_matches,
    )


def render_text_report(result: ScanResult) -> str:
    """Render a terminal-friendly report."""
    lines = [
        "Network Vulnerability Scanner Report",
        "=" * 38,
        f"Target: {result.target}",
        f"Input target: {result.input_target}",
        f"Profile: {result.profile}",
        f"Nmap args: {result.scan_arguments}",
        f"Scanned at: {result.scanned_at or 'not recorded'}",
        "",
        "Summary",
        "-" * 7,
        f"Score [1-10]: {result.security_score}/10 ({result.score_label}; Weakest - Strongest)",
        f"Open services: {len(result.services)}",
        f"Correlated CVEs: {len(result.cve_matches)}",
    ]

    risk_summary = summarize_findings(result.findings)
    lines.append(
        "Findings: "
        + ", ".join(f"{risk}={count}" for risk, count in risk_summary.items() if count)
        if any(risk_summary.values())
        else "Findings: 0"
    )
    if result.score_details:
        lines.append(
            "Score factors: "
            + ", ".join(
                f"{name.replace('_', ' ')}={value:g}"
                for name, value in result.score_details.items()
                if name != "base_score"
            )
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

    lines.extend(["", "CVE Correlation", "-" * 15])

    if not result.cve_matches:
        lines.append("No CVE correlations identified from the bundled database or Nmap script output.")
    else:
        for match in result.cve_matches:
            location = f" on {match.port}/{match.service}" if match.port else ""
            references = ", ".join(match.references) if match.references else "No reference URL available"
            lines.extend(
                [
                    f"- [{match.risk.upper()}] {match.cve_id}{location} (CVSS {match.cvss})",
                    f"  Product/version: {match.product or match.service} {match.installed_version or 'unknown'}",
                    f"  Affected: {match.affected}",
                    f"  Summary: {match.summary}",
                    f"  Recommendation: {match.recommendation}",
                    f"  Match reason: {match.match_reason}",
                    f"  References: {references}",
                ]
            )

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


def render_score_report(result: ScanResult) -> str:
    """Render only the score-oriented scan summary."""
    risk_summary = summarize_findings(result.findings)
    findings = ", ".join(f"{risk}={count}" for risk, count in risk_summary.items() if count) or "0"
    details = ", ".join(
        f"{name.replace('_', ' ')}={value:g}"
        for name, value in result.score_details.items()
        if name != "base_score"
    )
    lines = [
        "Target Score",
        "============",
        f"Target: {result.target}",
        f"Input target: {result.input_target}",
        f"Score [1-10]: {result.security_score}/10 ({result.score_label}; Weakest - Strongest)",
        f"Open services: {len(result.services)}",
        f"Correlated CVEs: {len(result.cve_matches)}",
        f"Findings: {findings}",
    ]
    if details:
        lines.append(f"Score factors: {details}")
    return "\n".join(lines)


def write_report(result: ScanResult, output_path: Path, output_format: str) -> None:
    """Write a scan report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "json":
        output_path.write_text(render_json_report(result), encoding="utf-8")
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
            "input_target",
            "security_score",
            "score_label",
            "type",
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
                    "input_target": result.input_target,
                    "security_score": result.security_score,
                    "score_label": result.score_label,
                    "type": "cve" if finding.title.startswith("CVE-") else "finding",
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


def render_cve_database(cve_database: list[dict[str, object]]) -> str:
    """Render bundled or custom CVE database entries."""
    lines = ["CVE correlation database", "========================", ""]
    for entry in cve_database:
        products = ", ".join(str(product) for product in entry.get("products", []))
        lines.extend(
            [
                f"- {entry.get('cve_id', 'UNKNOWN-CVE')} [{str(entry.get('risk', 'info')).upper()}] CVSS {entry.get('cvss', 0.0)}",
                f"  Products: {products or 'unknown'}",
                f"  Affected: {describe_affected_versions(entry)}",
                f"  Summary: {entry.get('summary', '')}",
            ]
        )
    return "\n".join(lines)


def render_service_inventory(result: ScanResult) -> str:
    """Render only discovered service inventory."""
    summary = summarize_services(result.services)
    lines = [
        "Service Inventory",
        "=================",
        f"Target: {result.target}",
        f"Score [1-10]: {result.security_score}/10 ({result.score_label}; Weakest - Strongest)",
        "",
    ]
    if not summary:
        lines.append("No open services discovered.")
        return "\n".join(lines)
    for service_name, count in summary.items():
        lines.append(f"- {service_name}: {count}")
    return "\n".join(lines)


def render_uninstall_help() -> str:
    """Render uninstall guidance without attempting to remove the CLI."""
    return "\n".join(
        [
            "Uninstall Help",
            "==============",
            "",
            "To uninstall the package, run:",
            "",
            f"  pip uninstall {PACKAGE_NAME}",
            "",
            f"Note: `{CLI_COMMAND}` is the command alias. `{PACKAGE_NAME}` is the pip package name.",
            "",
            "Windows troubleshooting:",
            "",
            f"  where.exe {CLI_COMMAND}",
            f"  py -ver -m pip uninstall {PACKAGE_NAME}",
            f"  C:\\Path\\To\\Python\\python.exe -m pip uninstall {PACKAGE_NAME}",
        ]
    )


def render_cli_help() -> str:
    """Render top-level CLI help with a compact boxed layout."""
    width = 116
    lines = [
        color_text(CLI_COMMAND, ANSI_BOLD + ANSI_CYAN),
        "",
        f" {color_text('Usage:', ANSI_BOLD)} {CLI_COMMAND} {color_text('[OPTIONS]', ANSI_YELLOW)} COMMAND [ARGS]...",
        "",
        f" {CLI_DESCRIPTION}",
        "",
    ]
    lines.extend(render_help_panel("Options", [("-h, --help", "Show this message and exit.")], width))
    lines.append("")
    lines.extend(render_help_panel("Commands", CLI_COMMANDS, width))
    lines.append("")
    lines.extend(render_examples_panel("Examples", CLI_EXAMPLES, width))
    lines.append("")
    lines.append(color_text("Only scan systems you own or have explicit permission to test.", ANSI_DIM))
    return "\n".join(lines)


def render_help_panel(title: str, rows: list[tuple[str, str]], width: int) -> list[str]:
    """Render a simple Unicode box for CLI help sections."""
    title_text = f" {title} "
    top = color_text("╭─" + title_text + "─" * (width - len(title_text) - 2) + "╮", ANSI_CYAN)
    bottom = color_text("╰" + "─" * width + "╯", ANSI_CYAN)
    body_width = width - 2
    name_width = max(len(name) for name, _ in rows) + 4
    panel = [top]
    for name, description in rows:
        wrapped = wrap_help_description(description, body_width - name_width)
        row = f"│ {name:<{name_width - 1}}{wrapped[0]:<{body_width - name_width}} │"
        panel.append(color_help_row(row, name))
        for extra_line in wrapped[1:]:
            panel.append(f"│ {'':<{name_width - 1}}{extra_line:<{body_width - name_width}} │")
    panel.append(bottom)
    return panel


def wrap_help_description(description: str, width: int) -> list[str]:
    """Wrap help text at word boundaries for boxed help output."""
    words = description.split()
    if not words:
        return [""]
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        if len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}"
    lines.append(current)
    return lines


def render_examples_panel(title: str, examples: list[str], width: int) -> list[str]:
    """Render example commands in a boxed CLI help section."""
    title_text = f" {title} "
    top = color_text("╭─" + title_text + "─" * (width - len(title_text) - 2) + "╮", ANSI_CYAN)
    bottom = color_text("╰" + "─" * width + "╯", ANSI_CYAN)
    body_width = width - 2
    panel = [top]
    for example in examples:
        row = f"│ {example:<{body_width - 1}}│"
        panel.append(row.replace(example, color_text(example, ANSI_GREEN), 1))
    panel.append(bottom)
    return panel


def color_help_row(row: str, name: str) -> str:
    """Color a help row without changing its visual padding."""
    colored_name = color_text(name, ANSI_GREEN if not name.startswith("-") else ANSI_YELLOW)
    return row.replace(name, colored_name, 1)


def color_text(text: str, style: str) -> str:
    """Wrap text in ANSI style codes."""
    return f"{style}{text}{ANSI_RESET}"


def print_cli_text(text: str) -> None:
    """Print CLI text as UTF-8 when the stream supports reconfiguration."""
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure:
        reconfigure(encoding="utf-8")
    print(text)


def add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach shared scan arguments to a parser."""
    parser.add_argument("target", help="Target host, IP, CIDR range, or website URL to scan.")
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
        "--cve-db",
        type=Path,
        help="Optional JSON CVE database to use instead of the bundled offline catalog.",
    )
    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Disable automated CVE correlation and only show service-rule findings.",
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
    parser.add_argument(
        "--score-only",
        action="store_true",
        help="Print a compact target score summary instead of the full scan report.",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        choices=range(1, 11),
        metavar="1-10",
        help="Return exit code 2 if the final target score is below this threshold.",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    if not argv:
        argv = ["--help"]

    if argv in (["-h"], ["--help"]):
        print_cli_text(render_cli_help())
        raise SystemExit(0)

    parser = argparse.ArgumentParser(
        prog=CLI_COMMAND,
        description=CLI_DESCRIPTION,
    )
    parser.add_argument("--version", action="version", version=f"{CLI_COMMAND} {CLI_VERSION}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>", title="commands")

    scan_parser = subparsers.add_parser(
        "scan",
        help=CLI_COMMANDS[0][1],
        description=CLI_COMMANDS[0][1],
    )
    add_scan_arguments(scan_parser)

    inventory_parser = subparsers.add_parser(
        "inventory",
        help=CLI_COMMANDS[1][1],
        description=CLI_COMMANDS[1][1],
    )
    add_scan_arguments(inventory_parser)

    cves_parser = subparsers.add_parser(
        "cves",
        help=CLI_COMMANDS[2][1],
        description=CLI_COMMANDS[2][1],
    )
    cves_parser.add_argument(
        "--cve-db",
        type=Path,
        help="Optional JSON CVE database to list instead of the bundled offline catalog.",
    )

    subparsers.add_parser("profiles", help=CLI_COMMANDS[3][1], description=CLI_COMMANDS[3][1])
    subparsers.add_parser("ports", help=CLI_COMMANDS[4][1], description=CLI_COMMANDS[4][1])
    subparsers.add_parser(
        "uninstall-help",
        help=CLI_COMMANDS[5][1],
        description=CLI_COMMANDS[5][1],
    )

    commands = {"scan", "inventory", "profiles", "ports", "cves", "uninstall-help", "-h", "--help", "--version"}
    if argv and argv[0] not in commands:
        argv = ["scan", *argv]
    return parser.parse_args(argv)


def run_scan_command(args: argparse.Namespace) -> ScanResult:
    """Run a scan from parsed CLI arguments."""
    normalized_target = normalize_scan_target(args.target)
    scan_arguments = resolve_scan_arguments(
        profile=args.profile,
        nmap_args=args.nmap_args,
        aggressive=args.aggressive,
    )
    ports = resolve_scan_ports(args.ports, args.port_group, args.target)
    profile = "custom" if args.nmap_args else ("deep" if args.aggressive else args.profile)
    cve_database = load_cve_database(args.cve_db) if not args.no_cve else []
    return perform_scan(
        target=normalized_target,
        ports=ports,
        scan_arguments=scan_arguments,
        nmap_path=args.nmap_path,
        profile=profile,
        minimum_risk=args.min_risk,
        cve_database=cve_database,
        enable_cve_correlation=not args.no_cve,
        input_target=args.target,
    )


def print_or_save_result(result: ScanResult, args: argparse.Namespace) -> None:
    """Print a report and optionally save it."""
    rendered = render_score_report(result) if args.score_only else render_report(result, args.format)
    print(rendered)

    if args.output:
        if args.score_only:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            write_report(result, args.output, args.format)
        print(f"\nReport saved to: {args.output}")


def score_exit_code(result: ScanResult, args: argparse.Namespace) -> int:
    """Return a nonzero code when the caller requested a score gate."""
    if args.min_score is not None and result.security_score < args.min_score:
        print(
            f"Score gate failed: {result.security_score}/10 is below required minimum {args.min_score}/10.",
            file=sys.stderr,
        )
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.command == "profiles":
        print(render_profiles())
        return 0

    if args.command == "ports":
        print(render_port_groups())
        return 0

    if args.command == "uninstall-help":
        print(render_uninstall_help())
        return 0

    if args.command == "cves":
        try:
            print(render_cve_database(load_cve_database(args.cve_db)))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        return 0

    try:
        result = run_scan_command(args)
    except (RuntimeError, ET.ParseError, OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.command == "inventory":
        rendered = render_score_report(result) if args.score_only else render_service_inventory(result)
        print(rendered)
        if args.output:
            if args.score_only:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(rendered, encoding="utf-8")
            else:
                write_report(result, args.output, args.format)
            print(f"\nReport saved to: {args.output}")
    else:
        print_or_save_result(result, args)

    return score_exit_code(result, args)


if __name__ == "__main__":
    raise SystemExit(main())
