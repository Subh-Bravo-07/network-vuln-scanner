# CLI Network Vulnerability Scanner v1.1.5 with Automated CVE Correlation

A Python command-line network vulnerability scanner that integrates with Nmap for automated port scanning and service enumeration. It parses Nmap XML output, identifies open services, applies basic vulnerability checks, and automatically correlates detected products and versions with a bundled offline CVE database.

> Use this tool only on systems you own or have explicit permission to test.

## Features

- CLI-based target scanning with the `netvs` command
- Nmap integration for port discovery and service/version enumeration
- Built-in scan profiles for quick, safe, deep, and vulnerability-oriented scans
- Named port groups for web, admin, database, Windows, and common top ports
- Automated CVE correlation by product, service, CPE, and version
- Nmap script CVE extraction from vulnerability scan output
- CVSS, affected-version, remediation, and reference details in reports
- 1-10 target strength score, from Weakest to Strongest
- Compact `--score-only` output and `--min-score` score gates for automation
- Direct website URL targets such as `https://example.com`
- Basic vulnerability identification for FTP, Telnet, HTTP, SMB, RDP, VNC, SNMP, NFS, databases, Memcached, and search database services
- Text, JSON, and CSV report output
- Severity filtering with `--min-risk`
- Custom JSON CVE database support with `--cve-db`
- Service inventory mode
- Colorized boxed top-level CLI help
- No third-party Python package required

## Requirements

- Python 3.10+
- Nmap installed and available in your system `PATH`

Check Nmap installation:

```bash
nmap --version
```

## Installation

Clone the repository:

```bash
git clone https://github.com/Subh-Bravo-07/network-vuln-scanner.git
cd network-vuln-scanner
```

Install the project locally so the `netvs` command is available from your terminal:

```bash
pip install -e .
```

Verify the CLI command:

```bash
netvs --help
```

Show uninstall instructions:

```bash
netvs uninstall-help
```

Uninstall the pip package:

```bash
pip uninstall netvs
```

`netvs` is the command alias you run in your terminal. `netvs` is also the pip package name to pass to `pip uninstall`.

On Windows, if the command is still available after uninstalling or you need to find which Python installation owns it, run:

```powershell
where.exe netvs
py -ver -m pip uninstall netvs
C:\Path\To\Python\python.exe -m pip uninstall netvs
```

## Usage

Show CLI help:

```bash
netvs --help
netvs scan --help
```

The top-level help uses a colorized boxed layout in supported terminals:

```text
netvs

 Usage: netvs [OPTIONS] COMMAND [ARGS]...

 Network vulnerability scanner powered by Nmap.

╭─ Options ─────────────────────────────────────────────────────────╮
│ -h, --help   Show this message and exit.                          │
╰────────────────────────────────────────────────────────────────────╯

╭─ Commands ────────────────────────────────────────────────────────╮
│ scan             Scan a target and identify basic vulnerabilities. │
│ inventory        Scan a target and show service counts only.       │
│ cves             List CVEs in the bundled or custom correlation    │
│                  database.                                         │
│ profiles         List built-in scan profiles.                      │
│ ports            List built-in port groups.                        │
│ uninstall-help   Show pip uninstall commands and Windows           │
│                  troubleshooting tips.                             │
╰────────────────────────────────────────────────────────────────────╯

╭─ Examples ────────────────────────────────────────────────────────╮
│ netvs scan 192.168.1.10 --profile quick                           │
│ netvs scan https://example.com                                     │
│ netvs scan https://example.com --score-only                        │
│ netvs scan 192.168.1.10 -p 22,80,443                              │
│ netvs inventory 192.168.1.10                                      │
│ netvs uninstall-help                                              │
╰────────────────────────────────────────────────────────────────────╯

Only scan systems you own or have explicit permission to test.
```

Scan a target with default Nmap service detection and CVE correlation:

```bash
netvs 192.168.1.10
```

The direct target syntax above is a shortcut for:

```bash
netvs scan 192.168.1.10
```

Scan selected ports:

```bash
netvs scan 192.168.1.10 -p 22,80,443
```

Scan a direct website link:

```bash
netvs scan https://example.com
netvs scan https://example.com:8443/admin
```

When a URL is supplied, the scanner passes the hostname to Nmap. HTTP and HTTPS URLs default to the built-in web port group unless you provide `--ports` or `--port-group`; URLs with an explicit port scan that port by default.

Use a named port group:

```bash
netvs scan 192.168.1.10 --port-group web
netvs scan 192.168.1.10 --port-group database
```

List available port groups:

```bash
netvs ports
```

Use a scan profile:

```bash
netvs scan 192.168.1.10 --profile quick
netvs scan 192.168.1.10 --profile safe
netvs scan 192.168.1.10 --profile deep
netvs scan 192.168.1.10 --profile vuln
```

List available profiles:

```bash
netvs profiles
```

List bundled CVE correlation rules:

```bash
netvs cves
```

Save reports:

```bash
netvs scan 192.168.1.10 -o report.txt
netvs scan 192.168.1.10 --format json -o report.json
netvs scan 192.168.1.10 --format csv -o findings.csv
```

Show only findings and CVEs at or above a risk level:

```bash
netvs scan 192.168.1.10 --min-risk medium
```

Show only the score summary:

```bash
netvs scan https://example.com --score-only
```

Fail automation when the target score is lower than a required minimum:

```bash
netvs scan https://example.com --min-score 7
```

Use a custom CVE database:

```bash
netvs scan 192.168.1.10 --cve-db custom_cves.json
```

Disable CVE correlation and show only service-rule findings:

```bash
netvs scan 192.168.1.10 --no-cve
```

Show service inventory only:

```bash
netvs inventory 192.168.1.10
```

Pass custom Nmap arguments:

```bash
netvs scan 192.168.1.10 --nmap-args "-sV --version-light"
```

## Example Output

```text
Network Vulnerability Scanner Report
======================================
Target: 192.168.1.10
Profile: default
Nmap args: -sV
Scanned at: 2026-05-03T05:55:00+00:00

Summary
-------
Score [1-10]: 7/10 (Strong; Weakest - Strongest)
Open services: 2
Correlated CVEs: 1
Findings: info=2, low=1, high=1
Score factors: open service penalty=0.3, finding penalty=2.9, risky port penalty=0, total penalty=3.2

Open Services
-------------
- 22/tcp ssh [open] (OpenSSH 8.4)
- 80/tcp http [open] (Apache httpd 2.4.49 cpe:/a:apache:http_server:2.4.49)

CVE Correlation
---------------
- [HIGH] CVE-2021-41773 on 80/http (CVSS 7.5)
  Product/version: Apache httpd 2.4.49
  Affected: == 2.4.49
  Summary: Apache HTTP Server 2.4.49 path traversal and file disclosure vulnerability.
  Recommendation: Upgrade Apache HTTP Server to 2.4.51 or later and review path alias configuration.
  Match reason: product+cpe+version
  References: https://nvd.nist.gov/vuln/detail/CVE-2021-41773

Findings
--------
- [HIGH] CVE-2021-41773: Apache HTTP Server 2.4.49 path traversal and file disclosure vulnerability. on 80/http
  Detected Apache httpd 2.4.49 matches affected versions: == 2.4.49.
  Recommendation: Upgrade Apache HTTP Server to 2.4.51 or later and review path alias configuration.
- [LOW] Unencrypted HTTP service detected on 80/http
  HTTP traffic can be intercepted or modified on the network.
  Recommendation: Enforce HTTPS, redirect HTTP to HTTPS, and enable HSTS.
```

## Project Structure

```text
.
├── README.md
├── pyproject.toml
└── network_vuln_scanner.py
```

## Architecture

The scanner is intentionally modular:

- `resolve_scan_arguments()` selects custom Nmap arguments or a built-in profile.
- `normalize_scan_target()` accepts direct website links and extracts the scan host.
- `resolve_ports()` maps manual ports or named port groups.
- `calculate_security_score()` converts exposure and finding severity into a 1-10 strength score.
- `render_score_report()` builds compact score-only output for CLI automation.
- `run_nmap_scan()` executes Nmap and collects XML output.
- `parse_services_from_nmap_xml()` extracts open services, versions, CPEs, and Nmap script output.
- `load_cve_database()` loads the bundled offline CVE database or a custom JSON database.
- `correlate_cves()` maps discovered services to CVEs using product, CPE, service name, and affected-version rules.
- `correlate_script_cves()` extracts CVE IDs reported directly by Nmap scripts.
- `merge_cve_matches()` deduplicates CVEs from service/version matching and Nmap script output.
- `cve_matches_to_findings()` converts CVE matches into report findings.
- `identify_vulnerabilities()` applies service-based vulnerability rules.
- `filter_findings_by_risk()` filters results by minimum severity.
- `render_text_report()`, `render_json_report()`, and `render_csv_report()` build reports.
- `write_report()` saves text, JSON, or CSV reports.

## Custom CVE Database Format

Custom CVE databases are JSON arrays:

```json
[
  {
    "cve_id": "CVE-2021-41773",
    "products": ["apache httpd", "apache http server", "httpd"],
    "cpe_keywords": ["apache:http_server"],
    "service_names": ["http"],
    "affected_versions": [
      { "operator": "==", "version": "2.4.49" }
    ],
    "risk": "high",
    "cvss": 7.5,
    "summary": "Apache HTTP Server path traversal vulnerability.",
    "recommendation": "Upgrade Apache HTTP Server to a fixed release.",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]
  }
]
```

Supported version operators are `==`, `<`, `<=`, `>`, `>=`, and `*`.

Set `"allow_service_only": true` only for protocol-level CVEs where a service name alone is enough evidence, such as selected SMB or RDP checks. Product-specific web CVEs should rely on product or CPE matching.

## Current Checks

The built-in checks include:

- FTP exposure
- Telnet exposure
- Unencrypted HTTP services
- SMB/NetBIOS exposure
- RDP exposure
- VNC exposure
- Legacy mail protocols
- SNMP exposure
- NFS exposure
- Database ports exposed on the network
- Elasticsearch-like search database exposure
- Memcached exposure
- Non-production version markers such as `beta`, `dev`, or `test`
- Nmap script output that references possible vulnerabilities or CVEs
- Service banner and version disclosure
- Offline CVE correlation for common Apache, Nginx, OpenSSH, SMB, RDP, FTP, database, VPN, and web application technology vulnerabilities

The bundled CVE database is intentionally compact for portfolio and learning use. For production-grade coverage, provide a larger custom CVE database generated from trusted feeds and validate results manually.

## Currently Achieved Features

- ~~CLI-based scanning with the `netvs` command~~
- ~~Nmap-powered port scanning and service/version enumeration~~
- ~~Built-in scan profiles: quick, default, safe, deep, and vuln~~
- ~~Named port groups for web, admin, database, Windows, and top common ports~~
- ~~Direct IP, host, CIDR, and website URL targets~~
- ~~Automated offline CVE correlation~~
- ~~Nmap script CVE extraction~~
- ~~Basic vulnerability checks for common exposed services~~
- ~~Text, JSON, and CSV report output~~
- ~~Severity filtering with `--min-risk`~~
- ~~Custom CVE database support with `--cve-db`~~
- ~~Service inventory mode~~
- ~~1-10 target strength score from Weakest to Strongest~~
- ~~Compact `--score-only` output~~
- ~~Score gates for automation with `--min-score`~~
- ~~Colorized boxed top-level CLI help~~
- ~~Uninstall guidance command~~

## Upcoming Feature Additions

- Export an HTML report with score summary, findings, services, and remediation steps.
- Add a larger optional CVE feed import workflow.
- Add scan history comparison to show new, removed, and changed services.
- Add remediation priority sorting based on risk, CVSS, exposure, and service criticality.
- Add safer presets for internet-facing website checks.
- Add optional screenshots or HTTP metadata capture for web services.
- Add richer tests around Nmap XML parsing and report rendering.

## Final Goal

Build `netvs` into a polished portfolio-grade vulnerability scanner that can take an IP, network range, hostname, or website link, run an authorized Nmap-backed assessment, correlate likely vulnerabilities, assign a clear 1-10 security strength score, and produce actionable reports that are useful for learning, demos, and small internal security reviews.

## Notes

- Some Nmap scans may require administrator/root privileges depending on scan type and OS.
- Network firewalls can affect scan results.
- Automated CVE correlation depends on accurate service and version detection.
- Always obtain permission before scanning a host or network.
