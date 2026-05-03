# CLI Network Vulnerability Scanner

A Python command-line network vulnerability scanner that integrates with Nmap for automated port scanning and service enumeration. It parses Nmap XML output, identifies open services, and applies basic vulnerability checks for exposed or risky services.

> Use this tool only on systems you own or have explicit permission to test.

## Features

- CLI-based target scanning
- Nmap integration for port discovery and service/version enumeration
- Built-in scan profiles for quick, safe, deep, and vulnerability-oriented scans
- Named port groups for web, admin, database, Windows, and common top ports
- Basic vulnerability identification for FTP, Telnet, HTTP, SMB, RDP, VNC, SNMP, NFS, databases, Memcached, and search database services
- Text, JSON, and CSV report output
- Severity filtering with `--min-risk`
- Service inventory mode
- Modular Python functions for future CVE mapping and exploit recommendation features
- No third-party Python package required

## Requirements

- Python 3.10+
- Nmap installed and available in your system `PATH`

Check Nmap installation:

```bash
nmap --version
```

## Installation

Install the project locally so the `netvs` command is available from your terminal:

```bash
pip install -e .
```

Verify the CLI command:

```bash
netvs --help
```

## Usage

Show CLI help:

```bash
netvs --help
netvs scan --help
```

Scan a target with default Nmap service detection:

```bash
netvs 192.168.1.10
```

The direct target syntax above is a shortcut for:

```bash
netvs scan 192.168.1.10
```

Scan selected ports:

```bash
netvs 192.168.1.10 -p 22,80,443
```

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

Run aggressive Nmap detection:

```bash
netvs scanme.nmap.org --aggressive
```

Save a text report:

```bash
netvs 192.168.1.10 -o report.txt
```

Generate JSON output:

```bash
netvs 192.168.1.10 --format json -o report.json
```

Generate CSV output:

```bash
netvs scan 192.168.1.10 --format csv -o findings.csv
```

Show only findings at or above a risk level:

```bash
netvs scan 192.168.1.10 --min-risk medium
```

Show service inventory only:

```bash
netvs inventory 192.168.1.10
```

Pass custom Nmap arguments:

```bash
netvs 192.168.1.10 --nmap-args "-sV --version-light"
```

You can still run the script directly during development:

```bash
python network_vuln_scanner.py 192.168.1.10
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
Open services: 2
Findings: info=2, low=1

Open Services
-------------
- 22/tcp ssh [open] (OpenSSH 8.4)
- 80/tcp http [open] (Apache httpd 2.4.54)

Findings
--------
- [LOW] Unencrypted HTTP service detected on 80/http
  HTTP traffic can be intercepted or modified on the network.
  Recommendation: Enforce HTTPS, redirect HTTP to HTTPS, and enable HSTS.
- [INFO] Service banner reveals version information on 22/ssh
  Detected banner: OpenSSH 8.4.
  Recommendation: Review whether detailed version disclosure is necessary.
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
- `resolve_ports()` maps manual ports or named port groups.
- `run_nmap_scan()` executes Nmap and collects XML output.
- `parse_services_from_nmap_xml()` extracts open services from Nmap results.
- `parse_script_output()` captures Nmap script output for vulnerability-oriented profiles.
- `identify_vulnerabilities()` applies service-based vulnerability rules.
- `filter_findings_by_risk()` filters results by minimum severity.
- `summarize_findings()` and `summarize_services()` generate report summaries.
- `render_text_report()` builds human-readable CLI output.
- `write_report()` saves text, JSON, or CSV reports.

This makes it straightforward to add future modules for:

- CVE mapping by service name and version
- CVSS scoring
- Exploit recommendation metadata
- HTML report generation
- Authenticated scanning profiles

## Current Vulnerability Checks

The built-in checks are intentionally basic and rule-based:

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

These checks are not a replacement for a full vulnerability management platform, but they provide a practical foundation for learning and extension.

## Notes

- Some Nmap scans may require administrator/root privileges depending on scan type and OS.
- Network firewalls can affect scan results.
- Always obtain permission before scanning a host or network.
