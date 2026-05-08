import contextlib
import io
import re
import unittest

import network_vuln_scanner

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


class UninstallHelpTests(unittest.TestCase):
    def test_top_level_help_uses_boxed_layout(self) -> None:
        stdout = io.StringIO()

        with self.assertRaises(SystemExit) as raised, contextlib.redirect_stdout(stdout):
            network_vuln_scanner.main(["--help"])

        output = strip_ansi(stdout.getvalue())
        self.assertEqual(raised.exception.code, 0)
        self.assertIn(" Usage: netvs [OPTIONS] COMMAND [ARGS]...", output)
        self.assertIn("-h, --help", output)
        self.assertIn("╭─ Options ", output)
        self.assertIn("╭─ Commands ", output)
        self.assertIn("╭─ Examples ", output)
        self.assertIn("netvs scan 192.168.1.10 --profile quick", output)
        self.assertIn("netvs scan https://example.com", output)
        self.assertIn("netvs scan https://example.com --score-only", output)
        self.assertIn("Only scan systems you own or have explicit permission to test.", output)
        self.assertIn("uninstall-help", output)

    def test_version_reports_1_1_5(self) -> None:
        stdout = io.StringIO()

        with self.assertRaises(SystemExit) as raised, contextlib.redirect_stdout(stdout):
            network_vuln_scanner.main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("netvs 1.1.5", stdout.getvalue())

    def test_uninstall_help_prints_pip_and_windows_guidance(self) -> None:
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            exit_code = network_vuln_scanner.main(["uninstall-help"])

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("pip uninstall netvs", output)
        self.assertIn("`netvs` is the command alias. `netvs` is the pip package name.", output)
        self.assertIn("where.exe netvs", output)
        self.assertIn("py -ver -m pip uninstall netvs", output)
        self.assertIn("C:\\Path\\To\\Python\\python.exe -m pip uninstall netvs", output)

    def test_url_targets_are_normalized_for_nmap(self) -> None:
        self.assertEqual(
            network_vuln_scanner.normalize_scan_target("https://example.com/admin"),
            "example.com",
        )
        self.assertEqual(
            network_vuln_scanner.resolve_scan_ports(None, None, "https://example.com:8443/admin"),
            "8443",
        )
        self.assertEqual(
            network_vuln_scanner.resolve_scan_ports(None, None, "https://example.com"),
            network_vuln_scanner.COMMON_PORT_GROUPS["web"],
        )

    def test_security_score_uses_weakest_to_strongest_scale(self) -> None:
        services = [
            network_vuln_scanner.Service(port=80, protocol="tcp", state="open", name="http"),
            network_vuln_scanner.Service(port=3389, protocol="tcp", state="open", name="rdp"),
        ]
        findings = [
            network_vuln_scanner.Finding(
                risk="high",
                title="Database service exposed",
                description="",
                recommendation="",
            ),
            network_vuln_scanner.Finding(
                risk="medium",
                title="Remote Desktop service exposed",
                description="",
                recommendation="",
            ),
        ]

        score = network_vuln_scanner.calculate_security_score(services, findings)
        details = network_vuln_scanner.calculate_security_score_details(services, findings)

        self.assertEqual(score, 6)
        self.assertEqual(network_vuln_scanner.score_label(score), "Moderate")
        self.assertEqual(details["total_penalty"], 4.0)

    def test_score_report_and_gate(self) -> None:
        result = network_vuln_scanner.ScanResult(
            target="example.com",
            input_target="https://example.com",
            security_score=8,
            score_label="Strong",
            score_details={
                "base_score": 10.0,
                "open_service_penalty": 0.15,
                "finding_penalty": 1.2,
                "risky_port_penalty": 0.0,
                "total_penalty": 1.35,
            },
            services=[
                network_vuln_scanner.Service(port=443, protocol="tcp", state="open", name="https"),
            ],
            findings=[
                network_vuln_scanner.Finding(
                    risk="medium",
                    title="Example finding",
                    description="",
                    recommendation="",
                ),
            ],
        )

        report = network_vuln_scanner.render_score_report(result)

        self.assertIn("Target Score", report)
        self.assertIn("Score [1-10]: 8/10 (Strong; Weakest - Strongest)", report)
        self.assertIn("Score factors:", report)

        args = type("Args", (), {"min_score": 9})()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(network_vuln_scanner.score_exit_code(result, args), 2)
        self.assertIn("Score gate failed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
