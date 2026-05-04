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
        self.assertIn("Only scan systems you own or have explicit permission to test.", output)
        self.assertIn("uninstall-help", output)

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


if __name__ == "__main__":
    unittest.main()
