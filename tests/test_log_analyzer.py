import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from log_analyzer import analyze_lines, render_html, render_text


class LogAnalyzerTests(unittest.TestCase):
    def test_ssh_bruteforce(self):
        lines = [
            "Aug 30 sshd: Failed password for invalid user root from 10.0.0.9 port 1 ssh2",
            "Aug 30 sshd: Failed password for invalid user root from 10.0.0.9 port 2 ssh2",
            "Aug 30 sshd: Failed password for user root from 10.0.0.9 port 3 ssh2",
        ]
        result = analyze_lines(lines, "test", "ssh", threshold=3, window=10)
        self.assertEqual(result.ssh_failures["10.0.0.9"], 3)
        self.assertEqual(result.threats[0].kind, "SSH brute force")

    def test_web_injection(self):
        lines = [
            '10.0.0.7 - - [30/Aug/2026:22:10:00 -0300] "GET /?q=\' OR 1=1 HTTP/1.1" 400 1',
            '10.0.0.8 - - [30/Aug/2026:22:10:00 -0300] "GET /?q=%3Cscript%3E HTTP/1.1" 403 1',
        ]
        result = analyze_lines(lines, "test", "web", threshold=5, window=10)
        self.assertEqual(len(result.threats), 2)
        self.assertIn("SQL injection", result.rule_counts)
        self.assertIn("XSS", result.rule_counts)

    def test_reports(self):
        result = analyze_lines([], "test", "web", 5, 10)
        self.assertIn("LOG ANALYZER", render_text(result))
        self.assertIn("<html", render_html(result))


if __name__ == "__main__":
    unittest.main()
