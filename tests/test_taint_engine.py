import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flowguard.analyzer import FlowGuardAnalyzer


class TestTaintEngine(unittest.TestCase):
    def setUp(self):
        self.analyzer = FlowGuardAnalyzer()

    def test_slide_12_vulnerability(self):
        code = (
            "name = input()\n"
            "if name:\n"
            "    query = name\n"
            "else:\n"
            "    query = 'guest'\n"
            "execute_query(query)\n"
        )
        res = self.analyzer.analyze(code)
        self.assertEqual(len(res.vulnerabilities), 1)
        v = res.vulnerabilities[0]
        self.assertEqual(v.vuln_type, "SQL Injection")
        self.assertEqual(v.sink_name, "execute_query")
        self.assertEqual(v.taint_record.source_name, "input()")

    def test_sanitized_safety(self):
        code = (
            "user = input()\n"
            "safe_user = sanitize(user)\n"
            "execute_query(safe_user)\n"
        )
        res = self.analyzer.analyze(code)
        self.assertEqual(len(res.vulnerabilities), 0)

    def test_command_injection_multi_hop(self):
        code = (
            "a = input()\n"
            "b = a\n"
            "c = 'cat ' + b\n"
            "system(c)\n"
        )
        res = self.analyzer.analyze(code)
        self.assertEqual(len(res.vulnerabilities), 1)
        v = res.vulnerabilities[0]
        self.assertEqual(v.vuln_type, "Command Injection")


if __name__ == "__main__":
    unittest.main()
