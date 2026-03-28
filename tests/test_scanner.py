"""Tests for the ML Security Scanner."""
import json
import os
import sys
import textwrap
import tempfile
import unittest

# Ensure the package root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml_scanner.ast_analyzer import ASTAnalyzer
from ml_scanner.pattern_engine import PatternEngine
from ml_scanner.api_scanner import APIScanner
from ml_scanner.reporter import Reporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_tmp(code: str, suffix: str = ".py") -> str:
    """Write *code* to a named temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(code))
    except Exception:
        os.unlink(path)
        raise
    return path


def _issues(findings):
    return [f["issue"] for f in findings]


# ---------------------------------------------------------------------------
# ASTAnalyzer tests
# ---------------------------------------------------------------------------

class TestASTAnalyzerPickle(unittest.TestCase):
    def setUp(self):
        self.analyzer = ASTAnalyzer()

    def test_pickle_load_detected(self):
        path = _write_tmp("""
            import pickle
            with open('model.pkl', 'rb') as f:
                model = pickle.load(f)
        """)
        try:
            findings = self.analyzer.analyze_file(path)
            issues = _issues(findings)
            self.assertTrue(
                any("pickle.load" in i for i in issues),
                f"Expected pickle.load finding, got: {issues}",
            )
            self.assertEqual(findings[0]["severity"], "HIGH")
        finally:
            os.unlink(path)

    def test_pickle_loads_detected(self):
        path = _write_tmp("""
            import pickle
            model = pickle.loads(data)
        """)
        try:
            findings = self.analyzer.analyze_file(path)
            issues = _issues(findings)
            self.assertTrue(any("pickle.loads" in i for i in issues))
        finally:
            os.unlink(path)

    def test_joblib_load_detected(self):
        path = _write_tmp("""
            import joblib
            model = joblib.load('model.pkl')
        """)
        try:
            findings = self.analyzer.analyze_file(path)
            self.assertTrue(any("joblib.load" in i for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_torch_load_detected(self):
        path = _write_tmp("""
            import torch
            model = torch.load('weights.pt')
        """)
        try:
            findings = self.analyzer.analyze_file(path)
            self.assertTrue(any("torch.load" in i for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_numpy_allow_pickle_detected(self):
        path = _write_tmp("""
            import numpy as np
            data = np.load('data.npy', allow_pickle=True)
        """)
        try:
            findings = self.analyzer.analyze_file(path)
            self.assertTrue(any("allow_pickle" in i for i in _issues(findings)))
        finally:
            os.unlink(path)


class TestASTAnalyzerExecEval(unittest.TestCase):
    def setUp(self):
        self.analyzer = ASTAnalyzer()

    def test_eval_detected(self):
        path = _write_tmp("result = eval(user_input)\n")
        try:
            findings = self.analyzer.analyze_file(path)
            self.assertTrue(any("eval()" in i for i in _issues(findings)))
            self.assertEqual(findings[0]["severity"], "HIGH")
        finally:
            os.unlink(path)

    def test_exec_detected(self):
        path = _write_tmp("exec(user_code)\n")
        try:
            findings = self.analyzer.analyze_file(path)
            self.assertTrue(any("exec()" in i for i in _issues(findings)))
        finally:
            os.unlink(path)


class TestASTAnalyzerSubprocess(unittest.TestCase):
    def setUp(self):
        self.analyzer = ASTAnalyzer()

    def test_subprocess_shell_true(self):
        path = _write_tmp("""
            import subprocess
            subprocess.run('ls', shell=True)
        """)
        try:
            findings = self.analyzer.analyze_file(path)
            self.assertTrue(any("shell=True" in i for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_subprocess_shell_false_not_flagged(self):
        path = _write_tmp("""
            import subprocess
            subprocess.run(['ls', '-la'])
        """)
        try:
            findings = self.analyzer.analyze_file(path)
            self.assertFalse(any("shell=True" in i for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_os_system_detected(self):
        path = _write_tmp("""
            import os
            os.system('rm -rf /tmp/data')
        """)
        try:
            findings = self.analyzer.analyze_file(path)
            self.assertTrue(any("os.system" in i for i in _issues(findings)))
        finally:
            os.unlink(path)


class TestASTAnalyzerYAML(unittest.TestCase):
    def setUp(self):
        self.analyzer = ASTAnalyzer()

    def test_yaml_load_unsafe(self):
        path = _write_tmp("""
            import yaml
            config = yaml.load(stream)
        """)
        try:
            findings = self.analyzer.analyze_file(path)
            self.assertTrue(any("yaml.load" in i for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_yaml_load_safe_not_flagged(self):
        path = _write_tmp("""
            import yaml
            config = yaml.load(stream, Loader=yaml.SafeLoader)
        """)
        try:
            findings = self.analyzer.analyze_file(path)
            self.assertFalse(any("yaml.load" in i for i in _issues(findings)))
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# PatternEngine tests
# ---------------------------------------------------------------------------

class TestPatternEngineAPIKeys(unittest.TestCase):
    def setUp(self):
        self.engine = PatternEngine()

    def test_openai_key_detected(self):
        path = _write_tmp(
            'OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ"\n'
        )
        try:
            findings = self.engine.analyze_file(path)
            self.assertTrue(any("OpenAI" in i for i in _issues(findings)))
            self.assertEqual(findings[0]["severity"], "HIGH")
        finally:
            os.unlink(path)

    def test_aws_access_key_detected(self):
        path = _write_tmp('key = "AKIAIOSFODNN7EXAMPLE"\n')
        try:
            findings = self.engine.analyze_file(path)
            self.assertTrue(any("AWS" in i for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_google_api_key_detected(self):
        path = _write_tmp('api_key = "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')
        try:
            findings = self.engine.analyze_file(path)
            self.assertTrue(any("Google" in i for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_hardcoded_password_detected(self):
        path = _write_tmp('password = "mysecretpassword123"\n')
        try:
            findings = self.engine.analyze_file(path)
            self.assertTrue(
                any("secret" in i.lower() or "password" in i.lower() for i in _issues(findings))
            )
        finally:
            os.unlink(path)

    def test_pem_key_detected(self):
        path = _write_tmp('key = "-----BEGIN RSA PRIVATE KEY-----"\n')
        try:
            findings = self.engine.analyze_file(path)
            self.assertTrue(any("private key" in i.lower() for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_no_false_positive_on_placeholder(self):
        path = _write_tmp('API_KEY = "your_api_key_here"\n')
        try:
            findings = self.engine.analyze_file(path)
            # placeholder should be filtered
            self.assertEqual(len(findings), 0)
        finally:
            os.unlink(path)

    def test_ssl_verify_false_detected(self):
        path = _write_tmp('resp = requests.get(url, verify=False)\n')
        try:
            # Pattern engine does not detect this; API scanner does.
            # Just verify no crash.
            findings = self.engine.analyze_file(path)
            self.assertIsInstance(findings, list)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# APIScanner tests
# ---------------------------------------------------------------------------

class TestAPIScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = APIScanner()

    def test_flask_debug_detected(self):
        path = _write_tmp("""
            app.run(debug=True, host='0.0.0.0')
        """)
        try:
            findings = self.scanner.analyze_file(path)
            self.assertTrue(any("debug" in i.lower() for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_ssl_verify_false_detected(self):
        path = _write_tmp("resp = requests.get(url, verify=False)\n")
        try:
            findings = self.scanner.analyze_file(path)
            self.assertTrue(any("SSL" in i for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_cors_wildcard_detected(self):
        path = _write_tmp("""
            CORS(app, allow_origins=["*"])
        """)
        try:
            findings = self.scanner.analyze_file(path)
            self.assertTrue(any("CORS" in i for i in _issues(findings)))
        finally:
            os.unlink(path)

    def test_unauthenticated_post_endpoint(self):
        path = _write_tmp("""
            from flask import Flask, request
            app = Flask(__name__)

            @app.route('/predict', methods=['POST'])
            def predict():
                return 'ok'
        """)
        try:
            findings = self.scanner.analyze_file(path)
            self.assertTrue(
                any("auth" in i.lower() or "POST" in i for i in _issues(findings))
            )
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Reporter tests
# ---------------------------------------------------------------------------

class TestReporter(unittest.TestCase):
    def _make_findings(self):
        return [
            {"file": "a.py", "line": 1, "issue": "Unsafe deserialization", "severity": "HIGH"},
            {"file": "b.py", "line": 2, "issue": "Hardcoded secret",       "severity": "MEDIUM"},
            {"file": "a.py", "line": 1, "issue": "Unsafe deserialization", "severity": "HIGH"},  # dup
        ]

    def test_deduplication(self):
        r = Reporter()
        r.add_findings(self._make_findings())
        findings = r.get_findings()
        self.assertEqual(len(findings), 2)

    def test_summary_counts(self):
        r = Reporter()
        r.add_findings(self._make_findings())
        report = r.build_report()
        self.assertEqual(report["summary"]["high"],   1)
        self.assertEqual(report["summary"]["medium"], 1)
        self.assertEqual(report["summary"]["total"],  2)

    def test_json_output_structure(self):
        r = Reporter()
        r.add_findings([
            {"file": "model.py", "line": 10, "issue": "Unsafe deserialization", "severity": "HIGH"}
        ])
        data = json.loads(r.to_json())
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        finding = data["findings"][0]
        self.assertEqual(finding["file"],     "model.py")
        self.assertEqual(finding["issue"],    "Unsafe deserialization")
        self.assertEqual(finding["severity"], "HIGH")

    def test_severity_sort_order(self):
        r = Reporter()
        r.add_findings([
            {"file": "x.py", "line": 1, "issue": "Low issue",    "severity": "LOW"},
            {"file": "x.py", "line": 2, "issue": "High issue",   "severity": "HIGH"},
            {"file": "x.py", "line": 3, "issue": "Medium issue", "severity": "MEDIUM"},
        ])
        findings = r.get_findings()
        severities = [f["severity"] for f in findings]
        self.assertEqual(severities, ["HIGH", "MEDIUM", "LOW"])


# ---------------------------------------------------------------------------
# VirusTotalScanner tests (HTTP calls fully mocked)
# ---------------------------------------------------------------------------

from unittest.mock import MagicMock, patch

from ml_scanner.virustotal_scanner import VirusTotalScanner, _risk_severity


class TestRiskSeverity(unittest.TestCase):
    """Unit tests for the pure _risk_severity() helper."""

    def test_high_many_malicious(self):
        self.assertEqual(_risk_severity({"malicious": 10, "harmless": 50}), "HIGH")

    def test_high_ratio(self):
        # 4 / 10 = 0.40 > 0.30 → HIGH
        self.assertEqual(_risk_severity({"malicious": 4, "harmless": 6}), "HIGH")

    def test_medium_some_malicious(self):
        self.assertEqual(_risk_severity({"malicious": 1, "harmless": 60}), "MEDIUM")

    def test_medium_many_suspicious(self):
        self.assertEqual(_risk_severity({"malicious": 0, "suspicious": 5, "harmless": 55}), "MEDIUM")

    def test_low_few_suspicious(self):
        self.assertEqual(_risk_severity({"malicious": 0, "suspicious": 1, "harmless": 60}), "LOW")

    def test_clean_returns_none(self):
        self.assertIsNone(_risk_severity({"malicious": 0, "suspicious": 0, "harmless": 70}))

    def test_empty_stats_returns_none(self):
        self.assertIsNone(_risk_severity({}))


class TestVirusTotalScannerInit(unittest.TestCase):
    def test_empty_key_raises(self):
        with self.assertRaises(ValueError):
            VirusTotalScanner(api_key="")


class TestVirusTotalScannerAnalyzeFile(unittest.TestCase):
    """Integration-style tests that mock the requests library."""

    def _make_scanner(self):
        return VirusTotalScanner(api_key="testapikey")

    def _hash_response(self, stats):
        """Build a fake VT /files/{hash} response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": stats,
                }
            }
        }
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def _not_found_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def _upload_response(self, analysis_id="analysis123"):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"id": analysis_id}}
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def _analysis_completed_response(self, stats):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": stats,
                }
            }
        }
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    @patch("ml_scanner.virustotal_scanner.requests.get")
    def test_clean_file_returns_no_findings(self, mock_get):
        mock_get.return_value = self._hash_response(
            {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 10}
        )
        scanner = self._make_scanner()
        path = _write_tmp("# clean python file\n")
        try:
            findings = scanner.analyze_file(path)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    @patch("ml_scanner.virustotal_scanner.requests.get")
    def test_high_severity_finding(self, mock_get):
        mock_get.return_value = self._hash_response(
            {"malicious": 15, "suspicious": 2, "harmless": 50, "undetected": 3}
        )
        scanner = self._make_scanner()
        path = _write_tmp("# malware\n")
        try:
            findings = scanner.analyze_file(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "HIGH")
            self.assertIn("VirusTotal", findings[0]["issue"])
            self.assertIn("15/", findings[0]["issue"])
        finally:
            os.unlink(path)

    @patch("ml_scanner.virustotal_scanner.requests.get")
    def test_medium_severity_finding(self, mock_get):
        mock_get.return_value = self._hash_response(
            {"malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 9}
        )
        scanner = self._make_scanner()
        path = _write_tmp("# suspicious\n")
        try:
            findings = scanner.analyze_file(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "MEDIUM")
        finally:
            os.unlink(path)

    @patch("ml_scanner.virustotal_scanner.requests.get")
    def test_low_severity_finding(self, mock_get):
        mock_get.return_value = self._hash_response(
            {"malicious": 0, "suspicious": 2, "harmless": 60, "undetected": 8}
        )
        scanner = self._make_scanner()
        path = _write_tmp("# slightly suspicious\n")
        try:
            findings = scanner.analyze_file(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "LOW")
        finally:
            os.unlink(path)

    @patch("ml_scanner.virustotal_scanner.requests.post")
    @patch("ml_scanner.virustotal_scanner.requests.get")
    def test_hash_not_found_triggers_upload(self, mock_get, mock_post):
        """When hash lookup returns 404, the file should be uploaded."""
        # First GET → 404 (hash not found)
        # Second GET → analysis completed
        mock_get.side_effect = [
            self._not_found_response(),
            self._analysis_completed_response(
                {"malicious": 5, "suspicious": 0, "harmless": 55, "undetected": 10}
            ),
        ]
        mock_post.return_value = self._upload_response("analysis-abc")

        scanner = self._make_scanner()
        path = _write_tmp("# unknown file\n")
        try:
            findings = scanner.analyze_file(path)
            self.assertTrue(mock_post.called, "File should have been uploaded")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "HIGH")
        finally:
            os.unlink(path)

    @patch("ml_scanner.virustotal_scanner.requests.get")
    def test_network_error_returns_low_finding(self, mock_get):
        import requests as req_lib
        mock_get.side_effect = req_lib.exceptions.ConnectionError("connection refused")
        scanner = self._make_scanner()
        path = _write_tmp("# file\n")
        try:
            findings = scanner.analyze_file(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "LOW")
            self.assertIn("VirusTotal scan error", findings[0]["issue"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
