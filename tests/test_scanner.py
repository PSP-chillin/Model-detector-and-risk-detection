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


if __name__ == "__main__":
    unittest.main()
