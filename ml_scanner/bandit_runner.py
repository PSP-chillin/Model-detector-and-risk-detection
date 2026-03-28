"""
Bandit integration – runs bandit as a subprocess and translates its JSON
output into the scanner's standard finding format.

Bandit covers a broad set of additional checks (B-series rules) and is
used here to extend the AST and pattern engines with its ruleset.
"""

import json
import os
import subprocess
import shutil
from typing import List, Dict, Any


# Severity mapping from bandit nomenclature to our levels
_SEV_MAP = {
    "HIGH":   "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW":    "LOW",
}

# Confidence mapping – we downgrade LOW confidence findings to INFO
_CONF_DOWNGRADE = {"LOW"}


class BanditRunner:
    """Run bandit on Python files and normalise findings."""

    def __init__(self) -> None:
        self._bandit_path = shutil.which("bandit")

    def available(self) -> bool:
        """Return True if bandit is installed and available on PATH."""
        return self._bandit_path is not None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_file(self, filepath: str) -> List[Dict[str, Any]]:
        return self._run([filepath], os.path.dirname(filepath) or ".")

    def analyze_directory(self, dirpath: str) -> List[Dict[str, Any]]:
        return self._run([dirpath], dirpath)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run(self, targets: List[str], cwd: str) -> List[Dict[str, Any]]:
        if not self.available():
            return [{"file": "(bandit)", "line": None,
                     "issue": "bandit is not installed – skipping extended rule checks",
                     "severity": "LOW"}]

        cmd = [
            self._bandit_path,
            "--format", "json",
            "--quiet",
            "-r",          # recursive
        ] + targets

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=cwd,
            )
        except subprocess.TimeoutExpired:
            return [{"file": "(bandit)", "line": None,
                     "issue": "bandit timed out", "severity": "LOW"}]
        except OSError as exc:
            return [{"file": "(bandit)", "line": None,
                     "issue": f"bandit execution error: {exc}", "severity": "LOW"}]

        # bandit exits with 1 when issues are found, 0 when clean – both are ok
        raw = result.stdout
        if not raw.strip():
            return []

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: List[Dict[str, Any]] = []
        for result_item in data.get("results", []):
            confidence = result_item.get("issue_confidence", "MEDIUM")
            severity   = result_item.get("issue_severity", "MEDIUM")

            # Downgrade very low-confidence hits
            if confidence in _CONF_DOWNGRADE:
                severity = "LOW"

            file_path = result_item.get("filename", "unknown")
            try:
                file_path = os.path.relpath(file_path)
            except ValueError:
                pass  # On Windows relpath may fail across drives

            findings.append({
                "file":     file_path,
                "line":     result_item.get("line_number"),
                "issue":    f"[bandit:{result_item.get('test_id', '?')}] {result_item.get('issue_text', '')}",
                "severity": _SEV_MAP.get(severity, "MEDIUM"),
            })

        return findings
