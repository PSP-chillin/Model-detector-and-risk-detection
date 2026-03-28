"""
Reporter – aggregates findings from all scanners and outputs structured JSON.

Output format per finding:
  {
    "file":     "model.py",
    "line":     42,            # optional – may be null
    "issue":    "Unsafe deserialization",
    "severity": "HIGH"
  }

The reporter also produces a summary block:
  {
    "summary": {
      "total": 5,
      "high": 3,
      "medium": 1,
      "low": 1
    },
    "findings": [ ... ]
  }
"""

import json
import sys
from typing import List, Dict, Any, Optional


_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _sev_key(finding: Dict[str, Any]) -> int:
    return _SEV_ORDER.get(finding.get("severity", "LOW"), 2)


class Reporter:
    """Collect, deduplicate, sort and serialise scan findings."""

    def __init__(self) -> None:
        self._findings: List[Dict[str, Any]] = []

    def add_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Add a list of findings from any scanner."""
        self._findings.extend(findings)

    def deduplicate(self) -> None:
        """Remove duplicate findings (same file + line + issue)."""
        seen = set()
        unique: List[Dict[str, Any]] = []
        for f in self._findings:
            key = (f.get("file"), f.get("line"), f.get("issue"))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self._findings = unique

    def filter_by_severity(self, min_severity: str) -> None:
        """
        Remove findings below *min_severity*.

        Severity order (highest to lowest): HIGH > MEDIUM > LOW.
        """
        threshold = _SEV_ORDER.get(min_severity, 2)
        self._findings = [
            f for f in self._findings
            if _SEV_ORDER.get(f.get("severity", "LOW"), 2) <= threshold
        ]

    def get_findings(self) -> List[Dict[str, Any]]:
        """Return deduplicated findings sorted by severity then file."""
        self.deduplicate()
        return sorted(self._findings, key=lambda f: (_sev_key(f), f.get("file", ""), f.get("line") or 0))

    def build_report(self) -> Dict[str, Any]:
        """Return the full report as a Python dict."""
        findings = self.get_findings()
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev in counts:
                counts[sev] += 1
            else:
                counts["LOW"] += 1

        return {
            "summary": {
                "total":  len(findings),
                "high":   counts["HIGH"],
                "medium": counts["MEDIUM"],
                "low":    counts["LOW"],
            },
            "findings": findings,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialise the report to a JSON string."""
        return json.dumps(self.build_report(), indent=indent)

    def print_report(
        self,
        output_file: Optional[str] = None,
        indent: int = 2,
    ) -> None:
        """
        Print the JSON report to *output_file* or stdout.
        Also prints a human-readable summary to stderr.
        """
        report = self.build_report()
        json_str = json.dumps(report, indent=indent)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(json_str)
                fh.write("\n")
            print(f"[*] Report written to {output_file}", file=sys.stderr)
        else:
            print(json_str)

        s = report["summary"]
        print(
            f"\n[summary] total={s['total']}  HIGH={s['high']}  "
            f"MEDIUM={s['medium']}  LOW={s['low']}",
            file=sys.stderr,
        )
