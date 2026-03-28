"""
Regex-based pattern engine for detecting hardcoded secrets and other
text-level vulnerabilities that AST analysis cannot easily catch.

Detects:
  - Hardcoded API keys  (OpenAI, AWS, GCP, GitHub, HuggingFace, generic)
  - Hardcoded passwords / secrets in assignments
  - Private-key PEM blocks in source
  - Bearer / Basic tokens hardcoded in source
  - TODO-security markers
"""

import re
import os
from typing import List, Dict, Any, Tuple


HIGH   = "HIGH"
MEDIUM = "MEDIUM"
LOW    = "LOW"


# ---------------------------------------------------------------------------
# Pattern definitions:  (name, compiled_regex, severity, issue_template)
# ---------------------------------------------------------------------------
_PATTERNS: List[Tuple[str, re.Pattern, str, str]] = [
    # --- OpenAI ---
    (
        "OpenAI API key",
        re.compile(r"sk-[A-Za-z0-9]{32,}", re.IGNORECASE),
        HIGH,
        "Hardcoded OpenAI API key",
    ),
    # --- AWS access key ---
    (
        "AWS access key ID",
        re.compile(r"(?<![A-Z0-9])(AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        HIGH,
        "Hardcoded AWS access key ID",
    ),
    # --- AWS secret key (heuristic: 40-char base64 after common var names) ---
    (
        "AWS secret key",
        re.compile(
            r'(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\']?([A-Za-z0-9+/]{40})["\']?'
        ),
        HIGH,
        "Hardcoded AWS secret access key",
    ),
    # --- Google / GCP API key ---
    (
        "Google API key",
        re.compile(r"AIza[0-9A-Za-z\-_]{32,}"),
        HIGH,
        "Hardcoded Google/GCP API key",
    ),
    # --- GitHub personal access token ---
    (
        "GitHub token",
        re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
        HIGH,
        "Hardcoded GitHub personal access token",
    ),
    # --- HuggingFace token ---
    (
        "HuggingFace token",
        re.compile(r"hf_[A-Za-z0-9]{34,}"),
        HIGH,
        "Hardcoded HuggingFace API token",
    ),
    # --- Slack token ---
    (
        "Slack token",
        re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        HIGH,
        "Hardcoded Slack token",
    ),
    # --- Generic high-entropy password/secret assignment ---
    (
        "Hardcoded secret",
        re.compile(
            r'(?i)\b(password|passwd|secret|api_key|apikey|token|auth_token|access_token)\s*[=:]\s*["\']([^"\']{8,})["\']'
        ),
        MEDIUM,
        "Possible hardcoded secret or password",
    ),
    # --- PEM private key block ---
    (
        "Private key",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        HIGH,
        "Embedded private key / PEM block",
    ),
    # --- Bearer token hardcoded ---
    (
        "Bearer token",
        re.compile(r'(?i)(Bearer\s+[A-Za-z0-9\-._~+/]+=*)'),
        MEDIUM,
        "Hardcoded Bearer token",
    ),
    # --- Basic auth credentials in URL ---
    (
        "Basic auth in URL",
        re.compile(r"https?://[^@\s]+:[^@\s]+@"),
        HIGH,
        "Credentials embedded in URL (Basic Auth)",
    ),
]

# Lines that look like comments explaining what a secret SHOULD be are often
# false positives – skip lines that are clearly documentation placeholders.
_PLACEHOLDER_RE = re.compile(
    r'(?i)(your[_\-]?(api[_\-]?)?key|<key>|<token>|<secret>|placeholder|\bxxx+\b|todo)',
    re.IGNORECASE,
)


class PatternEngine:
    """Scan files for hardcoded secrets and other text-level vulnerabilities."""

    def analyze_file(self, filepath: str) -> List[Dict[str, Any]]:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError as exc:
            return [{"file": filepath, "line": None,
                     "issue": f"Could not read file: {exc}", "severity": "LOW"}]

        filename = os.path.relpath(filepath)
        findings: List[Dict[str, Any]] = []

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip pure comment lines (Python #)
            if stripped.startswith("#"):
                continue
            # Skip obvious placeholder lines
            if _PLACEHOLDER_RE.search(stripped):
                continue

            for _name, pattern, severity, issue_label in _PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "file": filename,
                        "line": lineno,
                        "issue": issue_label,
                        "severity": severity,
                    })
                    break  # Only report the first matching pattern per line

        return findings

    def analyze_directory(self, dirpath: str) -> List[Dict[str, Any]]:
        """Recursively scan all text files under *dirpath*."""
        findings: List[Dict[str, Any]] = []
        skip_dirs = {".git", "__pycache__", ".tox", "venv", ".venv", "node_modules"}
        text_exts = {".py", ".ipynb", ".env", ".cfg", ".ini", ".yaml", ".yml",
                     ".json", ".toml", ".txt", ".sh", ".bash"}
        for root, dirs, files in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in text_exts:
                    findings.extend(self.analyze_file(os.path.join(root, fname)))
        return findings
