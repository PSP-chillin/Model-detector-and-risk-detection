"""
VirusTotal scanner – submits files to the VirusTotal v3 API and converts
the engine-detection results into risk findings compatible with the rest of
the ml_scanner pipeline.

Risk mapping
------------
  malicious engines > 3  OR  malicious / total > 0.30  → HIGH
  malicious engines > 0  OR  suspicious > 3             → MEDIUM
  suspicious > 0                                        → LOW
  all-clean (0 malicious, 0 suspicious)                 → no finding added

Usage
-----
    from ml_scanner.virustotal_scanner import VirusTotalScanner

    vt = VirusTotalScanner(api_key="YOUR_VT_API_KEY")
    findings = vt.analyze_file("/path/to/model.pkl")

The scanner will:
  1. Compute the SHA-256 hash of the file.
  2. Query the VT API for an existing report (avoids re-uploading known hashes).
  3. If no report exists, upload the file and wait for the analysis to finish.
  4. Parse `last_analysis_stats` and map the result to a severity finding.
"""

import hashlib
import os
import time
from typing import Any, Dict, List, Optional

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

_VT_BASE = "https://www.virustotal.com/api/v3"
_MAX_WAIT_SECS = 60   # maximum seconds to poll for analysis completion
_POLL_INTERVAL = 5    # seconds between polling attempts


def _sha256(filepath: str) -> str:
    """Return the hex SHA-256 digest of *filepath*."""
    h = hashlib.sha256()
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _risk_severity(stats: Dict[str, int]) -> Optional[str]:
    """
    Convert VirusTotal ``last_analysis_stats`` into a severity string.

    Returns None when no engines flagged the file (clean).
    """
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    if malicious > 3 or (total > 0 and malicious / total > 0.30):
        return HIGH
    if malicious > 0 or suspicious > 3:
        return MEDIUM
    if suspicious > 0:
        return LOW
    return None  # clean


class VirusTotalScanner:
    """Submit files to VirusTotal and return structured risk findings."""

    def __init__(self, api_key: str) -> None:
        if not api_key:
            raise ValueError("VirusTotal API key must not be empty")
        self._api_key = api_key
        self._headers = {"x-apikey": api_key}

    # ------------------------------------------------------------------
    # Public API (mirrors other scanner classes)
    # ------------------------------------------------------------------

    def available(self) -> bool:
        """Return True if the *requests* library is importable."""
        return _REQUESTS_AVAILABLE

    def analyze_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Scan *filepath* with VirusTotal and return a list of findings.

        Returns an empty list on a clean result.  Returns a single finding
        on error (severity LOW) so the caller is informed without crashing.
        """
        if not _REQUESTS_AVAILABLE:
            return [{
                "file": os.path.relpath(filepath),
                "line": None,
                "issue": "VirusTotal scan skipped – 'requests' library is not installed",
                "severity": LOW,
            }]

        filename = os.path.relpath(filepath)
        try:
            stats, file_hash = self._get_stats(filepath)
        except (OSError, TimeoutError, ValueError,
                requests.exceptions.RequestException) as exc:
            return [{
                "file": filename,
                "line": None,
                "issue": f"VirusTotal scan error: {exc}",
                "severity": LOW,
            }]

        severity = _risk_severity(stats)
        if severity is None:
            return []  # clean file

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())
        return [{
            "file":  filename,
            "line":  None,
            "issue": (
                f"VirusTotal: {malicious}/{total} engines flagged as malicious, "
                f"{suspicious} suspicious (SHA-256: {file_hash})"
            ),
            "severity": severity,
        }]

    def analyze_directory(self, dirpath: str) -> List[Dict[str, Any]]:
        """Recursively scan all files under *dirpath*."""
        findings: List[Dict[str, Any]] = []
        skip_dirs = {".git", "__pycache__", ".tox", "venv", ".venv"}
        for root, dirs, files in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                findings.extend(self.analyze_file(os.path.join(root, fname)))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_stats(self, filepath: str):
        """
        Return (last_analysis_stats, sha256) for *filepath*.

        Tries a hash lookup first; falls back to uploading the file.
        """
        file_hash = _sha256(filepath)
        stats = self._lookup_hash(file_hash)
        if stats is not None:
            return stats, file_hash

        # Not in VT database – upload and wait
        analysis_id = self._upload_file(filepath)
        stats = self._wait_for_analysis(analysis_id)
        return stats, file_hash

    def _lookup_hash(self, file_hash: str) -> Optional[Dict[str, int]]:
        """Query VT for an existing report by SHA-256.  Returns None on 404."""
        url = f"{_VT_BASE}/files/{file_hash}"
        resp = requests.get(url, headers=self._headers, timeout=30)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        return data["data"]["attributes"].get("last_analysis_stats", {})

    def _upload_file(self, filepath: str) -> str:
        """Upload *filepath* to VT and return the analysis ID."""
        url = f"{_VT_BASE}/files"
        with open(filepath, "rb") as fh:
            resp = requests.post(
                url,
                headers=self._headers,
                files={"file": (os.path.basename(filepath), fh)},
                timeout=120,
            )
        resp.raise_for_status()
        return resp.json()["data"]["id"]

    def _wait_for_analysis(self, analysis_id: str) -> Dict[str, int]:
        """Poll the analyses endpoint until the scan completes, then return stats."""
        url = f"{_VT_BASE}/analyses/{analysis_id}"
        deadline = time.monotonic() + _MAX_WAIT_SECS
        while True:
            resp = requests.get(url, headers=self._headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()["data"]
            if data["attributes"]["status"] == "completed":
                return data["attributes"].get("stats", {})
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"VirusTotal analysis {analysis_id!r} did not complete "
                    f"within {_MAX_WAIT_SECS}s"
                )
            time.sleep(_POLL_INTERVAL)
