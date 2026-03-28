#!/usr/bin/env python3
"""
ML Security Scanner – CLI entry point
======================================
Scans Python files / directories for common ML-codebase vulnerabilities.

Usage:
    python scan.py <path> [--output report.json] [--no-bandit] [--severity HIGH]

    <path>                File or directory to scan (required)
    --output / -o         Write JSON report to this file (default: stdout)
    --no-bandit           Skip bandit extended-rules scan
    --severity / -s       Minimum severity to include in output [HIGH|MEDIUM|LOW]
                          (default: LOW – show all)
    --api-scan            Enable API endpoint security checks (on by default)
    --no-api-scan         Disable API endpoint security checks
    --virustotal-key KEY  VirusTotal API key; enables file submission for
                          malware / risk detection (disabled by default)
"""

import argparse
import sys
import os

# Ensure the package is importable regardless of working directory
sys.path.insert(0, os.path.dirname(__file__))

from ml_scanner.ast_analyzer import ASTAnalyzer
from ml_scanner.pattern_engine import PatternEngine
from ml_scanner.bandit_runner import BanditRunner
from ml_scanner.api_scanner import APIScanner
from ml_scanner.virustotal_scanner import VirusTotalScanner
from ml_scanner.reporter import Reporter


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ML Security Scanner – detect vulnerabilities in ML Python codebases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        default=None,
        help="Write JSON report to FILE (default: stdout)",
    )
    parser.add_argument(
        "--no-bandit",
        action="store_true",
        default=False,
        help="Disable bandit extended-rule scanning",
    )
    parser.add_argument(
        "--no-api-scan",
        action="store_true",
        default=False,
        help="Disable API endpoint security scanning",
    )
    parser.add_argument(
        "--virustotal-key",
        metavar="KEY",
        default=None,
        help="VirusTotal API key – enables malware/risk detection via the VT v3 API",
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["HIGH", "MEDIUM", "LOW"],
        default="LOW",
        help="Minimum severity level to report (default: LOW)",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    target = args.path

    if not os.path.exists(target):
        print(f"[error] Path not found: {target}", file=sys.stderr)
        return 2

    is_dir = os.path.isdir(target)

    reporter = Reporter()

    # 1. AST-based analysis
    print(f"[*] Running AST analysis on {target} ...", file=sys.stderr)
    ast_analyzer = ASTAnalyzer()
    if is_dir:
        reporter.add_findings(ast_analyzer.analyze_directory(target))
    else:
        reporter.add_findings(ast_analyzer.analyze_file(target))

    # 2. Regex pattern engine
    print(f"[*] Running pattern engine on {target} ...", file=sys.stderr)
    pattern_engine = PatternEngine()
    if is_dir:
        reporter.add_findings(pattern_engine.analyze_directory(target))
    else:
        reporter.add_findings(pattern_engine.analyze_file(target))

    # 3. Bandit extended rules
    if not args.no_bandit:
        print(f"[*] Running bandit on {target} ...", file=sys.stderr)
        bandit = BanditRunner()
        if bandit.available():
            if is_dir:
                reporter.add_findings(bandit.analyze_directory(target))
            else:
                reporter.add_findings(bandit.analyze_file(target))
        else:
            print("[!] bandit not found – install with: pip install bandit", file=sys.stderr)

    # 4. API endpoint scanner
    if not args.no_api_scan:
        print(f"[*] Running API endpoint scan on {target} ...", file=sys.stderr)
        api_scanner = APIScanner()
        if is_dir:
            reporter.add_findings(api_scanner.analyze_directory(target))
        else:
            reporter.add_findings(api_scanner.analyze_file(target))

    # 5. VirusTotal risk detection
    if args.virustotal_key:
        print(f"[*] Running VirusTotal scan on {target} ...", file=sys.stderr)
        vt_scanner = VirusTotalScanner(api_key=args.virustotal_key)
        if vt_scanner.available():
            if is_dir:
                reporter.add_findings(vt_scanner.analyze_directory(target))
            else:
                reporter.add_findings(vt_scanner.analyze_file(target))
        else:
            print("[!] 'requests' not found – install with: pip install requests", file=sys.stderr)

    # Apply severity filter
    reporter.filter_by_severity(args.severity)

    reporter.print_report(output_file=args.output)

    # Return exit code: 1 if any HIGH findings, 0 otherwise
    report = reporter.build_report()
    return 1 if report["summary"]["high"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
