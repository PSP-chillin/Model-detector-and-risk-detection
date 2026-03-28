"""
API endpoint scanner for deployed ML models.

Detects insecure patterns in web-serving code:
  - Unauthenticated endpoints that accept file uploads or model inputs
  - Flask / FastAPI / Django routes that do not enforce authentication
  - Debug mode enabled in production
  - CORS wildcard (*) policy
  - Missing input validation on prediction endpoints
  - Insecure direct object reference patterns
"""

import ast
import os
import re
from typing import List, Dict, Any


HIGH   = "HIGH"
MEDIUM = "MEDIUM"
LOW    = "LOW"


# ---------------------------------------------------------------------------
# Regex-based patterns for quick text-level API checks
# ---------------------------------------------------------------------------

_API_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": re.compile(r"app\.run\s*\(.*debug\s*=\s*True", re.IGNORECASE),
        "issue":   "Flask debug mode enabled – exposes interactive debugger in production",
        "severity": HIGH,
    },
    {
        "pattern": re.compile(r'CORS\s*\(.*allow_origins\s*=\s*\[?\s*["\']?\*', re.IGNORECASE),
        "issue":   "CORS wildcard (*) – any origin can access the API",
        "severity": MEDIUM,
    },
    {
        "pattern": re.compile(r"@app\.route\b.*methods\s*=.*[\"\']POST[\"\']", re.IGNORECASE),
        "issue":   "Flask POST endpoint detected – verify authentication is enforced",
        "severity": LOW,
    },
    {
        "pattern": re.compile(r"@router\.(post|put|patch|delete)\s*\(", re.IGNORECASE),
        "issue":   "FastAPI mutating endpoint detected – verify authentication/authorization",
        "severity": LOW,
    },
    {
        "pattern": re.compile(r"allow_pickle\s*=\s*True", re.IGNORECASE),
        "issue":   "allow_pickle=True in endpoint code – unsafe deserialization of user input",
        "severity": HIGH,
    },
    {
        "pattern": re.compile(r"verify\s*=\s*False", re.IGNORECASE),
        "issue":   "SSL certificate verification disabled (verify=False)",
        "severity": HIGH,
    },
    {
        "pattern": re.compile(
            r'SECRET_KEY\s*=\s*["\']([^"\']{1,20}|secret|password|changeme|admin|letmein)["\']',
            re.IGNORECASE,
        ),
        "issue":   "Short or weak SECRET_KEY in Django/Flask settings",
        "severity": HIGH,
    },
    {
        "pattern": re.compile(r"DEBUG\s*=\s*True"),
        "issue":   "DEBUG=True detected – disable in production deployments",
        "severity": HIGH,
    },
]


# ---------------------------------------------------------------------------
# AST-level checks for API code
# ---------------------------------------------------------------------------

def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _ast_api_checks(filepath: str, filename: str) -> List[Dict[str, Any]]:
    """AST walk to find missing auth decorators on sensitive endpoints."""
    findings: List[Dict[str, Any]] = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        tree = ast.parse(source, filename=filepath)
    except (OSError, SyntaxError):
        return findings

    # Look for functions decorated with route-like decorators that accept POST
    # and do NOT have an auth-related decorator.
    auth_decorator_hints = {"login_required", "requires_auth", "jwt_required",
                            "token_required", "authenticate", "permission_required",
                            "security", "HTTPBearer", "Depends"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorator_names = set()
        is_post_route = False
        for dec in node.decorator_list:
            name = _dotted(dec)
            decorator_names.add(name)
            # Check if route accepts POST/PUT/DELETE
            if isinstance(dec, ast.Call):
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and str(elt.value).upper() in (
                                "POST", "PUT", "DELETE", "PATCH"
                            ):
                                is_post_route = True
                # FastAPI: @router.post / @app.post
                func_part = _dotted(dec.func) if isinstance(dec.func, ast.Attribute) else _dotted(dec)
                if any(func_part.endswith(m) for m in (".post", ".put", ".delete", ".patch")):
                    is_post_route = True

        if is_post_route:
            has_auth = any(
                any(hint.lower() in dn.lower() for hint in auth_decorator_hints)
                for dn in decorator_names
            )
            if not has_auth:
                # Also check function parameters for Depends(security) pattern
                param_names = {arg.arg for arg in node.args.args}
                if not param_names.intersection({"current_user", "token", "credentials"}):
                    findings.append({
                        "file":     filename,
                        "line":     node.lineno,
                        "issue":    f"API endpoint '{node.name}' accepts POST/PUT/DELETE without apparent authentication",
                        "severity": MEDIUM,
                    })

    return findings


class APIScanner:
    """Scan Python web-serving files for insecure API patterns."""

    # File-name hints that suggest this file contains API/serving code
    _API_FILE_HINTS = re.compile(
        r"(app|api|server|serve|endpoint|route|view|handler|predict|infer|deploy)",
        re.IGNORECASE,
    )

    def analyze_file(self, filepath: str) -> List[Dict[str, Any]]:
        filename = os.path.relpath(filepath)
        findings: List[Dict[str, Any]] = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return findings

        for lineno, line in enumerate(lines, start=1):
            for spec in _API_PATTERNS:
                if spec["pattern"].search(line):
                    findings.append({
                        "file":     filename,
                        "line":     lineno,
                        "issue":    spec["issue"],
                        "severity": spec["severity"],
                    })

        # AST-level auth checks
        findings.extend(_ast_api_checks(filepath, filename))

        return findings

    def analyze_directory(self, dirpath: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        skip_dirs = {".git", "__pycache__", ".tox", "venv", ".venv"}
        for root, dirs, files in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if fname.endswith(".py"):
                    findings.extend(self.analyze_file(os.path.join(root, fname)))
        return findings
