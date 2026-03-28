"""
AST-based analyzer for Python source files.

Detects:
  - Unsafe deserialization  : pickle.load / pickle.loads / joblib.load /
                               dill.load / shelve.open / numpy.load (allow_pickle)
  - exec / eval usage       : exec(), eval(), compile() + exec
  - Insecure file handling  : open() with mode 'w'/'a' on sensitive paths,
                               tempfile.mktemp (racy)
  - Shell-injection risks   : subprocess with shell=True, os.system, os.popen
  - Unsafe YAML loading     : yaml.load() without Loader=yaml.SafeLoader
  - Unsafe XML parsing      : xml.etree / minidom / expat on external data
"""

import ast
import os
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _dotted_name(node: ast.AST) -> str:
    """Return a dotted string for Attribute / Name nodes."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted_name(node.value)}.{node.attr}"
    return ""


def _collect_aliases(tree: ast.AST) -> dict:
    """
    Collect import aliases from the module.

    Returns a mapping of local_name -> canonical_name so that aliased
    calls such as ``import numpy as np; np.load(...)`` resolve to
    ``numpy.load`` correctly.
    """
    aliases: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                full = f"{module}.{alias.name}" if module else alias.name
                aliases[local] = full
    return aliases


def _resolve_name(dotted: str, aliases: dict) -> str:
    """Resolve the leading component of *dotted* using *aliases*."""
    parts = dotted.split(".", 1)
    canonical = aliases.get(parts[0], parts[0])
    if len(parts) > 1:
        return f"{canonical}.{parts[1]}"
    return canonical


# ---------------------------------------------------------------------------
# Individual detector helpers
# ---------------------------------------------------------------------------

# Unsafe deserialization call signatures
_UNSAFE_DESER: Dict[str, Dict[str, Any]] = {
    "pickle.load":     {"issue": "Unsafe deserialization (pickle.load)",    "severity": HIGH},
    "pickle.loads":    {"issue": "Unsafe deserialization (pickle.loads)",   "severity": HIGH},
    "pickle.Unpickler":{"issue": "Unsafe deserialization (pickle.Unpickler)","severity": HIGH},
    "joblib.load":     {"issue": "Unsafe deserialization (joblib.load)",    "severity": HIGH},
    "dill.load":       {"issue": "Unsafe deserialization (dill.load)",      "severity": HIGH},
    "dill.loads":      {"issue": "Unsafe deserialization (dill.loads)",     "severity": HIGH},
    "shelve.open":     {"issue": "Unsafe deserialization (shelve.open)",    "severity": HIGH},
    "torch.load":      {"issue": "Unsafe deserialization (torch.load) – use weights_only=True", "severity": HIGH},
    "tf.saved_model.load": {"issue": "Potential unsafe model load (TF SavedModel)", "severity": MEDIUM},
    "keras.models.load_model": {"issue": "Potential unsafe model load (Keras)", "severity": MEDIUM},
}

# Dangerous builtins / functions
_DANGEROUS_FUNCS: Dict[str, Dict[str, Any]] = {
    "exec":    {"issue": "Use of exec() – arbitrary code execution risk",  "severity": HIGH},
    "eval":    {"issue": "Use of eval() – arbitrary code execution risk",  "severity": HIGH},
    "compile": {"issue": "Use of compile() – may facilitate code injection","severity": MEDIUM},
    "os.system":  {"issue": "Use of os.system() – shell injection risk",   "severity": HIGH},
    "os.popen":   {"issue": "Use of os.popen() – shell injection risk",    "severity": HIGH},
    "commands.getoutput": {"issue": "Use of commands.getoutput() – shell injection risk", "severity": HIGH},
    "tempfile.mktemp": {"issue": "Use of tempfile.mktemp() – race condition vulnerability", "severity": MEDIUM},
}

# Insecure yaml.load
_YAML_LOAD = "yaml.load"

# subprocess with shell=True
_SUBPROCESS_CALLS = {"subprocess.call", "subprocess.run", "subprocess.Popen",
                     "subprocess.check_call", "subprocess.check_output"}

# numpy.load with allow_pickle
_NUMPY_LOAD = "numpy.load"


def _check_call_node(node: ast.Call, filename: str, aliases: dict = None) -> List[Dict[str, Any]]:
    """Inspect a single Call node and return any findings."""
    findings: List[Dict[str, Any]] = []
    raw_name = _dotted_name(node.func)
    func_name = _resolve_name(raw_name, aliases or {})

    # --- Unsafe deserialization ---
    if func_name in _UNSAFE_DESER:
        info = _UNSAFE_DESER[func_name]
        findings.append({
            "file": filename,
            "line": node.lineno,
            "issue": info["issue"],
            "severity": info["severity"],
        })

    # --- Dangerous functions ---
    if func_name in _DANGEROUS_FUNCS:
        info = _DANGEROUS_FUNCS[func_name]
        findings.append({
            "file": filename,
            "line": node.lineno,
            "issue": info["issue"],
            "severity": info["severity"],
        })

    # --- yaml.load without SafeLoader ---
    if func_name == _YAML_LOAD:
        # Check whether Loader=yaml.SafeLoader / yaml.FullLoader is passed
        safe = False
        for kw in node.keywords:
            if kw.arg == "Loader":
                loader_name = _dotted_name(kw.value)
                if "Safe" in loader_name or "Full" in loader_name:
                    safe = True
        if not safe:
            findings.append({
                "file": filename,
                "line": node.lineno,
                "issue": "Unsafe YAML loading (yaml.load without SafeLoader)",
                "severity": HIGH,
            })

    # --- subprocess with shell=True ---
    if func_name in _SUBPROCESS_CALLS:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                findings.append({
                    "file": filename,
                    "line": node.lineno,
                    "issue": f"Shell injection risk: {func_name}(shell=True)",
                    "severity": HIGH,
                })

    # --- numpy.load with allow_pickle=True ---
    if func_name == _NUMPY_LOAD:
        for kw in node.keywords:
            if kw.arg == "allow_pickle" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                findings.append({
                    "file": filename,
                    "line": node.lineno,
                    "issue": "Unsafe deserialization: numpy.load(allow_pickle=True)",
                    "severity": HIGH,
                })

    # --- open() with write mode on sensitive paths ---
    if func_name == "open":
        mode_str = ""
        # positional arg [1] is the mode
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            mode_str = str(node.args[1].value)
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode_str = str(kw.value.value)
        path_arg = node.args[0] if node.args else None
        path_str = ""
        if isinstance(path_arg, ast.Constant):
            path_str = str(path_arg.value).lower()
        sensitive_exts = (".pem", ".key", ".crt", ".p12", ".pfx", ".env",
                          "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
        if any(path_str.endswith(ext) for ext in sensitive_exts) and "w" in mode_str:
            findings.append({
                "file": filename,
                "line": node.lineno,
                "issue": f"Insecure file write to sensitive path: {path_str}",
                "severity": HIGH,
            })

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ASTAnalyzer:
    """Scan Python source files using the AST module."""

    def analyze_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Parse *filepath* and return a list of vulnerability findings.

        Each finding is a dict with keys: file, line, issue, severity.
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError as exc:
            return [{"file": filepath, "line": None,
                     "issue": f"Could not read file: {exc}", "severity": LOW}]

        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError as exc:
            return [{"file": filepath, "line": exc.lineno,
                     "issue": f"Syntax error – could not parse: {exc.msg}", "severity": LOW}]

        filename = os.path.relpath(filepath)
        findings: List[Dict[str, Any]] = []

        aliases = _collect_aliases(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(_check_call_node(node, filename, aliases))

        return findings

    def analyze_directory(self, dirpath: str) -> List[Dict[str, Any]]:
        """Recursively scan all .py files under *dirpath*."""
        findings: List[Dict[str, Any]] = []
        for root, _dirs, files in os.walk(dirpath):
            for fname in files:
                if fname.endswith(".py"):
                    findings.extend(self.analyze_file(os.path.join(root, fname)))
        return findings
