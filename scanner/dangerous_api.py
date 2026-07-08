"""
dangerous_api.py
----------------
Detects risky/dangerous function calls and imports in a parsed Python file.

Works in two layers:
  1. Import-level  - flags risky modules that were imported at all
  2. Call-level    - flags specific dangerous function/method calls

Each finding includes:
    category    - what type of risk (code execution, network, obfuscation, etc.)
    name        - the import or call name
    lineno      - where it appears
    severity    - LOW / MEDIUM / HIGH
    reason      - plain-English explanation
"""

import ast
from typing import List, Dict, Any, Optional, Set, Tuple

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.dangerous_imports import RISKY_IMPORTS
from scanner.data.dangerous_calls import DANGEROUS_CALLS


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _resolve_call_name(node: ast.expr) -> str:
    """
    Reconstruct a dotted call name from the AST node.
    
    Examples:
        - requests.post -> "requests.post"
        - os.getenv -> "os.getenv"
        - eval -> "eval"
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _resolve_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _get_import_root(module_name: str) -> str:
    """
    Get the root of an import name.
    
    Examples:
        - requests.post -> "requests"
        - os.path -> "os"
        - PIL.Image -> "PIL"
    """
    return module_name.split(".")[0] if module_name else ""


def _format_finding(
    finding_type: str,
    name: str,
    lineno: int,
    severity: str,
    category: str,
    reason: str
) -> Dict[str, Any]:
    """
    Create a standardized finding dictionary.
    """
    return {
        "type": finding_type,
        "name": name,
        "lineno": lineno,
        "severity": severity,
        "category": category,
        "reason": reason,
    }


# ==========================================
# DETECTION FUNCTIONS
# ==========================================

def _scan_imports(node: ast.AST) -> List[Dict[str, Any]]:
    """
    Scan import nodes for risky imports.
    """
    findings = []
    
    # ast.Import: import x, y, z
    if isinstance(node, ast.Import):
        for alias in node.names:
            root = _get_import_root(alias.name)
            if root in RISKY_IMPORTS:
                severity, category, reason = RISKY_IMPORTS[root]
                findings.append(_format_finding(
                    "import", alias.name, getattr(node, "lineno", 0),
                    severity, category, reason
                ))
    
    # ast.ImportFrom: from x import y, z
    elif isinstance(node, ast.ImportFrom):
        if node.module:
            root = _get_import_root(node.module)
            if root in RISKY_IMPORTS:
                severity, category, reason = RISKY_IMPORTS[root]
                findings.append(_format_finding(
                    "import", node.module, getattr(node, "lineno", 0),
                    severity, category, reason
                ))
    
    return findings


def _scan_calls(node: ast.Call) -> List[Dict[str, Any]]:
    """
    Scan a call node for dangerous calls.
    """
    findings = []
    
    name = _resolve_call_name(node.func)
    if name in DANGEROUS_CALLS:
        severity, category, reason = DANGEROUS_CALLS[name]
        findings.append(_format_finding(
            "call", name, getattr(node, "lineno", 0),
            severity, category, reason
        ))
    
    return findings


# ==========================================
# MAIN DETECTION FUNCTION
# ==========================================

def detect_dangerous_apis(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Run both import-level and call-level detection on the parsed AST.

    Returns a list of findings, each containing:
        type        - "import" or "call"
        name        - the flagged name
        lineno      - line number
        severity    - LOW / MEDIUM / HIGH
        category    - risk category string
        reason      - plain-English explanation
    """
    findings = []
    
    for node in ast.walk(tree):
        # Import-level scan
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            findings.extend(_scan_imports(node))
        
        # Call-level scan
        elif isinstance(node, ast.Call):
            findings.extend(_scan_calls(node))
    
    # Sort by line number for readable output
    findings.sort(key=lambda f: f["lineno"])
    
    return findings


# ==========================================
# LEGACY SUPPORT
# ==========================================

def detect_dangerous_apis_legacy(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return detect_dangerous_apis(tree, source)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "detect_dangerous_apis",
    "detect_dangerous_apis_legacy",
    "RISKY_IMPORTS",
    "DANGEROUS_CALLS",
]