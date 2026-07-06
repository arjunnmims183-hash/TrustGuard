"""
parser.py
---------
Reads a Python source file, builds an AST, and extracts:
  - All import statements
  - All function/method calls
  - All string literals

Everything downstream (dangerous_api, secret_scanner) works
from these extracted structures, not from raw text grep.
"""

import ast
from typing import Dict, List, Any


def parse_file(filepath: str) -> Dict[str, Any]:
    """
    Parse a Python file into an AST and extract key features.

    Returns a dict with:
        source     - raw source code (str)
        ast_tree   - the parsed AST object
        imports    - list of imported module names
        calls      - list of function call strings (e.g. "os.system")
        strings    - list of all string literals found
        error      - None if successful, error message if parse failed
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
    except FileNotFoundError:
        return {"error": f"File not found: {filepath}"}
    except UnicodeDecodeError:
        return {"error": f"Cannot decode file (not UTF-8): {filepath}"}

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        return {"error": f"Syntax error in file: {e}"}

    imports = _extract_imports(tree)
    calls = _extract_calls(tree)
    strings = _extract_strings(tree)

    return {
        "source": source,
        "ast_tree": tree,
        "imports": imports,
        "calls": calls,
        "strings": strings,
        "error": None,
    }


def _extract_imports(tree: ast.AST) -> List[str]:
    """
    Walk the AST and collect all imported module names.

    Handles:
        import os              -> ["os"]
        import os, sys         -> ["os", "sys"]
        from subprocess import Popen -> ["subprocess"]
        from base64 import b64encode -> ["base64"]
    """
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # alias.name is e.g. "os.path" or "requests"
                root = alias.name.split(".")[0]
                if root not in imports:
                    imports.append(root)

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                if root not in imports:
                    imports.append(root)

    return sorted(imports)


def _extract_calls(tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Walk the AST and collect all function/method call expressions.

    For each call, record:
        name    - best-effort readable name (e.g. "os.system", "eval")
        lineno  - line number in source
        args    - count of positional arguments
    """
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name:
                calls.append({
                    "name": name,
                    "lineno": getattr(node, "lineno", 0),
                    "arg_count": len(node.args),
                })
    return calls


def _call_name(node: ast.expr) -> str:
    """
    Try to reconstruct a readable name from a Call's func node.
    Examples:
        eval(...)         -> "eval"
        os.system(...)    -> "os.system"
        obj.method(...)   -> "obj.method"
    Returns empty string if we can't resolve it cleanly.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _extract_strings(tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Walk the AST and collect all string literals (ast.Constant where value is str).

    Records:
        value   - the string value
        lineno  - line number
    """
    strings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append({
                "value": node.value,
                "lineno": getattr(node, "lineno", 0),
            })
    return strings
